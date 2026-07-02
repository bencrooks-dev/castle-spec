#!/usr/bin/env python3
"""castle-verify — standalone, Castle-free provenance verifier (VERIFY-03).

Verify a Castle attestation packet with **zero Castle/DB access**. This script
imports NOTHING from the ``castle`` package — no SQLAlchemy, no FastAPI, no
config. Its only non-stdlib dependency is ``cryptography`` (for Ed25519), the
same library Castle already uses. An auditor can copy this single file plus the
packet JSON and verify the deliverable on an air-gapped machine.

What it checks, given an exported packet (+ optionally a published public key):

  1. **Merkle root** — rebuilds the tree from the packet's leaves and confirms it
     equals the committed ``merkle_root``.
  2. **Ed25519 signature** — confirms the signature over the packet's canonical
     bytes is valid for the public key. If ``--pubkey`` is supplied it is used
     (and must match the key embedded in the packet); otherwise the embedded key
     is used and reported (publish + pin it out-of-band for who-attested trust).
  3. **Per-artifact hashes** — confirms each leaf hash equals the recomputed hash
     of ``(object_type:object_id, stamped sha256)``.
  4. **Inclusion proofs** — for every leaf, rebuilds an inclusion proof and
     confirms it reconstructs the root (any single artifact is provable alone).
  5. **Public Rekor anchor (optional)** — when the packet carries a
     ``rekor_anchor`` block with ``anchor_status: anchored``, verifies FULLY
     OFFLINE that the packet's Merkle root is included in the public Sigstore
     Rekor transparency log: (a) the RFC 6962 leaf hash matches the entry UUID
     tail; (b) the RFC 9162 inclusion path (using the SHARD-LOCAL proof index)
     reconstructs the proof root; (c) the checkpoint commits to that root and
     its signed note verifies against the PEM pinned in the packet (keyhint =
     first 4 bytes of sha256 of the DER SPKI); (d) the signed entry timestamp
     verifies over the canonical entry (using the GLOBAL log index and the
     RETURNED canonical body); (e) the anchored digest is the digest of THIS
     packet's Merkle root. Stdlib hashing + cryptography ECDSA only.

  6. **Transparent Statements (countersign receipts).** When the input file
     is a Transparent Statement (``ts_version`` + ``receipts`` keys: the
     embedded signed packet plus countersignature receipts issued by an
     independent verifying Castle instance, aligned to the IETF SCITT
     architecture, draft-ietf-scitt-architecture, in IESG evaluation; the
     SCITT pattern and semantics, not COSE wire-format interop), the embedded
     packet is verified as above, then every receipt's Ed25519 signature and
     its binding to THIS packet's Merkle root + canonical sha256 are checked.
     The receipt binding digest covers the FULL signed packet including its
     ``signature`` block and excluding only ``rekor_anchor`` (which may be
     upgraded post-signing by an anchor retry). A receipt recording
     ``verification.result: fail`` (an attest-failure receipt) is reported
     honestly as a failure, never as a clean pass.

  7. **Trust-registry pinning (optional, ``--trust REGISTRY.json``).** A
     trust registry (``trust_registry_version: 1``) pins WHICH keys may
     appear at each tier. When supplied, the packet's signing key must match
     a registry entry with purpose ``attestation_signing``, and every
     countersignature receipt, endorsement, and delegation-record signing
     key must match an entry with purpose ``countersign_signing``. Matching
     compares canonical DER SubjectPublicKeyInfo bytes (never PEM text), and
     a passing verdict names the matched registry identity per tier. Fail
     closed: an unpinned key is a verification FAILURE (exit 1); a registry
     that does not validate (wrong version, missing fields, unknown purpose,
     or a key_id that does not match its PEM) is a usage error (exit 2).
     Combines with ``--pubkey``: both constraints apply.

  8. **Machine-readable output (``--json``).** With ``--json``, stdout carries
     EXACTLY one JSON object (``castle_verify_json_version: 1``) and nothing
     else: ``verdict`` (pass/fail/malformed), ``exit_code``, ``artifact_type``
     (packet / transparent_statement / delegation_chain), per-check pass/fail
     entries with stable ids and plain-language labels, the verbatim
     ``failures`` strings, a ``summary`` block (engagement, signer key_id,
     anchor status, receipts, delegation, trust-registry matches), and
     ``report_text`` — the byte-identical human report the same invocation
     would print WITHOUT ``--json``. Exit codes are unchanged; ``--quiet`` is
     ignored under ``--json``. Malformed inputs and usage errors (exit 2/4)
     still emit the JSON object (verdict ``malformed``, ``error`` set), so a
     UI consuming stdout can always parse it. This JSON is the single source
     of truth for human-readable verification UIs (website + dashboard).

Exit codes:  0 = all checks pass.  1 = a verification check failed.
             2 = usage / malformed-packet / malformed-trust-registry error.

The verifier's verdict distinguishes three states: packet valid; packet valid
AND publicly anchored; anchor data present but the inclusion check FAILED
(loud — that is a verification failure, not a footnote). A pending anchor
(``anchor_status: pending``) is reported but is not a failure: the packet
ships before anchoring completes by design.

HONESTY: a PASS proves the attested artifacts are unchanged as a set and were
signed by the holder of this key (integrity + who-attested). It does NOT prove the
underlying evidence is complete or real. The transparency log is LOCAL, not a
public witnessed service — unless the packet carries a verified public Rekor
anchor, in which case the ROOT (a hash only, never content) is also provably
recorded in a public, append-only log.

The Merkle/leaf logic below is intentionally DUPLICATED from ``castle/merkle.py``
to keep this tool standalone; ``tests/test_verifier.py`` asserts the two agree.

Usage:
    python castle_verify.py PACKET.json [--pubkey KEY.pem] [--trust REGISTRY.json]
                            [--quiet] [--json]
    castle-verify PACKET.json [--pubkey KEY.pem]          # via console entry
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import sys
from typing import Any

# Domain-separation prefixes + encoding — MUST match castle/merkle.py exactly.
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
_FIELD_SEP = "\x1f"
MERKLE_VERSION = 1
PACKET_VERSION = 1
RECEIPT_VERSION = 1
TS_VERSION = 1


# --- Merkle primitives (mirror of castle.merkle) ---------------------------


def _leaf_content(object_type: str, object_id: int, artifact_sha256: str) -> str:
    return f"{object_type}:{object_id}{_FIELD_SEP}{artifact_sha256}"


def _hash_leaf(content: str) -> str:
    return hashlib.sha256(_LEAF_PREFIX + content.encode("utf-8")).hexdigest()


def _hash_nodes(left: str, right: str) -> str:
    return hashlib.sha256(_NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def _build_levels(leaf_hashes: list[str]) -> list[list[str]]:
    if not leaf_hashes:
        return [[hashlib.sha256(b"").hexdigest()]]
    level = list(leaf_hashes)
    levels = [level]
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_hash_nodes(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        levels.append(nxt)
        level = nxt
    return levels


def _inclusion_proof(levels: list[list[str]], leaf_index: int) -> list[tuple[str, str]]:
    steps: list[tuple[str, str]] = []
    idx = leaf_index
    for level in levels[:-1]:
        is_right = idx % 2 == 1
        sibling_idx = idx - 1 if is_right else idx + 1
        if sibling_idx < len(level):
            position = "left" if is_right else "right"
            steps.append((level[sibling_idx], position))
        idx //= 2
    return steps


def _verify_inclusion(leaf_hash: str, steps: list[tuple[str, str]], root: str) -> bool:
    running = leaf_hash
    for sibling, position in steps:
        if position == "left":
            running = _hash_nodes(sibling, running)
        elif position == "right":
            running = _hash_nodes(running, sibling)
        else:
            return False
    return running == root


# --- Packet canonicalization (mirror of castle.attestation) ----------------


def _canonical_packet_bytes(packet: dict[str, Any]) -> bytes:
    # Mirrors castle.attestation: `signature` cannot sign itself, and
    # `rekor_anchor` is attached AFTER signing (a retry can upgrade it from
    # pending to anchored without re-signing). The anchor's own integrity is
    # proven by Rekor's signatures binding to the SIGNED merkle_root.
    body = {k: v for k, v in packet.items() if k not in ("signature", "rekor_anchor")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


# --- Public Rekor anchor verification (offline; spike-proven recipe) -------
#
# Recipe + gotchas from the proven feasibility spike (Castle-spikes/
# rekor-anchor/SPIKE-REPORT.md, 2026-06-11). Notably:
#   gotcha 2 — the entry's logIndex is GLOBAL across shards while
#     inclusionProof.logIndex is SHARD-LOCAL. The Merkle path below uses the
#     shard-local index; the SET payload uses the global one. Mixing them
#     produces a silent-looking verification failure.
#   gotcha 3 — the SET signs the RETURNED canonical body, never the request.
#   gotcha 4 — the body's publicKey.content is base64 of PEM TEXT
#     (double-encoded); signature content is base64 of raw signature bytes.


def _rekor_leaf_hash(body: bytes) -> bytes:
    """RFC 6962 leaf hash: sha256(0x00 || entry body)."""
    return hashlib.sha256(b"\x00" + body).digest()


def _verify_rfc9162_inclusion(
    leaf_hash: bytes, leaf_index: int, tree_size: int, proof: list[bytes], root: bytes
) -> bool:
    """RFC 9162 section 2.1.3.2 inclusion-proof verification (shard-local index)."""
    if leaf_index >= tree_size:
        return False
    fn, sn = leaf_index, tree_size - 1
    running = leaf_hash
    for sibling in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            running = hashlib.sha256(b"\x01" + sibling + running).digest()
            if not fn & 1:
                while True:
                    fn >>= 1
                    sn >>= 1
                    if fn & 1 or fn == 0:
                        break
        else:
            running = hashlib.sha256(b"\x01" + running + sibling).digest()
        fn >>= 1
        sn >>= 1
    return sn == 0 and running == root


def verify_rekor_anchor(anchor: dict[str, Any], merkle_root: str) -> list[str]:
    """Verify a ``rekor_anchor`` block fully offline. Return failure messages.

    *merkle_root* is the packet's committed root: step (e) proves the public
    log entry commits to THIS packet's root, not merely to something. All
    signature checks use the Rekor public key PEM pinned in the packet at
    anchor time (shard rotation would otherwise orphan old packets).
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    failures: list[str] = []
    prefix = "rekor anchor"

    try:
        body_b64 = anchor["body"]
        entry_uuid = anchor["entry_uuid"]
        global_log_index = anchor["log_index"]
        shard_log_index = anchor["shard_log_index"]
        integrated_time = anchor["integrated_time"]
        log_id = anchor["log_id"]
        set_b64 = anchor["signed_entry_timestamp"]
        proof = anchor["inclusion_proof"]
        proof_hashes = [bytes.fromhex(h) for h in proof["hashes"]]
        tree_size = int(proof["tree_size"])
        root_hash = bytes.fromhex(proof["root_hash"])
        checkpoint = anchor["checkpoint"]
        pinned_pem = anchor["rekor_public_key_pem"]
        body = base64.b64decode(body_b64)
    except (KeyError, TypeError, ValueError) as exc:
        return [f"{prefix}: block malformed or incomplete: {exc}"]

    # (a) RFC 6962 leaf hash must be the entry UUID's 64-hex tail (the UUID
    # prefix is the 16-hex shard tree id).
    leaf = _rekor_leaf_hash(body)
    if str(entry_uuid)[-64:] != leaf.hex():
        failures.append(f"{prefix}: leaf hash does not match the entry UUID tail")

    # (b) Inclusion path — SHARD-LOCAL index (gotcha 2).
    if not _verify_rfc9162_inclusion(
        leaf, int(shard_log_index), tree_size, proof_hashes, root_hash
    ):
        failures.append(f"{prefix}: RFC 9162 inclusion path does not reconstruct the proof root")

    try:
        pinned_key = serialization.load_pem_public_key(str(pinned_pem).encode("utf-8"))
    except ValueError as exc:
        failures.append(f"{prefix}: pinned Rekor public key unreadable: {exc}")
        return failures
    if not isinstance(pinned_key, ec.EllipticCurvePublicKey):
        failures.append(f"{prefix}: pinned Rekor public key is not an ECDSA key")
        return failures
    key_id = hashlib.sha256(
        pinned_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).digest()
    if key_id.hex() != str(log_id):
        failures.append(
            f"{prefix}: pinned Rekor key does not hash to the entry's logID (wrong key pinned?)"
        )

    # (c) Checkpoint: root commitment + signed-note signature + keyhint.
    # Note format: "origin\nsize\nb64root\n\n<em dash> <origin> <b64(hint||sig)>\n".
    note_body, _, sig_block = str(checkpoint).partition("\n\n")
    note_body += "\n"
    note_lines = note_body.strip().split("\n")
    if len(note_lines) < 3:
        failures.append(f"{prefix}: checkpoint note is malformed")
    else:
        try:
            cp_root = base64.b64decode(note_lines[2])
            cp_size = int(note_lines[1])
        except (ValueError, IndexError):
            failures.append(f"{prefix}: checkpoint size/root lines unreadable")
        else:
            if cp_root != root_hash:
                failures.append(
                    f"{prefix}: checkpoint root does not match the inclusion-proof root"
                )
            if cp_size != tree_size:
                failures.append(
                    f"{prefix}: checkpoint tree size does not match the proof tree size"
                )
        # The signed-note signature line starts with U+2014 (Rekor's wire
        # format for signed notes; protocol data, not Castle-authored copy).
        sig_lines = [line for line in sig_block.strip().split("\n") if line.startswith("—")]
        if not sig_lines:
            failures.append(f"{prefix}: checkpoint has no signature line")
        else:
            try:
                cp_sig_raw = base64.b64decode(sig_lines[0].split(" ")[-1])
            except ValueError:
                failures.append(f"{prefix}: checkpoint signature is not valid base64")
                cp_sig_raw = b""
            if cp_sig_raw:
                # keyhint = first 4 bytes of sha256(DER SPKI) = first 4 of logID.
                if cp_sig_raw[:4] != key_id[:4]:
                    failures.append(f"{prefix}: checkpoint keyhint does not match the pinned key")
                try:
                    pinned_key.verify(
                        cp_sig_raw[4:],
                        note_body.encode("utf-8"),
                        ec.ECDSA(crypto_hashes.SHA256()),
                    )
                except InvalidSignature:
                    failures.append(f"{prefix}: checkpoint note signature is INVALID")

    # (d) SET over the canonical entry — GLOBAL log index, RETURNED body
    # (gotchas 2 + 3): sorted keys, no whitespace (JCS-equivalent here).
    set_payload = json.dumps(
        {
            "body": body_b64,
            "integratedTime": integrated_time,
            "logID": log_id,
            "logIndex": global_log_index,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    try:
        pinned_key.verify(base64.b64decode(set_b64), set_payload, ec.ECDSA(crypto_hashes.SHA256()))
    except (InvalidSignature, ValueError):
        failures.append(f"{prefix}: signed entry timestamp (SET) is INVALID")

    # (e) Binding: the anchored digest must be the digest of THIS packet's
    # Merkle-root hex string; otherwise the entry proves inclusion of
    # something unrelated. The body also carries the anchor public key
    # (base64-of-PEM, gotcha 4) whose signature we verify when it is the
    # production ECDSA P-256 kind.
    try:
        inner = json.loads(body)
        hash_spec = inner["spec"]["data"]["hash"]
        algorithm = str(hash_spec["algorithm"]).lower()
        claimed_digest = str(hash_spec["value"])
        anchor_sig_b64 = inner["spec"]["signature"]["content"]
        anchor_pub_pem = base64.b64decode(inner["spec"]["signature"]["publicKey"]["content"])
    except (KeyError, TypeError, ValueError) as exc:
        failures.append(f"{prefix}: entry body is not a readable hashedrekord: {exc}")
        return failures
    if algorithm not in ("sha256", "sha512"):
        failures.append(f"{prefix}: unsupported anchored hash algorithm {algorithm!r}")
    else:
        recomputed = hashlib.new(algorithm, merkle_root.encode("ascii")).hexdigest()
        if recomputed != claimed_digest:
            failures.append(
                f"{prefix}: anchored digest does not commit to this packet's "
                "merkle_root (anchor belongs to different content)"
            )
    try:
        anchor_pub = serialization.load_pem_public_key(anchor_pub_pem)
    except ValueError:
        anchor_pub = None
        failures.append(f"{prefix}: anchor public key in the entry body is unreadable")
    if isinstance(anchor_pub, ec.EllipticCurvePublicKey):
        try:
            anchor_pub.verify(
                base64.b64decode(anchor_sig_b64),
                merkle_root.encode("ascii"),
                ec.ECDSA(crypto_hashes.SHA256()),
            )
        except (InvalidSignature, ValueError):
            failures.append(f"{prefix}: anchor signature over the merkle root is INVALID")
    # Non-ECDSA anchor keys (e.g. the spike's Ed25519ph test entries) are not
    # signature-verified here — `cryptography` has no Ed25519ph API and the
    # digest binding above already ties the public entry to this root.

    return failures


# --- Verification ----------------------------------------------------------


class VerifyError(Exception):
    """Raised on a malformed packet (usage-class error, exit 2)."""


def verify_packet(
    packet: dict[str, Any],
    pubkey_pem: str | None = None,
    trust: dict[str, Any] | None = None,
) -> list[str]:
    """Run all checks. Return a list of failure messages (empty == all pass).

    With *trust* (a registry parsed by :func:`load_trust_registry`), the
    signing key must additionally match a registry entry with purpose
    ``attestation_signing`` (canonical DER SPKI comparison; fail closed).
    Raises :class:`VerifyError` for a malformed/unsupported packet (exit 2).
    """
    # Lazy import so a malformed-packet usage error doesn't require cryptography.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    failures: list[str] = []

    pv = packet.get("packet_version")
    mv = packet.get("merkle_version")
    if pv != PACKET_VERSION or mv != MERKLE_VERSION:
        msg = (
            f"unsupported versions packet={pv} merkle={mv} "
            f"(this verifier supports packet={PACKET_VERSION} merkle={MERKLE_VERSION})"
        )
        # The most common mistake with a downloaded pack is dropping one of the
        # exhibit REPORTS on the verifier instead of the signed packet itself.
        # Say so plainly rather than leaving only the version numbers.
        if pv is None and mv is None:
            if "exhibit" in packet:
                msg += (
                    "; this file looks like an exhibit report from inside a pack, "
                    "not the signed packet. Exhibits are covered by the packet's "
                    "Merkle root but are not individually signed; the signed file "
                    "is packet.json in the same pack."
                )
            else:
                msg += (
                    "; this JSON has none of packet_version / ts_version / "
                    "chain_version, so it is not a packet, Transparent Statement, "
                    "or delegation chain. In a Castle pack the signed file is "
                    "packet.json (it contains merkle_root and signature)."
                )
        raise VerifyError(msg)

    leaves = packet.get("leaves")
    root = packet.get("merkle_root")
    if not isinstance(leaves, list) or not isinstance(root, str):
        raise VerifyError("packet missing 'leaves' list or 'merkle_root' string")

    # (3) Per-artifact hashes: recompute each leaf hash from its stamped sha.
    recomputed_leaf_hashes: list[str] = []
    for i, leaf in enumerate(leaves):
        try:
            ot = leaf["object_type"]
            oid = leaf["object_id"]
            sha = leaf["artifact_sha256"]
            claimed = leaf["leaf_hash"]
        except (KeyError, TypeError) as exc:  # malformed leaf
            raise VerifyError(f"leaf {i} malformed: {exc}") from exc
        recomputed = _hash_leaf(_leaf_content(ot, oid, sha))
        recomputed_leaf_hashes.append(recomputed)
        if recomputed != claimed:
            failures.append(
                f"artifact hash mismatch for {ot}#{oid}: "
                f"leaf_hash claims {claimed[:16]}… but recomputes {recomputed[:16]}…"
            )

    # (1) Merkle root: rebuild from recomputed leaf hashes (sorted, as built).
    ordered = sorted(recomputed_leaf_hashes)
    levels = _build_levels(ordered)
    if levels[-1][0] != root:
        failures.append(
            f"merkle root mismatch: packet claims {root[:16]}… but recomputes {levels[-1][0][:16]}…"
        )

    # (4) Inclusion proofs: every leaf must reconstruct the (recomputed) root.
    rebuilt_root = levels[-1][0]
    for idx, lh in enumerate(ordered):
        steps = _inclusion_proof(levels, idx)
        if not _verify_inclusion(lh, steps, rebuilt_root):
            failures.append(f"inclusion proof failed for leaf index {idx} ({lh[:16]}…)")

    # (5) Public Rekor anchor, when present and claiming anchored status.
    # A pending anchor is NOT a failure (packets ship before anchoring by
    # design); a claimed-anchored block that does not verify IS one (loud).
    anchor = packet.get("rekor_anchor")
    if isinstance(anchor, dict) and anchor.get("anchor_status") == "anchored":
        failures.extend(verify_rekor_anchor(anchor, str(root)))

    # (2) Ed25519 signature over the canonical packet body.
    sig = packet.get("signature")
    if not isinstance(sig, dict):
        failures.append("packet has no signature block (unsigned packet)")
        return failures
    embedded_pem = sig.get("public_key_pem")
    use_pem = pubkey_pem if pubkey_pem is not None else embedded_pem
    if not use_pem:
        failures.append("no public key available (none supplied, none embedded)")
        return failures
    if pubkey_pem is not None and embedded_pem and _norm(pubkey_pem) != _norm(embedded_pem):
        failures.append(
            "supplied --pubkey does not match the key embedded in the packet "
            "(possible key substitution)"
        )
    try:
        key = load_pem_public_key(use_pem.encode("utf-8"))
    except ValueError as exc:
        failures.append(f"could not parse public key: {exc}")
        return failures
    if not isinstance(key, Ed25519PublicKey):
        failures.append("public key is not an Ed25519 key")
        return failures
    try:
        key.verify(bytes.fromhex(sig["value"]), _canonical_packet_bytes(packet))
    except (InvalidSignature, KeyError, ValueError):
        failures.append("Ed25519 signature is INVALID for this packet + key")

    # Trust-registry pinning: the signing key must be registered for
    # attestation. Canonical DER SPKI comparison, never PEM text.
    if trust is not None:
        der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        if _trust_match(trust, der, "attestation_signing") is None:
            failures.append(
                "packet signing key is not in the trust registry "
                f"(key_id {hashlib.sha256(der).hexdigest()})"
            )

    return failures


def _norm(pem: str) -> str:
    return "".join(pem.split())


# --- Trust-registry pinning (--trust) ---------------------------------------
#
# A trust registry pins WHICH keys may appear at each tier of an artifact,
# closing the "internally consistent but self-signed" gap for countersigned
# evidence the same way --pubkey closes it for a single packet. Matching is
# on canonical DER SubjectPublicKeyInfo bytes, never PEM text. Fail closed:
# an unpinned key is a verification failure; a registry that does not
# validate is a usage error (exit 2), never a silent pass.

TRUST_REGISTRY_VERSION = 1
_TRUST_PURPOSES = ("attestation_signing", "countersign_signing")


def load_trust_registry(doc: Any) -> dict[str, Any]:
    """Validate a trust-registry document; return the parsed registry.

    Returns ``{"registry_name": ..., "entries": [...]}`` where each entry
    carries ``identity``, ``key_id``, ``purpose``, and ``der`` (the
    canonical DER SubjectPublicKeyInfo bytes recomputed from the entry's
    PEM). Raises :class:`VerifyError` (usage-class, exit 2) on ANY
    malformation — wrong version, missing/empty fields, unknown purpose,
    unreadable PEM, or a stated key_id that does not equal the sha256 of
    the PEM's DER encoding. A bad registry is a trust-setup error, not a
    packet failure, and it fails closed.
    """
    # Lazy import: keeps the module stdlib-only at import time (Pyodide/WASM).
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    if not isinstance(doc, dict):
        raise VerifyError("trust registry is not a JSON object")
    version = doc.get("trust_registry_version")
    if version != TRUST_REGISTRY_VERSION:
        raise VerifyError(
            f"unsupported trust_registry_version {version!r} "
            f"(this verifier supports {TRUST_REGISTRY_VERSION})"
        )
    raw_entries = doc.get("entries")
    if not isinstance(raw_entries, list):
        raise VerifyError("trust registry has no 'entries' list")
    entries: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            raise VerifyError(f"trust registry entry {index} is not an object")
        identity = raw.get("identity")
        key_id = raw.get("key_id")
        pem = raw.get("public_key_pem")
        purpose = raw.get("purpose")
        for field, value in (
            ("identity", identity),
            ("key_id", key_id),
            ("public_key_pem", pem),
            ("purpose", purpose),
        ):
            if not isinstance(value, str) or not value:
                raise VerifyError(f"trust registry entry {index} is missing '{field}'")
        if purpose not in _TRUST_PURPOSES:
            raise VerifyError(
                f"trust registry entry {index} ({identity!r}) has unknown purpose "
                f"{purpose!r} (expected one of: {', '.join(_TRUST_PURPOSES)})"
            )
        try:
            key = load_pem_public_key(str(pem).encode("utf-8"))
        except ValueError as exc:
            raise VerifyError(
                f"trust registry entry {index} ({identity!r}): public_key_pem unreadable: {exc}"
            ) from exc
        der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        recomputed = hashlib.sha256(der).hexdigest()
        if recomputed != key_id:
            raise VerifyError(
                f"trust registry entry {index} ({identity!r}): key_id {key_id!r} does "
                f"not match the sha256 of the entry's DER-encoded public key "
                f"({recomputed})"
            )
        entries.append({"identity": identity, "key_id": recomputed, "purpose": purpose, "der": der})
    name = doc.get("registry_name")
    return {
        "registry_name": name if isinstance(name, str) and name else None,
        "entries": entries,
    }


def _trust_match(trust: dict[str, Any], der: bytes, purpose: str) -> dict[str, Any] | None:
    """Return the registry entry matching *der* + *purpose*, or ``None``."""
    for entry in trust["entries"]:
        if entry["purpose"] == purpose and entry["der"] == der:
            return entry
    return None


def _trust_entry_for_pem(trust: dict[str, Any], pem: Any, purpose: str) -> dict[str, Any] | None:
    """Match a PEM-embedded key against the registry (canonical DER, not text)."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    if not isinstance(pem, str) or not pem:
        return None
    try:
        key = load_pem_public_key(pem.encode("utf-8"))
    except ValueError:
        return None
    return _trust_match(
        trust, key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), purpose
    )


def _trust_registry_label(trust: dict[str, Any]) -> str:
    name = trust.get("registry_name")
    return f" '{name}'" if name else ""


# --- Transparent Statement verification (countersign receipts) -------------
#
# Intentionally DUPLICATED from castle/countersign.py to keep this tool
# standalone; tests assert the two agree. A Transparent Statement is the
# embedded signed packet plus countersignature receipts from an independent
# verifying Castle instance (SCITT pattern; plain JSON, not COSE).


def _canonical_receipt_bytes(receipt: dict[str, Any]) -> bytes:
    # The receipt's `signature` block cannot sign itself.
    body = {k: v for k, v in receipt.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _countersign_packet_sha256(packet: dict[str, Any]) -> str:
    # The receipt binding covers the FULL signed packet INCLUDING its
    # signature block (signature tampering breaks the binding) and excluding
    # ONLY rekor_anchor (attached after signing; an anchor retry may upgrade
    # it from pending to anchored without changing what was countersigned).
    body = {k: v for k, v in packet.items() if k != "rekor_anchor"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _verify_receipt(
    receipt: dict[str, Any],
    packet: dict[str, Any],
    label: str,
    trust: dict[str, Any] | None = None,
) -> list[str]:
    """Verify one countersignature receipt against the embedded packet."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    failures: list[str] = []
    countersigner = receipt.get("countersigner") or {}
    identity = countersigner.get("identity") or "unknown countersigner"
    who = f"{label} ({identity})"

    if receipt.get("receipt_version") != RECEIPT_VERSION:
        return [
            f"{who}: unsupported receipt_version {receipt.get('receipt_version')!r} "
            f"(this verifier supports {RECEIPT_VERSION})"
        ]
    sig = receipt.get("signature")
    if not isinstance(sig, dict):
        return [f"{who}: has no signature block"]
    pem = sig.get("public_key_pem")
    if not isinstance(pem, str) or not pem:
        return [f"{who}: has no embedded public key"]
    try:
        key = load_pem_public_key(pem.encode("utf-8"))
    except ValueError as exc:
        return [f"{who}: embedded public key unreadable: {exc}"]
    if not isinstance(key, Ed25519PublicKey):
        return [f"{who}: embedded public key is not an Ed25519 key"]
    try:
        key.verify(bytes.fromhex(str(sig.get("value"))), _canonical_receipt_bytes(receipt))
    except (InvalidSignature, ValueError):
        return [f"{who}: Ed25519 signature is INVALID for this receipt + key"]

    der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    if countersigner.get("key_id") != hashlib.sha256(der).hexdigest():
        failures.append(f"{who}: countersigner key_id does not match the embedded public key")
    if trust is not None and _trust_match(trust, der, "countersign_signing") is None:
        failures.append(
            f"{who}: countersigner key is not in the trust registry "
            f"(key_id {hashlib.sha256(der).hexdigest()})"
        )

    if receipt.get("packet_merkle_root") != packet.get("merkle_root"):
        failures.append(
            f"{who}: bound to merkle root "
            f"{str(receipt.get('packet_merkle_root'))[:16]}... but this packet's "
            f"root is {str(packet.get('merkle_root'))[:16]}..."
        )
    if receipt.get("packet_sha256") != _countersign_packet_sha256(packet):
        failures.append(
            f"{who}: packet_sha256 binding does not match this packet's canonical "
            "bytes (the packet changed after countersigning, or the receipt "
            "belongs to a different packet)"
        )

    verification = receipt.get("verification") or {}
    if verification.get("result") != "pass":
        failures.append(
            f"{who}: records verification result {verification.get('result')!r} "
            "(attest-failure receipt; an honest record of a FAILED verification, "
            "not a clean countersignature)"
        )
    return failures


def verify_transparent_statement(
    ts: dict[str, Any],
    pubkey_pem: str | None = None,
    trust: dict[str, Any] | None = None,
) -> list[str]:
    """Verify a Transparent Statement fully offline. Empty list == valid.

    The embedded packet is verified with :func:`verify_packet` (an optional
    *pubkey_pem* pins the packet signer's key); then every receipt's
    signature and binding are checked. With *trust* (see
    :func:`load_trust_registry`) the packet key must be registered for
    ``attestation_signing`` and every countersigner key for
    ``countersign_signing``. Receipt order is informational, not
    cryptographic. Raises :class:`VerifyError` only for a malformed
    statement envelope; a malformed EMBEDDED packet is a failure (the
    receipts claim to countersign something this tool cannot verify).
    """
    if ts.get("ts_version") != TS_VERSION:
        raise VerifyError(
            f"unsupported ts_version {ts.get('ts_version')!r} (this verifier supports {TS_VERSION})"
        )
    packet = ts.get("packet")
    receipts = ts.get("receipts")
    if not isinstance(packet, dict):
        raise VerifyError("transparent statement has no embedded packet object")
    if not isinstance(receipts, list):
        raise VerifyError("transparent statement has no receipts list")

    failures: list[str] = []
    try:
        failures.extend(f"packet: {f}" for f in verify_packet(packet, pubkey_pem, trust))
    except VerifyError as exc:
        failures.append(f"packet: malformed: {exc}")
        return failures
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            failures.append(f"receipt {index}: not an object")
            continue
        failures.extend(_verify_receipt(receipt, packet, f"receipt {index}", trust))
    return failures


def _main_transparent_statement(
    ts: dict[str, Any],
    pubkey_pem: str | None,
    quiet: bool,
    trust: dict[str, Any] | None = None,
    outcome: dict[str, Any] | None = None,
) -> int:
    try:
        failures = verify_transparent_statement(ts, pubkey_pem, trust)
    except VerifyError as exc:
        print(f"castle-verify: malformed transparent statement: {exc}", file=sys.stderr)
        return 2
    if outcome is not None:
        outcome["failures"] = failures

    receipts = [r for r in ts.get("receipts", []) if isinstance(r, dict)]
    if failures:
        print("FAIL: transparent statement verification failed")
        if not quiet:
            for f in failures:
                print(f"  - {f}")
        return 1

    n = len(receipts)
    if quiet:
        print("PASS (countersigned)" if n else "PASS")
        return 0
    packet = ts.get("packet", {})
    eng = packet.get("engagement", {})
    if n:
        print(f"PASS: packet valid; {n} of {n} receipts valid (countersigned)")
    else:
        print("PASS: packet valid (no receipts present)")
    print(
        f"  engagement {eng.get('id')} ({eng.get('client_name')}); "
        f"merkle_root: {packet.get('merkle_root')}"
    )
    for index, receipt in enumerate(receipts):
        who = (receipt.get("countersigner") or {}).get("identity", "unknown")
        print(f"  receipt {index}: {who}: signature valid, binding to this packet holds.")
    if trust is not None:
        print(
            "  TRUST REGISTRY: all signing keys pinned via the supplied trust "
            f"registry{_trust_registry_label(trust)}:"
        )
        entry = _trust_entry_for_pem(
            trust, (packet.get("signature") or {}).get("public_key_pem"), "attestation_signing"
        )
        if entry is not None:
            print(f"    packet attestation key: {entry['identity']} (attestation_signing)")
        for index, receipt in enumerate(receipts):
            entry = _trust_entry_for_pem(
                trust,
                (receipt.get("signature") or {}).get("public_key_pem"),
                "countersign_signing",
            )
            if entry is not None:
                print(
                    f"    receipt {index} countersigner: {entry['identity']} (countersign_signing)"
                )
    print(
        "  Countersignature receipts were issued by a verifying Castle instance; "
        "aligned to the IETF SCITT architecture (draft-ietf-scitt-architecture, "
        "in IESG evaluation). Pattern and semantics, not COSE wire-format interop."
    )
    print(
        "  NOTE: proves packet integrity + independent verification by each "
        "countersigner, NOT evidence completeness or any compliance status."
    )
    return 0


# --- Delegation chain verification (multi-tier countersign) ----------------
#
# Intentionally DUPLICATED from castle/delegation.py to keep this tool
# standalone; tests assert the two agree. A delegation chain is a base
# Transparent Statement plus append-only endorsements: each tier
# countersigns the statement PLUS every endorsement below it (SCITT
# pattern; plain JSON, not COSE). Endorsement order is cryptographic.

CHAIN_VERSION = 1
DELEGATION_VERSION = 1


def _chain_canonical(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _ts_unbound(ts: dict[str, Any]) -> dict[str, Any]:
    # The embedded packet drops rekor_anchor exactly as the packet-receipt
    # binding does, so a pending-to-anchored Rekor upgrade on the innermost
    # packet never breaks an upper tier's binding.
    body = dict(ts)
    packet = body.get("packet")
    if isinstance(packet, dict):
        body["packet"] = {k: v for k, v in packet.items() if k != "rekor_anchor"}
    return body


def _countersigned_ts_sha256(ts: dict[str, Any]) -> str:
    return hashlib.sha256(_chain_canonical(_ts_unbound(ts))).hexdigest()


def _chain_subject_sha256(statement: dict[str, Any], endorsements: list[dict[str, Any]]) -> str:
    # Endorsement i binds the statement plus endorsements[:i] (everything
    # below it, receipts in full and in order). With an empty prefix the
    # subject is the statement itself.
    if not endorsements:
        return _countersigned_ts_sha256(statement)
    body = {
        "statement": _ts_unbound(statement),
        "endorsements": [dict(e) for e in endorsements],
    }
    return hashlib.sha256(_chain_canonical(body)).hexdigest()


def _verify_endorsement(
    receipt: dict[str, Any],
    statement: dict[str, Any],
    prefix: list[dict[str, Any]],
    label: str,
    innermost_root: Any,
    trust: dict[str, Any] | None = None,
) -> list[str]:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    failures: list[str] = []
    countersigner = receipt.get("countersigner") or {}
    identity = countersigner.get("identity") or "unknown countersigner"
    who = f"{label} ({identity})"

    if receipt.get("receipt_version") != RECEIPT_VERSION:
        return [
            f"{who}: unsupported receipt_version {receipt.get('receipt_version')!r} "
            f"(this verifier supports {RECEIPT_VERSION})"
        ]
    if receipt.get("subject_type") != "transparent_statement":
        return [
            f"{who}: subject_type {receipt.get('subject_type')!r} is not "
            "'transparent_statement' (not a statement receipt)"
        ]
    sig = receipt.get("signature")
    if not isinstance(sig, dict):
        return [f"{who}: has no signature block"]
    pem = sig.get("public_key_pem")
    if not isinstance(pem, str) or not pem:
        return [f"{who}: has no embedded public key"]
    try:
        key = load_pem_public_key(pem.encode("utf-8"))
    except ValueError as exc:
        return [f"{who}: embedded public key unreadable: {exc}"]
    if not isinstance(key, Ed25519PublicKey):
        return [f"{who}: embedded public key is not an Ed25519 key"]
    try:
        key.verify(bytes.fromhex(str(sig.get("value"))), _canonical_receipt_bytes(receipt))
    except (InvalidSignature, ValueError):
        return [f"{who}: Ed25519 signature is INVALID for this endorsement + key"]

    der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    if countersigner.get("key_id") != hashlib.sha256(der).hexdigest():
        failures.append(f"{who}: countersigner key_id does not match the embedded public key")
    if trust is not None and _trust_match(trust, der, "countersign_signing") is None:
        failures.append(
            f"{who}: endorsement signing key is not in the trust registry "
            f"(key_id {hashlib.sha256(der).hexdigest()})"
        )

    if receipt.get("subject_sha256") != _chain_subject_sha256(statement, prefix):
        failures.append(
            f"{who}: subject_sha256 binding does not match the statement plus "
            "the endorsements below this tier (the statement bytes changed "
            "after endorsement, an endorsement below was tampered with, "
            "dropped, or reordered, or base receipts were reordered on an "
            "endorsed chain: endorsing freezes the statement bytes)."
        )
    if receipt.get("packet_merkle_root") != innermost_root:
        failures.append(
            f"{who}: bound to merkle root "
            f"{str(receipt.get('packet_merkle_root'))[:16]}... but the "
            f"innermost packet's root is {str(innermost_root)[:16]}..."
        )
    verification = receipt.get("verification") or {}
    if verification.get("result") != "pass":
        failures.append(
            f"{who}: records verification result {verification.get('result')!r} "
            "(not a clean countersignature)"
        )
    return failures


def _verify_chain_delegation_record(
    record: dict[str, Any],
    chain: dict[str, Any],
    trust: dict[str, Any] | None = None,
) -> list[str]:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    failures: list[str] = []
    if record.get("delegation_version") != DELEGATION_VERSION:
        return [
            f"delegation_record: unsupported delegation_version "
            f"{record.get('delegation_version')!r} (this verifier supports {DELEGATION_VERSION})"
        ]
    hashed = {k: v for k, v in record.items() if k not in ("record_id", "signature")}
    expected_id = "dlg:" + hashlib.sha256(_chain_canonical(hashed)).hexdigest()[:32]
    if record.get("record_id") != expected_id:
        failures.append(
            "delegation_record: record_id does not match the canonical body "
            "(the record changed after issuance)"
        )
    sig = record.get("signature")
    if not isinstance(sig, dict):
        failures.append("delegation_record: has no signature block")
        return failures
    pem = sig.get("public_key_pem")
    if not isinstance(pem, str) or not pem:
        failures.append("delegation_record: has no embedded public key")
        return failures
    try:
        key = load_pem_public_key(pem.encode("utf-8"))
    except ValueError as exc:
        failures.append(f"delegation_record: embedded public key unreadable: {exc}")
        return failures
    if not isinstance(key, Ed25519PublicKey):
        failures.append("delegation_record: embedded public key is not an Ed25519 key")
        return failures
    body = {k: v for k, v in record.items() if k != "signature"}
    try:
        key.verify(bytes.fromhex(str(sig.get("value"))), _chain_canonical(body))
    except (InvalidSignature, ValueError):
        failures.append("delegation_record: Ed25519 signature is INVALID for this record + key")
        return failures
    delegator_block = record.get("delegator") or {}
    der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    if delegator_block.get("key_id") != hashlib.sha256(der).hexdigest():
        failures.append(
            "delegation_record: delegator key_id does not match the embedded public key"
        )
    # Delegation records are signed with the delegating org's COUNTERSIGN key
    # (castle.delegation.build_delegation_record: an authority act, never an
    # attestation), so the registry purpose checked here is countersign_signing.
    if trust is not None and _trust_match(trust, der, "countersign_signing") is None:
        failures.append(
            "delegation_record: signing key is not in the trust registry "
            f"(key_id {hashlib.sha256(der).hexdigest()})"
        )

    statement = chain.get("statement")
    statement_ref = statement.get("delegation_record_id") if isinstance(statement, dict) else None
    if statement_ref != record.get("record_id"):
        failures.append(
            f"delegation_record: statement's delegation_record_id "
            f"{statement_ref!r} does not reference this record ({record.get('record_id')!r})"
        )
    delegator = delegator_block.get("identity")
    endorsers = [
        ((e.get("countersigner") or {}).get("identity"))
        for e in chain.get("endorsements", [])
        if isinstance(e, dict)
    ]
    if delegator not in endorsers:
        failures.append(
            f"delegation_record: delegator {delegator!r} is not among the "
            "endorsement countersigners (the delegating tier did not endorse "
            "this evidence)"
        )
    return failures


def verify_delegation_chain(
    chain: dict[str, Any],
    pubkey_pem: str | None = None,
    trust: dict[str, Any] | None = None,
) -> list[str]:
    """Verify a delegation chain fully offline. Empty list == valid.

    The base Transparent Statement is verified with
    :func:`verify_transparent_statement` (an optional *pubkey_pem* pins the
    innermost packet signer's key); then every endorsement's signature,
    prefix binding, and innermost-root match are checked, plus the optional
    delegation record's consistency. With *trust* (see
    :func:`load_trust_registry`) every endorsement and delegation-record
    signing key must be registered for ``countersign_signing`` (the packet
    and receipt keys are checked by the statement verification above).
    """
    if chain.get("chain_version") != CHAIN_VERSION:
        return [
            f"unsupported chain_version {chain.get('chain_version')!r} "
            f"(this verifier supports {CHAIN_VERSION})"
        ]
    statement = chain.get("statement")
    endorsements = chain.get("endorsements")
    if not isinstance(statement, dict):
        return ["delegation chain has no embedded statement object"]
    if not isinstance(endorsements, list):
        return ["delegation chain has no endorsements list"]

    failures: list[str] = []
    try:
        failures.extend(
            f"statement: {f}" for f in verify_transparent_statement(statement, pubkey_pem, trust)
        )
    except VerifyError as exc:
        failures.append(f"statement: malformed: {exc}")
        return failures

    packet = statement.get("packet")
    innermost_root = packet.get("merkle_root") if isinstance(packet, dict) else None
    prefix: list[dict[str, Any]] = []
    for index, endorsement in enumerate(endorsements):
        label = f"endorsement {index} (tier {index + 1})"
        if not isinstance(endorsement, dict):
            failures.append(f"{label}: not an object")
            continue
        failures.extend(
            _verify_endorsement(endorsement, statement, prefix, label, innermost_root, trust)
        )
        prefix.append(endorsement)

    record = chain.get("delegation_record")
    if isinstance(record, dict):
        failures.extend(_verify_chain_delegation_record(record, chain, trust))
    elif record is not None:
        failures.append("delegation_record: not an object")
    return failures


def _main_delegation_chain(
    chain: dict[str, Any],
    pubkey_pem: str | None,
    quiet: bool,
    trust: dict[str, Any] | None = None,
    outcome: dict[str, Any] | None = None,
) -> int:
    failures = verify_delegation_chain(chain, pubkey_pem, trust)
    if outcome is not None:
        outcome["failures"] = failures
    endorsements = [e for e in chain.get("endorsements", []) if isinstance(e, dict)]
    if failures:
        print("FAIL: delegation chain verification failed")
        if not quiet:
            for f in failures:
                print(f"  - {f}")
        return 1

    n = len(endorsements)
    if quiet:
        print("PASS (chain)")
        return 0
    statement = chain.get("statement", {})
    packet = statement.get("packet", {}) if isinstance(statement, dict) else {}
    eng = packet.get("engagement", {}) if isinstance(packet, dict) else {}
    print(f"PASS: chain valid; {n} tiers endorsed")
    print(
        f"  innermost packet: engagement {eng.get('id')} ({eng.get('client_name')}); "
        f"merkle_root: {packet.get('merkle_root')}"
    )
    for index, endorsement in enumerate(endorsements):
        who = (endorsement.get("countersigner") or {}).get("identity", "unknown")
        print(
            f"  endorsement {index} (tier {index + 1}): {who}: signature valid, "
            "binds the statement plus every endorsement below it."
        )
    record = chain.get("delegation_record")
    if isinstance(record, dict):
        delegator = (record.get("delegator") or {}).get("identity", "unknown")
        delegatee = (record.get("delegatee") or {}).get("identity", "unknown")
        print(
            f"  delegation record {record.get('record_id')}: {delegator} delegated "
            f"{len(record.get('obligations') or [])} obligation(s) to {delegatee}; "
            "signature valid, statement reference holds."
        )
    if trust is not None:
        print(
            "  TRUST REGISTRY: all signing keys pinned via the supplied trust "
            f"registry{_trust_registry_label(trust)}:"
        )
        entry = _trust_entry_for_pem(
            trust,
            (packet.get("signature") or {}).get("public_key_pem") if packet else None,
            "attestation_signing",
        )
        if entry is not None:
            print(
                f"    innermost packet attestation key: {entry['identity']} (attestation_signing)"
            )
        receipts = statement.get("receipts", []) if isinstance(statement, dict) else []
        for index, receipt in enumerate(r for r in receipts if isinstance(r, dict)):
            entry = _trust_entry_for_pem(
                trust,
                (receipt.get("signature") or {}).get("public_key_pem"),
                "countersign_signing",
            )
            if entry is not None:
                print(
                    f"    receipt {index} countersigner: {entry['identity']} (countersign_signing)"
                )
        for index, endorsement in enumerate(endorsements):
            entry = _trust_entry_for_pem(
                trust,
                (endorsement.get("signature") or {}).get("public_key_pem"),
                "countersign_signing",
            )
            if entry is not None:
                print(
                    f"    endorsement {index} (tier {index + 1}) signer: "
                    f"{entry['identity']} (countersign_signing)"
                )
        if isinstance(record, dict):
            entry = _trust_entry_for_pem(
                trust,
                (record.get("signature") or {}).get("public_key_pem"),
                "countersign_signing",
            )
            if entry is not None:
                print(f"    delegation record signer: {entry['identity']} (countersign_signing)")
    print(
        "  Endorsements were issued by verifying Castle instances; aligned to "
        "the IETF SCITT architecture (draft-ietf-scitt-architecture, in IESG "
        "evaluation). Pattern and semantics, not COSE wire-format interop."
    )
    print(
        "  NOTE: proves evidence integrity + independent verification at each "
        "tier, NOT evidence completeness or any compliance status."
    )
    return 0


# --- Machine-readable output (--json) ---------------------------------------
#
# With --json, stdout carries EXACTLY one JSON object and nothing else: the
# single source of truth for human-readable verification UIs (website +
# dashboard). The human report is NOT forked: the same report code runs with
# stdout captured, and the capture is embedded byte-identical as report_text.

JSON_OUTPUT_VERSION = 1

_CHECK_LABELS = {
    "merkle_root": "Evidence integrity: Merkle root rebuilt from every artifact",
    "signature": "Authenticity: signature verified against the signing key",
    "artifact_hashes": "Per-artifact fingerprints match the packet",
    "inclusion_proofs": "Every artifact provably included in the sealed root",
    "key_pinning": "Key pinning: signing keys match the pinned key / trust registry",
    "anchor": "Public anchor: Merkle root recorded in the Sigstore Rekor transparency log",
    "countersignatures": "Independent countersignatures verified",
    "endorsements": "Endorsement chain: every tier binds the statement and all tiers below it",
    "delegation_record": "Delegation record verified and referenced by the statement",
}


def _attribute_failure(failure: str) -> str:
    """Map a verbatim failure string to a stable check id (substring category).

    Ordering matters: tier/prefix categories (anchor, trust, delegation,
    endorsement, receipt) are matched before generic content words so that
    e.g. a receipt's invalid signature lands on the countersignatures check.
    Anything unmatched returns ``other`` — verdict fails closed regardless.
    """
    f = failure.lower()
    if "rekor" in f or "anchor" in f:
        return "anchor"
    if "trust registry" in f or "pinned" in f or "pubkey" in f:
        return "key_pinning"
    if "delegation_record" in f:
        return "delegation_record"
    if "endorse" in f:
        return "endorsements"
    if "receipt" in f or "countersign" in f:
        return "countersignatures"
    if "inclusion" in f:
        return "inclusion_proofs"
    if "artifact hash" in f or "leaf" in f:
        return "artifact_hashes"
    if "merkle" in f:
        return "merkle_root"
    if "signature" in f or "signing key" in f or "public key" in f or "unsigned" in f:
        return "signature"
    return "other"


def _relevant_packet(artifact_type: str | None, doc: Any) -> dict[str, Any]:
    """The (innermost) packet a summary/checks derive from, or ``{}``."""
    if not isinstance(doc, dict):
        return {}
    if artifact_type == "packet":
        return doc
    if artifact_type == "transparent_statement":
        packet = doc.get("packet")
        return packet if isinstance(packet, dict) else {}
    if artifact_type == "delegation_chain":
        statement = doc.get("statement")
        packet = statement.get("packet") if isinstance(statement, dict) else None
        return packet if isinstance(packet, dict) else {}
    return {}


def _embedded_statement(artifact_type: str | None, doc: Any) -> dict[str, Any] | None:
    if not isinstance(doc, dict):
        return None
    if artifact_type == "transparent_statement":
        return doc
    if artifact_type == "delegation_chain":
        statement = doc.get("statement")
        return statement if isinstance(statement, dict) else None
    return None


def _build_checks(outcome: dict[str, Any], failures: list[str]) -> list[dict[str, Any]]:
    """Per-artifact check list; every listed check is genuinely performed."""
    artifact_type = outcome.get("artifact_type")
    doc = outcome.get("doc")
    rel_packet = _relevant_packet(artifact_type, doc)

    ids = ["merkle_root", "signature", "artifact_hashes", "inclusion_proofs"]
    if outcome.get("pubkey_pem") is not None or outcome.get("trust") is not None:
        ids.append("key_pinning")
    anchor = rel_packet.get("rekor_anchor")
    if isinstance(anchor, dict) and anchor.get("anchor_status") == "anchored":
        ids.append("anchor")
    if artifact_type in ("transparent_statement", "delegation_chain"):
        ids.append("countersignatures")
    if artifact_type == "delegation_chain":
        ids.append("endorsements")
        if isinstance(doc, dict) and doc.get("delegation_record") is not None:
            ids.append("delegation_record")

    attributed: dict[str, list[str]] = {check_id: [] for check_id in ids}
    unattributed: list[str] = []
    for failure in failures:
        check_id = _attribute_failure(failure)
        if check_id in attributed:
            attributed[check_id].append(failure)
        else:
            unattributed.append(failure)

    checks = [
        {
            "id": check_id,
            "label": _CHECK_LABELS[check_id],
            "status": "fail" if attributed[check_id] else "pass",
            "detail": "; ".join(attributed[check_id]),
        }
        for check_id in ids
    ]
    checks.extend(
        {
            "id": "other",
            "label": "Additional check failed",
            "status": "fail",
            "detail": failure,
        }
        for failure in unattributed
    )
    return checks


def _key_id_from_pem(pem: Any) -> str | None:
    """sha256 hex of the canonical DER SubjectPublicKeyInfo, or ``None``."""
    if not isinstance(pem, str) or not pem:
        return None
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    try:
        key = load_pem_public_key(pem.encode("utf-8"))
    except ValueError:
        return None
    return hashlib.sha256(
        key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()


def _trust_matched_identities(outcome: dict[str, Any]) -> list[str]:
    """Registry identities matched during this run (order kept, deduped)."""
    trust = outcome.get("trust")
    if trust is None:
        return []
    artifact_type = outcome.get("artifact_type")
    doc = outcome.get("doc")
    rel_packet = _relevant_packet(artifact_type, doc)
    identities: list[str] = []

    def _add(entry: dict[str, Any] | None) -> None:
        if entry is not None and entry["identity"] not in identities:
            identities.append(entry["identity"])

    sig = rel_packet.get("signature")
    pem = sig.get("public_key_pem") if isinstance(sig, dict) else None
    _add(_trust_entry_for_pem(trust, pem or outcome.get("pubkey_pem"), "attestation_signing"))

    statement = _embedded_statement(artifact_type, doc)
    if statement is not None:
        for receipt in statement.get("receipts") or []:
            if isinstance(receipt, dict):
                receipt_pem = (receipt.get("signature") or {}).get("public_key_pem")
                _add(_trust_entry_for_pem(trust, receipt_pem, "countersign_signing"))
    if artifact_type == "delegation_chain" and isinstance(doc, dict):
        for endorsement in doc.get("endorsements") or []:
            if isinstance(endorsement, dict):
                end_pem = (endorsement.get("signature") or {}).get("public_key_pem")
                _add(_trust_entry_for_pem(trust, end_pem, "countersign_signing"))
        record = doc.get("delegation_record")
        if isinstance(record, dict):
            record_pem = (record.get("signature") or {}).get("public_key_pem")
            _add(_trust_entry_for_pem(trust, record_pem, "countersign_signing"))
    return identities


def _null_summary() -> dict[str, Any]:
    return {
        "engagement_id": None,
        "client_name": None,
        "generated_at": None,
        "artifact_count": None,
        "merkle_root": None,
        "signer_key_id": None,
        "key_pinned": False,
        "trust_registry": None,
        "anchor": None,
        "receipts": [],
        "delegation": None,
        "tier_count": None,
    }


def _build_summary(outcome: dict[str, Any]) -> dict[str, Any]:
    artifact_type = outcome.get("artifact_type")
    doc = outcome.get("doc")
    trust = outcome.get("trust")
    rel_packet = _relevant_packet(artifact_type, doc)

    engagement = rel_packet.get("engagement")
    if not isinstance(engagement, dict):
        engagement = {}
    leaves = rel_packet.get("leaves")
    merkle_root = rel_packet.get("merkle_root")
    sig = rel_packet.get("signature")
    signer_pem = sig.get("public_key_pem") if isinstance(sig, dict) else None

    anchor_block = rel_packet.get("rekor_anchor")
    anchor = None
    if isinstance(anchor_block, dict):
        log_index = anchor_block.get("log_index")
        anchor = {
            "status": str(anchor_block.get("anchor_status")),
            "log_index": log_index if isinstance(log_index, int) else None,
        }

    receipts: list[dict[str, Any]] = []
    statement = _embedded_statement(artifact_type, doc)
    if statement is not None:
        for receipt in statement.get("receipts") or []:
            if not isinstance(receipt, dict):
                continue
            verification = receipt.get("verification") or {}
            receipts.append(
                {
                    "identity": (receipt.get("countersigner") or {}).get("identity"),
                    "result": verification.get("result"),
                    "verified_at": verification.get("verified_at"),
                }
            )

    delegation = None
    tier_count = None
    if artifact_type == "delegation_chain" and isinstance(doc, dict):
        tier_count = sum(1 for e in doc.get("endorsements") or [] if isinstance(e, dict))
        record = doc.get("delegation_record")
        if isinstance(record, dict):
            delegation = {
                "delegator": (record.get("delegator") or {}).get("identity"),
                "delegatee": (record.get("delegatee") or {}).get("identity"),
                "obligations_count": len(record.get("obligations") or []),
            }

    trust_registry = None
    if trust is not None:
        trust_registry = {
            "name": trust.get("registry_name"),
            "matched_identities": _trust_matched_identities(outcome),
        }

    return {
        "engagement_id": engagement.get("id"),
        "client_name": engagement.get("client_name"),
        "generated_at": rel_packet.get("generated_at"),
        "artifact_count": len(leaves) if isinstance(leaves, list) else None,
        "merkle_root": merkle_root if isinstance(merkle_root, str) else None,
        "signer_key_id": _key_id_from_pem(signer_pem),
        "key_pinned": outcome.get("pubkey_pem") is not None or trust is not None,
        "trust_registry": trust_registry,
        "anchor": anchor,
        "receipts": receipts,
        "delegation": delegation,
        "tier_count": tier_count,
    }


def _json_document(
    code: int, outcome: dict[str, Any], report_text: str, error_text: str
) -> dict[str, Any]:
    """Build the --json object. FAIL CLOSED: exit 1 is always verdict fail."""
    verdict = "pass" if code == 0 else "fail" if code == 1 else "malformed"
    if verdict == "malformed":
        return {
            "castle_verify_json_version": JSON_OUTPUT_VERSION,
            "verdict": verdict,
            "exit_code": code,
            "artifact_type": None,
            "checks": [],
            "failures": [],
            "summary": _null_summary(),
            "report_text": report_text,
            "error": error_text.strip() or None,
        }
    failures = list(outcome.get("failures") or [])
    return {
        "castle_verify_json_version": JSON_OUTPUT_VERSION,
        "verdict": verdict,
        "exit_code": code,
        "artifact_type": outcome.get("artifact_type"),
        "checks": _build_checks(outcome, failures),
        "failures": failures,
        "summary": _build_summary(outcome),
        "report_text": report_text,
        "error": None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="castle-verify",
        description="Standalone verifier for a Castle attestation packet "
        "(Merkle root + Ed25519 signature + inclusion proofs). Castle-free.",
    )
    parser.add_argument(
        "packet",
        help="Path to the exported packet JSON (or a Transparent Statement "
        "JSON: packet + countersignature receipts).",
    )
    parser.add_argument(
        "--pubkey",
        default=None,
        help="Path to a published Ed25519 public-key PEM to verify against "
        "(must match the key embedded in the packet). Defaults to the embedded key.",
    )
    parser.add_argument(
        "--trust",
        default=None,
        metavar="FILE",
        help="Path to a trust-registry JSON (trust_registry_version 1) pinning "
        "which keys may appear per tier: the packet signing key must match an "
        "'attestation_signing' entry; every countersignature receipt, "
        "endorsement, and delegation-record signing key must match a "
        "'countersign_signing' entry. Keys are matched on canonical DER "
        "SubjectPublicKeyInfo bytes; an unpinned key is a verification "
        "FAILURE (fail closed), and a malformed registry is a usage error "
        "(exit 2). May be combined with --pubkey (both constraints apply).",
    )
    parser.add_argument("--quiet", action="store_true", help="Only print PASS/FAIL.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit EXACTLY one machine-readable JSON object on stdout "
        "(castle_verify_json_version 1) and nothing else: verdict "
        "(pass/fail/malformed), exit_code, artifact_type, per-check "
        "pass/fail entries with stable ids and plain-language labels, "
        "verbatim failure strings, a summary block (engagement, signer "
        "key_id, anchor, receipts, delegation, trust-registry matches), and "
        "report_text (the byte-identical human report the same invocation "
        "prints without --json). Exit codes are unchanged; --quiet is "
        "ignored. Malformed inputs and usage errors (exit 2/4) still emit "
        "the JSON object with verdict 'malformed' and error set, so a UI "
        "consuming stdout can always parse it.",
    )
    parser.add_argument(
        "--require-pinned",
        action="store_true",
        help="Strict mode (SEC-P0-H1): FAIL unless --pubkey is supplied, so "
        "authorship is verified against an out-of-band published key rather than "
        "the key embedded in the packet. Use for examiner/CI verification. Also "
        "enabled by CASTLE_VERIFY_REQUIRE_PINNED=1.",
    )
    args = parser.parse_args(argv)

    if not args.json:
        return _run(args, {})

    # --json: run the SAME verification + report code path with stdout and
    # stderr captured, so the human report is produced exactly once (never
    # forked) and embedded byte-identical as report_text. --quiet is ignored:
    # the JSON object is the machine output; report_text is the full report.
    args.quiet = False
    outcome: dict[str, Any] = {}
    out_buffer = io.StringIO()
    err_buffer = io.StringIO()
    with contextlib.redirect_stdout(out_buffer), contextlib.redirect_stderr(err_buffer):
        code = _run(args, outcome)
    error_text = err_buffer.getvalue()
    if error_text:
        sys.stderr.write(error_text)  # keep stderr diagnostics alongside the JSON
    print(json.dumps(_json_document(code, outcome, out_buffer.getvalue(), error_text)))
    return code


def _run(args: argparse.Namespace, outcome: dict[str, Any]) -> int:
    """Verify + print the human report; record structured data in *outcome*.

    *outcome* is populated for ``--json``: ``artifact_type``, the parsed
    document (``doc``), the effective ``pubkey_pem`` / ``trust`` registry,
    and the verbatim ``failures`` list. Printing is unchanged — the non-json
    path calls this directly, the json path captures its stdout.
    """
    # SEC-P0-H1: in strict mode, verifying a packet against its OWN embedded key
    # proves integrity but NOT authorship — a forged packet self-signed with any
    # key would pass. Refuse, with a distinct exit code, unless a public key is
    # pinned out-of-band via --pubkey.
    require_pinned = args.require_pinned or os.environ.get(
        "CASTLE_VERIFY_REQUIRE_PINNED", ""
    ).strip().lower() in {"1", "true", "yes"}
    if require_pinned and not args.pubkey:
        print(
            "castle-verify: FAIL — --require-pinned set but no --pubkey supplied. "
            "Authorship cannot be verified (a packet self-signed with any key "
            "passes integrity checks); supply the publisher's out-of-band public "
            "key with --pubkey.",
            file=sys.stderr,
        )
        return 4

    try:
        with open(args.packet, encoding="utf-8") as fh:
            packet = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"castle-verify: cannot read packet: {exc}", file=sys.stderr)
        return 2

    pubkey_pem: str | None = None
    if args.pubkey:
        try:
            with open(args.pubkey, encoding="utf-8") as fh:
                pubkey_pem = fh.read()
        except OSError as exc:
            print(f"castle-verify: cannot read pubkey: {exc}", file=sys.stderr)
            return 2

    # Trust registry (--trust): load + validate BEFORE any verification. A
    # registry that does not validate is a trust-setup/usage error (exit 2),
    # never a packet failure, and never a silent pass.
    trust: dict[str, Any] | None = None
    if args.trust:
        try:
            with open(args.trust, encoding="utf-8") as fh:
                trust_doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"castle-verify: cannot read trust registry: {exc}", file=sys.stderr)
            return 2
        try:
            trust = load_trust_registry(trust_doc)
        except VerifyError as exc:
            print(f"castle-verify: malformed trust registry: {exc}", file=sys.stderr)
            return 2

    outcome["doc"] = packet
    outcome["pubkey_pem"] = pubkey_pem
    outcome["trust"] = trust

    # A delegation chain (Transparent Statement + append-only endorsements)
    # or a Transparent Statement (embedded packet + countersignature
    # receipts) is detected by shape and verified with the same offline logic.
    if isinstance(packet, dict) and "chain_version" in packet and "endorsements" in packet:
        outcome["artifact_type"] = "delegation_chain"
        return _main_delegation_chain(packet, pubkey_pem, args.quiet, trust, outcome)
    if isinstance(packet, dict) and "ts_version" in packet and "receipts" in packet:
        outcome["artifact_type"] = "transparent_statement"
        return _main_transparent_statement(packet, pubkey_pem, args.quiet, trust, outcome)

    outcome["artifact_type"] = "packet"
    try:
        failures = verify_packet(packet, pubkey_pem, trust)
    except VerifyError as exc:
        print(f"castle-verify: malformed packet: {exc}", file=sys.stderr)
        return 2
    outcome["failures"] = failures

    if failures:
        print("FAIL: provenance verification failed")
        if not args.quiet:
            for f in failures:
                print(f"  - {f}")
        return 1

    anchor = packet.get("rekor_anchor")
    anchored = isinstance(anchor, dict) and anchor.get("anchor_status") == "anchored"
    if not args.quiet:
        eng = packet.get("engagement", {})
        n = len(packet.get("leaves", []))
        print(
            f"PASS: verified {n} artifact(s) for engagement "
            f"{eng.get('id')} ({eng.get('client_name')})"
        )
        print(f"  merkle_root: {packet.get('merkle_root')}")
        if pubkey_pem is not None:
            print(
                "  Ed25519 signature valid against the PINNED public key; all "
                "artifact hashes + inclusion proofs hold."
            )
        else:
            print(
                "  Ed25519 signature valid against the key EMBEDDED in the packet; "
                "all artifact hashes + inclusion proofs hold."
            )
        if trust is not None:
            sig_pem = (
                pubkey_pem
                if pubkey_pem is not None
                else (packet.get("signature") or {}).get("public_key_pem")
            )
            entry = _trust_entry_for_pem(trust, sig_pem, "attestation_signing")
            if entry is not None:
                print(
                    "  TRUST REGISTRY: packet signing key pinned via the supplied "
                    f"trust registry{_trust_registry_label(trust)}: "
                    f"{entry['identity']} (attestation_signing)."
                )
        if anchored:
            print(
                "  PUBLICLY ANCHORED: Merkle root provably included in the Sigstore "
                f"Rekor transparency log (log index {anchor.get('log_index')}, "
                f"entry {str(anchor.get('entry_uuid'))[:20]}...). Verified offline."
            )
        elif isinstance(anchor, dict):
            print(
                "  Anchor status: "
                + str(anchor.get("anchor_status"))
                + " (anchor data present but the root is not yet publicly anchored; "
                "re-attempt with `castle anchor retry`)."
            )
        if pubkey_pem is not None:
            print(
                "  NOTE: proves integrity (unchanged) AND authorship (signed by the "
                "pinned key), NOT evidence completeness."
            )
        else:
            print(
                "  WARNING: no --pubkey was pinned, so this proves INTEGRITY ONLY — "
                "NOT authorship. A forged packet self-signed with any key also "
                "passes this check. Re-run with --pubkey set to the publisher's "
                "out-of-band published key to prove WHO attested."
            )
            print(
                "  NOTE: integrity proven; authorship UNVERIFIED (key unpinned); "
                "evidence completeness NOT proven."
            )
    else:
        print("PASS (publicly anchored)" if anchored else "PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
