#!/usr/bin/env python3
"""castle-verify: standalone, Castle-free provenance verifier (VERIFY-03).

Verify a Castle attestation packet with **zero Castle/DB access**. This script
imports NOTHING from the ``castle`` package: no SQLAlchemy, no FastAPI, no
config. Its only non-stdlib dependency is ``cryptography`` (for Ed25519), the
same library Castle already uses. An auditor can copy this single file plus the
packet JSON and verify the deliverable on an air-gapped machine.

What it checks, given an exported packet (+ optionally a published public key):

  1. **Merkle root**: rebuilds the tree from the packet's leaves and confirms it
     equals the committed ``merkle_root``.
  2. **Ed25519 signature**: confirms the signature over the packet's canonical
     bytes is valid for the public key. If ``--pubkey`` is supplied it is used
     (and must match the key embedded in the packet); otherwise the embedded key
     is used and reported (publish + pin it out-of-band for who-attested trust).
  3. **Per-artifact hashes**: confirms each leaf hash equals the recomputed hash
     of ``(object_type:object_id, stamped sha256)``.
  4. **Inclusion proofs**: for every leaf, rebuilds an inclusion proof and
     confirms it reconstructs the root (any single artifact is provable alone).

Exit codes:  0 = all checks pass.  1 = a verification check failed.
             2 = usage / malformed-packet error.

HONESTY: a PASS proves the attested artifacts are unchanged as a set and were
signed by the holder of this key (integrity + who-attested). It does NOT prove the
underlying evidence is complete or real. The transparency log is LOCAL, not a
public witnessed service.

The Merkle/leaf logic below is intentionally DUPLICATED from ``castle/merkle.py``
to keep this tool standalone; ``tests/test_verifier.py`` asserts the two agree.

Usage:
    python castle_verify.py PACKET.json [--pubkey KEY.pem] [--quiet]
    castle-verify PACKET.json [--pubkey KEY.pem]          # via console entry
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

# Domain-separation prefixes + encoding: MUST match castle/merkle.py exactly.
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
_FIELD_SEP = "\x1f"
MERKLE_VERSION = 1
PACKET_VERSION = 1


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
    body = {k: v for k, v in packet.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


# --- Verification ----------------------------------------------------------


class VerifyError(Exception):
    """Raised on a malformed packet (usage-class error, exit 2)."""


def verify_packet(packet: dict[str, Any], pubkey_pem: str | None = None) -> list[str]:
    """Run all checks. Return a list of failure messages (empty == all pass).

    Raises :class:`VerifyError` for a malformed/unsupported packet (exit 2).
    """
    # Lazy import so a malformed-packet usage error doesn't require cryptography.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    failures: list[str] = []

    pv = packet.get("packet_version")
    mv = packet.get("merkle_version")
    if pv != PACKET_VERSION or mv != MERKLE_VERSION:
        raise VerifyError(
            f"unsupported versions packet={pv} merkle={mv} "
            f"(this verifier supports packet={PACKET_VERSION} merkle={MERKLE_VERSION})"
        )

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

    return failures


def _norm(pem: str) -> str:
    return "".join(pem.split())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="castle-verify",
        description="Standalone verifier for a Castle attestation packet "
        "(Merkle root + Ed25519 signature + inclusion proofs). Castle-free.",
    )
    parser.add_argument("packet", help="Path to the exported packet JSON.")
    parser.add_argument(
        "--pubkey",
        default=None,
        help="Path to a published Ed25519 public-key PEM to verify against "
        "(must match the key embedded in the packet). Defaults to the embedded key.",
    )
    parser.add_argument("--quiet", action="store_true", help="Only print PASS/FAIL.")
    args = parser.parse_args(argv)

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

    try:
        failures = verify_packet(packet, pubkey_pem)
    except VerifyError as exc:
        print(f"castle-verify: malformed packet: {exc}", file=sys.stderr)
        return 2

    if failures:
        print("FAIL: provenance verification failed")
        if not args.quiet:
            for f in failures:
                print(f"  - {f}")
        return 1

    if not args.quiet:
        eng = packet.get("engagement", {})
        n = len(packet.get("leaves", []))
        print(
            f"PASS: verified {n} artifact(s) for engagement "
            f"{eng.get('id')} ({eng.get('client_name')})"
        )
        print(f"  merkle_root: {packet.get('merkle_root')}")
        print("  Ed25519 signature valid; all artifact hashes + inclusion proofs hold.")
        print("  NOTE: proves integrity (unchanged + who-attested), NOT evidence completeness.")
    else:
        print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
