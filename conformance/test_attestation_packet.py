"""Attestation-Packet conformance checks (PK-1 .. PK-5).

The point of the packet format is that an auditor needs NOTHING from the
implementation to verify it. So these checks recompute the Merkle root with
nothing but ``hashlib``, verify the signature with stock ``cryptography``
primitives, and run the standalone verifier loaded by file path the way an
auditor would, asserting it is import-isolated from the implementation.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from castle import attestation

REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = REPO_ROOT / "verifier" / "castle_verify.py"

ARTIFACTS = [
    ("approval", 3, hashlib.sha256(b"a").hexdigest()),
    ("task", 1, hashlib.sha256(b"b").hexdigest()),
    ("approval", 1, hashlib.sha256(b"c").hexdigest()),
    ("risk", 7, hashlib.sha256(b"d").hexdigest()),
    ("evidence", 2, hashlib.sha256(b"e").hexdigest()),
]


# -- Independent recompute primitives (PK-2, stdlib only) ----------------------
# These formulas ARE the requirement: a conformant packet producer in any
# language must hash exactly this way, domain-separation prefixes included.


def _leaf_hash(object_type: str, object_id: int, artifact_sha256: str) -> str:
    content = f"{object_type}:{object_id}\x1f{artifact_sha256}"
    return hashlib.sha256(b"\x00" + content.encode("utf-8")).hexdigest()


def _node_hash(left: str, right: str) -> str:
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def _root_from_leaves(leaf_hashes: list[str]) -> str:
    if not leaf_hashes:
        return hashlib.sha256(b"").hexdigest()
    level = list(leaf_hashes)
    while len(level) > 1:
        level = [
            _node_hash(level[i], level[i + 1]) if i + 1 < len(level) else level[i]
            for i in range(0, len(level), 2)
        ]
    return level[0]


def _canonical_packet_bytes(packet: dict) -> bytes:
    body = {k: v for k, v in packet.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


# -- Fixtures ------------------------------------------------------------------


@pytest.fixture()
def keypair(tmp_path, monkeypatch):
    monkeypatch.setenv("CASTLE_SIGNING_KEY", str(tmp_path / "k.pem"))
    monkeypatch.setenv("CASTLE_SIGNING_PUBKEY", str(tmp_path / "k.pub.pem"))
    attestation.generate_keypair()


@pytest.fixture()
def signed_packet(keypair):
    packet = attestation.build_packet(
        engagement_id=7,
        client_name="Conformance Co",
        artifacts=list(ARTIFACTS),
        flat_manifest_text="# flat\n",
        flat_manifest_sha256=hashlib.sha256(b"# flat\n").hexdigest(),
    )
    return attestation.sign_packet(packet)


@pytest.fixture()
def standalone_verifier():
    spec = importlib.util.spec_from_file_location("castle_verify_conformance", VERIFIER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# -- PK-1 ----------------------------------------------------------------------


def test_packet_carries_versioned_merkle_structure(signed_packet):
    assert signed_packet["packet_version"] == 1
    assert signed_packet["merkle_version"] == 1
    assert len(signed_packet["merkle_root"]) == 64
    assert len(signed_packet["leaves"]) == len(ARTIFACTS)
    for leaf in signed_packet["leaves"]:
        assert {"object_type", "object_id", "artifact_sha256"} <= set(leaf)


# -- PK-2 ----------------------------------------------------------------------


def test_merkle_root_recomputable_with_stdlib(signed_packet):
    leaf_hashes = [
        _leaf_hash(leaf["object_type"], leaf["object_id"], leaf["artifact_sha256"])
        for leaf in signed_packet["leaves"]
    ]
    assert _root_from_leaves(leaf_hashes) == signed_packet["merkle_root"]


# -- PK-3 ----------------------------------------------------------------------


def test_signature_verifiable_with_stock_crypto(signed_packet):
    sig = signed_packet["signature"]
    assert sig["algorithm"] == "ed25519"
    public_key = load_pem_public_key(sig["public_key_pem"].encode("ascii"))
    body = _canonical_packet_bytes(signed_packet)
    public_key.verify(bytes.fromhex(sig["value"]), body)  # raises on mismatch
    assert sig["signed_sha256"] == hashlib.sha256(body).hexdigest()


# -- PK-4 ----------------------------------------------------------------------


def test_standalone_verifier_accepts_packet(signed_packet, standalone_verifier):
    assert standalone_verifier.verify_packet(signed_packet) == []


def test_standalone_verifier_is_import_isolated():
    source = VERIFIER_PATH.read_text(encoding="utf-8")
    for line in source.splitlines():
        stripped = line.strip()
        assert not stripped.startswith(("import castle.", "from castle ", "from castle.")), (
            f"standalone verifier imports the implementation: {stripped!r}"
        )


# -- PK-5 ----------------------------------------------------------------------


def test_tampering_fails_closed(signed_packet, standalone_verifier):
    # Tamper a leaf.
    tampered = json.loads(json.dumps(signed_packet))
    tampered["leaves"][0]["artifact_sha256"] = "0" * 64
    assert standalone_verifier.verify_packet(tampered) != []

    # Tamper the root.
    tampered = json.loads(json.dumps(signed_packet))
    tampered["merkle_root"] = "f" * 64
    assert standalone_verifier.verify_packet(tampered) != []

    # Tamper the signature.
    tampered = json.loads(json.dumps(signed_packet))
    value = tampered["signature"]["value"]
    tampered["signature"]["value"] = ("0" if value[0] != "0" else "1") + value[1:]
    assert standalone_verifier.verify_packet(tampered) != []

    # Tamper a signed body field.
    tampered = json.loads(json.dumps(signed_packet))
    tampered["engagement"]["client_name"] = "Mallory Inc"
    assert standalone_verifier.verify_packet(tampered) != []
