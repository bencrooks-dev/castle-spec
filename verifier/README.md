# castle_verify.py: standalone packet verifier

A single-file verifier for Castle Obligation Schema attestation packets.
Copy this one file plus a packet JSON to any machine (including an air-gapped
one) and check the packet with no access to the producing system. It imports
nothing from the implementation; the conformance kit asserts that property
(PK-4).

This copy is byte-identical in code to the reference implementation's
`castle_verify.py`; only docstring punctuation differs.

## Dependencies (honest claim)

Not zero-dependency. The verifier uses the Python standard library plus
**one** third-party package, `cryptography`, for the Ed25519 signature check.
There is no other import. `cryptography` is loaded lazily, so malformed-packet
errors (exit code 2) are reported even without it installed, but a full
verification requires it:

```bash
pip install cryptography
```

## Usage

```bash
python castle_verify.py PACKET.json [--pubkey KEY.pem] [--quiet]
```

- `--pubkey KEY.pem`: verify against a published public key. It must match
  the key embedded in the packet (a mismatch is reported as possible key
  substitution). Without it, the embedded key is used and reported.
- `--quiet`: print only PASS or FAIL.

Exit codes: `0` all checks pass, `1` a verification check failed, `2` usage
or malformed-packet error.

Try it on the sample in this repository:

```bash
python verifier/castle_verify.py samples/sample-packet.json
```

## What a PASS proves (and does not)

Checks performed, per [SPEC.md](../SPEC.md) section 8:

1. Merkle root: rebuilt from the packet's leaves and compared to the
   committed `merkle_root`.
2. Per-artifact hashes: every `leaf_hash` recomputed from
   `(object_type, object_id, artifact_sha256)`.
3. Inclusion proofs: every leaf independently reconstructs the root.
4. Ed25519 signature: valid over the canonical packet bytes for the
   public key.

A PASS proves the attested artifacts are unchanged as a set and were signed
by the holder of this key (integrity plus who-attested). It does NOT prove
the underlying evidence is complete or real, and it is not a certification
or compliance status. For who-attested trust, pin the signer's published
public key out of band rather than trusting the embedded copy alone.
