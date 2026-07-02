# castle_verify.py: standalone verifier

A single-file verifier for Castle Obligation Schema artifacts: attestation
packets, Transparent Statements (packet plus countersignature receipts), and
delegation chains (statement plus multi-tier endorsements). Copy this one
file plus the artifact JSON to any machine (including an air-gapped one) and
check it with no access to the producing system. It imports nothing from the
implementation; the conformance kit asserts that property (PK-4).

This copy is byte-identical to the reference implementation's
`castle_verify.py`.

You can also verify in the browser at
[castlegrc.com/verify](https://castlegrc.com/verify): the page runs this
same unmodified file client-side (Python in WebAssembly via Pyodide), so
nothing you drop on it is uploaded anywhere.

## Dependencies (honest claim)

Not zero-dependency. The verifier uses the Python standard library plus
**one** third-party package, `cryptography`, for the Ed25519 and ECDSA
signature checks. There is no other import. `cryptography` is loaded lazily,
so malformed-input errors (exit code 2) are reported even without it
installed, but a full verification requires it:

```bash
pip install cryptography
```

## Usage

```bash
python castle_verify.py ARTIFACT.json [--pubkey KEY.pem] [--trust REGISTRY.json]
                        [--require-pinned] [--quiet] [--json]
```

The artifact type (packet, Transparent Statement, or delegation chain) is
detected from the file's shape; see SPEC.md section 8.1.

- `--pubkey KEY.pem`: verify against a published public key. It must match
  the key embedded in the packet (a mismatch is reported as possible key
  substitution). Without it, the embedded key is used and reported, and the
  report says plainly that authorship is unverified.
- `--trust REGISTRY.json`: pin signing keys per tier with a trust registry
  (`trust_registry_version` 1; SPEC.md section 12). The packet signing key
  must match an `attestation_signing` entry; every countersignature receipt,
  endorsement, and delegation-record key must match a `countersign_signing`
  entry. Keys are matched on canonical DER SubjectPublicKeyInfo bytes, never
  PEM text. Fail closed: an unpinned key is a verification failure (exit 1);
  a malformed registry is a usage error (exit 2). Combines with `--pubkey`
  (both constraints apply).
- `--require-pinned`: strict mode; fail (exit 4) unless `--pubkey` is
  supplied, so authorship is verified against an out-of-band published key
  rather than the key embedded in the packet. Also enabled by the
  environment variable `CASTLE_VERIFY_REQUIRE_PINNED=1`. Use for examiner
  or CI verification.
- `--json`: emit exactly one machine-readable JSON object on stdout
  (`castle_verify_json_version` 1; SPEC.md section 13): verdict
  (`pass`/`fail`/`malformed`), exit code, artifact type, per-check pass/fail
  entries with stable ids, verbatim failure strings, a summary block, and
  `report_text`, the byte-identical human report the same invocation would
  print without `--json`. Exit codes are unchanged; `--quiet` is ignored.
  Malformed inputs still emit the JSON object (verdict `malformed`, `error`
  set), so a consumer of stdout can always parse it.
- `--quiet`: print only PASS or FAIL.

Exit codes: `0` all checks pass, `1` a verification check failed, `2` usage
error or malformed input (including a malformed trust registry), `4`
`--require-pinned` set without `--pubkey`.

Try it on the sample in this repository:

```bash
python verifier/castle_verify.py samples/sample-packet.json
```

## What a PASS proves (and does not)

Checks performed, per [SPEC.md](../SPEC.md) sections 8 through 12:

1. Merkle root: rebuilt from the packet's leaves and compared to the
   committed `merkle_root`.
2. Per-artifact hashes: every `leaf_hash` recomputed from
   `(object_type, object_id, artifact_sha256)`.
3. Inclusion proofs: every leaf independently reconstructs the root.
4. Ed25519 signature: valid over the canonical packet bytes for the
   public key.
5. Public anchor (when present and claiming `anchored`): the packet's
   Merkle root is provably included in the public Sigstore Rekor
   transparency log, verified fully offline.
6. Countersignature receipts and endorsements (for statements and chains):
   each signature valid, each binding to this exact packet or statement
   intact, each recorded verification result honest.
7. Trust registry (with `--trust`): every signing key at every tier matches
   a registered identity for the right purpose.

A PASS proves the attested artifacts are unchanged as a set and were signed
by the holder of the reported keys (integrity plus who-signed). It does NOT
prove the underlying evidence is complete or real, and it is not a
certification or compliance status. For who-attested trust, pin the
signer's published public key out of band (`--pubkey`, `--require-pinned`)
or pin every tier with a trust registry (`--trust`) rather than trusting
embedded keys alone.
