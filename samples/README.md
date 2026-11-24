# Sample attestation packet

A complete, signed attestation packet so a stranger can run the verifier end
to end in under a minute.

What it is, honestly:

- **Synthetic data.** Generated from the reference implementation's seeded
  demo engagement ("Northwind Mutual Insurance" is fictional). It is not a
  customer, not a real engagement, and not evidence of anything.
- **Throwaway key.** Signed with an Ed25519 keypair generated in a temp
  directory solely for this sample. The embedded public key identifies
  nobody and pins nothing; it exists so the signature check has something to
  verify.

## Files

| File | What it is |
|---|---|
| `sample-packet.json` | Signed packet: 10 stamped artifacts, Merkle root, every leaf, Ed25519 signature block with embedded public key. |
| `expected-output.txt` | Byte-for-byte expected stdout of a successful verification. |

## Verify it

```bash
pip install cryptography
python verifier/castle_verify.py samples/sample-packet.json
```

Expected: exit code 0 and the output in `expected-output.txt`, beginning

```
PASS: verified 10 artifact(s) for engagement 1 (Northwind Mutual Insurance)
```

The transcript includes a WARNING that authorship is unverified. That is
expected and correct: no `--pubkey` is pinned (the sample key is a
throwaway), so the verifier proves integrity only and says so.

Then prove to yourself it fails closed: change any character of any
`artifact_sha256`, the `merkle_root`, the signature, or the client name, and
run it again. Exit code 1.

## How it was generated

From the reference implementation (Castle), against a temporary database and
temporary keys, nothing touched outside a temp directory and this folder:

```bash
python -c "from castle.attestation import generate_keypair; generate_keypair()"
castle --db sqlite:///$TMP/demo.db demo-seed
castle --db sqlite:///$TMP/demo.db verify --engagement 1 \
  --export-packet samples/sample-packet.json --sign
```

(with `CASTLE_SIGNING_KEY` and `CASTLE_SIGNING_PUBKEY` pointed at the temp
directory). Regenerating produces a different `generated_at`, a different
signature, and (with a fresh key) a different embedded public key; the Merkle
structure of the same seeded data is deterministic.

## Sample partner submission (PDS lite)

| File | What it is |
|---|---|
| `sample-submission.json` | A PDS 0.1 manifest from a fictional MGA ("Keystone Underwriters") to a fictional carrier: a continuity plan and an E&O certificate. |
| `sample-submission.zip` | The same manifest as `manifest.json` plus the two synthetic text files, ready for the receiver. |

```bash
python verifier/pds_check.py samples/sample-submission.zip --today 2026-11-24
```

Expected: exit code 0 and both items `received`. Run it with `--today 2027-07-01`
and the certificate is rejected as `expired` (exit code 1).
