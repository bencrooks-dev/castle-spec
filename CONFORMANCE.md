# Conformance Registry

An implementation is **conformant** when it passes the
[conformance kit](conformance/) for a named profile, at a named spec and kit
version. This file is the public record of claims. Conformance is earned by
evidence, not granted; see [GOVERNANCE.md](GOVERNANCE.md).

## Requirements at a glance

Each requirement is falsifiable: the kit binds it to an executable check, and
the recompute formulas are stated normatively in [SPEC.md](SPEC.md).

### Schema-Core (OS-1 .. OS-7)

| ID | Requirement (one line) |
|---|---|
| OS-1 | Every governed object carries the envelope (unique `node_uid`, `engagement_id`, `content_sha256`, `content_sha256_at`, `source_ref`, `created_at`, `updated_at`) and `node_uid` uniqueness is store-enforced. |
| OS-2 | Canonical serialization is deterministic JSON: sorted keys, compact separators, UTC ISO-8601 timestamps, envelope and documented lifecycle fields excluded. |
| OS-3 | The integrity fingerprint is SHA-256 over the canonical serialization, recomputable with nothing but a hash library. |
| OS-4 | Stamping is write-once and idempotent: re-stamping returns the original hash and never silently overwrites, even after an edit. |
| OS-5 | Documented lifecycle fields (for example `risks.status`, `risks.residual_score`) may change after stamping without breaking verification. |
| OS-6 | Out-of-band mutation of an identity field after stamping is detected by verification, reporting stamped vs current hashes. |
| OS-7 | Every stamp is recorded on the engagement's hash-chained event log, and the chain verifies clean. |

### Attestation-Packet (PK-1 .. PK-5)

| ID | Requirement (one line) |
|---|---|
| PK-1 | The packet carries `packet_version`, `merkle_version`, `merkle_root`, and every leaf, so any single artifact is independently provable. |
| PK-2 | Leaf hash is `SHA-256(0x00 \|\| "{object_type}:{object_id}" \|\| 0x1F \|\| artifact_sha256)`; interior hash is `SHA-256(0x01 \|\| raw(left) \|\| raw(right))`; leaves sort ascending; odd nodes promote; the root is recomputable from the packet with a stock hash library. |
| PK-3 | The signature is Ed25519 over the canonical packet bytes (sorted-keys compact ASCII JSON, `signature` block excluded), with the public key embedded in the packet. |
| PK-4 | A standalone verifier with zero implementation imports accepts a well-formed packet. |
| PK-5 | Any tamper (leaf, root, signature, or any signed body field) fails verification closed. |

## How to claim conformance

1. Run the kit against your implementation (kit v0.1 binds the checks to the
   reference implementation; a port that preserves the recompute formulas
   verbatim makes an equivalent claim):
   ```bash
   python -m pytest conformance/ -v
   ```
2. Record the result in the required format:

   > **Castle Obligation Schema `<spec-version>` / `<profile(s)>` / kit `<kit-version>` / `<pass>/<total>`**

   Example: Castle Obligation Schema 0.1 / Schema-Core + Attestation-Packet / kit v0.1 / 14/14
3. Open a PR adding a row to the table below, linking your CI run or results
   log.

Do not advertise "Castle-schema compatible" without a named profile and
version; that claim is meaningless and is disallowed.

## Registry

| Implementation | Language | Profiles | Spec | Kit | Result | Evidence |
|---|---|---|---|---|---|---|
| [Castle](https://github.com/bencrooks-dev/Castle) (reference) | Python | Schema-Core, Attestation-Packet | 0.1 | v0.1 | 14/14 | `conformance` CI job in the Castle repository |

No implementations other than the reference implementation are registered.
That is the honest current state of a v0.1 draft.
