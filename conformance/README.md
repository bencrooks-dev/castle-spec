# Conformance Kit v0.1

Executable proof that an implementation satisfies the
[Castle Obligation Schema](../SPEC.md) integrity contract. This is the third
artifact a standard needs, alongside the spec and a reference implementation:
a test corpus a third party can run (or port) to make a credible, falsifiable
conformance claim.

Kit version: **v0.1**. Schema spec version: **0.1 (Draft)**.

## Honest coupling note (read this first)

Kit v0.1 ships **coupled to the reference implementation**: the checks are
pytest functions that exercise Castle's Python API directly (`castle.*`
imports). There is no implementation-neutral adapter interface yet; designing
one is [RFC material](../rfcs/README.md), and pretending otherwise with a
half-built shim would be fake portability.

What this means in practice:

- Running this kit as-is validates the **reference implementation** against
  the spec. That is still useful here: it pins the executable meaning of every
  requirement, and the spec's recompute formulas
  ([SPEC.md](../SPEC.md) sections 3, 4, 5, 6, and 7) are stated
  implementation-neutrally.
- A second implementation in another language demonstrates conformance by
  **porting the checks**, preserving the recompute formulas verbatim (the
  stdlib-only recompute helpers at the top of `test_attestation_packet.py`
  are the requirement, not Castle's internals).
- The one adaptation in this copy of the kit: `test_attestation_packet.py`
  loads the standalone verifier from this repository's `verifier/` directory
  instead of the Castle repository root.

## Run it

Requires the reference implementation to be importable (it is a private
repository at the time of writing; access on request):

```bash
pip install -e /path/to/Castle
python -m pytest conformance/ -v
```

Expected: 14 passed (8 Schema-Core checks covering OS-1..OS-7, 6
Attestation-Packet checks covering PK-1..PK-5).

## Profiles and requirements

### Schema-Core ([SPEC.md](../SPEC.md) sections 2 through 5)

| ID | Requirement | Test |
|---|---|---|
| OS-1 | Every node carries the envelope: unique `node_uid`, `engagement_id`, `content_sha256`, `content_sha256_at`, `source_ref`, `created_at`, `updated_at`. | `test_schema_core.py::test_node_envelope_columns_present`, `::test_node_uid_uniqueness_enforced` |
| OS-2 | Canonical serialization is deterministic JSON: sorted keys, compact separators, UTC ISO-8601 datetimes, envelope and documented lifecycle columns excluded. | `test_schema_core.py::test_canonical_serialization_is_deterministic_json` |
| OS-3 | The integrity fingerprint is SHA-256 over the canonical serialization, recomputable with nothing but a hash library. | `test_schema_core.py::test_fingerprint_recomputable_with_stdlib_sha256` |
| OS-4 | Stamping is write-once and idempotent: re-stamping returns the original hash, never silently overwrites. | `test_schema_core.py::test_stamp_is_write_once` |
| OS-5 | Documented lifecycle fields (for example `risks.status`, `risks.residual_score`) may change after stamping without breaking verification. | `test_schema_core.py::test_lifecycle_fields_mutate_without_breaking_verification` |
| OS-6 | Out-of-band mutation of an identity field after stamping is detected by graph verification, reporting stamped vs current hashes. | `test_schema_core.py::test_identity_tampering_is_detected` |
| OS-7 | Every stamp is recorded on the engagement's hash-chained event log, and the chain verifies clean. | `test_schema_core.py::test_stamp_lands_on_intact_event_chain` |

### Attestation-Packet ([SPEC.md](../SPEC.md) sections 6 through 8)

| ID | Requirement | Test |
|---|---|---|
| PK-1 | The packet carries `packet_version`, `merkle_version`, `merkle_root`, and every leaf, so any single artifact is independently provable. | `test_attestation_packet.py::test_packet_carries_versioned_merkle_structure` |
| PK-2 | Leaf hash is `sha256(0x00 \|\| "{object_type}:{object_id}" 0x1F "{artifact_sha256}")`; interior hash is `sha256(0x01 \|\| left_raw \|\| right_raw)`; odd nodes promote. The root is recomputable from the packet with a stock hash library. | `test_attestation_packet.py::test_merkle_root_recomputable_with_stdlib` |
| PK-3 | The signature is Ed25519 over the canonical packet bytes (sorted-keys compact JSON, `signature` block excluded), with the public key embedded in the packet. | `test_attestation_packet.py::test_signature_verifiable_with_stock_crypto` |
| PK-4 | A standalone verifier with zero implementation imports accepts a well-formed packet. | `test_attestation_packet.py::test_standalone_verifier_accepts_packet`, `::test_standalone_verifier_is_import_isolated` |
| PK-5 | Any tamper (leaf, root, or signature) fails verification closed. | `test_attestation_packet.py::test_tampering_fails_closed` |

Planned for a later kit version: an Event-Chain profile covering the
hash-chained event log requirements of [SPEC.md](../SPEC.md) section 5
directly (the reference implementation already tests these internally).

## Claiming conformance

A conformance claim MUST name the profile(s), the spec version, and the kit
version, for example:

> **Castle Obligation Schema 0.1 / Schema-Core + Attestation-Packet / kit v0.1 / 14/14 passing**

Do not advertise "Castle-schema compatible" without a named profile and
version. Record claims in the public registry:
[CONFORMANCE.md](../CONFORMANCE.md).
