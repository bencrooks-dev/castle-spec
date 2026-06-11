# Castle Obligation Schema

**Version:** 0.1 (Draft)
**Status:** Pre-release draft. Normative wording may change before 1.0 via the [RFC process](rfcs/README.md).
**License:** Specification text CC BY 4.0 (see [LICENSE](LICENSE)).

This document specifies an open integrity format for AI-governance evidence:
how governed objects are serialized and fingerprinted, how governance events
are hash-chained, and how a portable attestation packet is built, signed with
Ed25519, and verified with no access to the producing system.

The specification is written to be implementable standalone. No part of the
format requires importing or running the reference implementation (Castle).
Worked example values in Appendix A allow an implementer to check their
primitives byte for byte.

Honesty note: this is a draft with a single implementation (Castle, the
reference implementation). No other adopters are claimed. A verified packet
proves integrity (the attested artifacts are unchanged as a set, signed by the
holder of a key), NOT that the underlying evidence is complete, real, or that
any engagement is "passing".

## 1. Terminology and conventions

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in RFC 2119.

- **Governed object (node):** a record under governance (a risk, remediation,
  system, vendor, obligation, or similar) carrying the envelope of section 2.
- **Engagement:** the scoping unit for a body of evidence. Every governed
  object and event belongs to exactly one engagement.
- **Artifact:** any stamped object referenced by an attestation packet,
  identified by `(object_type, object_id)` plus its stamped content hash.
- **Hex digest:** lowercase hexadecimal encoding of a hash output. All hashes
  in this specification are SHA-256 (FIPS 180-4); a hex digest is therefore
  64 characters.
- **Canonical JSON:** JSON serialized with lexicographically sorted keys and
  compact separators (`,` and `:`), no insignificant whitespace.

## 2. Governed-object envelope

<!-- source: conformance/test_schema_core.py:26-34 (Castle reference implementation, ENVELOPE_COLUMNS) -->
Every governed-object type MUST carry these envelope fields:

| Field | Type | Meaning |
|---|---|---|
| `node_uid` | string, unique | Stable identity of the object across its life. Uniqueness MUST be enforced by the store. |
| `engagement_id` | integer | The engagement this object belongs to. |
| `content_sha256` | hex digest, nullable until stamped | Write-once integrity fingerprint (section 4). |
| `content_sha256_at` | timestamp, nullable until stamped | When the fingerprint was stamped. |
| `source_ref` | string, nullable | Provenance pointer to the object's origin (document, system, import). |
| `created_at` | timestamp | Row creation time. |
| `updated_at` | timestamp | Row last-update time. |

`created_at`, `updated_at`, `content_sha256`, and `content_sha256_at` are
bookkeeping: they are excluded from the canonical serialization (section 3) so
that legitimate bookkeeping churn never breaks verification.

## 3. Canonical serialization of governed objects

<!-- source: castle/obligation_graph.py:131-149 (canonical_serialization) -->
The canonical serialization of a governed object is the canonical JSON of its
persisted fields, subject to the following rules:

1. **Excluded always** <!-- source: castle/obligation_graph.py:64-70 (_FINGERPRINT_EXCLUDE) -->:
   the surrogate primary key (`id`), the stamp fields (`content_sha256`,
   `content_sha256_at`), and the bookkeeping timestamps (`created_at`,
   `updated_at`) MUST be excluded.
2. **Excluded per type (lifecycle fields)** <!-- source: castle/obligation_graph.py:77-128 (_FINGERPRINT_EXCLUDE_BY_TABLE) -->:
   each object type MAY declare additional excluded fields that legitimately
   evolve after creation (for example `risks.status` and
   `risks.residual_score` in the reference implementation). The exclusion
   list for each type MUST be documented and fixed; changing it for stamped
   data is a breaking change. The evolution of excluded lifecycle fields
   SHOULD be tracked on the event chain (section 5) instead.
3. **Timestamps** <!-- source: castle/obligation_graph.py:146-147 -->:
   datetime values MUST be rendered in UTC with microsecond precision and a
   literal `Z` suffix, format `%Y-%m-%dT%H:%M:%S.%fZ`
   (example: `2026-06-10T14:03:07.123456Z`).
4. **Serialization** <!-- source: castle/obligation_graph.py:149 -->:
   the remaining field map MUST be serialized as canonical JSON (sorted keys,
   compact separators). Values that are not JSON-native are coerced to their
   string representation in the reference implementation; implementations
   SHOULD restrict governed fields to JSON-native types so coercion never
   matters.

Re-serializing at verification time MUST reproduce the write-time bytes
exactly; determinism of this serialization is what makes the fingerprint
(section 4) recomputable by a third party.

## 4. Content hashing and write-once stamping

<!-- source: castle/obligation_graph.py:152-199 (stamp_node) -->
The integrity fingerprint of a governed object is:

```
content_sha256 = SHA-256( UTF-8( canonical_serialization(object) ) )
```

expressed as a hex digest. It MUST be recomputable with nothing but a hash
library and the canonical serialization rules of section 3
<!-- source: conformance/test_schema_core.py:114-118 (OS-3) -->.

Stamping rules:

1. **Write-once.** If an object already has a `content_sha256`, stamping MUST
   return the existing value unchanged and MUST NOT overwrite it
   <!-- source: castle/obligation_graph.py:169-171; conformance/test_schema_core.py:124-134 (OS-4) -->.
   An edit to an identity field after stamping MUST surface as a verification
   mismatch, never as a silent re-hash.
2. **Lifecycle safety.** Mutating a documented lifecycle field (section 3
   rule 2) after stamping MUST NOT break verification
   <!-- source: conformance/test_schema_core.py:139-143 (OS-5) -->.
3. **Tamper detection.** Verification recomputes the fingerprint of every
   stamped object and MUST report any object whose recomputed hash differs
   from the stamped hash, including both the stamped and the current hash
   <!-- source: conformance/test_schema_core.py:149-163 (OS-6) -->.
4. **Event recording.** Every stamp MUST be recorded as an event
   (`node_integrity_stamped` in the reference implementation) on the
   engagement's hash chain (section 5), and the chain MUST verify clean
   afterwards <!-- source: castle/obligation_graph.py:188-198; conformance/test_schema_core.py:168-171 (OS-7) -->.

## 5. Event hash chain

Every engagement has an append-only event log. Each event is fingerprinted
and linked to its predecessor so that rewriting any historical event breaks
every subsequent link.

### 5.1 Event fingerprint

<!-- source: castle/event_log.py:185-207 (_compute_event_sha) -->
The event fingerprint is:

```
event_sha = SHA-256( UTF-8( engagement_id || "|" || ts || "|" || actor || "|"
                            || event_type || "|" || phase || "|"
                            || payload_json || "|" || prev_event_sha ) )
```

where the seven fields are joined with the pipe character `|` (0x7C) and:

- `engagement_id` is the decimal rendering of the engagement integer id;
- `ts` is the event time in UTC, microsecond precision, literal `Z` suffix,
  format `%Y-%m-%dT%H:%M:%S.%fZ`
  <!-- source: castle/event_log.py:172-182 (_canonical_ts) -->;
- `actor` is the acting identity string;
- `event_type` is the event type string;
- `phase` is the phase string, or the empty string when absent
  <!-- source: castle/event_log.py:202 -->;
- `payload_json` is the canonical JSON of the payload object, with `{}` for
  an absent payload <!-- source: castle/event_log.py:167-169 (_canonical_payload) -->;
- `prev_event_sha` is the previous event's `event_sha`, or the literal string
  `GENESIS` for the first event of an engagement
  <!-- source: castle/event_log.py:155 -->.

Interoperability note: the join is delimiter-based. Producers SHOULD NOT
permit the pipe character in `actor`, `event_type`, or `phase`; payloads are
safe because canonical JSON escapes nothing into a bare pipe ambiguity only
if other fields also contain pipes.

### 5.2 Chain rules

<!-- source: castle/event_log.py:215-279 (emit_event) -->
1. Events of an engagement form a single linear chain ordered by insertion.
2. A new event's `prev_event_sha` MUST be the `event_sha` of the current
   chain head, or `GENESIS` when the chain is empty.
3. Implementations MUST prevent two events of the same engagement sharing
   the same `prev_event_sha` (fork prevention). The reference implementation
   enforces this with a unique constraint on
   `(engagement_id, prev_event_sha)` and retries the loser
   <!-- source: castle/event_log.py:236-244 -->.
4. Chain verification MUST walk the chain from `GENESIS`, check every
   `prev_event_sha` link, recompute every `event_sha`, and report the first
   break <!-- source: castle/event_log.py:449-488 (verify_event_chain) -->.

## 6. Attestation packet

The attestation packet is a portable, self-describing JSON document that
carries everything a verifier needs: the artifact set, a Merkle commitment
over it, and (when signed) an Ed25519 signature with the public key embedded.

### 6.1 Packet fields

<!-- source: castle/attestation.py:159-189 (build_packet); conformance/test_attestation_packet.py:101-107 (PK-1) -->
An unsigned packet MUST contain:

| Field | Type | Meaning |
|---|---|---|
| `packet_version` | integer | Packet format version. This specification defines version `1` <!-- source: castle/attestation.py:51 (PACKET_VERSION) -->. |
| `merkle_version` | integer | Merkle encoding version. This specification defines version `1` <!-- source: castle/merkle.py:49 (MERKLE_VERSION) -->. |
| `engagement` | object | `{ "id": <integer>, "client_name": <string> }`. |
| `generated_at` | string | Packet creation time, ISO 8601 in UTC. The reference implementation emits an offset form such as `2026-06-10T14:03:07.123456+00:00` <!-- source: castle/attestation.py:180 -->. Informational; covered by the signature but not recomputed by verifiers. |
| `merkle_root` | hex digest | Root of the Merkle tree over all leaves (section 6.3). |
| `leaves` | array | Every artifact leaf (section 6.2), so any single artifact is independently provable. |
| `flat_manifest` | object | `{ "text": <string>, "sha256": <hex digest> }`. A human-readable manifest carried verbatim for reference-implementation compatibility. Informative; verifiers of this specification do not recompute it <!-- source: castle/attestation.py:184-188 -->. |

A signed packet additionally contains a top-level `signature` object
(section 7). Verifiers MUST ignore unknown additional fields inside
`signature` (additive evolution, for example `key_version`
<!-- source: castle/attestation.py:241-242 -->).

### 6.2 Leaves

Each element of `leaves` MUST contain:

| Field | Type |
|---|---|
| `object_type` | string |
| `object_id` | integer |
| `artifact_sha256` | hex digest (the stamped `content_sha256` of section 4) |
| `leaf_hash` | hex digest (recomputable; see below) |

The leaf preimage binds the artifact's stamped hash to its stable identity:

```
leaf_content = "{object_type}:{object_id}" || 0x1F || artifact_sha256
leaf_hash    = SHA-256( 0x00 || UTF-8(leaf_content) )
```

<!-- source: castle/merkle.py:36-44 (_LEAF_PREFIX, _FIELD_SEP), castle/merkle.py:52-63 (leaf_content, hash_leaf); castle_verify.py:48-63; conformance/test_attestation_packet.py:39-41 (PK-2) -->

- `object_id` is rendered in decimal.
- The unit separator byte `0x1F` joins the identity and the hash. It cannot
  occur in either side (ids are integers, hashes are hex), so the encoding is
  unambiguous.
- The single byte `0x00` is the leaf domain prefix (RFC 6962 style).

### 6.3 Merkle tree construction

<!-- source: castle/merkle.py:156-200 (build_leaves, build_tree); castle_verify.py:66-84; conformance/test_attestation_packet.py:44-57 (PK-2) -->

1. Compute the `leaf_hash` of every artifact (section 6.2).
2. Sort the leaf hashes ascending (lexicographic order of the lowercase hex
   strings, equivalent to bytewise order). The tree shape and root are
   therefore independent of input order. A proof's `leaf_index` refers to a
   position in this sorted order <!-- source: castle/merkle.py:156-173 -->.
3. Level 0 is the sorted leaf-hash list. To build each next level, pair
   adjacent nodes left to right:

   ```
   parent = SHA-256( 0x01 || raw(left) || raw(right) )
   ```

   where `raw()` is the 32-byte decoding of the hex digest and `0x01` is the
   interior-node domain prefix
   <!-- source: castle/merkle.py:37,66-68 (hash_nodes) -->.
   Note the asymmetry: leaves hash UTF-8 text, interior nodes hash raw bytes.
4. **Odd promotion:** a trailing node with no sibling MUST be promoted to the
   next level unchanged. It MUST NOT be duplicated (this avoids the
   CVE-2012-2459 duplicate-leaf ambiguity)
   <!-- source: castle/merkle.py:189-199 -->.
5. The root is the single hash of the final level.
6. **Empty set:** a packet with zero leaves MUST commit to
   `merkle_root = SHA-256(empty input) =`
   `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
   <!-- source: castle/merkle.py:183-185 -->.

Domain separation rationale: the `0x00`/`0x01` prefixes keep the leaf and
interior hash spaces disjoint, defending against second-preimage confusion
between a leaf and an interior node.

### 6.4 Inclusion proofs

<!-- source: castle/merkle.py:133-153 (inclusion_proof), castle/merkle.py:203-213 (verify_inclusion); castle_verify.py:87-109 -->
An inclusion proof for the leaf at `leaf_index` is the list of sibling steps
from level 0 upward. At each level, if the running node has a sibling, the
step records the sibling's hex digest and its `position` relative to the
running hash (`"left"` or `"right"`); a promoted node contributes no step at
that level.

Verification folds the steps over the leaf hash:

- `position == "left"`: `running = SHA-256(0x01 || raw(sibling) || raw(running))`
- `position == "right"`: `running = SHA-256(0x01 || raw(running) || raw(sibling))`

The proof is valid if and only if the final `running` equals the root.

## 7. Ed25519 signing

<!-- source: castle/attestation.py:146-156 (canonical_packet_bytes), castle/attestation.py:217-243 (sign_packet); conformance/test_attestation_packet.py:124-130 (PK-3) -->

### 7.1 Canonical packet bytes

The bytes that are hashed and signed are:

```
body  = packet object minus the top-level "signature" key
bytes = UTF-8( canonical JSON of body, ASCII-escaped )
```

Concretely (Python semantics of the reference implementation):
`json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
Non-ASCII characters MUST be escaped (`\uXXXX`), keys MUST be sorted at every
nesting level, and no whitespace is emitted. The signature block is excluded
because it cannot sign itself.

### 7.2 Signature block

Signing computes an Ed25519 (RFC 8032) signature over the canonical packet
bytes and attaches:

```json
"signature": {
  "algorithm": "ed25519",
  "value": "<128 lowercase hex chars>",
  "public_key_pem": "<PEM, SubjectPublicKeyInfo>",
  "signed_sha256": "<hex SHA-256 of the signed bytes>"
}
```

- `algorithm` MUST be `"ed25519"`.
- `value` is the hex encoding of the 64-byte signature.
- `public_key_pem` embeds the signer's public key so the packet is
  self-describing. For who-attested trust beyond the packet itself, the
  public key SHOULD be published and pinned out of band.
- `signed_sha256` is a convenience digest of the canonical bytes; verifiers
  MAY recompute it.
- Additional fields (for example `key_version`) MAY be present; verifiers
  MUST ignore fields they do not check.

## 8. Verification algorithm

<!-- source: castle_verify.py:129-215 (verify_packet), castle_verify.py:23-24,260-279 (exit codes) -->
A verifier, given a packet (and optionally an out-of-band public key), MUST
perform these steps:

1. **Version gate.** If `packet_version != 1` or `merkle_version != 1`,
   reject as malformed (do not attempt verification with different rules)
   <!-- source: castle_verify.py:141-147 -->.
2. **Shape gate.** If `leaves` is not a list or `merkle_root` is not a
   string, reject as malformed <!-- source: castle_verify.py:149-152 -->.
3. **Per-leaf recompute.** For every leaf, recompute the leaf hash from
   `(object_type, object_id, artifact_sha256)` per section 6.2. A mismatch
   with the claimed `leaf_hash` is a verification failure
   <!-- source: castle_verify.py:154-170 -->.
4. **Root recompute.** Sort the recomputed leaf hashes ascending, rebuild the
   tree per section 6.3, and compare to `merkle_root`. A mismatch is a
   verification failure <!-- source: castle_verify.py:172-178 -->.
5. **Inclusion proofs.** For every leaf index, build the inclusion proof from
   the rebuilt levels and verify it folds back to the rebuilt root
   (section 6.4). Any failure is a verification failure
   <!-- source: castle_verify.py:180-185 -->.
6. **Signature.** If the packet has no `signature` object, report it as
   unsigned (a failure for verifiers requiring signed packets). If an
   out-of-band public key is supplied, it MUST match the embedded
   `public_key_pem` after whitespace normalization; a mismatch is a failure
   (possible key substitution) <!-- source: castle_verify.py:197-201,218-219 -->.
   Parse the key (it MUST be Ed25519) and verify `signature.value` over the
   canonical packet bytes of section 7.1. An invalid signature is a failure
   <!-- source: castle_verify.py:202-213 -->.
7. **Fail closed.** Any tamper to a leaf, the root, the signature, or any
   signed body field MUST cause failure
   <!-- source: conformance/test_attestation_packet.py:152-172 (PK-5) -->.

Outcome contract of the reference verifier: exit `0` when all checks pass,
`1` when any verification check fails, `2` for a malformed packet or usage
error.

A passing verification proves the artifact set is unchanged and was signed by
the holder of the embedded key. It does NOT prove the evidence is complete,
truthful, or endorsed by anyone.

## 9. Conformance

Conformance is claimed per profile, against a named spec version and kit
version, by passing the executable [conformance kit](conformance/). The
profiles and their falsifiable requirements are registered in
[CONFORMANCE.md](CONFORMANCE.md):

- **Schema-Core (OS-1 .. OS-7):** envelope, canonical serialization,
  SHA-256 write-once stamping, lifecycle-safe verification, tamper detection,
  event-chain recording.
- **Attestation-Packet (PK-1 .. PK-5):** versioned Merkle packet,
  domain-separated hashing, Ed25519 over canonical bytes, standalone
  zero-implementation-import verification, fail-closed tampering.

A claim MUST name the profile(s), the spec version, and the kit version.
"Compatible" without those qualifiers is not a conformance claim.

In kit v0.1 the executable checks are written in pytest against the reference
implementation's Python API; porting the recompute formulas (sections 4, 6,
and 7 of this document) to another stack is sufficient for an equivalent
claim. An implementation-neutral adapter interface is RFC material.

## 10. Security considerations

- **Integrity, not completeness.** All mechanisms here detect modification of
  what was recorded. None of them can prove that everything relevant was
  recorded. Consumers MUST NOT present a PASS as an audit opinion.
- **Key custody.** The Ed25519 private key is the attestation identity.
  It MUST NOT be committed to version control; the reference implementation
  refuses to overwrite an existing key rather than silently rotating identity
  <!-- source: castle/attestation.py:85-95 -->.
- **Embedded-key trust.** A packet verified only against its embedded key
  proves internal consistency. Binding the attestation to a real-world
  identity requires publishing and pinning the public key out of band.
- **Local transparency log.** The reference implementation appends each
  attestation to a hash-chained local log (genesis link `0` x 64, entry hash
  SHA-256 over `prev_hash + canonical body`)
  <!-- source: castle/attestation.py:258,261-264,281-314 -->. This is a
  single-writer local file: it makes the sequence tamper-evident, but it is
  NOT a public witnessed transparency service, and this specification does
  not claim otherwise.
- **Delimiter discipline.** See the interoperability note in section 5.1.

## 11. Versioning

`packet_version` and `merkle_version` gate breaking changes: a verifier MUST
refuse versions it does not implement (section 8 step 1) rather than guess.
Within a version, evolution MUST be additive (new optional fields), and
verifiers MUST tolerate unknown additive fields they do not check. Changes to
this document follow the [RFC process](rfcs/README.md).

## Appendix A: Worked example (informative, values generated from the reference implementation)

Artifact set (the conformance kit's PK fixtures
<!-- source: conformance/test_attestation_packet.py:25-31 -->), where the
artifact hashes are SHA-256 of the single bytes `a`, `b`, `c`, `d`, `e`:

| object | artifact_sha256 |
|---|---|
| approval:3 | `ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb` |
| task:1 | `3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d` |
| approval:1 | `2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6` |
| risk:7 | `18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4` |
| evidence:2 | `3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea` |

Leaf hashes (section 6.2), then sorted into tree order:

| sorted index | leaf | leaf_hash |
|---|---|---|
| 0 | approval:3 | `04393d1f1e564260a316ec9f870e31f84740f1501f1835d703fc0428e979fbae` |
| 1 | evidence:2 | `5317e52f996d6af9486cccdd3ec87d73c6942491db861f331cf64f92935c1d53` |
| 2 | risk:7 | `6c646c45e0b3693360c77b04688a5bbdf0de5eea529c27d93bb95f7b15b67ee0` |
| 3 | task:1 | `7fa27af7c4a55a846aca4bb0005682a7934318d2329aa73f7d38608270f9ddcb` |
| 4 | approval:1 | `962f4462c39ecd803d83cc86060adee5bad5626a8fa37b385f18565b6eb4efb5` |

Levels (odd nodes promote unchanged):

```
level 1: 6404c670db8326abd1dc5d9306f8cd8383de93e6afd7adc909a36298108951b1
         eb3f71b028ffa65bc2012c09081bdcfb01f200ccd5d58d2bd0f85f11eacc650b
         962f4462c39ecd803d83cc86060adee5bad5626a8fa37b385f18565b6eb4efb5
level 2: 62f387d0e8721fd164a4a8381388d91a905bc26efa6a4120a14575160e9b1f97
         962f4462c39ecd803d83cc86060adee5bad5626a8fa37b385f18565b6eb4efb5
root:    2822935e60bf2df50246074173dd61d086923fd7eccec548cc55763f19ac470c
```

Inclusion proof for sorted leaf 0 (`approval:3`):

```json
{
  "leaf_hash": "04393d1f1e564260a316ec9f870e31f84740f1501f1835d703fc0428e979fbae",
  "leaf_index": 0,
  "steps": [
    {"hash": "5317e52f996d6af9486cccdd3ec87d73c6942491db861f331cf64f92935c1d53", "position": "right"},
    {"hash": "eb3f71b028ffa65bc2012c09081bdcfb01f200ccd5d58d2bd0f85f11eacc650b", "position": "right"},
    {"hash": "962f4462c39ecd803d83cc86060adee5bad5626a8fa37b385f18565b6eb4efb5", "position": "right"}
  ]
}
```

Canonical-bytes illustration (section 7.1): the object
`{"b": 1, "a": {"y": null, "x": "s"}, "signature": {...}}` canonicalizes to

```
{"a":{"x":"s","y":null},"b":1}
```

A complete signed packet and its expected verification transcript are
provided in [samples/](samples/).
