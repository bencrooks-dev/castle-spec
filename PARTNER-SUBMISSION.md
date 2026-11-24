# Partner Document Submission (PDS), Lite

> **Status: v0.1 draft, companion to [SPEC.md](SPEC.md).** Normative wording can
> change through the [RFC process](rfcs/README.md). One implementation today
> (Castle, the reference implementation); no other adopters are claimed.

## 1. Purpose and scope

Carriers require the same documents from every MGA and TPA writing on their
paper: continuity and recovery plans, security and AI policies, certificates of
insurance, licenses, financials. Today each partner decides how to send them.
PDS is the smallest common format for that hand-off: **one JSON manifest that
describes the files, plus the files.** Any partner system can produce it, any
carrier system can receive it, and the receiver can prove what it received.

In scope: describing submitted documents, a shared vocabulary of document
types, file integrity, dates, the receipt. Out of scope: how a carrier reviews
or accepts a document, transport security, premium and loss bordereaux, and
any scoring. A PDS submission is never an acceptance.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 2. The manifest

A submission is a JSON object that validates against
[`schemas/partner-submission-v0.1.schema.json`](schemas/partner-submission-v0.1.schema.json).

```json
{
  "pds_version": "0.1",
  "partner": {"legal_name": "Keystone Underwriters", "kind": "mga", "id": "keystone"},
  "recipient": {"legal_name": "Northwind Mutual", "program": "small-commercial"},
  "submitted_by": {"name": "Hannah Becker", "email": "hannah@keystone.example"},
  "submitted_at": "2026-11-24T15:00:00Z",
  "items": [
    {
      "requirement": "doc_bcp",
      "filename": "keystone-bcp-2026.pdf",
      "media_type": "application/pdf",
      "sha256": "9f2c...64 hex characters...",
      "size_bytes": 482113,
      "document_date": "2026-10-01"
    },
    {
      "requirement": "doc_coi_eo",
      "filename": "eo-certificate.pdf",
      "media_type": "application/pdf",
      "sha256": "41ab...",
      "size_bytes": 90211,
      "document_date": "2026-06-01",
      "expires_on": "2027-06-01",
      "request_ref": "REQ-1042"
    }
  ]
}
```

Rules:

- `submitted_by.name` MUST be a named person, not a system or shared mailbox.
- `sha256` is the lowercase hex SHA-256 of the file's exact bytes; `size_bytes` is its length.
- `document_date` is the date the document states (approved, signed, tested or issued), not the upload date.
- `expires_on` MUST be present for document types marked *expires* in section 3.
- `request_ref` is OPTIONAL and echoes the receiver's request identifier when the item answers one.
- `filename` MUST be a bare name (no path separators) and unique within the manifest.

## 3. Document vocabulary

`requirement` is one of the keys below, or a private key starting `x-`
(for example `x-flood-procedures`) that sender and receiver agree on.
*Max age* is the default freshness rule: a receiver SHOULD treat a document
whose `document_date` is older than this as stale. A receiver MAY set stricter rules.

| Key | Document | Max age (days) | Expires |
|---|---|---|---|
| `doc_bcp` | Business continuity plan | 365 | |
| `doc_dr` | Disaster recovery plan and last test results | 365 | |
| `doc_infosec` | Information security policy | 365 | |
| `doc_incident` | Incident response plan | 365 | |
| `doc_privacy` | Privacy policy and procedures | 365 | |
| `doc_ai_policy` | AI policy and procedures | 365 | |
| `doc_ai_inventory` | AI system inventory | 182 | |
| `doc_vendor` | Vendor management policy | 365 | |
| `doc_change` | Change management procedure | 365 | |
| `doc_procedures` | Underwriting and claims procedures | 365 | |
| `doc_coi_eo` | Certificate of insurance: errors and omissions | 400 | yes |
| `doc_coi_cyber` | Certificate of insurance: cyber | 400 | yes |
| `doc_license` | Agency or producer license | 1100 | yes |
| `doc_financials` | Financial statements | 400 | |
| `doc_soc` | SOC report or independent controls report | 400 | |
| `doc_ownership` | Ownership and key people | 365 | |
| `doc_references` | Carrier or market references | 365 | |
| `doc_agreement` | Signed program agreement | 1100 | |

## 4. Carrying the files

Either binding is conformant:

1. **Bundle.** A ZIP file with `manifest.json` at its root and each file at its
   `filename`, also at the root. Nothing else is read.
2. **HTTP.** The receiver publishes what it needs and accepts one item per
   request (multipart: `file`, `document_date`, optional `expires_on`), keyed by
   its own request identifier. The manifest fields map one to one.

## 5. Receiving

A receiver MUST, for each item:

1. Recompute SHA-256 and length over the received bytes and reject the item on any mismatch.
2. Reject an unknown `requirement` that does not start with `x-`.
3. Reject an item whose `expires_on` is before the date of receipt, or whose type expires and has no `expires_on`.
4. Record the item as **received, not accepted**. Acceptance is a separate decision by a named person at the receiver.
5. Treat a resubmission with the same `requirement` and `sha256` as the same document (idempotent).

A receiver MUST NOT reject the whole manifest because one item fails; each item stands alone.
It SHOULD flag stale items (section 3) without rejecting them.

The receiver returns a **receipt**, which also validates against the schema:

```json
{
  "pds_receipt_version": "0.1",
  "received_at": "2026-11-24T15:00:04Z",
  "manifest_sha256": "c0ff...",
  "items": [
    {"filename": "keystone-bcp-2026.pdf", "sha256": "9f2c...", "status": "received"},
    {"filename": "eo-certificate.pdf", "sha256": "41ab...", "status": "rejected",
     "reason": "expired"}
  ]
}
```

`manifest_sha256` is the SHA-256 of the manifest bytes as received, so both
sides can later show which manifest a receipt answers. `reason` is one of
`digest_mismatch`, `size_mismatch`, `unknown_requirement`, `expired`,
`missing_expiry`, `missing_file`, or `other`; `status` also allows `stale`
(received, flagged as older than its max age).

## 6. Conformance

**Producer.** Emits manifests that validate against the schema, with digests,
sizes and dates that match the files (section 2), using the vocabulary in section 3.

**Receiver.** Accepts either binding in section 4, applies every rule in
section 5, and returns a valid receipt. A receiver MUST NOT report a received
item as accepted, compliant or approved.

## 7. Reference checker and relation to SPEC.md

[`verifier/pds_check.py`](verifier/pds_check.py) is a stdlib-only receiver for
the bundle binding: it applies every rule in section 5 to a manifest and its
files and prints the receipt. Exit code 0 means every item was received (some
possibly `stale`), 1 means at least one item was rejected, 2 means the manifest
itself is unusable.

```bash
python verifier/pds_check.py samples/sample-submission.zip --today 2026-11-24
```

A received item is evidence in the sense of [SPEC.md](SPEC.md): its `sha256`
is the content fingerprint of the file's bytes. A receiver MAY carry received
documents into an attestation packet (SPEC.md section 6) so a third party can
later verify exactly what was received, without access to the receiver's
system. The Castle reference implementation provides the HTTP binding.

## 8. Versioning

`pds_version` changes from `0.1` only for breaking changes. New vocabulary keys
are additive and do not change the version.
