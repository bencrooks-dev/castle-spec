# Castle Obligation Schema (castle-spec)

An open integrity format for AI-governance evidence: deterministic
serialization and SHA-256 fingerprinting of governed objects, hash-chained
governance events, and a portable attestation packet (Merkle manifest plus
Ed25519 signature) that anyone can verify with a single standalone script and
no access to the producing system. On top of the packet, the format defines
countersignature receipts (Transparent Statements), multi-tier delegation
chains, a trust-registry format for pinning signing keys, an optional public
transparency anchor, and a structured JSON verdict for verification UIs.

The pitch in one line: verify, don't trust. An auditor who needs the vendor's
product to check the vendor's evidence has not verified anything.

## Status: v0.2 draft, pre-release

Plain framing, on purpose:

- This is a **draft standard**. Normative wording can still change through
  the [RFC process](rfcs/README.md).
- There is **one implementation today**: Castle
  ([castlegrc.com](https://castlegrc.com)), which is the reference
  implementation. **No other adopters are claimed.**
- There is **no certification program**. Conformance is a falsifiable,
  self-run claim (see [CONFORMANCE.md](CONFORMANCE.md)), not a badge anyone
  grants.
- Conformance kit v0.1 is **coupled to the reference implementation** (the
  executable checks are pytest against Castle's Python API). The recompute
  formulas themselves are implementation neutral and fully specified in
  [SPEC.md](SPEC.md); an implementation-neutral adapter interface is RFC
  material, not shipped machinery.
- We are **seeking implementers and reviewers**, not announcing an ecosystem.

Nothing in this repository is a certification, a regulator endorsement, or a
compliance status. A verified packet proves integrity (artifacts unchanged,
signed by the holder of a key), not completeness or truth of the evidence.

## Verify a packet right now

Two ways, both running the exact same verifier:

- **In the browser:** drop a packet on
  [castlegrc.com/verify](https://castlegrc.com/verify). The page runs the
  unmodified `castle_verify.py` from this repository client-side (Python in
  WebAssembly); nothing is uploaded anywhere.
- **Offline:** the single-file verifier in [verifier/](verifier/). Requires
  Python 3.11+ and `pip install cryptography` (its only third-party
  dependency):

  ```bash
  python verifier/castle_verify.py samples/sample-packet.json
  ```

Expected output: see [samples/expected-output.txt](samples/expected-output.txt).
Exit code 0 means every check passed: Merkle root, per-artifact hashes,
inclusion proofs, and the Ed25519 signature. Tamper with any byte of the
packet body and verification fails closed. Add `--pubkey` or `--trust` to
pin who signed, and `--json` for a machine-readable verdict; see
[verifier/README.md](verifier/README.md).

## What is in this repository

| Path | What it is |
|---|---|
| [SPEC.md](SPEC.md) | The normative specification (RFC 2119 language), implementable standalone: packet format, receipts, delegation chains, trust registry, anchoring, structured output. |
| [CONFORMANCE.md](CONFORMANCE.md) | Conformance registry and the OS-1..7 / PK-1..5 requirement summaries. |
| [conformance/](conformance/) | The executable conformance kit (pytest, kit v0.1, coupled to the reference implementation). |
| [verifier/](verifier/) | `castle_verify.py`, the standalone verifier (stdlib plus the `cryptography` package), byte-identical to the reference implementation's copy. |
| [samples/](samples/) | A signed sample packet generated from seeded demo data, plus its expected verification output. |
| [GOVERNANCE.md](GOVERNANCE.md) | How decisions are made and the staged path to neutral governance. |
| [rfcs/](rfcs/) | The RFC process and template for spec changes. |

## How to adopt

Three adoption levels, smallest first:

1. **Verify counterparty evidence.** No integration at all: use the
   [browser verifier](https://castlegrc.com/verify) or the single file in
   [verifier/](verifier/) to check any packet, statement, or chain you
   receive. Pin keys with `--pubkey` or a trust registry.
2. **Emit compatible packets.** Implement the recompute formulas in
   [SPEC.md](SPEC.md) (sections 3, 4, 6, and 7 are sufficient for a signed
   packet) and check yourself against the worked example in Appendix A and
   the conformance kit.
3. **Run a verify node.** A verify node independently verifies and
   countersigns packets it receives, producing the receipts of SPEC.md
   section 10. The node kit and runbook ship with the reference
   implementation; request them via
   [castlegrc.com/#contact](https://castlegrc.com/#contact).

If you are building a second implementation, open an issue first; making the
kit run against you is exactly the feedback a v0.x draft needs.

## Run the conformance kit

Kit v0.1 runs against the reference implementation, so Castle must be
importable (from a checkout of the Castle repository):

```bash
pip install -e /path/to/Castle
python -m pytest conformance/ -v
```

14 checks: OS-1..OS-7 (Schema-Core) and PK-1..PK-5 (Attestation-Packet).
See [conformance/README.md](conformance/README.md) for the requirement
mapping and for what the coupling means for a port to another language.

## Relationship to Castle

Castle ([castlegrc.com](https://castlegrc.com)) is the commercial governance
system that produced this format and remains its reference implementation.
The spec is split out so it can be implemented, criticized, and eventually
governed independently of any single vendor; the staged neutrality triggers
are written down in [GOVERNANCE.md](GOVERNANCE.md).

## Licensing

- Specification text: [CC BY 4.0](LICENSE).
- Verifier and conformance code in this repository: [MIT](LICENSE-CODE).

## Contributing

Spec changes go through the [RFC process](rfcs/README.md). Problem statements
beat format proposals.
