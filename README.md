# Castle Obligation Schema (castle-spec)

An open integrity format for AI-governance evidence: deterministic
serialization and SHA-256 fingerprinting of governed objects, hash-chained
governance events, and a portable attestation packet (Merkle manifest plus
Ed25519 signature) that anyone can verify with a single standalone script and
no access to the producing system.

The pitch in one line: verify, don't trust. An auditor who needs the vendor's
product to check the vendor's evidence has not verified anything.

## Status: v0.1 draft, pre-release

Plain framing, on purpose:

- This is a **draft standard**. Normative wording can still change through
  the [RFC process](rfcs/README.md).
- There is **one implementation**: [Castle](https://github.com/bencrooks-dev/Castle),
  which is the reference implementation. **No other adopters are claimed.**
- Conformance kit v0.1 is **coupled to the reference implementation** (the
  executable checks are pytest against Castle's Python API). The recompute
  formulas themselves are implementation neutral and fully specified in
  [SPEC.md](SPEC.md); an implementation-neutral adapter interface is RFC
  material, not shipped machinery.
- We are **seeking implementers and reviewers**, not announcing an ecosystem.

Nothing in this repository is a certification, a regulator endorsement, or a
compliance status. A verified packet proves integrity (artifacts unchanged,
signed by the holder of a key), not completeness or truth of the evidence.

## What is in this repository

| Path | What it is |
|---|---|
| [SPEC.md](SPEC.md) | The normative specification (RFC 2119 language), implementable standalone. |
| [CONFORMANCE.md](CONFORMANCE.md) | Conformance registry and the OS-1..7 / PK-1..5 requirement summaries. |
| [conformance/](conformance/) | The executable conformance kit (pytest, kit v0.1, coupled to the reference implementation). |
| [verifier/](verifier/) | `castle_verify.py`, the standalone packet verifier (stdlib plus the `cryptography` package). |
| [samples/](samples/) | A signed sample packet generated from seeded demo data, plus its expected verification output. |
| [GOVERNANCE.md](GOVERNANCE.md) | How decisions are made and the staged path to neutral governance. |
| [rfcs/](rfcs/) | The RFC process and template for spec changes. |

## Verify the sample packet

The fastest way to see the format work end to end. Requires Python 3.11+ and
`pip install cryptography` (the verifier's only third-party dependency):

```bash
python verifier/castle_verify.py samples/sample-packet.json
```

Expected output: see [samples/expected-output.txt](samples/expected-output.txt).
Exit code 0 means every check passed: Merkle root, per-artifact hashes,
inclusion proofs, and the Ed25519 signature. Tamper with any byte of the
packet body and verification fails closed.

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

Castle is the commercial governance control plane that produced this format
and remains its reference implementation. The spec is split out so it can be
implemented, criticized, and eventually governed independently of any single
vendor; the staged neutrality triggers are written down in
[GOVERNANCE.md](GOVERNANCE.md).

## Licensing

- Specification text: [CC BY 4.0](LICENSE).
- Verifier and conformance code in this repository: [MIT](LICENSE-CODE).

Note: this license split is pending final maintainer review and may be
adjusted before the repository is made public.

## Contributing

Spec changes go through the [RFC process](rfcs/README.md). Problem statements
beat format proposals. If you are building a second implementation, open an
issue first; making the kit run against you is exactly the feedback v0.1
needs.
