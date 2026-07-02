# Governance

This document explains how decisions are made for the **Castle Obligation
Schema** (the open integrity and evidence format specified in
[SPEC.md](SPEC.md) and bound to executable requirements by the
[conformance kit](conformance/)). It is deliberately honest about the
project's current stage and the path to neutral governance, because a
standard that looks like one company's property does not get adopted.

## Two things, governed differently

| | **Castle Obligation Schema** (the standard, this repository) | **Castle** (the reference implementation) |
|---|---|---|
| What it is | An implementation-neutral integrity and evidence format | A commercial governance control plane |
| License | CC BY 4.0 (spec text and conformance requirements); MIT for the verifier and kit code in this repository | Proprietary |
| Change process | [RFC process](rfcs/README.md) | normal PRs and releases |
| Goal | belong to the whole industry | be the canonical, conformant implementation |

Keeping these distinct is a governance requirement, not a formality: anyone
may implement the schema without touching Castle, and the spec must be able
to outlive any single implementation. The verifiability story depends on it;
an auditor who needs the vendor's product to check the vendor's evidence has
not verified anything.

## Current stage (be honest)

The schema is at **v0.2 (Draft)**. There is exactly one implementation (the
reference implementation, Castle, which is pre-1.0 with no production
customers) and no external adopters. Today the project is **maintainer-led**
(a single maintainer, effectively a BDFL model). This is normal and
appropriate for this stage, but it is explicitly a stage, not the end state.
We do not pretend to be a foundation we are not.

Known coupling, stated plainly: conformance kit v0.1 executes against the
reference implementation's Python API. An implementation-neutral adapter
interface is RFC material (see [conformance/README.md](conformance/README.md)).

## Decision-making (now)

- **Routine changes** (typo fixes, clarifications that do not change
  meaning): a maintainer reviews and merges via PR.
- **Spec changes**: follow the [RFC process](rfcs/README.md). A Draft-stage
  spec can change with maintainer approval plus a recorded rationale in the
  RFC; once a section reaches **Stable**, breaking it requires a major spec
  version.
- **Breaking changes** require an RFC, a migration note, and a deprecation
  window of at least one minor version.

## Path to neutral governance (the commitment)

We will move the schema out of a single-vendor home as adoption justifies it.
The triggers, in order:

1. **Second independent conformant implementation** exists and passes the
   [conformance kit](conformance/) (or its ported equivalent): publish a
   public RFC process and an open decision log.
2. **External contributors or adopters** beyond the originating maintainer:
   establish a working group with named stewards from more than one
   organization.
3. **Material industry adoption**: move the spec to a neutral home (its own
   org) under an open-governance body. MCP's donation to the Linux
   Foundation's Agentic AI Foundation (December 2025) is the model we intend
   to follow.

Until trigger 3, this repository is the spec's interim home, and Castle's
maintainers are its interim stewards.

## Conformance authority

"Conformant" is not granted by us as a favor; it is **earned by passing the
[conformance kit](conformance/)** and recorded in the public
[conformance registry](CONFORMANCE.md). We maintain the kit and the registry;
we do not gatekeep who may implement the spec.

## Relationship to ARI

The reference implementation governs agent runtimes; it does not standardize
them. For runtimes implementing
[ARI (the Agent Runtime Interface)](https://github.com/bencrooks-dev/marrow),
Castle ships an enforcement adapter. The two standards are complementary and
separately governed: ARI defines how agents run, the Castle Obligation Schema
defines how their obligations and evidence are made tamper-evident.

## Amending this document

Changes to governance follow the same RFC process as spec changes, so the
rules for changing the rules are themselves on the record.
