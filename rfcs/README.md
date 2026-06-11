# Castle Obligation Schema RFC Process

How changes to the [Castle Obligation Schema](../SPEC.md)
are proposed, discussed, and accepted. The point of a written process is that
**the rules for changing the standard are themselves on the record**: adopters
need to trust that the contract will not shift under them arbitrarily.

This process governs the *spec* (the schema document, the conformance
requirements in [conformance/README.md](../conformance/README.md), and
[GOVERNANCE.md](../GOVERNANCE.md)). Changes to the *implementation* (Castle)
follow normal PRs and releases.

## When you need an RFC

| Change | RFC required? |
|---|---|
| Typo or clarification that does not change meaning | No, normal PR |
| New optional field, new node type, new profile, new informative appendix | Lightweight RFC |
| Changing a requirement, tightening an existing one, removing anything | Full RFC |
| Anything that could make a currently-conformant implementation non-conformant | Full RFC + migration note |

## Lifecycle

```
Draft  ->  Proposed  ->  Accepted  ->  Stable          (or -> Rejected / Withdrawn)
 |           |             |             |
 issue/PR    RFC doc       maintainer    ships in a
 sketch      + discuss     sign-off      versioned spec
```

1. **Draft**: open a GitHub issue tagged `schema-spec` describing the problem.
   Problem first, solution second. "What breaks today / what can't be
   expressed" beats "here's my format change."
2. **Proposed**: submit an RFC document (PR adding `rfcs/NNNN-title.md`)
   using [the template](0000-template.md). Discussion happens on the PR.
3. **Accepted**: a maintainer (today) or the working group (after
   [governance](../GOVERNANCE.md) trigger 2) signs off, with a recorded
   rationale. Acceptance requires at least one reference-implementation sketch
   or a clear conformance-kit check for the new behavior.
4. **Stable**: the change ships in a versioned spec release and the
   [conformance kit](../conformance/) is updated to cover it. From here,
   breaking it requires a major spec version.

Rejected and withdrawn RFCs are kept, not deleted, so the reasoning is
preserved.

## Principles

- **Additive over breaking.** Within a major version, prefer new optional
  fields and new profiles to changing existing requirements.
- **Spec follows running code.** Prefer changes proven in a real
  implementation (ideally a real deployment) over speculative design.
- **Conformance is the contract.** If a change cannot be expressed as a
  conformance-kit check, it probably is not a crisp enough requirement.
- **Verification stays implementation-free.** No change may make packet or
  fingerprint verification depend on access to Castle itself; the
  zero-import standalone verifier property (PK-4) is non-negotiable.
