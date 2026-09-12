# ADR-0030: Delta version eligibility

**Status:** draft · **Date:** 2026-09-12

## Context

WIST-1's unsupported-major rejection named Consumers without assigning a
Delta diagnostic or explicitly covering admission by other validators.
Schema-valid version spelling alone cannot establish that a validator
implements the object's rules. Converting unbounded decimal components to
machine integers can also reject otherwise permitted spellings.

## Decision

WIST-1 §§3.1/7 define Delta version spelling, role-independent major support
and WIST1-E15 after complete field validation. Same-major minor and patch
differences alone do not reject; signed values remain unchanged and every
rule of the implemented revision still applies. Existing diagnostic sets,
transport wrappers and object/stage dispositions remain authoritative.
Other object diagnostics are outside this decision.

## Alternatives and consequences

Exact-string equality would invent incompatibility between minor or patch
versions without a corresponding rule change. Schema-only acceptance would
allow an Aggregator to seal a major whose semantics it cannot validate.
E14 for unsupported majors would conflate malformed fields with unsupported
semantics; checking the major before all fields would erase field precedence.
A machine-integer limit would narrow the schema's decimal language.

The rule assumes validators implement a pinned revision under
[ADR-0028](0028-unreleased-object-version.md) and
[PUBLICATION.md](../PUBLICATION.md); accepting a version never licenses legacy field translation
or skipping other checks. A new semantic diagnostic lets version rejection
avoid unrelated network checks, but any check actually performed retains
its retrieval and refresh obligations.

Signed cases in `vectors/wist1/delta-fields.json` cover supported minor/patch
values, unbounded components, unsupported majors, malformed spellings and
field/signature/static-error combinations. They establish supplied-context
diagnostics, not live admission, complete chains or other objects' support.
