# ADR-0020: Parameter combinations validate the prospective schedule

**Status:** draft · **Date:** 2026-09-05

## Context

A pending sampling floor of 4,000,000 and a pending ceiling of 3,000,000
can each pass against defaults while jointly scheduling an invalid map.
WIST-4 §9's reference to another parameter's current value did not define
which pending changes a combination check must include.

## Decision

Validate candidates in canonical Log order. After checking individual
requirements, tentatively insert the candidate into the accepted schedule.
Check all combination rules at the sealing instant and every pending
effective instant, using the existing greatest-effective-time and
Log-order tie rules. Reject the candidate as `WIST4-E03` if any resulting
map fails; otherwise retain it. Do not roll back earlier acceptances or
reconsider rejected candidates after later amendments.

## Consequences

An invalid intermediate future state cannot hide behind a later valid
one. Superseding a same-time amendment is permitted only after the new
candidate passes. Same-Block validation uses the already canonical Entry
order, adding no ordering freedom to the Aggregator.

## Anchor parameters for in-flight windows

### Context

Changing a duration while a duty is outstanding could move its deadline
on replay. Confirmation also lacked a parameter read instant when Records
straddled a quorum or window amendment.

### Decision

WIST-4 §9 lists each clock's anchor. Duties retain their opening profile;
confirmation evaluates each candidate under its own Block's profile and
preserves its first historical success. An extension's contradiction test
retains its triggering profile and closes once. A later confirmation does
not rewrite that closed test. Appeal and seal clocks read the notice;
the ruling clock reads the accepted appeal.

### Consequences

Recomputation preserves established deadlines and findings. Epoch,
selection, reputation and materialization reads keep their explicit
anchors. A fixed count of Blocks still follows the actual cadence.

## Escalation predicates have no numeric amendment

### Context

The Registry admitted integer amendments for three compound ladder rules
without mapping those integers to counts, windows or severity branches.

### Decision

Remove `escalation_l2`, `escalation_l3` and `escalation_l4` from the
identifier table and schema. Reject them as `WIST4-E03`; retain §7's
printed predicates. Amending the ladder requires a protocol revision.

### Consequences

An arbitrary integer cannot silently disable a severity branch or choose
which component of a compound rule changes. Existing ladder transitions
remain unchanged after a rejected amendment.

## Parameter wire bounds preserve integer reputation

### Context

WIST-1 §4 claimed every integer's own bounds kept it in the interoperable
range, but Registry values lacked that bound. A negative Provisional cap
also made §6.2 return a negative reputation.

### Decision

Require all suite integer members to fit ±(2^53−1), inclusive, in addition
to field-specific bounds. Apply that range in the parameter schema and
require `provisional_cap_u` ≥ 0. Intermediate arithmetic stays exact and
may exceed the wire range. Schema acceptance never replaces semantic
amendment validation.

### Consequences

A large JSON number cannot silently round to another parameter value.
Zero Provisional reputation remains possible; negative reputation does not.
