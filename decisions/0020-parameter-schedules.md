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
