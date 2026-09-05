# ADR-0026: Parameter combinations validate the prospective schedule

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012

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
