# ADR-0025: Simultaneous roster claims resolve as a batch

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012

## Context

WIST-4 §3.1 rotates an Observer at a later registration's sealing instant.
Two registrations in one Block have no later instant. Shared-key bars
likewise gave no winner among simultaneous otherwise-valid claims.
WIST-3 §3.3 denies registry acts a positional precedence.

## Decision

After removals, reject duplicate same-subject admission or registration
groups. Validate remaining candidates against the resulting incumbent
map. A remaining admission displaces a same-subject registration
candidate. Reject all cross-subject key-ID or public-key collisions
among the survivors, simultaneously, and apply those left together.
No rejected candidate is retried. An Observer key released by rotation
or admission becomes available to others only in a later Block.

## Consequences

Failed rotations preserve the incumbent Observer key. Simultaneous
collisions choose no winner by Entry position. An independently invalid
candidate cannot veto a valid one through a shared key; a candidate
rejected for an earlier conflict cannot be rescued by a later rejection.
