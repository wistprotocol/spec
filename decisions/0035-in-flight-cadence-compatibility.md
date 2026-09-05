# ADR-0035: Cadence transitions preserve older extension windows

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012, ADR-0026, ADR-0027

## Context

A 72-hour extension permits publication at hour 36 and sealing within
24 Blocks. Changing from hourly to two-hourly Blocks breaks that window,
even when the incoming profile raises its own window to 96 hours.

## Decision

For every constant-map interval, retain its extension publication span,
window and seal count. Bound sealing by the largest cadence that may be
in force before a window opened in that interval closes. Reject a candidate
whose tentative schedule breaks the bound. The interval's end plus its
window is exclusive. The rule deliberately bounds possible anchors without
using the presence or absence of particular triggers.

## Consequences

A slower cadence can be staged after a larger window has been in force
long enough for earlier windows to close. Brief cadence increases still
participate in the bound. Canary readiness uses its separate actual-prefix
check, so a faster cadence cannot outrun coverage and checkpoint duties.
