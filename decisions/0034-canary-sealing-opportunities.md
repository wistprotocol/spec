# ADR-0034: Canary reveals wait for actual sealing opportunities

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012, ADR-0027

## Context

The fixed suffix walk bounds delay only under an unchanged suffix set and
budget. A growing roster can move an original suffix out of each turn
assumed by a reveal minimum computed before the change.

## Decision

Retain the numeric reveal minimum and additionally check actual coverage
and checkpoint sealing opportunities. Every bound Delta's coverage sealing
allowance must finish below the reveal. Every original suffix still
represented must receive a budgeted epoch ending after the last coverage
deadline, with its fetch and sealing allowance finished below the reveal.
Use actual epochs, rosters and anchored seal counts.

## Consequences

Roster and parameter changes cannot make a numeric bound stand in for a
service opportunity that never occurred. Churn can prevent revelation
before the commitment's unchanged lifetime; expiry then scores nothing.
