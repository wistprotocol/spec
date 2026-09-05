# ADR-0031: A sanction identifies its primary finding

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012

## Context

One sanction severity could not be matched unambiguously to an evidence
array containing several findings of different severities.

## Decision

Require `details.finding`, the first confirming Audit Record ID of one
finding for the subject. Its closed confirming set determines the scalar
severity. Evidence includes that Record and a complete quorum establishing
the finding there; additional Audit Record evidence may differ in severity.
All cited Records must be available at the sanction's Block.

## Consequences

Optional corroboration cannot change a sanction's primary severity.
The derived ladder continues to count every qualifying finding.
