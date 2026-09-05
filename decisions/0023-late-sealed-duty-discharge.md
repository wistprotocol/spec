# ADR-0023: Late-sealed discharge clears the current coverage count

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012

## Context

WIST-4 §4 requires publication by a deadline but permits subsequent
sealing. It does not expressly settle a Record first sealed after an
unmet pull attestation or the unattested fallback established a failure.
The sealing instant alone cannot prove when the Record was published.

## Decision

Read completed duty from the available Log prefix. A complete discharge
removes the pair from the current count from its completion Block,
without requiring suppression evidence. Partial completion does not.
Apply the existing standing and void-discharge rules. Empty selection
still needs its coverage attestation.

## Consequences

Later completion changes no prior prefix or sealed removal. It proves
completion rather than timely publication; the publication duty remains.
Keeping a failure solely because its discharge sealed late would make
an allowed transport delay indistinguishable from Auditor shirking.
