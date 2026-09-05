# ADR-0024: Attested suppression evidence names the affected duty

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012

## Context

A missing `prev_record` ID contains no visible Auditor duty or Block.
WIST-4 §4 nevertheless asks whether a successor contradicts a particular
unmet pull attestation. A generic missing predecessor cannot supply that
attribution.

## Decision

Require the missing ID to appear in that pull attestation's `found` list.
The same Auditor's successor for the same Log must seal at or above the
attestation height, including its own Block. Read both the successor and
the missing-ID test from the prefix through N. An unrelated gap exempts
no attested pair. Once the missing item seals, ordinary discharge decides
completion.

## Consequences

The Aggregator's signed receipt supplies the pair attribution without
putting off-Log publication time into replay. Empty or unrelated receipts
give no chain-based exemption. This decision does not expand the separate
unattested-pair rule.
