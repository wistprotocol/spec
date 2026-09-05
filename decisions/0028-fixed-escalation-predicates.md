# ADR-0028: Escalation predicates have no numeric amendment

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012

## Context

The Registry admitted integer amendments for three compound ladder rules
without mapping those integers to counts, windows or severity branches.

## Decision

Remove `escalation_l2`, `escalation_l3` and `escalation_l4` from the
identifier table and schema. Reject them as `WIST4-E03`; retain §7's
printed predicates. Amending the ladder requires a protocol revision.

## Consequences

An arbitrary integer cannot silently disable a severity branch or choose
which component of a compound rule changes. Existing ladder transitions
remain unchanged after a rejected amendment.
