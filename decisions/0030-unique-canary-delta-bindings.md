# ADR-0030: Canary Delta bindings are unique within a Log

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012, ADR-0018

## Context

A ban on a Delta being bound to two leaves did not state its scope.
Repeating a Delta across commitments could multiply the same encounter.

## Decision

An accepted reveal permanently reserves its Delta IDs within that Log.
Reject a later reuse. Deduplicate identical Update IDs, then reject all
otherwise-valid simultaneous candidates sharing a commitment or Delta.
Rejected candidates reserve nothing. Score each Audit Record ID once.

## Consequences

Expired scoring windows cannot be revived by recommitting a Delta.
Entry order does not choose a winner in a simultaneous collision.
Multiple checkpoints authenticate one Record without multiplying its score.
