# ADR-0003: Publication is ping + pull, never content push

**Status:** accepted · **Date:** 2026-08-02

## Context

Sites must be able to notify the system of changes with minimal cost and
without coupling themselves to any particular aggregator.

## Decision

Publishers publish Deltas on their own `.well-known` path and send a
one-field, unauthenticated ping; the aggregator pulls and validates.

## Consequences

- The site's `.well-known` is the canonical source of truth: any
  aggregator, auditor, or researcher pulling the same paths sees the same
  data — third-party verifiability and aggregator substitutability follow.
- The ping needs no authentication (authenticity comes from the signed
  pull), so the ingest endpoint is trivially cheap and hard to weaponize.
- Serving cost for publishers is static files with immutable caching.
- A lost ping only delays ingestion — baseline polling recovers it.

## Alternatives considered

- **Direct content POST to the aggregator**: couples every publisher to
  one aggregator, requires authenticated uploads, and destroys
  third-party verifiability — nobody else can see what was submitted.
