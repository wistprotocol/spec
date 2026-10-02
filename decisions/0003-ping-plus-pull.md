# ADR-0003: Publication is ping + pull, never content push

**Status:** draft · **Date:** 2026-08-02

## Context

Sites must be able to notify the system of changes with minimal cost and
without coupling themselves to any particular aggregator.

## Decision

Publishers serve their Declaration, the signed Catalog of each Collection
with the tree files, change lists and Payloads it names
([ADR-0052](0052-items-and-catalogs.md),
[ADR-0053](0053-change-lists.md)), and their Labels on their own
`.well-known` path, and send a one-field, unauthenticated ping; the
aggregator pulls and validates.

## Consequences

- The site's `.well-known` is the canonical source of truth for the
  Publisher's present state: any party pulling the same paths at the same
  time sees the same data — third-party verifiability and aggregator
  substitutability follow. The site holds that state and not its history,
  so a reader that starts later obtains the Catalogs served then and not
  those they replaced, which only a Log that sealed them still holds.
- The ping needs no authentication (authenticity comes from the signed
  pull), so the ingest endpoint is trivially cheap and hard to weaponize.
- Serving cost for publishers is static files: tree files, change lists
  and Payloads are named by hash and cached as immutable, and only
  `publisher.json`, each `catalog.json` and the Label Feed change.
- A lost ping only delays ingestion — baseline polling recovers it.

## Alternatives considered

- **Direct content POST to the aggregator**: couples every publisher to
  one aggregator, requires authenticated uploads, and destroys
  third-party verifiability — nobody else can see what was submitted.
