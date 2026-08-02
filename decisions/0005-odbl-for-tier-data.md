# ADR-0005: ODbL for public tier data

**Status:** accepted · **Date:** 2026-08-02

## Context

DC-4's constitutional invariants promise that the data stays open and
that the commons is forkable if its operating institution is ever
captured. The data license must make that promise legally binding.

## Decision

Public tier data (snapshots, Tier 0/1 artifacts) is licensed under the
Open Database License (ODbL) 1.0, irrevocably. Spec text is CC-BY 4.0.

## Consequences

- Share-alike on the database means any enriched or corrected derivative
  that is publicly used must remain open — a proprietary enclosure fork
  cannot legally out-compete the commons with the commons' own data.
- This is the same legal architecture that has protected OpenStreetMap
  for over a decade; precedent and community familiarity are strong.
- Attribution and share-alike obligations add mild friction for
  commercial consumers; acceptable, since consuming locally (the primary
  use) triggers no public-use obligations.

## Alternatives considered

- **CC0**: maximal reuse and zero friction, but permits closed
  enrichment forks — it would make the forkability guarantee
  economically hollow precisely in the capture scenario it exists for.
