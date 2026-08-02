# ADR-0006: No self-declared importance anywhere in the protocol

**Status:** accepted · **Date:** 2026-08-02

## Context

In a push system, submission is nearly free. Thirty years of web history
(meta keywords, blog pings, sitemap `<priority>`, pay-for-inclusion
engines) show that every channel where submission can assert relevance is
flooded until the signal is worthless — and that consumers respond by
ignoring the field, leaving it as pure spam surface.

## Decision

No object in the protocol carries any field by which a publisher declares
the importance, relevance, or ranking of its own content. A publisher can
say "I changed" and "my content is this" — never "I matter". This is a
constitutional invariant (DC-4 §8); importance is measured at
consumption, entirely outside the protocol.

## Consequences

- The single most valuable spam surface is removed by construction
  rather than policed at runtime — the load-bearing anti-spam decision
  of the suite.
- Ranking becomes explicitly out of scope for the protocol; consumers
  and downstream systems derive importance from usage, corroboration,
  and citation — signals publishers cannot cheaply fabricate.
- The aggregator has nothing to sell: combined with "position is not
  for sale" (DC-4 §8), there is no field whose value money could buy.

## Alternatives considered

- **Declared priority à la sitemaps `<priority>`**: ignored by every
  major consumer in practice, yet permanently exploited; worse than
  useless.
- **Reputation-weighted self-declaration**: still converges to purchased
  or farmed importance; rejected on the same grounds.
