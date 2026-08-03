# ADR-0008: The protocol transports the raw citation graph, never a score

**Status:** accepted · **Date:** 2026-08-03

## Context

ADR-0006 rules importance out of the protocol and names citation among
the signals consumers should derive it from — signals publishers cannot
cheaply fabricate. But the suite distributed no citation data: a
consumer wanting link-based ranking had to re-crawl pages for their
links, against the protocol's premise that freshness never requires
crawling. Outbound links are not self-importance. "This page links to
X" is a verifiable statement about the Publisher's own content — an
Auditor re-fetching the page checks it exactly as it checks the extract
— while importance arises only from aggregating *other* publishers'
links, which no publisher controls.

## Decision

The Payload carries the page's external links and their true count
(DC-1 §3.6), extracted by one deterministic procedure (DC-2 §11) that binds
Publisher and Auditor alike; Snapshots materialize the graph
(`tier1/links.parquet`, DC-3 §7); audits read a `link_agreement` and
link fraud carries its own verdicts and a severity of its own, below
content fabrication (DC-4 §5, §7). The protocol transports these
declarations raw. It never carries a rank, a weight, a score, or any
aggregate of the graph: ranking — PageRank, HITS, anything — happens at
consumption, where competing systems compute over the same commons and
no publisher can buy position.

The declared subset is the first N links in raw-HTML document order.
The rule converts declaration from an unaudited choice into an
auditable function of the page, and it forces manipulation to be
visible in the page itself, where humans and ranking layers can see it.
It does not remove editorial discretion over the page: a publisher
still chooses what its page links to and in what order. No declaration
rule could remove that, because the page is the publisher's to write —
what the rule removes is the gap between the page and its declaration.

## Consequences

- Sybil link farms are a ranking-layer problem, out of scope here by
  construction: the protocol's identity is domain-anchored (ADR-0002),
  and as ADR-0002 states, "Sybil resistance comes for free at the
  identity layer", so every node in the graph already costs a domain,
  and what weight a ring of cheap domains deserves is exactly the
  judgement ADR-0006 reserves to consumers.
- The graph is erasable with the content it came from: links live in
  the Payload under its salt and leave distribution with it (DC-3
  §6.2), so carrying the graph adds no permanent commitment to page
  content.
- A consumer's ranking is reproducible by any other consumer from the
  same Snapshot, and contestable by publishing a better function — the
  competition ADR-0006 intends, now with the data to run it on.
