# ADR-0008: The protocol transports the raw citation graph, never a score

**Status:** draft · **Date:** 2026-08-03

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

The Payload carries the external links of the published content and their
true count (WIST-1 §3.6), extracted from an emitted HTML fragment by one
deterministic procedure (WIST-2 §11) or listed by an Emission of text
([ADR-0050](0050-emitted-publications.md)); Snapshots materialize the graph
(`tier1/links.parquet`, WIST-3 §7); audits read a `link_agreement` and
link fraud carries its own verdicts and a severity of its own, below
content fabrication (WIST-4 §5, §7). The protocol transports these
declarations raw. It never carries a rank, a weight, a score, or any
aggregate of the graph: ranking — PageRank, HITS, anything — happens at
consumption, where competing systems compute over the same commons and
no publisher can buy position.

The declared subset is the first N links in the order of the emitted
content: the document order of an emitted HTML fragment, or the order an
Emission of text lists them in. The rule converts declaration from an
unaudited choice into a function of the published content, so
manipulation is visible in the publication itself, where humans and
ranking layers can see it. It does not remove editorial discretion: a
publisher still chooses what its content links to and in what order. No
declaration rule could remove that, because the content is the
publisher's to write — what the rule removes is the gap between the
published content and its declaration. WIST-2 §11 applies to a served
page only for a party that chooses to compare the page with the
publication.

## Consequences

- Sybil link farms are a ranking-layer problem, out of scope here by
  construction: the protocol's identity is domain-anchored (ADR-0002),
  and as ADR-0002 states, "Sybil resistance comes for free at the
  identity layer", so every node in the graph already costs a domain,
  and what weight a ring of cheap domains deserves is exactly the
  judgement ADR-0006 reserves to consumers.
- The graph is erasable with the content it came from: links live in
  the Payload under its salt and leave distribution with it (WIST-3
  §6.2), so carrying the graph adds no permanent commitment to page
  content.
- A consumer's ranking is reproducible by any other consumer from the
  same Snapshot, and contestable by publishing a better function — the
  competition ADR-0006 intends, now with the data to run it on.
