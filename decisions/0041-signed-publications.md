# ADR-0041: The Payload is the publication, and trust is assessed at consumption

**Status:** draft · **Date:** 2026-09-16

## Context

WIST-1 defined the Payload as a description of a page — `extract`,
`summary`, `links` — and WIST-4 established its truth by having
independent Auditors fetch the page and measure the description against
it: sampling by VRF, a roster with admission and removal, Observers and
canaries to test the Auditors, seven verdicts over pinned extraction and
shingling, two-Auditor confirmation inside a window, a reputation
function, a four-rung sanction ladder with notices, appeals and rulings,
evidence retention and coverage duties. That layer is more than half of
the suite by text and by parameter count.

Its guarantee is narrow. A Confirmed Inconsistency says the page did not
carry the signed text at the fetch; it says nothing about whether the
text was worth indexing, and §6.4 forbids reading reputation as a
content signal. A domain that signs spam and serves spam passes every
audit. What the layer prevented — signing one text and serving another,
and leaving a stale claim in place — is visible to any reader who
follows the link and is recorded by the Log either way.

Its cost includes a false-positive class the design cannot remove
without further machinery: a Publisher that rewrites a page and seals
the correction after an Auditor's fetch is measured against the text it
already replaced, two such fetches confirm "fabricated content" at
severity 3, and one severity-3 finding arms Sanctioned Quarantine. The
honest transition and the lie leave identical evidence; only a grace
window told them apart, and a grace window forgives the lie too.

Indexes built without crawling exist at scale. AT Protocol relays pull
signed repositories from hosts and re-broadcast them; indexers build
views from the stream; relays never compare a record with a web page.
Nostr relays store and forward signed events; spam is a relay policy and
trust an optional assertion layer. Email put authentication in the
protocol (DKIM, SPF, DMARC) and left reputation to shared lists outside
it. Systems that kept the page as the source of truth kept crawling:
IndexNow only accelerates a crawl, and Signed Exchanges, which made a
page carry its own signature, are being withdrawn by their vendors.

## Decision

### The Payload is the publication

A Delta's Payload is what the Publisher publishes for a URL: `extract` is
the canonical text, `links` the citations the Publisher vouches for,
`summary` the structured summary, all as WIST-1 §3.6 shapes them. The
URL locates the publication and scopes it under the Publisher's
authority (WIST-1 §3.2); whether the resource at the URL carries the
same text is not a protocol property. No party measures it, no verdict
records it and no consequence follows from it. A Consumer MAY present
the signed publication directly and MAY link to the URL.

`observed_at` keeps its meaning as the instant the Publisher asserts the
publication for; the clock rule of WIST-1 §3.4 still bounds it at
acceptance. `attest` keeps its meaning as a freshness claim over the
anchor Payload; `delete` ends the URL's publication. Payload
commitments and salts stay as WIST-1 §3.6 defines them: they bind
content that lives outside the Log so that withdrawal can erase it
(ADR-0007), and they need no audit to be useful.

### No Auditor role

The suite defines three roles: Publisher, Aggregator, Consumer. Audit
Records, the Auditor roster, Observers, canary commitments and reveals,
sampling and selection, verdicts, confirmation, extension, coverage
duties, reputation, sanctions, notices, appeals, rulings, lifts, evidence
retention, the VRF and every parameter, error code, schema, Registry
Update action, Entry type and Snapshot state tuple that served
them are removed from WIST-1 through WIST-4. WIST-4 becomes the
governance document: the Parameter Registry, parameter amendments,
Aggregator key acts, Payload withdrawal, the constitutional invariants,
security and privacy considerations.

Quota and inclusion no longer read a reputation. Every domain has the
same Ping quota, `quota_base` per UTC day, and every accepted Delta is
eligible for the next Epoch, bounded by `max_inclusion_epochs` and the
per-domain Epoch capacity exactly as before. The per-domain ingest
budget, the Delta caps and the clock rule are unchanged.

### Labelers are Publishers

A Labeler is a domain that publishes signed Labels about other domains'
URLs or about domains. A Label names a subject (a Normalized URL or a
Canonical Host), a name from an open vocabulary under a registered
prefix, an optional integer value in micro-units and the instant the
Labeler asserts it for. Labels are published one file per Label and
listed in a Label Feed with the Feed's structure, signing, paging, Ping
and pull behavior, sealed as `label` Entries, carried in Snapshots as
label tuples and materialized in a tier beside the records. A Labeler declares itself with an ordinary
Declaration; its Labels are outside every scope rule because a Label is
an opinion about another party, not a publication for it, and the Log
records who signed it. A Consumer applies only the Labels of Labelers it
subscribes to; the protocol never aggregates Labels into a score. Trust
seeds and distrust seeds are Labels.

### Consumers rank

ADR-0006 and ADR-0008 stand: no protocol object carries importance and
the suite transports the raw citation graph, never a score. Ranking is a
Consumer policy, expected to be selectable and shareable: text
relevance, trust propagated from seed domains along the signed link
graph, distrust propagated from bad seeds, the domain's age and
publication history read from the Log, chain freshness, and subscribed
Labels. Because every Consumer at one height holds the same graph, the
same Labels and the same history, a ranking is reproducible from a
profile and a height. A tier-1 domain-to-domain edge table with counts
MAY be added as raw data.

## Alternatives considered

- **Grace window for late corrections, incident identity per reference,
  link containment, a small-site Provisional gate and retractions as
  scrutiny.** Removes the false-positive class inside the audit model at
  the cost of the whole model; forgives the same bounded lies the audit
  was meant to catch; keeps an unbuilt role and evidence retention.
- **Aggregator checks at ingest and unpredictable re-checks with
  exclusion.** Cheaper, still fetches, still cannot judge content, and
  makes one party's observation the trust signal without independence.
- **Reader witnesses, publication receipts, signed exchanges,
  immutable page histories.** Each proves something about delivery at
  costs no participant bears today, and none judges content.
- **Keeping WIST-4 as an optional layer.** Rejected: an optional audit
  layer would still have to be specified, implemented and validated to
  mean anything, and a Consumer that wants delivery evidence can obtain
  it from a Labeler that fetches.

## Consequences

- The index asserts "this domain signed this publication at this Log
  height", ranked by a policy the Consumer chooses. Documentation states
  that guarantee and no stronger one.
- Bait and switch — signing one text and serving another — is a reader's
  observation and a Labeler's subject, not a protocol finding. Stale
  publications are a freshness question the chain answers.
- WIST-1 loses its audit references; WIST-2 loses the Auditor pull
  rules, `robots.txt` audit exemptions and the roster submissions path,
  and its extraction procedures (§11, §12) become the recommended way
  for Publisher tooling to derive a publication from a page rather than
  a measurement two Auditors must reproduce; WIST-3 loses the
  `audit_record` Entry, the roster and canary Registry Updates, the
  sanction, notice, appeal, ruling and lift acts, the reduced-weight
  materialization and the audit state tuples, and gains the `label`
  Entry and tuple; WIST-4 is rewritten as governance. Schemas, vectors,
  the reference tools, CONFORMANCE.md and the checklists follow in the
  same revision.
- Superseded decisions: ADR-0010, ADR-0011, ADR-0012, ADR-0016,
  ADR-0018, ADR-0019, ADR-0035 and ADR-0037. ADR-0017 keeps the Unicode
  pin for the Canonical Host. ADR-0020 keeps parameter schedules over
  the remaining registry. ADR-0036 keeps the Registry Update
  dispositions for the remaining acts.
- Implementations remove the audit machinery and add Labels, link
  indexing and ranking profiles; the consolidation criteria name three
  roles.

## Verification

The revision that removes the audit layer regenerates the vector suite
without the WIST-4 audit vectors and with Label vectors: Label fields
and signing, subject shapes, self-labeling, currency and retraction,
Snapshot tuples and materialization. Integrated validation exercises
Publisher, Labeler, Aggregator and Consumer in one run.
