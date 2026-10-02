# ADR-0031: Declaration refresh during ingestion

**Status:** draft · **Date:** 2026-09-12

## Context

A pull reads a Publisher's signed objects under its Declaration. An
Aggregator that caches a Key Set between pulls meets a rotation first in a
signed object the cached keys do not verify. Excluding Declaration
discovery from the ingest budget, or counting it, changes what a Publisher
with a large history can obtain.

## Decision

An Aggregator fetches the Declaration at the start of every pull and reads
no Key Set from a cache ([ADR-0051](0051-collections-scope-and-keys.md),
WIST-2 §5.1), so the objects of a pull are judged under the Declaration
the Publisher serves at that pull. No object schema changes. A Catalog
that fails its binding check is reported and retries nothing (WIST-1 §7).
WIST-2 does not determine whether a Label Feed or Page whose signature
fails triggers a second Declaration request in the same pull
([CONFORMANCE.md](../CONFORMANCE.md)).

Declaration requests do not debit the ingest budget, and its exhaustion
does not defer them. Page verification retains WIST-2 §3.2's authenticated
current/first-next sources; fetching and accepting a Declaration does not
establish its Log inclusion. Historical replay and sealing retain their
authenticated Log sources.

## Alternatives and consequences

A failure-triggered re-fetch beside the fetch that opens every pull would
return the Declaration the pull already read unless the Publisher changed
it within the pull, and would double discovery traffic for an authority it
could rarely add.

Excluding Declaration requests keeps authority repair independent of
history size and content-budget exhaustion. Including them would require a
separate rule to defer required verification without counting false
failures. The content budget consequently does not bound discovery
traffic; implementations still need resource controls for response size,
destinations, concurrency and total work. This decision introduces no
numeric discovery allowance and does not authorize bypassing the
protocol's required retrievals.

Letting a fetched unsealed Declaration authorize a Page would bypass the
current/first-next cutoffs and make Page authority depend on local
admission. A validator may retain one authenticated prefix through a Label
walk; discovery then cannot change its Page sources.

`vectors/wist2/declaration-refresh.json` carries Feed and Delta retry
sequences, objects this decision no longer covers; its content-budget
boundaries and its Page cases, which distinguish admission authority from
current/first-next sources using supplied sealing positions, remain
applicable. They establish no Epoch inclusion or complete Page fields.
