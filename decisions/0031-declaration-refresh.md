# ADR-0031: Declaration refresh during ingestion

**Status:** draft · **Date:** 2026-09-12

## Context

WIST-1's “once on that observation” did not define the Delta retry unit or
whether missing bindings qualified. WIST-2 limited Feed retries per pull
but left Declaration discovery's relationship to its content budget unclear.
A rotation can first become visible in a Delta or a retrieved predecessor,
including when an unchanged Feed still verifies with a cached key.

## Decision

WIST-1 §5.1 delegates live Delta retries to WIST-2 §5, which defines their
trigger, per-ID/per-pull scope, authenticated retry and budget treatment.
No object schema changes. The live Feed retains its separate retry.
Historical replay and sealing retain their authenticated Log sources.

## Alternatives and consequences

Retrying only E01 misses rotations introducing a new identifier or replacing
an excluded or future binding. One shared retry per pull lets an earlier
unrelated failure consume a later Delta's opportunity to discover rotation.
Retrying each validation pass lets predecessor insertion or settlement
multiply discovery requests for one object. Per-ID attempts permit different
Deltas to observe successive rotations while bounding each ID's retry work.
Duplicate or changed Envelopes served for one ID do not create extra attempts.

Excluding Declaration requests keeps authority repair independent of history
size and content-budget exhaustion. Including them would require a separate
rule to defer required verification without counting false failures. The
content budget consequently does not bound discovery traffic; implementations
still need resource controls for response size, destinations, concurrency
and total work. This decision introduces no numeric discovery allowance and
does not authorize bypassing the protocol's required retrievals or retries.

An unsuccessful refresh cannot renew cache authority unless it is a valid
unchanged re-serve. Retrying the original object preserves its signed
observation and prevents a replacement response from hiding the failure.
Multiple rotations in one pull can still invalidate an earlier accepted
Delta at sealing; WIST-1 §5.2's sealing verification remains necessary.

`vectors/wist2/declaration-refresh.json` exercises signed discovery, Feed and
Delta sequences, independent retries, unsuccessful responses and content
budget boundaries. Recovery settlement and crash durability require live
integration beyond these supplied ordinary-rotation sequences.
