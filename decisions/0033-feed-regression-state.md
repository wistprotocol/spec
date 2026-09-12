# ADR-0033: Durable Feed regression state

**Status:** draft · **Date:** 2026-09-12

## Context

WIST-2 rejects decreasing live Feed timestamps without specifying the
observation that establishes the baseline or its lifetime. A pull can
authenticate the live Feed and then fail on an older Page or a Delta.
Declaration changes and restart provide additional possible reset points.

## Decision

WIST-2 §3.2 defines a durable maximum per requested Canonical Host, advanced
atomically after live Feed authentication and before dependent retrieval.
Its rules govern rejection precedence, equal timestamps, subsequent failures,
sealed Pages, Declaration changes and first observations.

## Alternatives and consequences

Recording only successful Delta admission permits replay of older Feeds
after an authenticated observation with unavailable content. Recording before
authentication lets an unauthenticated response raise the baseline. Resetting
on restart or rotation makes rollback protection depend on local uptime or
key management. Domain-scoped persistence avoids those reset opportunities;
an identity reset does not constitute an authenticated Feed-clock reset.

An authorized signer can raise the timestamp far ahead of wall time, including
to the final representable second. Recovery must then publish at least that
value; equality permits publication without advancing time. Adding a future
clock bound or authenticated reset would be a separate protocol decision.
Retained observations cannot be reconstructed from Delta timestamps or Log
inclusion, which do not authenticate which live Feed was served. Restoring
an older database backup therefore requires separately preserved observation
state to retain the same rollback protection.

`vectors/wist2/feed-regression.json` supplies signed ordered observations,
failure combinations and full-range timestamp boundaries. The reference checks
the state transitions; durable storage and retrieval ordering require live
integration tests.
