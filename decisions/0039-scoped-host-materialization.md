# ADR-0039: Scoped-host materialization preference

**Status:** draft · **Date:** 2026-09-16

## Context

WIST-1 §3.2 lets a Publisher list any hostname in its `subdomain_scope`,
ancestor or not, and WIST-3 §7 keys the materialized state by (Publisher
domain, Normalized URL). Self-declaration decided the case of a host that
declares for itself; nothing decided a host that never declares while two
or more scoped Publishers hold live records for one of its URLs, so a
query could see two records for one URL and two replayers could show
different ones.

## Decision

For a URL whose host has no own `seq`-0 Declaration Entry sealed at the
height, the record materialized is the nearest ancestor Publisher's: the
longest domain the host descends from. A non-ancestor Publisher
materializes the URL only while no ancestor holds a live record, and
among non-ancestors the least domain in ascending octet order does. The
other records are excluded at that height like a parent's under
self-declaration and return when the preferred record leaves. Audit
attribution is untouched: every Publisher's Deltas stay in the selection
domain and keep their chains.

## Alternatives and consequences

Materializing every record would hand queries two answers for one URL and
let a Publisher listing a foreign host shadow its content in every index.
Preferring the earliest sealed claim rewards squatting and needs the whole
history of the URL to decide the present; the chosen inputs are the live
records and the Publishers' domains, both in the Log. Ancestors come first
because an ancestor's authority over a descendant is what DNS delegation
establishes, while a listing of an unrelated host proves nothing; the
nearest ancestor wins over a farther one for the same reason
self-declaration wins over a parent. Octet order between non-ancestors is
arbitrary but stateless and total, so two replayers agree without reading
history, and it decides a case no authority argument can.

`vectors/wist3/materialization-preference.json` fixes the outcomes,
including a label-boundary case a raw suffix match would get wrong.
