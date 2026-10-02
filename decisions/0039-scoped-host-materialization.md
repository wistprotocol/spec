# ADR-0039: Scoped-host materialization preference

**Status:** draft · **Date:** 2026-09-16

## Context

WIST-1 §3.2 lets a Publisher list any hostname in its `subdomain_scope`,
ancestor or not, and WIST-3 §7 keys records by (Publisher domain,
Normalized URL). Self-declaration decided the case of a host that
declares for itself, without saying whether anything ends it; nothing
decided a host that never declares while two or more scoped Publishers
hold records for one of its URLs, so a query could see two records for
one URL and two replayers could show different ones.

## Decision

The rule chooses among the records of one URL whose Item no withdrawal
names. From the height at which the first `publisher_declaration` Entry
whose `domain` is the host is sealed, only the host's own Publisher's
record is materialized, and nothing ends that. For a URL whose host has
no such Entry sealed at the height, the record materialized is the
nearest ancestor Publisher's: the longest domain the host descends from.
A non-ancestor Publisher materializes the URL only while no ancestor
holds such a record, and among non-ancestors the least domain in
ascending octet order does. The other records stay records, are not
materialized, and return when the preferred record leaves; a Snapshot
carries them (WIST-3 §7), so a resumed Consumer restores one as a
replaying Consumer does.

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

Ending self-declaration when the host's Declaration stops standing was
considered: no Entry makes a Declaration stop standing — a Declaration
chain is never removed and a fresh identity replaces its head — so no two
replayers could evaluate the condition alike. A Snapshot that carried
only the materialized records would leave a resumed Consumer with nothing
to restore when the preferred record leaves, where a replaying one
restores the next.

`vectors/wist3/materialization-preference.json` fixes the outcomes,
including a label-boundary case a raw suffix match would get wrong, and
`vectors/wist3/record-materialization.json` the return of an
unmaterialized record after a Snapshot.
