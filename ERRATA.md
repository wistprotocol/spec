# Errata

The suite was frozen on 2026-08-05. This file records every change made to a
document after that date, so that "frozen" stays a legible claim rather than
one a reader has to reconstruct from the commit log.

An entry belongs here when it meets both conditions:

- it cannot break an implementation that conformed to the text before it, and
- it states something the suite already implied, or corrects something the
  suite got wrong.

A change that fails either condition is not errata. It is a revision — and
revisions are expected rather than forbidden. Implementation finds genuine
defects, and the sharpest kind is a contradiction between two sections, which
no implementation can conform to either way, so resolving one necessarily
breaks whoever guessed the other branch. What the freeze buys is not the
absence of such changes but their shape: a revision is scoped to the defect
that provoked it and reopens the suite no further.

**What ends the freeze.** A freeze with a start and no exit criterion is a
preference, and the first strong argument overturns it. This one holds until
two independent implementations pass the vector suite, one of them the
pure-Python conformance reference in `tools/`, kept independent for exactly
this reason, so that neither can quietly become the oracle. The
disagreements found on the way there are the errata this file expects to
collect.

**Why the documents are edited in place.** A published RFC never changes; its
corrections live in a database outside it, because implementations shipped
against those bytes and interoperability is what immutability protects.
Nothing has shipped against this suite. While that holds, editing the document
and recording the edit here is cheaper and more honest than an errata list
every reader must cross-reference against a text that contradicts it. It stops
holding the moment a deployment exists: from the first Log sealing Blocks a
third party consumes, a document's text is fixed, corrections are recorded
here and nowhere else, and a substantive change takes a new major version —
which is what WIST-4 §8 already requires of the constitutional invariants, and
which is a fork that must win adoption on its own merits.

Each entry names its status honestly. **Exercised** means the vector suite
covers the behavior. **Unexercised** means the text rests on reading alone,
because nothing in the harness reaches it — a distinction that matters most
for text added after the vectors were built.

---

## 2026-08-06 — WIST-3 §8, §12: following more than one Log

Adds the paragraph *Following more than one Log* at the end of §8, and one
Consumer line to the §12 checklist.

**What it states.** A Delta ID is the SHA-256 of the Delta's Canonical Bytes
(WIST-1 §4), which carry nothing about the Log that sealed them, and `prev`
chains a URL's Deltas on the Publisher's side — so one Delta has one identity
in every Log that sealed it, and a Consumer holding two Logs deduplicates by
Delta ID exactly. What a Log derives rather than transports does not merge:
its ingest set, its Auditor roster, and every reputation, sanction, exclusion
and quota computed from that roster's Records are state of one chain, and a
Consumer MUST NOT carry them into another. Coverage across Logs is partial in
the sense §7 already gives a sharded Snapshot. §3.4 succession is excluded: it
is one Log continued under new keys, not two Logs reconciled.

**Why it qualifies.** WIST-4 §6 already defines reputation as a function of
one Log's history evaluated at a Block height, so mixing chains was already
non-conforming; the `MUST NOT` forbids nothing that was previously permitted.
A Consumer following a single Log is unaffected, and no prior text addressed
the multi-Log case at all. Before this, the only acknowledgement that
concurrent Logs exist was §6.2's note that a withdrawal binds one Log.

**Status.** Unexercised. No vector seals the same Delta into two Logs, so the
identity-stability claim is verified by reading WIST-1 §4 rather than by
execution. A vector that does so belongs with the first multi-Log consumer.

## 2026-08-08 — WIST-2 §11 step 5: `link_extraction.py` and empty authority

No document text changes. This entry records a divergence in the pure-Python
reference tool's `normalize_url`, found by checking the tool against an
independent implementation of the same procedure, from what WIST-2 §11
step 5 already pins.

**What it states.** `urllib.parse.urljoin` treats a candidate such as
`https:///x` — a scheme, a `//` authority marker, and no host — as carrying
no authority at all, and falls back to the base's host: resolved against
`https://example.com/blog/post-1`, it yields `https://example.com/x`. RFC
3986 §5.3 Component Recomposition takes the opposite reading: once a
transformed reference carries a `//` marker, its authority (here, the empty
string) is what gets recomposed, not the base's. An implementation
following §5.3 literally extracts that empty authority, and the empty
host it produces then fails the Normalized URL's
LDH-host check (WIST-1 §2), so `normalize_url("https:///x", base)` returns
`None` rather than falling back to any host.

**Why it qualifies.** WIST-2 §11 step 5 already named RFC 3986 §5 as the
resolution algorithm; this states what that pin already implied about
empty-authority candidates rather than adding a rule. `tools/link_extraction.py`'s
own fixtures never construct a `scheme:///path` candidate, so no vector
result changes.

**Status.** Unexercised. Neither `vectors/wist2/link-extraction.json` nor
`tools/link_extraction.py`'s fixtures carry an empty-authority candidate.
The tool's own fix is left to a later change to the tool.

## 2026-08-08 — WIST-2 §11 step 5: `link_extraction.py` and empty path segments

No document text changes. Same pin as the entry above, a second divergence
in the same function.

**What it states.** `urllib.parse.urljoin` merging `a//b` against
`https://example.com/blog/post-1` collapses the doubled `/` and yields
`https://example.com/blog/a/b`. RFC 3986 §5.2.3 Merge Paths and §5.2.4
Remove Dot Segments — the algorithm WIST-2 §11 step 5 pins — merge the
base's directory prefix with the reference's path unchanged and remove only
`.` and `..` segments; an empty segment between two `/` characters is
neither, so the RFC-correct result is `https://example.com/blog/a//b`.
An implementation following §5.2.3/§5.2.4 literally produces exactly
this: `a//b` against this base normalizes to
`https://example.com/blog/a//b`, and `x//` to `https://example.com/blog/x//`.

**Why it qualifies.** Same pin as the entry above: WIST-2 §11 step 5 already
named RFC 3986 §5, so this states what the existing text implied rather than
adding a rule. `tools/link_extraction.py`'s own fixtures never carry an
empty interior path segment in a relative reference, so no vector result
changes.

**Status.** Unexercised: `vectors/wist2/link-extraction.json` carries no
candidate with an empty interior path segment. The tool's own fix is left to a later
change to the tool.

## 2026-08-11 — WIST-4 §5, §9, registry-update schema: bounded Auditor fetches (revision, not errata)

Adds the fetch-bounds passage to §5 (four parameters:
`audit_fetch_cap_bytes`, `audit_domain_budget_bytes_day`,
`audit_redirect_max`, `audit_fetch_timeout_seconds`), extends the
`unreachable` and `not_auditable` rows of the §5 verdict table and the
blocking-Record definition to name them, adds their §9 registry rows,
bounds and combination rule, adds two Auditor conformance-checklist items,
and registers the four identifiers (with floors for three) in
`schemas/registry-update.schema.json`. Decision record: ADR-0010.

**Why it is a revision.** It fails the first errata condition: an Auditor
that conformed to the prior text by reading arbitrarily large responses, or
following unbounded redirects, now has behavior the text bounds, and a
`parameter_change` naming one of the four identifiers was schema-invalid
before this change and is valid after it. The defect that provoked it is
scoped and stated in ADR-0010: every other fetch magnitude in the suite was
bounded, and two honest Auditors with different implicit limits could reach
different verdicts on the same URL — the disagreement §4's integer
arithmetic exists to eliminate, reproduced one layer down.

**What it does not change.** No verdict is added, no Record field changes,
no error code is added; `unreachable` and `not_auditable` already omit the
commitment fields for exactly the cases the bounds produce.

**Status.** Unexercised. No vector reaches the fetch layer; the bounds
enter the vector suite only when audit-behavior vectors exist at all
(none exist — the suite carries no §4/§5 audit-behavior vectors).
