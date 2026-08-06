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
