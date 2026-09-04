# ADR-0016: The audit reference is the chain tip at fetch

**Status:** accepted · **Date:** 2026-08-21

## Context

WIST-4 §5 fixed an audit's Reference Payload by the audited Delta alone,
and WIST-3 §6.1 stated that the resolution "carries no liveness
qualifier" by design, so that a Record audited honestly would keep
verifying after a later `update` moved the URL's anchor. The Aggregator
retains superseded Payloads for one availability window after
supersession precisely so the superseded Delta stays auditable.

Under that rule an honest Publisher that rewrites a page and seals the
rewrite while the previous Delta is still inside its audit window is
measured, by every Auditor fetching after the rewrite, against text it
has already replaced. A thorough rewrite scores a containment near zero,
which §7 reads as severity 3 — fabricated content — and a single
severity-3 Confirmed Inconsistency is level 3 of the sanction ladder.
The extension rule makes confirmation near-certain: it summons every
independent Auditor *after* the first `inconsistent`, and every one of
them sees the same rewrite. For a URL that changes faster than the audit
window this is not a race but the steady state. The sentence in §5
claiming that independent confirmation "absorbs … legitimate change
between push and audit" held only for change that differs by vantage or
by moment, never for change the Publisher sealed.

The verifiability argument behind the old rule does not require the
reference to be the audited Delta. It requires that the reference not
*move* after the Record is written. Naming the reference in the Record
satisfies that with any Delta in the chain.

## Decision

Every Audit Record carries `reference_delta`: the newest Delta of the
audited Delta's per-URL chain sealed in a Block whose `sealed_at` is at
or before the Record's `fetched_at`. The Reference Payload is the anchor
as of that Delta — its own Payload where it is content-bearing, the last
content-bearing Payload at or before it otherwise — and the change type
read for the `delete` mirror, the link dimension and `C` is the
reference Delta's. The salt stays the Reference Payload's.

A validator recomputing reputation rejects, as malformed evidence, a
reference outside the audited Delta's chain, before the audited Delta in
it, or sealed after `fetched_at`. Whether the Auditor named the newest
qualifying Delta rather than an older one is not decidable from the Log;
it is a false statement of the same class as a false `similarity` and
meets the same answer — a second independent Auditor, and contradiction
for a lone stale filing.

Selection, coverage, the extension rule, confirmation, the confirming
Block, severity and the one-penalty-per-Delta rule stay keyed by
`audited_delta`. Only what the similarity is read against changes.

## Alternatives considered

**Similarity as the maximum over the audited Delta's Payload and every
later content-bearing Payload sealed before the Record's Block.** Keeps
the audited Delta's salt and needs no new member. Rejected because it is
defeated without detecting the fetch: a Publisher alternating a false
`update` and a true one hourly has, for every audit of a false Delta, a
true Delta sealed before the Record's Block — Records seal days after
the fetch — so the maximum reads `consistent` and the index carries the
false claim half the time, uncaught.

**A neutral verdict whenever a later Delta exists.** Rejected because a
Publisher that follows every Delta with an `update` is never measured.

**Keying Confirmed Inconsistencies by `reference_delta`.** One penalty
per declared state that was not served, rather than per audited Delta.
More principled, and a larger revision: confirmation pairs, the
extension rule's summons and the confirming-Block selection would all
regroup by reference. Deferred; a lie served while k Deltas were audited
can yield up to k penalties under this decision, each for a Delta the
Publisher sealed under that lie, and the narrower change can return as
its own decision if that proves wrong in practice.

## Consequences

- The Record schema gains a REQUIRED member. Verdicts change for any
  audit whose chain advanced before the fetch, so this is a revision.
- WIST-3 §6.1's serving window after supersession now exists to keep
  sealed Records verifiable; fresh audits read the current anchor.
- An Auditor behind on the Log names a stale tip and is contradicted,
  at a cost bounded by `contradictions_max`.
- A Publisher that answers a sealed `inconsistent` with a truthful
  `update` before the summoned Auditors fetch has them resolve the new
  tip and file `consistent`, which contradicts the honest filer under §4
  and counts toward its `contradictions_max`. The cost lands on the
  Auditor, bounded by that parameter, and it is the same cloaked-vantage
  class §4's contradiction rule already accepts.
- Change the Publisher seals before the fetch is absorbed; change that
  propagates to the served page after its Delta seals is not, and is
  left named rather than solved.
- Every later construction keyed by "the Reference Payload's salt"
  reads the reference Delta's.
- `vectors/wist4/superseded-audit.json` carries the cases that separate
  this rule from the rejected maximum: a reference sealed after the
  fetch is rejected, a stale reference is valid and measured.

## Addendum (2026-09-04) — no minimum fetch delay

The Consequences leave change that propagates to the served page after
its Delta seals named rather than solved, and a minimum fetch delay in
Blocks — a floor on `fetched_at` some cadences above the audited Block's
`sealed_at`, so that caches settle before the first fetch — was the
candidate remedy. It is not adopted.

The Publisher holds both instants the race runs between: it purges its
caches and it sends the Ping (WIST-2 §4), so it can ping when propagation
is done, and its Delta's `observed_at` asserts the page already is what
the Delta describes. An Auditor that fetches at the audited Block's
`sealed_at` and meets a stale edge files `inconsistent`; the Auditors
§4's extension rule summons fetch after *B₁* seals, at least one cadence
later, and file `consistent`; the first filer is contradicted at a cost
bounded by `contradictions_max` — the class the Consequences already
accept, landing on the party that fetched early. A fixed delay would
shift the same race later by a constant, protect only the Publishers
whose propagation happens to fit inside it, and add a Registry parameter
to §3's fetch interval for that. The incentive as it stands already
points the eager Auditor at a later fetch, and no section is changed.
