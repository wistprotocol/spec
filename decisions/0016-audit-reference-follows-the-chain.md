# ADR-0016: The audit reference is the chain tip at fetch

**Status:** draft · **Date:** 2026-08-21

## Context

An honest Publisher may rewrite a page and seal its update while a previous
Delta remains inside its audit window. Comparing every later fetch with
the old Payload can classify the legitimate rewrite as fabricated content.
Summoning independent Auditors does not cure that mismatch: they all see
the same updated page. Historical verification needs a reference fixed
when a Record is written, rather than a reference permanently tied to the
Delta that originally triggered selection.

WIST-4 §§3–5 define Record validity, selection and measurement; WIST-1 §3.3
and WIST-3 §6.1 define Payload anchoring and availability. WIST-4 §9 fixes
the parameter profile used to interpret the measured text.

## Decision

### Reference identity

Each Audit Record names `reference_delta`: the newest Delta of the audited
Delta's per-URL chain sealed at or before `fetched_at`. The Reference
Payload is that Delta's anchor: its own Payload if content-bearing, or the
last content-bearing Payload at or before it otherwise. Its change type
governs the delete mirror, link dimension and `C`; its salt governs the
Record's commitments.

A reference outside the audited chain, before the audited Delta or sealed
after the fetch is malformed evidence. Whether an Auditor named the newest
qualifying Delta rather than an older eligible one is a statement subject
to independent audit and contradiction, like the claimed similarity.
Selection, coverage, extension triggers, confirmation, severity and the
one-penalty-per-Delta rule remain keyed by `audited_delta`.

### Extraction and scoring profile

Read shingle size, observed-word mass guard and both similarity thresholds
at the audited Delta's Block for Record production and hard-hit scoring.
This applies to ordinary and extension audits by Auditors and Observers.
The reference Delta and later publication, checkpoint, reveal and query
instants cannot move the profile. Observer Records need no individual
sealing Block to supply this anchor.

An unchanged Record therefore retains its extract-band interpretation after
a parameter change. The reveal separately anchors its availability and
scoring-window duration. Unicode interpretation and the delete mirror
remain the document's fixed rules.

### Reference availability and fetch limits

When a daily budget prevents obtaining a verified Reference Payload with
a nonempty normalized extract, record `not_auditable` with
`unmeasured = reference`, which is nonblocking. The same applies when all
reference sources fail under timeout or redirect limits. If a usable
reference is available and the audited URL fetch exhausts the byte budget,
use `unmeasured = observed`, blocking. A previously obtained reference
remains available when the budget expires. No fetch order is prescribed.

The `unreachable` result for transport limits concerns the audited URL
fetch with a usable reference available. Missing reference evidence must
not become evidence that the Publisher's page is unmeasurable. The sealed
side makes the blocking distinction replayable without reconstructing
the Auditor's network budget.

### Publication timing

There is no minimum delay from the audited Block to fetching. The
Publisher controls when it sends its Ping and can wait for its content to
propagate; `observed_at` asserts the page already matches the declaration.
A stale edge can still produce a false inconsistency. Contradiction then
escalates the audited domain's sampling without itself removing the
Auditor, under [ADR-0012](0012-auditor-track-record-becomes-derivable.md).

## Alternatives considered

**Maximum similarity across the audited Payload and later Payloads.** A
Publisher could alternate false and true updates and use a later truthful
Payload to excuse a false claim. Reading the reference at fetch time
prevents an update after the fetch from repairing that Record's reference.

**A neutral verdict whenever an update follows.** A Publisher could avoid
measurement simply by continually updating.

**Confirming by `reference_delta` instead of `audited_delta`.** This would
regroup confirmation, extension summons and penalty identity. The chosen
design preserves one finding identity per selected Delta; a lie served
while several Deltas are audited can therefore produce several penalties.

**A mandatory fetch delay.** A Publisher that already controls propagation
and its Ping can also time a delayed audit. A fixed delay adds a timing
rule without making every cache settle or establishing honest delivery.

## Consequences and verification

Naming the reference keeps a Record verifiable after later updates.
Superseded Payload retention supports that verification; fresh audits read
the current anchor. A truthful update after an inconsistent fetch can make
later Auditors report consistency, which is why contradiction increases
scrutiny without itself proving misconduct by the original filer.

`vectors/wist4/superseded-audit.json` exercises reference eligibility;
`canary.json` exercises scoring profiles; `unauditable.json` exercises the
observed/reference distinction. Live retrieval, budget exhaustion and
evidence capture additionally require the WIST-4 role checks.
