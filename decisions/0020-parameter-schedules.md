# ADR-0020: Parameter schedules preserve historical obligations

**Status:** draft · **Date:** 2026-09-05

## Context

Parameters that are valid individually can form an invalid future state.
For example, a pending sampling floor of 4,000,000 and a pending ceiling
of 3,000,000 can each pass against defaults while failing together.
Changing duration, cadence or byte caps can also invalidate an obligation
established before the change. WIST-4 §9 therefore validates the accepted
schedule and preserves the parameter profiles that opened existing duties.

## Decision

### Admission and integer bounds

Validate candidates in canonical Log order. After individual checks,
tentatively insert the candidate and check every combination rule at
sealing and every pending effective instant. Use greatest effective time
and the specified Log-order tie rule. Reject an invalid prospective map
as `WIST4-E03`; otherwise retain the candidate. Never roll back an earlier
acceptance or reconsider a rejection because of a later candidate.

All wire integer members fit ±(2^53−1), inclusive, in addition to their
field-specific bounds. `provisional_cap_u` is nonnegative. Intermediate
arithmetic remains exact and may exceed the wire range. Schema acceptance
does not replace semantic schedule validation.

The compound escalation predicates in WIST-4 §7 have no integer encoding.
`escalation_l2`, `escalation_l3` and `escalation_l4` are not Registry
identifiers; attempts to amend them reject as `WIST4-E03`. Changing those
predicates requires a protocol change with a defined representation.

### Temporal profiles

WIST-4 §9 fixes each clock's anchor. Duties retain their opening profile;
confirmation evaluates each candidate at its own Block and preserves the
first success. Extension contradiction uses the triggering profile and
closes once. Appeal and seal clocks read the notice; ruling duration reads
the accepted appeal. Epochs, selection, reputation and materialization use
their specified anchors. Block counts still follow actual sealing cadence.

Extraction and hard-hit thresholds read the audited Delta's Block, not a
later reference, checkpoint, reveal or scoring instant; see
[ADR-0016](0016-audit-reference-follows-the-chain.md). Actual sanction
process retention follows [ADR-0018](0018-confirmation-and-sanctions.md).

### Delta and Payload sizes

WIST-1 §3.6 defines size-cap parameter time for admission, sealing and
historical verification. Admission needs a locally available clock and
accepted prefix; sealing supplies the authenticated instant every later
validator can reconstruct. Retaining an attempt's profile through Payload
retrieval prevents network delay alone from splitting its checks.

Admission-time permanence would require an additional authenticated receipt
and make otherwise identical sealed Deltas depend on unpublished state.
Using `observed_at` would let Publishers select obsolete caps by backdating.
Using the replay clock would make a reduction invalidate already-sealed
content and let an increase conceal an invalid inclusion. Applying pending
reductions early would shorten their announced grace period.

Rechecking at sealing can reject queued content after a reduction. A
Publisher must produce content that fits the sealing profile; its signature
and commitment cannot be rewritten by the Aggregator. An old reference
Payload remains valid under its own committing Delta's profile even when a
later audit uses a different extraction or verdict profile. This assumes
availability of the authenticated schedule through each relevant Block;
a missing prefix cannot be replaced with current defaults.

### Delta clock eligibility

WIST-1 §3.4 fixes both the clock and `clock_skew_seconds` for admission,
sealing and historical validation. An unsealed attempt freezes its local
clock and schedule; sealing rechecks against the candidate Block, whose
clock and allowance every historical validator can reconstruct.

Using replay time would let the same history acquire different eligible
Deltas and reputation merely by waiting. Using a later allowance could
invalidate earlier inclusions after a reduction or conceal invalid ones
after an increase; negative allowances make even old observations vulnerable
to such reclassification. Using `observed_at` as the anchor would give the
Publisher control over the bound. Freezing the admission clock permanently
would require an authenticated receipt absent from the Log.

The committing Block supplies a deterministic clock, not independent proof
of civil time. A queued Delta may fail after an allowance reduction, and a
later wall clock cannot repair an invalid sealed inclusion. Exact arithmetic
preserves signed allowances and fractional endpoints without requiring every
computed bound to have a four-digit timestamp representation.

### Cadence transitions

For every constant-map interval, retain its extension publication span,
window and seal count. Bound sealing by the largest cadence that may be
in force before a window opened in that interval closes. The interval's
end plus its window is exclusive. Reject a tentative schedule that breaks
this bound, regardless of whether particular triggers have occurred.

A 72-hour extension allowing publication at hour 36 and sealing within
24 Blocks cannot safely change from hourly to two-hourly Blocks while
that profile may still govern a window. Increasing only the incoming
profile's window to 96 hours does not protect the older duty. Stage the
larger window early enough for earlier windows to close before slowing
cadence. Even brief increases participate in the compatibility bound.
Canary readiness additionally checks actual service opportunities under
[ADR-0012](0012-auditor-track-record-becomes-derivable.md).

### Block sizes and transport

Every candidate's prospective caps cover the largest complete JCS Block
through its own height. Every new Block respects the current cap and all
accepted pending caps, so production cannot invalidate an accepted
reduction. Historical replay uses the running maximum at each height;
restoration preserves or reconstructs that maximum and the accepted
schedule, including pending amendments.

Before decompressing, use the greatest current or future cap in the
verified prefix, or the Registry default before genesis. Authenticate the
Block and replay its amendments before enforcing the tighter current and
prospective size bounds. Missing or false frame sizes and exceeded Block
bounds reject as `WIST3-E03`; infeasible amendments reject as `WIST4-E03`.

## Consequences and alternatives

No invalid intermediate map can hide behind a later valid one. Replacing
a same-time amendment requires the replacement to pass; current-state-only
validation is insufficient. Pinning opening profiles prevents a later edit
from moving an established deadline, while cadence checks protect the actual
time available to fulfill it.

A cap reduction cannot make an old Block unreadable. A future increase can
authorize a larger Block without trusting its unread header to discover
the decompression bound. Transport may permit more bytes than an individual
Block may occupy, so authentication and tighter semantic checks are both
necessary. Pending reductions constrain production immediately.

## Verification

`vectors/wist4/parameter-combinations.json` exercises prospective maps,
cadence transitions, retention, wire bounds and Block-size guarantees,
including ordering, exact endpoints, pending increases and restoration.
`vectors/wist1/delta-cap-time.json` adds signed size-cap histories and
admission/sealing/retrieval probes across increases and decreases.
`vectors/wist1/delta-clock-time.json` distinguishes frozen attempt clocks,
sealing rechecks and historical clock/allowance anchors across amendments,
including signed negative allowances and exact fractional endpoints.
Live pacing, durable publication and recovery additionally require the
WIST-3 and WIST-4 role checks.
