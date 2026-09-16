# ADR-0036: Registry Update field, version and authenticity dispositions

**Status:** draft · **Date:** 2026-09-14

## Context

The Registry Update schema constrains every Envelope, but the error registry
named codes only for `details`/`evidence` contract failures, roster, canary,
parameter and process rules. An Envelope carrying unknown members, a
malformed signature field, an unsupported major version, a timestamp
denoting no instant, or a signature that fails under the key its action's
signing rule names had no diagnostic and no stated precedence, and nothing
said whether such an act still takes part in §3.1's batch. The subject shape
§9.1 requires of roster acts likewise named no code.

## Decision

WIST-4 §9.1 defines the eligibility gate every Registry Update passes before
any semantic rule: WIST-1 §4 JSON/JCS eligibility (`WIST1-E05`), then the
complete schema, partitioned into the action's `details`, `evidence` and
`subject` contract (`WIST4-E04`) and every other field failure (`WIST4-E11`),
then the act's own version support (`WIST4-E11`), then authenticity under the
signing rule its action fixes (`WIST4-E11` unless the act's section registers
another code, as §3.1 does for checkpoints and §7 for appeals). E11 precedes
E04; field failures precede authenticity; authenticity precedes semantics. An
act rejected at the gate is no candidate in §3.1's batch and changes no
state; the containing Block stays valid. The schema's version, timestamp and
identifier patterns are exact whole-string patterns, and an `auditor_remove`
subject carries the hostname shape an `auditor_admit` requires.

A `payload_withdrawal` is authenticated under the Log key (WIST4-E11
otherwise); its `delta_id` must name a Delta sealed at or below the act's
Block whose signed `publisher` is the `subject`, or the act fails its
`details` contract (WIST4-E04). Repeated withdrawals of one Delta are
accepted, the earliest Block governing. Rejecting a withdrawal of an
unsealed or foreign Delta keeps the act's `subject` truthful and gives every
replayer one withdrawal height per Delta.

Every Registry Update is identified by its ID: a repeated occurrence is
idempotent for roster acts, checkpoints, attestations and canary acts as
§7 already made it for process acts, so a re-sealed Entry never re-applies,
conflicts with itself or scores twice. Canary subjects keep §9.1's two-label
hostname shape (WIST4-E04 otherwise), matching Observers and Auditors and
the two-label suffix the epoch ration reads; a `leaves` below 1 is a
contract failure (WIST4-E04) while one above `canary_leaves_max` is the
parameter-dependent rejection (WIST4-E08).

## Alternatives and consequences

Ignoring such acts without a code leaves implementations no shared
diagnostic and no precedence, so two validators could report a malformed
admission as E04, E07 or nothing. Assigning field failures to E04 would make
one code cover both an action's contract and unrelated Envelope defects,
which §10.1 already separates for Records (E09/E02). Letting a malformed or
unauthenticated act into stage 1 would let anyone who can place bytes in a
Block reject a same-subject admission without holding any key.

Reusing `WIST1-E01` for every failing signature would mislabel an act signed
under the wrong key, whose signature may verify under a key the rule does not
admit. Where a section already names a code the gate defers to it, so
existing checkpoint and appeal dispositions do not change.

`vectors/wist4/roster-acts.json` supplies signed roster-act histories with
raw JSON, field, version, precedence, authenticity and batch-participation
cases. Publisher-signed governance acts and Aggregator-signed process acts
follow the same gate; their vectors accompany the canary and process work
recorded in [CONFORMANCE.md](../CONFORMANCE.md).

The undeployed draft changes under [PUBLICATION.md](../PUBLICATION.md).
