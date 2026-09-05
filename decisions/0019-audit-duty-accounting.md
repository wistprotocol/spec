# ADR-0019: Late-sealed discharge clears the current coverage count

**Status:** draft · **Date:** 2026-09-05

## Context

WIST-4 §4 requires publication by a deadline but permits subsequent
sealing. It does not expressly settle a Record first sealed after an
unmet pull attestation or the unattested fallback established a failure.
The sealing instant alone cannot prove when the Record was published.

## Decision

Read completed duty from the available Log prefix. A complete discharge
removes the pair from the current count from its completion Block,
without requiring suppression evidence. Partial completion does not.
Apply the existing standing and void-discharge rules. Empty selection
still needs its coverage attestation.

## Consequences

Later completion changes no prior prefix or sealed removal. It proves
completion rather than timely publication; the publication duty remains.
Keeping a failure solely because its discharge sealed late would make
an allowed transport delay indistinguishable from Auditor shirking.

## Extension triggers spend ration in Log order

### Context

Two eligible triggers by one Auditor can seal in one Block with one
ration slot remaining. WIST-4 §4 gave no tie rule, while WIST-3 §3.3
claimed Audit Records did not read intra-Block position. Confirmation
already reads the canonical stored Entry order.

### Decision

Evaluate triggers in ascending Block height and Entry index. Eligibility
and ration use the strict prefix before each trigger, including earlier
Entries in its Block. Peer exclusion also includes the trigger itself. Extract and link inconsistency
Records share the per-Delta trigger sequence and per-Auditor ration.
The earlier eligible Entry spends the last slot. A later Record remains
valid and contributes to confirmation even when it summons nobody.

### Consequences

Canonical Entry order supplies the tie without new ordering freedom.
A later same-Block filing cannot retroactively cancel a trigger or remove
one of its summoned peers. WIST-3 names the ordering-dependent extension
and confirmation rules explicitly.

## Attested suppression evidence names the affected duty

### Context

A missing `prev_record` ID contains no visible Auditor duty or Block.
WIST-4 §4 nevertheless asks whether a successor contradicts a particular
unmet pull attestation. A generic missing predecessor cannot supply that
attribution.

### Decision

Require the missing ID to appear in that pull attestation's `found` list.
The same Auditor's successor for the same Log must seal at or above the
attestation height, including its own Block. Read both the successor and
the missing-ID test from the prefix through N. An unrelated gap exempts
no attested pair. Once the missing item seals, ordinary discharge decides
completion.

### Consequences

The Aggregator's signed receipt supplies the pair attribution without
putting off-Log publication time into replay. Empty or unrelated receipts
give no chain-based exemption. This decision does not expand the separate
unattested-pair rule.
