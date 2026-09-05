# ADR-0018: Sanction rungs latch until reversed

**Status:** draft · **Date:** 2026-09-05

## Context

WIST-4 §7 says rungs remain in force from their establishing Block onward,
but describes a high-rung reversal using lower criteria at the reversal
height. It does not explicitly settle aging, rearming, or a lift sharing
a Block with a confirming Record.

## Decision

Latch each rung independently until its reversal or identity reset.
Counting windows govern entry, not automatic expiry. A high-rung void
clears only its activation; lower latched rungs survive aged evidence.
A lift clears every rung before the Block's confirming Records, following
WIST-3's application order. A same-Block finding may rearm a rung.

Evaluate each branch on new qualifying findings, in confirming-Record
order. Retain pre-reversal findings in counting windows. The level-4
further-finding branch reads level 3 immediately before the new finding,
so two findings in one Block may reach levels 3 then 4. A single finding
cannot supply both the initial level 3 and its own further finding.

## Consequences

A weight reduction no longer has an implicit aging expiry. Reversal
cannot be defeated by immediately rereading unchanged evidence. A new
qualifying finding can rearm a rung, with old findings still contributing
to its window. Notice-scoped reversals do not clear later activations.

## A confirmation quorum shares one window

### Context

WIST-4 §9 permits `confirm_auditors` above two, but §§5 and 7 describe
pairs. A stale Record and a fresh independent pair can therefore either
confirm or fail an amended quorum of three. The contradiction predicate
likewise counts two consistent Auditors regardless of the amendment.

### Decision

Every quorum member lies inside one closed `confirm_window_hours` window
ending at the confirming Record's Block. Count pairwise independent
Auditors, separately for extract and link verdicts. The earliest Record
completing `confirm_auditors` members establishes the finding. Severity
still reads the full prefix specified by §7, rather than a selected
quorum witness.

A triggered extension closes contradicted only when no complete quorum
of the triggering verdict includes that trigger and a complete quorum
of independent consistent Auditors sealed inside its closed window.
Both thresholds read `confirm_auditors`.

### Consequences

Default two-member confirmation is unchanged. An amended quorum no
longer accepts a stale member merely because two others are fresh, and
a consistent pair alone cannot contradict under a quorum of three.
A smaller roster may be unable to meet the amended threshold; no
implicit reduction of a governance-selected quorum is permitted.
