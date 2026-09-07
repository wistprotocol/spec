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

## Appeal processes have deterministic conflict rules

### Context

WIST-4 §7 gives a notice one appeal and ruling clock but does not choose
among several sealed appeals or contradictory rulings. WIST-2's immutable
served appeal path does not prevent conflicting acts in a Log.

### Decision

Use one appeal, one merits ruling and one unappealed-statement slot per
notice. Registry Update IDs deduplicate acts at their first sealing
Block. The first eligible act fills its slot; distinct competing acts in
one Block all fail as `WIST4-E05`, leaving that slot open. Later distinct
acts cannot replace an accepted one. Resolve appeals before rulings in
a Block, independent of stored Entry order.

Merits rulings require the timely appeal and must seal by its ruling
deadline. Unappealed statements use the existing window-close-to-T
interval and cannot defeat a timely sealed appeal. Every act names a
sealed sanction notice for its own subject. Invalid acts fill no slot.

### Consequences

A conflicting batch cannot let Entry order select a favorable outcome.
A later valid act can still fill an unoccupied slot before its deadline.
Once a merits ruling closes a process, a discretionary change uses
`sanction_lift`; a second ruling cannot rewrite its outcome.

## A sanction identifies its primary finding

### Context

One sanction severity could not be matched unambiguously to an evidence
array containing several findings of different severities.

### Decision

Require `details.finding`, the first confirming Audit Record ID of one
finding for the subject. Its closed confirming set determines the scalar
severity. Evidence includes that Record and a complete quorum establishing
the finding there; additional Audit Record evidence may differ in severity.
All cited Records must be available at the sanction's Block.

### Consequences

Optional corroboration cannot change a sanction's primary severity.
The derived ladder continues to count every qualifying finding.

## A sanction notice names one rung activation

### Context

A notice carried no level or activation identity, although a notice-scoped
reversal must leave later rearmings untouched. Repeated notices also left
room for competing clocks over one activation.

### Decision

Require level 3 or 4 and the confirming Record ID that armed it. Accept
one notice per subject, level and activation: the first eligible Block's
unique candidate, with simultaneous conflicts rejected together. Targets
must be active or newly armed in that Block. Later notices restart nothing.
A notice-scoped reversal reaches only a still-matching activation.

### Consequences

An old process cannot clear a new activation. Same-Block findings may
support notices without making notice validation change rung derivation.
Recovery notices remain outside sanction process.

## Retain cited Blocks through the actual sanction process

### Context

Notice and appeal clocks can read different parameter maps. The sum in a
single current map therefore need not cover an older notice's proceeding.
Cited evidence may also be old before the notice opens an appeal window.

### Decision

A Mirror serving an accepted sanction notice must serve the notice and
its cited Audit Record Blocks through the process's actual closing
instant. It acquires missing evidence before serving the notice Block.
No accepted appeal means closure at T, even with an earlier unappealed
statement. An accepted appeal means closure at its ruling deadline or an
earlier accepted merits ruling. Preserve prefix causality and include the
closing endpoint. Ordinary Block retention reads its value at first service.

### Consequences

Parameter changes cannot make a Mirror discard sealed evidence during an
open proceeding. Multiple processes impose overlapping duties. The rule
protects Blocks; Payload availability and withdrawal keep their own rules.

## Merits rulings follow the target activation's Block

### Context

A notice can name an activation first armed in its own Block, and an
appeal and merits ruling can otherwise share that Block. Reversals apply
before confirming findings, when this target does not yet exist.

### Decision

Require a merits ruling to seal strictly above its target activation's
Block. An earlier or same-Block ruling is ineligible (`WIST4-E05`), fills
no ruling slot and schedules no deferred reversal. A notice and appeal
may still seal in the activation's Block. A later distinct ruling follows
the existing deadline and multiplicity rules.

### Consequences

Registry-before-finding replay remains unchanged. An overturning ruling
can only clear an activation that already exists at its reversal phase.
Same-Block appeals remain timely; rejection of an early ruling neither
restarts the appeal clock nor prevents a subsequent eligible ruling.
