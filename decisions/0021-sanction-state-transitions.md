# ADR-0021: Sanction rungs latch until reversed

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012

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
