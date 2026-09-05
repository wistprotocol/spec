# ADR-0022: Appeal processes have deterministic conflict rules

**Status:** accepted; amended by ADR-0032 (2026-09-05: notices bind one rung activation and one process); amended by ADR-0027 (2026-09-05: anchor parameter reads for in-flight windows) · **Date:** 2026-09-05
**Amends:** ADR-0012

## Context

WIST-4 §7 gives a notice one appeal and ruling clock but does not choose
among several sealed appeals or contradictory rulings. WIST-2's immutable
served appeal path does not prevent conflicting acts in a Log.

## Decision

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

## Consequences

A conflicting batch cannot let Entry order select a favorable outcome.
A later valid act can still fill an unoccupied slot before its deadline.
Once a merits ruling closes a process, a discretionary change uses
`sanction_lift`; a second ruling cannot rewrite its outcome.
