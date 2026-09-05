# ADR-0027: Anchor parameters for in-flight windows

**Status:** accepted; amended by ADR-0036 (2026-09-05: retain cited Blocks through each actual notice process); amended by ADR-0035 (2026-09-05: cadence transitions preserve older extension profiles); amended by ADR-0034 (2026-09-05: canary reveals require actual post-duty sealing opportunities) · **Date:** 2026-09-05
**Amends:** ADR-0012, ADR-0019, ADR-0022

## Context

Changing a duration while a duty is outstanding could move its deadline
on replay. Confirmation also lacked a parameter read instant when Records
straddled a quorum or window amendment.

## Decision

WIST-4 §9 lists each clock's anchor. Duties retain their opening profile;
confirmation evaluates each candidate under its own Block's profile and
preserves its first historical success. An extension's contradiction test
retains its triggering profile and closes once. A later confirmation does
not rewrite that closed test. Appeal and seal clocks read the notice;
the ruling clock reads the accepted appeal.

## Consequences

Recomputation preserves established deadlines and findings. Epoch,
selection, reputation and materialization reads keep their explicit
anchors. A fixed count of Blocks still follows the actual cadence.
