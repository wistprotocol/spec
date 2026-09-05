# ADR-0019: A confirmation quorum shares one window

**Status:** accepted; amended by ADR-0027 (2026-09-05: anchor parameter reads for in-flight windows) · **Date:** 2026-09-05
**Amends:** ADR-0012

## Context

WIST-4 §9 permits `confirm_auditors` above two, but §§5 and 7 describe
pairs. A stale Record and a fresh independent pair can therefore either
confirm or fail an amended quorum of three. The contradiction predicate
likewise counts two consistent Auditors regardless of the amendment.

## Decision

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

## Consequences

Default two-member confirmation is unchanged. An amended quorum no
longer accepts a stale member merely because two others are fresh, and
a consistent pair alone cannot contradict under a quorum of three.
A smaller roster may be unable to meet the amended threshold; no
implicit reduction of a governance-selected quorum is permitted.
