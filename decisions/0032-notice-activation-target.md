# ADR-0032: A sanction notice names one rung activation

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012, ADR-0021, ADR-0022

## Context

A notice carried no level or activation identity, although a notice-scoped
reversal must leave later rearmings untouched. Repeated notices also left
room for competing clocks over one activation.

## Decision

Require level 3 or 4 and the confirming Record ID that armed it. Accept
one notice per subject, level and activation: the first eligible Block's
unique candidate, with simultaneous conflicts rejected together. Targets
must be active or newly armed in that Block. Later notices restart nothing.
A notice-scoped reversal reaches only a still-matching activation.

## Consequences

An old process cannot clear a new activation. Same-Block findings may
support notices without making notice validation change rung derivation.
Recovery notices remain outside sanction process.
