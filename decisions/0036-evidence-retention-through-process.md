# ADR-0036: Retain cited Blocks through the actual sanction process

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012, ADR-0022, ADR-0027

## Context

Notice and appeal clocks can read different parameter maps. The sum in a
single current map therefore need not cover an older notice's proceeding.
Cited evidence may also be old before the notice opens an appeal window.

## Decision

A Mirror serving an accepted sanction notice must serve the notice and
its cited Audit Record Blocks through the process's actual closing
instant. It acquires missing evidence before serving the notice Block.
No accepted appeal means closure at T, even with an earlier unappealed
statement. An accepted appeal means closure at its ruling deadline or an
earlier accepted merits ruling. Preserve prefix causality and include the
closing endpoint. Ordinary Block retention reads its value at first service.

## Consequences

Parameter changes cannot make a Mirror discard sealed evidence during an
open proceeding. Multiple processes impose overlapping duties. The rule
protects Blocks; Payload availability and withdrawal keep their own rules.
