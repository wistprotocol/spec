# ADR-0020: Extension triggers spend ration in Log order

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012

## Context

Two eligible triggers by one Auditor can seal in one Block with one
ration slot remaining. WIST-4 §4 gave no tie rule, while WIST-3 §3.3
claimed Audit Records did not read intra-Block position. Confirmation
already reads the canonical stored Entry order.

## Decision

Evaluate triggers in ascending Block height and Entry index. Eligibility
and ration use the strict prefix before each trigger, including earlier
Entries in its Block. Peer exclusion also includes the trigger itself. Extract and link inconsistency
Records share the per-Delta trigger sequence and per-Auditor ration.
The earlier eligible Entry spends the last slot. A later Record remains
valid and contributes to confirmation even when it summons nobody.

## Consequences

Canonical Entry order supplies the tie without new ordering freedom.
A later same-Block filing cannot retroactively cancel a trigger or remove
one of its summoned peers. WIST-3 names the ordering-dependent extension
and confirmation rules explicitly.
