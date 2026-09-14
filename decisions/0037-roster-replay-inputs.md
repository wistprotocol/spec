# ADR-0037: Roster replay reads sealed strings and post-batch tenures

**Status:** draft · **Date:** 2026-09-14

## Context

Three roster questions were left to implementation choice. Whether an
`observer_checkpoint` whose `head` names no sealed Entry is rejected; which
registration a checkpoint sealed beside a rotation or an admission is read
against, and whether a same-Block registration or checkpoint counts toward an
admission's `track_record`; and whether an `auditor_admit` naming a
`public_key` that decodes to an unusable point is rejected at admission or
admitted and fails at verification.

## Decision

WIST-4 §3.1 checks `head` by spelling only: what it covers is read when a
scoreboard is derived over the Observer's served chain, never at replay. A
checkpoint reads the registrations in force after its Block's batch, since a
registration holds from its own Block's `sealed_at`. An admission reads
Observer history and citable checkpoints strictly below its Block. WIST-4 §3
admits a `public_key` by spelling; an unusable point holds the slot and
every Record and proof under it fails verification (`WIST4-E01`).

## Alternatives and consequences

Requiring `head` to name a sealed Entry would reject every Observer whose
Records never reach the Log, and requiring it to name a served Record would
make two replayers holding different served histories derive different
rosters, which §3.1 forbids. Reading pre-batch registrations for checkpoints
would leave a rotating Observer unable to checkpoint under its new key in
the rotation's Block while the tenure rule already ends the old key there.
Counting a same-Block checkpoint as citable would make an admission's
evidence depend on whether the admission itself applies, since the admission
ends the registration the checkpoint needs.

Rejecting an unusable admitted key as `WIST4-E04` would make the roster a
function of point arithmetic rather than sealed strings and contradict §4,
which already treats a proof under such a key as a Record failure. The cost
is an Auditor slot held by a key that can sign nothing until the Aggregator
removes it; coverage failure accrues to that identity in the meantime, as it
does for any Auditor that publishes nothing.

`vectors/wist4/roster-acts.json` supplies same-Block registration, rotation,
checkpoint and admission histories, unsealed and Delta-shaped heads, and a
small-order admission with a Record probe under it.

The undeployed draft changes under [PUBLICATION.md](../PUBLICATION.md).
