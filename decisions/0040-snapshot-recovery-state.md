# ADR-0040: Snapshot recovery state carries the floor and the chain head

**Status:** draft · **Date:** 2026-09-16

## Context

WIST-3 §7's `declaration` tuple carried the current Declaration and its
height, and `recovery_window` the owner height and window end. WIST-1 §5.2
keeps the highest accepted `seq` through a settlement that restores a
lower-sequence head, and lets a follower name the recovery-chain head that
an earlier follower advanced. A Consumer resuming from those tuples could
accept a Declaration full replay rejects — a `seq` above the restored head
but below the floor — or reject one it accepts, a follower naming a head
the Consumer never saw.

## Decision

`declaration` carries the highest accepted `seq`. `recovery_window` carries
the recovery-chain head's Declaration Envelope and its sealing height beside
the owner height and window end. A resuming Consumer treats the head as an
eligible predecessor and settles the window before the first Block at or
after its end, keeping the floor.

## Alternatives and consequences

Reconstructing from the owner height would make every cold start replay up
to a window of Blocks and leave the state artifact insufficient by design.
Carrying only the head's hash would leave the Consumer without the Key Set
that verifies followers, and with no Block to fetch it from. Carrying the
window's competitors adds nothing: settlement supersedes them, and a later
Declaration naming one already fails predecessor eligibility, since only
the current Declaration and the head are eligible. The pre-recovery Key
Set serves queue admission only and stays out.

Two tuples grow, and the `state_digest` of any Snapshot with an open window
changes. `vectors/wist1/recovery-heads.json` shows a Consumer resuming from
the tuples reaching every full-replay probe result, and that dropping the
floor or the head changes one.
