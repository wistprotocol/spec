# ADR-0015: What a recovery window admits, supersedes and settles

**Status:** draft · **Date:** 2026-08-16

## Context

The recovery window is the suite's only answer to a stolen Publisher signing
key. WIST-1 §5.2 gave it a start (the `sealed_at` of the Block sealing the
recovery Declaration), a length (`recovery_window_days`), a behavior
(Deltas queued rather than sealed), and an outcome (the recovery Declaration
takes effect, superseding "any ordinary rotation sealed during that
window"). The text leaves four questions unanswered, and each of them
changes what a replaying party derives:

1. **Which Key Set admits a Delta to the queue.** "The domain's Deltas are
   queued" does not say which Deltas qualify. Under the pre-recovery set
   alone, a Publisher that has just recovered cannot publish for seven days,
   because its own new keys are unknown to the queue. Under the recovery
   Declaration's set alone, the compromised key's Deltas are rejected at
   ingest, nothing is left to settle, and `WIST1-E13` becomes unreachable.
2. **What supersession covers.** §5.2 names ordinary rotations. A thief
   holding the compromised signing key can answer a recovery with a *fresh
   identity* instead — signed by a key in neither previous set, which
   §5.2 otherwise says "is accepted" — and keep the domain, losing only `A`
   and `C`.
3. **Which Key Set settlement revalidates against.** §5.2 says "the recovery
   Declaration's"; the historical-verification paragraph says the recovery
   Declaration "and whatever legitimately follows it". They differ exactly
   when the recovering Publisher rotates again inside its own window.
4. **How far `WIST1-E13` reaches.** "Dropped, never sealed" does not say
   whether the Delta's identity is barred or only that queued copy.

## Decision

**Recovery ownership follows application order.** Validate and apply each
domain's Declarations in ascending `(Block height, seq)` order, including
signature and predecessor checks. The first accepted recovery owns the
window; another recovery inside it cannot replace the owner or open another
window. Canonical leaf-hash order is storage order and cannot choose the
owner. Signed Block histories in `vectors/wist1/recovery-order.json` include
two recoveries whose sequence order reverses their leaf-hash order.
This changes no object fields or schema constraints; it defines application
order within the existing signed format under PUBLICATION.md.

**Admission is the union.** A Delta is queued when it verifies under either
the Key Set in effect immediately before the recovery or the recovery
Declaration's own. The recovering Publisher keeps publishing; the
compromised key's Deltas still reach the queue, where the settlement rejects
them in the open rather than at an ingest no replaying party can see.

**Supersession covers everything outside the recovery chain.** At the
window's end, every Declaration sealed inside it other than the recovery
Declaration and the chain legitimately following it is superseded, whatever
its classification. A Declaration legitimately follows when its signer is
named in its predecessor's `keys` or `recovery_keys`, the predecessor being
the recovery Declaration or an earlier link of the same chain.

**A fresh identity inside a window is accepted and superseded.** It is not
`WIST1-E08`: nothing about it is a sequencing violation, and rejecting it at
ingest would leave a thief's attempt invisible to a party replaying the Log.

**Settlement revalidates against the chain's newest Declaration** — the
recovery Declaration's own Key Set unless a legitimate follower was sealed
inside the window.

**`WIST1-E13` drops the queued copy, not the identity.** The same Delta
re-served later and verifying under the Key Set then in force is sealed like
any other.

`vectors/wist1/recovery-settlement.json` carries both derivations over five
cases, and `vectors/wist1/declaration-sequence.json` gains the open-window
acceptance case.

## Alternatives considered

**Use canonical Entry index to break a same-Block recovery race.** Rejected
because Declaration predecessors and WIST-3 §3.3 application precedence read
sequence numbers. A lower-sequence Declaration can be the authenticated
predecessor of a higher-sequence Declaration even when stored after it.
Selecting ownership by leaf hash would give storage order a conflicting
authority over recovery. Selecting the highest sequence instead would let
a later recovery replace the owner during its existing window.

**Reject non-recovery Declarations while a window is open** (the reading
a strict ingest reaches, under `WIST1-E08`). It is simpler, and it is what a
reader reaches for when supersession is unstated. Rejected because it
resolves at ingest what the Log can resolve at settlement: the attempt
leaves no sealed trace, so a Consumer replaying the Log cannot see that a
thief tried, and the rejection uses a code whose registry row lists no such
cause.

**Bar the Delta ID permanently on `WIST1-E13`.** Rejected because it makes
replay agreement depend on a per-Log list of dropped IDs that every Consumer
must carry and agree on, to prevent something the Key Set already prevents:
a Delta signed by a superseded key does not verify, whenever it is served.

## Consequences

- Queue admission, settlement and recovery ownership have explicit rules.
  Accepted versus effective predecessor heads and superseded identity-reset
  effects still require resolution under CONFORMANCE.md before authenticated
  recovery history replay can be validated.
- A recovering Publisher may rotate again inside its own window — the
  realistic case, since a recovery is performed with an offline key that the
  operator usually wants to replace immediately afterwards.
- The thief's options inside a window are all sealed and all superseded, so
  the Log records the attempt rather than hiding it.
- Two implementation behaviors change: an aggregator stops rejecting
  in-window Declarations with `WIST1-E08`, and a consumer stops superseding
  a legitimate post-recovery rotation.
