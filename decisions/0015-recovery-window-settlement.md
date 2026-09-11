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

**The owner freezes the recovery deadline.** Read `recovery_window_days`
from the map in force at the owner Block, including amendments effective
exactly at its `sealed_at`. Add that many 86,400-second days and retain the
end through later amendments and recoveries inside the window. Recomputing
from the current map could release queued Deltas early or extend their hold;
reanchoring at a follower would let repeated rotations postpone settlement.
A new window after settlement reads its own owner Block’s map. This adds no
object fields or schema constraints. `recovery_window_cases` in
`vectors/wist4/parameter-combinations.json` distinguishes these readings
with explicitly accepted parameter schedules and eligible recovery events;
those stage inputs do not establish Declaration or amendment authentication.

**Equal-sequence groups cannot choose authority by storage order.** Evaluate
each domain's group against the state after settlement and lower-sequence
groups. A group containing only re-serves of the current canonical
`publisher` object is idempotent and installs no signature. Otherwise all
canonical Envelopes, including signatures, must be identical; apply that
Envelope once, subject to every acceptance check. Distinct first-install
Envelopes invalidate the entire Block with `WIST1-E08`. This includes two
signatures over identical publisher bytes: an ordinary key and a recovery
key can each authenticate those bytes but imply different window ownership.
Initial Declarations and open recovery windows use the same rule; domains
remain independent. A Declaration acceptance failure invalidates its Block
without committing any Entry or settlement. Check a structurally valid
group's equality before its signatures; filtering bad signatures would
silently select a member of a conflicting batch. Different failing domains
may report different applicable diagnostics, since their processing order
does not affect Block rejection or retained state. Signed cases and positive
controls in `vectors/wist1/declaration-conflicts.json` exercise these rules.
This adds no object fields or schema constraints.

**Admission is the union.** A Delta is queued when it verifies under either
the Key Set in effect immediately before the recovery or the recovery
Declaration's own. The recovering Publisher keeps publishing; the
compromised key's Deltas still reach the queue, where the settlement rejects
them in the open rather than at an ingest no replaying party can see.
Freeze both signing sets at the owner's application, including any
same-Block predecessor; later competitors and legitimate followers replace
neither admission source. WIST-1 §5.1 and
[ADR-0023](0023-declaration-key-binding.md) retain complete named bindings,
filter key usability and each timestamp bound before signature verification,
and assign E02 when no eligible binding remains or E01 when all eligible
bindings fail verification. The union applies only to queue admission;
settlement and historical verification retain their selected single source.
`vectors/wist1/recovery-bindings.json` authenticates the owner and a later
follower, exercising fixed sources and diagnostics with signed Delta probes.

**Supersession covers everything outside the recovery chain.** At the
window's end, every Declaration accepted after its owner while it is open,
other than the recovery Declaration and the chain legitimately following it,
is superseded, whatever
its classification. A Declaration legitimately follows when its authenticated
signing public key belongs to its named predecessor's `keys` or
`recovery_keys`, that predecessor being the current recovery-chain head.

**Accepted sequence and effective predecessor are distinct state.** Retain
the highest accepted sequence, even when its Declaration is superseded.
During a window, a new Declaration may name either the latest accepted
replacement or the current recovery-chain head. The named predecessor
supplies signer bindings, classification and recovery-key protection.
Only an ordinary or recovery rotation naming the chain head extends it;
fresh identities and descendants of competitors stay outside it. This lets
the recovering Publisher extend its chain after a competing fresh identity
without requiring the competitor's cooperation. It does not allow a fork
from an earlier recovery-chain ancestor.

Settle before applying Declarations in the first Block at or after the
window end, restoring the chain head as the only eligible predecessor.
The same boundary governs admission. The sequence floor survives. A
re-serve of the current canonical `publisher` object is idempotent, including
the restored lower-sequence head; any other old Declaration rejects. Equal
`prev_declaration` values alone do not prove identical objects. Idempotence
changes no accepted state and installs no new signature.

**A fresh identity inside a window is accepted and superseded.** Fresh
classification alone is not `WIST1-E08`; all sequence, predecessor, signature
and recovery-key checks still apply. Rejecting an otherwise valid attempt at
ingest would leave it invisible to a party replaying the Log.

**Competing Declarations do not reset the recovering identity.** The owner
preserves the identity immediately preceding its application. A fresh
competitor accepted after it changes the accepted head and sequence floor,
but not WIST-4 §6.3's reset height, reputation scope, findings or sanction
state. The same applies to a competitor's ordinary or recovery descendants.
This rule holds in every open prefix, so settlement has no identity effects
to undo. Age, audit credit, decay, findings and ordinary sanction processes
continue during the window; settlement does not roll them back or freeze
their inputs. Signature eligibility remains a separate requirement.

Declarations preceding the owner in its own Block are not competitors. A
fresh predecessor resets normally, and the owner preserves that new identity.
The entire opening Block still belongs to the Delta-queuing interval.
After settlement, a fresh Declaration naming the restored head resets
normally unless another window has already opened in application order.

**Settlement revalidates against the chain's newest Declaration** — the
recovery Declaration's own Key Set unless a legitimate follower was sealed
inside the window.

**Each sanction notice freezes its appeal authority.** After due settlement
and all Declarations in the notice's Block, use the recovery-chain head's
signing entries if a window remains open, otherwise the current
Declaration's signing entries. A competitor cannot acquire authority over
the identity recovery preserves. Retain the complete identifier/public-key
bindings; later extensions, settlement, rotations, resets and new windows
cannot alter them. The historical Delta rule and queue-admission union
do not apply. Recovery keys remain Declaration-only.

Appeals carry no `observed_at`; the selected signing entries have no
additional `valid_from` filter. Neither self-declared `effective_at` nor a
sealing instant substitutes for the Delta timestamp that WIST-1 §5.1 bounds.
Missing notice authority or a missing identifier is WIST4-E05; a signature
failing under its selected entry is WIST1-E01 under WIST-1 §4. Neither
failure fills an appeal slot. This defines authority within existing signed
objects, adding no fields or schema constraints. Signed histories and
independent signature probes in `vectors/wist4/recovery-appeals.json`
exercise WIST-4 §7's resolution; notice evidence eligibility remains a
separate validation obligation.

**`WIST1-E13` drops the queued copy, not the identity.** The same Delta
re-served later and verifying under the Key Set then in force is sealed like
any other.

`vectors/wist1/recovery-settlement.json` carries seven authenticated hourly
Declaration histories and signed Delta inputs. Fresh competitors preserve
their named predecessor's recovery set; their ordinary descendants remain
off-chain. A shared signing key naming a competitor does not extend recovery,
whereas the same key naming the recovery head does. Independent candidate
probes reject unauthorized recovery-set replacement, stale predecessors and
invalid author signatures. Separate Delta binding probes distinguish public
key reuse, identifier renaming, `valid_from`, invalid signatures and later
re-serving of a rejected Delta ID. Survivors are signature-eligible inputs,
not proof of eventual inclusion. No object field or schema constraint changes.
`vectors/wist1/recovery-heads.json` carries a signed hourly Block chain,
Declaration predecessors and independent candidate probes across settlement.
It distinguishes accepted sequence from restored head, authenticates chain
extensions past competitors, and rejects stale predecessors and recovery-key
replacement without authority. No object field or schema constraint changes.

## Alternatives considered

**Use the latest accepted competitor for appeals.** Rejected because it
gives an off-chain fresh identity control of a sanction process against the
identity it cannot reset. Selecting the recovery head makes appeal authority
follow the party whose continuity the open window preserves.

**Use the eventual settled head for earlier notices.** Rejected because
later chain extensions could invalidate a previously accepted appeal or
authorize a previously rejected signature, changing process deadlines and
outcomes between prefixes. Freezing each notice's authority also preserves
the existing opportunity to appeal notices preceding recovery or a reset.

**Apply a new timestamp filter to appeal keys.** Rejected because an appeal
has no Delta `observed_at`, and self-declared `effective_at` supplies no
authority clock. A notice-sealing filter would prevent an admitted signing
entry dated after the notice from ever appealing it; an appeal-sealing
filter would let inclusion timing change the authority supplied by the
same notice. Key omission in the selected Declaration controls revocation.

**Take the first equal-sequence Entry and ignore its siblings.** Rejected
because a Block would certify conflicting state transitions and leaf-hash
order would select identity or recovery authority. Rejecting every sibling
Entry but accepting the Block also discards a sealed Declaration whose
acceptance WIST-3 §3.3 requires. Unsealed submissions remain subject to
ordinary admission checks; the conflict rule does not mandate their sealing.

**Compare only publisher bytes on first installation.** Rejected because
different valid signatures can classify the same replacement as ordinary
or recovery. Requiring one canonical Envelope also avoids introducing
signature-equivalence rules for aliases that authenticate the same key.
Idempotence is safe only against already-current publisher
bytes at entry to the sequence group; those re-serves install no signature.

**Reject all repeated sequences.** Rejected because byte-identical Envelope
duplicates and already-current publisher re-serves have no additional
effect, and equal sequence numbers for different domains are unrelated.

**Reset on acceptance and restore at settlement.** Rejected because it
temporarily discards the recovering identity's audit credit and findings,
clears sanctions, and makes a candidate Block's notice targets depend on
whether replay has reached a later settlement. Reconstructing dormant
identity state cannot undo already applied ingestion effects.

**Make a competing reset permanent.** Rejected because recovery would
restore keys but forfeit the identity they were registered to protect. A
competitor could erase penalties without possessing any recovery key.

**Freeze reputation and sanction state for the window.** Rejected because
audits of earlier Deltas and ordinary process deadlines continue to occur.
Key recovery grants no immunity from findings or reversals.

**Always follow the latest accepted Declaration.** A fresh competitor would
then force a legitimate follower to authenticate against the competitor's
keys, severing recovery continuity. Keeping the recovery-chain head eligible
avoids that obstruction without accepting arbitrary ancestors.

**Roll sequence back to the settled head.** Rejected because supersession
does not erase accepted signed history. Reusing a competitor's sequence
would make a previously rejected replay valid after settlement. The retained
floor preserves monotonicity; an accepted high sequence still obliges every
later replacement to exceed it.

**Accept any authenticated recovery-chain ancestor.** Rejected because two
successors of an old head could revive already replaced keys. Requiring the
current chain head makes legitimate continuation serial.

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

- Queue admission, settlement, recovery ownership, predecessor selection and
  the persistent sequence floor and identity continuity have explicit rules.
  Conflicting batches reject atomically. Notice-era appeal authority is
  stable across prefixes; sufficient Snapshot recovery state still requires
  resolution under CONFORMANCE.md before Snapshot recovery replay can be
  validated. The signed head vectors assert no reputation or sanction result.
  `vectors/wist4/recovery-identity.json` adds signed Declaration histories and
  identity-scoping projections over separately supplied eligible event inputs;
  it does not authenticate Audit Records, notices or appeals.
- A recovering Publisher may rotate again inside its own window — the
  realistic case, since a recovery is performed with an offline key that the
  operator usually wants to replace immediately afterwards.
- Admissible competing Declarations can be sealed and are superseded;
  sequence, signature and recovery-key violations still reject at admission.
- Two implementation behaviors change: an aggregator stops rejecting
  in-window Declarations with `WIST1-E08`, and a consumer stops superseding
  a legitimate post-recovery rotation.
