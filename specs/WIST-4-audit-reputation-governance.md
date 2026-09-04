# WIST-4: Audit, Reputation & Governance

**Status:** v1.0.0-draft · **Date:** 2026-08-02 · **License:** CC-BY 4.0

## 1. Introduction

Everything WIST-4 defines is an input to, or a pure function of, the log.
Nothing exists outside it.

WIST-1 through WIST-3 make the system verifiable; WIST-4 makes it defensible.
It defines how sampled Deltas are checked against reality (audit), how a
domain's track record becomes a number anyone can recompute (reputation),
how misbehavior is punished with due process (sanctions), and which rules
are beyond amendment by operation (constitutional invariants). Because
every audit record, sanction, appeal, and parameter change is a log entry
(WIST-3 §3.3), the entire governance history of the system is public,
ordered, and permanent — and any party can independently recompute every
reputation score and verify every sanction's evidence.

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as
shown here.

- **Auditor**: a keyed identity, admitted via the log, that re-fetches
  audited URLs and emits Audit Records.
- **Audit Record**: an Auditor's signed statement about one Delta
  (schema: [`schemas/audit-record.schema.json`](../schemas/audit-record.schema.json)).
- **Verdict**: the graded outcome of one audit: `consistent`,
  `inconsistent`, `unreachable`, `dynamic_variance`, `not_auditable`,
  `link_variance`, or `link_inconsistent`.
- **VRF Proof**: the 80-octet `pi_string` an Auditor produces over a Block
  Hash with its own key under ECVRF-EDWARDS25519-SHA512-TAI ([RFC 9381]),
  carried in every Audit Record as `vrf_proof`. It lets anyone recompute
  that Auditor's selection set for that Block, and only that Auditor
  produce it (§4).
- **Confirmed Inconsistency**: ≥ 2 Auditors, independent in the sense §3
  defines, returning `inconsistent` for the same Delta within 72 hours
  measured on Block `sealed_at` (§5).
- **Confirmed Link Inconsistency**: ≥ 2 Auditors, independent in the sense
  §3 defines, returning `link_inconsistent` for the same Delta, the
  confirming Record sealed within `confirm_window_hours` of an earlier
  such Record, measured on Block `sealed_at` (§5, §7).
- **Registry Update**: the signed governance object this document defines,
  sealed as a `registry_update` Entry (WIST-3 §3.3). Its `action` selects one
  of the thirteen governance acts of §3, §4, §7 and §9.1; `subject` names
  what the act is about; `details` and `evidence` are constrained per
  `action` by §9.1.
- **Sanction**: a graduated, logged penalty against a domain (§7).
- **Parameter Registry**: the versioned table of every numeric constant
  in the suite (§9).
- **Reputation**: the pure function of log history defined in §6.
- **Provisional**: the starting state of every new or reset domain —
  reputation capped, full participation otherwise (§6).
- **Sanctioned Quarantine**: sanction level 3 (§7), a punitive state that
  suspends ingestion.

Every signed object in this document carries `wist_version` (WIST-1 §3.1)
and the WIST-1 §4 signature block (`key_id`, `alg`, `value`).

## 3. Auditors

Auditors are admitted by an `auditor_admit` Registry Update (schema:
[`schemas/registry-update.schema.json`](../schemas/registry-update.schema.json))
whose `subject` is the Auditor's `auditor_id` and whose `details` MUST carry
the Auditor's `key_id` and its raw Ed25519 `public_key` (base64url, 32
octets unpadded), and removed by `auditor_remove`. Both are signed by the
Aggregator and, like everything else, live in the log — the roster of who
may audit, and since when, is public and permanent.

**An Auditor is a domain, not a bare key.** `auditor_id` is a hostname of
at least two labels, anchored the way a Publisher's identity is (WIST-1
§5.1): the Auditor MUST serve, at
`https://<auditor_id>/.well-known/wist/publisher.json`, a
Declaration whose `domain` is that hostname and whose Key Set carries the
admitted `key_id` and `public_key`, and the Aggregator MUST verify that
document before sealing the `auditor_admit`. A bare key says nothing about
who holds it, and an Aggregator's statement about a key it may itself hold
is not evidence; anchoring the key to a domain gives every Audit Record an
addressable author and lets any party check the admission against what that
host actually publishes.

That check is deliberately kept out of recomputation. Reputation is a pure
function of Log history (§1, §6), so whether a Record counts MUST NOT depend
on what some host serves at the moment a party replays the Log: the
`auditor_admit` Entry is the Log-native fact, and the Declaration is what
makes it falsifiable. A host that does not publish the admitted key
contradicts the admission publicly, which is evidence for `auditor_remove`
and an instance of the exposure §11 states — never a retroactive rewriting
of Records already sealed.

**Independence, and what it is worth.** Two Auditors are **independent**
when their `auditor_id`s share no suffix of two or more labels:
`a.example.org` and `b.example.org` share `example.org` and are not
independent; `audit.example.net` and `checker.example.org` share nothing
and are. The test is a label comparison over hostnames the Log already
carries, so every party recomputes it identically with no Public Suffix
List, no registry lookup, and no judgement, and it errs toward finding
Auditors dependent — it withholds confirmations rather than manufacturing
them. Two unrelated operators under one two-label suffix (`a.com.br`,
`b.com.br`) therefore cannot confirm each other's `inconsistent` verdicts;
both may still audit everything, and what a confirmation needs is a third
Auditor elsewhere, not an exception here. A Confirmed Inconsistency (§5)
requires two Auditors independent in exactly this sense, not merely two
keys.

**The identity a Record claims is the admitted one.** A Record's
`auditor_id` MUST be byte-identical to the `subject` of the
`auditor_admit` that admitted the key named in its `sig.key_id`, and a
Record where it is not MUST be rejected by validators recomputing
reputation. Without that binding every test below compares a string the
Auditor writes for itself: one admitted key could sign
`checker.example.org` on one Record and `audit.example.net` on the next
and pass the independence test against itself, or claim an unrelated
hostname in order to audit its own domain. The Log already says which
hostname that key was admitted under; the Record is required to agree with
it, and the schema constrains the field to the same shape `subject`
carries.

An Auditor MUST NOT audit a Delta whose Publisher domain fails the
independence test above against its own `auditor_id` — that is, whose
Publisher domain shares a suffix of two or more labels with it — and an
`auditor_admit` MUST NOT name an `auditor_id` that fails the same test
against the Log Anchor's `log_id` (WIST-3 §3.4). One test governs all three
relations deliberately: a rule that put only a hostname's parents and
subdomains beyond its audits would leave `audit.example.net` free to audit
`blog.example.net`, which is the same operator by the very measure §5's
confirmation rule uses. Both are comparisons over values the Log carries:
a Record breaching the first MUST be rejected by validators recomputing
reputation, and an `auditor_admit` breaching the second MUST be rejected
outright, so no key it names is ever an admitted key and no Record signed
by that key counts. Neither rule makes independence true — §11 states
exactly how far it reaches — but both remove the cases the Log itself
already shows to be false.

**Seed the roster across suffixes.** Because the test is a suffix
comparison, a roster whose members all sit under one two-label suffix is a
roster in which no Confirmed Inconsistency can ever form, however many
Auditors it holds and however diligently each audits. A deployment MUST
therefore admit Auditors under distinct two-label suffixes, and SHOULD
treat the number of *mutually independent* suffixes on the roster, not the
number of admitted keys, as the measure of whether confirmation is
possible at all. The warning is sharpest in a namespace where operators
cluster under one public suffix — where every candidate Auditor is under
`.com.br`, admitting eight of them yields a roster that looks healthy and
a confirmation mechanism that is silently disabled.

That one `public_key` serves both purposes: it verifies the Auditor's
Record signatures **and** it is the VRF public key against which its
`vrf_proof` is checked (§4). ECVRF-EDWARDS25519-SHA512-TAI and Ed25519
share the [RFC 8032] key format, so no second key is admitted, and there is
no way for an Auditor to sign under one identity while drawing its audit
assignments under another. **An `auditor_id` holds at most one admitted
key at any height**, and which key that is at a given Block is read from
that Block's `sealed_at`: a key is held from the `sealed_at` of the Block
sealing its `auditor_admit` to the `sealed_at` of the Block sealing its
`auditor_remove`, the latter instant excluded, and an `auditor_admit`
whose `subject` holds a key not removed at or before the admit's own
Block is rejected by every replaying party (§4, `WIST4-E07`). Two
`auditor_admit` Entries naming one `subject` in one Block are both
rejected the same way: either would have the `auditor_id` hold two keys
at that `sealed_at`, and a Registry Update's position within a Block
carries no meaning (WIST-3 §3.3), so there is no first of the two to
prefer. Every duty
and proof of a Block reads the key held at that Block's `sealed_at`; a
Record's signature reads the key held at the Record's own Block. Across
a rotation the two differ — a Record sealed after it for a Block before
it is signed under the new key and carries a proof under the old one —
and both are the same `auditor_id`'s, by the binding above. Were two keys
held at once, the Auditor would hold two draws for every Block and could
publish whichever selected less.

**Windows and admission run on `sealed_at`.** `fetched_at` is
Auditor-supplied and unverifiable by anyone else, so nothing anchored to it
is recomputable. Every admission test and every window in this document
reads Block `sealed_at` values instead (WIST-3 §3.1), which are ordered,
strictly increasing, and identical for every replaying party — the appeal
window of §7 and the recovery window of WIST-1 §5.2 included, neither of
which reads the `effective_at` of the Entry that records it. Every
timestamp this suite compares against a Block `sealed_at` is written in the
same whole-second, literal-`Z` form that field carries, so no comparison
rests on a normalization step two implementations could perform
differently: `fetched_at` below, a Feed's `generated_at` (WIST-2 §3.2), a
Registry Update's `effective_at`, and a `notice`'s `appeal_deadline` (§9.1)
are all constrained to it by their schemas. Validators
recomputing reputation MUST reject:

- a Record signed by a key not admitted at, or removed at or before, the
  `sealed_at` of the Block carrying that Record;
- a Record whose `vrf_proof` gives it no standing: one that does not
  verify over the audited Block's Block Hash, under the key admitted at
  that Block's `sealed_at` (§4), with `audited_delta` in the selection
  set that proof determines — and does not verify over the Block Hash of
  a Block *B₁* at which §4's extension rule names `audited_delta` for
  that Auditor, under the key admitted at *B₁*'s `sealed_at`. The proof
  names the path: an extension Record's proof is over *B₁*, whose
  selection set the Delta joined, never over the audited Block, whose
  draw did not select it;
- a Record whose `fetched_at` falls outside the closed interval from the
  `sealed_at` of the Block its proof is over — the audited Delta's Block,
  or *B₁* for an extension Record — to the `sealed_at` of the
  Record's own Block. Neither end rests on trust: an Auditor's selection is
  derived from that Block's Block Hash, so under this protocol it
  cannot have fetched for the duty before that Block was sealed, and no
  Record is sealed before it is written. A `fetched_at` outside that interval contradicts
  the Log's own ordering;
- a Record whose `reference_delta` (§5) is not a sealed Delta in the same
  per-URL chain as `audited_delta`; or precedes `audited_delta` in that
  chain; or is sealed in a Block whose `sealed_at` is after the Record's
  `fetched_at` — which, with the interval above, also places it at or
  before the Record's own Block. Each test reads the chain and two Block
  timestamps, all in the Log. What no test reads is whether the Auditor
  named the *newest* qualifying Delta rather than an older one: that is a
  false statement of the same class as a false `similarity`, and it meets
  the same answer — a Confirmed Inconsistency needs a second independent
  Auditor, and a lone `inconsistent` against a stale reference is
  contradicted by the peers §4's extension rule summons;
- a Record whose Auditor audited a domain the self-audit rule above puts
  beyond it;
- a Record whose Auditor was **in coverage failure** at the `sealed_at` of
  the Block carrying that Record — that is, one for which the Log shows
  more than `coverage_failures_max` failed coverage duties inside the 30
  days ending there (§4). The predicate is computed from the Log like every
  other test here, and it does not wait on an `auditor_remove`;
- a Record whose `similarity` **or `link_agreement`** does not satisfy
  §5's condition for its own `verdict` — including a link verdict whose
  `link_agreement` sits outside its band, and a `consistent` Record
  carrying a `link_agreement` below `link_agreement_consistent` — is
  malformed evidence, not a divergent judgement call, and MUST NOT be
  allowed to leave `sim` (§7) resting on a value outside every severity
  band;
- a Record carrying a `link_agreement` where §5 makes the link dimension
  neutral: a `delete` audit, or a verdict of `unreachable` or
  `not_auditable`. A reading of a dimension that was not audited is
  malformed for the same reason a reading outside its band is — it
  asserts a comparison against a reference set the audit had none of.
  Both cases are decidable from the Log by the party doing the
  rejecting: the verdict is in the Record, and a validator already
  resolves `reference_delta` to its change type to apply §5's `delete`
  mirror. The one neutral case this rejection does not reach is a
  non-HTML representation (WIST-2 §11), which no party can settle from the
  Log alone; there the reading is evidence like the rest of the Record's
  and is weighed with it.

The first and the coverage-failure rejections are scoped to reputation and
do not reach coverage: an Auditor removed after a Block was sealed but
before its coverage deadline still discharges its §4 duty for that Block by
publishing, because coverage is anchored to the `sealed_at` of the Block
the duty is anchored to — the audited Block for a VRF selection, *B₁* for
a Delta §4's extension rule names — rather than to the height at which
the Record lands, and an Auditor in
coverage failure still discharges — and can still recover from — the duty
by publishing. Such a Record proves the Auditor met its duty; it does not
enter any domain's reputation. A Record §10 rejects as malformed evidence
(`WIST4-E02`) discharges the duty the same way: the Auditor held standing,
fetched and published, and what the rejection withholds is the Record's
weight as evidence, not the fact of its publication. A Record void for
more than one reason discharges only if every reason is one of these;
one reason under which no duty existed leaves nothing to discharge.

Aggregator keys are admitted and retired by the `aggregator_key_add` /
`aggregator_key_remove` actions defined in WIST-3 §3.4; their `details`
sub-schema is specified in §9.1.

## 4. Audit Sampling

Selection is per-Auditor and unpredictable to everyone, including the
Aggregator.

For each sealed Block *B*, each admitted Auditor computes a Verifiable
Random Function output over the Block Hash using its own key:

    beta = ECVRF_proof_to_hash(ECVRF_prove(auditor_sk, alpha))
    alpha = the 32 raw octets of B's Block Hash (the hex digest decoded;
            the "sha256:" prefix is not part of alpha)

The VRF is **ECVRF-EDWARDS25519-SHA512-TAI**, the ciphersuite of [RFC 9381]
§5.5 with `suite_string` `0x03`; `pi` is its 80-octet `pi_string` and `beta`
its 64-octet `beta_string`. `auditor_sk` is the Auditor's 32-octet
[RFC 8032] Ed25519 secret key — the very key whose public half was admitted
by `auditor_admit` (§3) and is in force at *B*'s `sealed_at`, and which
signs the Auditor's Records. *B*'s Block Hash is
`"sha256:" + hex(SHA-256(JCS(header)))` (WIST-3 §3.1), so `alpha` is those 32
octets and nothing else: not the `sha256:`-prefixed string, not its ASCII
hex, not the header bytes.

For each Delta *d* carried by a `publisher_delta` Entry of *B* and
inside *B*'s **selection domain** — every such Delta except one that
WIST-3 §7's one-URL, one-Publisher rule excludes from materialization at
*B*'s height, a parent's Delta for a host whose own `seq`-0 Declaration
Entry is sealed at or below *B* — the Auditor
MUST audit *d* if and only if the VRF test below selects it and §3's
self-audit rule does not bar the Auditor from *d* — or the
**extension rule** below names it, which is the one path into any
Auditor's selection set that no VRF draw gates. A Delta outside the
domain is in no Auditor's selection set by either path: a Record for it
is void (§3, `WIST4-E01`) and triggers no extension. A Delta §3 bars an
Auditor from is in none of *that* Auditor's selection sets by either
path, whatever its draw says: the Auditor owes no Record for it, a
Record it publishes anyway is void (§3, `WIST4-E01`), and its own
domain's Deltas cost it no coverage and earn it nothing — the bar reads
two hostnames the Log carries and consults no draw, so every party
derives the same selection set for the same Auditor. The domain
excludes exactly what no party materializes — auditing such a Delta
would spend fetches on a claim nobody consumes and could sanction the
parent for content the subdomain serves — and it reads Declaration
heights the Log carries, which every Auditor replays already. For the
VRF test:

    D(d)  = first 8 octets of SHA-256(beta || d.delta_id_utf8),
            read big-endian: an integer in [0, 2^64)
    p_1e7 = clamp(200 000 + 3 x (1 000 000 - reputation_u),
                  200 000, 5 000 000)
    select(d)  <=>  D(d) x 10^7  <  p_1e7 x 2^64

`D(d)`, `p_1e7`, and both sides of that comparison are integers, and **no
floating-point operation appears anywhere in the selection test**. `beta`
is those 64 raw octets; `d.delta_id_utf8` is the UTF-8 encoding of the full
Delta ID string including its `sha256:` prefix; `domain(d)` is the domain
of the Publisher whose key signed *d*; and `reputation_u` is that domain's
§6 reputation, in micro-units, at height *B* − 1 — the state of the log
immediately before *B* was sealed, which for Block 0 is the empty log —
evaluated with the §9 constants in force at *B*'s `sealed_at`. If a
level-1 sanction (§7) is in force against `domain(d)` at that same height,
`p_1e7` is 5 000 000 instead of the clamp above; that is the only thing
that displaces the formula.

`p_1e7` is the sampling rate scaled by 10^7, and that scale is exact
rather than approximate: `reputation_u` carries six decimal digits and the
slope contributes one more, so seven digits represent the rate with
nothing left over to round. The floor 200 000, the ceiling 5 000 000, and
the slope 3 per micro-unit of reputation are the Parameter Registry values
(§9); rendered for humans they are the familiar 0.02, 0.50 and 0.30, but
**the integers are normative and the decimals are only a reading of
them** — an implementation MUST compute with the integers. Likewise
`select` is the exact rendering of "the draw `D / 2^64` falls below the
rate `p_1e7 / 10^7`", with both sides multiplied by `10^7 x 2^64` so that
neither fraction is ever evaluated. `D x 10^7` reaches
`(2^64 − 1) x 10^7` ≈ 1.845e26, which needs 88 bits, and `p_1e7 x 2^64`
reaches 9.223e25; implementations MUST use 128-bit or arbitrary-precision
integers for both. Computing either product in 64-bit arithmetic overflows
and is non-conforming.

This is what makes selection *recomputable* rather than merely
*reproducible-in-practice*. The comparison is strict and sits directly on
the last digit of the reputation that feeds it, so had either side stayed
in binary floating point, two honest Auditors using two correct `libm`s
could have disagreed about whether a given Delta was theirs to audit —
and, under the coverage duty below, one of them would be provably in
breach for a Delta the other never owed. Integers remove the disagreement
rather than making it rare.

The Auditor publishes the VRF proof `pi`, lowercase hex, in every Audit
Record it emits for Block *B* (`vrf_proof`). Verification runs RFC 9381's
`ECVRF_verify` **with** the optional `ECVRF_validate_key` step, which that
document leaves to the application: a proof under an Auditor public key
that fails key validation — a small-order or non-canonically encoded point
— does not verify, and the Record is void for standing (`WIST4-E01`) like
any other Record whose `vrf_proof` does not verify. The step is required
because §11's claim rests on the uniqueness it buys: without it a small-order
Auditor key admits more than one valid `beta` for the same Block, and an
Auditor could grind selection sets until one omitted the Deltas it preferred
not to audit. It is also the same standard WIST-1 §4 applies to the Ed25519
keys of this suite, which RFC 9381 §5.5 shares with the VRF.
Anyone can verify with the
Auditor's public key that `beta` is the unique correct output for that
Block, and can therefore recompute the Auditor's entire selection set for
*B* — the VRF draw plus any Deltas the extension rule below names, every
input to which is itself in the Log — and check it audited exactly that
set: no more (harassment) and no less (favoritism).

This construction closes three problems at once. The Aggregator cannot
steer audits: it does not hold Auditor keys, so grinding the Block Hash
changes every Auditor's selection unpredictably and in no chosen direction.
The Auditor cannot steer them either: the VRF output is uniquely determined
by its key and the Block, and any deviation is detectable. And assignment
needs no coordinator: each Auditor's duties for each Block are derived, not
allocated.

**Coverage duty.** For **every** Delta in its selection set for a Block
— those its VRF selects, less those §3's self-audit rule bars it from —
an
Auditor MUST publish an Audit Record — or, when it cannot fetch at all, a
Record with verdict `unreachable` — within 72 hours of that Block's
`sealed_at`. When that selection set is empty, it MUST instead
publish, by the same deadline, a `coverage_attestation` Registry Update
naming that Block and carrying its VRF proof and the `prev_record` chain
link every Record carries (§9.1), and nothing further: it reports no
verdict, because there was nothing selected to audit. It names the Block
because a sealed attestation is otherwise bound to one only by the
`pull_attestation` that happens to list it: the proof is over the Block
Hash, so a replaying party that cannot tell which Block the attestation is
for cannot verify the proof at all, and an attestation the Aggregator
never attested to would discharge a duty no one could locate.

**Withdrawn and unavailable Payloads discharge the duty.** A selected
Delta whose Payload has been withdrawn (WIST-3 §6.2), or which the Auditor
cannot obtain from any source, is audited with a Record whose verdict is
`not_auditable` (§5). That Record discharges the coverage duty for that
Delta exactly as any other verdict does, so the Block does not count
toward `coverage_failures_max`. Without this rule an Auditor would accrue
coverage failures for a withdrawal it did not cause, could not foresee,
and cannot remedy — and the cheapest way to remove an inconvenient Auditor
would be to withdraw Payloads it was about to audit. Inside the
availability window an Auditor SHOULD first try another Mirror and the
Publisher, and the absence is a `WIST3-E05` fault against the Mirror that
lacked it (WIST-3 §6.1); `not_auditable` records the Auditor's inability to
judge, never the Publisher's fault, and never counts toward a sanction.

The duty is anchored to the Block's `sealed_at`: it exists only if the
Auditor was admitted at that instant, and the Record or attestation
discharging it MUST verify against the key admitted then, even if the
Auditor has since been removed. Removal therefore ends an Auditor's future
duties; it does not retroactively excuse the ones already incurred, and it
does not strip the Auditor of the ability to discharge them.

The duty is verifiable in-band, because the VRF proof reaches the Log for
every Block whether or not anything was selected. An Auditor has **failed
its coverage duty for a Block** when any selected Delta lacks a Record at
the deadline, or when its selection was empty and no attestation appears;
publishing Records for some but not all selected Deltas is a failure, not
partial credit. Whether a failure so defined *counts* is a further
question the transport below answers: it enters the failure count only
under the `pull_attestation` condition there, because an absence the
Aggregator can manufacture is not evidence until the Aggregator has
signed what it found. Because `pi` pins the selection set exactly, that is an
objective and recomputable fact rather than a judgement. Without the
attestation an Auditor that simply does nothing would be indistinguishable
from one whose VRF selected nothing, and coverage would rest on an
out-of-band challenge — which §1's "nothing exists outside the Log"
forbids.

**The consequence is derived from the same fact.** An Auditor is **in
coverage failure** at a height N when the Log shows it failing the duty for
more than `coverage_failures_max` Blocks (Parameter Registry; default 24)
inside the 30 whole days ending at Block N's `sealed_at`. From that height,
and for as long as that holds, its Records do not count: a validator
recomputing reputation rejects every Record it signs (§3), so its verdicts
enter no domain's `C`, no `penalty_n`, and no Confirmed Inconsistency.
The Aggregator MUST also remove it by `auditor_remove` (§3), whose
`evidence` MUST name the failed Blocks — but the `auditor_remove` records
the consequence and does not create it. A failure count is exactly as
recomputable as the selection set that produced it, and the state a
provably shirking Auditor's Records are in MUST NOT depend on whether the
one party those Records are evidence against chooses to file: an Aggregator
holding an Auditor key of its own would otherwise keep a demonstrably
shirking Auditor on the roster and keep counting whatever it did publish.

The derived exclusion tracks the predicate rather than outliving it: as
failures age out of the 30-day window with none replacing them, the Auditor
is no longer in coverage failure and its later Records count again. A
sealed `auditor_remove` does not age out — removal is the Log-native fact
§3 reads for admission, and it is permanent — so the derivation is a floor
under the duty, never a way around removal.

**What removal binds, and how an Auditor rotates.** An `auditor_remove`
retires its `key_id` permanently, exactly as an `aggregator_key_remove`
does (WIST-3 §3.4): no later `auditor_admit` may name that `key_id`, and a
replayer MUST reject one (`WIST4-E07`, as every rejection in this
paragraph); an `auditor_remove` naming a key its `subject` does not hold
retires nothing and is rejected the same way. Whether it also bars the *`auditor_id`* is
decided by the removal's own `evidence`. A removal carrying evidence —
an `evidence` member naming at least one ID: failed Blocks, void
Records, systematic divergence — is for cause, and an
`auditor_admit` whose `subject` is that `auditor_id` MUST thereafter be
rejected by any party replaying the Log: without this, "removal is
permanent" would be permanent for a key that costs nothing to replace and
porous for the operator behind it, and a removed Auditor would re-enter
by generating thirty-two fresh octets. A removal carrying no evidence —
the member absent; an empty array names nothing and is not a valid
`auditor_remove` (§9.1) — is
an exit or a rotation, and bars nothing — which *is* the key-rotation
mechanism: an Auditor rotates by having an evidence-less `auditor_remove`
for the old key and an `auditor_admit` for the new one sealed, same
`auditor_id`, in one Block or the removal first — §3 holds one key per
`auditor_id` per height, and a removal sealed at an instant ends the old
key's tenure before an admission sealed at the same instant is read —
each duty still anchored to whichever key was admitted at
the relevant Block's `sealed_at` (§4). A compromised Auditor key is the
rotation case with urgency: the removal ends the key's authority from
its sealing height forward, and Records the stolen key signed for Blocks
after the removal verify against no admitted key and are void without
any further rule. The exclusion is scoped to
reputation and carries no notice and no appeal, for the reason §5 gives for
the unauditable horizon: nothing here is punitive, and what it withdraws is
the weight of Records from a party the Log already shows was not doing the
work they claim to be part of.

`coverage_attestation` is the second class of Registry Update not signed by
the Aggregator (the first is `appeal`, §7): the Auditor signs it with its
own admitted key, and its `subject` is the Auditor's `auditor_id`.

**The extension rule.** When a Block *B₁* seals an `inconsistent` or
`link_inconsistent` Record for a Delta *d*, and no earlier such Record for
*d* was sealed inside the §5 confirmation window ending at *B₁*, then *d*
enters the selection set of **every** Auditor admitted at *B₁*'s
`sealed_at` that is independent (§3) of every Auditor whose such Record
for *d* is already sealed — and that is not barred from auditing *d* by
§3's self-audit rule. Each such Auditor MUST audit *d* and publish the
Record within `confirm_window_hours / 2` hours (integer division) of
*B₁*'s `sealed_at`; the duty is a coverage duty exactly as for a VRF
selection, discharged by any verdict, `unreachable` and `not_auditable`
included, and counted by the same failure arithmetic. A Record produced
under this rule carries the `vrf_proof` for *B₁* like any Record for a
selection in *B₁* — *B₁*'s selection set is the one *d* joined, and the
proof over *B₁* is what binds the Record to the Block whose `sealed_at`
fixes the Auditor's admission, its deadline and its fetch interval (§3);
the audited Block's draw did *not* select *d*, and the extension is why
the Record is nonetheless valid. It is served at *B₁*'s records path
below, and its duty is counted against the (Auditor, *B₁*) pair. Without
this rule the document would promise what §3 forbids: §5's "re-audit by
additional Auditors" would name an act that voids the Record of any
Auditor performing it, confirmation would exist only where two VRF draws
coincided — at the sampling floor, a chance a fraudulent Delta survives
thousands of times over — and the sanction ladder would police exactly
the established domains it was built to reach last. The duty's span is
half the confirmation window so that a Record published at the deadline
can still seal inside the window it exists to serve; §9's combination
rules bound the pair.

**Extensions are rationed, and the ration is per triggering Auditor.**
A triggering Record extends selection sets only while its signing
Auditor has triggered fewer than `extension_triggers_max` (Parameter
Registry; default 3) extensions in the 30 whole days ending at *B₁*'s
`sealed_at`; beyond that the Record is valid, counts toward
confirmation if peers happen to audit *d* anyway, and simply summons
nobody. Without the ration the rule is an amplifier pointed at the
roster: one Auditor's `inconsistent` costs every independent peer a
fetch, so a hostile or captured Auditor filing false verdicts across
25 Blocks in a month would push every honest peer past
`coverage_failures_max` — voiding their Records and *mandating* their
removal — at a cost to itself of one fetch per attack. Rationing makes
the ceiling on that attack 3 forced fetches per Auditor per month,
while leaving the honest case untouched: a roster meeting real fraud
triggers on the fraud, not on one member's say-so, and a genuine wave
of fraud reaches the roster through many Auditors' VRF draws rather
than one Auditor's filings.

**Contradiction is derived, and it costs the filer.** An `inconsistent`
or `link_inconsistent` Record is **contradicted** when the extension it
triggered closes with no Confirmed Inconsistency and at least two
independent Auditors sealed `consistent` for the same Delta inside the
window. Only a Record that triggered an extension can be contradicted,
and the ration above admits at most `extension_triggers_max` triggers
into any 30-day window, so the ration is also the ceiling on
contradictions in that window — which is why `contradictions_max` MUST
be below `extension_triggers_max` (§9). An Auditor whose Records were
contradicted more than `contradictions_max` times (Parameter Registry;
default 2) in the 30 whole days ending at height N is in **divergence**
from that height, and for as long as it holds: a validator recomputing
reputation rejects
every Record it signs, exactly as for coverage failure (§4), and the
Aggregator MUST remove it by `auditor_remove` naming the contradicted
Records — recording the consequence, never creating it. The state
tracks the predicate rather than outliving it, and the derivation is
what matters: §11 claimed systematic divergence was "grounds for
`auditor_remove`", which left the suite's answer to a lying Auditor
resting on the one party the design refuses to trust to file. The cost
of the extension rule is therefore one fetch per admitted Auditor per
*rationed* triggering Record: fraud pays it, and a lying Auditor pays
it three times before its own removal is derivable from the Log by
anyone.

**How Records reach the Log.** Every duty above is discharged by a
Record or attestation *sealed* in the Log, and this paragraph is the
transport that makes sealing depend on no party's goodwill. An Auditor
MUST serve everything it publishes for a Block — the Audit Records for
that Block's selection set, VRF-drawn and extension-named alike, and any
`coverage_attestation` — as a single JSON array at

    https://<auditor_id>/.well-known/wist/records/<block-hash-hex>.json

(that Block's Block Hash in hex, without its `sha256:` prefix), by its
§4 deadlines for that Block, and MUST keep serving it until every
item in it is sealed. Each Record and each `coverage_attestation` an
Auditor publishes carries `prev_record`: the ID of the same Auditor's
immediately preceding Record or attestation in its own publication
order, or `null` for its first ever. The chain is what turns selective
suppression into evidence: a sealed item whose `prev_record` names an
ID the Log does not contain proves, to any replaying party, that the
missing item existed and was published before its successor — so the
absence is suppression or a failed pull, never shirking, and a coverage
failure MUST NOT be derived from it. For each sealed Block and each
Auditor admitted at its `sealed_at`, the Aggregator MUST fetch that
Auditor's path for the Block after the Auditor's coverage deadline for
it passes — the later of its deadlines there, by §9's combination rule —
and MUST seal everything it finds within `record_seal_blocks` Blocks
(Parameter Registry; default 24) of the fetch, and MUST seal alongside
it a `pull_attestation` Registry Update — `subject` the `auditor_id`,
details naming the audited Block and the IDs found, empty where the
fetch found nothing to seal. A coverage failure for an (Auditor, Block)
pair enters the §4 failure count **only** when the Log carries the
Aggregator's `pull_attestation` for that pair showing the duty unmet
and no later-sealed item contradicts it by chain. The asymmetry is
deliberate, and it is the appeal pattern (§7, WIST-2 §3.3) applied to the
one evidence class that lacked it: without the attestation requirement,
an Aggregator could manufacture an honest Auditor's removal by silently
declining to pull — a coverage failure needs no `auditor_remove`, so
suppression and shirking would be indistinguishable on replay, the
opposite of what §11 claims. With it, silence stops counting against
the Auditor and starts counting against the Aggregator, whose missing
attestation for a duty it owes is itself derivable by replay; and a
false attestation is a permanent signed statement that any third party
who fetched the Auditor's path during the window can contradict.

**The gate is not an amnesty.** Gating the failure count on the
attestation protects an honest Auditor from a silent Aggregator, but
read alone it would hand every shirking Auditor the same protection:
an Aggregator that simply never attests would make coverage failure
uncountable for the whole roster, and §11's "shirking is detectable
from the Log alone" would be true of the detection and false of the
consequence. So the omission resolves rather than suspends. When the
Log carries no `pull_attestation` for an (Auditor, Block) pair by
`record_seal_blocks` Blocks after that Auditor's coverage deadline,
the pair is **unattested**, and an unattested pair counts toward the
§4 failure count exactly as an attested unmet duty does — unless the
Log carries, for that Auditor, any sealed item whose `prev_record`
chain shows a published item the Aggregator did not seal, in which
case every unattested pair for that Auditor in the same 30-day window
is excluded from the count instead. The chain is the discriminator the
attestation cannot be: an Auditor that published has proof it
published, and one that published nothing has none. An Aggregator that
stops attesting therefore stops shielding shirkers without gaining any
lever over the Auditors who serve their duty, which is the only
division of the two cases that rests on evidence rather than on
either party's word.

Worked numbers for this section — real values from `vectors/wist4/sampling.json`
— are in the Appendix.

## 5. Verdicts and Tolerance

An Audit Record is an Envelope whose inner object is `record` (WIST-1 §4),
and its fields are: `audited_delta` (the Delta ID under audit),
`reference_delta` (the Delta the audit measured against: the URL's chain
tip at fetch, fixed below),
`auditor_id` (the Auditor's hostname identity), `fetched_at` (when the
Auditor fetched the URL), `response_commitment` (over the raw response
body), `ref_extract_commitment` (over the Auditor's own reference
extraction), `similarity` (the §5 metric value, an integer in micro-units),
`verdict`, `evidence_commitment` (over the WARC capture; §5 fixes which
captures the Auditor preserves and for how long), `link_agreement` (the §5 link-dimension reading, an
integer in micro-units, present only where that dimension applies),
`robots_excluded` (present only on an `unreachable` Record the
`robots.txt` rule below produced), and `vrf_proof` (the §4 VRF Proof
over the Block Hash of the Block in whose selection set the Auditor holds
`audited_delta`: the Block carrying the audited Delta, or, for a Record
§4's extension rule names, the Block *B₁* that sealed the triggering
Record; 80 octets as 160 lowercase hex characters). Every Record also carries `prev_record`
(§4): the ID of the same Auditor's preceding publication, or `null` for
its first. The Record names no Block: the audited
Block is the one Block
whose `publisher_delta` Entries carry `audited_delta`, which WIST-3 §3.2
makes unique and permanent, and *B₁*, where the proof is over it, is the
Block that sealed the Record which named `audited_delta` for this
Auditor — a fact of the Log a verifier locates before it verifies. `vrf_proof` is REQUIRED in every Record,
`unreachable` and `not_auditable` included, because it is what establishes
the Auditor's right and duty to have audited at all.

**`reference_delta`.** Every Record names the Delta it measured against.
`reference_delta` is the ID of the newest Delta in the audited Delta's
per-URL chain (WIST-1 §3.5: the same Publisher, the same Normalized URL)
sealed in a Block whose `sealed_at` is at or before the Record's
`fetched_at`. "Newest" is Log order — ascending Block height, then chain
order within a Block (WIST-3 §3.3). The audited Delta always qualifies,
because §3 already places `fetched_at` at or after its Block's
`sealed_at`, so the member is determinable for every Record,
`unreachable` and `not_auditable` included; where the chain has not
advanced by the fetch, `reference_delta` is `audited_delta`. An Auditor
holds the Log head when it fetches — its selection is derived from Block
Hashes — so the tip at fetch is a fact it already has.

**The Reference Payload.** Every audit is measured against exactly one
Payload, and which one is fixed by `reference_delta` alone:

- for a `new` or `update` reference Delta, that Delta's own Payload;
- for an `attest` or a `delete` reference Delta, the Payload of the **last
  content-bearing Delta at or before `reference_delta`** in that URL's
  per-URL chain — the URL's anchor Payload as of `reference_delta`
  (WIST-3 §6.1).

The reference is named in the Record rather than resolved from the URL's
present state, and that is what makes a Record verifiable at any later
height: a later `update` changes nothing the Record says, and the salt
below stays the salt of the Payload the Auditor actually held. Measuring
against the chain tip at fetch rather than against the audited Delta is
what makes an audit a question the Publisher can answer honestly. The
claim a page must carry at any instant is the Publisher's *latest* sealed
claim: a Publisher that rewrote a page and sealed the rewrite before an
Auditor fetched is judged on the rewrite, and a Publisher whose latest
sealed claim is not what it serves is judged on that. A reference fixed
by the audited Delta alone would instead measure an honest rewrite
against text the Publisher had already replaced, and the extension rule
(§4) — which summons every independent Auditor *after* the first
divergence — would confirm the finding against every page that changes
faster than the audit window. The reading is not the Record's own Block
either: a reference that could be any Delta sealed before the Record
seals would let a Publisher answer a fetch it noticed with an `update`
declaring whatever it served, and every lie would be followed by its own
absolution. Because the chain, its order, every Delta in it and the
Block `sealed_at` values are in the Log, the resolution is deterministic
from Log order alone.

Wherever this section reads a change type — the `delete` mirror, the link
dimension's applicability, §6's `C` — it reads the **reference Delta's**.

A `delete` audit has a Reference Payload for the same reason it has
anything to check: the claim a `delete` makes is that the content its
chain last committed to is no longer served (WIST-1 §3.3), so that Payload
is what the claim is judged against, and the capture the Auditor preserves
may contain that very content where the claim is false.

When an audit has nothing to measure against, the verdict is `not_auditable`.
That covers four cases: the Reference Payload has been withdrawn (WIST-3
§6.2); it cannot be fetched from any source; the URL's chain carries no
content-bearing Delta at or before `reference_delta`, so no anchor exists to
resolve; and the Reference Payload is obtained and verifies but its `extract`
is empty under the normalization below, so the Payload exists and there is
still no text the audit could confirm or refute.

WIST-1 §3.3 requires `payload` on every `new` and `update`, so a Delta
claiming content while committing to none is rejected (`WIST1-E09`) and never
sealed by a conforming Aggregator, and this list needs no case for it.
Should one reach a Log regardless, it is `not_auditable` for the reason the
requirement exists: a Delta asserting that content appeared or changed
without saying what it changed to leaves nothing to check it against, and
its Reference Payload is not the URL's earlier anchor, because the claim it
makes is precisely that the content is no longer what the anchor holds.

**The Auditor's commitments.** An Audit Record observes page content
directly, so every content-derived value it seals uses the same
construction the Delta uses, under the same key:

    <commitment> = "hmac-sha256:" + hex(HMAC-SHA256(key = salt,
                                                    message = <octets>))

where `<octets>` is the raw response body, the UTF-8 bytes of the
Auditor's reference extraction, or the bytes of the WARC capture, and
`salt` is **the salt of the audit's Reference Payload** (WIST-1 §3.6). The
Auditor holds that salt because it MUST verify that Payload before
comparing anything, so no second salt, and no second lifecycle, is
introduced.

**The capture format.** The WARC capture is a WARC file ([ISO 28500])
recording the fetched exchange §12 describes. No version of the format is
pinned, because every duty this suite places on the capture is over its
octets: `evidence_commitment` commits to them, and a party checking a
Record recomputes over the same octets, so the version changes no value
any party computes. An Auditor SHOULD nonetheless write WARC 1.1, so that
an appellant fetching the capture under §7 can read the evidence with
ordinary WARC tooling rather than with the Auditor's.

`response_commitment`, `ref_extract_commitment`, `evidence_commitment` and
`similarity` are REQUIRED when the verdict is `consistent`, `inconsistent`,
`dynamic_variance`, `link_variance`, or `link_inconsistent`, and MUST be
omitted when it is `unreachable` or `not_auditable`. Those two verdicts
are exactly the cases with nothing to commit to and no key to commit
under: `unreachable` records that no representation of the page was
obtained to compare against, whether the fetch failed outright, returned
an error status the table below does not except, or was forbidden by
`robots.txt`, so whatever bytes the failure produced are not the page and
are not committed to; `not_auditable` records that there was no text to
measure against, and where the Reference Payload itself is missing there is
no salt either. `schemas/audit-record.schema.json` enforces both
directions.

The requirement is the same for every change type, `delete` included. A
Record carries a `similarity` whenever it carries a judgement that was read
from one, and what the change type adjusts is the *reading* — the mirror
below — never the presence of the field. That is what keeps §7's severity
derivable for every Confirmed Inconsistency, and it is enforceable by the
schema, which sees a verdict but cannot resolve `reference_delta` to a
change type.

A bare digest here would undo the rest of this design. Moving extracts out
of the Log accomplishes nothing if the Log keeps unsalted hashes of the
same text: a party holding a copy could recompute one and confirm the text
was there, which is exactly the confirmability WIST-1 §3.6's salt exists to
destroy. Binding one salt to all four commitments — the Publisher's and
the Auditor's three — makes them expire together rather than leaving the
weakest one governing.

**Which captures are preserved.** The preservation duty is scoped to the
Records that can ever become evidence. An Auditor MUST preserve the WARC
capture behind an `inconsistent` or `link_inconsistent` Record for
`warc_retention_days` (Parameter Registry; default 90) from the
`sealed_at` of the Block sealing the Record — and for as long beyond that
as a `notice` naming the Record in its `evidence` has an appeal window,
sealing deadline or ruling deadline still open (§7). While such a notice
is pending, the Auditor MUST serve the capture at
`https://<auditor_id>/.well-known/wist/evidence/<record-id-hex>.warc`
(the Record ID's hex, without its `sha256:` prefix), so an appellant can
recompute `evidence_commitment` without the Auditor's cooperation being a
favor. For every other verdict the capture MAY be discarded once the
Record is sealed: only `inconsistent` and `link_inconsistent` Records can
join a Confirmed Inconsistency or Confirmed Link Inconsistency, so only
they can ever be the evidence a sanction or an appeal turns on, and a
duty to hold every capture for every audit would grow with system
throughput while securing nothing — its cost would fall precisely on the
role this suite gives no revenue, and pricing Auditors out is itself a
security failure (§11). `evidence_commitment` is still sealed on every
Record that carries one; for a discarded capture it remains what any
commitment is after its artifact lapses — binding on what the Auditor
held, checkable while the Auditor still holds it, and nothing further.

**Verifying a commitment, and when it stops being possible.** A party
checking an Audit Record obtains the salt the way the Auditor did: it
fetches the audit's Reference Payload, verifies that Payload against its
own Delta's commitment (WIST-1 §3.6), and takes the salt from it. It then
recomputes the Record's commitments over the artifacts it holds — the
Auditor's preserved WARC capture above all. While that Payload is served,
every value in the Record is checkable by anyone.

How much of a sanction's evidence is still checkable when the Publisher
appeals is decided by §7's ladder spans, and for one rung the answer is:
not all of it. Levels 1 and 2 open no appeal window at all — they follow
automatically from evidence any party can recompute — so nothing there
depends on a capture surviving. For levels 3 and 4 the ladder bounds
nothing that helps. Its 90-day and 180-day spans bound how far apart the
Confirmed Inconsistencies may lie, not how old any of them is when the
process runs, and level 3's other branch — any severity-3 — fires on a
single Confirmed Inconsistency of no age at all. At the other end §7 sets
no deadline for sealing a `notice` once the criteria are met, the appeal
window runs from the `sealed_at` of the Block sealing that notice rather
than from a confirming Record's sealing, and level 4's second branch — a
level-3 domain that
accrues one further Confirmed Inconsistency — carries no span bound
whatever, because the level-3 state it builds on has none. An Aggregator
that files late moves the whole process later without limit.

So the age of a confirming Record when the appeal resting on it is heard
is unbounded above, and one reachable case is enough to show the
consequence: on level 4's 180-day branch the oldest confirming Record can
already be 180 days old at the `notice`, and 180 + 14 + 7 + 30 — the appeal
window, the sealing deadline and the ruling deadline of §7 — puts the
ruling at day 231, past the 180-day availability window (WIST-3 §6.1).
Nothing in the suite guarantees a Reference Payload is still served at that point. It
is guaranteed for confirmation, which is fixed within 72 hours of the
`sealed_at` of the Block sealing the first `inconsistent` Record, and for
nothing beyond that: a Record's
Reference Payload may lawfully have lapsed, or been withdrawn, throughout
the appeal it is being used to justify.

What an appellant can and cannot do in that window follows directly. For
every confirming Record whose Reference Payload is still served, it can
obtain the salt, demand the Auditor's capture, and recompute all three
commitments — the full check. For a Record whose Reference Payload is gone
it can do none of that, and neither can the Aggregator, the Auditor, or
the party ruling on the appeal: the evidence is symmetrically unverifiable
rather than verifiable by one side only. What remains is the `verdict` and
the `similarity` sealed in the Record, and those are sufficient for the
ruling to have a determinate basis, because §7 derives severity from the
effective similarity alone and §6.1 derives `penalty_n` from the same
values. An
appellant contesting an unverifiable Record is contesting whether the
Auditor judged honestly, which is what `auditor_remove` and the §4 VRF
evidence address, not whether the arithmetic was applied correctly.

Once a Reference Payload is withdrawn (WIST-3 §6.2), the salt is destroyed at
every serving path that rule binds — the Aggregator's, every Mirror's, and
the Publisher's own well-known copy (WIST-2 §3.1) — and that Record's
commitments can no longer be checked by anyone, the
Auditor included. That is the intended outcome, not a defect: it is the
same instant at which the Delta's own commitment stops being checkable. A
verifier that encounters an unverifiable commitment MUST NOT treat the
Record as invalid on that ground; it reads the Record's verdict as the Log
records it.

**What an audit fetches.** The Delta commits to content it does not carry
(WIST-1 §3.6), so an Auditor holding a Block fetches two further things: the
audit's **Reference Payload**, defined below, from
`/payloads/<delta-id-hex>.json` at the Aggregator, a Mirror, or the
Publisher (WIST-3 §6.1, WIST-2 §3.1) — where `<delta-id-hex>` is the ID of
the Delta whose Payload the Reference Payload is, `reference_delta` itself
where that Delta is content-bearing and the last content-bearing Delta at
or before it otherwise — and the URL itself. That Delta may be
`audited_delta`, may be earlier than it in the chain, or, where a
content-bearing reference was sealed after the audited Delta, may be later
than it. The Auditor MUST verify that Payload against **its own** Delta's
`commitment` and `bytes` before comparing anything, and MUST reject a
Payload that fails (`WIST1-E10`) rather than audit against it. The
commitment was fixed when the Publisher signed that Delta, so a Payload
that verifies is what the Publisher declared no matter who served it —
which is what lets the comparison below remain an audit of the Publisher
rather than of a Mirror.

**Both fetches are bounded, and the bounds are parameters.** An Auditor
MUST NOT be obliged to read more than `audit_fetch_cap_bytes` (Parameter
Registry; default 8 MiB) of response body for one audited URL, nor more
than `audit_domain_budget_bytes_day` (default 1 GiB) of Payloads and
audited URLs for one domain in one UTC day; it MUST NOT follow more than
`audit_redirect_max` (default 5) redirects for one fetch, and MUST NOT
wait longer than `audit_fetch_timeout_seconds` (default 30) for one. A
fetch stopped by the byte cap or the daily budget yields `not_auditable`,
and that Record is a **blocking Record** below. One stopped by the
redirect ceiling or the timeout yields `unreachable`, which is where
transport failure already lands.

The bounds exist for the reason §4's integers exist. Two honest Auditors
whose clients differ in what they will read reach different verdicts on the
same URL — one a measurement, the other nothing — and §5's confirmation
machinery cannot tell that disagreement from evidence. A similarity
computed in pinned integers over a representation obtained under unpinned
limits is not recomputable, whatever the arithmetic does. The bounds also
close an amplification the Aggregator was already protected from
(WIST-2 §5): the coverage duty means an Auditor owes a Record for every
selected Delta and so cannot decline a hostile response, which without a
ceiling lets a Publisher spend an Auditor's bandwidth at a rate the
Publisher chooses. Both limits are per-domain or per-URL, so a Publisher
serving oversized responses spends its own egress to exclude its own URLs
from materialization and reaches no other Publisher's; and because
`not_auditable` discharges the coverage duty like any other verdict (§4),
it cannot drive the Auditors it targets into coverage failure either.

Every Audit Record has an **Audit Record ID**: `"sha256:" + hex(SHA-256(JCS(record)))`
— the record's inner object canonicalized and hashed under the same
content-addressing construction WIST-1 §4 uses for a Delta ID. A `sanction`'s
`evidence` (§7) is a list of Audit Record IDs, so anyone can fetch exactly
the Records a sanction claims to rest on and recompute what they establish,
rather than trust the claim.

The web is not deterministic; byte equality is never the criterion.

`similarity` is an integer in **micro-units** (0 … 1 000 000, the same
resolution as `reputation_u`, §6), never a floating-point ratio. It
compares two texts: the `extract` of the audit's verified Reference Payload
— the **reference text** — and the WIST-2 §12 whole-document extraction of
the Auditor's own fetch, the **observed text**. Both sides are pinned:
the reference by the Payload's commitment, the observed by WIST-2 §12's
procedure over the raw response octets — no step between the fetched
bytes and the sealed integer is an implementation's choice.

**Normalization.** Each text is normalized on its own, in this order:

1. Unicode NFC.
2. Case-folding by the Unicode **default full case-folding** algorithm,
   never a locale-sensitive lowercasing: locale rules map Turkish dotted
   and dotless *i* differently from every other locale, and an Auditor's
   server locale MUST NOT be able to move a verdict.
3. Segmentation into words by the **default** word-boundary rules of
   [UAX #29], with no dictionary-based or language-specific tailoring.
   Tailorings are exactly where implementations diverge — a build carrying
   a Thai or Khmer dictionary segments a sentence that a build without one
   does not — and a metric that inherits that divergence is not
   recomputable. Under the default rules, scripts written without spaces
   still segment: Han, Thai, Khmer and Lao characters each stand as their
   own word, so their texts yield many short words rather than one long
   one.
4. Every segment containing no character of Unicode General Category L\* or
   N\* is discarded. What remains, in order, is the text's **word
   sequence**; its **normalized form** is those words joined by a single
   U+0020. A text whose word sequence is empty is itself **empty**.

**Shingles.** Let *w* be a text's word count and *g* the count of extended
grapheme clusters ([UAX #29]) in its normalized form. With *A* the shingle
set of the reference text and *B* that of the observed text:

- If both texts have *w* ≥ 8, the unit is the word and the shingle length
  is 8: each set is that text's contiguous 8-word sequences.
- Otherwise the unit is the extended grapheme cluster of the normalized
  form and the shingle length is `n = min(8, g_A, g_B)`: each set is that
  text's contiguous *n*-cluster sequences.

Then

    similarity = floor((|A ∩ B| × 1 000 000) / |A|)

in exact integer arithmetic on the shingle sets' cardinalities — no
floating-point ratio is ever computed or compared, and no two conforming
Auditors can disagree about a boundary case from rounding alone.

**The quotient is containment, not resemblance, and the denominator is
the reference alone.** The observed text is the whole document (WIST-2
§12), so *B* carries every navigation link, footer and template string
the page serves; a symmetric ratio over `|A ∪ B|` would dilute an honest
Publisher's score with its own page furniture, and a heavy template
could sink a faithfully served extract below the `consistent` band.
Containment reads the one question an audit asks — *how much of the
committed text does the page carry?* — and boilerplate lands only in
*B*, where it costs nothing. What containment forgoes is also stated: a
page can carry the committed text and other content besides, up to and
including a page whose visible emphasis is elsewhere, and score full
marks — including where the committed text is present in the response
octets but hidden from a reader by CSS or layout, since WIST-2 §12 extracts
from the octets and never from a rendered page. Naming that plainly
matters more than narrowing it: detecting hidden text means resolving
styles, which means a rendering engine, which is precisely the
implementation-divergent step WIST-2 §12 exists to remove — a metric that
disagreed between Auditors would be worse than one with a stated
blind spot. What the metric therefore certifies is exact: **the
response carries the committed text**, not that a reader sees it
foremost. The suite's posture on the gap is ADR-0008's — what a page
serves is the Publisher's editorial act, and what a served page
deserves is ranking's judgement, computed by consumers over the same
commons, on evidence including the raw octets every Consumer can
fetch for itself. The `delete`
mirror below is unaffected — effective similarity `1 000 000 −
similarity` reads "the committed text is still being served", which is
exactly what refutes a `delete`.

The second branch is normative, not a convenience. Eight-word shingles do
not exist in a text of fewer than eight words, and a rule that let the
reference set come out empty would leave the quotient undefined exactly
where a Publisher's extract is a headline. Falling to grapheme clusters
keeps a short text comparable at the granularity it actually has, and
capping the shingle length at the shorter text's own length keeps `|A|`
≥ 1 — the empty-reference case never reaches the quotient, because the
rule below sends it to `not_auditable` first.

Texts too small to measure are ruled on rather than measured, and both
rulings are `not_auditable`. An empty **reference** text is
`not_auditable` (above): a Publisher that committed to no text made no
claim an audit could confirm or refute. On the observed side the rule is
the **mass guard**: an observed text of fewer than `min_observed_words`
words (Parameter Registry; default 40), counted after normalization, is
`not_auditable` — absence is not contradiction. The guard exists because
a low-mass page cannot distinguish the cases that matter: a script-shell
whose text exists only after execution, a bot interstitial served to
every Auditor at once, and a genuinely blanked page all produce a
near-empty extraction, the first two from perfectly honest Publishers —
and correlated across Auditors, since every Auditor meets the same
interstitial, so the two `inconsistent` Records a confirmation needs
would not be independent evidence but the same failure observed twice,
one correlated artifact from a severity-3 band. Above the guard the
ambiguity inverts: forty words is no longer a page that says nothing
but a page that says *something else*, which is precisely the fraud
case, and a fraudster padding junk past the guard to dodge it walks
into the `inconsistent` band containment gives junk. What the guard
forgoes is bounded and correct: a page persistently below it
accumulates `not_auditable` Records, its claims go unconfirmed, `C`
stops growing, and — these being **blocking Records** in the sense the
unauditable horizon below defines — two independent ones exclude the
URL from materialization. Exclusion, not sanction, is the consequence
for content the audit mechanism cannot see, and it is a consequence
rather than an exemption: the guard protects an honest Publisher from
being punished for a page nobody can measure, never from having an
unmeasurable page's declared extract dropped from the index. The `delete` mirror below is unaffected: a `404` or `410` to a
`delete` audit is a ruled-on response, not a measured extraction.

**The similarity dimension is defined over HTML.** The observed text is
produced by WIST-2 §12's extraction from a fetched HTML representation,
and no such procedure is pinned for any other media type — a PDF, an
image, or a media stream has no extraction two Auditors are bound to
compute identically, and a metric that inherits a parser disagreement is
not recomputable (the reason the link dimension already skips non-HTML,
WIST-2 §11). An audit whose fetched representation is not HTML in the
sense of WIST-2 §11 is `not_auditable` for the similarity dimension,
whatever its bytes: an honest Publisher of un-parseable-by-Auditor
content MUST NOT be sanctionable for the tooling gap. The same horizon
consequence governs — such a Record is a **blocking Record** below, so
non-HTML claims are excluded from materialization on the same terms as
any other unmeasurable page rather than carried unaudited. This is an
auditability boundary, recorded as such: a later revision MAY pin
per-media-type extraction procedures and move it, and the cost until
then is borne where it belongs — a Publisher whose PDFs the tiers omit
has a remedy (serve an HTML representation), while a suite that indexed
them unauditably would give its Consumers none.

**Effective similarity.** A `new`, `update` or `attest` Delta claims the
URL carries the reference content, so agreement confirms it; a `delete`
claims the opposite, so agreement refutes it. One table serves both, read
over the **effective similarity**:

    effective similarity = similarity                 (new, update, attest)
                         = 1 000 000 − similarity     (delete)

Every threshold in this suite is read over the effective similarity —
the table below and §7's severity bands alike — while `similarity` is what
the Record seals. A validator resolving `reference_delta` to its change
type applies the mirror; nothing else in the pipeline changes shape.

| Verdict | Condition |
|---------|-----------|
| `consistent` | effective similarity ≥ 600 000 and, where the link dimension applies, `link_agreement` ≥ 600 000 |
| `dynamic_variance` | 300 000 ≤ effective similarity < 600 000 |
| `inconsistent` | effective similarity < 300 000 |
| `unreachable` | no representation of the URL was obtained: transport or DNS failure, `audit_redirect_max` or `audit_fetch_timeout_seconds` exceeded (above), an error status other than the `404`/`410` a `delete` audit expects (below), or a `robots.txt` prohibition (WIST-2 §5) |
| `not_auditable` | there is no text to measure against: the Reference Payload is withdrawn (WIST-3 §6.2), never existed, cannot be obtained from any source, or carries an empty `extract`; or the page cannot be read within `audit_fetch_cap_bytes` or `audit_domain_budget_bytes_day` (above) |
| `link_variance` | effective similarity ≥ 600 000 and 300 000 ≤ `link_agreement` < 600 000 (neutral: it never contributes to sanctions) |
| `link_inconsistent` | effective similarity ≥ 600 000 and `link_agreement` < 300 000 |

**The seven are ordered, and the order is normative**, because more than
one description can fit one audit: `not_auditable`, then `unreachable`,
then the three extract bands, then the two link bands. An Auditor with no
reference text records `not_auditable` whether or not the fetch also
failed — from a withdrawal's sealing height it MUST, even holding a copy —
and an Auditor that obtained no representation records `unreachable`
without computing a similarity it has no observed text for; one whose
representation is non-HTML, whose observed text falls below the mass
guard, or which the fetch bounds above stopped before a representation
was read, records `not_auditable` under the three rules above — except on
the `delete` mirror's ruled-on `404`/`410`. A band is read only when
there is a reference to measure against, an HTML representation to
measure, and an observed text past the guard to measure it by. Since the three extract bands partition 0 … 1 000 000 with no gap
and no overlap, exactly one of `consistent`, `dynamic_variance` or
`inconsistent` fits every audit's effective similarity. The `inconsistent`
row rests on the number alone: a conjunct requiring the claimed content to
be "absent from the fetched page" would name no procedure two Auditors
could apply to one answer, and would leave every audit below the floor
whose content was in some sense still present with no verdict at all —
which is the one thing a verdict table may not do. The extract reading is
resolved first, and only an extract in the `consistent` band can yield a
link verdict, because a fabricated page makes every reading of its links
moot and extract fraud already sanctions harder. The thresholds are
`link_agreement_consistent` and `link_variance_floor` (Parameter
Registry), read directly — no mirror applies, the dimension being neutral
for `delete`.

The totality claim extends to the full seven rows the same way. Inside
the extract-`consistent` band, where the link dimension applies, the
amended `consistent` condition and the two link bands partition
`link_agreement`'s own 0 … 1 000 000 with no gap and no overlap in turn:
`link_agreement` ≥ `link_agreement_consistent` reads `consistent`,
`link_variance_floor` ≤ `link_agreement` < `link_agreement_consistent`
reads `link_variance`, and `link_agreement` < `link_variance_floor` reads
`link_inconsistent`. That second partition is nested inside the one
extract band it can move a verdict out of — an extract-`dynamic_variance`
or extract-`inconsistent` audit is already decided and never reaches
it — and the qualifying clause is simply vacuous, not applying, for a
`delete` audit, a non-HTML representation, or an extract band other than
`consistent`. One partition over the extract reading, nested with a
second over `link_agreement` where and only where the first admits it:
exactly one verdict fits every audit, seven rows included.

**The link dimension.** Where the reference Delta's change type is `new`,
`update` or `attest` and the fetched representation is HTML in the sense
WIST-2 §11 fixes — by the `Content-Type` media type alone, never by sniffing
the body — the Auditor also applies that section's extraction procedure to its
own fetched octets and compares the result against the Reference Payload's
`links` member. Two integer readings, each in micro-units, combine by minimum:

    subset  = floor(|D ∩ O| × 1 000 000 / |D ∪ O|)        D, O non-empty union
            = 1 000 000                                    D = O = ∅
    count   = floor(min(Td, To) × 1 000 000 / max(Td, To)) max > 0
            = 1 000 000                                    Td = To = 0
    link_agreement = min(subset, count)

where `D` is the set of declared `urls`, `O` the first-prefix set the
Auditor's own extraction yields under the same budget, and `Td`, `To`
the two totals. Exact integer arithmetic on set cardinalities — no
floating-point ratio is ever computed or compared, the rule §5 already
states for `similarity`. The dimension is **neutral** — `link_agreement`
is not computed and no link verdict can arise — for a `delete` audit
(the expected `404`/`410` has no links to observe), for a non-HTML
representation (whose conforming declaration is `{"total": 0, "urls":
[]}` and whose extraction WIST-2 does not define), and wherever the
verdict is `unreachable` or `not_auditable`.

A Record that produced a measured verdict for a non-`delete` audit of an
HTML representation SHOULD carry `link_agreement`. "Measured" excludes an
`unreachable` and a `not_auditable` Record, for which the dimension is
neutral above and which therefore never carry the field however the
change type and the media type read: the first observed no
representation to extract from, the second has no reference set to
compare one against, and `schemas/audit-record.schema.json` rejects
either sealing a reading it cannot have taken. Omission where the
dimension does apply leaves it unaudited for that Delta, and it is
visible in the Record itself: a Record whose change type, representation
and verdict all say the dimension applied, and which nonetheless carries
no `link_agreement`, is a fact any party recomputing reputation can see
and weigh, not a silent gap.

**`delete` audits.** Two consequences of the mirror are worth stating
outright. A `404` or `410` response to an audit whose reference Delta is a
`delete` is not a fetch failure but the state the Delta claims: the Auditor
treats it as a representation, its observed text is empty, `similarity` is 0,
the effective similarity is 1 000 000, and the verdict is `consistent`. And a
URL still serving the content its chain committed to after a `delete`
reference is `inconsistent` — its effective similarity is below 300 000 like
any other, so §7 derives its severity from the same bands over the same sealed
field as for every other Confirmed Inconsistency. A `delete` is a claim like
the rest and MUST NOT become a way to retire a false one by making it
unmeasurable: were a false `delete` to carry no severity input, publishing one
would be the cheapest way to end an audit trail that was about to contradict
the Publisher.

`attest` and `delete` Deltas carry no Payload of their own, so both depend
on a Payload that may have been sealed long before
the Block under audit — often long before the availability window that
covers ordinary Payloads. Two independent parties are obliged to serve it:
the Publisher, for as long as it attests to the URL, re-anchoring the
chain with an `update` or a `delete` when it cannot (WIST-2 §3.1); and the
Aggregator, with no expiry until the first superseding content-bearing
Delta or `delete` for that URL is sealed, and then for one further
availability window (WIST-3 §6.1). Either
copy satisfies the audit, because the commitment makes them
interchangeable, so a Publisher cannot render its own freshness claims
unauditable by withholding its copy. Where the Reference Payload is
nonetheless unobtainable from every source, or has been withdrawn, the
verdict is `not_auditable`.

From the sealing height of a `payload_withdrawal` (WIST-3 §6.2), an Auditor
MUST record `not_auditable` for every audit whose Reference Payload is the
withdrawn one, even if it still holds or can still obtain a copy of the
Payload. Auditing is the one process that would otherwise keep
re-establishing, in a permanent public record, the link between a withdrawn
text and its commitment.

`dynamic_variance`, `unreachable`, `not_auditable` and `link_variance` are
neutral: they never contribute to sanctions. Like `dynamic_variance`, a
`link_variance` Record never adds its URL to §6's `C` — only a
`consistent` verdict does — so persistent link churn holds a URL outside
the reputation numerator exactly as content churn does: neutrality means
no sanction, not no consequence. Auditor re-fetches of content URLs
respect `robots.txt` (WIST-2 §5); a fetch forbidden by `robots.txt` is
recorded `unreachable` with `robots_excluded` true. That flag is REQUIRED
when `robots.txt` is the reason and MUST NOT appear on any other verdict,
so the Log distinguishes a URL nobody is permitted to check from one that
happened to be down.

**Declining audits is not indefinitely free.** A URL is **unauditable** at
height N when the Log holds two **blocking Records** for Deltas on
that URL, signed by Auditors independent of one another (§3), each of them
sealed in a Block itself sealed inside the 30 whole days (Parameter
Registry: `unauditable_horizon_days`) ending at Block N's `sealed_at` —
end-inclusive and start-exclusive, measured as every window in this
document is (§4, §7), so a blocking Record sealed exactly 30 whole days
before N has aged out — and no
Record for a Delta on that URL with verdict `consistent`, `inconsistent`,
`dynamic_variance`, `link_variance` or `link_inconsistent`, signed by an
Auditor independent of both, was sealed after the later of those two and
at or below N. An
unauditable URL MUST be excluded from materialization (WIST-3 §7) for as
long as that holds; it ceases to be unauditable when such a Record is
sealed, or when the blocking Records age out of the window with none
replacing them.

A **blocking Record** is a `robots_excluded` Record — the URL nobody is
permitted to check — or a `not_auditable` Record produced by the observed
side: the mass guard, the non-HTML rule below, or the fetch bounds above.
It is not a
`not_auditable` Record produced by a missing or empty **reference**,
which says the Publisher committed to nothing an audit could measure and
is the Publisher's own claim to have made no claim. The distinction is
what the predicate turns on: a URL whose *page* cannot be measured is a
URL whose declared `extract` no Auditor can ever confirm, and carrying
an unconfirmable extract in the tiers indefinitely is exactly the
unverified index this suite exists to replace. Exclusion, not sanction,
remains the answer — the Publisher is not accused of anything, and
serving one measurable page restores the URL — but the answer has to
exist: without this clause a Publisher committing to a rich `extract`
while serving a twenty-word shell, a PDF, or a response no Auditor is
obliged to finish reading would be permanently unauditable, permanently
unsanctionable, and permanently materialized, which is the one
combination no rule here may produce.

Two properties of that definition are load-bearing, and both are
departures from the obvious shape. It arms on the **presence** of
exclusions rather than on the absence of successes, and it clears only on
a success by an Auditor **independent of the Auditors that were turned
away**. A rule that cleared on any success would be defeated by a
`robots.txt` that admits exactly one Auditor: that Auditor's Records would
clear every exclusion the others recorded, keeping the URL materialized
forever while guaranteeing that no second independent Auditor can ever see
the page — and a Confirmed Inconsistency, needing two, could then never
form for it. WIST-2 §5 closes that from the other side by making a
`robots.txt` that discriminates between admitted Auditors a prohibition
for all of them; the independence requirement here is what holds if a
Publisher discriminates by some means `robots.txt` does not express.

It takes two Auditors to arm the horizon for the same reason it takes two
to confirm an inconsistency. `robots_excluded` is a single Auditor's
unverifiable claim about a file that party alone fetched, and exclusion
from materialization is a real consequence carrying no notice and no
appeal; one Auditor MUST NOT be able to impose it alone (§11).

Nothing here is punitive and nothing here is a sanction: no reputation
consequence attaches, no `notice` is filed, no appeal window opens, and no
Aggregator action is required, because a Publisher may exclude a crawler
for reasons that are entirely its own. What the rule removes is the
*combination*. A Publisher may decline audits and keep publishing signed
Deltas, or it may be materialized, but not both indefinitely — an index
carrying content that nobody is permitted to check is exactly the
unverified index this suite exists to replace. Every half is recomputed
from the Log by every party alike, and the whole of the state is one URL's
Audit Records in Log order.

**No single audit punishes.** An `inconsistent` verdict triggers re-audit
by additional Auditors — §4's extension rule is the mechanism, and it is
a duty, not an invitation. A **Confirmed Inconsistency** exists only when ≥ 2
Auditors, independent of one another in the sense §3 defines, return
`inconsistent` for the same Delta, with the `sealed_at` of the Block
sealing the confirming Record no more than 72 hours after the `sealed_at`
of the Block sealing an earlier such Record from an Auditor independent
of the confirmer. The window is pairwise and ends at the confirming
Record's Block — the same window §4's extension rule reads as "ending at
*B₁*" — so a lone early Record that goes stale unconfirmed does not bar a
later independent pair from confirming, and the extension a later lone
Record triggers can still seal a confirmation inside the window it
serves. The window is measured on
Blocks and not on `fetched_at` for the reason §3 gives: `fetched_at` is
Auditor-supplied, and a confirmation nobody can recompute is not evidence.
Only Confirmed Inconsistencies and Confirmed Link Inconsistencies enter the
reputation formula and sanction ladder. Independence absorbs what differs by
vantage or by moment — A/B tests, geo-variation, a transient defacement — and
`reference_delta` absorbs sealed change: a rewrite the Publisher sealed before
the fetch is what the fetch is measured against.

## 6. Reputation

Reputation is an integer in **micro-units** (`reputation_u`, 0 … 1 000 000,
a resolution of 1e-6) and is a pure, deterministic function of Log history
evaluated **at a Block height N**. No floating-point arithmetic appears
anywhere in its definition: every input is an integer, every division is
integer division, and any implementation replaying the same Log to the
same height MUST produce bit-identical values. An implementation that
computes reputation in binary floating point is non-conforming even when
its results happen to agree, because `exp()` is not correctly rounded in
any mainstream math library and the last unit in the last place decides
audit selection, quota, and inclusion latency.

Every other section consumes `reputation_u` itself — §4's selection test
and §6.4's quota and latency thresholds all take the integer. No section
converts reputation to a fraction of 1: micro-units are the single
normative representation, and any decimal shown in this document (0.10 for
the Provisional cap, 0.5 for the latency threshold) is a reading of the
integer, not a second definition of it. All constants live in the
Parameter Registry (§9), read as of the `sealed_at` of Block N.

**Evaluation order is normative.** Every integer division an
implementation performs is written below with its dividend and its divisor
fully parenthesized, and **those parentheses are part of the definition**.
Each division applies only to the parenthesized expression immediately
preceding it: multiplications inside a dividend are carried out first, in
exact integer arithmetic on the full-width product, and only that quotient
is truncated. No addition or subtraction standing outside the parentheses
is ever folded into a dividend, and no operand is divided before being
multiplied. The rule governs every integer division in this suite,
including any a later revision adds. Today there are exactly **four**, all
of them here — §4's selection test contains none — together with the two
misreadings that produce different and non-conforming results:

| # | Correct | Wrong | Why it matters |
|---|---|---|---|
| 1 | `(seconds(Y) − seconds(X)) / 86 400` (§6.1) | — | the dividend is a difference *inside* the parentheses, the one place a subtraction is part of a dividend, and it is written that way |
| 2 | `100 000 + ((900 000 × min(A, 730)) / 730)` (`base_u`, §6.1) | `(100 000 + 900 000 × min(A, 730)) / 730` | at `A` = 0 gives 100 000, not 136 — the wrong parse destroys the Provisional-cap continuity of §6.2 |
| 3 | `(base_u × (C + 1) × 1 000 000 000) / ((C + 1) × 1 000 000 000 + 5 × penalty_n)` (`reputation_u`, §6.2) | — | one fully parenthesized product over one fully parenthesized sum; it has no second reading |
| 4 | `100 + ((10 000 × reputation_u) / 1 000 000)` (`Q`, §6.4) | `100 + (10 000 × (reputation_u / 1 000 000))` | at `reputation_u` = 359 236 gives 3 692, not 100 — the wrong parse truncates every sub-unit reputation to zero quota slope |

Fractions that appear elsewhere in this document — `exp(−t / 180)` in the
decay table's construction, `(C + 1) / ((C + 1) + 5 × penalty_n)` in the
monotonicity argument below, `D / 2^64` in §4 — are rationals used to
explain a definition, and no conforming implementation ever evaluates one:
the table is read, not computed, and §4's test multiplies both sides out.

### 6.1. Inputs

Every day count is derived from Block `sealed_at` values, never from wall
clock time and never from a Publisher-supplied timestamp. A Block's
`sealed_at` carries whole-second precision and a literal trailing `Z`,
enforced by both WIST-3 §3.1 and `schemas/block.schema.json`, so
`seconds(sealed_at)` — the count of seconds since 1970-01-01T00:00:00Z
with every day counted as exactly 86 400 seconds and no leap seconds — is
an exact integer for every conforming Block, with no fractional part to
round and no offset to reduce. "Whole days between X and Y" is then
`(seconds(Y) − seconds(X)) / 86 400` under integer division. `sealed_at`
is strictly increasing across Blocks (WIST-3 §3.1), so every such difference
is non-negative and the rounding direction of a negative quotient never
arises.

**Identity scope.** `A`, `C`, and the set of Confirmed Inconsistencies are
all scoped to the domain's **current identity**: every one of them counts
only Log events sealed at a height ≤ N that belong to that identity, and
an event belongs to the identity whose Delta it concerns. An accepted
Delta belongs by its own sealing height; an Audit Record — a `consistent`
one for `C`, a confirming one for a Confirmed Inconsistency — by the
sealing height of its `audited_delta`, never by its own. That height
MUST be greater than the domain's most recent identity reset (§6.3) for
the event to count. A domain that has never reset has no such lower
bound, and everything from height 0 counts.

- **`A`** = whole days between the `sealed_at` of the Block that first
  contained an accepted Delta from this domain under its current identity
  and the `sealed_at` of Block N. A domain with no accepted Delta in that
  range has `A` = 0. Publisher-supplied `observed_at` is never used, so
  backdating a Delta cannot age a domain.
- **`base_u`** = `100 000 + ((900 000 × min(A, 730)) / 730)`, integer
  division, parenthesized as written. It rises linearly from 100 000
  (exactly the Provisional cap) at `A` = 0 to 1 000 000 at `A` ≥ 730.
- **`C`** = the number of distinct Normalized URLs (WIST-1 §3.2) of this
  domain that have at least one `consistent` Audit Record — sealed at a
  height ≤ N, for an `audited_delta` sealed above the domain's most
  recent identity reset — whose
  `reference_delta` (§5) is a content-bearing Delta (`new` or `update`)
  on that URL, capped at `C_cap` = 500. A Record whose reference is an
  `attest` or a `delete` never contributes, whatever Delta it audited.
  Counting distinct URLs rather than Records, and capping the count,
  prevents a high-volume Publisher from diluting penalties toward zero.
- **Confirmed Inconsistencies and Confirmed Link Inconsistencies.** Only
  those whose confirming Audit Record is sealed at a height ≤ N and whose
  Delta — the `audited_delta` its confirming Records share (§5) — is
  sealed above the domain's most recent identity reset count. For each such Confirmed
  Inconsistency or Confirmed Link Inconsistency *i*: `s_i` is computed
  from its confirming Records (§7) by the §7 severity table — {1 = minor
  divergence, 2 = misleading extract, 3 = fabricated content} — for a
  Confirmed Inconsistency, and is fixed at 1, satisfying no rule that
  names severity 3, for a Confirmed Link Inconsistency; in both cases
  independently of whether any `sanction` Registry Update exists for it.
  `t_i` is the whole days between the `sealed_at` of the **confirming
  Block** and the `sealed_at` of Block N. The confirming Block is the one
  sealing the **earliest Audit Record, in Log order (ascending Block
  height, then ascending Entry index within a Block), at which the
  applicable confirmation predicate is first satisfied** for that Delta —
  §5's for a Confirmed Inconsistency, §7's for a Confirmed Link
  Inconsistency: the same height that fixes `t_i` is the height at which
  it begins contributing to `penalty_n`, whether or not the Aggregator
  ever files a `sanction` for it. Records beyond that one — a third or
  fourth `inconsistent` or `link_inconsistent` verdict — do not move the
  date and do not create a second Confirmed Inconsistency or Confirmed
  Link Inconsistency; for a Confirmed Inconsistency they additionally do
  not move `sim` (§7), which a Confirmed Link Inconsistency's fixed
  severity has none of.
- **`decay(t)`** is read from the normative decay table
  ([`vectors/wist4/decay-table.json`](../vectors/wist4/decay-table.json)): an
  array of 1826 integers, `decay(t) = floor(exp(−t / 180) × 1e9)` — the
  decay scale 1e9 being 1 000 000 000 — indexed by whole days 0 … 1825,
  with `decay(t) = 0` for `t` > `decay_horizon_days` (§9), whose default
  is 1825 and which MUST NOT exceed the table's last index: a shorter
  horizon reads a prefix of the table, and no horizon reads past it. The table,
  not `exp()`, is normative; implementations MUST read it and MUST NOT
  recompute it at runtime. `decay(0)` = 1 000 000 000 and the table is
  strictly decreasing. Expiry at the horizon drops a residue of
  `decay(1825)` = 39 512 (3.95e-5 of full weight) to zero; that step can
  only raise a reputation, never lower one. The table is normative as
  *bytes*: SHA-256 of the file is
  `1ef9e9be20c99e595c1c75c5ab63409e1cc4f9540b466b67ecebf4e2959986b9`, and
  an implementation carrying a table that does not hash to that value is
  non-conforming even if every entry looks plausible. Changing the table
  changes every reputation in the system, and it is not a
  `parameter_change`: the table is normative as bytes, so a new one is a
  new artifact of this suite (§9), and the constant it was generated
  from — 180 days, the penalty decay constant — carries no identifier
  for the same reason, since a bare number cannot regenerate bytes every
  party must hold identically. The horizon alone is amendable, downward.
- **`penalty_n`** = `Σ s_i × decay(t_i)`, in exact integer arithmetic. The
  sum is over integers, so its value does not depend on summation order;
  implementations that publish intermediate sums SHOULD nevertheless
  accumulate in ascending `t_i`, ties broken by ascending byte order of
  the UTF-8 Delta ID of the inconsistent or link-inconsistent Delta, so
  that intermediates agree too.

### 6.2. The formula

    reputation_u = (base_u × (C + 1) × 1 000 000 000)
                   / ((C + 1) × 1 000 000 000 + 5 × penalty_n)

using integer division, then clamped to [0, 1 000 000]. The 1 000 000 000
is the decay scale: it cancels against the scale of `penalty_n`, so
`decay` never has to be un-scaled and no rounding happens before the final
division. Every dividend here is non-negative and every divisor is
positive, so truncation toward zero and flooring coincide: no
implementation language's treatment of negative operands can change the
result. The clamp is defensive — the quotient cannot leave the range — and
MUST be applied anyway.

A signed 64-bit integer holds every intermediate: the numerator is at most
1 000 000 × 501 × 1 000 000 000 ≈ 5.01e17, and the denominator exceeds
2^63 only for a domain carrying more than 6 × 10^8 unexpired Confirmed
Inconsistencies at once. Implementations SHOULD nevertheless use
arbitrary-precision integers, and MUST NOT let any intermediate wrap
silently.

**Provisional cap.** While `A` < 30 or `C` < 10, the domain is
**Provisional** and

    reputation_u = min(reputation_u, 100 000)

The cap is a **ceiling only**, never a floor: it is `min(formula, cap)`,
not "forced to exactly the cap". A Provisional domain that has earned a
Confirmed Inconsistency therefore scores *below* 0.10, and the gate does
not launder it clean.

**No cliff at the boundary.** Reputation MUST NOT decrease solely because
a gate lifted, and under this definition it cannot: with `A`, `C`, and
`penalty_n` fixed, the gated value is `min(f, 100 000)` and the ungated
value is `f`, and `min(f, 100 000) ≤ f` for every `f`. The formula also
meets the cap continuously from below rather than jumping past it: at
`A` = 0 with no penalty, `base_u` is exactly 100 000, so a brand-new
domain's *ungated* value already equals the cap, and at the gate values
(`A` = 30, `C` = 10, no penalty) it is 136 986 — a promotion, not the
demotion the earlier `age_score = A / 730` formula produced. Since
`base_u` is non-decreasing in `A`, `(C + 1) / ((C + 1) + 5 × penalty_n)`
is non-decreasing in `C`, and `A` and `C` never fall except at an identity
reset (§6.3), `reputation_u` is monotone non-decreasing in both. Only a
new Confirmed Inconsistency lowers it. Worked values at, just below, and
just above the gate are in Appendix B.

Lifting the `C` gate can raise reputation by a large step — an aged domain
sitting at the cap with `C` = 9 moves to its full `base_u` at `C` = 10.
That is deliberate: standing above 0.10 requires audit evidence, and the
step is upward.

### 6.3. Identity, reset, and Provisional

`A`, `C`, and a domain's Confirmed Inconsistencies belong to a **key
identity**, not to a name. A Declaration that WIST-1 §5.2 classifies as a
**fresh identity** — signed by neither a key of the previous Key Set nor a
key in the previous Declaration's `recovery_keys` — is an **identity
reset** at the height its Declaration Entry is sealed. Call that height
`R`; the domain re-enters Provisional, and from `R` onward:

- **`A`** is measured from the `sealed_at` of the first Block above `R`
  sealing an accepted Delta from the domain. Until such a Block exists,
  `A` = 0.
- **`C`** counts only distinct URLs whose qualifying `consistent` Audit
  Record audits a Delta sealed above `R`. A URL audited before the reset
  does not count again until a Delta the fresh identity sealed on it is
  audited, and the pre-reset Records remain in the Log — they simply
  belong to the previous identity, as does a Record sealed above `R` for
  one of its Deltas.
- **Penalties do not carry across a reset.** A Confirmed Inconsistency
  for a Delta sealed at or below `R` leaves `penalty_n` entirely,
  whenever its confirming Record lands; only those for Deltas sealed
  above `R` count. A fresh identity starts clean, for exactly
  the reason `A` and `C` start at zero: it is a different party as far as
  the protocol can tell, and the Provisional cap — not inherited debt — is
  what bounds what it can claim. The finding follows the claim, not the
  confirmation: a Delta sealed below `R` is the previous identity's
  statement, and an audit that lands above `R` — inside that Delta's
  audit window, or under §4's extension rule — measures a statement the
  fresh identity never made and can only retract with a Delta of its own.
  Scoping by the confirming Record's height instead would hand the fresh
  identity a penalty, and under §7 a ladder rung, for content it did not
  publish, and would let the previous identity's timing decide which
  party a finding lands on.

**Sanction state binds the key identity too.** The §7 ladder is state
about the same party `A`, `C` and `penalty_n` are state about, and it
follows them: every rung in force at or below `R` — intensified
sampling, weight reduction, quarantine, delisting — lifts at `R`, and
the fresh identity enters Provisional like any other, which under WIST-2
§4 means no `403`: the two rules agree because a reset domain *is*
Provisional. Both alternatives are worse, and both were live before
this paragraph said otherwise. Were sanction state to survive a reset,
an innocent buyer of a lapsed level-3 domain would inherit a quarantine
it could never appeal — the appeal must verify against the notice-era
Key Set, which is exactly what a fresh identity does not hold — and
WIST-2's "Provisional domains MUST NOT receive 403" would contradict
level 3's required `403` for the same domain at the same instant. And
the lift is not the escape §6.3 forbids: what a reset sanctioned party
buys is Provisional's cap, the sampling ceiling §4 applies at that
reputation, zero `A`, zero `C` — level 3's practical effect (nothing it
publishes is materialized with standing) reconstituted from the other
end, plus the permanent Log record tying the old identity's evidence
to the domain name for any consumer that cares to look. Replayers MUST
derive the lift from the reset Declaration itself, as with every §7
state: no `sanction_lift` is involved, and an Aggregator's failure to
file one changes nothing.

Resetting is therefore never an escape: it costs the domain its entire
age, its whole audited-URL count, and its standing above 0.10, in exchange
for shedding penalties that decay to nothing in five years anyway. A
domain with a severity-3 Confirmed Inconsistency and two years of history
gives up far more than it sheds.

An **ordinary rotation** (signed by a previous signing key) and a
**recovery rotation** (signed by a pre-registered offline recovery key)
are not resets: both preserve `A`, `C`, and every outstanding penalty in
full. Replacing a Key Set is therefore not by itself a reset; only the
loss of every cryptographic link to the prior identity is.

Provisional is not a penalty and MUST NOT block participation: a
Provisional domain pings, is pulled, has its Deltas sealed, and is audited
exactly like any other, at the reputation-derived quota and sampling rate.
It is the only way `A` and `C` can grow, and therefore the only path out of
Provisional; an implementation that suspends ingestion for Provisional
domains cannot bootstrap and is non-conforming.

### 6.4. What reputation governs

Exactly three things:

1. **Ping quota** (WIST-2 §4): `Q = 100 + ((10 000 × reputation_u) /
   1 000 000)` Pings per UTC day, integer division, parenthesized as
   written. The new-domain quota WIST-2 §5 refers to is this formula at
   `reputation_u` = 100 000, i.e. **Q = 1100**. `reputation_u` is read at
   the **highest Block sealed before the UTC day began** — the day being
   the quota's own window — so Q is one value for the whole day and any
   party can recompute the exact Q a rejection was measured against
   without knowing the instant the Aggregator checked. A domain with no
   Block before its first day (a Log's first day) reads the empty log,
   which is the new-domain value above.
2. **Sampling rate** `p_1e7` (§4), which takes `reputation_u` directly at
   the height §4 fixes.
3. **Inclusion latency**: `reputation_u` ≥ 500 000 → eligible for the next
   Block; below → eligible for the Block after the next (one full Block
   of delay). Eligibility is a floor, and it has a ceiling: an accepted
   Delta MUST be sealed no later than `max_inclusion_blocks` (Parameter
   Registry; default 4) Blocks after the Block it became eligible for.
   A Delta queued under WIST-1 §5.2's recovery window is not yet
   eligible: its eligibility, and with it this ceiling's clock, starts
   at the first Block at or after the window's end, after WIST-1 §5.2's
   revalidation. Eligibility is gated the same way by WIST-3 §3.2's
   per-domain Block capacity: where more of a domain's Deltas are
   eligible for a Block than `domain_block_entries_max` admits, they take
   the capacity in acceptance order, and a Delta the cap holds out of a
   Block becomes eligible for the first Block with room for it, which is
   where its ceiling's clock starts. The ceiling bounds the Aggregator's
   delay of a Delta whose turn has come, not the domain's rate: a
   backfill of 50 000 accepted Deltas seals over five Blocks at the
   default cap, and none of them is late.
   The ceiling exists because both ends of the eligible-to-sealed gap
   are otherwise the Aggregator's, and operator revenue —
   subscriptions to the fresh stream — is proportional to the free
   stream's staleness: without a ceiling, "eligible for the next Block"
   bounds nothing and position *in time, on the read side* is lawfully
   for sale, one hop removed from the payment Invariant 2 forbids. The
   duty is not derivable from the Log alone — the Log cannot see an
   acceptance the Aggregator shelved — but it is observable by every
   Publisher against its own status endpoint (WIST-2 §7.1, which shows
   acceptance) and Feed, so a breach is a pattern any Publisher can
   document; and `block_cadence_seconds` carries a hard upper bound
   (§9) for the same reason, so the ceiling cannot be reconstituted by
   stretching the Block itself.

**Invariant: reputation is not a ranking signal.** It MUST NOT be used
by, exported to, or interpreted as an input for content relevance. It
measures *trustworthiness of process*, never *importance of content*.

## 7. Sanctions and Due Process

Sanctions are graduated, logged, evidence-bound Registry Updates
(`action: "sanction"`, `subject` = the domain, `evidence` = the Audit
Record IDs (§5) of the Audit Records establishing the Confirmed
Inconsistencies):

1. **Intensified sampling** — `p_1e7` raised to its maximum, 5 000 000
   (§4).
2. **Weight reduction** — the domain's Deltas are marked reduced-weight
   in materialized snapshots.
3. **Sanctioned Quarantine** — ingestion is suspended: the domain's Pings
   and Feed pulls are rejected (`403`, WIST-2 §4) until `sanction_lift` or
   a successful appeal.
4. **Delisting** — the domain's Deltas are excluded from materialization
   (the log, as always, retains history).

Severity is **derived from the evidence, not chosen**. The **confirming
Records** of a Confirmed Inconsistency are exactly the `inconsistent`
Audit Records for that Delta, in Log order (ascending Block height, then
ascending Entry index within a Block), from the first such verdict
through the Record at which §5's confirmation predicate is first
satisfied — the same closed set §6.1 uses to fix `t_i`; a Record sealed
after that point is not a confirming Record and moves neither `t_i` nor
`sim` (§6.1). For a Confirmed Inconsistency, let `sim` be the highest
**effective similarity** (§5) among its confirming Records: the set is
closed before the extremum is taken, so a Record arriving after
confirmation cannot lower severity by outbidding the ones that established
it. Reading the effective similarity rather than the sealed integer is what
gives a false `delete` a severity like any other finding — its confirming
Records seal a *high* `similarity`, because the content is still served,
and the §5 mirror turns that into the low effective value the bands below
are written over. Every `inconsistent` verdict has an effective similarity
below 300 000 by §5's own table, so every Confirmed Inconsistency lands in
exactly one row, whatever its reference Delta's change type.

| Condition | `severity` |
|---|---|
| 150 000 ≤ `sim` < 300 000 | 1 (minor divergence) |
| 50 000 ≤ `sim` < 150 000 | 2 (misleading extract) |
| `sim` < 50 000 | 3 (fabricated content) |

**Confirmed Link Inconsistency.** Two `link_inconsistent` Records for
the same Delta from Auditors independent under §3, the confirming Record
sealed within `confirm_window_hours` of the earlier — the same pairwise
window §5 defines — are a Confirmed Link
Inconsistency. For §6.1's `penalty_n` and every escalation count this
section defines, a Confirmed Link Inconsistency **counts as a Confirmed
Inconsistency with severity 1 fixed** — never derived from
`link_agreement`'s magnitude, unlike the severity table above — and it
satisfies no rule that names severity 3, so no accumulation of link
findings alone reaches the **fast path** to Delisting: neither level 3's
any-severity-3 branch nor level 4's three-severity-3 branch can ever
fire on them. The counting route stays open, by design — 10 link
findings inside 90 days reach level 3 and one further finding reaches
level 4, exactly as 10 severity-1 findings of any other kind would,
because a domain misdeclaring its links at that rate is no longer doing
it by accident. What the fixed severity settles is which route: the
slow, countable one, with the notice and the appeal window §7 attaches
to levels 3 and 4, never a single finding that delists on its own.
Declaring a distorted link set is gaming a signal, not fabricating
content, and the graph's consumers can weigh a domain's link record for
themselves. Severity is derived from the evidence, not chosen, here as
everywhere: a link finding carries level 1 whatever its magnitude.

A party recomputing reputation locates every Confirmed Inconsistency
directly from Audit Records under §5 — no `sanction` Registry Update is
required to find one — and computes each one's severity from the table
above; §6.1 counts it in `penalty_n` from the confirming Block onward
regardless of whether the Aggregator ever records a `sanction` for it. A
`sanction` therefore does not create the penalty: it records the ladder
action (the numbered list above) the Aggregator is taking in response, and
that is what a recomputing party checks it against. It MUST reject a
`sanction` whose `details.severity` disagrees with the table's value for
the Confirmed Inconsistency it names, or whose `evidence` does not resolve
to Audit Record IDs (§5) establishing one, and treat the ladder level that
sanction claims to apply as never having taken effect — but rejecting the
sanction does not touch the underlying Confirmed Inconsistency's penalty,
which was never conditioned on the sanction's existence. The Aggregator
therefore records ladder actions; it does not decide, and cannot suppress,
the reputation weight of what the evidence already shows.

Process requirements:

- Levels 1–2 follow automatically from the escalation criteria; levels 3
  and 4 MUST be preceded by a `notice` naming the evidence, whose sealing
  starts the appeal window below. Levels 1–2 need neither: their entire
  basis — the confirming Audit Records and the §7 severity table above — is already
  public and independently recomputable, so there is nothing a notice
  would let the Publisher contest that a replaying party cannot already
  verify for itself; this holds even for level 2's weight reduction, which
  affects standing without suspending ingestion. This applies to sanction
  notices (`details.kind` `"sanction"`); a `notice` with `details.kind`
  `"recovery"` *records* the WIST-1 §5.2 recovery window instead — that
  window opens at the `sealed_at` of the Block sealing the recovery
  Declaration itself, so it opens whether or not the notice is ever sealed
  — and is not subject to the appeal process below.
- Escalation criteria: level 1 at a single Confirmed Inconsistency; level
  2 at 3 within 90 days; level 3 at 10 within 90 days, or any severity-3;
  **level 4 at 3 severity-3 Confirmed Inconsistencies within 180 days, or
  a level-3 domain that accrues a further Confirmed Inconsistency**. Level
  4 is never conditioned on whether the Publisher appealed. Each window is
  measured exactly as §4's are: the 90 or 180 **whole days ending at**
  Block N's `sealed_at`, so a Confirmed Inconsistency counts when the §6.1
  whole-day distance from its confirming Block to N is below 90 (or below
  180) — end-inclusive, start-exclusive. Nothing here introduces a second
  way to measure a window: the Blocks that bound these spans sit on an
  hourly cadence, so a finding exactly 90 days before N would otherwise be
  in one implementation's count and outside another's.
- **Every rung is derived, levels 3 and 4 included.** Once the escalation
  criteria above are met at some height N, the corresponding state is in
  force on recomputation from N's Block onward, whether or not the
  Aggregator has sealed a `sanction` recording it. For levels 1 and 2 this
  is what "follow automatically" above already says, and it is not
  optional: §4's sampling rate reads a level-1 sanction as an input, and
  §6.4 and WIST-3 §7 read level 2 as one, so a rung that took effect only
  when an Aggregator chose to file would make audit selection and
  materialization depend on an act outside the Log — which §1 forbids and
  §4's recomputability claim could not survive. Levels 3 and 4 are derived
  on the same terms, mirroring severity above and the deadline rule below,
  and the derivation reaches their states — ingestion rejected (level 3),
  excluded from materialization (level 4). This governs
  recomputation only: the Aggregator's own conduct still MUST issue the
  `notice` before it enforces the rejection or exclusion in real time, so
  a Publisher retains its chance to appeal before the Aggregator itself
  acts. A captured Aggregator that never files either cannot spare a
  qualifying domain — a party replaying the Log arrives at the level-3 or
  level-4 state independently of what the Aggregator chose to record.
- **Derivation and due process, reconciled.** The rule above lets a party
  that operates no Aggregator — a Consumer, a Snapshot rebuilder, any
  third-party materializer — treat a domain as level-3 or level-4 when no
  `notice` has ever been sealed and no appeal window has ever opened. That
  is deliberate, and what makes it compatible with due process is what due
  process here is for. It is not a guarantee that no consequence precedes a
  notice; it is a guarantee that no consequence rests on facts the affected
  Publisher cannot see, recompute and contest. The derived state rests on
  nothing but Audit Records already sealed in the public Log, under the
  same §7 table every party applies, so a `notice` tells the Publisher
  nothing it could not read for itself — it fixes *who is obliged to tell
  it*, and it binds the one party that also holds the ingestion lever.
  Reversal propagates the same way the state does: a `sanction_lift`, an
  `appeal_ruling` of `"overturned"`, a ruling deadline that lapses, and an
  appeal-sealing deadline that lapses with neither an `appeal` nor an
  `"unappealed"` ruling sealed against the notice are all facts of the Log,
  so every recomputing party lifts the state at the same
  height without waiting on the Aggregator (WIST-3 §7). This is also why the
  derivation is bounded to the sanction's *state* and never to `penalty_n`:
  §6.1 counts the penalty from the evidence regardless, and an appeal has
  never reached it.

  The limit is worth naming rather than glossing. The appeal window is
  anchored to a `notice`'s Block, so where the criteria are met
  and the Aggregator seals no `notice`, the derived state is in force on
  recomputation with no window ever opening against it. The Publisher's
  remedy in that case is not an appeal but the evidence: the confirming
  Records are public, and a Record that is void under §3, or a severity the
  §7 table does not support, is rejected by every recomputing party alike,
  which removes the derived state at its root rather than pardoning it. An
  Aggregator that suppresses notices while the derivation runs is visible
  as exactly that, and §8's invariant 4 is what the commons has instead of
  an appeal to it.
- **Every Registry Update has a Registry Update ID**:
  `"sha256:" + hex(SHA-256(JCS(update)))` — the update's inner object
  canonicalized and hashed under the same content-addressing construction
  WIST-1 §4 uses for a Delta ID and §5 for an Audit Record ID. An `appeal`
  and an `appeal_ruling` name by that ID the `notice` they belong to
  (§9.1), which is what attaches each to one process rather than to
  whatever processes a domain has open.
- The appeal window is `appeal_window_days` (14) from the `sealed_at` of
  the Block sealing the `notice`, never from its `effective_at`.
  `effective_at` is a value the Aggregator writes for itself, bounded by
  nothing: a notice sealed today and dated a month ago would arrive with
  its own appeal window already closed, and every recomputing party would
  agree that it was. Every window in this document reads Block `sealed_at`
  for exactly that reason (§3), and the notice's `appeal_deadline` (§9.1)
  restates the derived instant rather than setting it — where the two
  disagree, the Block governs.
- **An appeal is published, then recorded.** A Publisher appeals by
  serving a signed `appeal` Registry Update at
  `/.well-known/wist/appeals/<notice-id-hex>.json` (WIST-2 §3.3),
  where `<notice-id-hex>` is the 64-character hex digest of the notice's
  Registry Update ID. That is the publish-then-pull path every other
  Publisher artifact takes, and it is the only one still open to a domain
  whose ingestion a level-3 sanction has suspended: the Publisher MAY ping
  (WIST-2 §4), but that domain's Pings are answered `403`, so WIST-2 §3.3 puts
  the fetch on the Aggregator as a duty that no notification gates. The
  appeal exists from the moment it is served; the
  Aggregator's Entry records it rather than creating it, and any party can
  fetch the served copy and verify it for itself. An `appeal` is signed by
  the Publisher and MUST verify against the Key Set current at the
  `notice`'s Block — not the present one — so that a domain in key
  compromise or identity reset (WIST-1 §5.2) can still appeal.
- **Sealing an appeal is a duty with a derived deadline.** An `appeal`
  served inside the appeal window MUST be sealed within `appeal_seal_days`
  (Parameter Registry; default 7) of the Aggregator obtaining it, and in no
  case later than `appeal_seal_days` after the window closes. Call that
  instant **T**: the notice's Block `sealed_at`, plus `appeal_window_days`,
  plus `appeal_seal_days` — a function of the Log and nothing else. By T
  the Aggregator MUST have sealed, for that notice, either the `appeal` it
  received or an `appeal_ruling` with `outcome` `"unappealed"` recording
  that the window closed with none. If the Log holds neither at T, the
  sanction's *state* — the level 3 ingestion rejection or the level 4
  exclusion from materialization — is void on recomputation from T,
  exactly as a lapsed ruling deadline voids it below.
- **A late appeal is recorded and changes nothing.** An `appeal` served
  after the appeal window has closed MAY be sealed, and an Aggregator that
  obtains one SHOULD seal it: it is a signed statement by the Publisher,
  and a rule that let the Aggregator drop it without trace is the silent
  suppression §4's `pull_attestation` exists to end elsewhere. What it does
  not do is reopen the process. It does not discharge **T**, because the
  window it belongs to already closed and only an `appeal` served inside
  the window or an `"unappealed"` ruling discharges it; it starts no ruling
  deadline; and it does not by itself alter the sanction's state. The
  Aggregator may still act on what it reads — `sanction_lift` is always
  available and needs no appeal to justify it — but that is a discretionary
  act recorded as one, not a deadline the Publisher restarted by filing
  late. Otherwise the appeal window would be advisory: a filing weeks
  overdue would reopen a closed process and void a state on a deadline the
  Aggregator could no longer meet.
- **An `"unappealed"` ruling cannot precede what it reports.** Such a
  ruling discharges T only when the Block sealing it has a `sealed_at` at
  or after the close of the appeal window — the notice's Block `sealed_at`
  plus `appeal_window_days`. One sealed earlier states that a window still
  open closed with nothing served, which the Log itself contradicts at the
  moment it is sealed, and a party recomputing MUST treat it as absent: if
  nothing else discharges T, the state is void from T as above. Without
  that constraint the ruling could be sealed in the same Block as the
  notice it closes, and an Aggregator could discharge every process it
  opens before any Publisher could answer one — recovering, for the price
  of a single Entry, exactly the free suppression this deadline exists to
  end. The constraint is a comparison of two Block `sealed_at` values and
  a parameter, so every replaying party applies it identically; no schema
  can express it, because the two Blocks are different Entries.
- **Why the omission carries the consequence.** Suppressing an appeal was
  otherwise strictly more effective than suppressing a ruling, which this
  section already closes: an unsealed appeal starts no clock, so a sanction
  the Publisher had contested stood forever while one it had not was
  eventually void. Anchoring the duty to T removes the asymmetry without
  making any party's silence a reprieve. A Publisher that does not appeal
  is answered by the `"unappealed"` ruling and its sanction takes effect
  unchanged — there is no silent reprieve and no penalty for silence. An
  Aggregator that receives an appeal and buries it must seal an
  `"unappealed"` ruling to keep the sanction standing, and that ruling is a
  signed, permanent, public claim that the Publisher's own served,
  signed appeal falsifies at a path anyone can fetch. What was invisible
  and free becomes attributable and dated, and doing nothing at all lifts
  the state on the same clock as an unmet ruling deadline.

  One consequence is worth naming rather than leaving to be discovered:
  sealing a `notice` now starts a clock the Aggregator must answer, so an
  Aggregator looking only at its own workload is better off sealing none.
  That path is already closed from the other side and at a price the same
  §7 sets — the Aggregator MUST issue the `notice` before it enforces the
  rejection or exclusion itself, so an Aggregator that files nothing keeps
  no ingestion lever and no exclusion of its own; what remains is the
  derived state that every other party applies without it. The bargain is
  the intended one. An Aggregator that wants a level-3 or level-4 sanction
  it can act on takes on a bounded, public duty to run the process it
  opened, and one that will not take that on does not get to act.
- An `appeal_ruling` MUST be sealed within `ruling_deadline_days` (30) of
  the `sealed_at` of the Block sealing the `appeal`
  (Parameter Registry: ruling deadline). An appeal does not stay a
  sanction unless the ruling says so, but if the deadline passes with no
  ruling, the sanction's *state* — the level 3 ingestion rejection or the
  level 4 exclusion from materialization — is void on recomputation as of
  that expiry: a party replaying the Log treats it as lifted whether or
  not a `sanction_lift` was ever sealed, so the Aggregator's inaction
  cannot keep it in force. This governs only the sanction's state, not
  `penalty_n`, which §6.1 derives from the evidence independently of any
  sanction. The Aggregator MAY still seal a `sanction_lift` recording the
  expiry, but it is descriptive: recomputation does not depend on it.

## 8. Constitutional Invariants

Four rules are constitutional: conforming implementations MUST enforce
them, and no Parameter Registry change, sanction, or operational decision
can amend them. Amending them requires a new major version of this suite
— which is to say, a fork that must win adoption on its own merits.

1. **No self-declared importance.** No object in this protocol carries a
   field by which a publisher declares its own relevance (WIST-1 §6). A
   push channel where submission could claim importance would inherit
   the entire adversarial history of SEO; importance is measured at
   consumption, outside the protocol.
2. **Position is not for sale.** The Aggregator MUST NOT accept payment
   or any consideration in exchange for inclusion, weight, latency, or
   any treatment of a Publisher's content. The day money buys position,
   the index's neutrality — its entire value — is gone. (Payment for
   infrastructure services that treat all Publishers identically, e.g.
   mirror bandwidth, is outside this prohibition.)
3. **The record is not rewritable.** Sealed Blocks are immutable and the
   Log is corrected by appending, never by editing; every commitment,
   verdict and governance action ever sealed remains. Content Payloads are
   not part of that record: they may be withdrawn, and only withdrawn,
   through a logged entry stating its legal basis (WIST-3 §6.2). The
   distinction is deliberate — an index must be able to comply with an
   erasure order without being able to rewrite its own history.
4. **The data stays open.** Public tier data is licensed under ODbL 1.0,
   irrevocably. Together with invariant 3, this guarantees forkability:
   if the institution operating the Aggregator is ever captured, the
   community can take the commons and leave.

## 9. Parameter Registry

Every numeric constant in the suite, with its normative default. Changes
are made by `parameter_change` Registry Updates and MUST have
`effective_at` ≥ 7 days after the Block's `sealed_at` (the grace period
— itself a parameter, changeable only by the same process). The
**Identifier** column is the value `details.parameter` MUST carry
(schema: `schemas/registry-update.schema.json`, §9.1); a parameter with no
identifier is not independently amendable by `parameter_change`, for one of
three reasons. It is a fixed structural definition, like the reputation
resolution. It is changed by publishing a new artifact rather than a bare
number, as the decay table digest is (§6) — and with it the decay
constant the table was generated from, which no number can amend
without regenerating the bytes the digest pins. Or its value is meaningful only
against another parameter, which is the case for `coverage_failures_max`:
it counts **Blocks**, so at the default hourly cadence 24 Blocks is a
tolerance of about one day in thirty, and halving `block_cadence_seconds`
halves that tolerance in wall-clock terms without anyone amending this
number. The coupling is stated rather than removed, and it binds the
cadence: a `parameter_change` to `block_cadence_seconds` is also a change
to how much shirking §4 tolerates, and MUST be weighed as both.

**In force.** A `parameter_change` is in force at every instant T at or
after its `effective_at`, the endpoint included. The value of a
parameter in force at T is that of the amendment naming it with the
greatest `effective_at` ≤ T, or the Registry default where no such
amendment exists; where two amendments share that `effective_at`, the
one later in Log order (WIST-3 §3.3: ascending Block height, then Entry
index) prevails, being the Aggregator's later statement, and the other
is superseded from the moment the later one seals and is never in
force. Log order decides nothing else: two pending amendments for one
identifier take effect each at its own instant (WIST-3 §7), so the one
with the later `effective_at` prevails once that instant arrives even
when it was sealed first. The endpoint is inclusive because the grace
period lands exactly on the Block grid — `effective_at` seven days
after a `sealed_at` is itself a `sealed_at` — and WIST-3 §3.1 reads the
cadence "in force at the previous Block's `sealed_at`": a change
effective at that instant governs the next Block, rather than leaving
the Block sealed at `effective_at` under a value two readings could
place on either side.

**Every value the registry carries is an integer** in the unit its row
states, and `details.value` is typed `integer` for that reason (§9.1).
The suite computes reputation, sampling and similarity in integers end to
end (§4, §5, §6); a rational reaching `penalty_weight` would land in
§6.2's denominator and a rational reaching `sampling_slope` in §4's clamp,
which is the one way §6's "every input is an integer" could be falsified
from inside a conforming Log.

A `parameter_change` MUST NOT make a §7 severity band unreachable, and MUST
NOT set **any** parameter — those in the table below as much as any a later
revision adds — to a value that nullifies the mechanism implementing a §8
invariant, or the audit, due-process or availability guarantee this suite
states elsewhere. That is a rule about what a value does, not about which
parameters were foreseen when it was written: a rate of zero is not a low
rate but the absence of the mechanism, and a deadline of zero is not a
tight deadline but an unmeetable one. The schema enforces it wherever it
reduces to a fixed numeric bound; the table below publishes exactly those
bounds, and each is the point at which the mechanism named beside it stops
existing rather than a recommended setting.

| Parameter | Bound | What a value past it removes |
|---|---|---|
| `block_cadence_seconds` | ≥ 1 and ≤ 86 400 | a cadence of zero seals no Block, so nothing anchored to `sealed_at` — every window in this document — has a clock; above a day, "eligible for the next Block" is lawful staleness measured in weeks, and the read-side position sale §6.4's inclusion ceiling forbids returns through the cadence |
| `block_decompressed_cap_bytes` | ≥ 1024 | a Consumer MUST reject a frame declaring more than the cap without decompressing it (WIST-3 §6), so below the octets an empty Block occupies no Block can be applied at all — and WIST-3 §3.2 requires an Aggregator to be able to seal an empty Block as the chain's heartbeat |
| `extract_cap_bytes` | ≥ 2 | `JCS("")` is 2 octets, so below that even an empty `extract` exceeds the cap, every Payload fails WIST-1 §3.6's size check, and no content-bearing Delta can ever be sealed |
| `links_cap_bytes` | ≥ 21 | `JCS({"total":0,"urls":[]})` is 21 octets and `links` is REQUIRED (WIST-3 §6.1), so below that no conforming Payload exists and no content-bearing Delta can ever be sealed |
| `link_url_cap_bytes` | ≥ 14 | below the 14 octets of `JCS("https://a.b/")` — the serialization of the shortest Normalized URL (WIST-1 §2) — no link can ever be declared, which removes the link dimension while leaving its verdicts defined — §5's `link_inconsistent` would then rest on a set nobody can populate |
| `summary_cap_bytes` | ≥ 12 | `JCS({"title":""})` is 12 octets and `title` is REQUIRED (WIST-3 §6.1), so below that no conforming `summary` exists and no content-bearing Delta can ever be sealed |
| `feed_window` | ≥ 1 | a Feed that can hold no Delta ID leaves nothing discoverable to pull (WIST-2 §3.2) |
| `recovery_window_days` | ≥ 1 | a zero-length window contains no Block, so no ordinary rotation is ever superseded and the recovery key stops being the answer to a stolen signing key (WIST-1 §5.2, §8) |
| `sampling_floor` | ≥ 1 | at zero the clamp's own lower bound is zero, so a maximum-reputation domain is never selected at all (§4) |
| `sampling_ceiling` | ≥ 1 | at zero no Delta is ever selected by any Auditor, which voids every Audit Record before it is written and with it every confirmation, penalty and sanction — a more complete nullification than `confirm_auditors` = 1, which this section already forbids |
| `similarity_consistent` | ≥ 150 002 and ≤ 1 000 000 | below `similarity_variance_floor`'s own floor the `dynamic_variance` band is empty; above the micro-unit range no audit can ever be `consistent`, so `C` never grows and every domain stays Provisional for ever (§5, §6) |
| `similarity_variance_floor` | ≥ 150 001 and ≤ 300 000 | below, §7's severity-1 band is empty; above, a Confirmed Inconsistency between 300 000 and the new floor lands in no severity row at all (§5, §7) |
| `link_agreement_consistent` | ≥ 2 and ≤ 1 000 000 | at or below `link_variance_floor`'s own floor the `link_variance` band is empty; above the micro-unit range no audit of a page with links can ever be `consistent`, so `C` stops growing for every conforming Publisher (§5, §6) |
| `link_variance_floor` | ≥ 1 and ≤ 999 999 | at zero no declaration can ever be `link_inconsistent` and the dimension audits nothing; at the range's top the neutral band vanishes and every dynamic page's link churn becomes a finding (§5) |
| `shingle_size` | ≥ 1 | a shingle length of zero leaves both shingle sets empty and §5's quotient undefined |
| `min_observed_words` | ≥ 1 | at zero the mass guard admits the empty observed text, and §5's quotient is read against a page that said nothing (§5) |
| `extension_triggers_max` | ≥ 1 | at zero no `inconsistent` Record ever extends a selection set, and §4's extension rule — the only path to confirmation that does not wait on coincidence — is disabled entirely (§4, §5) |
| `contradictions_max` | ≥ 1 | at zero a single contradicted Record carries the whole divergence consequence — removal and 30 days of voided Records — though a transiently wrong page (a defacement reverted, an edge cache out of sync) can contradict an honest filer, which is why a threshold exists at all; a predicate firing on the first contradiction measures an event rather than the systematic divergence §4 derives, and makes filing `inconsistent` the risk the extension rule exists to remove (§4, §5) |
| `confirm_auditors` | ≥ 2 | one Auditor confirming itself is the whole of what §5's confirmation rule exists to prevent |
| `confirm_window_hours` | ≥ 1 | at zero a confirming Record must share its Block with the first, since `sealed_at` is strictly increasing (WIST-3 §3.1) |
| `coverage_deadline_hours` | ≥ 1 | at zero the duty is discharged only by a Record sealed in the audited Block itself, so every Auditor fails every Block (§4) |
| `age_norm_days` | ≥ 1 | zero is a division by zero in `base_u` (§6.1) |
| `decay_horizon_days` | ≥ 1 and ≤ 1825 | a horizon of zero expires every penalty after a single day; above the table's last index `decay(t)` has no entry to read for the days the horizon adds, and the table is normative as bytes (§6.1) |
| `penalty_weight` | ≥ 1 | at zero `penalty_n` leaves the formula entirely and no Confirmed Inconsistency costs anything (§6.2) |
| `c_cap` | ≥ 1 | at zero `C` is always zero, so no domain ever satisfies the `provisional_audits` gate and reputation is capped at the Provisional cap for ever (§6) |
| `appeal_window_days` | ≥ 1 | a window of zero days closes before the notice can be read, which is the whole of the due process levels 3 and 4 carry (§7) |
| `appeal_seal_days` | ≥ 1 | at zero the Aggregator must seal a received appeal in the Block that closes the window, so the state voids for reasons no Aggregator can avoid (§7) |
| `ruling_deadline_days` | ≥ 1 | at zero every level-3 and level-4 state voids at T, whatever the evidence (§7) |
| `param_grace_days` | ≥ 1 | at zero a parameter changes in the Block that announces it, and the notice period this very section rests on is gone |
| `payload_window_days` | ≥ 30 | below, a Mirror may drop what it dislikes and call the absence expiry (WIST-3 §6.1) |
| `unauditable_horizon_days` | ≥ 7 | below, whether a URL is excluded turns on publication scheduling rather than on its `robots.txt` (§5) |
| `mirror_retention_days` | ≥ 51 | below, an appellant cannot fetch the Records its own sanction rests on (WIST-3 §6) |
| `warc_retention_days` | ≥ 51 | below, the capture behind a confirming Record can lawfully be gone before the appeal that contests it can conclude (§5, §7) |
| `record_seal_blocks` | ≥ 1 | at zero the Aggregator must seal what it pulled in the Block of the pull itself, so every pull is a breach the instant it completes (§4) |
| `domain_block_entries_max` | ≥ 1 | at zero no domain can seal anything and the Log carries only governance (WIST-3 §3.2) |
| `max_inclusion_blocks` | ≥ 1 | at zero an eligible Delta must seal in its eligibility Block itself, a deadline no Aggregator can meet for a Delta accepted mid-Block (§6.4) |
| `ingest_budget_bytes_day` | ≥ 1 048 576 | below one MiB the §3.2 walk cannot fetch a single capped Payload with its Feed page, and every backfill starves (WIST-2 §5) |
| `audit_fetch_cap_bytes` | ≥ 65 536 | twice the largest `extract` a Publisher may commit to (WIST-1 §3.6); below it an honest page carrying a full-cap extract in marked-up HTML cannot be read, and the blocking-Record path (§5) turns that into exclusion from materialization — a `parameter_change` route to emptying the tiers without sanctioning anyone |
| `audit_redirect_max` | ≥ 1 | at zero no redirect is followed at all, so every URL served from a redirecting host is `unreachable` whatever it serves (§5) |
| `audit_fetch_timeout_seconds` | ≥ 1 | at zero every fetch expires before it can complete and every audit is `unreachable` (§5) |
| `url_cap_bytes` | ≥ 14 | `JCS("https://a.b/")` is 14 octets — the serialization of the shortest Normalized URL that can exist — so below it no Delta can name any subject at all (WIST-1 §2, §3.2) |

Where the rule does not reduce to a fixed bound — a value that is
individually in range but collapses a mechanism only in combination with
another parameter's current value — a party recomputing reputation MUST
reject the `parameter_change` directly against the rule rather than apply
it. The combinations the present table cannot express are named so that no
party has to discover them: `sampling_ceiling` MUST NOT be below
`sampling_floor`, or the level-1 sanction's intensified sampling is
indistinguishable from no sanction; `similarity_consistent` MUST be
greater than `similarity_variance_floor`, or the `dynamic_variance` band
is empty; `c_cap` MUST NOT be below `provisional_audits`, or no domain can
leave Provisional; `confirm_window_hours` and `coverage_deadline_hours`
MUST NOT be shorter than `block_cadence_seconds`, or a duty falls due
before the Block that could discharge it can be sealed — and
`confirm_window_hours / 2` (integer division), the extension duty's own
span (§4), MUST NOT be shorter than `block_cadence_seconds` either, or a
re-audit can never seal inside the window it exists to serve, and MUST
NOT be longer than `coverage_deadline_hours`, or an Auditor's path for
*B₁* is pulled before the extension duty *B₁* carries falls due;
`block_decompressed_cap_bytes` MUST NOT be below the size of the largest
Block the Aggregator seals, since only the pair decides whether any Block
is applicable; and the `mirror_retention_days` sum below. `links_cap_bytes`
MUST NOT be below `link_url_cap_bytes` + 21, the structural octets of
`JCS({"total":1,"urls":[…]})` around a single maximum-length URL literal —
below it a page whose first link is long declares an empty prefix the
budget rule then makes mandatory. `link_variance_floor` MUST be below
`link_agreement_consistent`, or the two link bands overlap and one audit
fits two verdicts. `contradictions_max` MUST be below
`extension_triggers_max`: only an extension-triggering Record can be
contradicted and the ration admits at most `extension_triggers_max` of
them into any 30-day window (§4), so at or above it the divergence
predicate is one no history can satisfy and §4's answer to a lying
Auditor stops existing. `audit_domain_budget_bytes_day` MUST NOT be below
`audit_fetch_cap_bytes` + `extract_cap_bytes` + `links_cap_bytes` +
`summary_cap_bytes` + 32 — the audited URL under its own cap plus the
largest Payload WIST-1 §3.6 permits, which are the two fetches one audit
makes (§5) — or the day's budget cannot cover a single audit of the domain
and every Delta it publishes is `not_auditable` on arrival — which the
blocking-Record rule then reads as a page nobody can measure rather than
as a budget nobody could meet.

Every remaining identifier carries no bound because none reduces to one,
and each is named here so that "exactly those bounds" above is a claim a
reader can check rather than take. `escalation_l2`, `escalation_l3` and
`escalation_l4` publish compound criteria rather than single numbers, so
§7's criteria and not an integer are what a party checks them against.
`clock_skew_seconds`, `keyset_cache_ttl_seconds` and `baseline_poll_seconds`
set tolerances rather than mechanisms: at zero each is the strict reading
of the rule it relaxes, and nothing ceases to exist. `sampling_slope` at
zero stops the audit rate varying with reputation, while selection,
confirmation, penalties and the level-1 rate all still run.
`provisional_age_days`, `provisional_audits` and `provisional_cap_u` loosen
or tighten a gate on reputation rather than removing one — unlike `c_cap`,
whose zero leaves that gate unsatisfiable for every domain for ever.
`quota_base` and `quota_slope` at zero silence the Ping path, which WIST-2
§5's baseline polling exists to survive. And `latency_threshold_u` at
either extreme puts every domain on one side of a one-Block delay, which is
a policy rather than the absence of one.

`payload_window_days` carries a floor for the same reason. The window is
what makes a missing Payload evidence (WIST-3 §6.1): shortened toward zero
it would leave a Mirror free to drop whatever it disliked and call the
absence ordinary expiry, retiring the distinction between erasure and
censorship without amending anything. The floor is set well above the
72-hour coverage deadline and above any plausible Mirror resynchronisation
lag, so that absence inside the window remains attributable rather than
routine.

`unauditable_horizon_days` carries one because the horizon it sets is the
window inside which exclusions and the audits that clear them have to meet.
The floor is set well above the 72-hour coverage deadline (§4): in a window
shorter than the interval within which Auditors are even obliged to
publish, whether a URL is excluded would turn on publication scheduling
rather than on what its `robots.txt` does — two exclusions and a clearing
audit need room to land inside the same window.

`mirror_retention_days` carries one because the retention it sets is what
makes an evidence bundle assemblable after the fact (WIST-3 §6), and the
proceedings that need one run on this suite's own clocks. An appeal opens
within `appeal_window_days` of the `notice`'s Block, MUST be sealed within
`appeal_seal_days` of that window closing, and MUST be ruled on within
`ruling_deadline_days` of the Block sealing it, so at present defaults 51
days is the
longest span the process itself guarantees between the sanction complained
of and the ruling on it. A Mirror free to drop a Block sooner could leave an
appellant unable to fetch the Audit Records its own sanction rests on, which
would decide an appeal on retention policy rather than on evidence; the floor
is therefore set at exactly that span, so the schema's number and the
deadlines it protects have the same derivation rather than merely the same
order of magnitude. The floor is a floor, not a target: the default is 90
days, and the sum is the point below which the process stops working at all.

Because that sum is of three amendable parameters, the schema can pin the
constant but not the combination. A `parameter_change` raising
`appeal_window_days`, `appeal_seal_days` or `ruling_deadline_days` MUST NOT
leave `mirror_retention_days` below their sum, and a party replaying the Log
MUST reject one that does directly against this sentence, exactly as for the
combination cases above.

| Parameter | Identifier | Default | Defined in |
|---|---|---|---|
| Block sealing cadence | `block_cadence_seconds` | 1 hour | WIST-3 §3.2 |
| Block decompressed size cap | `block_decompressed_cap_bytes` | 256 MiB | WIST-3 §6 |
| `extract` size cap | `extract_cap_bytes` | 32768 octets of `JCS(extract)` | WIST-1 §3.6 |
| `links` size cap | `links_cap_bytes` | 4096 octets of `JCS(links)` | WIST-1 §3.6 |
| Link `url` size cap | `link_url_cap_bytes` | 2048 octets of `JCS(url)` per link | WIST-1 §3.6 |
| `summary` size cap | `summary_cap_bytes` | 2048 octets of `JCS(summary)` | WIST-1 §3.6 |
| `url` size cap | `url_cap_bytes` | 2048 octets of `JCS(url)` | WIST-1 §3.2 |
| Payload availability window | `payload_window_days` | 180 days | WIST-3 §6.1 |
| Mirror Block retention floor | `mirror_retention_days` | 90 days | WIST-3 §6 |
| WARC retention floor (`inconsistent` / `link_inconsistent` Records) | `warc_retention_days` | 90 days | §5 |
| Pull sealing deadline | `record_seal_blocks` | 24 Blocks | §4 |
| Per-domain Block capacity | `domain_block_entries_max` | 10 000 Entries | WIST-3 §3.2 |
| Inclusion ceiling | `max_inclusion_blocks` | 4 Blocks | §6.4 |
| Per-domain daily ingest budget | `ingest_budget_bytes_day` | 1 GiB | WIST-2 §5 |
| Feed window | `feed_window` | 1000 IDs | WIST-2 §3.2 |
| Clock skew allowance | `clock_skew_seconds` | 10 minutes | WIST-1 §3.4 |
| Key Set cache TTL | `keyset_cache_ttl_seconds` | 24 hours | WIST-1 §5.1 |
| Baseline feed poll interval | `baseline_poll_seconds` | 24 hours | WIST-2 §5 |
| Sampling floor / ceiling (`p_1e7`) | `sampling_floor` / `sampling_ceiling` | 200 000 / 5 000 000 (reads as 0.02 / 0.50) | §4 |
| Sampling reputation slope | `sampling_slope` | 3 per micro-unit of reputation (reads as 0.30) | §4 |
| Coverage duty deadline | `coverage_deadline_hours` | 72 hours | §4 |
| Audit fetch body cap (per audited URL) | `audit_fetch_cap_bytes` | 8 MiB | §5 |
| Audit fetch budget (per Auditor per domain per UTC day) | `audit_domain_budget_bytes_day` | 1 GiB | §5 |
| Audit fetch redirect ceiling | `audit_redirect_max` | 5 | §5 |
| Audit fetch timeout | `audit_fetch_timeout_seconds` | 30 seconds | §5 |
| `coverage_failures_max` | — | 24 Blocks per 30 days | §4 |
| Similarity thresholds (consistent / variance floor) | `similarity_consistent` / `similarity_variance_floor` | 600 000 / 300 000 micro-units (reads as 0.60 / 0.30) | §5 |
| Link agreement thresholds (consistent / variance floor) | `link_agreement_consistent` / `link_variance_floor` | 600 000 / 300 000 micro-units (reads as 0.60 / 0.30) | §5 |
| Shingle size | `shingle_size` | 8 (words, or grapheme clusters on §5's short-text branch) | §5 |
| Observed-text mass guard | `min_observed_words` | 40 words | §5 |
| Extension ration (per Auditor per 30 days) | `extension_triggers_max` | 3 | §4 |
| Divergence threshold (per Auditor per 30 days) | `contradictions_max` | 2 | §4 |
| Unauditable horizon | `unauditable_horizon_days` | 30 days | §5 |
| Confirmation: auditors / window | `confirm_auditors` / `confirm_window_hours` | 2 / 72 hours | §5 |
| Age normalization | `age_norm_days` | 730 days | §6 |
| Reputation base at age 0 | — | 100 000 micro-units (= the Provisional cap) | §6 |
| Penalty decay constant (1/e) | — | 180 days (the true half-life is 180·ln2 ≈ 124.8 days; fixed by the table's bytes) | §6 |
| Decay table horizon | `decay_horizon_days` | 1825 days | §6 |
| Decay table digest (SHA-256) | — | `1ef9e9be…959986b9` | §6 |
| Distinct-URL cap `C_cap` | `c_cap` | 500 | §6 |
| Reputation resolution | — | 1e-6 (micro-units) | §6 |
| Penalty weight | `penalty_weight` | 5 | §6 |
| Provisional gates (age / distinct audited URLs) | `provisional_age_days` / `provisional_audits` | 30 days / 10 | §6 |
| Provisional reputation cap (ceiling, not floor) | `provisional_cap_u` | 0.10 = 100 000 micro-units | §6 |
| Ping quota base / slope | `quota_base` / `quota_slope` | 100 / 10000 per day | §6 |
| Inclusion latency threshold | `latency_threshold_u` | reputation 0.5 = 500 000 micro-units | §6 |
| Escalation: level 2 / level 3 / level 4 | `escalation_l2` / `escalation_l3` / `escalation_l4` | 3 in 90 days / 10 in 90 days or severity 3 / 3 severity-3 in 180 days or a level-3 domain's next Confirmed Inconsistency | §7 |
| Appeal window | `appeal_window_days` | 14 days | §7 |
| Appeal sealing deadline | `appeal_seal_days` | 7 days | §7 |
| Appeal ruling deadline | `ruling_deadline_days` | 30 days | §7 |
| Recovery window | `recovery_window_days` | 7 days | WIST-1 §5.2 |
| Parameter change grace period | `param_grace_days` | 7 days | §9 |

### 9.1. Registry Update `details` Contract

`schemas/registry-update.schema.json` constrains `details` per `action`,
mirroring §7 and §3:

- `aggregator_key_add`, `auditor_admit`: `key_id`, `alg` (`"Ed25519"`), and
  `public_key` (the raw Ed25519 public key, 43-character base64url). An
  `auditor_admit`'s `subject` additionally MUST be the Auditor's
  `auditor_id`, a hostname of at least two labels, because §3 anchors an
  Auditor to a domain and a Record's `auditor_id` is what §3's independence
  and self-audit tests compare.
- `aggregator_key_remove`, `auditor_remove`: `key_id`. An
  `auditor_remove`'s `evidence` (top-level), where present, MUST name at
  least one ID: its presence is what makes the removal for cause (§4),
  and an empty array would be a removal that is neither for cause nor an
  exit.
- `sanction`: `level` (1–4) and `severity` (1–3, §7); `evidence`
  (top-level, not `details`) MUST carry at least the two Audit Record IDs
  (§5) of the concurring, independent Auditors' Records that establish
  the Confirmed Inconsistency (§5's own minimum).
- `notice`: `kind` (`"sanction"` or `"recovery"`); a `"sanction"` notice
  additionally requires `reason`, `appeal_deadline`, and a top-level
  `evidence` naming what the notice is about; a `"recovery"` notice
  requires nothing further (WIST-1 §5.2). `appeal_deadline` restates the
  instant §7 derives — the `sealed_at` of the Block sealing this notice
  plus `appeal_window_days` — and carries the whole-second-plus-`Z` form
  `sealed_at` carries, so the restatement and the value it is computed
  from compare without normalization. It is descriptive: where it and the
  Block disagree, §7's derivation governs.
- `appeal`: `notice`, the Registry Update ID (§7) of the `notice` being
  appealed. REQUIRED, because §7's sealing deadline and void rule are
  evaluated per notice: an appeal naming none would attach to every open
  process of that domain or to none of them.
- `appeal_ruling`: `notice` (the Registry Update ID of the `notice` this
  ruling closes), `outcome` (`"upheld"`, `"overturned"`, or
  `"unappealed"` — the last recording that the appeal window closed with
  no appeal served, §7) and `reasoning`.
- `parameter_change`: `parameter`, one of the Identifier values in the
  table above, and `value` — an **integer** in that parameter's own unit,
  bounded by the table of bounds above where a fixed bound exists;
  `effective_at` MUST be ≥ 7 days
  after the Block's `sealed_at`, as stated above.
- `payload_withdrawal`: `delta_id` (the Delta whose Payload is being
  withdrawn), `legal_basis`, and `jurisdiction` (WIST-3 §6.2); `subject` is
  the Publisher's domain. All three are REQUIRED, because a withdrawal
  that named no Delta, no basis, or no demanding jurisdiction would be an
  unfalsifiable claim to have removed something — which is precisely what
  a quiet drop looks like.
- `pull_attestation`: `block` (the audited Block's Block Hash) and
  `found` (the IDs the §4 pull returned, an array, empty where the fetch
  found nothing to seal); `subject` is the Auditor's `auditor_id`. Both
  are REQUIRED, because the attestation exists to be the signed statement
  a coverage failure is derived against (§4), and an attestation naming
  no Block or no result set would attest to nothing a replayer could
  hold the Aggregator to.

- `coverage_attestation`: `block` (the audited Block's Block Hash, the
  same value that names the Auditor's well-known records file, §4),
  `vrf_proof` (the §4 VRF Proof for that Block, 80 octets as 160 lowercase
  hex characters) and `prev_record` (§4), the same Auditor's preceding
  publication or `null`; `subject` is the Auditor's `auditor_id`. All three
  are REQUIRED, because the attestation exists to put the proof of an empty
  selection in the Log where the coverage duty is derived from it (§4): one
  carrying no proof attests to nothing a replayer could check, and one
  naming no Block leaves the proof with no input to verify against.

`sanction_lift` carries an unconstrained `details` object, and an
`appeal`'s is unconstrained beyond the `notice` it MUST name; every Audit
Record carries `prev_record` (§4), the same Auditor's preceding
publication or `null`.
§4 and §7 govern the rest of their content in prose, not the schema.
The same is true of any action a future major revision adds.

No `details` object, constrained or not, may carry a bare digest of
Payload content. A content-derived value anywhere in this suite is
committed under the Payload salt (§5, WIST-1 §3.6) or it is not carried at
all (WIST-3 §6.2). An unconstrained `details` is unconstrained in shape, not
licensed to reintroduce the confirmability the salt exists to destroy, and
a party replaying the Log MUST reject a Registry Update that carries one.

**No `details` object, constrained or not, and no `evidence` element, may
carry personal data.** The rule is written over the position rather than
over a list of field names, because the position is what makes it
necessary: everything a Registry Update carries is sealed, permanent, and
outside the withdrawal mechanism entirely (WIST-3 §6.2), so any of it recited
once is recited for ever. It binds whoever writes the value, not only the
Aggregator — a `payload_withdrawal`'s `legal_basis`, a `notice`'s
`reason`, an `appeal_ruling`'s `reasoning` and a `sanction_lift`'s
`details` are the Aggregator's, and an `appeal`'s `details` are the
Publisher's, written by the party with the strongest reason to recite a
data subject's circumstances and the least reason to have read this
paragraph. A
`legal_basis` names a legal ground, not the person invoking it; a `reason`,
a `reasoning` and an appeal's grounds name their evidence by Audit Record
ID (§5) or Registry Update ID (§7) rather than reciting what was found.
Nothing in this suite requires identifying a data subject in order to
record why an action was taken or contested (§12).

## 10. Error Registry

WIST-1, WIST-2 and WIST-3 register the codes their surfaces reject
with; this section registers WIST-4's. These are replay-side codes: the
conditions are evaluated by any party replaying the Log (§3, §5, §7,
§9), not by a Publisher-facing surface, so unlike WIST-1/WIST-2 codes
they carry no status-endpoint duty. One rule spans the table: rejection
under this registry rejects the *item* — the Record or Registry Update
is ignored during replay, contributing to nothing — and never
invalidates the containing Block. Block validity is exclusively
WIST-3 §3's; a registry that let one bad Entry void a sealed Block
would hand any Auditor a veto over every other Entry sealed beside it.

| Code | Meaning and required behavior |
|---------|--------------------------------------------------------------|
| WIST4-E01 | Audit Record void for standing: signed by a key not admitted at (or removed at or before) its Block's `sealed_at`; a `vrf_proof` that gives no standing — one verifying over neither the audited Block with `audited_delta` in its selection set nor a Block *B₁* at which §4's extension rule names `audited_delta` for the Auditor; a Delta outside its Block's selection domain (§4); a self-audit (§3); or an Auditor in coverage failure at sealing (§3). Ignored in replay: no reputation input, no Confirmed Inconsistency. Coverage reads it by the §3 carve-out: a Record void only because its key was removed after the `sealed_at` of the Block its duty is anchored to — the audited Block for a VRF selection, *B₁* for an extension (§4) — or because its Auditor is in coverage failure at sealing, still discharges the §4 duty anchored there; in every other case there was no duty to discharge — a key never admitted at that Block, a proof binding the Record to no Block that selected or named `audited_delta` for it, a Delta outside the selection domain, a self-audit — and the Record discharges nothing, whatever else is also true of it. |
| WIST4-E02 | Audit Record malformed as evidence: `fetched_at` outside §3's closed interval; a `reference_delta` outside the audited Delta's chain, before `audited_delta` in it, or sealed after `fetched_at` (§3); `similarity` or `link_agreement` failing §5's condition for its own verdict; a `link_agreement` carried where §5 makes the link dimension neutral. Ignored in replay as a WIST4-E01 Record is: no reputation input, no Confirmed Inconsistency. It discharges the §4 duty it answers (§3): the Auditor held standing, fetched and published, and the defect is in the Record as evidence, not in the duty's discharge. |
| WIST4-E03 | Registry Update rejected under §9: a `parameter_change` naming an identifier §9 does not list, a value outside its §9 bound, or an amendment §8's Invariants or §9's unamendable rows forbid. Ignored during replay; the Registry value in force is unchanged. |
| WIST4-E04 | Registry Update `details` contract violation (§9.1): a REQUIRED `details` or `evidence` member missing or malformed for its `action`, a bare content digest, or personal data. Ignored as WIST4-E03. |
| WIST4-E05 | Governance act contradicting its own evidence: a `sanction` whose `details.severity` disagrees with the §7 derivation from the evidence it names, or a `sanction`/`sanction_lift` whose named evidence does not establish it. Ignored; §7's derived ladder governs regardless. |
| WIST4-E06 | Recomputation divergence: a published reputation, sampling rate, quota, or sanction state that does not equal the replayer's own §4–§7 recomputation. Not an Entry rejection — a falsified-index signal: the value MUST NOT be trusted, and the divergence SHOULD be published with the `log_position` it was computed at, since anyone replaying the Log can check the report. |
| WIST4-E07 | Roster act rejected (§3, §4): an `auditor_admit` naming a retired `key_id`, a `subject` barred by a removal for cause, a `subject` holding a key not removed at or before the admit's Block, a `subject` a second `auditor_admit` in the same Block also names (both rejected), or an `auditor_id` failing §3's independence test against `log_id`; or an `auditor_remove` naming a key its `subject` does not hold. Ignored during replay; the roster is unchanged, and no Record signed under a key the rejected act named counts. |

## 11. Security Considerations

- **Audit selection is unforgeable and unsteerable.** Who audits what is
  fixed by each Auditor's own VRF over the Block Hash (§4), so no party
  chooses it. Two of the three inputs the Aggregator once chose freely
  are now pinned — `sealed_at` to the cadence grid, Entry order to
  canonical order (WIST-3 §3.1, §3.3) — leaving Block membership as its one
  grinding dimension, bounded by the cadence: one candidate hash per
  deferral, hours apart, in a Log where deferral itself is bounded by
  §6.4's inclusion ceiling. And the direction of any grind is blind: the
  Aggregator holds no Auditor key, so a changed Block Hash moves every
  Auditor's selection at once and in no direction it can predict, and
  the sub-two-trial steer that a single log-wide draw permitted no longer
  exists. The Auditor cannot steer its own draw either, because `beta` is
  uniquely determined by its key and the Block. Auditing *outside* the VRF
  set is detectable by anyone: the published `pi` recomputes the set, §4's
  extension rule is the one further path in and every input to it is
  sealed, and a Record for a Delta outside both is void (§3) and is
  evidence for `auditor_remove`. Confirmation requires *independent*
  Auditors and does not wait on coincidence: the extension rule summons
  every independent Auditor to the first `inconsistent` Record, so a
  fraudulent Delta's chance of escaping confirmation is the chance of
  escaping the whole roster, not of escaping a second simultaneous VRF
  draw; systematic divergence by one Auditor remains grounds for
  `auditor_remove`, in the log with evidence like any sanction.
- **Shirking is detectable from the Log alone, whole or partial.** For every
  Block sealed in an Auditor's admitted window the Log must hold that
  Auditor's `vrf_proof` — inside an Audit Record for each selected Delta,
  or inside a `coverage_attestation` where the VRF selected nothing (§4).
  An Auditor that audits nothing and attests nothing is therefore not merely
  suspected but demonstrated, by any party replaying the Log, with no
  challenge protocol, no side channel, and no cooperation from the Auditor
  — demonstrated, that is, once the Aggregator's `pull_attestation` for the
  pair is sealed, which §4 requires before any failure counts: absence
  alone is never evidence against the Auditor, because absence is exactly
  what suppression would manufacture, and the `prev_record` chain turns
  any selectively suppressed item into proof of its own existence.
  Since the proof is published either way, an Auditor cannot hide behind "my
  VRF selected nothing": that claim is a signed, falsifiable statement whose
  proof anyone can check against the Block Hash. Nor can it shirk *part* of
  a Block and buy silence with a single Record: the proof it publishes in
  that Record recomputes the whole selection set, so covering some selected
  Deltas and not others is a failure for the Block, not partial credit (§4).
- **Reputation gaming via attest-farming.** A domain cannot inflate `C`
  by emitting torrents of trivially-true `attest` Deltas: a Record whose
  reference Delta is an `attest` or a `delete` never contributes to `C`,
  whatever Delta it audited (§6.1). Nor can it inflate `C` by
  re-publishing the same URL: `C` counts *distinct* Normalized URLs with
  a `consistent` audit, capped at 500, so the only way to dilute a
  penalty is to publish, and keep passing audits on, many different
  pages — exactly the thing that is expensive to fake at scale.
- **Domain resale.** Reputation attaches to key continuity, not the name.
  A Declaration signed by neither the previous Key Set nor the previous
  `recovery_keys` is a fresh identity: `A` and `C` reset and the domain
  re-enters Provisional (§6.3, WIST-1 §5.2). Buying an aged domain, or its
  hosting, buys no standing. An ordinary rotation and a recovery rotation
  both preserve standing, because both prove possession of a key the prior
  identity chose in advance — recovery keys exist precisely so that losing
  a signing key does not force a Publisher to forfeit its history, and a
  thief holding only a signing key cannot outrun them (WIST-1 §5.2).
- **Floating-point divergence in reputation.** Reputation decides audit
  selection, quota, and inclusion latency through strict comparisons, so
  two implementations differing by one unit in the last place would
  disagree about which Deltas were required to be audited. §6 removes the
  possibility rather than tolerating it: every quantity is an integer,
  `exp()` is replaced by a published table, and division order and
  rounding are pinned. There is no conforming path that uses `double`.
- **Sanction censorship, and why equivocation is not the answer to it.**
  Omission is not equivocation. An Aggregator that seals a Block without an
  entry it should have sealed produces one chain, consistent with itself,
  which every observer sees identically — WIST-3 §5's proof needs two
  Checkpoints with one `block_number` and two `block_hash`es, and uniform
  omission produces neither. Nothing about suppression is detectable that
  way, and this document does not rest on the claim that it is. What
  bounds it is that the consequences of the entries an Aggregator would
  want to suppress do not depend on the entries. A `sanction` it never
  files leaves the penalty in place, because §6.1 computes `penalty_n` from
  the Audit Records (§7). A ladder rung it never records is in force on
  recomputation from the height the criteria were met (§7). A `notice` it
  never seals opens no window, and the Publisher's remedy there is the
  evidence rather than an appeal (§7). And an `appeal` it never seals
  voids the sanction's state at T unless it also seals an `"unappealed"`
  ruling, which the Publisher's own served appeal falsifies (§7). Each is
  a derivation the Aggregator cannot reach, not a detection it cannot
  evade.
- **A sanction's severity can be neither fabricated nor suppressed.**
  Severity is derived from the confirming Audit Records' **effective
  similarity** values (§5) by the §7 table — the sealed `similarity` read
  directly, or mirrored where the reference Delta is a `delete` — not
  asserted by the Aggregator, and §6.1 counts every Confirmed
  Inconsistency's and Confirmed Link Inconsistency's penalty from its
  confirming Block onward regardless of whether a `sanction` Registry
  Update ever names it. A party recomputing reputation therefore arrives
  at the same `penalty_n` whether the Aggregator inflates a
  `details.severity` past what the Records show (the mismatched
  `sanction` is rejected and the table's value used instead), invents a
  `sanction` with no real evidence behind it (rejected outright — §5's
  predicate fails), or never records one at all (the penalty applies
  anyway, computed directly from the Records). A captured Aggregator has
  no lever over the reputation consequence of evidence that is already
  public.
- **Griefing via false `inconsistent` verdicts.** A single hostile Auditor
  confirms nothing by itself: a Confirmed Inconsistency requires a second
  `inconsistent` from an Auditor independent of it under §3's suffix test,
  inside 72 hours measured on Block `sealed_at`, and the sampling rule (§4)
  makes it verifiable that each had the right to audit at all. An Auditor
  also cannot reach a domain it is too close to: §3 puts every Publisher
  domain sharing a two-label suffix with its own `auditor_id` beyond its
  audits, and a Record breaching that is rejected on recomputation rather
  than argued about. Two hostile Auditors under one operator are a
  different case, and the bullet below is what this document has to say
  about it.
- **Griefing via false `robots_excluded` verdicts.** The other verdict that
  carries a consequence is `robots_excluded`, and its consequence —
  exclusion from materialization — arrives with no notice, no appeal and no
  Aggregator action, which is level 4's effect without level 4's process.
  It is an unverifiable claim by construction: only the Auditor fetched the
  file, and a `robots.txt` that has since changed leaves nothing anyone can
  recompute. Three things bound it, and the first is the reason the rule is
  written the way it is. Two Auditors independent of each other are needed
  to arm the horizon, the same floor a Confirmed Inconsistency carries, so
  no single Auditor imposes it. The exclusion is not permanent: it lifts on
  a successful audit by an Auditor independent of both, and it ages out
  when the exclusions leave the horizon window. And no reputation
  consequence follows at all, so a false claim costs the Publisher
  visibility for a bounded period rather than standing — while
  contradiction by an independent Auditor's successful fetch of the same
  URL is exactly the evidence `auditor_remove` runs on.
- **Auditor independence is an admission-time trust assumption, and this
  document does not claim otherwise.** `auditor_admit` is signed by the
  Aggregator alone. An Aggregator holding two Auditor keys, admitted under
  hostnames that share no two-label suffix and each publishing a matching
  Declaration, satisfies §5's confirmation requirement literally while
  being one party — and can seal a Confirmed Inconsistency out of two
  substantively false Records that every schema and every recomputation
  accepts. Nothing downstream repairs that: §6.1 counts the penalty from
  the confirming Block whether or not a `sanction` is ever filed, and an
  appeal reaches the sanction's state, never `penalty_n`. Four things bound
  the exposure and none removes it. Selection is VRF-derived (§4), so both
  keys must have *selected* the same Delta: reaching a chosen one means
  grinding Block membership and ordering until they do, which costs
  re-sealing work rather than being impossible. Every Record names a
  domain-anchored identity (§3), so a fabrication has a public author with
  a published Key Set rather than an opaque key. While the Reference
  Payload is served, anyone holding the page — the audited Publisher above
  all — can obtain the salt, demand the Auditor's capture, and show the
  commitments do not reproduce (§5); after withdrawal nobody can, in either
  direction. And an Aggregator shown to be doing this is an institution the
  commons can leave: the Log is public, the tier data is ODbL, and §8's
  invariant 4 makes the fork the remedy rather than an appeal to the party
  that admitted the Auditors. A deployment that needs more than that MUST
  obtain it outside this protocol — by admitting Auditors it did not
  choose, or by operating no Auditor keys at all — because nothing inside
  the protocol distinguishes an Aggregator's second Auditor from a
  stranger's.
- **The independence test is also a suppression lever.** It cuts both ways,
  and the second edge is the quieter one. Because confirmation requires two
  Auditors that share no two-label suffix, an Aggregator that admits eight
  Auditors all under one suffix has published a roster that looks healthy
  by every visible measure — eight keys, eight Declarations, full coverage
  attestations, `inconsistent` verdicts appearing in the Log — inside which
  no Confirmed Inconsistency can ever form, and therefore no penalty and no
  sanction. Nothing about that is detectable as misconduct, because each
  admission is individually unimpeachable and the rule suppressing the
  confirmations is this document's own. It is deniable by construction: the
  same configuration arises by accident wherever candidate Auditors cluster
  under one public suffix (§3). What a party replaying the Log can do is
  compute the roster's independent suffixes directly, which is why §3 makes
  that count, and not the key count, the measure of whether confirmation is
  possible — a roster of one suffix is a Log-visible fact, and one that any
  Consumer choosing which Log to follow can weigh.
- **Roster size is a security parameter, and audit effort does not shard.**
  Selection is per-Auditor over every Delta (§4), so each admitted Auditor
  draws its own share of the whole Log and no Auditor's work is any other's
  relief: a roster of N costs N times one Auditor's fetch volume and buys
  coverage rather than division of labour. That is deliberate — a scheme
  that partitioned Deltas between Auditors would have to make the partition
  derivable, and a derivable partition tells a Publisher which Auditors can
  ever see it, which is the collusion surface §4's unpredictability exists
  to remove — but it fixes what N buys, and the figures are worth stating
  because the roster is the one variable an Aggregator controls and a
  Consumer can inspect. At the `sampling_floor` rate a mature domain
  enjoys, one altered URL is selected by at least one Auditor with
  probability 1 − (1 − 0.02)^N: about 10 % at N = 5, 33 % at N = 20, 64 %
  at N = 50. Confirmation does not then need a second coincidence, because
  the extension rule summons every independent Auditor to the first
  `inconsistent` Record — so for a campaign small enough to stay inside
  `extension_triggers_max`, detection of the campaign is detection of any
  one of its URLs: five altered URLs are caught 40 % of the time by a
  five-Auditor roster, twenty-five of them 92 % of the time. A campaign
  large enough to ration the extension rule out falls back to needing two
  independent draws on the same Delta — 0.38 % per URL at N = 5 — but it
  arrives there having already been confirmed `extension_triggers_max`
  times per triggering Auditor, and the ladder it walked into raises its
  sampling rate to `sampling_ceiling`, twenty-five times the floor, for
  everything it publishes next. The property the suite offers is therefore
  bounded undetected fraud rather than none: small-scale alteration by a
  high-reputation domain can go unaudited, sustained alteration cannot, and
  N is what sets where the boundary falls.

## 12. Privacy Considerations

Audit Records expose fetch timing and, via `evidence_commitment`, WARC
captures of public pages; the WIST-1 §9 rule (nothing beyond what the page
itself publishes) applies to evidence exactly as to extracts. Appeals and
rulings are public and permanent: the `notice` that opens a sanction
window MUST state this, so a Publisher weighs publicity before appealing.
Reputation scores are recomputable by anyone from public data; there is
no private reputation channel.

An Audit Record is the one object in the suite that observes page content
directly, so it is the one that would otherwise carry the residue of a
withdrawal in a sealed, permanent form. It does not, because none of its
content-derived values is a bare digest: the response, the Auditor's own
extraction and the WARC capture are all committed under the audited
Payload's salt (§5). A party holding a candidate copy of a withdrawn text
therefore cannot confirm it against an Audit Record any more than against
the Delta — the key that would let it is gone, and it is the same key in
both cases.

Two things do survive a withdrawal in the Log, and they are named here
rather than glossed. The `verdict` and `similarity` are derived from the
content. Against a party holding only a candidate text neither is
confirming: `similarity` scores an audit against a reference that party
cannot reconstruct. Against a party that also holds the Auditor's
reference extraction or its capture, `similarity` is recomputable and can
be matched against the sealed integer exactly — what stands between that
party and the content is the destroy obligation of WIST-3 §6.2, a duty on a
named holder rather than a property of the format. Both values survive
deliberately, because reputation is a pure function of Log history (§6)
and must remain recomputable after a withdrawal that the audited domain
did not control.

A third residue is everything a Registry Update carries. Its `details` and
its `evidence` are sealed in the Log, permanent, and outside the withdrawal
mechanism entirely — the same class as a Delta's `meta` (WIST-1 §3.7) — and
§9.1 therefore forbids personal data in any of it, whether the schema
constrains that field or leaves it open, and whoever writes it. The
enumeration matters less than the position, but the positions are worth
naming: the Aggregator writes a `payload_withdrawal`'s `legal_basis`, a
`notice`'s `reason`, an `appeal_ruling`'s `reasoning` and a
`sanction_lift`'s `details`; the Publisher writes an `appeal`'s
`details`, and an appeal is the one place in this suite where a party is
contesting a finding about itself and is most likely to recite a
person's circumstances in doing so.
A `legal_basis` names a legal ground, not the person invoking it; a
`reason`, a `reasoning` and an appeal's grounds name their evidence by
Audit Record ID (§5) or Registry Update ID (§7) rather than reciting what
was found. Nothing in this suite requires identifying a data subject in
order to record why an action was taken or contested, and doing so would
seal into the Log precisely the data an erasure is meant to remove.

The Auditor's WARC capture is a full copy of the fetched exchange — the
request, the response headers, and the response body whose bytes
`response_commitment` covers, never subresources the audit did not fetch —
and it is held
off-Log. WIST-3 §6.2 requires the Auditor to destroy it, along with the
Payload and its salt, when the Payload is withdrawn. That is an obligation
on the Auditor, enforceable the way the Aggregator's and the Mirrors' are
and no further: an Auditor that defies it retains both the capture and the
salt, and could then confirm a candidate text. The protocol makes that a
violation with a named holder rather than a structural inevitability,
which is the most a specification can do about a copy in someone else's
hands.

## 13. Conformance Checklist

**Auditor:**

- [ ] Audits exactly its VRF-selected set, drawn over the Block's selection
      domain, and publishes `vrf_proof` (§4)
- [ ] Meets the coverage duty for every Block sealed while admitted, within
      72 hours of `sealed_at` — a Record for **every** selected Delta, or a
      `coverage_attestation` when its VRF selected nothing (§4)
- [ ] Names as `reference_delta` the newest Delta of the URL's chain sealed
      at or before its fetch, resolves the Reference Payload as of it, and
      verifies that Payload against its own Delta's commitment before
      comparing anything (§5)
- [ ] Serves a Declaration at its own `auditor_id` carrying the admitted
      key, writes that same hostname — the one its `auditor_admit` names —
      in every Record, and never audits a Delta from a Publisher domain
      sharing a two-label suffix with it (§3)
- [ ] Computes similarity with the normative §5 metric — the WIST-2 §12
      observed text, NFC, default full case-folding, untailored UAX #29
      segmentation, reference-containment quotient, mass guard — and
      reads the verdict from the effective similarity, mirrored for a
      `delete` (§5, WIST-2 §12)
- [ ] Applies WIST-2 §11's extraction procedure, unchanged, to its own
      fetch of the Reference Payload's page when checking the declared
      `links` member (§5, WIST-2 §11)
- [ ] Computes `link_agreement` and seals the field on the Record
      whenever the link dimension applies — a reference Delta whose
      change type is `new`, `update` or `attest`, an HTML representation
      (WIST-2 §11), and a measured verdict, never on an `unreachable` or
      `not_auditable` Record — and reads `link_variance` or
      `link_inconsistent` from it once the extract reading is also
      `consistent` (§5)
- [ ] Emits `unreachable` (never `inconsistent`) for failed fetches, and
      sets `robots_excluded` when and only when `robots.txt` is the reason
      — including where the file discriminates between admitted Auditors,
      whatever access it grants this one (§5, WIST-2 §5)
- [ ] Emits `not_auditable` (never `inconsistent` or `unreachable`) for a
      withdrawn, unobtainable or empty-extract Reference Payload, for an
      observed text below the mass guard (outside the `delete` mirror's
      ruled-on `404`/`410`), for a non-HTML representation, and for a page
      the fetch bounds stopped before a representation was read — each
      discharging the coverage duty (§4, §5)
- [ ] Bounds its own fetches: reads no more than `audit_fetch_cap_bytes`
      of response body per audited URL, fetches no more than
      `audit_domain_budget_bytes_day` for one domain per UTC day, follows
      no more than `audit_redirect_max` redirects and waits no longer than
      `audit_fetch_timeout_seconds` — recording `not_auditable` for the
      first two and `unreachable` for the last two (§5, §9)
- [ ] Audits every Delta §4's extension rule names for it, within the
      extension deadline, exactly as a VRF selection — the Record carrying
      the proof for *B₁* and served at *B₁*'s records path (§4)
- [ ] Serves its Records and attestations per audited Block at its
      well-known records path until sealed, each carrying `prev_record`
      in its own publication order (§4)
- [ ] Signs Records with a key admitted at the `sealed_at` of the Block
      carrying the Record, and fetches inside the interval §3 fixes — with
      the coverage carve-out: an Auditor removed after a Block was sealed
      but before that Block's coverage deadline still discharges its §4
      duty by publishing under the key admitted at the `sealed_at` of the
      Block the duty is anchored to — the audited Block, or *B₁* for an
      extension — and such a Record proves the duty was met without
      entering any domain's reputation (§3, §4)
- [ ] Commits the response, its own extraction and its WARC capture under
      the Reference Payload's salt — never as bare digests (§5)
- [ ] Preserves the WARC capture behind every `inconsistent` and
      `link_inconsistent` Record for `warc_retention_days`, extended and
      served at the §5 evidence path while a notice naming the Record is
      pending, and destroys any capture, the Reference Payload and the
      salt on withdrawal (§5, WIST-3 §6.2)

**Aggregator (governance side):**

- [ ] Admits/removes Auditors only via logged Registry Updates, after
      verifying the Declaration at the Auditor's own domain, and never
      under a hostname that fails §3's independence test against its own
      `log_id` (§3)
- [ ] Excludes unauditable URLs from materialization for as long as §5's
      predicate holds — two independent `robots_excluded` Records inside
      the horizon, cleared only by a successful audit from an Auditor
      independent of both, or by their ageing out (§5, WIST-3 §7)
- [ ] Removes an Auditor past `coverage_failures_max` by `auditor_remove`
      naming the failed Blocks — recording an exclusion that §4 already
      derives, never creating it (§3, §4)
- [ ] Applies sanctions only per the §7 ladder — evidence for every
      sanction, notice and an appeal window for levels 3–4
- [ ] Fetches every sanction notice's appeal path (WIST-2 §3.3) and seals
      the `appeal` it finds, or an `"unappealed"` `appeal_ruling`, by the
      §7 sealing deadline — and rules on a sealed appeal within the ruling
      deadline (§7)
- [ ] Never suspends ingestion for a Provisional domain; only
      Sanctioned Quarantine or delisting rejects a Ping or pull (§6, §7)
- [ ] Pulls every admitted Auditor's well-known records path per Block
      after its deadline, seals what it finds within
      `record_seal_blocks`, and seals a `pull_attestation` for every
      pull — including the empty ones (§4)
- [ ] Seals an accepted Delta within `max_inclusion_blocks` of its
      eligibility Block — the first Block with room for it under the
      per-domain capacity, in acceptance order (§6.4, WIST-3 §3.2)
- [ ] Seals a served, valid recovery Declaration within
      `record_seal_blocks` of discovering it (WIST-1 §5.2)
- [ ] Enforces the §8 invariants unconditionally
- [ ] Changes parameters only via `parameter_change` with the grace
      period (§9)

**Any party recomputing reputation:**

- [ ] Reads a `parameter_change` as in force from its `effective_at`
      inclusive, the greatest `effective_at` ≤ T prevailing among an
      identifier's amendments and Log order breaking an equal pair (§9)

- [ ] Reproduces §6 exactly (constants from the Parameter Registry as of
      the evaluated block height)
- [ ] Uses integer arithmetic and the normative decay table only (§6)
- [ ] Derives `A` and every `t_i` from Block `sealed_at`, never from
      `observed_at` or wall clock time (§6.1)
- [ ] Verifies VRF proofs before counting a Record (§4)
- [ ] Derives the roster from the Log — one key per `auditor_id` per
      height, read at each Block's `sealed_at` — rejecting the acts
      `WIST4-E07` names (§3, §4, §10)
- [ ] Counts a Record only when its Auditor's key was admitted at its own
      Block's `sealed_at`, its `auditor_id` matches that admission's
      `subject`, its `fetched_at` lies in §3's interval, and the audit was
      not a self-audit (§3)
- [ ] Counts only admitted-Auditor Records (§3) and only Confirmed
      Inconsistencies and Confirmed Link Inconsistencies, confirmed by
      independent Auditors inside the `sealed_at` window (§3, §5, §7)
- [ ] Stops counting the Records of an Auditor in coverage failure at
      their own Block's `sealed_at`, whether or not an `auditor_remove`
      was ever sealed, and counts them again once the failures age out of
      the 30-day window (§3, §4)
- [ ] Excludes from `C` a Record whose `reference_delta` is an `attest`
      or a `delete`, whatever Delta it audited; counts distinct
      Normalized URLs; and applies `C_cap` (§6.1)
- [ ] Applies the Provisional cap as a ceiling, not a floor (§6.2), and
      resets `A`/`C` only for a fresh identity — never for an ordinary or
      recovery rotation (§6.3)
- [ ] Scopes `C` and every Confirmed Inconsistency to the current identity
      by the sealing height of the Record's `audited_delta`, not the
      Record's own (§6.1, §6.3)
- [ ] Recomputes severity from evidence and rejects unsupported sanctions (§7)
- [ ] Counts every Confirmed Inconsistency's and Confirmed Link
      Inconsistency's penalty from its confirming Block onward,
      independent of whether a `sanction` Registry Update exists for it
      (§6.1, §7)
- [ ] Derives the level-3 and level-4 sanction *states* from the §7
      escalation criteria at the height they are met, whether or not the
      Aggregator sealed the `notice` and `sanction` that record them, and
      lifts each at the height a `sanction_lift`, an `"overturned"`
      `appeal_ruling`, a lapsed ruling deadline, a lapsed
      appeal-sealing deadline, or an identity reset (§6.3) takes
      effect (§7, WIST-3 §7)
- [ ] Runs every window from the `sealed_at` of the Block sealing the
      Entry that opens it — the appeal window from the `notice`'s Block,
      the recovery window from the recovery Declaration's own (WIST-1 §5.2)
      — and never from an `effective_at` (§3, §7)
- [ ] Treats an `appeal_ruling` of `"unappealed"` whose own Block
      `sealed_at` precedes the close of that notice's appeal window as
      absent, so it discharges nothing and T lapses against it (§7)
- [ ] Keeps that derivation to the sanction's state and never lets an
      appeal, a lift or a lapsed deadline touch `penalty_n`, which §6.1
      derives from the evidence alone (§6.1, §7)

## Appendix A. Worked Sampling Example

Real values, computed by `tools/gen_vectors.py` and machine-checked by
`tools/validate_examples.py` (`vectors:wist4-sampling`). The source of truth
is [`vectors/wist4/sampling.json`](../vectors/wist4/sampling.json); the test
key is the WIST-1 vector keypair (`vectors/wist1/keypair.json`, seed
`000102…1f` — **never use it in production**).

| Field | Value |
|---|---|
| Ciphersuite | `ECVRF-EDWARDS25519-SHA512-TAI` (`suite_string` `0x03`) |
| Auditor public key (base64url) | `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg` |
| Block Hash of *B* | `sha256:f6a352a23522bbce2ae827d9c4c4941dbca3a8a9a7be37d99d4f620e4d0d5487` |
| `alpha` (32 octets, hex) | `f6a352a23522bbce2ae827d9c4c4941dbca3a8a9a7be37d99d4f620e4d0d5487` |
| `pi` = `vrf_proof` (80 octets) | `defb838b0b6ea0932bbd29a9ac6c5f89ef0d8bac94f76e2cf92dea63bc98f0bc`<br>`80b9d48617d2aca12c50449654647c3e60f63a8f9b9e1fb5c5232316c6ed6ff1`<br>`84358bb73f251175fb6a4ac8b935ca09` |
| `beta` (64 octets) | `4d3a0bfb2e4d9b96b3d4245b0d846450d8bddb532b06361bb7c31bbaa30c74d8`<br>`76741d9fb507a447a99adec5148154e602f8e78d1639ff5b9bd101d04e0960a7` |
| Delta ID of Entry 0 | `sha256:bb28d0f30208ef88cdb4d88aadb3531a7b023eb6639c8642d91fa503ea0a78e4` |
| `SHA-256(beta ‖ Entry 0)[0..8]` | `90f367d0f8992759` |
| `D`(Entry 0) | `10444806108023957337` |
| Delta ID of Entry 3 | `sha256:21733620f4ade1efdc598a6512fd91d230ee1a66bb9bec640f846bf80cbdf47d` |
| `SHA-256(beta ‖ Entry 3)[0..8]` | `46129a20b3dd8f1f` |
| `D`(Entry 3) | `5049267597483020063` |

Note that `alpha` is the Block Hash's 32 decoded octets, while the Delta ID
enters the draw as the UTF-8 bytes of the whole string, `sha256:` prefix
included — the two are deliberately different and an implementation that
confuses them will produce a different, wrong selection set.

Selection outcomes, by the §4 integer test `D × 10^7 < p_1e7 × 2^64`. Both
Deltas are real Entries of the same Block drawn against the same `beta`;
the two domains differ only in reputation:

| Delta | `reputation_u` | `p_1e7` | `D × 10^7` | `p_1e7 × 2^64` | Selected? |
|---|---|---|---|---|---|
| Entry 0 | 100 000 (Provisional) | 2 900 000 | 1.044e26 | 5.350e25 | no |
| Entry 0 | 900 000 (established) | 500 000 | 1.044e26 | 9.223e24 | no |
| Entry 3 | 100 000 (Provisional) | 2 900 000 | 5.049e25 | 5.350e25 | **yes** |
| Entry 3 | 900 000 (established) | 500 000 | 5.049e25 | 9.223e24 | no |

The two product columns are shown rounded for reading; the exact integers
are in the vector, and an implementation MUST compare the exact ones. Note
what the third row costs the Provisional domain: the same Delta that an
established domain's rate leaves alone is audited at 0.29. A different
Auditor, holding a different key, gets a different `beta` over the same
Block and therefore an independently drawn selection set.

## Appendix B. Worked Reputation Example

Real values, computed by `tools/gen_vectors.py` and machine-checked by
`tools/validate_examples.py` (`vectors:wist4-reputation`,
`vectors:wist4-decay-table`). The source of truth is
[`vectors/wist4/reputation.json`](../vectors/wist4/reputation.json) and
[`vectors/wist4/decay-table.json`](../vectors/wist4/decay-table.json). Every
number below is an integer produced by the §6 operations in the order §6
gives them.

A domain whose first accepted Delta was sealed in the Block of Appendix A
(`sealed_at` `2026-08-02T13:00:00Z`), evaluated at a Block N sealed
`2027-09-06T18:00:00Z`, with 12 distinct audited URLs and one severity-2
Confirmed Inconsistency whose confirming Block was sealed
`2027-08-07T17:00:00Z`:

| Quantity | Value | How |
|---|---|---|
| `A` | 400 | (Block N − first Block) = 400 d 5 h; the partial day truncates |
| `t_1` | 30 | (Block N − confirming Block) = 30 d 1 h; likewise |
| `base_u` | 593 150 | 100 000 + ((900 000 × 400) / 730) |
| `C` | 12 | distinct Normalized URLs with a `consistent` audit, under `C_cap` |
| `decay(30)` | 846 481 724 | table lookup, not `exp()` |
| `penalty_n` | 1 692 963 448 | 2 × 846 481 724 |
| numerator | 7 710 950 000 000 000 | 593 150 × 13 × 1e9 |
| denominator | 21 464 817 240 | 13 × 1e9 + 5 × 1 692 963 448 |
| `reputation_u` | 359 236 | integer division, not Provisional, no clamping |
| `Q` | 3 692 | 100 + ((10 000 × 359 236) / 1 000 000) |
| `p_1e7` (§4) | 2 122 292 (reads as 0.2122292) | clamp(200 000 + 3 × (1 000 000 − 359 236), …) |

**The Provisional boundary.** Reputation never falls because a gate
lifted. Rows 1–3 cross the age gate with a clean record; rows 4–5 cross
the same gate with the severity-2 penalty above still in force, where the
cap is not even binding; rows 6–7 cross the `C` gate for an aged domain,
the only place the cap does bind; row 8 is a brand-new domain.

| `A` | `C` | `penalty_n` | `base_u` | formula | Provisional? | `reputation_u` | `Q` |
|---|---|---|---|---|---|---|---|
| 29 | 10 | 0 | 135 753 | 135 753 | yes | 100 000 | 1100 |
| 30 | 10 | 0 | 136 986 | 136 986 | no | 136 986 | 1469 |
| 31 | 10 | 0 | 138 219 | 138 219 | no | 138 219 | 1482 |
| 29 | 10 | 1 692 963 448 | 135 753 | 76 717 | yes | 76 717 | 867 |
| 30 | 10 | 1 692 963 448 | 136 986 | 77 413 | no | 77 413 | 874 |
| 800 | 9 | 0 | 1 000 000 | 1 000 000 | yes | 100 000 | 1100 |
| 800 | 10 | 0 | 1 000 000 | 1 000 000 | no | 1 000 000 | 10 100 |
| 0 | 0 | 0 | 100 000 | 100 000 | yes | 100 000 | 1100 |

Three things to read off this table. Graduating is a promotion
(100 000 → 136 986), not the demotion the old real-valued formula
produced. The cap is a ceiling: at rows 4–5 the penalized domain scores
below 0.10 while Provisional, so the gate cannot launder a Confirmed
Inconsistency, and its `Q` is 867, not 1100. And the last row is why the
two meet at all — at `A` = 0 the ungated formula equals the cap exactly,
so the Provisional cap is the value the formula already has rather than a
number bolted on top of it.

**Nothing here is rounded.** The `p_1e7` column of
`vectors/wist4/reputation.json` is §4's sampling rate computed by §4's own
integer clamp on `reputation_u`; for the worked example it is 2 122 292,
which *reads* as 0.2122292 but is never computed as a decimal. The decay
table's endpoints, `decay(0)` = 1 000 000 000 and `decay(1825)` = 39 512,
are likewise exact integers rather than the output of any `exp()`. Reading
this appendix together with Appendix A, every number the protocol compares
— reputation, quota, sampling rate, and the draw itself — is an integer
from end to end.

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- [RFC 8032] Edwards-Curve Digital Signature Algorithm (EdDSA) — the
  Ed25519 key format and edwards25519 group shared by signing and the VRF
- [RFC 9381] Verifiable Random Functions (VRFs) — ECVRF-EDWARDS25519-SHA512-TAI
  (§5.5); the normative source for §4's `prove`, `proof_to_hash` and `verify`
- [UAX #29] Unicode Standard Annex #29, Unicode Text Segmentation — the
  default word-boundary and extended grapheme cluster rules §5's similarity
  metric segments by, used without tailoring
- [UAX #44] Unicode Standard Annex #44, Unicode Character Database — General
  Category values (L\*, N\*) and the default full case-folding §5 applies
- [ISO 28500] ISO 28500, WARC file format — the format of the capture §5's
  `evidence_commitment` covers and §7's appellant fetches
- WIST-1: Delta Format & Identity — key rotation, scope rule, §6 absence
- WIST-2: Site Publication — quotas, hints, robots.txt boundary
- WIST-3: Logbook & Distribution — entry envelope, checkpoints,
  immutability, Block Hash (WIST-3 §3.1)
