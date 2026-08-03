# DC-4: Audit, Reputation & Governance

**Status:** v1.0.0-draft · **Date:** 2026-08-02 · **License:** CC-BY 4.0

## 1. Introduction

Everything DC-4 defines is an input to, or a pure function of, the log.
Nothing exists outside it.

DC-1 through DC-3 make the system verifiable; DC-4 makes it defensible.
It defines how sampled Deltas are checked against reality (audit), how a
domain's track record becomes a number anyone can recompute (reputation),
how misbehavior is punished with due process (sanctions), and which rules
are beyond amendment by operation (constitutional invariants). Because
every audit record, sanction, appeal, and parameter change is a log entry
(DC-3 §3.3), the entire governance history of the system is public,
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
  `inconsistent`, `unreachable`, `dynamic_variance`, or `not_auditable`.
- **VRF Proof**: the 80-octet `pi_string` an Auditor produces over a Block
  Hash with its own key under ECVRF-EDWARDS25519-SHA512-TAI ([RFC 9381]),
  carried in every Audit Record as `vrf_proof`. It lets anyone recompute
  that Auditor's selection set for that Block, and only that Auditor
  produce it (§4).
- **Confirmed Inconsistency**: ≥ 2 Auditors, independent in the sense §3
  defines, returning `inconsistent` for the same Delta within 72 hours
  measured on Block `sealed_at` (§5).
- **Registry Update**: the signed governance object this document defines,
  sealed as a `registry_update` Entry (DC-3 §3.3). Its `action` selects one
  of the twelve governance acts of §3, §4, §7 and §9.1; `subject` names
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

Every signed object in this document carries `dc_version` (DC-1 §3.1)
and the DC-1 §4 signature block (`key_id`, `alg`, `value`).

## 3. Auditors

Auditors are admitted by an `auditor_admit` Registry Update (schema:
[`schemas/registry-update.schema.json`](../schemas/registry-update.schema.json))
whose `subject` is the Auditor's `auditor_id` and whose `details` MUST carry
the Auditor's `key_id` and its raw Ed25519 `public_key` (base64url, 32
octets unpadded), and removed by `auditor_remove`. Both are signed by the
Aggregator and, like everything else, live in the log — the roster of who
may audit, and since when, is public and permanent.

**An Auditor is a domain, not a bare key.** `auditor_id` is a hostname of
at least two labels, anchored the way a Publisher's identity is (DC-1
§5.1): the Auditor MUST serve, at
`https://<auditor_id>/.well-known/deltacommons/publisher.json`, a
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
and an instance of the exposure §10 states — never a retroactive rewriting
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
against the Log Anchor's `log_id` (DC-3 §3.4). One test governs all three
relations deliberately: a rule that put only a hostname's parents and
subdomains beyond its audits would leave `audit.example.net` free to audit
`blog.example.net`, which is the same operator by the very measure §5's
confirmation rule uses. Both are comparisons over values the Log carries:
a Record breaching the first MUST be rejected by validators recomputing
reputation, and an `auditor_admit` breaching the second MUST be rejected
outright, so no key it names is ever an admitted key and no Record signed
by that key counts. Neither rule makes independence true — §10 states
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
assignments under another.

**Windows and admission run on `sealed_at`.** `fetched_at` is
Auditor-supplied and unverifiable by anyone else, so nothing anchored to it
is recomputable. Every admission test and every window in this document
reads Block `sealed_at` values instead (DC-3 §3.1), which are ordered,
strictly increasing, and identical for every replaying party — the appeal
window of §7 and the recovery window of DC-1 §5.2 included, neither of
which reads the `effective_at` of the Entry that records it. Every
timestamp this suite compares against a Block `sealed_at` is written in the
same whole-second, literal-`Z` form that field carries, so no comparison
rests on a normalization step two implementations could perform
differently: `fetched_at` below, a Feed's `generated_at` (DC-2 §3.2), a
Registry Update's `effective_at`, and a `notice`'s `appeal_deadline` (§9.1)
are all constrained to it by their schemas. Validators
recomputing reputation MUST reject:

- a Record signed by a key not admitted at, or removed at or before, the
  `sealed_at` of the Block carrying that Record;
- a Record whose `vrf_proof` does not verify — over the audited Block's
  Block Hash, under the key admitted at that Block's `sealed_at` (§4) — or
  whose `audited_delta` is not in the selection set that proof determines
  (§4);
- a Record whose `fetched_at` falls outside the closed interval from the
  `sealed_at` of the audited Delta's Block to the `sealed_at` of the
  Record's own Block. Neither end rests on trust: an Auditor's selection is
  derived from the audited Block's Block Hash, so under this protocol it
  cannot have fetched before that Block was sealed, and no Record is sealed
  before it is written. A `fetched_at` outside that interval contradicts
  the Log's own ordering;
- a Record whose Auditor audited a domain the self-audit rule above puts
  beyond it;
- a Record whose Auditor was **in coverage failure** at the `sealed_at` of
  the Block carrying that Record — that is, one for which the Log shows
  more than `coverage_failures_max` failed coverage duties inside the 30
  days ending there (§4). The predicate is computed from the Log like every
  other test here, and it does not wait on an `auditor_remove`;
- a Record whose `similarity` does not satisfy §5's condition for its own
  `verdict` — a `verdict: "inconsistent"` Record whose effective similarity
  (§5) is not below §5's threshold for that verdict is malformed evidence,
  not a divergent judgement call, and MUST NOT be allowed to leave `sim`
  (§7) resting on a value outside every severity band.

The first and the coverage-failure rejections are scoped to reputation and
do not reach coverage: an Auditor removed after a Block was sealed but
before its coverage deadline still discharges its §4 duty for that Block by
publishing, because coverage is anchored to the audited Block's `sealed_at`
rather than to the height at which the Record lands, and an Auditor in
coverage failure still discharges — and can still recover from — the duty
by publishing. Such a Record proves the Auditor met its duty; it does not
enter any domain's reputation.

Aggregator keys are admitted and retired by the `aggregator_key_add` /
`aggregator_key_remove` actions defined in DC-3 §3.4; their `details`
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
`"sha256:" + hex(SHA-256(JCS(header)))` (DC-3 §3.1), so `alpha` is those 32
octets and nothing else: not the `sha256:`-prefixed string, not its ASCII
hex, not the header bytes.

For each Delta *d* carried by a `publisher_delta` Entry of *B*, the Auditor
MUST audit *d* if and only if

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
Record it emits for Block *B* (`vrf_proof`). Anyone can verify with the
Auditor's public key that `beta` is the unique correct output for that
Block, and can therefore recompute the Auditor's entire selection set for
*B* and check it audited exactly that set — no more (harassment) and no
less (favoritism).

This construction closes three problems at once. The Aggregator cannot
steer audits: it does not hold Auditor keys, so grinding the Block Hash
changes every Auditor's selection unpredictably and in no chosen direction.
The Auditor cannot steer them either: the VRF output is uniquely determined
by its key and the Block, and any deviation is detectable. And assignment
needs no coordinator: each Auditor's duties for each Block are derived, not
allocated.

**Coverage duty.** For **every** Delta its VRF selects in a Block, an
Auditor MUST publish an Audit Record — or, when it cannot fetch at all, a
Record with verdict `unreachable` — within 72 hours of that Block's
`sealed_at`. When its VRF selects no Delta in a Block, it MUST instead
publish, by the same deadline, a `coverage_attestation` Registry Update
carrying that Block's VRF proof and nothing else.

**Withdrawn and unavailable Payloads discharge the duty.** A selected
Delta whose Payload has been withdrawn (DC-3 §6.2), or which the Auditor
cannot obtain from any source, is audited with a Record whose verdict is
`not_auditable` (§5). That Record discharges the coverage duty for that
Delta exactly as any other verdict does, so the Block does not count
toward `coverage_failures_max`. Without this rule an Auditor would accrue
coverage failures for a withdrawal it did not cause, could not foresee,
and cannot remedy — and the cheapest way to remove an inconvenient Auditor
would be to withdraw Payloads it was about to audit. Inside the
availability window an Auditor SHOULD first try another Mirror and the
Publisher, and the absence is a `DC3-E05` fault against the Mirror that
lacked it (DC-3 §6.1); `not_auditable` records the Auditor's inability to
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
partial credit. Because `pi` pins the selection set exactly, that is an
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
under the duty, never a way around removal. The exclusion is scoped to
reputation and carries no notice and no appeal, for the reason §5 gives for
the unauditable horizon: nothing here is punitive, and what it withdraws is
the weight of Records from a party the Log already shows was not doing the
work they claim to be part of.

`coverage_attestation` is the second class of Registry Update not signed by
the Aggregator (the first is `appeal`, §7): the Auditor signs it with its
own admitted key, and its `subject` is the Auditor's `auditor_id`.

Worked numbers for this section — real values from `vectors/dc4/sampling.json`
— are in the Appendix.

## 5. Verdicts and Tolerance

An Audit Record is an Envelope whose inner object is `record` (DC-1 §4),
and its fields are: `audited_delta` (the Delta ID under audit),
`auditor_id` (the Auditor's hostname identity), `fetched_at` (when the
Auditor fetched the URL), `response_commitment` (over the raw response
body), `ref_extract_commitment` (over the Auditor's own reference
extraction), `similarity` (the §5 metric value, an integer in micro-units),
`verdict`, `evidence_commitment` (over the WARC capture, which the Auditor
MUST preserve), `robots_excluded` (present only on an `unreachable` Record
the `robots.txt` rule below produced), and `vrf_proof` (the §4 VRF Proof
over the Block Hash of the Block carrying the audited Delta, 80 octets as
160 lowercase hex characters). The Record names no Block: the audited
Block is the one Block
whose `publisher_delta` Entries carry `audited_delta`, which DC-3 §3.2
makes unique and permanent. `vrf_proof` is REQUIRED in every Record,
`unreachable` and `not_auditable` included, because it is what establishes
the Auditor's right and duty to have audited at all.

**The Reference Payload.** Every audit is measured against exactly one
Payload, and which one is fixed by the audited Delta alone:

- for a `new` or `update` Delta, the audited Delta's own Payload;
- for an `attest` or a `delete` Delta, the Payload of the **last
  content-bearing Delta at or before `audited_delta`** in that URL's
  per-URL chain (DC-1 §3.5) — the URL's anchor Payload as of the audited
  Delta (DC-3 §6.1).

The qualifier "at or before `audited_delta`" is normative and is what
makes a Record verifiable at any later height. Resolving the reference to
whatever the URL's current anchor happens to be would silently change it
whenever a later `update` is sealed, and with it the salt below, so a
Record audited honestly would stop verifying through no act of its
Auditor's. Because the chain, its order, and every Delta in it are in the
Log, the resolution is deterministic from Log order alone.

A `delete` audit has a Reference Payload for the same reason it has
anything to check: the claim a `delete` makes is that the content its
chain last committed to is no longer served (DC-1 §3.3), so that Payload
is what the claim is judged against, and the capture the Auditor preserves
may contain that very content where the claim is false.

When an audit has nothing to measure against, the verdict is
`not_auditable`. That covers four cases: the Reference Payload has been
withdrawn (DC-3 §6.2); it cannot be fetched from any source; the URL's
chain has never carried a content-bearing Delta, so no anchor exists to
resolve; and the Reference Payload is obtained and verifies but its
`extract` is empty under the normalization below, so the Payload exists and
there is still no text the audit could confirm or refute.

DC-1 §3.3 requires `payload` on every `new` and `update`, so a Delta
claiming content while committing to none is rejected (`DC1-E09`) and never
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
`salt` is **the salt of the audit's Reference Payload** (DC-1 §3.6). The
Auditor holds that salt because it MUST verify that Payload before
comparing anything, so no second salt, and no second lifecycle, is
introduced.

`response_commitment`, `ref_extract_commitment`, `evidence_commitment` and
`similarity` are REQUIRED when the verdict is `consistent`, `inconsistent`,
or `dynamic_variance`, and MUST be omitted when it is `unreachable` or
`not_auditable`. Those two verdicts are exactly the cases with nothing to
commit to and no key to commit under: `unreachable` records that no
representation of the page was obtained to compare against, whether the
fetch failed outright, returned an error status the table below does not
except, or was forbidden by
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
schema, which sees a verdict but cannot resolve `audited_delta` to a change
type.

A bare digest here would undo the rest of this design. Moving extracts out
of the Log accomplishes nothing if the Log keeps unsalted hashes of the
same text: a party holding a copy could recompute one and confirm the text
was there, which is exactly the confirmability DC-1 §3.6's salt exists to
destroy. Binding one salt to all four commitments — the Publisher's and
the Auditor's three — makes them expire together rather than leaving the
weakest one governing.

**Verifying a commitment, and when it stops being possible.** A party
checking an Audit Record obtains the salt the way the Auditor did: it
fetches the audit's Reference Payload, verifies that Payload against its
own Delta's commitment (DC-1 §3.6), and takes the salt from it. It then
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
ruling at day 231, past the 180-day availability window (DC-3 §6.1).
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

Once a Reference Payload is withdrawn (DC-3 §6.2), the salt is destroyed at
every serving path that rule binds — the Aggregator's, every Mirror's, and
the Publisher's own well-known copy (DC-2 §3.1) — and that Record's
commitments can no longer be checked by anyone, the
Auditor included. That is the intended outcome, not a defect: it is the
same instant at which the Delta's own commitment stops being checkable. A
verifier that encounters an unverifiable commitment MUST NOT treat the
Record as invalid on that ground; it reads the Record's verdict as the Log
records it.

**What an audit fetches.** The Delta commits to content it does not carry
(DC-1 §3.6), so an Auditor holding a Block fetches two further things: the
audit's **Reference Payload**, defined below, from
`/payloads/<reference-delta-id-hex>.json` at the Aggregator, a Mirror, or
the Publisher (DC-3 §6.1, DC-2 §3.1) — where `<reference-delta-id-hex>`
names the Delta whose Payload that is, which for an `attest` or a `delete`
is an earlier Delta in the chain and not `audited_delta` — and the URL
itself. It MUST verify that Payload against **its own** Delta's
`commitment` and `bytes` before comparing anything, and MUST reject a
Payload that fails (`DC1-E10`) rather than audit against it. The
commitment was fixed when the Publisher signed that Delta, so a Payload
that verifies is what the Publisher declared no matter who served it —
which is what lets the comparison below remain an audit of the Publisher
rather than of a Mirror.

Every Audit Record has an **Audit Record ID**: `"sha256:" + hex(SHA-256(JCS(record)))`
— the record's inner object canonicalized and hashed under the same
content-addressing construction DC-1 §4 uses for a Delta ID. A `sanction`'s
`evidence` (§7) is a list of Audit Record IDs, so anyone can fetch exactly
the Records a sanction claims to rest on and recompute what they establish,
rather than trust the claim.

The web is not deterministic; byte equality is never the criterion.

`similarity` is an integer in **micro-units** (0 … 1 000 000, the same
resolution as `reputation_u`, §6), never a floating-point ratio. It
compares two texts: the `extract` of the audit's verified Reference Payload
— the **reference text** — and the Auditor's own extraction of the fetched
page, the **observed text**.

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

    similarity = floor((|A ∩ B| × 1 000 000) / |A ∪ B|)

in exact integer arithmetic on the shingle sets' cardinalities — no
floating-point Jaccard ratio is ever computed or compared, and no two
conforming Auditors can disagree about a boundary case from rounding alone.

The second branch is normative, not a convenience. Eight-word shingles do
not exist in a text of fewer than eight words, and a rule that let both
sets come out empty would score every short text as identical to every
other — a free `consistent` for any Publisher whose extract is a headline.
Falling to grapheme clusters keeps a short text comparable at the
granularity it actually has, and capping the shingle length at the shorter
text's own length keeps both sets non-empty, so `|A ∪ B|` ≥ 1 always and
the quotient is defined for every pair of non-empty texts.

Empty texts are ruled on rather than measured, and the two are not
symmetric. An empty **reference** text is `not_auditable` (above): a
Publisher that committed to no text made no claim an audit could confirm or
refute. An empty **observed** text is a finding about the URL, not an
absence of evidence — the page was fetched and yielded no text where the
Publisher committed to some — and scores `similarity` = 0 by definition,
there being no shingle of the reference for it to share. Where both are
empty the reference rule governs, because the verdict order below puts
`not_auditable` first.

**Effective similarity.** A `new`, `update` or `attest` Delta claims the
URL carries the reference content, so agreement confirms it; a `delete`
claims the opposite, so agreement refutes it. One table serves both, read
over the **effective similarity**:

    effective similarity = similarity                 (new, update, attest)
                         = 1 000 000 − similarity     (delete)

Every threshold in this suite is read over the effective similarity —
the table below and §7's severity bands alike — while `similarity` is what
the Record seals. A validator resolving `audited_delta` to its change type
applies the mirror; nothing else in the pipeline changes shape.

| Verdict | Condition |
|---------|-----------|
| `consistent` | effective similarity ≥ 600 000 |
| `dynamic_variance` | 300 000 ≤ effective similarity < 600 000 |
| `inconsistent` | effective similarity < 300 000 |
| `unreachable` | no representation of the URL was obtained: transport or DNS failure, an error status other than the `404`/`410` a `delete` audit expects (below), or a `robots.txt` prohibition (DC-2 §5) |
| `not_auditable` | there is no text to measure against: the Reference Payload is withdrawn (DC-3 §6.2), never existed, cannot be obtained from any source, or carries an empty `extract` |

**The five are ordered, and the order is normative**, because more than one
description can fit one audit: `not_auditable`, then `unreachable`, then
the three bands. An Auditor with no reference text records `not_auditable`
whether or not the fetch also failed — from a withdrawal's sealing height
it MUST, even holding a copy — and an Auditor that obtained no
representation records `unreachable` without computing a similarity it has
no observed text for. A band is read only when there is a reference to
measure against and a representation to measure. Since the three bands
partition 0 … 1 000 000 with no gap and no overlap, exactly one verdict
fits every audit. The `inconsistent` row rests on the number alone: a
conjunct requiring the claimed content to be "absent from the fetched page"
would name no procedure two Auditors could apply to one answer, and would
leave every audit below the floor whose content was in some sense still
present with no verdict at all — which is the one thing a verdict table may
not do.

**`delete` audits.** Two consequences of the mirror are worth stating
outright. A `404` or `410` response to a `delete` audit is not a fetch
failure but the state the Delta claims: the Auditor treats it as a
representation, its observed text is empty, `similarity` is 0, the
effective similarity is 1 000 000, and the verdict is `consistent`. And a
URL still serving the content its chain committed to after a `delete` is
`inconsistent` — its effective similarity is below 300 000 like any other,
so §7 derives its severity from the same bands over the same sealed field
as for every other Confirmed Inconsistency. A `delete` is a claim like
the rest and MUST NOT become a way to retire a false one by making it
unmeasurable: were a false `delete` to carry no severity input, publishing
one would be the cheapest way to end an audit trail that was about to
contradict the Publisher.

`attest` and `delete` Deltas carry no Payload of their own, so both depend
on a Payload that may have been sealed long before
the Block under audit — often long before the availability window that
covers ordinary Payloads. Two independent parties are obliged to serve it:
the Publisher, for as long as it attests to the URL, re-anchoring the
chain with an `update` or a `delete` when it cannot (DC-2 §3.1); and the
Aggregator, with no expiry until the first superseding content-bearing
Delta or `delete` for that URL is sealed, and then for one further
availability window (DC-3 §6.1). Either
copy satisfies the audit, because the commitment makes them
interchangeable, so a Publisher cannot render its own freshness claims
unauditable by withholding its copy. Where the Reference Payload is
nonetheless unobtainable from every source, or has been withdrawn, the
verdict is `not_auditable`.

From the sealing height of a `payload_withdrawal` (DC-3 §6.2), an Auditor
MUST record `not_auditable` for the affected Delta even if it still holds
or can still obtain a copy of the Payload. Auditing is the one process
that would otherwise keep re-establishing, in a permanent public record,
the link between a withdrawn text and its commitment.

`dynamic_variance`, `unreachable` and `not_auditable` are neutral: they
never contribute to sanctions. Auditor re-fetches of content URLs respect
`robots.txt` (DC-2 §5); a fetch forbidden by `robots.txt` is recorded
`unreachable` with `robots_excluded` true. That flag is REQUIRED when
`robots.txt` is the reason and MUST NOT appear on any other verdict, so the
Log distinguishes a URL nobody is permitted to check from one that happened
to be down.

**Declining audits is not indefinitely free.** A URL is **unauditable** at
height N when the Log holds two `robots_excluded` Records for Deltas on
that URL, signed by Auditors independent of one another (§3), each of them
sealed in a Block itself sealed no more than 30 whole days (Parameter
Registry: `unauditable_horizon_days`) before Block N's `sealed_at`, and no
Record for a Delta on that URL with verdict `consistent`, `inconsistent`
or `dynamic_variance`, signed by an Auditor independent of both, was
sealed after the later of those two. An unauditable URL MUST be excluded
from materialization (DC-3 §7) for as long as that holds; it ceases to be
unauditable when such a Record is sealed, or when the exclusions age out
of the window with none replacing them.

Two properties of that definition are load-bearing, and both are
departures from the obvious shape. It arms on the **presence** of
exclusions rather than on the absence of successes, and it clears only on
a success by an Auditor **independent of the Auditors that were turned
away**. A rule that cleared on any success would be defeated by a
`robots.txt` that admits exactly one Auditor: that Auditor's Records would
clear every exclusion the others recorded, keeping the URL materialized
forever while guaranteeing that no second independent Auditor can ever see
the page — and a Confirmed Inconsistency, needing two, could then never
form for it. DC-2 §5 closes that from the other side by making a
`robots.txt` that discriminates between admitted Auditors a prohibition
for all of them; the independence requirement here is what holds if a
Publisher discriminates by some means `robots.txt` does not express.

It takes two Auditors to arm the horizon for the same reason it takes two
to confirm an inconsistency. `robots_excluded` is a single Auditor's
unverifiable claim about a file that party alone fetched, and exclusion
from materialization is a real consequence carrying no notice and no
appeal; one Auditor MUST NOT be able to impose it alone (§10).

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
by additional Auditors. A **Confirmed Inconsistency** exists only when ≥ 2
Auditors, independent of one another in the sense §3 defines, return
`inconsistent` for the same Delta, with the `sealed_at` of the Block
sealing the confirming Record no more than 72 hours after the `sealed_at`
of the Block sealing the first such Record. The window is measured on
Blocks and not on `fetched_at` for the reason §3 gives: `fetched_at` is
Auditor-supplied, and a confirmation nobody can recompute is not evidence.
Only Confirmed Inconsistencies enter the reputation formula and sanction
ladder. This absorbs A/B tests, geo-variation, and legitimate change
between push and audit.

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
enforced by both DC-3 §3.1 and `schemas/block.schema.json`, so
`seconds(sealed_at)` — the count of seconds since 1970-01-01T00:00:00Z
with every day counted as exactly 86 400 seconds and no leap seconds — is
an exact integer for every conforming Block, with no fractional part to
round and no offset to reduce. "Whole days between X and Y" is then
`(seconds(Y) − seconds(X)) / 86 400` under integer division. `sealed_at`
is strictly increasing across Blocks (DC-3 §3.1), so every such difference
is non-negative and the rounding direction of a negative quotient never
arises.

**Identity scope.** `A`, `C`, and the set of Confirmed Inconsistencies are
all scoped to the domain's **current identity**: every one of them counts
only Log events sealed at a height greater than the domain's most recent
identity reset (§6.3) and ≤ N. A domain that has never reset has no such
lower bound, and everything from height 0 counts.

- **`A`** = whole days between the `sealed_at` of the Block that first
  contained an accepted Delta from this domain under its current identity
  and the `sealed_at` of Block N. A domain with no accepted Delta in that
  range has `A` = 0. Publisher-supplied `observed_at` is never used, so
  backdating a Delta cannot age a domain.
- **`base_u`** = `100 000 + ((900 000 × min(A, 730)) / 730)`, integer
  division, parenthesized as written. It rises linearly from 100 000
  (exactly the Provisional cap) at `A` = 0 to 1 000 000 at `A` ≥ 730.
- **`C`** = the number of distinct Normalized URLs (DC-1 §3.2) of this
  domain that have at least one `consistent` Audit Record — sealed above
  the domain's most recent identity reset and at a height ≤ N — for a
  content-bearing Delta (`new` or `update`) on that URL, capped at
  `C_cap` = 500. Audits of `attest` and `delete` Deltas never contribute.
  Counting distinct URLs rather than Records, and capping the count,
  prevents a high-volume Publisher from diluting penalties toward zero.
- **Confirmed Inconsistencies.** Only those whose confirming Audit Record
  is sealed above the domain's most recent identity reset and at a height
  ≤ N count. For each such Confirmed Inconsistency *i*: `s_i` ∈ {1 = minor
  divergence, 2 = misleading extract, 3 = fabricated content} is computed
  from its confirming Records (§7) by the §7 severity table —
  independently of whether any `sanction` Registry Update exists for it —
  and `t_i` is the whole days between the `sealed_at` of the **confirming
  Block** and the `sealed_at` of Block N. The confirming Block is the one
  sealing the **earliest Audit Record, in Log order (ascending Block
  height, then ascending Entry index within a Block), at which §5's
  confirmation predicate is first satisfied** for that Delta: the same
  height that fixes `t_i` is the height at which the Confirmed
  Inconsistency begins contributing to `penalty_n`, whether or not the
  Aggregator ever files a `sanction` for it. Records beyond that one — a
  third or fourth `inconsistent` verdict — do not move the date, do not
  move `sim` (§7), and do not create a second Confirmed Inconsistency.
- **`decay(t)`** is read from the normative decay table
  ([`vectors/dc4/decay-table.json`](../vectors/dc4/decay-table.json)): an
  array of 1826 integers, `decay(t) = floor(exp(−t / 180) × 1e9)` — the
  decay scale 1e9 being 1 000 000 000 — indexed by whole days 0 … 1825,
  with `decay(t) = 0` for `t` > 1825. The table,
  not `exp()`, is normative; implementations MUST read it and MUST NOT
  recompute it at runtime. `decay(0)` = 1 000 000 000 and the table is
  strictly decreasing. Expiry at the horizon drops a residue of
  `decay(1825)` = 39 512 (3.95e-5 of full weight) to zero; that step can
  only raise a reputation, never lower one. The table is normative as
  *bytes*: SHA-256 of the file is
  `f0cd1eb48cbfb1647a083b4ba06e7f69e6c42d5b5f4bf8e4f42b97c6bfdf7dc1`, and
  an implementation carrying a table that does not hash to that value is
  non-conforming even if every entry looks plausible. Changing the table
  changes every reputation in the system and is a `parameter_change` (§9)
  like any other constant.
- **`penalty_n`** = `Σ s_i × decay(t_i)`, in exact integer arithmetic. The
  sum is over integers, so its value does not depend on summation order;
  implementations that publish intermediate sums SHOULD nevertheless
  accumulate in ascending `t_i`, ties broken by ascending byte order of
  the UTF-8 Delta ID of the inconsistent Delta, so that intermediates
  agree too.

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
identity**, not to a name. A Declaration that DC-1 §5.2 classifies as a
**fresh identity** — signed by neither a key of the previous Key Set nor a
key in the previous Declaration's `recovery_keys` — is an **identity
reset** at the height its Declaration Entry is sealed. Call that height
`R`; the domain re-enters Provisional, and from `R` onward:

- **`A`** is measured from the `sealed_at` of the first Block above `R`
  sealing an accepted Delta from the domain. Until such a Block exists,
  `A` = 0.
- **`C`** counts only distinct URLs whose qualifying `consistent` Audit
  Record is sealed above `R`. A URL audited before the reset does not
  count again unless it is audited again after it, and the pre-reset
  Records remain in the Log — they simply belong to the previous identity.
- **Penalties do not carry across a reset.** Confirmed Inconsistencies
  confirmed at or below `R` leave `penalty_n` entirely; only those
  confirmed above `R` count. A fresh identity starts clean, for exactly
  the reason `A` and `C` start at zero: it is a different party as far as
  the protocol can tell, and the Provisional cap — not inherited debt — is
  what bounds what it can claim.

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

1. **Ping quota** (DC-2 §4): `Q = 100 + ((10 000 × reputation_u) /
   1 000 000)` Pings per UTC day, integer division, parenthesized as
   written. The new-domain quota DC-2 §5 refers to is this formula at
   `reputation_u` = 100 000, i.e. **Q = 1100**.
2. **Sampling rate** `p_1e7` (§4), which takes `reputation_u` directly at
   the height §4 fixes.
3. **Inclusion latency**: `reputation_u` ≥ 500 000 → eligible for the next
   Block; below → eligible for the Block after the next (one full Block
   of delay).

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
   and Feed pulls are rejected (`403`, DC-2 §4) until `sanction_lift` or
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
exactly one row, whatever its audited Delta's change type.

| Condition | `severity` |
|---|---|
| 150 000 ≤ `sim` < 300 000 | 1 (minor divergence) |
| 50 000 ≤ `sim` < 150 000 | 2 (misleading extract) |
| `sim` < 50 000 | 3 (fabricated content) |

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
  `"recovery"` *records* the DC-1 §5.2 recovery window instead — that
  window opens at the `sealed_at` of the Block sealing the recovery
  Declaration itself, so it opens whether or not the notice is ever sealed
  — and is not subject to the appeal process below.
- Escalation criteria: level 1 at a single Confirmed Inconsistency; level
  2 at 3 within 90 days; level 3 at 10 within 90 days, or any severity-3;
  **level 4 at 3 severity-3 Confirmed Inconsistencies within 180 days, or
  a level-3 domain that accrues a further Confirmed Inconsistency**. Level
  4 is never conditioned on whether the Publisher appealed.
- **Every rung is derived, levels 3 and 4 included.** Once the escalation
  criteria above are met at some height N, the corresponding state is in
  force on recomputation from N's Block onward, whether or not the
  Aggregator has sealed a `sanction` recording it. For levels 1 and 2 this
  is what "follow automatically" above already says, and it is not
  optional: §4's sampling rate reads a level-1 sanction as an input, and
  §6.4 and DC-3 §7 read level 2 as one, so a rung that took effect only
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
  height without waiting on the Aggregator (DC-3 §7). This is also why the
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
  DC-1 §4 uses for a Delta ID and §5 for an Audit Record ID. An `appeal`
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
  `/.well-known/deltacommons/appeals/<notice-id-hex>.json` (DC-2 §3.3),
  where `<notice-id-hex>` is the 64-character hex digest of the notice's
  Registry Update ID. That is the publish-then-pull path every other
  Publisher artifact takes, and it is the only one still open to a domain
  whose ingestion a level-3 sanction has suspended: the Publisher MAY ping
  (DC-2 §4), but that domain's Pings are answered `403`, so DC-2 §3.3 puts
  the fetch on the Aggregator as a duty that no notification gates. The
  appeal exists from the moment it is served; the
  Aggregator's Entry records it rather than creating it, and any party can
  fetch the served copy and verify it for itself. An `appeal` is signed by
  the Publisher and MUST verify against the Key Set current at the
  `notice`'s Block — not the present one — so that a domain in key
  compromise or identity reset (DC-1 §5.2) can still appeal.
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
   field by which a publisher declares its own relevance (DC-1 §6). A
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
   through a logged entry stating its legal basis (DC-3 §6.2). The
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
number, as the decay table digest is (§6). Or its value is meaningful only
against another parameter, which is the case for `coverage_failures_max`:
it counts **Blocks**, so at the default hourly cadence 24 Blocks is a
tolerance of about one day in thirty, and halving `block_cadence_seconds`
halves that tolerance in wall-clock terms without anyone amending this
number. The coupling is stated rather than removed, and it binds the
cadence: a `parameter_change` to `block_cadence_seconds` is also a change
to how much shirking §4 tolerates, and MUST be weighed as both.

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
| `block_cadence_seconds` | ≥ 1 | a cadence of zero seals no Block, so nothing anchored to `sealed_at` — every window in this document — has a clock |
| `block_decompressed_cap_bytes` | ≥ 1024 | a Consumer MUST reject a frame declaring more than the cap without decompressing it (DC-3 §6), so below the octets an empty Block occupies no Block can be applied at all — and DC-3 §3.2 requires an Aggregator to be able to seal an empty Block as the chain's heartbeat |
| `extract_cap_bytes` | ≥ 2 | `JCS("")` is 2 octets, so below that even an empty `extract` exceeds the cap, every Payload fails DC-1 §3.6's size check, and no content-bearing Delta can ever be sealed |
| `links_cap_bytes` | ≥ 21 | `JCS({"total":0,"urls":[]})` is 21 octets and `links` is REQUIRED (DC-3 §6.1), so below that no conforming Payload exists and no content-bearing Delta can ever be sealed |
| `link_url_cap_bytes` | ≥ 14 | below the 14 octets of `JCS("https://a.b/")` — the serialization of the shortest Normalized URL (DC-1 §2) — no link can ever be declared, which removes the link dimension while leaving its verdicts defined — §5's `link_inconsistent` would then rest on a set nobody can populate |
| `summary_cap_bytes` | ≥ 12 | `JCS({"title":""})` is 12 octets and `title` is REQUIRED (DC-3 §6.1), so below that no conforming `summary` exists and no content-bearing Delta can ever be sealed |
| `feed_window` | ≥ 1 | a Feed that can hold no Delta ID leaves nothing discoverable to pull (DC-2 §3.2) |
| `recovery_window_days` | ≥ 1 | a zero-length window contains no Block, so no ordinary rotation is ever superseded and the recovery key stops being the answer to a stolen signing key (DC-1 §5.2, §8) |
| `sampling_floor` | ≥ 1 | at zero the clamp's own lower bound is zero, so a maximum-reputation domain is never selected at all (§4) |
| `sampling_ceiling` | ≥ 1 | at zero no Delta is ever selected by any Auditor, which voids every Audit Record before it is written and with it every confirmation, penalty and sanction — a more complete nullification than `confirm_auditors` = 1, which this section already forbids |
| `similarity_consistent` | ≥ 150 002 and ≤ 1 000 000 | below `similarity_variance_floor`'s own floor the `dynamic_variance` band is empty; above the micro-unit range no audit can ever be `consistent`, so `C` never grows and every domain stays Provisional for ever (§5, §6) |
| `similarity_variance_floor` | ≥ 150 001 and ≤ 300 000 | below, §7's severity-1 band is empty; above, a Confirmed Inconsistency between 300 000 and the new floor lands in no severity row at all (§5, §7) |
| `shingle_size` | ≥ 1 | a shingle length of zero leaves both shingle sets empty and §5's quotient undefined |
| `confirm_auditors` | ≥ 2 | one Auditor confirming itself is the whole of what §5's confirmation rule exists to prevent |
| `confirm_window_hours` | ≥ 1 | at zero a confirming Record must share its Block with the first, since `sealed_at` is strictly increasing (DC-3 §3.1) |
| `coverage_deadline_hours` | ≥ 1 | at zero the duty is discharged only by a Record sealed in the audited Block itself, so every Auditor fails every Block (§4) |
| `age_norm_days` | ≥ 1 | zero is a division by zero in `base_u` (§6.1) |
| `decay_constant_days` | ≥ 1 | zero is a division by zero in the decay table's own construction (§6.1) |
| `decay_horizon_days` | ≥ 1 | a horizon of zero expires every penalty after a single day |
| `penalty_weight` | ≥ 1 | at zero `penalty_n` leaves the formula entirely and no Confirmed Inconsistency costs anything (§6.2) |
| `c_cap` | ≥ 1 | at zero `C` is always zero, so no domain ever satisfies the `provisional_audits` gate and reputation is capped at the Provisional cap for ever (§6) |
| `appeal_window_days` | ≥ 1 | a window of zero days closes before the notice can be read, which is the whole of the due process levels 3 and 4 carry (§7) |
| `appeal_seal_days` | ≥ 1 | at zero the Aggregator must seal a received appeal in the Block that closes the window, so the state voids for reasons no Aggregator can avoid (§7) |
| `ruling_deadline_days` | ≥ 1 | at zero every level-3 and level-4 state voids at T, whatever the evidence (§7) |
| `param_grace_days` | ≥ 1 | at zero a parameter changes in the Block that announces it, and the notice period this very section rests on is gone |
| `payload_window_days` | ≥ 30 | below, a Mirror may drop what it dislikes and call the absence expiry (DC-3 §6.1) |
| `unauditable_horizon_days` | ≥ 7 | below, whether a URL is excluded turns on publication scheduling rather than on its `robots.txt` (§5) |
| `mirror_retention_days` | ≥ 51 | below, an appellant cannot fetch the Records its own sanction rests on (DC-3 §6) |
| `url_cap_bytes` | ≥ 14 | `JCS("https://a.b/")` is 14 octets — the serialization of the shortest Normalized URL that can exist — so below it no Delta can name any subject at all (DC-1 §2, §3.2) |

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
before the Block that could discharge it can be sealed;
`block_decompressed_cap_bytes` MUST NOT be below the size of the largest
Block the Aggregator seals, since only the pair decides whether any Block
is applicable; and the `mirror_retention_days` sum below. `links_cap_bytes`
MUST NOT be below `link_url_cap_bytes` + 21, the structural octets of
`JCS({"total":1,"urls":[…]})` around a single maximum-length URL literal —
below it a page whose first link is long declares an empty prefix the
budget rule then makes mandatory.

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
`quota_base` and `quota_slope` at zero silence the Ping path, which DC-2
§5's baseline polling exists to survive. And `latency_threshold_u` at
either extreme puts every domain on one side of a one-Block delay, which is
a policy rather than the absence of one.

`payload_window_days` carries a floor for the same reason. The window is
what makes a missing Payload evidence (DC-3 §6.1): shortened toward zero
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
makes an evidence bundle assemblable after the fact (DC-3 §6), and the
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
| Block sealing cadence | `block_cadence_seconds` | 1 hour | DC-3 §3.2 |
| Block decompressed size cap | `block_decompressed_cap_bytes` | 256 MiB | DC-3 §6 |
| `extract` size cap | `extract_cap_bytes` | 32768 octets of `JCS(extract)` | DC-1 §3.6 |
| `links` size cap | `links_cap_bytes` | 4096 octets of `JCS(links)` | DC-1 §3.6 |
| Link `url` size cap | `link_url_cap_bytes` | 2048 octets of `JCS(url)` per link | DC-1 §3.6 |
| `summary` size cap | `summary_cap_bytes` | 2048 octets of `JCS(summary)` | DC-1 §3.6 |
| `url` size cap | `url_cap_bytes` | 2048 octets | DC-1 §3.2 |
| Payload availability window | `payload_window_days` | 180 days | DC-3 §6.1 |
| Mirror Block retention floor | `mirror_retention_days` | 90 days | DC-3 §6 |
| Feed window | `feed_window` | 1000 IDs | DC-2 §3.2 |
| Clock skew allowance | `clock_skew_seconds` | 10 minutes | DC-1 §3.4 |
| Key Set cache TTL | `keyset_cache_ttl_seconds` | 24 hours | DC-1 §5.1 |
| Baseline feed poll interval | `baseline_poll_seconds` | 24 hours | DC-2 §5 |
| Sampling floor / ceiling (`p_1e7`) | `sampling_floor` / `sampling_ceiling` | 200 000 / 5 000 000 (reads as 0.02 / 0.50) | §4 |
| Sampling reputation slope | `sampling_slope` | 3 per micro-unit of reputation (reads as 0.30) | §4 |
| Coverage duty deadline | `coverage_deadline_hours` | 72 hours | §4 |
| `coverage_failures_max` | — | 24 Blocks per 30 days | §4 |
| Similarity thresholds (consistent / variance floor) | `similarity_consistent` / `similarity_variance_floor` | 600 000 / 300 000 micro-units (reads as 0.60 / 0.30) | §5 |
| Shingle size | `shingle_size` | 8 (words, or grapheme clusters on §5's short-text branch) | §5 |
| Unauditable horizon | `unauditable_horizon_days` | 30 days | §5 |
| Confirmation: auditors / window | `confirm_auditors` / `confirm_window_hours` | 2 / 72 hours | §5 |
| Age normalization | `age_norm_days` | 730 days | §6 |
| Reputation base at age 0 | — | 100 000 micro-units (= the Provisional cap) | §6 |
| Penalty decay constant (1/e) | `decay_constant_days` | 180 days (the true half-life is 180·ln2 ≈ 124.8 days) | §6 |
| Decay table horizon | `decay_horizon_days` | 1825 days | §6 |
| Decay table digest (SHA-256) | — | `f0cd1eb4…bfdf7dc1` | §6 |
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
| Recovery window | `recovery_window_days` | 7 days | DC-1 §5.2 |
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
- `aggregator_key_remove`, `auditor_remove`: `key_id`.
- `sanction`: `level` (1–4) and `severity` (1–3, §7); `evidence`
  (top-level, not `details`) MUST carry at least the two Audit Record IDs
  (§5) of the concurring, independent Auditors' Records that establish
  the Confirmed Inconsistency (§5's own minimum).
- `notice`: `kind` (`"sanction"` or `"recovery"`); a `"sanction"` notice
  additionally requires `reason`, `appeal_deadline`, and a top-level
  `evidence` naming what the notice is about; a `"recovery"` notice
  requires nothing further (DC-1 §5.2). `appeal_deadline` restates the
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
  withdrawn), `legal_basis`, and `jurisdiction` (DC-3 §6.2); `subject` is
  the Publisher's domain. All three are REQUIRED, because a withdrawal
  that named no Delta, no basis, or no demanding jurisdiction would be an
  unfalsifiable claim to have removed something — which is precisely what
  a quiet drop looks like.

`sanction_lift` and `coverage_attestation` carry an unconstrained `details`
object, and an `appeal`'s is unconstrained beyond the `notice` it MUST
name; §4 and §7 govern the rest of their content in prose, not the schema.
The same is true of any action a future major revision adds.

No `details` object, constrained or not, may carry a bare digest of
Payload content. A content-derived value anywhere in this suite is
committed under the Payload salt (§5, DC-1 §3.6) or it is not carried at
all (DC-3 §6.2). An unconstrained `details` is unconstrained in shape, not
licensed to reintroduce the confirmability the salt exists to destroy, and
a party replaying the Log MUST reject a Registry Update that carries one.

**No `details` object, constrained or not, and no `evidence` element, may
carry personal data.** The rule is written over the position rather than
over a list of field names, because the position is what makes it
necessary: everything a Registry Update carries is sealed, permanent, and
outside the withdrawal mechanism entirely (DC-3 §6.2), so any of it recited
once is recited for ever. It binds whoever writes the value, not only the
Aggregator — a `payload_withdrawal`'s `legal_basis`, a `notice`'s `reason`
and an `appeal_ruling`'s `reasoning` are the Aggregator's, and an
`appeal`'s and a `sanction_lift`'s `details` are the Publisher's, written
by the party with the strongest reason to recite a data subject's
circumstances and the least reason to have read this paragraph. A
`legal_basis` names a legal ground, not the person invoking it; a `reason`,
a `reasoning` and an appeal's grounds name their evidence by Audit Record
ID (§5) or Registry Update ID (§7) rather than reciting what was found.
Nothing in this suite requires identifying a data subject in order to
record why an action was taken or contested (§11).

## 10. Security Considerations

- **Audit selection is unforgeable and unsteerable.** Who audits what is
  fixed by each Auditor's own VRF over the Block Hash (§4), so no party
  chooses it. The Aggregator holds no Auditor key: grinding `sealed_at`,
  Entry order, or Block membership — all of which it does control — moves
  every Auditor's selection at once and in no direction it can predict, so
  the sub-two-trial steer that a single log-wide draw permitted no longer
  exists. The Auditor cannot steer its own draw either, because `beta` is
  uniquely determined by its key and the Block. Auditing *outside* the VRF
  set is detectable by anyone: the published `pi` recomputes the set, and a
  Record for a Delta outside it is void (§3) and is evidence for
  `auditor_remove`. Confirmation still requires *independent* Auditors, and
  the Aggregator MAY still commission overlapping audits and compare
  outcomes; systematic divergence by one Auditor remains grounds for
  `auditor_remove`, in the log with evidence like any sanction.
- **Shirking is detectable from the Log alone, whole or partial.** For every
  Block sealed in an Auditor's admitted window the Log must hold that
  Auditor's `vrf_proof` — inside an Audit Record for each selected Delta,
  or inside a `coverage_attestation` where the VRF selected nothing (§4).
  An Auditor that audits nothing and attests nothing is therefore not merely
  suspected but demonstrated, by any party replaying the Log, with no
  challenge protocol, no side channel, and no cooperation from the Auditor.
  Since the proof is published either way, an Auditor cannot hide behind "my
  VRF selected nothing": that claim is a signed, falsifiable statement whose
  proof anyone can check against the Block Hash. Nor can it shirk *part* of
  a Block and buy silence with a single Record: the proof it publishes in
  that Record recomputes the whole selection set, so covering some selected
  Deltas and not others is a failure for the Block, not partial credit (§4).
- **Reputation gaming via attest-farming.** A domain cannot inflate `C`
  by emitting torrents of trivially-true `attest` Deltas: audits of
  `attest` and `delete` Deltas never contribute to `C` (§6). Nor can it
  inflate `C` by re-publishing the same URL: `C` counts *distinct*
  Normalized URLs with a `consistent` audit, capped at 500, so the only
  way to dilute a penalty is to publish, and keep passing audits on, many
  different pages — exactly the thing that is expensive to fake at scale.
- **Domain resale.** Reputation attaches to key continuity, not the name.
  A Declaration signed by neither the previous Key Set nor the previous
  `recovery_keys` is a fresh identity: `A` and `C` reset and the domain
  re-enters Provisional (§6.3, DC-1 §5.2). Buying an aged domain, or its
  hosting, buys no standing. An ordinary rotation and a recovery rotation
  both preserve standing, because both prove possession of a key the prior
  identity chose in advance — recovery keys exist precisely so that losing
  a signing key does not force a Publisher to forfeit its history, and a
  thief holding only a signing key cannot outrun them (DC-1 §5.2).
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
  which every observer sees identically — DC-3 §5's proof needs two
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
  directly, or mirrored where the audited Delta is a `delete` — not
  asserted by the Aggregator, and §6.1 counts
  every Confirmed Inconsistency's penalty from its confirming Block onward
  regardless of whether a `sanction` Registry Update ever names it. A
  party recomputing reputation therefore arrives at the same `penalty_n`
  whether the Aggregator inflates a `details.severity` past what the
  Records show (the mismatched `sanction` is rejected and the table's
  value used instead), invents a `sanction` with no real evidence behind
  it (rejected outright — §5's predicate fails), or never records one at
  all (the penalty applies anyway, computed directly from the Records). A
  captured Aggregator has no lever over the reputation consequence of
  evidence that is already public.
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

## 11. Privacy Considerations

Audit Records expose fetch timing and, via `evidence_commitment`, WARC
captures of public pages; the DC-1 §9 rule (nothing beyond what the page
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
party and the content is the destroy obligation of DC-3 §6.2, a duty on a
named holder rather than a property of the format. Both values survive
deliberately, because reputation is a pure function of Log history (§6)
and must remain recomputable after a withdrawal that the audited domain
did not control.

A third residue is everything a Registry Update carries. Its `details` and
its `evidence` are sealed in the Log, permanent, and outside the withdrawal
mechanism entirely — the same class as a Delta's `meta` (DC-1 §3.7) — and
§9.1 therefore forbids personal data in any of it, whether the schema
constrains that field or leaves it open, and whoever writes it. The
enumeration matters less than the position, but the positions are worth
naming: the Aggregator writes a `payload_withdrawal`'s `legal_basis`, a
`notice`'s `reason` and an `appeal_ruling`'s `reasoning`; the Publisher
writes an `appeal`'s and a `sanction_lift`'s `details`, and an appeal is
the one place in this suite where a party is contesting a finding about
itself and is most likely to recite a person's circumstances in doing so.
A `legal_basis` names a legal ground, not the person invoking it; a
`reason`, a `reasoning` and an appeal's grounds name their evidence by
Audit Record ID (§5) or Registry Update ID (§7) rather than reciting what
was found. Nothing in this suite requires identifying a data subject in
order to record why an action was taken or contested, and doing so would
seal into the Log precisely the data an erasure is meant to remove.

The Auditor's WARC capture is a full copy of the page, and it is held
off-Log. DC-3 §6.2 requires the Auditor to destroy it, along with the
Payload and its salt, when the Payload is withdrawn. That is an obligation
on the Auditor, enforceable the way the Aggregator's and the Mirrors' are
and no further: an Auditor that defies it retains both the capture and the
salt, and could then confirm a candidate text. The protocol makes that a
violation with a named holder rather than a structural inevitability,
which is the most a specification can do about a copy in someone else's
hands.

## 12. Conformance Checklist

**Auditor:**

- [ ] Audits exactly its VRF-selected set and publishes `vrf_proof` (§4)
- [ ] Meets the coverage duty for every Block sealed while admitted, within
      72 hours of `sealed_at` — a Record for **every** selected Delta, or a
      `coverage_attestation` when its VRF selected nothing (§4)
- [ ] Resolves the Reference Payload as of `audited_delta`, not as of the
      URL's current state, and verifies it against its own Delta's
      commitment before comparing anything (§5)
- [ ] Serves a Declaration at its own `auditor_id` carrying the admitted
      key, writes that same hostname — the one its `auditor_admit` names —
      in every Record, and never audits a Delta from a Publisher domain
      sharing a two-label suffix with it (§3)
- [ ] Computes similarity with the normative §5 metric — NFC, default full
      case-folding, untailored UAX #29 segmentation — and reads the verdict
      from the effective similarity, mirrored for a `delete` (§5)
- [ ] Applies DC-2 §11's extraction procedure, unchanged, to its own
      fetch of the Reference Payload's page when checking the declared
      `links` member (§5, DC-2 §11)
- [ ] Emits `unreachable` (never `inconsistent`) for failed fetches, and
      sets `robots_excluded` when and only when `robots.txt` is the reason
      — including where the file discriminates between admitted Auditors,
      whatever access it grants this one (§5, DC-2 §5)
- [ ] Emits `not_auditable` (never `inconsistent` or `unreachable`) for a
      withdrawn, unobtainable or empty-extract Reference Payload, and
      treats it as discharging the coverage duty (§4, §5)
- [ ] Signs Records with a key admitted at the `sealed_at` of the Block
      carrying the Record, and fetches inside the interval §3 fixes — with
      the coverage carve-out: an Auditor removed after a Block was sealed
      but before that Block's coverage deadline still discharges its §4
      duty by publishing under the key admitted at the *audited* Block's
      `sealed_at`, and such a Record proves the duty was met without
      entering any domain's reputation (§3, §4)
- [ ] Commits the response, its own extraction and its WARC capture under
      the Reference Payload's salt — never as bare digests (§5)
- [ ] Preserves the WARC capture matching `evidence_commitment`, and
      destroys it, the Reference Payload and the salt on withdrawal
      (§5, DC-3 §6.2)

**Aggregator (governance side):**

- [ ] Admits/removes Auditors only via logged Registry Updates, after
      verifying the Declaration at the Auditor's own domain, and never
      under a hostname that fails §3's independence test against its own
      `log_id` (§3)
- [ ] Excludes unauditable URLs from materialization for as long as §5's
      predicate holds — two independent `robots_excluded` Records inside
      the horizon, cleared only by a successful audit from an Auditor
      independent of both, or by their ageing out (§5, DC-3 §7)
- [ ] Removes an Auditor past `coverage_failures_max` by `auditor_remove`
      naming the failed Blocks — recording an exclusion that §4 already
      derives, never creating it (§3, §4)
- [ ] Applies sanctions only per the §7 ladder — evidence for every
      sanction, notice and an appeal window for levels 3–4
- [ ] Fetches every sanction notice's appeal path (DC-2 §3.3) and seals
      the `appeal` it finds, or an `"unappealed"` `appeal_ruling`, by the
      §7 sealing deadline — and rules on a sealed appeal within the ruling
      deadline (§7)
- [ ] Never suspends ingestion for a Provisional domain; only
      Sanctioned Quarantine or delisting rejects a Ping or pull (§6, §7)
- [ ] Enforces the §8 invariants unconditionally
- [ ] Changes parameters only via `parameter_change` with the grace
      period (§9)

**Any party recomputing reputation:**

- [ ] Reproduces §6 exactly (constants from the Parameter Registry as of
      the evaluated block height)
- [ ] Uses integer arithmetic and the normative decay table only (§6)
- [ ] Derives `A` and every `t_i` from Block `sealed_at`, never from
      `observed_at` or wall clock time (§6.1)
- [ ] Verifies VRF proofs before counting a Record (§4)
- [ ] Counts a Record only when its Auditor's key was admitted at its own
      Block's `sealed_at`, its `auditor_id` matches that admission's
      `subject`, its `fetched_at` lies in §3's interval, and the audit was
      not a self-audit (§3)
- [ ] Counts only admitted-Auditor Records (§3) and only Confirmed
      Inconsistencies, confirmed by independent Auditors inside the
      `sealed_at` window (§3, §5)
- [ ] Stops counting the Records of an Auditor in coverage failure at
      their own Block's `sealed_at`, whether or not an `auditor_remove`
      was ever sealed, and counts them again once the failures age out of
      the 30-day window (§3, §4)
- [ ] Excludes `attest` and `delete` audits from `C`, counts distinct
      Normalized URLs, and applies `C_cap` (§6.1)
- [ ] Applies the Provisional cap as a ceiling, not a floor (§6.2), and
      resets `A`/`C` only for a fresh identity — never for an ordinary or
      recovery rotation (§6.3)
- [ ] Recomputes severity from evidence and rejects unsupported sanctions (§7)
- [ ] Counts every Confirmed Inconsistency's penalty from its confirming
      Block onward, independent of whether a `sanction` Registry Update
      exists for it (§6.1, §7)
- [ ] Derives the level-3 and level-4 sanction *states* from the §7
      escalation criteria at the height they are met, whether or not the
      Aggregator sealed the `notice` and `sanction` that record them, and
      lifts each at the height a `sanction_lift`, an `"overturned"`
      `appeal_ruling`, a lapsed ruling deadline, or a lapsed
      appeal-sealing deadline takes effect (§7, DC-3 §7)
- [ ] Runs every window from the `sealed_at` of the Block sealing the
      Entry that opens it — the appeal window from the `notice`'s Block,
      the recovery window from the recovery Declaration's own (DC-1 §5.2)
      — and never from an `effective_at` (§3, §7)
- [ ] Treats an `appeal_ruling` of `"unappealed"` whose own Block
      `sealed_at` precedes the close of that notice's appeal window as
      absent, so it discharges nothing and T lapses against it (§7)
- [ ] Keeps that derivation to the sanction's state and never lets an
      appeal, a lift or a lapsed deadline touch `penalty_n`, which §6.1
      derives from the evidence alone (§6.1, §7)

## Appendix A. Worked Sampling Example

Real values, computed by `tools/gen_vectors.py` and machine-checked by
`tools/validate_examples.py` (`vectors:dc4-sampling`). The source of truth
is [`vectors/dc4/sampling.json`](../vectors/dc4/sampling.json); the test
key is the DC-1 vector keypair (`vectors/dc1/keypair.json`, seed
`000102…1f` — **never use it in production**).

| Field | Value |
|---|---|
| Ciphersuite | `ECVRF-EDWARDS25519-SHA512-TAI` (`suite_string` `0x03`) |
| Auditor public key (base64url) | `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg` |
| Block Hash of *B* | `sha256:0336a883ede9f0059239ac30649b7be91e4d5fef6b2bc2c938f3d32bbdb14809` |
| `alpha` (32 octets, hex) | `0336a883ede9f0059239ac30649b7be91e4d5fef6b2bc2c938f3d32bbdb14809` |
| `pi` = `vrf_proof` (80 octets) | `2b1c91a879cb2bcfd0f87420fc17a2c213ea9a44e39371c7dc5b7882b71b2af5`<br>`9282b4cd8708ada538a34273358d60a7a2d7100b8114be31055e28db5dffbc14`<br>`c87de363c1ab0fe4370e9a01e4b99e0e` |
| `beta` (64 octets) | `6a14e671c3fa9e262a0c398a8e4660f842a167f57f9e10b0dccc264c319b1379`<br>`bf1903fc33d2ac1ca0982890a27a10bcd5fdbbe8c4bf481f68ba5e1a9e6048f5` |
| Delta ID of Entry 0 | `sha256:6cac5bdd5e1c39278b73552eb0ef84ce3460c1778061443c2a9238a659a85120` |
| `SHA-256(beta ‖ Entry 0)[0..8]` | `6aeb8247400b4a5b` |
| `D`(Entry 0) | `7704394830076136027` |
| Delta ID of Entry 2 | `sha256:8d5ccbbb940151aef6a885b1d6a290265651b3029392b501d0892b566077be53` |
| `SHA-256(beta ‖ Entry 2)[0..8]` | `2657a087bd2e2835` |
| `D`(Entry 2) | `2762853401270036533` |

Note that `alpha` is the Block Hash's 32 decoded octets, while the Delta ID
enters the draw as the UTF-8 bytes of the whole string, `sha256:` prefix
included — the two are deliberately different and an implementation that
confuses them will produce a different, wrong selection set.

Selection outcomes, by the §4 integer test `D × 10^7 < p_1e7 × 2^64`. Both
Deltas are real Entries of the same Block drawn against the same `beta`;
the two domains differ only in reputation:

| Delta | `reputation_u` | `p_1e7` | `D × 10^7` | `p_1e7 × 2^64` | Selected? |
|---|---|---|---|---|---|
| Entry 0 | 100 000 (Provisional) | 2 900 000 | 7.704e25 | 5.350e25 | no |
| Entry 0 | 900 000 (established) | 500 000 | 7.704e25 | 9.223e24 | no |
| Entry 2 | 100 000 (Provisional) | 2 900 000 | 2.763e25 | 5.350e25 | **yes** |
| Entry 2 | 900 000 (established) | 500 000 | 2.763e25 | 9.223e24 | no |

The two product columns are shown rounded for reading; the exact integers
are in the vector, and an implementation MUST compare the exact ones. Note
what the third row costs the Provisional domain: the same Delta that an
established domain's rate leaves alone is audited at 0.29. A different
Auditor, holding a different key, gets a different `beta` over the same
Block and therefore an independently drawn selection set.

## Appendix B. Worked Reputation Example

Real values, computed by `tools/gen_vectors.py` and machine-checked by
`tools/validate_examples.py` (`vectors:dc4-reputation`,
`vectors:dc4-decay-table`). The source of truth is
[`vectors/dc4/reputation.json`](../vectors/dc4/reputation.json) and
[`vectors/dc4/decay-table.json`](../vectors/dc4/decay-table.json). Every
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
`vectors/dc4/reputation.json` is §4's sampling rate computed by §4's own
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
- DC-1: Delta Format & Identity — key rotation, scope rule, §6 absence
- DC-2: Site Publication — quotas, hints, robots.txt boundary
- DC-3: Commons Log & Distribution — entry envelope, checkpoints,
  immutability, Block Hash (DC-3 §3.1)
