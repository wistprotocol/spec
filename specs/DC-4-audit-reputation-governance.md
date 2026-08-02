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
  `inconsistent`, `unreachable`, or `dynamic_variance`.
- **VRF Proof**: the 80-octet `pi_string` an Auditor produces over a Block
  Hash with its own key under ECVRF-EDWARDS25519-SHA512-TAI ([RFC 9381]),
  carried in every Audit Record as `vrf_proof`. It lets anyone recompute
  that Auditor's selection set for that Block, and only that Auditor
  produce it (§4).
- **Confirmed Inconsistency**: ≥ 2 independent Auditors returning
  `inconsistent` for the same Delta within 72 hours (§5).
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
whose `details` MUST carry the Auditor's `key_id` and its raw Ed25519
`public_key` (base64url, 32 octets unpadded), and removed by
`auditor_remove`. Both are signed by the Aggregator and, like everything
else, live in the log — the roster of who may audit, and since when, is
public and permanent.

That one `public_key` serves both purposes: it verifies the Auditor's
Record signatures **and** it is the VRF public key against which its
`vrf_proof` is checked (§4). ECVRF-EDWARDS25519-SHA512-TAI and Ed25519
share the [RFC 8032] key format, so no second key is admitted, and there is
no way for an Auditor to sign under one identity while drawing its audit
assignments under another.

An Audit Record signed by a key not admitted at the Record's `fetched_at`
MUST be rejected by validators recomputing reputation. So MUST a Record
whose `vrf_proof` does not verify under that key over the audited Block's
Block Hash, and one whose `audited_delta` is not in the selection set that
proof determines (§4).

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

    draw(d) = first 8 octets of SHA-256(beta || d.delta_id_utf8),
              read big-endian, divided by 2^64
    draw(d) < p(domain(d))
    p(domain) = clamp(0.02 + 0.30 x (1 - reputation), 0.02, 0.50)

where `beta` is those 64 raw octets, `d.delta_id_utf8` is the UTF-8
encoding of the full Delta ID string including its `sha256:` prefix,
`domain(d)` is the domain of the Publisher whose key signed *d*, and
reputation is that domain's §6 reputation at height *B* − 1 — the state of
the log immediately before *B* was sealed, which for Block 0 is the empty
log — evaluated with the §9 constants in force at *B*'s `sealed_at`. If a
level-1 sanction (§7) is in force against `domain(d)` at that same height,
`p(domain(d))` is 0.50 instead of the clamp above; that is the only thing
that displaces the formula.

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

**Coverage duty.** For every Delta its VRF selects, an Auditor MUST publish
either an Audit Record or, when it cannot fetch at all, a Record with
verdict `unreachable`, within 72 hours of the Block's `sealed_at`. The duty
attaches to every Block sealed while the Auditor is admitted, and to no
other Block. Because `pi` pins the selection set exactly, failure is an
objective and recomputable fact rather than a judgement.

The duty is verifiable in-band, because the VRF proof reaches the Log for
every Block whether or not anything was selected: for each sealed Block, an
Auditor MUST publish either at least one Audit Record carrying its
`vrf_proof` for that Block, or — when its VRF selects no Delta in that
Block — a `coverage_attestation` Registry Update carrying the same proof
and nothing else. An Auditor with neither, at the coverage deadline, has
failed its duty for that Block; an Auditor that fails it for more than
`coverage_failures_max` Blocks in any 30-day window (Parameter Registry;
default 24) is removed by `auditor_remove` (§3), whose `evidence` MUST name
the failed Blocks. Without the attestation, an Auditor that simply does
nothing would be indistinguishable from one whose VRF selected nothing.

`coverage_attestation` is the second class of Registry Update not signed by
the Aggregator (the first is `appeal`, §7): the Auditor signs it with its
own admitted key, and its `subject` is the Auditor's `auditor_id`.

Worked numbers for this section — real values from `vectors/dc4/sampling.json`
— are in the Appendix.

## 5. Verdicts and Tolerance

An Audit Record's fields: `audited_delta` (the Delta ID under audit),
`auditor_id` (the Auditor's hostname identity), `fetched_at` (when the
Auditor fetched the URL), `response_hash` (SHA-256 of the raw response
body), `ref_extract_hash` (SHA-256 of the Auditor's own reference
extraction), `similarity` (the §5 metric value), `verdict`, and
`evidence` (`warc:sha256:` + hash of the WARC capture, which the Auditor
MUST preserve), and `vrf_proof` (the §4 VRF Proof over the Block Hash of
the Block carrying the audited Delta, 80 octets as 160 lowercase hex
characters). The Record names no Block: the audited Block is the one Block
whose `publisher_delta` Entries carry `audited_delta`, which DC-3 §3.2
makes unique and permanent. `response_hash`, `ref_extract_hash`, `similarity`, and
`evidence` are REQUIRED whenever the fetch succeeded, and omitted for
`unreachable`; `vrf_proof` is REQUIRED in every Record, `unreachable`
included, because it is what establishes the Auditor's right and duty to
have audited at all.

The web is not deterministic; byte equality is never the criterion.

The normative similarity metric is **Jaccard similarity over the sets of
word 8-grams (shingles)** of (a) the audited Delta's `extract` and (b)
the Auditor's own extraction of the fetched page, after Unicode NFC
normalization, lowercasing, and whitespace collapsing. Verdicts:

| Verdict | Condition |
|---------|-----------|
| `consistent` | similarity ≥ 0.60 |
| `dynamic_variance` | 0.30 ≤ similarity < 0.60 |
| `inconsistent` | similarity < 0.30 **and** the Delta's claimed content is absent from the fetched page |
| `unreachable` | network or HTTP failure fetching the URL |

For `attest` and `delete` Deltas (which carry no `extract`), the audit
checks the asserted state: `attest` is `consistent` if the page's current
extraction is ≥ 0.60-similar to the last content-bearing Delta in the
per-URL chain; `delete` is `consistent` if the URL returns 404/410 or no
longer carries indexable content.

`dynamic_variance` and `unreachable` are neutral: they never contribute
to sanctions. Auditor re-fetches of content URLs respect `robots.txt`
(DC-2 §5); a fetch forbidden by `robots.txt` is recorded `unreachable`.

**No single audit punishes.** An `inconsistent` verdict triggers
re-audit by additional independent Auditors. A **Confirmed
Inconsistency** exists only when ≥ 2 independent Auditors return
`inconsistent` for the same Delta within 72 hours of the first such
verdict. Only Confirmed Inconsistencies enter the reputation formula and
sanction ladder. This absorbs A/B tests, geo-variation, and legitimate
change between push and audit.

## 6. Reputation

Reputation is a pure, deterministic function of log history. Anyone
replaying the log MUST arrive at the same score for every domain at every
block height. All constants live in the Parameter Registry (§9).

For a domain at evaluation time *t*:

- `A` = days since the domain's first accepted Delta;
  `age_score = min(A / 730, 1)`.
- `C` = lifetime count of `consistent` Audit Records for the domain's
  **content-bearing** Deltas (`new`/`update`). Audits of `attest` Deltas
  do not increment `C` (§10).
- For each Confirmed Inconsistency *i*: severity `s_i` ∈ {1 = minor
  divergence, 2 = misleading extract, 3 = fabricated content} — assigned
  in the corresponding `sanction` Registry Update — and age `t_i` in
  days; `penalty = Σ s_i × exp(−t_i / 180)`.
- `reputation = age_score × (C + 1) / (C + 1 + 5 × penalty)`, clamped to
  [0, 1].

**Provisional:** while `A < 30` or `C < 10`, reputation is capped at
0.10. A domain whose Key Set is replaced without a valid rotation
signature (DC-1 §5.2) resets `A` and `C` to zero and re-enters
Provisional.

Provisional is not a penalty and MUST NOT block participation: a
Provisional domain pings, is pulled, has its Deltas sealed, and is audited
exactly like any other, at the reputation-derived quota and sampling rate.
It is the only way `A` and `C` can grow, and therefore the only path out of
Provisional; an implementation that suspends ingestion for Provisional
domains cannot bootstrap and is non-conforming.

Reputation governs exactly three things:

1. **Ping quota** (DC-2 §4): `Q = 100 + 10000 × reputation` Pings/day.
2. **Sampling rate** `p(domain)` (§4).
3. **Inclusion latency**: reputation ≥ 0.5 → eligible for the next
   Block; below → eligible for the Block after the next (one full Block
   of delay).

**Invariant: reputation is not a ranking signal.** It MUST NOT be used
by, exported to, or interpreted as an input for content relevance. It
measures *trustworthiness of process*, never *importance of content*.

## 7. Sanctions and Due Process

Sanctions are graduated, logged, evidence-bound Registry Updates
(`action: "sanction"`, `subject` = the domain, `evidence` = the Delta IDs
of the Audit Records establishing the Confirmed Inconsistencies):

1. **Intensified sampling** — `p(domain)` raised to its 0.50 maximum.
2. **Weight reduction** — the domain's Deltas are marked reduced-weight
   in materialized snapshots.
3. **Sanctioned Quarantine** — ingestion is suspended: the domain's Pings
   and Feed pulls are rejected (`403`, DC-2 §4) until `sanction_lift` or
   a successful appeal.
4. **Delisting** — the domain's Deltas are excluded from materialization
   (the log, as always, retains history).

Process requirements:

- A `notice` Registry Update MUST precede any sanction above level 1,
  naming the evidence and opening the appeal window. This applies to
  sanction notices (`details.kind` `"sanction"`); a `notice` with
  `details.kind` `"recovery"` opens the DC-1 §5.2 recovery window
  instead and is not subject to the appeal process below.
- The appeal window is 14 days from a sanction `notice`'s `effective_at`.
  The Publisher appeals with an `appeal` Registry Update signed by its
  own domain key (one of only two classes of Registry Update not signed by
  the Aggregator; the other is `coverage_attestation`, §4).
- An `appeal_ruling` closes the appeal with its reasoning in `details`.
- `sanction_lift` reverses a sanction; like everything else it is
  logged, permanent, and public.

The ladder is proportionate: level 1 is automatic on a single Confirmed
Inconsistency; levels 2–4 require escalation criteria in the Parameter
Registry (defaults: level 2 at 3 Confirmed Inconsistencies within 90
days; level 3 at 10 within 90 days or any severity-3; level 4 by
`appeal_ruling` only, never automatically).

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
3. **The past is not rewritable.** Sealed Blocks are immutable; history
   is corrected by appending, never by editing (DC-3 §3.2). Every
   mistake and its correction remain visible forever.
4. **The data stays open.** Public tier data is licensed under ODbL 1.0,
   irrevocably. Together with invariant 3, this guarantees forkability:
   if the institution operating the Aggregator is ever captured, the
   community can take the commons and leave.

## 9. Parameter Registry

Every numeric constant in the suite, with its normative default. Changes
are made by `parameter_change` Registry Updates and MUST have
`effective_at` ≥ 7 days after the Block's `sealed_at` (the grace period
— itself a parameter, changeable only by the same process).

| Parameter | Default | Defined in |
|---|---|---|
| Block sealing cadence | 1 hour | DC-3 §3.2 |
| Block decompressed size cap | 256 MiB | DC-3 §6 |
| `extract` size cap | 32768 bytes | DC-1 §3.6 |
| `summary` size cap | 2048 bytes | DC-1 §3.7 |
| Feed window | 1000 IDs | DC-2 §3.2 |
| Clock skew allowance | 10 minutes | DC-1 §3.4 |
| Key Set cache TTL | 24 hours | DC-1 §5.1 |
| Baseline feed poll interval | 24 hours | DC-2 §5 |
| Sampling floor / ceiling | 0.02 / 0.50 | §4 |
| Sampling reputation slope | 0.30 | §4 |
| Coverage duty deadline | 72 hours | §4 |
| Coverage failures allowed | 24 Blocks per 30 days | §4 |
| Similarity thresholds (consistent / variance floor) | 0.60 / 0.30 | §5 |
| Shingle size | 8 words | §5 |
| Confirmation: auditors / window | 2 / 72 hours | §5 |
| Age normalization | 730 days | §6 |
| Penalty half-life divisor | 180 days | §6 |
| Penalty weight | 5 | §6 |
| Provisional gates (age / consistent audits) | 30 days / 10 | §6 |
| Provisional reputation cap | 0.10 | §6 |
| Ping quota base / slope | 100 / 10000 per day | §6 |
| Inclusion latency threshold | reputation 0.5 | §6 |
| Escalation: level 2 / level 3 | 3 in 90 days / 10 in 90 days or severity 3 | §7 |
| Appeal window | 14 days | §7 |
| Recovery window | 7 days | DC-1 §5.2 |
| Parameter change grace period | 7 days | §9 |

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
- **Shirking is detectable from the Log alone.** Every Block in an
  Auditor's admitted window has exactly one of two artefacts in the Log
  bearing that Auditor's `vrf_proof`: an Audit Record, or a
  `coverage_attestation` where the VRF selected nothing (§4). An Auditor
  that audits nothing and attests nothing is therefore not merely suspected
  but demonstrated, by any party replaying the Log, with no challenge
  protocol, no side channel, and no cooperation from the Auditor. Since the
  proof is published either way, an Auditor cannot hide behind "my VRF
  selected nothing": that claim is now a signed, falsifiable statement whose
  proof anyone can check against the Block Hash.
- **Reputation gaming via attest-farming.** A domain cannot inflate `C`
  by emitting torrents of trivially-true `attest` Deltas: audits of
  `attest` Deltas never increment `C` (§6). Only content-bearing Deltas
  that survive audit build reputation, and those are exactly the Deltas
  that are expensive to fake at scale.
- **Domain resale.** Reputation attaches to key continuity, not the
  name: a Key Set replaced without rotation signature resets to
  Provisional (§6, DC-1 §5.2). Buying an aged domain buys no standing.
- **Sanction censorship.** An Aggregator cannot quietly suppress a
  sanction or an appeal: withholding log entries from some observers is
  equivocation, detectable and provable per DC-3 §5.
- **Griefing via false `inconsistent` verdicts.** A single hostile
  Auditor cannot harm anyone: confirmation requires a second independent
  `inconsistent` within 72 hours, and the sampling rule (§4) makes it
  verifiable that an Auditor had the right to audit at all.

## 11. Privacy Considerations

Audit Records expose fetch timing and, via `evidence`, WARC captures of
public pages; the DC-1 §9 rule (nothing beyond what the page itself
publishes) applies to evidence exactly as to extracts. Appeals and
rulings are public and permanent: the `notice` that opens a sanction
window MUST state this, so a Publisher weighs publicity before appealing.
Reputation scores are recomputable by anyone from public data; there is
no private reputation channel.

## 12. Conformance Checklist

**Auditor:**

- [ ] Audits exactly its VRF-selected set and publishes `vrf_proof` (§4)
- [ ] Meets the coverage duty for every Block sealed while admitted, within
      72 hours of `sealed_at` — a Record, or a `coverage_attestation` when
      its VRF selected nothing (§4)
- [ ] Computes similarity with the normative §5 metric and thresholds
- [ ] Emits `unreachable` (never `inconsistent`) for robots.txt-forbidden
      or failed fetches
- [ ] Signs Records with a key admitted at `fetched_at` (§3)
- [ ] Preserves WARC evidence matching the `evidence` hash

**Aggregator (governance side):**

- [ ] Admits/removes Auditors only via logged Registry Updates (§3)
- [ ] Applies sanctions only per the §7 ladder, with notice, evidence,
      and appeal window
- [ ] Never suspends ingestion for a Provisional domain; only
      Sanctioned Quarantine or delisting rejects a Ping or pull (§6, §7)
- [ ] Enforces the §8 invariants unconditionally
- [ ] Changes parameters only via `parameter_change` with the grace
      period (§9)

**Any party recomputing reputation:**

- [ ] Reproduces §6 exactly (constants from the Parameter Registry as of
      the evaluated block height)
- [ ] Verifies VRF proofs before counting a Record (§4)
- [ ] Counts only admitted-Auditor Records (§3) and only Confirmed
      Inconsistencies (§5)
- [ ] Excludes `attest` audits from `C` (§6)

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
| Block Hash of *B* | `sha256:d5eb92e066b027b78d8e872730bfc7e13667bc316856267ce211760b2f8f2c95` |
| `alpha` (32 octets, hex) | `d5eb92e066b027b78d8e872730bfc7e13667bc316856267ce211760b2f8f2c95` |
| `pi` = `vrf_proof` (80 octets) | `856e908f120334751af0091a2a608197268c57170671dd4a0c5776116f4081b1`<br>`6c9445faf5482a1b43ca6b87c259750924297cd4f88daf9892e24576b7d918e7`<br>`fefb066cf325db4855dd58c11c8f5e04` |
| `beta` (64 octets) | `cd753c76ddf3539df84f434de5d1638b84ab31c6195a36d4640d3378c6a5911e`<br>`840ebe82d2653c91785ae0fc8878f3b705f7cc1e5db0423b4d55896329529703` |
| Delta ID *d* | `sha256:e3ba905f6a994d67e5286ca3264c894a72283c2bdaf07b4a5600cdd0000187b1` |
| `SHA-256(beta ‖ d)[0..8]` | `fc5101e3231c0551` |
| `draw(d)` | `0.9856110744` |

Note that `alpha` is the Block Hash's 32 decoded octets, while the Delta ID
enters `draw` as the UTF-8 bytes of the whole string, `sha256:` prefix
included — the two are deliberately different and an implementation that
confuses them will produce a different, wrong selection set.

Selection outcome for this draw:

| Domain reputation | `p` | `draw < p`? | Outcome |
|---|---|---|---|
| 0.10 (Provisional) | 0.29 | no | not selected |
| 0.90 (established) | 0.05 | no | not selected |

A draw below the threshold would select the Delta for audit; a different
Auditor, holding a different key, gets a different `beta` over the same
Block and therefore an independently drawn selection set.

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- [RFC 8032] Edwards-Curve Digital Signature Algorithm (EdDSA) — the
  Ed25519 key format and edwards25519 group shared by signing and the VRF
- [RFC 9381] Verifiable Random Functions (VRFs) — ECVRF-EDWARDS25519-SHA512-TAI
  (§5.5); the normative source for §4's `prove`, `proof_to_hash` and `verify`
- DC-1: Delta Format & Identity — key rotation, scope rule, §6 absence
- DC-2: Site Publication — quotas, hints, robots.txt boundary
- DC-3: Commons Log & Distribution — entry envelope, checkpoints,
  immutability, Block Hash (§3.1)
