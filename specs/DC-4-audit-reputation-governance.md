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
whose `vrf_proof` does not verify — over the audited Block's Block Hash,
under the key admitted at that Block's `sealed_at` (§4) — and one whose
`audited_delta` is not in the selection set that proof determines (§4).

That first rejection is scoped to reputation and does not reach coverage:
an Auditor removed after a Block was sealed but before its coverage
deadline still discharges its §4 duty for that Block by publishing, because
coverage is anchored to `sealed_at` rather than to fetch time. Such a
Record proves the Auditor met its duty; it does not enter any domain's
reputation.

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
objective and recomputable fact rather than a judgement. An Auditor that
fails the duty for more than `coverage_failures_max` Blocks in any 30-day
window (Parameter Registry; default 24) is removed by `auditor_remove`
(§3), whose `evidence` MUST name the failed Blocks. Without the attestation
an Auditor that simply does nothing would be indistinguishable from one
whose VRF selected nothing, and coverage would rest on an out-of-band
challenge — which §1's "nothing exists outside the Log" forbids.

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

Every Audit Record has an **Audit Record ID**: `"sha256:" + hex(SHA-256(JCS(record)))`
— the record's inner object canonicalized and hashed under the same
content-addressing construction DC-1 §4 uses for a Delta ID. A `sanction`'s
`evidence` (§7) is a list of Audit Record IDs, so anyone can fetch exactly
the Records a sanction claims to rest on and recompute what they establish,
rather than trust the claim.

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
  from the confirming Audit Records by the §7 severity table —
  independently of whether any `sanction` Registry Update exists for it —
  and `t_i` is the whole days between the `sealed_at` of the **confirming
  Block** and the `sealed_at` of Block N. The confirming Block is the one
  sealing the **earliest Audit Record, in Log order (ascending Block
  height, then ascending Entry index within a Block), at which §5's
  confirmation predicate is first satisfied** for that Delta: the same
  height that fixes `t_i` is the height at which the Confirmed
  Inconsistency begins contributing to `penalty_n`, whether or not the
  Aggregator ever files a `sanction` for it. Records beyond that one — a
  third or fourth `inconsistent` verdict — do not move the date and do not
  create a second Confirmed Inconsistency.
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

Severity is **derived from the evidence, not chosen**. For a Confirmed
Inconsistency, let `sim` be the highest `similarity` among the confirming
`inconsistent` Audit Records:

| Condition | `severity` |
|---|---|
| 0.15 ≤ `sim` < 0.30 | 1 (minor divergence) |
| 0.05 ≤ `sim` < 0.15 | 2 (misleading extract) |
| `sim` < 0.05 | 3 (fabricated content) |

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
  and 4 MUST be preceded by a `notice` naming the evidence and opening the
  appeal window. Levels 1–2 need neither: their entire basis — the
  confirming Audit Records and the §7 severity table below — is already
  public and independently recomputable, so there is nothing a notice
  would let the Publisher contest that a replaying party cannot already
  verify for itself; this holds even for level 2's weight reduction, which
  affects standing without suspending ingestion. This applies to sanction
  notices (`details.kind` `"sanction"`); a `notice` with `details.kind`
  `"recovery"` opens the DC-1 §5.2 recovery window instead and is not
  subject to the appeal process below.
- Escalation criteria: level 1 at a single Confirmed Inconsistency; level
  2 at 3 within 90 days; level 3 at 10 within 90 days, or any severity-3;
  **level 4 at 3 severity-3 Confirmed Inconsistencies within 180 days, or
  a level-3 domain that accrues a further Confirmed Inconsistency**. Level
  4 is never conditioned on whether the Publisher appealed.
- The appeal window is 14 days from the `notice`'s `effective_at`. If it
  lapses with no `appeal`, the sanction takes effect unchanged; there is no
  silent reprieve and no penalty for silence.
- An `appeal` is signed by the Publisher and MUST verify against the Key
  Set current at the `notice`'s Block — not the present one — so that a
  domain in key compromise or identity reset (DC-1 §5.2) can still appeal.
- An `appeal_ruling` MUST be sealed within 30 days of the `appeal`
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
— itself a parameter, changeable only by the same process). The
**Identifier** column is the value `details.parameter` MUST carry
(schema: `schemas/registry-update.schema.json`, §9.1); a parameter with no
identifier is not independently amendable by `parameter_change` — it is
either a fixed structural definition or, for the decay table digest,
changed by publishing a new table (§6), never by a bare number.

| Parameter | Identifier | Default | Defined in |
|---|---|---|---|
| Block sealing cadence | `block_cadence_seconds` | 1 hour | DC-3 §3.2 |
| Block decompressed size cap | `block_decompressed_cap_bytes` | 256 MiB | DC-3 §6 |
| `extract` size cap | `extract_cap_bytes` | 32768 bytes | DC-1 §3.6 |
| `summary` size cap | `summary_cap_bytes` | 2048 bytes | DC-1 §3.7 |
| Feed window | `feed_window` | 1000 IDs | DC-2 §3.2 |
| Clock skew allowance | `clock_skew_seconds` | 10 minutes | DC-1 §3.4 |
| Key Set cache TTL | `keyset_cache_ttl_seconds` | 24 hours | DC-1 §5.1 |
| Baseline feed poll interval | `baseline_poll_seconds` | 24 hours | DC-2 §5 |
| Sampling floor / ceiling (`p_1e7`) | `sampling_floor` / `sampling_ceiling` | 200 000 / 5 000 000 (reads as 0.02 / 0.50) | §4 |
| Sampling reputation slope | `sampling_slope` | 3 per micro-unit of reputation (reads as 0.30) | §4 |
| Coverage duty deadline | `coverage_deadline_hours` | 72 hours | §4 |
| `coverage_failures_max` | — | 24 Blocks per 30 days | §4 |
| Similarity thresholds (consistent / variance floor) | `similarity_consistent` / `similarity_variance_floor` | 0.60 / 0.30 | §5 |
| Shingle size | `shingle_size` | 8 words | §5 |
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
| Appeal ruling deadline | `ruling_deadline_days` | 30 days | §7 |
| Recovery window | `recovery_window_days` | 7 days | DC-1 §5.2 |
| Parameter change grace period | `param_grace_days` | 7 days | §9 |

### 9.1. Registry Update `details` Contract

`schemas/registry-update.schema.json` constrains `details` per `action`,
mirroring §7 and §3:

- `aggregator_key_add`, `auditor_admit`: `key_id`, `alg` (`"Ed25519"`), and
  `public_key` (the raw Ed25519 public key, 43-character base64url).
- `aggregator_key_remove`, `auditor_remove`: `key_id`.
- `sanction`: `level` (1–4) and `severity` (1–3, §7); `evidence`
  (top-level, not `details`) MUST carry at least the two Audit Record IDs
  (§5) of the concurring, independent Auditors' Records that establish
  the Confirmed Inconsistency (§5's own minimum).
- `notice`: `kind` (`"sanction"` or `"recovery"`); a `"sanction"` notice
  additionally requires `reason` and `appeal_deadline` (date-time, the
  `effective_at` + the appeal window, §7); a `"recovery"` notice requires
  nothing further (DC-1 §5.2).
- `appeal_ruling`: `outcome` (`"upheld"` or `"overturned"`) and
  `reasoning`.
- `parameter_change`: `parameter`, one of the Identifier values in the
  table above, and `value` (a number); `effective_at` MUST be ≥ 7 days
  after the Block's `sealed_at`, as stated above.

`sanction_lift`, `appeal`, and `coverage_attestation` carry an
unconstrained `details` object; §4 and §7 govern their content in prose,
not the schema. The same is true of any action a future major revision
adds.

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
- **Sanction censorship.** An Aggregator cannot quietly suppress a
  sanction or an appeal: withholding log entries from some observers is
  equivocation, detectable and provable per DC-3 §5.
- **A sanction's severity can be neither fabricated nor suppressed.**
  Severity is derived from the confirming Audit Records' `similarity`
  values by the §7 table, not asserted by the Aggregator, and §6.1 counts
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
      72 hours of `sealed_at` — a Record for **every** selected Delta, or a
      `coverage_attestation` when its VRF selected nothing (§4)
- [ ] Computes similarity with the normative §5 metric and thresholds
- [ ] Emits `unreachable` (never `inconsistent`) for robots.txt-forbidden
      or failed fetches
- [ ] Signs Records with a key admitted at `fetched_at` (§3)
- [ ] Preserves WARC evidence matching the `evidence` hash

**Aggregator (governance side):**

- [ ] Admits/removes Auditors only via logged Registry Updates (§3)
- [ ] Applies sanctions only per the §7 ladder — evidence for every
      sanction, notice and an appeal window for levels 3–4
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
- [ ] Counts only admitted-Auditor Records (§3) and only Confirmed
      Inconsistencies (§5)
- [ ] Excludes `attest` and `delete` audits from `C`, counts distinct
      Normalized URLs, and applies `C_cap` (§6.1)
- [ ] Applies the Provisional cap as a ceiling, not a floor (§6.2), and
      resets `A`/`C` only for a fresh identity — never for an ordinary or
      recovery rotation (§6.3)
- [ ] Recomputes severity from evidence and rejects unsupported sanctions (§7)
- [ ] Counts every Confirmed Inconsistency's penalty from its confirming
      Block onward, independent of whether a `sanction` Registry Update
      exists for it (§6.1, §7)

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
| Delta ID of Entry 0 | `sha256:e3ba905f6a994d67e5286ca3264c894a72283c2bdaf07b4a5600cdd0000187b1` |
| `SHA-256(beta ‖ Entry 0)[0..8]` | `fc5101e3231c0551` |
| `D`(Entry 0) | `18181315245729645905` |
| Delta ID of Entry 3 | `sha256:d3a22b1cedf703c2efd115dc67c8d7ff44d409b820bf45ebc9e66a803ca1c903` |
| `SHA-256(beta ‖ Entry 3)[0..8]` | `373a3915f98ecf73` |
| `D`(Entry 3) | `3979555987279236979` |

Note that `alpha` is the Block Hash's 32 decoded octets, while the Delta ID
enters the draw as the UTF-8 bytes of the whole string, `sha256:` prefix
included — the two are deliberately different and an implementation that
confuses them will produce a different, wrong selection set.

Selection outcomes, by the §4 integer test `D × 10^7 < p_1e7 × 2^64`. Both
Deltas are real Entries of the same Block drawn against the same `beta`;
the two domains differ only in reputation:

| Delta | `reputation_u` | `p_1e7` | `D × 10^7` | `p_1e7 × 2^64` | Selected? |
|---|---|---|---|---|---|
| Entry 0 | 100 000 (Provisional) | 2 900 000 | 1.818e26 | 5.350e25 | no |
| Entry 0 | 900 000 (established) | 500 000 | 1.818e26 | 9.223e24 | no |
| Entry 3 | 100 000 (Provisional) | 2 900 000 | 3.980e25 | 5.350e25 | **yes** |
| Entry 3 | 900 000 (established) | 500 000 | 3.980e25 | 9.223e24 | no |

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
- DC-1: Delta Format & Identity — key rotation, scope rule, §6 absence
- DC-2: Site Publication — quotas, hints, robots.txt boundary
- DC-3: Commons Log & Distribution — entry envelope, checkpoints,
  immutability, Block Hash (§3.1)
