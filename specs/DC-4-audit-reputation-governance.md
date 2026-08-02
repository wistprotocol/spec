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
- **Confirmed Inconsistency**: ≥ 2 independent Auditors returning
  `inconsistent` for the same Delta within 72 hours (§5).
- **Sanction**: a graduated, logged penalty against a domain (§7).
- **Parameter Registry**: the versioned table of every numeric constant
  in the suite (§9).
- **Reputation**: the pure function of log history defined in §6.
- **Quarantine**: the capped-reputation state of new or reset domains (§6).

Every signed object in this document carries `dc_version` (DC-1 §3.1)
and the DC-1 §4 signature block (`key_id`, `alg`, `value`).

## 3. Auditors

Auditors are admitted by an `auditor_admit` Registry Update (schema:
[`schemas/registry-update.schema.json`](../schemas/registry-update.schema.json))
whose `details` carry the Auditor's `key_id` and raw Ed25519 `public_key`,
and removed by `auditor_remove`. Both are signed by the Aggregator and,
like everything else, live in the log — the roster of who may audit, and
since when, is public and permanent.

An Audit Record signed by a key not admitted at the Record's `fetched_at`
MUST be rejected by validators recomputing reputation.

Aggregator keys are admitted and retired by the `aggregator_key_add` /
`aggregator_key_remove` actions defined in DC-3 §3.4; their `details`
sub-schema is specified in §9.1.

## 4. Audit Sampling

Sampling MUST be deterministic and unpredictable before sealing:

> A Delta in Block *B* is selected for audit if and only if
> `HMAC-SHA256(key = raw Block Hash of B, message = Delta ID string)`,
> interpreting the first 8 bytes of the MAC as a big-endian integer
> divided by 2^64, is **less than** `p(domain)`, where
>
> `p(domain) = clamp(0.02 + 0.30 × (1 − reputation), 0.02, 0.50)`

Because the Block Hash does not exist until the Block is sealed, no
Publisher can know at submission time whether a Delta will be audited;
because it is public afterward, anyone can verify that Auditors audited
exactly what the rule selected — no more (harassment) and no less
(favoritism).

**Worked example** (test vectors, DC-1/DC-3 appendices; computed by
`tools/gen_vectors.py`): Block Hash
`1e0eb04676c1f4de91a5a1ace6252a0d9baf4c1a78992e13ff845dcdb13edc7f`,
Delta ID
`sha256:e3ba905f6a994d67e5286ca3264c894a72283c2bdaf07b4a5600cdd0000187b1`.
First 8 MAC bytes: `a082cb92882f0e16` → draw = `0.6269957764`. For a
quarantined domain (reputation 0.10): p = 0.290 → 0.6270 ≥ 0.290, **not
selected**. For a reputable domain (0.90): p = 0.050 → **not selected**.
A draw below the threshold would select the Delta for audit.

## 5. Verdicts and Tolerance

An Audit Record's fields: `audited_delta` (the Delta ID under audit),
`auditor_id` (the Auditor's hostname identity), `fetched_at` (when the
Auditor fetched the URL), `response_hash` (SHA-256 of the raw response
body), `ref_extract_hash` (SHA-256 of the Auditor's own reference
extraction), `similarity` (the §5 metric value), `verdict`, and
`evidence` (`warc:sha256:` + hash of the WARC capture, which the Auditor
MUST preserve). `response_hash`, `ref_extract_hash`, `similarity`, and
`evidence` are REQUIRED whenever the fetch succeeded, and omitted for
`unreachable`.

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

**Quarantine:** while `A < 30` or `C < 10`, reputation is capped at
0.10. A domain whose Key Set is replaced without a valid rotation
signature (DC-1 §5.2) resets `A` and `C` to zero and re-enters
Quarantine.

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
3. **Quarantine** — re-entry into the §6 cap.
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
  own domain key (the one class of Registry Update not signed by the
  Aggregator).
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
| Similarity thresholds (consistent / variance floor) | 0.60 / 0.30 | §5 |
| Shingle size | 8 words | §5 |
| Confirmation: auditors / window | 2 / 72 hours | §5 |
| Age normalization | 730 days | §6 |
| Penalty half-life divisor | 180 days | §6 |
| Penalty weight | 5 | §6 |
| Quarantine gates (age / consistent audits) | 30 days / 10 | §6 |
| Quarantine reputation cap | 0.10 | §6 |
| Ping quota base / slope | 100 / 10000 per day | §6 |
| Inclusion latency threshold | reputation 0.5 | §6 |
| Escalation: level 2 / level 3 | 3 in 90 days / 10 in 90 days or severity 3 | §7 |
| Appeal window | 14 days | §7 |
| Recovery window | 7 days | DC-1 §5.2 |
| Parameter change grace period | 7 days | §9 |

## 10. Security Considerations

- **Auditor collusion.** Confirmation requires *independent* Auditors,
  and Auditors are themselves auditable: the Aggregator MAY commission
  overlapping audits of the same Delta by disjoint Auditor sets and
  compare outcomes; systematic divergence by one Auditor is grounds for
  `auditor_remove`, in the log with evidence like any sanction.
- **Reputation gaming via attest-farming.** A domain cannot inflate `C`
  by emitting torrents of trivially-true `attest` Deltas: audits of
  `attest` Deltas never increment `C` (§6). Only content-bearing Deltas
  that survive audit build reputation, and those are exactly the Deltas
  that are expensive to fake at scale.
- **Domain resale.** Reputation attaches to key continuity, not the
  name: a Key Set replaced without rotation signature resets to
  Quarantine (§6, DC-1 §5.2). Buying an aged domain buys no standing.
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

- [ ] Audits exactly the Deltas the §4 rule selects — no more, no fewer
- [ ] Computes similarity with the normative §5 metric and thresholds
- [ ] Emits `unreachable` (never `inconsistent`) for robots.txt-forbidden
      or failed fetches
- [ ] Signs Records with a key admitted at `fetched_at` (§3)
- [ ] Preserves WARC evidence matching the `evidence` hash

**Aggregator (governance side):**

- [ ] Admits/removes Auditors only via logged Registry Updates (§3)
- [ ] Applies sanctions only per the §7 ladder, with notice, evidence,
      and appeal window
- [ ] Enforces the §8 invariants unconditionally
- [ ] Changes parameters only via `parameter_change` with the grace
      period (§9)

**Any party recomputing reputation:**

- [ ] Reproduces §6 exactly (constants from the Parameter Registry as of
      the evaluated block height)
- [ ] Counts only admitted-Auditor Records (§3) and only Confirmed
      Inconsistencies (§5)
- [ ] Excludes `attest` audits from `C` (§6)

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- [RFC 2104] HMAC: Keyed-Hashing for Message Authentication
- DC-1: Delta Format & Identity — key rotation, scope rule, §6 absence
- DC-2: Site Publication — quotas, hints, robots.txt boundary
- DC-3: Commons Log & Distribution — entry envelope, checkpoints,
  immutability
