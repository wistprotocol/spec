# WIST-4: Governance & Parameters

**Status:** v1.0.0-draft · **Date:** 2026-09-16 · **License:** CC-BY 4.0

## 1. Introduction

WIST-4 defines the governance acts an Aggregator seals into its Log —
Aggregator key changes, parameter amendments and Payload withdrawals —
the Parameter Registry those amendments change, the registry of Label
names Labelers publish under (WIST-2 §3.3), and the constitutional
invariants no operator can amend. Governance acts are Log Entries
(WIST-3 §3.3), so any party replaying the Log derives the parameter
schedule, the key registry and every withdrawal from public, ordered
history. Nothing in this suite measures a Publisher's page or scores a
Publisher; ranking and trust are assessed at consumption, over the raw
inputs the Log carries
([ADR-0041](../decisions/0041-signed-publications.md)).

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as
shown here.

- **Registry Update**: the signed governance object this document defines,
  sealed as a `registry_update` Entry (WIST-3 §3.3). Its `action` selects
  one of the four governance acts of §3; `subject` names what the act is
  about; `details` is constrained per `action` by §5.1.
- **Registry Update ID**: `"sha256:" + hex(SHA-256(JCS(update)))` — the
  act's inner object canonicalized and hashed under the construction
  WIST-1 §4 uses for a Delta ID. Replay identifies every act by it (§5.1).
- **Parameter Registry**: the versioned table of every numeric constant
  in the suite (§5).
- **Label**: a signed statement by a Labeler about a subject outside its
  own authority — a Normalized URL or a Canonical Host — under a name
  from the Label Registry (§6, WIST-2 §3.3).
- **Labeler**: a Publisher whose publications include Labels (WIST-2
  §3.4). Every Publisher MAY label; a Labeler needs no admission.

Every signed object in this document carries `wist_version` (WIST-1 §3.1)
and the WIST-1 §4 signature block (`key_id`, `alg`, `value`).

## 3. Governance Acts

A Registry Update is an Envelope whose inner object is `update` (schema:
[`schemas/registry-update.schema.json`](../schemas/registry-update.schema.json)),
carrying `wist_version`, `action`, `subject`, `effective_at` and, where
the act's contract requires it, `details`. The four acts are:

- `aggregator_key_add` and `aggregator_key_remove` — the Aggregator's own
  signing keys, valid at a height as WIST-3 §3.4 defines.
- `parameter_change` — an amendment to one Parameter Registry value,
  in force from its `effective_at` under §5.
- `payload_withdrawal` — the removal of one Payload from distribution
  under WIST-3 §6.2.

Every act is signed by the Aggregator under a Log key valid at the act's
Block (WIST-3 §3.4). `effective_at` is a whole-second UTC instant with a
literal trailing `Z`, the form every Block `sealed_at` carries (WIST-3
§3.1); it is descriptive of when the act takes effect and never the
anchor of a window — a recovery window runs from the `sealed_at` of the
Block sealing the recovery Declaration (WIST-1 §5.2). An act's `subject`
is the parameter identifier, the key identifier or the Publisher's
Canonical Host its contract names (§5.1).

## 4. Constitutional Invariants

Four rules are constitutional: conforming implementations MUST enforce
them, and no Parameter Registry change or operational decision can amend
them. Once an edition is frozen under WIST-1 §3.1 and
[PUBLICATION.md](../PUBLICATION.md), amending them requires a new major
version of this suite — a fork that must win adoption on its own merits.

1. **No self-declared importance.** Publishers cannot declare their own
   relevance in any protocol object (WIST-1 §6). Importance is measured at
   consumption, outside the protocol; see
   [ADR-0006](../decisions/0006-no-self-declared-importance.md). A Label
   is a Labeler's statement about another party (§6), never a Publisher's
   statement about itself: a Label whose subject lies under the Labeler's
   own authority (WIST-1 §3.2) is rejected (WIST-2 §3.3).
2. **Position is not for sale.** The Aggregator MUST NOT accept payment
   or any consideration for inclusion, weight, latency or any treatment
   of a Publisher's content. Every domain has the same Ping quota and the
   same inclusion eligibility (§5). Infrastructure services treating all
   Publishers identically, such as mirror bandwidth, are exempt.
3. **The record is not rewritable.** Sealed Blocks and their commitments,
   Labels and governance actions are immutable; corrections append to the
   Log. Payloads remain outside it and may be withdrawn only through a
   logged entry stating the legal basis (WIST-3 §6.2). Erasure rationale:
   [ADR-0007](../decisions/0007-content-payloads-outside-the-log.md).
4. **The data stays open.** Public tier data is irrevocably licensed under
   ODbL 1.0 ([ADR-0005](../decisions/0005-odbl-for-tier-data.md)). Together
   with invariant 3, this permits the community to retain the data and
   fork if an Aggregator's operator is captured.

## 5. Parameter Registry

Every numeric constant in the suite, with its normative default. Changes
are made by `parameter_change` Registry Updates and MUST have
`effective_at` ≥ 7 days after the Block's `sealed_at` (the grace period
— itself a parameter, changeable only by the same process). The
**Identifier** column is the value `details.parameter` MUST carry
(schema: `schemas/registry-update.schema.json`, §5.1).

**In force.** A `parameter_change` is in force at every instant T at or
after its `effective_at`, the endpoint included. The value of a
parameter in force at T is that of the amendment naming it with the
greatest `effective_at` ≤ T, or the Registry default where no such
amendment exists; where two amendments share that `effective_at`, the
one later in Log order (WIST-3 §3.3: ascending Block height, then Entry
index) prevails, being the Aggregator's later statement, and the other
is superseded from the moment the later one seals and is never in
force. Log order also fixes amendment validation below; two pending
amendments for one identifier take effect each at its own instant
(WIST-3 §7), so the one with the later `effective_at` prevails once that
instant arrives even when it was sealed first. The endpoint is inclusive
because the grace period lands exactly on the Block grid — `effective_at`
seven days after a `sealed_at` is itself a `sealed_at` — and WIST-3 §3.1
reads the cadence "in force at the previous Block's `sealed_at`": a
change effective at that instant governs the next Block, rather than
leaving the Block sealed at `effective_at` under a value two readings
could place on either side.

**Validate the prospective schedule at sealing.** Process
`parameter_change` candidates in ascending Block height and canonical
Entry index. A candidate is an act that passed §5.1's Envelope
eligibility and precedence; one that fails them — a non-integer `value`,
a malformed `effective_at` — is rejected there (`WIST4-E04`,
`WIST4-E11`), ignored whether met before sealing or in a sealed Block,
and never reaches these checks. First apply their individual bounds,
identifier and grace requirements. For a remaining candidate,
tentatively add it to the accepted prefix, including amendments not yet
effective. At the sealing instant and at every `effective_at` at or
after that instant in this tentative prefix, derive the complete
parameter map by the in-force rule above and check every combination
rule below, including the transition checks over successive maps.
Between those instants the map is constant; after the final one it
remains that final map. If any checked map violates a combination,
reject this candidate as `WIST4-E03` and retain the previously accepted
schedule unchanged. Otherwise accept it. Rejected amendments are never
reconsidered merely because a later candidate would make them feasible.
No future Entry participates in this validation, and no accepted earlier
amendment is retroactively rejected. A same-effective-time replacement
must pass these checks before it can supersede the prior value.

Thus "current value" in a combination check means the value in each
prospective map being tested, not merely the default or the value in
force when the candidate was sealed. Two amendments individually safe
against today's values cannot jointly schedule an invalid future state.

**Parameter reads for work already begun.** An anchor below means the
parameter map in force at that Block's `sealed_at`. Once read, these
values remain attached to that duty; recomputing at a later height does
not move its endpoints. An amendment whose `effective_at` equals the
anchor instant is included.

| Use | Parameter anchor |
|---|---|
| WIST-1 §§3.2/3.6 sealed Delta and committed Payload size caps | Committing Delta's Block; unsealed attempts and sealing rechecks follow WIST-1 §3.6, **Size-cap parameter time** |
| WIST-1 §3.4 Delta clock allowance | Committing Delta's Block, which also supplies the historical validation clock; unsealed attempts and sealing rechecks follow WIST-1 §3.4, **Clock parameter time** |
| WIST-1 §5.2 recovery window length | Window owner Declaration's Block; freeze the end through later amendments and in-window recoveries |
| WIST-2 §3.3 Label field caps | Sealing Block of the Label's `label` Entry; unsealed attempts follow the same rule as Deltas |
| WIST-3 §3.2 cadence and per-domain capacity | The previous Block's `sealed_at` for the cadence; the sealing Block for the capacity |

This table does not replace explicit reads elsewhere, including
materialization at its stated height. Fixed block counts count actual
successor Blocks; pinning a count does not pin the cadence of those
Blocks.

**Every value the registry carries is an integer** in the unit its row
states, inside −9 007 199 254 740 991 … 9 007 199 254 740 991 inclusive
(WIST-1 §4), in addition to all parameter-specific bounds below.
`details.value` is typed `integer` with those limits (§5.1). These are
wire limits, not limits on exact intermediate arithmetic: implementations
MUST NOT round or overflow an intermediate product to fit the wire range.
A schema-valid value still requires this section's identifier, grace,
combination and guarantee-preservation checks; schema acceptance alone is
not a valid amendment.

A `parameter_change` MUST NOT set **any** parameter — those in the table
below as much as any a later revision adds — to a value that nullifies
the mechanism implementing a §4 invariant, or the availability guarantee
this suite states elsewhere. That is a rule about what a value does, not
about which parameters were foreseen when it was written: a cadence of
zero is not a fast cadence but the absence of the mechanism, and a
capacity of zero is not a tight capacity but an unmeetable one. The
schema enforces it wherever it reduces to a fixed numeric bound; the
table below publishes exactly those bounds, and each is the point at
which the mechanism named beside it stops existing rather than a
recommended setting.

| Parameter | Bound | What a value past it removes |
|---|---|---|
| `block_cadence_seconds` | ≥ 1 and ≤ 86 400 | a cadence of zero seals no Block, so nothing anchored to `sealed_at` has a clock; above a day, "eligible for the next Block" is lawful staleness measured in weeks, and the read-side position sale §5's inclusion ceiling forbids returns through the cadence |
| `block_decompressed_cap_bytes` | ≥ 1024 | a Consumer MUST reject a frame declaring more than the cap without decompressing it (WIST-3 §6), so below the octets an empty Block occupies no Block can be applied at all — and WIST-3 §3.2 requires an Aggregator to be able to seal an empty Block as the chain's heartbeat |
| `extract_cap_bytes` | ≥ 2 | `JCS("")` is 2 octets, so below that even an empty `extract` exceeds the cap, every Payload fails WIST-1 §3.6's size check, and no content-bearing Delta can ever be sealed |
| `links_cap_bytes` | ≥ 21 | `JCS({"total":0,"urls":[]})` is 21 octets and `links` is REQUIRED (WIST-3 §6.1), so below that no conforming Payload exists and no content-bearing Delta can ever be sealed |
| `link_url_cap_bytes` | ≥ 14 | below the 14 octets of `JCS("https://a.b/")` — the shortest Normalized URL under a two-label host; a one-label host's `https://a/` serializes to 12 and stays declarable (WIST-1 §2) — no link under a registrable host can be declared |
| `summary_cap_bytes` | ≥ 12 | `JCS({"title":""})` is 12 octets and `title` is REQUIRED (WIST-3 §6.1), so below that no conforming `summary` exists and no content-bearing Delta can ever be sealed |
| `url_cap_bytes` | ≥ 14 | `JCS("https://a.b/")` is 14 octets — the shortest Normalized URL under a two-label host; a one-label host's `https://a/` serializes to 12 and stays nameable — so below it no Delta under a registrable host can name any subject (WIST-1 §2, §3.2) |
| `feed_window` | ≥ 1 | a Feed or Label Feed that can hold no ID leaves nothing discoverable to pull (WIST-2 §3.2, §3.4) |
| `recovery_window_days` | ≥ 1 | a zero-length window contains no Block, so no ordinary rotation is ever superseded and the recovery key stops being the answer to a stolen signing key (WIST-1 §5.2, §4) |
| `param_grace_days` | ≥ 1 | at zero a parameter changes in the Block that announces it, and the notice period this very section rests on is gone |
| `payload_window_days` | ≥ 30 | below, a Mirror may drop what it dislikes and call the absence expiry (WIST-3 §6.1) |
| `mirror_retention_days` | ≥ 30 | below a month a Consumer resuming from the newest Snapshot may find the Blocks above it already gone from every Mirror (WIST-3 §6, §8) |
| `record_seal_blocks` | ≥ 1 | at zero the Aggregator must seal what it discovered in the Block of the discovery itself, so every discovery is a breach the instant it completes (WIST-1 §5.2, WIST-2 §3.3) |
| `domain_block_entries_max` | ≥ 1 | at zero no domain can seal anything and the Log carries only governance (WIST-3 §3.2) |
| `max_inclusion_blocks` | ≥ 1 | at zero an eligible Delta must seal in its eligibility Block itself, a deadline no Aggregator can meet for a Delta accepted mid-Block |
| `ingest_budget_bytes_day` | ≥ 1 048 576 | below one MiB the WIST-2 §3.2 walk cannot fetch a single capped Payload with its Feed page, and every backfill starves (WIST-2 §5) |
| `quota_base` | ≥ 1 | at zero no Ping is ever accepted and publication depends on baseline polling alone (WIST-2 §4) |

Where the rule does not reduce to a fixed bound — a value that is
individually in range but collapses a mechanism only in combination with
another parameter's current value — a party replaying the Log MUST
reject the `parameter_change` directly against the rule rather than apply
it. The combinations the present table cannot express are named so that
no party has to discover them: `block_decompressed_cap_bytes` MUST NOT be
below the size of the largest Block through the candidate's own Block,
measured as the octet length of `JCS(Block)` including its header,
Entries and signature, under the Block-size rule below; `links_cap_bytes`
MUST NOT be below `link_url_cap_bytes` + 21, the structural octets of
`JCS({"total":1,"urls":[…]})` around a single maximum-length URL literal
— below it a page whose first link is long declares an empty prefix the
budget rule then makes mandatory; and `mirror_retention_days` MUST NOT be
below `payload_window_days` divided by 6, so that a Consumer resuming
from a Snapshot published inside the availability window finds the
Blocks it needs. `recovery_window_days` is bounded by the Log's own clock
as well: a `parameter_change` whose value, in 86,400-second days from the
amendment's `effective_at`, would end a window opened at that instant
after `9999-12-31T23:59:59Z` — the last instant a Log timestamp denotes
(WIST-3 §3.1) — MUST be rejected against this sentence (`WIST4-E03`),
because a window WIST-1 §5.2 cannot freeze cannot open. A window opened
later than that `effective_at` can still reach past the range; WIST-1
§5.2 then withholds the recovery Declaration from sealing.

**Block-size guarantees include the sealed prefix.** For a candidate in
Block B, let M be the greatest `JCS(Block)` octet length among Blocks 0
through B, including B's complete contents regardless of which Entries
are accepted. Every prospective map checked for that candidate MUST have
`block_decompressed_cap_bytes` ≥ M. Otherwise reject the candidate as
`WIST4-E03`, preserving the accepted prefix. Later Entries do not change
B's size input and cannot rescue a rejected candidate. Equality is valid.

After all B's parameter candidates have been processed, every map at
B's `sealed_at` and every accepted `effective_at` at or after it MUST
still have a cap ≥ M. An Aggregator MUST constrain the complete Block it
seals to the smallest of those caps, even before a scheduled reduction
takes effect. A later Block exceeding this bound is invalid; it does not
revoke an earlier accepted amendment. A Consumer MUST NOT apply that
Block (`WIST3-E03`). An increase permits larger Blocks only from its
`effective_at`, the endpoint included; replacing a pending reduction can
relax the bound only when the replacement itself passes admission.

Replay uses the actual sizes at each historical height, never the largest
Block at the eventual query height to reconsider an earlier candidate.
Restoration MUST preserve or reconstruct both this running maximum and
the accepted schedule, including pending amendments. A value-only
Registry snapshot cannot establish the historical size guarantee. The
pre-decompression bound is specified separately in WIST-3 §6.

Every remaining identifier carries no additional parameter-specific
bound, and each is named here so that "exactly those bounds" above is a
claim a reader can check rather than take. `clock_skew_seconds`,
`keyset_cache_ttl_seconds` and `baseline_poll_seconds` set tolerances
rather than mechanisms: at zero each is the strict reading of the rule
it relaxes, and nothing ceases to exist.

`payload_window_days` carries a floor because the window is what makes
a missing Payload evidence (WIST-3 §6.1): shortened toward zero it would
leave a Mirror free to drop whatever it disliked and call the absence
ordinary expiry, retiring the distinction between erasure and censorship
without amending anything. The floor is set well above any plausible
Mirror resynchronisation lag, so that absence inside the window remains
attributable rather than routine.

**Ping quota and inclusion.** Every domain's Ping quota is `quota_base`
Pings per UTC day (WIST-2 §4), the same for a domain on its first day
and one a decade old. Every accepted Delta is eligible for the next
Block, and an accepted Delta MUST be sealed no later than
`max_inclusion_blocks` Blocks after the Block it became eligible for. A
Delta queued under WIST-1 §5.2's recovery window is not yet eligible:
its eligibility, and with it this ceiling's clock, starts at the first
Block at or after the window's end, after WIST-1 §5.2's revalidation.
Eligibility is gated the same way by WIST-3 §3.2's per-domain Block
capacity: where more of a domain's Deltas are eligible for a Block than
`domain_block_entries_max` admits, they take the capacity in acceptance
order, and a Delta the cap holds out of a Block becomes eligible for the
first Block with room for it, which is where its ceiling's clock starts.
The ceiling bounds the Aggregator's delay of a Delta whose turn has come,
not the domain's rate: a backfill of 50 000 accepted Deltas seals over
five Blocks at the default cap, and none of them is late. The ceiling
exists because both ends of the eligible-to-sealed gap are otherwise the
Aggregator's, and operator revenue — subscriptions to the fresh stream —
is proportional to the free stream's staleness: without a ceiling,
"eligible for the next Block" bounds nothing and position *in time, on
the read side* is lawfully for sale, one hop removed from the payment
Invariant 2 forbids. The duty is not derivable from the Log alone — the
Log cannot see an acceptance the Aggregator shelved — but it is
observable by every Publisher against its own status endpoint (WIST-2
§7.1, which shows acceptance) and Feed, so a breach is a pattern any
Publisher can document; and `block_cadence_seconds` carries a hard upper
bound for the same reason, so the ceiling cannot be reconstituted by
stretching the Block itself. A Label is sealed under the same eligibility
and ceiling as a Delta (WIST-2 §3.3).

| Parameter | Identifier | Default | Defined in |
|---|---|---|---|
| Block sealing cadence | `block_cadence_seconds` | 1 hour | WIST-3 §3.2 |
| Block decompressed size cap | `block_decompressed_cap_bytes` | 256 MiB | WIST-3 §6 |
| `extract` size cap | `extract_cap_bytes` | 32768 octets of `JCS(extract)` | WIST-1 §3.6 |
| `links` size cap | `links_cap_bytes` | 4096 octets of `JCS(links)` | WIST-1 §3.6 |
| Link `url` size cap | `link_url_cap_bytes` | 2048 octets of `JCS(url)` per link | WIST-1 §3.6 |
| `summary` size cap | `summary_cap_bytes` | 2048 octets of `JCS(summary)` | WIST-1 §3.6 |
| `url` size cap | `url_cap_bytes` | 2048 octets of `JCS(url)`; also a Label's `subject` (WIST-2 §3.3) | WIST-1 §3.2 |
| Payload availability window | `payload_window_days` | 180 days | WIST-3 §6.1 |
| Mirror Block retention floor | `mirror_retention_days` | 90 days | WIST-3 §6 |
| Discovery sealing deadline | `record_seal_blocks` | 24 Blocks | WIST-1 §5.2, WIST-2 §3.3 |
| Per-domain Block capacity | `domain_block_entries_max` | 10 000 Entries | WIST-3 §3.2 |
| Inclusion ceiling | `max_inclusion_blocks` | 4 Blocks | §5 |
| Per-domain daily ingest budget | `ingest_budget_bytes_day` | 1 GiB | WIST-2 §5 |
| Feed window | `feed_window` | 1000 IDs | WIST-2 §3.2, §3.4 |
| Clock skew allowance | `clock_skew_seconds` | 10 minutes | WIST-1 §3.4 |
| Key Set cache TTL | `keyset_cache_ttl_seconds` | 24 hours | WIST-1 §5.1 |
| Baseline feed poll interval | `baseline_poll_seconds` | 24 hours | WIST-2 §5 |
| Ping quota (per domain per UTC day) | `quota_base` | 1000 | §5, WIST-2 §4 |
| Recovery window | `recovery_window_days` | 7 days | WIST-1 §5.2 |
| Parameter change grace period | `param_grace_days` | 7 days | §5 |

### 5.1. Registry Update `details` Contract

`schemas/registry-update.schema.json` constrains `details` per `action`:

- `aggregator_key_add`: `key_id`, `alg` (`"Ed25519"`), and `public_key`
  (the raw Ed25519 public key, 43-character base64url); `subject` is the
  `key_id` (WIST-3 §3.4).
- `aggregator_key_remove`: `key_id`; `subject` is the `key_id`.
- `parameter_change`: `parameter`, one of the Identifier values in the
  table above, and `value` — an **integer** in that parameter's own unit,
  bounded by the table of bounds above where a fixed bound exists;
  `subject` is the identifier; `effective_at` MUST be ≥ `param_grace_days`
  days after the Block's `sealed_at`, as stated above.
- `payload_withdrawal`: `delta_id` (the Delta whose Payload is being
  withdrawn), `legal_basis`, and `jurisdiction` (WIST-3 §6.2); `subject` is
  the Publisher's domain. All three are REQUIRED. `delta_id` MUST name a
  Delta sealed at or below the act's Block whose signed `publisher` is
  `subject`; an act naming no such Delta, or another Publisher's, fails
  its `details` contract (`WIST4-E04`). A later withdrawal of an already
  withdrawn Delta is accepted and changes nothing: the earliest accepted
  withdrawal's Block is the height every rule reads.

**Envelope eligibility and precedence.** Every party validating a
Registry Update — an Aggregator before sealing one, and any party
replaying the Log — MUST apply WIST-1 §4's JSON/JCS eligibility first;
failure is `WIST1-E05`. Preserve the original signed object; parsing
MUST reject duplicate decoded member names, including inside nested
objects. Then validate the complete Envelope against
`schemas/registry-update.schema.json`. A failure in a member the schema
constrains for the act's `action` — `details`, or a `subject` outside
the shape that action's contract fixes — is `WIST4-E04`. Any other field
failure is `WIST4-E11`: a missing or unknown Envelope, `update` or `sig`
member; a non-object container; a malformed `wist_version`, `action`,
`effective_at` or signature field; a `subject` outside the general bound;
and a leap second or a timestamp denoting no instant (WIST-3 §3.1), year
zero included. E11 takes precedence over E04; field failures take
precedence over authenticity and semantic diagnostics. Replay identifies
every Registry Update by its ID (§2): an occurrence of an ID already
accepted at a lower Block, or earlier in the same Block, is idempotent —
it applies nothing and rejects nothing, so only the earliest sealing
Block participates.

`wist_version` MUST contain exactly three dot-separated nonnegative ASCII
decimal components, without leading zeros except `0` itself, prerelease
or build suffixes, or a numeric upper bound; a major other than `1` is
`WIST4-E11`, and a different minor or patch component alone MUST NOT
reject. This is the act's own version check, independent of any object
it names.

After field validation, authenticate the act under the Log key
`sig.key_id` names, valid at the act's Block (WIST-3 §3.4), with WIST-1
§4's profile. An act whose `sig.key_id` names no such key, or whose
signature does not verify under the key it names, is `WIST4-E11`.
Authenticity takes precedence over semantic diagnostics.

An act rejected under `WIST1-E05`, `WIST4-E11` or `WIST4-E04`, or left
unauthenticated, is ignored as every §7 rejection is: it changes no key
registry, schedule or withdrawal state, and leaves the containing Block
valid.

No `details` object may carry a bare digest of Payload content. A
content-derived value anywhere in this suite is committed under the
Payload salt (WIST-1 §3.6) or it is not carried at all (WIST-3 §6.2), and
a party replaying the Log MUST reject a Registry Update that carries one.

**No `details` member may carry personal data.** Everything a Registry
Update carries is sealed, permanent, and outside the withdrawal
mechanism entirely (WIST-3 §6.2), so any of it recited once is recited
for ever. A `payload_withdrawal`'s `legal_basis` names a legal ground,
not the person invoking it, and its `jurisdiction` names a jurisdiction.
Nothing in this suite requires identifying a data subject in order to
record why a Payload was withdrawn (§9).

## 6. Label Registry

A Label (WIST-2 §3.3) carries a `name` from this registry. A name is a
string of at most 64 characters in the form `<prefix>:<term>`, where
`term` is one or more of the ASCII characters `a`–`z`, `0`–`9` and `-`,
and `prefix` identifies who defines the term: the prefix `wist` is
reserved for the names this section defines, and every other prefix is
a Canonical Host (WIST-1 §2) whose terms are defined by that domain,
which MAY publish their meaning at any path it chooses. A name under the
`wist` prefix that this section does not define is outside the registry
and fails WIST-2 §3.3's form check.
A Label under a prefix its Labeler does not control is still a valid
Label: the prefix says whose vocabulary the term belongs to, and the
Labeler's signature says who applied it.

The `wist` terms are:

| Name | Subject | Meaning |
|---|---|---|
| `wist:trust-seed` | Canonical Host | the Labeler treats the domain's publications as a starting point for trust propagated along declared links |
| `wist:distrust-seed` | Canonical Host | the Labeler treats the domain's publications as a starting point for distrust propagated along declared links |
| `wist:spam` | Canonical Host or Normalized URL | the Labeler reports the subject's publications as unsolicited or deceptive |
| `wist:copied` | Normalized URL | the Labeler reports the subject's publication as copied from another source |
| `wist:mismatch` | Normalized URL | the Labeler observed the resource at the URL not carrying the subject's published text |
| `wist:unavailable` | Normalized URL | the Labeler observed the URL not serving any resource |
| `wist:adult` | Canonical Host or Normalized URL | the Labeler reports the subject's publications as adult content |

A Label's optional `value` is an integer in micro-units (0 … 1 000 000)
whose meaning the name's definer fixes; for the `wist` terms it is the
Labeler's confidence, 1 000 000 where absent. A Label's `retracted`
member, where `true`, withdraws the Labeler's earlier Label of the same
name on the same subject (WIST-2 §3.3).

This registry fixes names, subjects and meanings and nothing else. No
party in this suite aggregates Labels into a score, and no Consumer is
bound to apply any Label: which Labelers a Consumer subscribes to, how it
weighs their Labels and what it does with a `wist:trust-seed` are its own
policy, exactly as ranking is ([ADR-0008](../decisions/0008-raw-citation-graph-never-a-score.md)).
An Aggregator MUST seal every eligible Label it pulls whatever its name
or subject and MUST NOT read a Label when materializing records (WIST-3
§7): Labels are transported beside the records, never applied to them.

## 7. Error Registry

WIST-1, WIST-2 and WIST-3 register the codes their surfaces reject
with; this section registers WIST-4's. These are replay-side codes: the
conditions are evaluated by any party replaying the Log (§3, §5), not by
a Publisher-facing surface, so unlike WIST-1/WIST-2 codes they carry no
status-endpoint duty. One rule spans the table: rejection under this
registry rejects the *item* — the Registry Update is ignored during
replay, contributing to nothing — and never invalidates the containing
Block. Block validity is exclusively WIST-3 §3's; a registry that let one
bad Entry void a sealed Block would hand any act a veto over every other
Entry sealed beside it. The codes `WIST4-E01`, `WIST4-E02`, `WIST4-E05`
and `WIST4-E07` through `WIST4-E10` were registered by the Auditor
mechanisms this revision removed and are retired; a later revision
MUST NOT reuse them for another meaning.

| Code | Meaning and required behavior |
|---------|--------------------------------------------------------------|
| WIST4-E03 | Registry Update rejected under §5, including a prospective schedule that fails a combination rule: a `parameter_change` naming an identifier §5 does not list, a value outside its §5 bound, or an amendment §4's Invariants or §5's unamendable rules forbid. Ignored during replay; the Registry value in force is unchanged. |
| WIST4-E04 | Registry Update `details` contract violation (§5.1): a REQUIRED `details` member missing or malformed for its `action`, a `subject` outside the shape that action's contract fixes, a bare content digest, or personal data. Ignored as WIST4-E03. |
| WIST4-E06 | Recomputation divergence: a published parameter value, quota or withdrawal state that does not equal the replayer's own §5 recomputation. Not an Entry rejection — a falsified-index signal: the value MUST NOT be trusted, and the divergence SHOULD be published with the `log_position` it was computed at, since anyone replaying the Log can check the report. |
| WIST4-E11 | Registry Update Envelope failure under §5.1: a field failure outside the act's `details` and `subject` contract, including unknown members and malformed `wist_version`, `effective_at` or signature fields; a major version the validator does not implement; or an act not authenticated under a Log key valid at its Block. Ignored as WIST4-E03: no key registry, schedule or withdrawal state changes, and the containing Block stays valid. |

## 8. Security Considerations

- **Nothing here judges content.** The suite authenticates who published
  what and when; it does not measure a page, score a domain or sanction
  anyone. A domain that signs deceptive publications is caught, if at
  all, by Labelers a Consumer subscribes to and by the Consumer's own
  ranking over the signed link graph and the Log's history. That is a
  design boundary, not an omission: the mechanisms that measured pages
  could not tell an honest rewrite from a lie and never judged quality
  either ([ADR-0041](../decisions/0041-signed-publications.md)).
- **Label capture.** A Labeler that many Consumers subscribe to becomes a
  gatekeeper in practice. Subscriptions are explicit and switchable,
  every Label is signed and sealed, so a Labeler's record is public, and
  a Consumer MAY subscribe to several Labelers and weigh them; none of
  that prevents concentration, and a deployment that needs independent
  labeling obtains it by operating or funding independent Labelers.
- **Label flooding.** A Labeler's Labels cost the Aggregator the same
  budget as its Deltas (WIST-2 §5) and count against the same per-domain
  capacity (WIST-3 §3.2), so labeling cannot outrun publication. A Label
  about a subject nobody subscribes to costs its Labeler a registration
  and its Log a row.
- **Self-labeling.** A Label whose subject lies under the Labeler's own
  authority is rejected (§4, WIST-2 §3.3), so a domain cannot declare
  itself a trust seed; a domain declaring a sibling it also controls can,
  and only a Consumer's choice of Labelers answers that.
- **Domain resale.** Buying a domain or its hosting conveys no history.
  WIST-1 §5.2 binds continuity to keys: a fresh identity is visible in
  the Log as a Declaration signed by neither the previous Key Set nor its
  recovery keys, and a Consumer reading a domain's age or publication
  history from the Log reads it from that height.
- **Parameter capture.** A `parameter_change` is the one lever an
  Aggregator holds over every Publisher at once; the grace period, the
  bounds table, the combination rules and the prospective validation
  above bound what a single amendment can do, and every amendment is
  sealed for any party to replay.

## 9. Privacy Considerations

Everything a Registry Update carries is sealed in the Log, permanent, and
outside the withdrawal mechanism entirely — the same class as a Delta's
`meta` (WIST-1 §3.7) — and §5.1 therefore forbids personal data in any of
it. A `legal_basis` names a legal ground, not the person invoking it.
Nothing in this suite requires identifying a data subject in order to
record why a Payload was withdrawn, and doing so would seal into the Log
precisely the data an erasure is meant to remove.

A Label is a statement about another party's publication and is sealed
under the same permanence. Its `name` is a registry term, its `subject` a
URL or host the Log already carries, and its `value` an integer; WIST-2
§3.4 gives it no free-text member, so a Label can name what a Labeler
found and never recite who a page is about. Labelers remain bound by
WIST-1 §9's rule that nothing beyond what the subject itself publishes
enters the Log.

## 10. Conformance Checklist

**Aggregator (governance side):**

- [ ] Signs every Registry Update under a Log key valid at its Block and
      admits or removes its own keys only in-band (§3, WIST-3 §3.4)
- [ ] Changes parameters only via `parameter_change` with the grace
      period, validating the prospective schedule and the Block-size
      guarantee at sealing (§5)
- [ ] Withdraws a Payload only by a `payload_withdrawal` naming the
      Delta, the legal basis and the jurisdiction (§5.1, WIST-3 §6.2)
- [ ] Applies the same Ping quota and the same inclusion eligibility to
      every domain, and seals an accepted Delta or Label within
      `max_inclusion_blocks` of its eligibility Block (§5)
- [ ] Seals every eligible Label it pulls whatever its name or subject,
      rejects a self-labeling Label, and never reads a Label when
      materializing records (§6, WIST-2 §3.3, WIST-3 §7)
- [ ] Enforces the §4 invariants unconditionally

**Any party replaying the Log:**

- [ ] Reads a `parameter_change` as in force from its `effective_at`
      inclusive, the greatest `effective_at` ≤ T prevailing among an
      identifier's amendments and Log order breaking an equal pair (§5)
- [ ] Applies §5.1's Registry Update field, version and authenticity
      checks and their precedence, and treats a repeated Registry Update
      ID as idempotent (§5.1)
- [ ] Rejects a `parameter_change` that fails a bound, a combination
      rule, the Block-size guarantee or the grace period, preserving the
      accepted schedule (§5, §7)
- [ ] Reads a withdrawal from the earliest Block sealing it and applies
      WIST-3 §6.2 from that height (§5.1)
- [ ] Carries Labels as sealed and never aggregates them into a value the
      Log did not carry (§6)

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- [RFC 8032] Edwards-Curve Digital Signature Algorithm (EdDSA) — the
  Ed25519 key format every signed object uses
- WIST-1: Delta Format & Identity — key rotation, scope rule, §6 absence
- WIST-2: Site Publication — quotas, hints, Labels
- WIST-3: Logbook & Distribution — entry envelope, checkpoints,
  immutability, Block Hash (WIST-3 §3.1)
