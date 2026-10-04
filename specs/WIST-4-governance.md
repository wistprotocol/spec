# WIST-4: Governance & Parameters

**Status:** v1.0.0-draft · **Date:** 2026-10-02 · **License:** CC-BY 4.0

## 1. Introduction

WIST-4 defines the governance acts an Aggregator seals into its Log —
Aggregator key changes, parameter amendments, Payload withdrawals and
Public Suffix List snapshots — the Parameter Registry those amendments
change, the registry of Label names Labelers publish under (WIST-2
§3.3), and the constitutional invariants no operator can amend.
Governance acts are Log Entries (WIST-3 §3.3), so any party replaying
the Log derives the parameter schedule, the key registry, every
withdrawal and the snapshot every quota reads from public, ordered
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
  one of the five governance acts of §3; `subject` names what the act is
  about; `details` is constrained per `action` by §5.1.
- **Registry Update ID**: `"sha256:" + hex(SHA-256(JCS(update)))` — the
  act's inner object canonicalized and hashed under the construction
  WIST-1 §4 uses for a Catalog ID. Replay identifies every act by it (§5.1).
- **Parameter Registry**: the versioned table of every numeric value of
  the suite that a Log may amend (§5).
- **Label**: a signed statement by a Labeler about a subject outside its
  own authority — a Normalized URL or a Canonical Host — under a name
  from the Label Registry (§6, WIST-2 §3.3).
- **Labeler**: a Publisher whose publications include Labels (WIST-2
  §3.3). Every Publisher MAY label; a Labeler needs no admission.
- **Dispute**: a labeled domain's signed answer to one sealed Label,
  sealed beside the Labels and never applied to them (WIST-2 §3.3).
- **Public Suffix List snapshot**: the exact octets of one revision of
  the Public Suffix List file, identified by `"sha256:" +
  hex(SHA-256(octets))`, pinned into the Log by a `suffix_list_update`
  (§3.1) and served beside the Log (WIST-3 §6).
- **Registrable Domain**: of a Canonical Host, the domain the Public
  Suffix List algorithm derives from it under the snapshot in force
  (§3.1): the public suffix plus one label, or the host itself where the
  list leaves no such domain. Quota and capacity are accounted per
  Registrable Domain; identity, signing and scope stay per Canonical
  Host (WIST-1 §3.8).

Every signed object in this document carries `wist_version` (WIST-1 §3.1)
and the WIST-1 §4 signature block (`key_id`, `alg`, `value`).

## 3. Governance Acts

A Registry Update is an Envelope whose inner object is `update` (schema:
[`schemas/registry-update.schema.json`](../schemas/registry-update.schema.json)),
carrying `wist_version`, `action`, `subject`, `effective_at` and, where
the act's contract requires it, `details`. The five acts are:

- `aggregator_key_add` and `aggregator_key_remove` — the Aggregator's own
  signing keys, valid at a height as WIST-3 §3.4 defines.
- `parameter_change` — an amendment to one Parameter Registry value,
  in force from its `effective_at` under §5.
- `payload_withdrawal` — the removal of one Payload from distribution
  under WIST-3 §6.2.
- `suffix_list_update` — the Public Suffix List snapshot every quota and
  capacity decision reads from the next Epoch on (§3.1).

Every act is signed by the Aggregator under a Log key valid at the
height WIST-3 §3.4 fixes for authenticating it. `effective_at` is a
whole-second UTC instant with a
literal trailing `Z`, the form every Epoch `sealed_at` carries (WIST-3
§3.1); it is descriptive of when the act takes effect and never the
anchor of a window — a recovery window runs from the `sealed_at` of the
Epoch sealing the recovery Declaration (WIST-1 §5.2). An act's `subject`
is the parameter identifier, the key identifier, the Publisher's
Canonical Host or the snapshot identifier its contract names (§5.1).

### 3.1. Public Suffix List Snapshots and the Registrable Domain

Every Canonical Host is a separate Publisher identity (WIST-1 §3.8), and
a hostname under a shared parent costs nothing: a subdomain of a hosting
provider, or of a domain its operator already holds, is a free
identity. Every bound this suite places on how much one party may
publish — the Ping quota (WIST-2 §4), the ingest budget (WIST-2 §5) and
the per-domain Epoch capacity (WIST-3 §3.2) — is therefore accounted
per **Registrable Domain**, the unit the Public Suffix List draws
between what a registry sells and what a registrant subdivides, and
never per hostname. Hosts under a suffix the list's private section
names — `alice.github.io` and `bob.github.io`, whose provider registers
`github.io` there — stay separate units, because the list records that
their names are allocated to different parties; `a.example.com` and
`b.example.com` share one.

**The snapshot.** The list changes, and two parties reading different
revisions of it would account one Log two ways, so the revision in
force is pinned in the Log. A `suffix_list_update` names a snapshot by
`details.sha256`, the identifier `"sha256:" + hex(SHA-256(octets))` of
the exact file, and `details.bytes`, the octet count of that file;
`subject` repeats the identifier (§5.1). The Aggregator MUST serve the
named octets at `/log/suffix-lists/<hex>.dat` (WIST-3 §6) from the
Epoch that seals the act, immutably and without expiry, and Mirrors
retain them as they retain Checkpoints; a served file whose SHA-256 is
not the identifier is `WIST3-E03`, and one no source holds is
`WIST3-E01`, which leaves every Epoch the snapshot governs unverifiable
until it is obtained. An act whose `bytes` disagrees with the named
file's octet count fails its contract (`WIST4-E04`). An Aggregator MUST
NOT seal an act naming a file it does not hold, since it could not
serve the file from the sealing Epoch: at the Aggregator such an act
fails its contract (`WIST4-E04`). A Consumer that cannot obtain the
file an act names cannot check the act's `bytes` either, so it neither
accepts nor ignores the act: it stops at the act's Epoch (`WIST3-E01`)
and resumes once the file is obtained, and a file obtained that does
not hash to its name stops it the same way (`WIST3-E03`).

**In force.** An accepted `suffix_list_update` is in force from the
Epoch after its sealing Epoch: the snapshot in force at Epoch B is the
one named by the most recent accepted `suffix_list_update` sealed at a
height below B, and the snapshot in force at an instant T is the one
named by the most recent accepted act sealed at or before T — the same
snapshot the first Epoch sealed after T reads. An act naming the
snapshot already in force is accepted and changes nothing, the height
WIST-3 §7's tuple carries included: that height is the sealing height
of the accepted act that put the snapshot in force. Before the
first accepted act, no snapshot is in force and **every Canonical Host
is its own Registrable Domain**; an Aggregator SHOULD seal its first
`suffix_list_update` in Epoch 0, since until it does a free hostname is
a free quota. Where the name of the snapshot in force is needed by a
Consumer resuming from a Snapshot, WIST-3 §7's `suffix_list` tuple
carries it.

**The algorithm.** A snapshot is a UTF-8 text, and its lines are the
texts U+000A separates. Each line's rule is the text before its first
whitespace character, which is U+0009, U+000B, U+000C, U+000D or U+0020
and no other; a line whose rule is empty, or begins with `//`, carries no
rule, so a line that begins with whitespace carries none. Every rule line
of the file applies, in the ICANN section and the private section alike.
A rule is an optional
leading `!`, the exception marker, followed by labels separated by `.`;
a label is `*`, the wildcard, or a hostname label, which is converted
to Canonical Host form by WIST-1 §2's processing before any comparison,
so that a rule the list spells in Unicode matches the A-labels a
Canonical Host carries. A rule with a label that processing rejects is
ignored. The Registrable Domain of a Canonical Host H under the
snapshot is derived as the Public Suffix List's algorithm states it:

1. A rule matches H when H has at least as many labels as the rule and,
   pairing labels from the right, every rule label is `*` or equals the
   host label it is paired with. Collect the matching rules.
2. The prevailing rule is the exception rule among them, the one with
   the most labels where several are exceptions; otherwise the matching
   rule with the most labels; otherwise, where no rule matches, `*`.
3. Where the prevailing rule is an exception rule, drop its leftmost
   label. The public suffix of H is its rightmost labels, as many as the
   prevailing rule has.
4. The Registrable Domain is the public suffix plus the one label of H
   to its left. Where H has no label to the left of its public suffix —
   H is a listed suffix, a single label, or a host a wildcard rule
   swallows whole — **the Registrable Domain is the host itself**.

Under this derivation `a.b.example.com` and `example.com` share the
Registrable Domain `example.com`; `alice.github.io` is its own, and so
is `github.io`; `www.ck` is its own under the exception `!www.ck` while
`test.ck` is a suffix under `*.ck` and therefore its own unit; a host
under a top-level label the list does not carry keys on its last two
labels. The vector `vectors/wist4/registrable-domain.json` fixes these
readings, transcribes the Public Suffix List project's own test cases
over a fixture snapshot, and replays acts, capacity and quota under a
snapshot advance.

**Identity is unchanged.** The Registrable Domain is an accounting key
and nothing else. A Publisher is still its Canonical Host, signs under
its own Declaration, holds its own scope and its own status endpoint
(WIST-2 §7.1), and Labels are still applied to the Canonical Host or
URL they name. Two hosts sharing a Registrable Domain share a quota and
a capacity; they share no key, no chain and no consequence of each
other's Labels.

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
   of a Publisher's content. Every Registrable Domain has the same Ping
   quota and every domain the same inclusion eligibility (§5, WIST-3
   §3.3).
   Infrastructure services treating all Publishers identically, such as
   mirror bandwidth, are exempt.
3. **The record is not rewritable.** Sealed Epochs and their commitments,
   Labels and governance actions are immutable; corrections append to the
   Log. Payloads remain outside it and may be withdrawn only through a
   logged entry stating the legal basis (WIST-3 §6.2). Erasure rationale:
   [ADR-0007](../decisions/0007-content-payloads-outside-the-log.md).
4. **The data stays open.** Public tier data is irrevocably licensed under
   ODbL 1.0 ([ADR-0005](../decisions/0005-odbl-for-tier-data.md)). Together
   with invariant 3, this permits the community to retain the data and
   fork if an Aggregator's operator is captured.

## 5. Parameter Registry

Every numeric value of the suite that a Log may amend, with its normative
default. Values the suite fixes for every Log, which no Log amends and no
parameter map carries, are stated where they are defined and are not in
this registry. Changes are made by `parameter_change` Registry Updates
and MUST have `effective_at` ≥ 7 days after the Epoch's `sealed_at` (the
grace period — itself a parameter, changeable only by the same process).
The
**Identifier** column is the value `details.parameter` MUST carry
(schema: `schemas/registry-update.schema.json`, §5.1).

**In force.** A `parameter_change` is in force at every instant T at or
after its `effective_at`, the endpoint included. The value of a
parameter in force at T is that of the amendment naming it with the
greatest `effective_at` ≤ T, or the Registry default where no such
amendment exists; where two amendments share that `effective_at`, the
one later in Log order (WIST-3 §3.3: ascending Epoch number, then Entry
index) prevails, being the Aggregator's later statement, and the other
is superseded from the moment the later one seals and is never in
force. Log order also fixes amendment validation below; two pending
amendments for one identifier take effect each at its own instant
(WIST-3 §7), so the one with the later `effective_at` prevails once that
instant arrives even when it was sealed first. The endpoint is inclusive
because the grace period lands exactly on the Epoch grid — `effective_at`
seven days after a `sealed_at` is itself a `sealed_at` — and WIST-3 §3.1
reads the cadence "in force at the previous Epoch's `sealed_at`": a
change effective at that instant governs the next Epoch, rather than
leaving the Epoch sealed at `effective_at` under a value two readings
could place on either side.

**Validate the prospective schedule at sealing.** Process
`parameter_change` candidates in ascending Epoch number and canonical
Entry index. A candidate is an act that passed §5.1's Envelope
eligibility and precedence; one that fails them — a non-integer `value`,
a malformed `effective_at` — is rejected there (`WIST4-E04`,
`WIST4-E11`), ignored whether met before sealing or in a sealed Epoch,
and never reaches these checks. A string `parameter` that names no
identifier of this section, and an integer `value` outside its bound
below, pass them and are rejected here (`WIST4-E03`). First apply their individual bounds,
identifier and grace requirements. For a remaining candidate,
tentatively add it to the accepted prefix, including amendments not yet
effective. At the sealing instant and at every `effective_at` at or
after that instant in this tentative prefix, derive the complete
parameter map by the in-force rule above and check every combination
rule below against that map. Every combination rule reads one map;
the only check that reads the sealed prefix is the Epoch-size guarantee
below, and no rule compares two successive maps. Between those instants
the map is constant; after the final one it remains that final map. If
any checked map violates a combination,
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
parameter map in force at that Epoch's `sealed_at`. Once read, these
values remain attached to that duty; recomputing at a later height does
not move its endpoints. An amendment whose `effective_at` equals the
anchor instant is included.

| Use | Parameter anchor |
|---|---|
| WIST-1 §3.6 size caps of Items, Payloads, Catalogs and tree files, and WIST-1 §5.1 counts of a Declaration | The Epoch sealing the Entry, whose map a Payload read for a sealed Item retains; a tree file, which no Entry carries, is read with the Catalog whose admission, sealing recheck or sealed Entry reads it; unsealed attempts and sealing rechecks follow WIST-1 §3.6, **Size-cap parameter time** |
| WIST-1 §3.4 Catalog clock allowance | The Epoch sealing the Catalog, which also supplies the historical validation clock; unsealed attempts and sealing rechecks follow WIST-1 §3.4, **Clock parameter time** |
| WIST-1 §5.2 recovery window length | Window owner Declaration's Epoch; freeze the end through later amendments and in-window recoveries |
| WIST-1 §5.2 discovery sealing deadline (`record_seal_epochs`) of a recovery Declaration and of a Declaration that reduces authority | The first Epoch sealed after the discovery, from which WIST-1 §5.2 counts the deadline |
| WIST-2 §3.3 Label field caps | The Epoch sealing the `label` Entry; an unsealed Label reads the map WIST-1 §3.6, **Size-cap parameter time**, selects for a Catalog at the same stage |
| WIST-3 §3.2 cadence, per-domain capacity and per-Labeler cap | The previous Epoch's `sealed_at` for the cadence; the sealing Epoch for the capacity and the cap |
| WIST-3 §3.3 inclusion ceiling of a Catalog, an Item, a Label or a dispute | The Epoch it is eligible for; a deferral that moves that Epoch reads the map again at the new one |
| WIST-3 §5 Witness quorum | The Checkpoint's own `sealed_at` |

This table does not replace explicit reads elsewhere, including
materialization at its stated height. Fixed Epoch counts count actual
successor Epochs; pinning a count does not pin the cadence of those
Epochs.

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
table below publishes exactly those bounds and the floors of the next
paragraph, each the point past which a mechanism stops existing or a
conforming publication is refused, not a recommended setting.

**Values a Publisher builds to.** A Publisher reads no Log's parameters
and builds what it serves to the defaults of this section (WIST-5).
`url_cap_bytes`, `extract_cap_bytes`, `summary_cap_bytes`,
`links_cap_bytes`, `link_url_cap_bytes`, `collections_max`,
`scope_entries_max`, `catalog_items_max`, `tree_file_cap_bytes` and
`tree_depth_max` are therefore amended to no value below their defaults,
the floors the table below gives them: a Log below one would refuse
Items, Payloads, Catalogs, tree files, Declarations or Labels built to
this suite, for a value their Publisher cannot read. A Log may raise
them, `url_cap_bytes` to no value above 32 768 (WIST-1 §3.2).

| Parameter | Bound | What a value past it removes |
|---|---|---|
| `epoch_cadence_seconds` | ≥ 1 and ≤ 86 400 | a cadence of zero seals no Epoch, so nothing anchored to `sealed_at` has a clock; above a day, "eligible for the next Epoch" is lawful staleness measured in weeks, and the read-side position sale §5's inclusion ceiling forbids returns through the cadence |
| `epoch_cap_bytes` | ≥ 65 537 | the octets one Entry of WIST-3 §3.3's largest admissible size occupies in an entry bundle (WIST-3 §6): below it the cap, not the format, decides which conforming Entries can be sealed, and the inclusion ceiling below can oblige an Aggregator to seal an Entry the cap forbids |
| `checkpoint_witness_quorum` | ≥ 0 | a negative count of Cosignatures is no threshold; at zero none is required and WIST-3 §5's unwitnessed interim applies |
| `extract_cap_bytes` | ≥ 32 768 | Payloads whose `extract` a Publisher built to the default (above) |
| `links_cap_bytes` | ≥ 4096 | Payloads whose `links` a Publisher built to the default (above) |
| `link_url_cap_bytes` | ≥ 2048 | Payloads declaring a link a Publisher built to the default (above) |
| `summary_cap_bytes` | ≥ 2048 | Payloads whose `summary` a Publisher built to the default (above) |
| `url_cap_bytes` | ≥ 2048 and ≤ 32 768 | below, Items, Scope entries and Label subjects a Publisher built to the default (above); above, the fit in one Entry of 65 535 octets of a `publisher_item` Entry within WIST-1 §7's bound on `JCS(item)` (WIST-1 §3.2, WIST-3 §3.3) |
| `collections_max` | ≥ 16 | Declarations whose Collections a Publisher built to the default (above) |
| `scope_entries_max` | ≥ 32 | Declarations whose Scopes a Publisher built to the default (above) |
| `catalog_items_max` | ≥ 16 777 216 | Catalogs whose lists a Publisher built to the default (above) |
| `tree_file_cap_bytes` | ≥ 65 536 | Catalogs whose tree files a Publisher built to the default (above) |
| `tree_depth_max` | ≥ 16 | Catalogs whose trees a Publisher built to the default depth (above) |
| `catalog_refresh_seconds` | ≥ 1 and ≤ 7 776 000 | at zero every unchanged Catalog passes C4 and the refresh rule is gone; above 90 days a refresh of an unchanged Collection signed at the suite's interval can be a base and remove its records (WIST-3 §3.2, §7) |
| `feed_window` | ≥ 1 | a Label Feed that can hold no ID leaves no Label or dispute discoverable to pull (WIST-2 §3.2) |
| `recovery_window_days` | ≥ 1 | a zero-length window contains no Epoch, so no ordinary rotation is ever superseded and the recovery key stops being the answer to a stolen signing key (WIST-1 §5.2, §4) |
| `param_grace_days` | ≥ 1 | at zero a parameter changes in the Epoch that announces it, and the notice period this very section rests on is gone |
| `payload_window_days` | ≥ 30 | below, a Mirror may drop what it dislikes and call the absence expiry (WIST-3 §6.1) |
| `mirror_retention_days` | ≥ 30 | below a month a Consumer resuming from the newest Snapshot may find the Epochs above it already gone from every Mirror (WIST-3 §6, §8) |
| `record_seal_epochs` | ≥ 1 | at zero the Aggregator must seal what it discovered in the first Epoch it seals after the discovery, a deadline no Aggregator can meet for a discovery made as that Epoch is sealed (WIST-1 §5.2) |
| `declaration_activation_epochs` | ≥ 0 | at zero a fresh identity activates in the Epoch that seals it, the delay absent by choice; below zero it would activate before it is sealed, an order no replay can apply (WIST-1 §5.2) |
| `domain_epoch_entries_max` | ≥ 1 | at zero no domain can seal anything and the Log carries only governance (WIST-3 §3.2) |
| `labeler_epoch_entries_max` | ≥ 1 | at zero no Label or dispute can seal and every Label Feed is dead weight (WIST-3 §3.2) |
| `max_inclusion_epochs` | ≥ 1 | at zero an Entry must be sealed in the Epoch it is eligible for, a deadline no Aggregator can meet for one whose pull ends as that Epoch is sealed (WIST-3 §3.3) |
| `ingest_budget_bytes_day` | ≥ 1 048 576 | below one MiB a pull cannot read within one UTC day a change list of `change_list_cap_bytes` octets, so its Catalog is always walked, nor a Label Feed or Page at its 1 MiB response bound, so its Label walk never ends (WIST-2 §5.2, §8) |
| `quota_base` | ≥ 1 | at zero no Ping is ever accepted and publication depends on baseline polling alone (WIST-2 §4) |

Where the rule does not reduce to a fixed bound — a value that is
individually in range but collapses a mechanism only in combination with
another parameter's current value — a party replaying the Log MUST
reject the `parameter_change` directly against the rule rather than apply
it. The combinations the present table cannot express are named so that
no party has to discover them: `epoch_cap_bytes` MUST NOT be
below the size of the largest Epoch through the candidate's own Epoch,
measured as WIST-3 §6 defines an Epoch's size — the octets its Entries
occupy in entry bundles — under the Epoch-size rule below; `links_cap_bytes`
MUST NOT be below `link_url_cap_bytes` + 21, the structural octets of
`JCS({"total":1,"urls":[…]})` around a single maximum-length URL literal
— below it a page whose first link is long declares an empty prefix the
budget rule then makes mandatory; `mirror_retention_days` MUST NOT be
below `payload_window_days` divided by 6, so that a Consumer resuming
from a Snapshot published inside the availability window finds the
Epochs it needs; and `labeler_epoch_entries_max` MUST NOT exceed
`domain_epoch_entries_max`, since a Labeler's Labels count against both
and a per-Labeler cap above the per-domain one bounds nothing (WIST-3
§3.2). `recovery_window_days` is bounded by the Log's own clock
as well: a `parameter_change` whose value, in 86,400-second days from the
amendment's `effective_at`, would end a window opened at that instant
after `9999-12-31T23:59:59Z` — the last instant a Log timestamp denotes
(WIST-3 §3.1) — MUST be rejected against this sentence (`WIST4-E03`),
because a window WIST-1 §5.2 cannot freeze cannot open. A window opened
later than that `effective_at` can still reach past the range; WIST-1
§5.2 then withholds the recovery Declaration from sealing.

**Epoch-size guarantees include the sealed prefix.** For a candidate in
Epoch B, let M be the greatest Epoch size (WIST-3 §6) among Epochs 0
through B, including B's complete contents regardless of which Entries
are accepted. Every prospective map checked for that candidate MUST have
`epoch_cap_bytes` ≥ M. Otherwise reject the candidate as
`WIST4-E03`, preserving the accepted prefix. Later Entries do not change
B's size input and cannot rescue a rejected candidate. Equality is valid.

After all B's parameter candidates have been processed, every map at
B's `sealed_at` and every accepted `effective_at` at or after it MUST
still have a cap ≥ M. An Aggregator MUST constrain the complete Epoch it
seals to the smallest of those caps, even before a scheduled reduction
takes effect. A later Epoch exceeding this bound is invalid; it does not
revoke an earlier accepted amendment. A Consumer MUST reject that
Epoch (`WIST3-E03`; WIST-3 §3.3, **Rejected Epochs**). An increase permits larger Epochs only from its
`effective_at`, the endpoint included; replacing a pending reduction can
relax the bound only when the replacement itself passes admission.

Replay uses the actual sizes at each historical height, never the largest
Epoch at the eventual query height to reconsider an earlier candidate.
Restoration MUST preserve or reconstruct both this running maximum and
the accepted schedule, including pending amendments. A value-only
Registry snapshot cannot establish the historical size guarantee. The
transport bound a Consumer applies while fetching is specified
separately in WIST-3 §6.

Every remaining identifier carries no additional parameter-specific
bound, and each is named here so that "exactly those bounds" above is a
claim a reader can check rather than take. `clock_skew_seconds` and
`baseline_poll_seconds` set tolerances rather than mechanisms: at zero
each is the strict reading of the rule it relaxes, and nothing ceases to
exist.

`payload_window_days` carries a floor because the window is what makes
a missing Payload evidence (WIST-3 §6.1): shortened toward zero it would
leave a Mirror free to drop whatever it disliked and call the absence
ordinary expiry, retiring the distinction between erasure and censorship
without amending anything. The floor is set well above any plausible
Mirror resynchronisation lag, so that absence inside the window remains
attributable rather than routine.

**Ping quota and inclusion.** Every Registrable Domain's Ping quota is
`quota_base` Pings per UTC day (WIST-2 §4), shared by every Canonical
Host under it (§3.1) and the same for a domain on its first day and one
a decade old. A Catalog, an Item, a Label or a dispute MUST be sealed
no later than `max_inclusion_epochs` Epochs after the Epoch it is
eligible for. Which Epoch that is, the deferrals that move it and the
ceiling with it, and the order in which a Registrable Domain's sealed
Entries take its capacity are WIST-3 §3.3's (**Eligibility**, **Capacity
order**). The duty ends without the sealing only where WIST-3 §3.3's
rules of what leaves (**Waiting**) have it leave: by the Leaves row for a
Catalog or an Item, by a judgment failed at its turn for a Label or a
dispute; one the Aggregator merely does not seal has not left. The
ceiling bounds the Aggregator's delay of an Entry whose turn has
come, not the domain's rate: the first pull of a Collection of 50 000
Items seals over six Epochs at the default capacity, its Catalog taking
room first, and none of them is late. The ceiling
exists because both ends of the eligible-to-sealed gap are otherwise the
Aggregator's, and operator revenue — subscriptions to the fresh stream —
is proportional to the free stream's staleness: without a ceiling,
"eligible for the next Epoch" bounds nothing and position *in time, on
the read side* is lawfully for sale, one hop removed from the payment
Invariant 2 forbids. The duty is not derivable from the Log alone — the
Log cannot see an acceptance the Aggregator shelved — but for a Catalog
or an Item it is observable by every Publisher against its own status
endpoint (WIST-2 §7.1, which shows each waiting Catalog and Item with
its deferrals) and the Log, and for a Label or a dispute against the
Epoch that seals it, which the Log shows beside the Label Feed its
Labeler serves, so a breach is a pattern any Publisher can document;
and `epoch_cadence_seconds` carries a hard upper bound for the same
reason, so the ceiling cannot be reconstituted by stretching the Epoch
itself.

| Parameter | Identifier | Default | Defined in |
|---|---|---|---|
| Epoch sealing cadence | `epoch_cadence_seconds` | 1 hour | WIST-3 §3.2 |
| Epoch size cap, in entry-bundle octets | `epoch_cap_bytes` | 256 MiB | WIST-3 §6 |
| `extract` size cap | `extract_cap_bytes` | 32768 octets of `JCS(extract)` | WIST-1 §3.6 |
| `links` size cap | `links_cap_bytes` | 4096 octets of `JCS(links)` | WIST-1 §3.6 |
| Link `url` size cap | `link_url_cap_bytes` | 2048 octets of `JCS(url)` per link | WIST-1 §3.6 |
| `summary` size cap | `summary_cap_bytes` | 2048 octets of `JCS(summary)` | WIST-1 §3.6 |
| `url` size cap | `url_cap_bytes` | 2048 octets of `JCS(url)`; also a Scope entry's `url` (WIST-1 §5.1) and a Label's `subject` (WIST-2 §3.3) | WIST-1 §3.2 |
| Collections in a Declaration | `collections_max` | 16 Collections | WIST-1 §5.1 |
| Entries in a Scope | `scope_entries_max` | 32 entries | WIST-1 §5.1 |
| Items in a Catalog | `catalog_items_max` | 16 777 216 Items | WIST-1 §3.5, §4.2 |
| Tree file size cap | `tree_file_cap_bytes` | 65 536 octets | WIST-1 §4.2 |
| Tree depth | `tree_depth_max` | 16 levels of tree files | WIST-1 §4.2 |
| Catalog refresh interval | `catalog_refresh_seconds` | 604 800 seconds | WIST-3 §3.2 |
| Payload availability window | `payload_window_days` | 180 days | WIST-3 §6.1 |
| Mirror Epoch retention floor | `mirror_retention_days` | 90 days | WIST-3 §6 |
| Witness quorum | `checkpoint_witness_quorum` | 0 Witnesses | WIST-3 §5 |
| Discovery sealing deadline | `record_seal_epochs` | 24 Epochs | WIST-1 §5.2 |
| Per-domain Epoch capacity (per Registrable Domain) | `domain_epoch_entries_max` | 10 000 Entries | WIST-3 §3.2 |
| Per-Labeler Epoch cap (per Registrable Domain) | `labeler_epoch_entries_max` | 1 000 Entries | WIST-3 §3.2 |
| Inclusion ceiling | `max_inclusion_epochs` | 4 Epochs | §5, WIST-3 §3.3 |
| Per-domain daily ingest budget | `ingest_budget_bytes_day` | 1 GiB | WIST-2 §5.2 |
| Label Feed window | `feed_window` | 1000 IDs | WIST-2 §3.2 |
| Clock skew allowance | `clock_skew_seconds` | 10 minutes | WIST-1 §3.4 |
| Baseline pull interval | `baseline_poll_seconds` | 24 hours | WIST-2 §5.4 |
| Ping quota (per Registrable Domain per UTC day) | `quota_base` | 1000 | §5, WIST-2 §4 |
| Recovery window | `recovery_window_days` | 7 days | WIST-1 §5.2 |
| Fresh-identity activation delay | `declaration_activation_epochs` | 24 Epochs | WIST-1 §5.2 |
| Parameter change grace period | `param_grace_days` | 7 days | §5 |

### 5.1. Registry Update `details` Contract

`schemas/registry-update.schema.json` constrains `details` per `action`:

- `aggregator_key_add`: `key_id`, `alg` (`"Ed25519"`), and `public_key`
  (the raw Ed25519 public key, 43-character base64url); `subject` is the
  `key_id` (WIST-3 §3.4).
- `aggregator_key_remove`: `key_id`; `subject` is the `key_id`. An
  authenticated key act of either kind that WIST-3 §3.4 lists as a
  key-act failure fails its `details` contract (`WIST4-E04`).
- `parameter_change`: `parameter`, one of the Identifier values in the
  table above, and `value` — an **integer** in that parameter's own unit,
  bounded by the table of bounds above where a fixed bound exists;
  `subject` is the identifier; `effective_at` MUST be ≥ `param_grace_days`
  days after the Epoch's `sealed_at`, as stated above.
- `payload_withdrawal`: `delta_id`, the Item ID of the Item whose
  Payload is withdrawn (the member keeps its name), `legal_basis`, and `jurisdiction` (WIST-3 §6.2); `subject` is the
  Publisher's Canonical Host. All three are REQUIRED. The act meets its
  `details` contract only where a valid `publisher_item` Entry (WIST-3
  §3.3) sealed the Item it names, of kind `page`, at or below the act's
  Epoch — in the act's own Epoch whatever the order of its Entries —
  against a Catalog whose `publisher` is `subject`; otherwise it fails
  the contract (`WIST4-E04`). A later withdrawal of an already withdrawn
  Item is accepted and changes nothing: the earliest accepted
  withdrawal's Epoch is the height every rule reads. An act sealed in the
  Epoch that seals the Item it names takes effect as WIST-3 §6.2 states.
  A Consumer resumed from a Snapshot holds no set of the Items sealed at
  or below its `tree_size` (WIST-3 §7). It judges the contract of an act
  sealed above that `tree_size` against what it holds: the valid
  `publisher_item` Entries it applied above that `tree_size` through the
  act's Epoch, and the `record`, `removal` and `withdrawal` tuples of the
  Snapshot it last resumed from. Where one of them shows the named Item
  sealed as the contract requires — such an Entry, or a `record` or
  `withdrawal` tuple of the Publisher `subject` naming the Item — the act
  meets the contract. Otherwise, where one of them shows the Item sealed
  otherwise — an Entry, a `record` tuple or a `withdrawal` tuple of
  another Publisher, an Entry of an Item of kind `removed`, a `removal`
  tuple naming the Item ID — the act fails it (`WIST4-E04`), as it does
  on replay. Where none shows the Item, the Consumer accepts the act as
  consistent. It then differs from a replaying Consumer only for an act
  the Aggregator breaks its contract by sealing (WIST-3 §3.3,
  **Waiting**) and for what follows from that act in that Log — a later
  withdrawal of the same Item then reads another earliest height — the
  one exception WIST-3 §8 states to the convergence of the two paths.
- `suffix_list_update`: `sha256`, the snapshot identifier (§3.1), and
  `bytes`, the octet count of the identified file, an integer ≥ 1;
  `subject` is the identifier and MUST equal `details.sha256`. Both are
  REQUIRED. An act whose `bytes` is not the named file's octet count
  fails its `details` contract (`WIST4-E04`); which snapshot is in force
  at a height follows §3.1.

**Envelope eligibility and precedence.** Every party validating a
Registry Update — an Aggregator before sealing one, and any party
replaying the Log — MUST apply WIST-1 §4's JSON/JCS eligibility first;
failure is `WIST1-E05`. Preserve the original signed object; parsing
MUST reject duplicate decoded member names, including inside nested
objects. Then validate the complete Envelope against
`schemas/registry-update.schema.json`. A failure in a member the schema
constrains for the act's `action` — `details`, or a `subject` outside
the shape that action's contract fixes — is `WIST4-E04`, except two
failures of a `parameter_change`, which are no field failures: a string
`details.parameter` that names no §5 identifier, with a `subject` that is
the same string, and an integer `details.value` outside its §5 bound.
Such an act proceeds to authentication and is rejected under §5
(`WIST4-E03`); a non-string `parameter` stays `WIST4-E04`. Any other field
failure is `WIST4-E11`: a missing or unknown Envelope, `update` or `sig`
member; a non-object container; a malformed `wist_version`, `action`,
`effective_at` or signature field; a `subject` outside the general bound;
and a leap second or a timestamp denoting no instant (WIST-3 §3.1), year
zero included. E11 takes precedence over E04; field failures take
precedence over authenticity and semantic diagnostics. Replay identifies
every Registry Update by its ID (§2), which hashes `update` alone. An
occurrence that fails the JSON/JCS eligibility or the field validation
above is rejected with that failure's code whether or not its ID was
accepted earlier, and changes no state either way. An occurrence that
passes them and carries an ID already accepted at a lower Epoch, or
earlier in the same Epoch, is idempotent (which IDs a rejected Epoch
accepts: WIST-3 §3.3, **Rejected Epochs**) — it applies nothing and rejects
nothing, so only the earliest sealing Epoch participates. A Consumer
resumed from a Snapshot holds as accepted at or below its `tree_size` the
IDs of the Snapshot's `registry_update` tuples (WIST-3 §7).

`wist_version` MUST contain exactly three dot-separated nonnegative ASCII
decimal components, without leading zeros except `0` itself, prerelease
or build suffixes, or a numeric upper bound; a major other than `1` is
`WIST4-E11`, and a different minor or patch component alone MUST NOT
reject. This is the act's own version check, independent of any object
it names.

After field validation, authenticate the act under the Log key
`sig.key_id` names, valid at the height WIST-3 §3.4 fixes — the height
below the act's Epoch for a key act, the act's Epoch for every other —
with WIST-1 §4's profile. An act whose `sig.key_id` names no such key,
or whose
signature does not verify under the key it names, is `WIST4-E11`.
Authenticity takes precedence over semantic diagnostics, a key-act
failure's `WIST4-E04` among them.

An act rejected under `WIST1-E05`, `WIST4-E11` or `WIST4-E04`, or left
unauthenticated, is ignored as every §7 rejection is: it changes no key
registry, schedule or withdrawal state, and leaves the containing Epoch
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
name on the same subject; its `expires_at` ends its application at an
Epoch instant; its `delta` binds it to one Item of a URL (WIST-2
§3.3).

**Treatments.** What a Consumer does with a labeled subject is a
**treatment**: `hide` (the subject is not presented), `warn` (presented
with the Label shown) or `inform` (the Label is available to whoever
asks). A Consumer's profile names a treatment per Labeler and name; for
a name its profile does not cover it applies the treatment the
Labeler's definition of the name declares (WIST-2 §3.3), and `inform`
where no definition verifies. A Labeler therefore states, in public and
under its signature, how strongly it means each name, and a Consumer
that follows it does so knowingly.

**Disputes.** The domain a Label is about may answer it with a signed
dispute (WIST-2 §3.3), sealed beside the Labels and carried to every
Consumer as the Label is. No party in this suite rules on a dispute:
the Aggregator seals it and applies nothing, the Snapshot carries both
sides, and a Consumer's profile decides how a disputed Label is treated
— whether a dispute lowers the treatment, suspends it, or merely shows.
What the dispute changes is that the answer travels with the
accusation, signed by the accused, where every Consumer that sees the
one sees the other.

**A recommended default profile.** A Consumer profile is the Consumer's
own; the following defaults are recommended for one that names nothing
else. Count a `wist:mismatch` or `wist:unavailable` Label against a
subject only once it has persisted across two consecutive Epochs — the
Label current, unretracted and unexpired at a height and at the height
before it — since a page changes between a Labeler's fetch and the
Publisher's next Catalog and one Epoch's disagreement is the ordinary
course of publication, not evidence. Ignore a Labeler with no sealed
Entry of any type within a configured number of Epochs, 720 by default
(thirty days at the default cadence): an unattended labeler is a set of
opinions nobody stands behind. Both rules read the Log alone and are
exercised by `vectors/wist3/label-tables.json`.

**Labeler statistics.** The Aggregator materializes, per Labeler, how
many Labels it has sealed, how many of those retract, how many distinct
subjects it has labeled and the height it first labeled at (WIST-3 §7,
`tier1/labelers.parquet`), reading no Label's meaning. A Consumer can
recompute every figure from the Log; the table exists so that the
question a subscription decision starts with — what has this Labeler
done — has an answer before the Consumer trusts anything.

This registry fixes names, subjects and meanings and nothing else. No
party in this suite aggregates Labels into a score, and no Consumer is
bound to apply any Label: which Labelers a Consumer subscribes to, how it
weighs their Labels and what it does with a `wist:trust-seed` are its own
policy, exactly as ranking is ([ADR-0008](../decisions/0008-raw-citation-graph-never-a-score.md)).
Two readings are recommended to every ranking policy that propagates
trust or distrust along the signed link graph, because the alternative
readings hand the graph to whoever holds the cheapest names: propagate
over Registrable Domains (§3.1), collapsing every host of one
Registrable Domain into one node under the snapshot in force at the
height ranked, so that a thousand free subdomains are one voice and
hosts under a private-section suffix keep theirs; and read a domain's
age from the height of the first Entry the Log seals for it — its first
`publisher_declaration` Entry, or the height at which a fresh identity
activates (WIST-1 §5.2) — never from registration records, WHOIS or any source
outside the Log, which are neither replayable nor bound to the keys
that sign.
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
Epoch. Epoch validity is exclusively WIST-3 §3's; a registry that let one
bad Entry void a sealed Epoch would hand any act a veto over every other
Entry sealed beside it. The codes `WIST4-E01`, `WIST4-E02`, `WIST4-E05`
and `WIST4-E07` through `WIST4-E10` were registered by the Auditor
mechanisms this revision removed and are retired; a later revision
MUST NOT reuse them for another meaning.

| Code | Meaning and required behavior |
|---------|--------------------------------------------------------------|
| WIST4-E03 | Registry Update rejected under §5, including a prospective schedule that fails a combination rule: a `parameter_change` naming an identifier §5 does not list, a value outside its §5 bound, or an amendment §4's Invariants or §5's unamendable rules forbid. Ignored during replay; the Registry value in force is unchanged. |
| WIST4-E04 | Registry Update `details` contract violation (§5.1): a REQUIRED `details` member missing or malformed for its `action`, a `subject` outside the shape that action's contract fixes, a bare content digest, or personal data; a `payload_withdrawal` naming no Item its contract admits (§5.1); a `suffix_list_update` whose `bytes` is not the named file's octet count, or, at the Aggregator, naming a file it does not hold (§3.1); or an authenticated key act that is a key-act failure under WIST-3 §3.4 — an `aggregator_key_add` whose `key_id` or note key ID was ever admitted, or an `aggregator_key_remove` of a `key_id` not valid at the previous height. Ignored as WIST4-E03. |
| WIST4-E06 | Recomputation divergence: a published parameter value, quota or withdrawal state that does not equal the replayer's own §5 recomputation. Not an Entry rejection — a falsified-index signal: the value MUST NOT be trusted, and the divergence SHOULD be published with the `tree_size` it was computed at, since anyone replaying the Log can check the report. |
| WIST4-E11 | Registry Update Envelope failure under §5.1: a field failure outside the act's `details` and `subject` contract, including unknown members and malformed `wist_version`, `effective_at` or signature fields, in an occurrence of an already accepted Registry Update ID as in any other; a major version the validator does not implement; or an act not authenticated under a Log key valid at the height WIST-3 §3.4 fixes for it. Ignored as WIST4-E03: no key registry, schedule or withdrawal state changes, and the containing Epoch stays valid. |

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
  ingest budget as its Catalogs, tree files and Payloads (WIST-2 §5.2)
  and count against the same per-domain capacity (WIST-3 §3.2), so
  labeling cannot outrun publication. A Label
  about a subject nobody subscribes to costs its Labeler a registration
  and its Log a row.
- **Self-labeling.** A Label whose subject lies under the Labeler's own
  authority is rejected (§4, WIST-2 §3.3), so a domain cannot declare
  itself a trust seed; a domain declaring a sibling it also controls can,
  and only a Consumer's choice of Labelers answers that.
- **Unanswerable labels.** A label store that accepts every statement
  and forgets none, with no answer path and no bound, ends as an
  attestation spam sink or as a moderation queue nobody can appeal to.
  Four bounds address that here: a Label can expire, so a stale claim
  ends without its Labeler's attention; a Label can bind to one
  publication, so a corrected page is not carried under the old claim;
  the labeled domain can dispute in the Log, signed, beside the Label,
  so the answer reaches every Consumer the claim does; and a Labeler
  seals at most `labeler_epoch_entries_max` Labels and disputes per
  Epoch (§5, WIST-3 §3.2), so filling the commons with opinions costs
  Epochs as filling it with publications does. None of them judges a
  Label; each keeps the Consumer's judgement possible.
- **Domain resale.** Buying a domain or its hosting conveys no history.
  WIST-1 §5.2 binds continuity to keys: a fresh identity is visible in
  the Log as a Declaration signed by neither the previous Key Set nor its
  recovery keys, takes effect only after its activation delay, and a
  Consumer reading a domain's age or publication history from the Log
  reads it from the height at which it activates.
- **Free hostnames.** A hostname under a domain one already holds, or
  under a hosting provider's suffix, costs nothing, so any bound keyed
  per hostname is no bound. Quota, ingest budget and Epoch capacity are
  keyed per Registrable Domain (§3.1), which makes a thousand subdomains
  one unit and leaves a hosting provider's customers separate through
  the list's private section; the snapshot is pinned in the Log so the
  accounting replays identically, and a Consumer that ranks over the
  link graph is advised to collapse hosts the same way (§6). What no
  list bounds is registration itself: a party that buys a thousand
  cheap domains holds a thousand units, priced by the registries and
  visible in the Log as a thousand fresh identities.
- **Parameter capture.** A `parameter_change` is the one lever an
  Aggregator holds over every Publisher at once; the grace period, the
  bounds table, the combination rules and the prospective validation
  above bound what a single amendment can do, and every amendment is
  sealed for any party to replay.

## 9. Privacy Considerations

Everything a Registry Update carries is sealed in the Log, permanent, and
outside the withdrawal mechanism entirely — the same class as an Item's
`meta` (WIST-1 §3.7) — and §5.1 therefore forbids personal data in any of
it. A `legal_basis` names a legal ground, not the person invoking it.
Nothing in this suite requires identifying a data subject in order to
record why a Payload was withdrawn, and doing so would seal into the Log
precisely the data an erasure is meant to remove.

A Label is a statement about another party's publication and is sealed
under the same permanence. Its `name` is a registry term, its `subject` a
URL or host the Log already carries, and its `value` an integer; WIST-2
§3.3 gives it no free-text member, so a Label can name what a Labeler
found and never recite who a page is about. Labelers remain bound by
WIST-1 §9's rule that nothing beyond what the subject itself publishes
enters the Log.

## 10. Conformance Checklist

**Aggregator (governance side):**

- [ ] Signs every Registry Update under a Log key valid at the height
      WIST-3 §3.4 fixes for it, admits or removes its own keys only
      in-band and seals no key-act failure (§3, WIST-3 §3.4)
- [ ] Changes parameters only via `parameter_change` with the grace
      period, validating the prospective schedule and the Epoch-size
      guarantee at sealing (§5)
- [ ] Withdraws a Payload only by a `payload_withdrawal` naming the
      Item ID of an Item of kind `page` sealed against a Catalog of
      `subject`, the legal basis and the jurisdiction, and seals none that
      breaks that contract (§5.1, WIST-3 §6.2)
- [ ] Applies the same Ping quota to every Registrable Domain and the
      same inclusion eligibility to every domain, and seals every Catalog,
      Item, Label and dispute within `max_inclusion_epochs` of the Epoch
      it is eligible for unless it leaves under WIST-3 §3.3's rules of
      what leaves (§5, WIST-3 §3.3)
- [ ] Pins the Public Suffix List snapshot it accounts under with a
      `suffix_list_update`, serves every pinned snapshot at
      `/log/suffix-lists/<hex>.dat` without expiry, and keys quota,
      ingest budget and capacity on the Registrable Domain under the
      snapshot in force (§3.1)
- [ ] Seals every eligible Label and dispute it pulls whatever the name
      or subject, within the per-Labeler cap, rejects a self-labeling
      Label and a third party's dispute, never reads a Label when
      materializing records and never applies a dispute to a Label (§5,
      §6, WIST-2 §3.3, WIST-3 §§3.2/7)
- [ ] Materializes the labeler statistics from Entry counts alone (§6,
      WIST-3 §7)
- [ ] Enforces the §4 invariants unconditionally

**Any party replaying the Log:**

- [ ] Reads a `parameter_change` as in force from its `effective_at`
      inclusive, the greatest `effective_at` ≤ T prevailing among an
      identifier's amendments and Log order breaking an equal pair (§5)
- [ ] Applies §5.1's Registry Update field, version and authenticity
      checks and their precedence, authenticating a key act under the
      keys valid at the previous height, ignores a key-act failure as
      `WIST4-E04`, and treats a repeated Registry Update ID as
      idempotent only in an occurrence that passes field validation,
      reading the IDs accepted up to a Snapshot it resumed from in that
      Snapshot's `registry_update` tuples (§5.1, WIST-3 §§3.4, 7)
- [ ] Rejects a `parameter_change` that fails a bound, a combination
      rule, the Epoch-size guarantee or the grace period, preserving the
      accepted schedule (§5, §7)
- [ ] Ignores a withdrawal that breaks its `details` contract as
      `WIST4-E04`, judging it after a resume from a Snapshot against the
      Entries applied and the Snapshot's `record` and `removal` tuples, reads a
      withdrawal from the earliest Epoch sealing it and applies WIST-3
      §6.2 from that height (§5.1)
- [ ] Reads the snapshot in force at an Epoch as the most recent accepted
      `suffix_list_update` sealed below it, obtains and verifies the
      named octets, and derives Registrable Domains by §3.1's algorithm,
      every Canonical Host being its own before the first act (§3.1)
- [ ] Carries Labels and disputes as sealed, drops a Label at its expiry
      and reads its `delta` binding to an Item, and never aggregates them
      into a value the Log did not carry (§6, WIST-2 §3.3)

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- [RFC 8032] Edwards-Curve Digital Signature Algorithm (EdDSA) — the
  Ed25519 key format every signed object uses
- WIST-1: Item Format & Identity — Items, Catalogs, Collections, key
  rotation, §6 absence
- WIST-2: Site Publication — quotas, the ingest budget, Labels
- WIST-3: Logbook & Distribution — entry envelope, eligibility and
  capacity, checkpoints, immutability, the tree size and root hash a
  Checkpoint states (WIST-3 §§3.1, 3.3, 5)
- WIST-5: Emissions — what a Publisher builds to the defaults of §5
