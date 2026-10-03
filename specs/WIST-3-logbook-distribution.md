# WIST-3: Logbook & Distribution

**Status:** v1.0.0-draft · **Date:** 2026-08-02 · **License:** CC-BY 4.0

## 1. Introduction

The Logbook is one append-only RFC 6962 Merkle tree whose leaves are
Declarations, Catalogs and Items (WIST-1), Labels and disputes (WIST-2
§3.3) and governance actions (WIST-4), published as C2SP checkpoints and
tiles so that generic transparency-log clients and Witnesses read it
with no knowledge of this suite. Consumers verify the tree and recompute
derived artifacts. The Certificate Transparency [RFC 6962] design
rationale is recorded in
[ADR-0004](../decisions/0004-log-centric-ct-model.md) and the adoption
of the C2SP formats in
[ADR-0046](../decisions/0046-single-tree-log.md).

This document defines Epochs as intervals of the tree, the Entry format,
how Catalogs and Items are judged, wait and are sealed, the records they
leave, the tree and its proofs, Checkpoints, Witnesses and
anti-equivocation, the static distribution layout, snapshots and tiers,
and the consumer synchronization procedure.

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as
shown here.

- **Log** (the **Logbook**): the append-only RFC 6962 Merkle tree this
  document defines, whose leaves are the Entries in the order they were
  appended. "The Log" always means the whole tree, never one
  Aggregator's current view of it.
- **Epoch**: the interval of the Log between two consecutive
  Checkpoints — the leaves from the previous Checkpoint's tree size up
  to, excluding, its own — sealed together under one `sealed_at` (§3).
  An Epoch's number is its **height**.
- **Entry**: one typed item in an Epoch (`publisher_declaration`,
  `registry_update`, `publisher_catalog`, `publisher_item`, `label` or
  `dispute`), and one leaf of the tree (§3.3).
- **Publication**: a Catalog or an Item, as a pull accepts or admits it
  (WIST-2 §5.1) and an Entry seals it (§3.3).
- **Latest Catalog**, **floor**, **record**, **removal state** and
  **base**: the state replay of a Log holds per Collection and per URL
  (§7).
- **Last accepted Catalog**, **waiting**, **place** and **eligibility
  Epoch**: the Aggregator's sealing state (§3.3).
- **Log Anchor**: the self-signed document that identifies a Log by its
  `log_id` and declares its `genesis_key`; it is the Log's out-of-band
  trust root, obtained through a channel the Consumer trusts rather than
  from the Log itself (§3.4).
- **genesis key**: the Aggregator signing key the Log Anchor declares. It
  is the only Aggregator key not admitted in-band; every later one is
  added and retired by Registry Updates the genesis key's chain of
  successors signs (§3.4).
- **Checkpoint**: the Aggregator's signed statement of the tree at one
  size — a signed note in the C2SP checkpoint format, carrying the
  Epoch's number and `sealed_at` (§5). Checkpoint N ends Epoch N.
- **Witness**: a party that cosigns a Checkpoint after verifying it
  consistent with every Checkpoint of the same Log it cosigned before,
  under the C2SP witness protocol; a **Cosignature** is the signature
  line it adds (§5).
- **Consumer**: any party that synchronizes the Log and materializes an
  index from it (§8). A Consumer trusts no Aggregator and no Mirror: it
  verifies signatures, hashes and commitments for itself.
- **Mirror**: any party re-serving the log's static files.
- **Snapshot**: a signed, derived materialization of log state at an Epoch.
- **Tier**: a size/completeness layer of a Snapshot (Tier 0 compact,
  Tier 1 full extracts and the link graph).
- **Inclusion Proof**: a Merkle audit path proving an Entry is a leaf of
  the tree a Checkpoint states (§4).
- **Consistency Proof**: the RFC 6962 proof that the tree one Checkpoint
  states extends the tree an earlier one states (§4).
- **Payload**: the content an Item of kind `page` commits to (WIST-1
  §3.6), distributed alongside the Epoch that seals that Item and not
  inside it (§6.1).
- **Withdrawal**: the logged removal of a Payload from distribution,
  under §6.2.

Terms from WIST-1 (Envelope, Item, Item ID, Catalog, Catalog ID,
Collection, Scope, key, leaf, root, Canonical Bytes, Publisher,
Publisher Declaration, Aggregator, Canonical Host, Normalized URL,
idempotent re-serve) and WIST-2 (Label, Labeler, Label Feed, pull) keep
their defined meanings; an Item's Inclusion Proof against its Catalog has the
form of §4 (WIST-1 §4.3). Every
signed object in this document except the Checkpoint is constructed exactly as WIST-1 §4 requires —
inner object canonicalized with JCS, signed with Ed25519, signature
detached — and carries `wist_version` (WIST-1 §3.1) and the WIST-1 §4 signature
block (`key_id`, `alg`, `value`). The Checkpoint is a signed note under
the C2SP formats §5 names, signed by the same Aggregator keys (§3.4).

In the vocabulary of RFC 9943 (SCITT), the Aggregator is the
Transparency Service, a Publisher an Issuer, the URL an Item is about
(WIST-1 §3.2) the Subject, the admission rules (WIST-1 §7, WIST-2 §5,
§3 of this document) the Registration Policy, and an Inclusion Proof
against a cosigned Checkpoint the Receipt. The mapping places the suite
for a reader arriving from SCITT and adds no object: a COSE-encoded
Receipt is OPTIONAL and undefined in this edition, because it would be
a second encoding of the proof §4 already defines.

## 3. Epoch Format

An Epoch is the interval of the Log between two consecutive Checkpoints.
Write `size(N)` for the tree size Checkpoint N states (§5), with
`size(-1)` = 0: Epoch N's Entries are the leaves with indexes from
`size(N-1)` up to, excluding, `size(N)`, and its `entry_count` is
`size(N) - size(N-1)`, derived and never carried. No object represents an
Epoch: Checkpoint N is its signed statement, and its Entries are served
as §6 describes.

### 3.1. Identity and `sealed_at`

Checkpoint N states, for Epoch N:

| Value | Rule |
|-------------------|------------------------------------------------------|
| `epoch_number` | Sequential from 0, no gaps. |
| tree size | `size(N)` ≥ `size(N-1)`; equality is an empty Epoch. |
| root hash | Root of the tree at `size(N)` (§4); the tree at `size(N-1)` is its prefix, which a Consistency Proof verifies (§5). |
| `sealed_at` | RFC 3339 UTC at **whole-second precision with a literal trailing `Z`**; strictly increasing across Epochs. |

`sealed_at` MUST match `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9]Z$`:
no fractional seconds, and no numeric offset
even one equal to zero. An Epoch whose `sealed_at` carries either MUST be
rejected. RFC 3339 permits both, but every day count in the suite — a
recovery window (WIST-1 §5.2), the availability window (§6.1), a parameter's
grace period (WIST-4 §5) — is derived from these values by converting them
to integer seconds, and a fractional or offset form would make that
conversion a rounding decision that two implementations could take
differently — one rounded half-second can move a whole-day boundary and
with it a window's end. Constraining the field is cheaper than specifying a rounding rule,
and it costs the Aggregator nothing: it chooses when to seal.

The date and time MUST be valid in the Gregorian calendar. Seconds are
`00` through `59`: a leap-second spelling with `:60` MUST be rejected,
never normalized to another instant. Integer Unix seconds count exactly
86,400 seconds per calendar day from 1970-01-01T00:00:00Z, without leap
seconds; 2016-12-31T23:59:59Z and 2017-01-01T00:00:00Z are one second
apart. The same profile applies wherever the suite requires this
whole-second, literal-`Z` form, including the Snapshot state timestamps
in §7. Other RFC 3339 fields retain their specified formats.

What it does not choose is the timestamp inside that choice: `sealed_at`,
converted to integer Unix seconds, MUST be an integer multiple
of `epoch_cadence_seconds` as in force at the previous Epoch's
`sealed_at`, and a Consumer replaying the Log MUST reject an Epoch off the
grid. The grid leaves the Aggregator its sealing cadence and removes
its choice of digits, so an Epoch's instant is a fact of the schedule
rather than an operator's choice. The first Epoch after a `parameter_change` to
`epoch_cadence_seconds` takes effect lands on the new grid; the Anchor's
own `created_at` is not an Epoch and is unconstrained.

The table's rules fail as follows. A gap is never an object a Consumer
holds: it verifies Checkpoints in `epoch_number` order (§5), so it
verifies no Checkpoint N+1 and applies nothing of Epoch N+1 before
Checkpoint N, and an archived Checkpoint no source serves is `WIST3-E01`
(§6). A Checkpoint N whose `sealed_at` is not later than Checkpoint
N−1's, or is off the grid, is `WIST3-E03`, whether or not its signature
verifies. One that verifies under the key set valid at N is misbehavior
no source repairs: the Log can sign no other Checkpoint N without
equivocating (§5), so the Consumer keeps its verified head at N−1 and
the remedy is succession (§3.4). A Checkpoint N stating a tree size
below Checkpoint N−1's has no Entries to walk, so the key set valid at
N is the one valid at N−1. It is `WIST3-E03` with the same
consequences, unless its signature verifies under that set and its
root is not the root of Checkpoint N−1's tree at the smaller size:
that is §5's third form of Equivocation (`WIST3-E02`), with Checkpoints
N−1 and N and the tree hashes of the larger tree as the evidence. A
Checkpoint failing more than one of these rules is `WIST3-E02` when
that form applies and `WIST3-E03` otherwise.

An Epoch is identified by its number; what its Checkpoint states about
the tree is the pair (tree size, root hash), which an empty Epoch shares
with the Epoch before it (§3.2), and an Epoch has no hash apart from
the root. Where this suite
carries an Epoch's root hash in a JSON member — `root_hash` (§7),
`final_root_hash` (§3.4) — it is `"sha256:" + hex(root hash)`, the
same 32 octets the Checkpoint's root hash line carries in base64 (§5).

Checkpoint N commits to the Epoch's Entries through the tree: a verifier
holding Checkpoints N−1 and N knows the Epoch's leaf range and
authenticates any Entry against Checkpoint N with an Inclusion Proof
(§4). Entries are transported unsigned (§6); a verifier that downloads an
Epoch's Entries MUST verify, before use, that their leaf hashes occupy
that range in the tree whose root Checkpoint N states — an Inclusion
Proof per Entry, or the recomputation of that root from the tree hashes
it holds, which is the same check made once.

### 3.2. Sealing

Epochs are sealed at a fixed cadence (Parameter Registry, WIST-4 §5;
default: hourly): at a grid instant of §3.1 the Aggregator appends the
Epoch's Entries to the tree in the order §3.3 fixes and issues its
Checkpoint (§5). The Aggregator MUST issue a Checkpoint at every grid
instant, an empty Epoch — a Checkpoint restating the previous tree size
— where nothing is eligible; empty Epochs keep the Log's heartbeat
observable, and a replaying Consumer, which sees only the Checkpoints
issued, checks each against the grid and does not reject a missed
instant (§5 gives the staleness signal). Once sealed, an Epoch is
immutable forever: its Entries' leaf indexes never change and no later
Checkpoint omits them.

**Per-domain Epoch capacity.** An Epoch MUST NOT carry more than
`domain_epoch_entries_max` (Parameter Registry; default 10 000)
`publisher_catalog`, `publisher_item` and `label` Entries, counted
together, whose Publisher's or Labeler's Canonical Host has one
Registrable Domain under the Public Suffix List snapshot in force at the
Epoch (WIST-4 §3.1), and a Consumer replaying the Log MUST reject an
Epoch that does (`WIST3-E03`). The Publisher's Canonical Host of a
`publisher_catalog` Entry is its `catalog.publisher` and that of a
`publisher_item` Entry its `item.publisher`, and the Labeler's of a
`label` Entry its `label.labeler`; such an Entry counts whether its
judgment (§3.3) finds it valid or ignores it, and one whose member is
not a Canonical Host counts toward no domain. The unit is the Registrable
Domain, not the hostname, because a hostname under a name one holds is
free; before the first accepted `suffix_list_update` every Canonical
Host is its own unit. `dispute` Entries count with the publications and
Labels of the unit of their `dispute.disputant`, and one whose
`disputant` is not a Canonical Host counts toward no domain. The
Publishers and Collections of one Registrable Domain share its capacity,
and no Collection has a share of its own. **Per-Labeler cap.** Inside that capacity, an Epoch MUST NOT
carry more than `labeler_epoch_entries_max` (Parameter Registry; default
1 000) `label` and `dispute` Entries, counted together, of one
Registrable Domain, and a Consumer replaying the Log MUST reject an Epoch
that does (`WIST3-E03`); the surplus waits its turn in the order of
places (§3.3) like any other. The cap never exceeds the per-domain
capacity (WIST-4 §5), so a Labeler's Labels are bounded twice and its
publications once: labeling is an opinion about other parties'
publications, and a party that could fill an Epoch with opinions as
freely as with publications would make every Consumer's subscription
list the only bound on it. Where a Registrable Domain has more Entries
eligible for an Epoch than the capacity admits, they take it in the
order §3.3 gives across its Publishers and Collections, and the capacity
defers the rest with their inclusion ceiling (§3.3) — so the capacity
never obliges an Aggregator to breach the ceiling, nor the ceiling to
breach the capacity. This is the one bound in
the suite on how much a domain may publish, and it is deliberately a
bound on *rate*, not on worth or on standing: every Registrable Domain
has the same quota and every domain the same eligibility (WIST-4 §5), judging
content's worth is outside the protocol (ADR-0006), and a ceiling that
grew with any standing would re-create the pay-for-position pressure
Invariant 2 exists to forbid — so the cap is flat, high enough that a large site's
backfill crosses it in days, and low enough that filling the whole
commons with honest junk is a project of years conducted in public
rather than a weekend purchase. What the cap does not do is also stated:
content nobody wants is not a protocol violation, and which records
deserve a consumer's attention is ranking, decided at consumption
(ADR-0006, ADR-0008), not admission.

**A Label is sealed once.** A Label ID (WIST-2 §3.3) MUST appear in at
most one `label` Entry in the whole Log. An Aggregator that pulls a Label
it has already sealed holds it as seen (WIST-2 §5.5) and MUST NOT seal it
a second time; a Consumer replaying the Log MUST reject an Epoch
containing a `label` Entry whose Label ID a lower Entry — in the same
Epoch or an earlier one — already carries (`WIST3-E03`). Together with
immutability above, this makes "the Epoch that sealed this Label" a
function. An Item may be sealed more than once (§3.3).

**Refresh.** A Catalog whose `root` is its latest Catalog's is valid only
as C4 (§3.3) allows, reading `catalog_refresh_seconds` (WIST-4 §5; default
604 800 seconds); the part of a Publisher that signs signs each
Collection's Catalog at least as often as the suite value states,
whatever a Log has amended (WIST-5). A `parameter_change` of
`catalog_refresh_seconds` to a value below 1 or above 7 776 000 seconds,
90 days, is outside its bound (`WIST4-E03`): a Publisher that signs a
Collection at least once in 90 days then has its first unchanged Catalog
pass C4 at most 15 552 000 seconds after the floor, which is never a base
(§7), so a refresh of an unchanged Collection removes no record.

### 3.3. Entries

Each Entry is `{"type": <t>, "body": <b>}`, where `type` is one of exactly
six values and `body` is the object that value names:

- `publisher_declaration` — a Publisher Declaration Envelope (WIST-1 §5.1).
- `registry_update` — a Registry Update Envelope (WIST-4 §3).
- `publisher_catalog` — a Catalog Envelope (WIST-1 §3.5).
- `publisher_item` — an object with exactly the members `item`, an Item
  (WIST-1 §3.3); `collection`, the name of its Collection in the form of
  WIST-1 §5.1; `catalog`, the Catalog ID of the Catalog it is proved
  against; and `proof`, its Inclusion Proof against that Catalog (WIST-1
  §4.3) (schema:
  [`schemas/publisher-item.schema.json`](../schemas/publisher-item.schema.json)).
- `label` — a Label Envelope (WIST-2 §3.3).
- `dispute` — a Dispute Envelope (WIST-2 §3.3).

The body of `registry_update` is normative in WIST-4, of `label` and
`dispute` in WIST-2, and of `publisher_declaration` and `publisher_catalog`
in WIST-1; this section defines the `publisher_item` body. Validators MUST
reject Epochs containing unknown Entry types under the current major
version (`WIST3-E03`). An Entry that is not a JSON object with exactly the
members `type` and `body` is rejected the same way, with its Epoch
(`WIST3-E03`): the Entry form is the Log's own, and no rule reads a member
beside the two.

A `body` that is not a JSON object rejects no Epoch by this section. It is
a field failure of the object its `type` names and takes the consequence
that object's rules give one: a `publisher_declaration` Entry fails its
acceptance checks (`WIST1-E14`, WIST-1 §5.1) and rejects the Epoch as any
failing Declaration does; a `publisher_catalog` Entry fails C1 and a
`publisher_item` Entry fails I1 (`WIST1-E14`), and a `registry_update`
Entry is a non-object container under WIST-4 §5.1 (`WIST4-E11`), each
ignored in an Epoch that stays accepted; a `label` or `dispute` Entry
fails the field check of WIST-2 §3.3 (`WIST2-E06`).

**An Entry fits one leaf.** An Entry's JCS serialization — its leaf
data (§4) — MUST NOT exceed 65 535 octets, the largest length the
16-bit prefix of an entry bundle can carry ([tlog-tiles], §6). The
Aggregator MUST NOT seal a larger Entry, and a Consumer replaying the
Log MUST reject an Epoch that contains one (`WIST3-E03`).

**Entry order is canonical.** Within an Epoch, Entries MUST appear grouped
by type in the fixed order `publisher_declaration`, `registry_update`,
`publisher_catalog`, `publisher_item`, `label`, `dispute`, and within each
group in ascending octet order of each Entry's Merkle leaf hash (§4). A
Consumer replaying the Log MUST reject an Epoch ordered otherwise
(`WIST3-E03`). The rule exists for the same
reason as the `sealed_at` grid (§3.1): Entry order fixes each leaf's
index, and with it the root hash every Checkpoint from N on states, and
a free permutation of Entries would let one set of Entries seal under
many roots. Canonical order leaves the Aggregator its one real choice,
Epoch membership. An Entry's leaf index (§4) is `size(N-1)` plus its
position in this order, so Log order — ascending Epoch number, then
Entry index — is ascending leaf index.

Storage order and application order are therefore decoupled, and
**application order** is defined, not inherited: within an Epoch, apply
`publisher_declaration` Entries first (for each domain, validate and apply
them in ascending `seq`, after settling any recovery window whose end is
at or before this Epoch's `sealed_at` and activating any pending head
whose activation height is this Epoch's; WIST-1 §5.2 retains the highest
accepted sequence through settlement and selects a recovery window's owner in
ascending `(Epoch number, seq)` order, so intra-Epoch storage position
never decides between them; a fresh Declaration applied before that owner
becomes pending, while an in-window fresh competitor does not),
with equal-sequence groups handled by WIST-1 §5.2: conflicting first-install
Envelopes invalidate the entire Epoch under `WIST1-E08`; current-Declaration
re-serves and exact duplicates install no additional state or signature.
Narrowing applies with them (WIST-1 §5.2).
Every Declaration must pass its acceptance checks; on failure reject the
whole Epoch with the applicable error, preserving the previously accepted
prefix and all its state, including recovery windows due to settle in the
rejected Epoch. Then apply `registry_update` Entries (key acts first, in
canonical Entry index order, each authenticated under the keys valid at
the previous height; then every other act, authenticated under the keys
valid at this Epoch, §3.4;
`parameter_change` validation and equal-effective-time precedence read
canonical Entry index under WIST-4 §5; the `details` contract of a
`payload_withdrawal` reads the `publisher_item` Entries of its own Epoch,
which apply after it, WIST-4 §5.1), then `publisher_catalog` Entries and
then `publisher_item` Entries, each group in ascending Entry index, a
base removing its Collection's records when its Catalog applies (§7).
`label` Entries apply next, in ascending Entry index in the canonical
stored order, which WIST-2 §3.3 reads to order two Labels of one Labeler
sealed in one Epoch, and `dispute` Entries last, in the same order, which
orders two disputes of one Label by one disputant; a dispute applies
nothing to the Label it names. No conforming behavior depends on any ordering freedom this
paragraph does not name. An Epoch that meets more than one whole-Epoch
rejection of §3.2, this section or WIST-1 §5.2 is rejected; a validator
MAY report the code of any it has established.

**Declaration sealing obligation.** An Aggregator MUST seal every
Declaration under which a pull read at or below the Epoch that seals the
first Catalog that pull accepted or Item it admitted (WIST-2 §5.1),
except a Declaration WIST-1 §5.2 removes from the eligible sealing set;
the inclusion ceiling of those publications bounds its sealing (WIST-1
§5.2, **Reaching the Log**).

**Judgment.** An Entry of Epoch N is judged once, at N, and not again:
under the Declaration in force for its Publisher once every transition
of Epoch N has applied (WIST-1 §5.2, **Historical verification**), under
the parameter map in force at N's `sealed_at` (WIST-4 §5), and with N's
`sealed_at` as the clock (WIST-1 §3.4). The Publisher of a
`publisher_catalog` Entry is `catalog.publisher`, and that of a
`publisher_item` Entry is the `publisher` of its named Catalog (I3),
whatever `item.publisher` spells. A Catalog of a Publisher with no
Declaration in force has no candidate and fails C1 with `WIST1-E02`.
Whether a recovery window of the Publisher is open at N is WIST-1 §5.2's
(**Publications during recovery**).

A `publisher_catalog` Entry is valid when all four conditions hold.

| # | Condition |
|---|---|
| C1 | The Catalog meets none of WIST-1 §7's Catalog conditions but `WIST2-E04` and `WIST2-E05`, which apply at a pull |
| C2 | No recovery window of the Publisher is open at N |
| C3 | Its Publisher and Collection name have no floor (§7), or `generated_at` is later than the floor |
| C4 | The name has no latest Catalog (§7); or `root` is not the latest Catalog's; or `generated_at` is at least `catalog_refresh_seconds` (§3.2) later than the floor; or the latest Catalog fails the binding check (WIST-1 §5.1) at N |

A `publisher_item` Entry is valid when all seven conditions hold, read
once the `publisher_catalog` Entries of Epoch N have applied.

| # | Condition |
|---|---|
| I1 | The body has the form above, the Item's own form (WIST-1 §7's `WIST1-E14` Item conditions) and the proof's (WIST-1 §4.3) included |
| I2 | No recovery window of the Publisher is open at N |
| I3 | `catalog` is the Catalog ID of a latest Catalog (§7), the **named Catalog** |
| I4 | The Declaration in force names the named Catalog's Collection, and the named Catalog passes the binding check at N |
| I5 | `collection` is the named Catalog's `collection`, and the Item meets none of WIST-1 §7's Item conditions, judged with the named Catalog |
| I6 | `proof` verifies against the named Catalog (WIST-1 §4.3) |
| I7 | An Item of kind `page` is not the Item of its URL's record (§7), and no `payload_withdrawal` sealed in an Epoch below N names its Item ID; an Item of kind `removed` has a record for its URL. The record is that of the Publisher and the URL, whatever Collection it carries |

C2 to C4 are read only for a Catalog that meets neither `WIST1-E05` nor a
`WIST1-E14` condition. Where I1 fails no other condition of the Item is
read, and I2 and I4 to I7 are read only where I3 holds, since they read
the named Catalog. I7 reads, of each `payload_withdrawal` that meets its
`details` contract (WIST-4 §5.1), the Item ID it names in
`details.delta_id`, and nothing else; a withdrawal that breaks its
contract names no Item.

A valid Catalog becomes the latest Catalog of its Publisher and
Collection name (§7). A valid Item of kind `page` becomes the record of
its Publisher and URL in place of any record they had, and a valid Item
of kind `removed` removes that record (§7). An
Item may be sealed in a Log more than once: after narrowing or a base
removed its URL's record, the Item that record carried passes I7 again,
unless a withdrawal names it, and is sealed again against the latest
Catalog.

An Entry that is not valid is **ignored**: it changes no state, the floor
included, and the Epoch stays accepted. An Entry that names an ignored
Catalog, a replaced one or one never sealed fails I3.

| Condition failed | Code |
|---|---|
| I1 | `WIST1-E14` |
| C1, I5 | The code of the Catalog condition, of the body rule (`WIST1-E17` for a `collection` that is not the named Catalog's) or of the Item condition met |
| I4 | `WIST1-E03` for a Collection the Declaration does not name; otherwise `WIST1-E02` or `WIST1-E01`, as the binding check distinguishes them |
| I6 | `WIST1-E17` |
| C2, C3, C4, I2, I3, I7 | `WIST3-E06` |

`WIST1-E05` and the `WIST1-E14` conditions are checked first; among the
others WIST-1 §7 leaves the choice of diagnostic.

An Epoch is rejected whole, with `WIST3-E03`, when two of its
`publisher_catalog` Entries carry the same strings as `catalog.publisher`
and as `catalog.collection`, whether or not either is valid; an Entry in
which either member is not a string is compared with none.

**Waiting.** An Aggregator seals no Entry the judgment ignores, no Epoch
that a Consumer rejects and no `payload_withdrawal` that breaks its
`details` contract. The rules from here to the end of this section bind
the Aggregator alone: the Log does not show an acceptance, so no Consumer
derives them. A pull accepts Catalogs and admits Items (WIST-2 §5.1);
from the discovery of a recovery rotation until the settlement of its
window, WIST-1 §5.2 (**Publications during recovery**) queues and holds
what it accepts and admits instead, and gives what survives settlement
its place and eligibility.

The **last accepted Catalog** of a Collection is the Catalog a pull
accepted last, unless it failed C1 at its turn, and the latest Catalog
otherwise. The order of a pull (`WIST2-E05`) and the idempotent re-serve
(WIST-1 §7) read it. Per Collection at most one Catalog waits, and per
Publisher and URL at most one Item.

| | A Collection's Catalog | A URL's Item |
|---|---|---|
| Waits | The last accepted Catalog, while it is not the latest Catalog and has not failed C4 at its turn | The Item the last accepted Catalog lists for the URL, while the Item is admitted (WIST-2 §5.1) and I7 holds for it |
| Place | Taken at the pull that accepts a Catalog while none of the Collection waits. A later accepted Catalog takes the place and the eligibility Epoch of the waiting one it replaces | Taken at the pull from which the URL waits, and kept with its eligibility Epoch while the URL waits without interruption, whichever Item waits for it |
| Leaves | When sealed. When it fails C1 at its turn, whether or not it fails C4: it is reported with C1's code alone at the status endpoint (WIST-2 §7.1) and is no longer the last accepted Catalog. When it fails C4 alone at its turn: it is not reported and stays the last accepted Catalog | When sealed. When the URL no longer waits: an Item for which I7 no longer holds once the Epoch's transitions and Catalogs have applied leaves unreported, whatever other condition it fails. When the Item fails I5 at its turn: it is reported with the code and is a refused Item of its list |

A Label or a dispute waits from the pull that accepts it. It leaves when
sealed, or when it fails at its turn a check of WIST-2 §3.3 that the
Aggregator repeats before sealing under the candidate Epoch's parameter
map and clock (WIST-4 §5, WIST-1 §§3.4, 3.6): it is then not sealed and
is reported among the status endpoint's `rejections` (WIST-2 §7.1) with
the code of that check and its Label or Dispute ID. It leaves no other
way.

An idempotent re-serve replaces no Catalog and gives no waiting Item
another place. Where the last accepted Catalogs of two Collections of a
Publisher each list for one URL an admitted Item for which I7 holds, the
Item that waits at an Epoch is that of the Collection whose Scope covers
the URL under the Declaration in force once that Epoch's transitions
have applied, and where no Scope covers it, that of the Catalog later in
the Catalog order (WIST-1 §3.5); at a pull the Declaration read for this
is the current one of the sealed history. The Item that waits for a URL
at an Epoch is read once that Epoch's transitions and Catalogs have
applied and takes the URL's turn in that Epoch, with the place and the
eligibility Epoch the URL has; an Item it replaces for the URL leaves
without a report, the URL having waited without interruption.

**Places.** A URL that begins to wait at an Epoch or at a settlement, and
not at a pull, takes its place there. A Label or a dispute takes its
place at the pull that accepts it, after the places that pull gives
Catalogs and URLs, and among the Labels and disputes of that pull in the
order the pull accepts them. A place taken at an event comes after every
place taken at an earlier one, and places taken at one Epoch, one
settlement or one pull are ordered by the Publisher's Canonical Host in
ascending octet order, then by the order of the Collections of the
Declaration in force for that Publisher, a Collection that Declaration
does not name coming after the named ones in ascending octet order of
name, then by the order of the list. For this order the Declaration in
force is, at an Epoch, the one in force once its transitions have
applied; at a settlement, the one it leaves current; at a pull, the one
the pull reads Collections from, and with two sources the one in effect
before the recovery. For this order a settlement and the Epoch at which
it settles are one event; the eligibility of what a settlement keeps is
WIST-1 §5.2's.

**Eligibility.** A Catalog, an Item, a Label or a dispute is eligible
for the Epoch that follows the event at which it took its place, and the
inclusion ceiling (`max_inclusion_epochs`, WIST-4 §5) counts from the
Epoch it is eligible for. A replacement that keeps a place moves no
eligibility Epoch. Each of the following **deferrals** defers the
eligibility, and the ceiling with it, to the first Epoch at which none of
them applies. Each that applies to a Catalog or an Item is reported at
the status endpoint (WIST-2 §7.1) under the name it carries; those of a
Label or a dispute are not reported:

1. `recovery_window`: for a Catalog or an Item, a recovery window of the
   Publisher open at the Epoch;
2. `capacity`: no room in the capacity of the Registrable Domain (§3.2),
   taken in the order below, and for a Label or a dispute no room under
   the per-Labeler cap (§3.2) either;
3. `catalog_waiting`: for an Item, a waiting Catalog of its Collection
   that one of the two above holds out of the Epoch;
4. `latest_fails_i4`: for an Item, a latest Catalog of its Collection
   that fails I4 at the Epoch, while no Catalog of that Collection waits
   that nothing defers.

Nothing else defers a Catalog or an Item. Whether a recovery window open
for a Labeler or a disputant defers its Labels and disputes is not fixed
by this edition.

Every deferral that applies to a Catalog or an Item at an Epoch is
reported for it, in the order of this list; the capacity defers only
what nothing else defers at that Epoch, and where `recovery_window`
applies it is the only deferral reported (WIST-1 §5.2, **Queue**).

A Declaration that reduces authority orders the sealing and defers
nothing: its **hold** (WIST-1 §5.2, **Reaching the Log**) keeps the
publications of its Publisher out of the Epochs below the one that seals
it, and Labels and disputes are not held. A Catalog or an Item that the
hold keeps out of an Epoch takes no room in the capacity there, and
neither the hold nor the capacity moves its eligibility Epoch or its
ceiling at that Epoch; where a recovery window of the Publisher is open
at the Epoch, the window defers it. It is reported at the status
endpoint as held where no deferral applies to it, and with the deferral
where one does.

**Sealing an Item.** An Item is sealed in an Epoch only when, once the
Epoch's Catalogs have applied, the latest Catalog of its Collection has
the `root` of the last accepted Catalog and passes I4; the Entry names
that latest Catalog and carries the proof against it. While a Catalog of
another `root` waits, the Items of its Collection wait with it. While the
latest Catalog fails the binding check, they wait, with their places,
for the Catalog the Publisher signs next. A waiting Catalog that nothing
defers is sealed at or below the Epoch that seals an Item of its
Collection, so the earliest ceiling among the waiting Items of its
Collection bounds its sealing; an Item that had reached its eligibility
Epoch keeps it and its ceiling when a Catalog of another `root` is
accepted.

Before sealing an Item of kind `page`, however it was admitted, the Item
of its URL's record that waits under a base included (§7), the
Aggregator checks its Payload by WIST-1 §7's Payload checks against the
Item's `payload`, under the parameter map in force at the candidate
Epoch's `sealed_at`, at the Item's turn in that Epoch when the capacity
has room for it, and at no Epoch that defers it or that the hold
keeps it out of; a Payload the Aggregator
does not hold at the Item's turn fails the check. An Item whose Payload
fails at its turn takes no room, is not sealed, is no longer admitted and
is reported with `WIST2-E03`; the other Items proceed. The Payloads named
by the withdrawals an Epoch seals are destroyed (§6.2) before its Items
take their turn, so an Aggregator seals no Item in the Epoch that seals
the withdrawal of its Payload; replay accepts such an Item, I7 reading
the withdrawals of earlier Epochs alone.

**Capacity order.** In an Epoch the capacity of a Registrable Domain is
taken first by its Catalogs, then by its Items of kind `removed`, then by
its Items of kind `page`, its Labels and its disputes together, and
within each of the three in the order of the places; the per-Labeler cap
(§3.2) applies inside it. A Catalog or an Item that fails its judgment at
its turn takes no room, and the next in order takes it. Nor does an
eligible Catalog, Item, Label or dispute that the Aggregator leaves
unsealed in the Epoch: `capacity` defers only what does not fit, under
the capacity or the per-Labeler cap, after the Entries sealed before it
in the order of the places. C2 defers a waiting Catalog and fails none,
and C3 fails none that a pull accepted or a settlement kept, since the
order of the pull and the settlement read the floor.

### 3.4. Aggregator Keys and the Log Anchor

A Log is identified by its **Log Anchor**, a self-signed document whose
inner object is `anchor` (schema:
[`schemas/log-anchor.schema.json`](../schemas/log-anchor.schema.json)),
served at `/log/anchor.json`. It declares `wist_version`, the `log_id` (the
Log's hostname identity, and the origin line of its Checkpoints, §5), the `genesis_key` — an object carrying that key's
`key_id`, `alg` and raw base64url `public_key` — and `created_at`, the
instant the Log was established. A party MUST validate an Anchor against
its schema before it verifies the signature, and MUST reject one that
fails it with `WIST3-E03`. A member present with a value the schema does
not admit fails it: an Anchor carrying `"predecessor": null` is rejected,
and is not an Anchor without a predecessor. The Anchor is self-signed: its
`sig.key_id` MUST name its own `genesis_key`, and a Consumer MUST reject
an Anchor whose signature does not verify under the very key it declares.

The Anchor is the Log's out-of-band trust
root: a Consumer MUST obtain it through a channel it trusts (bundled with
the client, pinned by the operator, or verified against an out-of-band
fingerprint) and MUST NOT accept an Anchor fetched from the Log itself
without such verification. Anchors are content-addressed by
`"sha256:" + hex(SHA-256(JCS(anchor)))`, so a fingerprint is short enough to
publish in documentation or a package manifest.

All subsequent Aggregator keys are admitted in-band: an
`aggregator_key_add` Registry Update adds a key and an
`aggregator_key_remove` retires one; the two are the **key acts**. A
`key_id` is **valid at height N** if it is the genesis key, or an
accepted `aggregator_key_add` naming it was sealed at a height ≤ N, and
no accepted `aggregator_key_remove` naming it was sealed at any height
≤ N. A key act is **accepted** when it passes WIST-4 §5.1's field
validation, authenticates under the next paragraph's rule and is not a
key-act failure (below). The key set valid at height −1 is the genesis key
alone.

**Authentication heights.** A key act sealed in Epoch N is authenticated
under the keys valid at height N−1. Every other Registry Update sealed
in Epoch N, and Checkpoint N (§5), is authenticated under the keys valid
at height N, the set that results from all of Epoch N's accepted key
acts. A key may therefore sign its own removal; a key added in Epoch N
signs no key act of Epoch N and may sign Epoch N's other acts and
Checkpoint N; a key removed in Epoch N may sign Epoch N's key acts and
signs neither its other acts nor Checkpoint N. The key set valid
at N does not depend on the order in which Epoch N's key acts are
evaluated, except through the Entry-index tie-break between two
additions (below). The genesis key is removable like any other key. An
Epoch whose accepted removals leave no key valid at N has no valid
Checkpoint N (§5) and is therefore never applied.

**Unsealed documents.** An Aggregator-signed document that is neither
sealed in the Log nor a Checkpoint — the Snapshot index (§6), a Snapshot
manifest and state file, each part of a split state file included (§7),
and the Mirror list (§5) — states no height of its own. A Consumer
verifies it under the keys valid at the height of the Checkpoint it
adopts (§8): a signature under a key not valid at that height does not
verify, whatever that key's validity at a lower height. An Aggregator
that removes a key MUST re-sign, under a key valid at the removing
Epoch's height, every such document that key signed and the Aggregator
still serves, and SHOULD add a replacement key at a lower height than it
removes the key replaced, since no document verifies on both sides of an
Epoch across which no key stays valid.

Removal is permanent, not a toggle: a `key_id` removed at height N is
invalid at every height ≥ N, and an `aggregator_key_add` naming it is a
key-act failure (below) that restores no validity. An operator that
needs that key's role again admits a fresh `key_id` instead; generating a
new key costs nothing, and permanent retirement avoids any ambiguity
about which of several add/remove events for the same `key_id` governs. A
Consumer replaying the Log from the Anchor can therefore compute the set
of valid keys at every height without external input.

**An Aggregator key as a note signer.** A Checkpoint is a signed note
(§5), and an Aggregator key signs it under the Ed25519 signature type of
[signed-note]: the key name is the Log's origin, its `log_id` (§5), for
every Aggregator key, as [tlog-checkpoint] recommends; the note key ID
is `SHA-256(key name || 0x0A || 0x01 || 32-byte public key)[:4]`, the
derivation [signed-note] gives that type; and the signature line's
value is `base64(key ID || Ed25519 signature over the note text)`. The
verifier-key string [signed-note] defines,
`<log_id>+<hex key ID>+base64(0x01 || public key)`, is the form in which
a key is configured at a Witness. A `key_id` never appears in the note:
a Consumer maps a signature line to a `key_id` by computing the note
key ID of every key valid at the Checkpoint's height. An
`aggregator_key_add` whose key's note key ID equals that of a key
already admitted is therefore a key-act failure (below): a collision is
the one case in which a signature line would name two keys.

**Key-act failures.** Epoch N's authenticated key acts are evaluated in
canonical Entry index order (§3.3) against the **admitted set**: the
genesis key, every key an accepted `aggregator_key_add` admitted at a
height below N, removed keys included, and every key an accepted
`aggregator_key_add` at a lower Entry index in Epoch N admitted. A key
act fails when it is:

- an `aggregator_key_add` whose `key_id` names a key in the admitted
  set, valid or removed;
- an `aggregator_key_add` whose key's note key ID equals that of a key
  in the admitted set, valid or removed — a public key repeated under a
  new `key_id` is one instance; or
- an `aggregator_key_remove` whose `key_id` is not valid at height N−1:
  never admitted, removed at a lower height, or added in Epoch N.

Of two additions of one `key_id`, or of one note key ID, in one Epoch,
the one at the lower Entry index is thus accepted and the other fails.
Two removals in one Epoch of a `key_id` valid at N−1 are both accepted,
and the second changes nothing. An occurrence of an already accepted
key act's ID that passes WIST-4 §5.1's field validation is idempotent
under it and is not evaluated. The
Aggregator MUST NOT seal a key-act failure. A Consumer replaying the
Log ignores one as `WIST4-E04` under WIST-4 §5.1: it changes no key
registry state, and the containing Epoch stays valid. Authentication
precedes this evaluation (WIST-4 §5.1), so a key act that does not
authenticate is `WIST4-E11` whatever else it fails, and it joins
neither the admitted set nor the tie-break.

Key rotation does not repudiate the past. A signature made by a key that
was valid when the signed object was sealed remains binding evidence
forever — including for the equivocation proof of §5. An Aggregator MUST
NOT be treated as exonerated by removing a key after the fact.

**Succession.** A chain whose every valid key is lost can never extend —
no in-band act can admit a new key, because every admission is signed by
a valid one — and a chain whose keys are compromised may be one two
parties can extend, which §5 makes detectable and nothing here makes
recoverable. Both end the same way: the Log stops being the place where
this commons continues. The continuation is a **successor Log**: a new
Anchor whose optional `predecessor` names the ended Log's `log_id` and
the exact Epoch — `final_epoch_number`, and `final_root_hash`, the root
hash Checkpoint `final_epoch_number` states in the `sha256:` form of
§3.1 — at which it ended. The successor's `log_id` MUST differ from its
predecessor's: the origin names one tree at every Witness and Consumer
(§5), and the successor's tree begins empty. The successor Anchor is a
trust root like any Anchor: obtained
and verified out-of-band (§3.4 above), believed because Consumers and
Publishers choose it, not because the old chain — which by
hypothesis can no longer say anything trustworthy — endorses it.

What the field changes is what a Consumer that accepts the successor
MUST do with the past: verify the predecessor chain to the named final
Epoch exactly as §8 verifies any chain, and carry the state at that
Epoch — materialized records, Declarations, parameters, withdrawals,
Labels, every §7 state-artifact category — into the
successor's genesis, exactly as if the successor's Epoch 0 were Epoch
`final_epoch_number + 1`. Windows anchored to a `sealed_at` of the dead
chain keep their instants; Epochs of the successor discharge them. The
carry is the point: a fork is this suite's stated remedy for a captured
or colluding operator (WIST-4 §4, §8), and a remedy that erased every
domain's history and every withdrawal would punish every honest
Publisher — a successor without `predecessor` does exactly that,
lawfully, as a new Log that inherits nothing. **The named final Epoch must be the last one.** A `predecessor` MUST
name the highest Epoch of the ended Log for which any validly signed
Checkpoint exists, and a Consumer MUST reject a successor Anchor whose
`final_epoch_number` is lower than the highest Checkpoint it holds or
can obtain for that `log_id` — reject the Anchor, not merely the
carry. Without this rule succession is a laundering machine dressed as
continuity: an operator, or anyone else, publishes a successor naming a
final Epoch from before a withdrawal or key removal it dislikes, and
every Consumer that pins it carries state from a height at which that
Entry had not happened. Truncation is exactly as attributable as equivocation and is
caught by the same retained artifact — Mirrors keep every Checkpoint
they ever served (§5), so a Checkpoint above the named final Epoch is
a complete, signed refutation of the successor's central claim, and
`mirror_retention_days` is what keeps one obtainable.

Competing successors that survive that test are resolved the way the
Anchor itself is: by which one the ecosystem verifiably pins, a choice
this specification makes falsifiable — each candidate names its final
Epoch, the rule above says whether that Epoch was the end, and §5's
evidence rules say whether the chain reaching it was honest — but
deliberately does not make. A major-version migration uses the same
field: a v2 Log naming a v1 predecessor is a continuation, and WIST-1
§1's "reject unknown major versions" governs objects, not history.

## 4. Merkle Tree, Inclusion and Consistency Proofs

The Log is one RFC 6962 Merkle tree over SHA-256, with that RFC's
hashing discipline:

```
leaf  = SHA-256(0x00 || JCS(entry))
node  = SHA-256(0x01 || left || right)
```

A leaf's data is the Entry object's JCS serialization (RFC 8785), so an
Entry's leaf hash is a function of the Entry alone. Leaves are the
Entries in Log order (§3.3), indexed from 0. Levels are built pairwise,
left-to-right; **an unpaired final node is promoted unchanged to the
next level**, which yields RFC 6962 §2.1's `MTH` at every tree size.
The root of a single-leaf tree is that leaf's hash, and the root of the
empty tree — the Log before its first Entry, tree size 0 — is
`SHA-256("")`, as RFC 6962 §2.1 defines:
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Every tree size, the empty one included, is exactly RFC 6962's, so an
existing RFC 6962 or C2SP implementation verifies this Log unmodified.

An Inclusion Proof for the Entry at leaf index *i* in the tree of size
*n* is `{"index": i, "tree_size": n, "path": [<hex sibling hash>, ...]}`:
`index` is the leaf index in the Log, never the Entry's position in its
Epoch, and `tree_size` is the size a Checkpoint states. Sibling **sides
are not carried in the proof**: they are derived from `index` and
`tree_size`, exactly as in RFC 6962, so that a proof authenticates the
Entry's *position* as well as its membership.

Verification MUST reconstruct the audit path exactly as RFC 6962 §2.1.1
defines it (the `PATH(m, D[n])` function, with `tree_size` as the tree
size *n* and `index` as *m*), applying the leaf and node hashing above.
Concretely: start with `h = leaf(JCS(entry))` and walk from leaf to
root, tracking the current node's own index within its level, `fn`
(initially `index`), and the index of the last node at that level, `sn`
(initially `tree_size - 1`). While `sn > 0`:

```
if fn is odd:               # fn is a right child
    consume the next path element as its LEFT sibling
elif fn < sn:                # fn is a left child with a real sibling
    consume the next path element as its RIGHT sibling
else:                        # fn == sn, fn even: the lone, unpaired
    consume nothing           # trailing node at this level, promoted
                              # unchanged (matching the promotion rule above)
fn = fn div 2; sn = sn div 2
```

The walk terminates when `sn == 0`; the resulting hash is accepted iff
`h` equals the root hash the Checkpoint states.

A verifier MUST reject a proof when:

- `index >= tree_size` or `index < 0`;
- the proof's `tree_size` differs from the tree size of the Checkpoint
  it is verified against, so that a forged tree size cannot reshape the
  derivation;
- the walk needs a `path` element beyond the ones supplied (it runs out
  of siblings before `sn == 0`), or terminates with `path` elements left
  unconsumed.

Because the sides are derived from `index` and `tree_size` rather than
read from the proof, a proof authenticates the Entry's position as well
as its membership.

A **Consistency Proof** from tree size *m* to tree size *n*, 0 ≤ *m* ≤ *n*,
is RFC 6962 §2.1.2's `PROOF(m, D[n])`. It is verified by reconstructing
the root at *m* and the root at *n* from it as RFC 9162 §2.1.4.2
defines, and accepted iff each equals the root hash the corresponding
Checkpoint states. The proof is empty when *m* = 0 — the empty tree is a
prefix of every tree — and when *m* = *n*, where the two roots MUST be
equal; no proof exists from a larger size to a smaller one. An empty
proof exempts no root from comparison: the root reconstructed at size 0
is `SHA-256("")` (above), the tree before Epoch 0 included, so a
Checkpoint stating tree size 0 with any other root hash fails the
Consistency Proof from size 0 as any root mismatch does — `WIST3-E02`
when the Checkpoint is validly signed (§5) — and a verifier MUST compare
the size-0 root rather than skip the empty proof. The Log
serves no proof objects: a Consumer holding the tree hashes §6 serves
computes either proof itself, and a proof it receives from another
party is verified the same way.

Inclusion Proofs let a light client verify "this Entry is in the Log"
holding only a Checkpoint and the proof: the Checkpoint is authenticated
by the Aggregator's signature and the Cosignatures it carries (§5), and
the proof binds the Entry to the root it states.

## 5. Checkpoints and Anti-Equivocation

After sealing each Epoch the Aggregator publishes its **Checkpoint**: a
signed note [signed-note] in the C2SP checkpoint format
[tlog-checkpoint], served at the current-head URL and archived per
Epoch at the paths §6 assigns. Its note text is exactly five lines:

```
<origin>
<tree size>
<root hash>
epoch_number <epoch_number>
sealed_at <sealed_at>
```

The first three are the lines [tlog-checkpoint] defines. The origin is
the Log's `log_id` (§3.4) verbatim, which is the schema-less URL form
that format recommends; the tree size is `size(N)`; the root hash is
the root of the tree at that size (§4) in the base64 encoding that
format specifies. The last two are that format's extension lines, which
it leaves opaque and this document fixes: line 4 is the string
`epoch_number`, one space (U+0020) and the Epoch's number as an ASCII
decimal with no leading zeroes (`0` for Epoch 0); line 5 is the string
`sealed_at`, one space and the Epoch's `sealed_at` in the §3.1 profile.
They are extension lines rather than members of a signed object so that
a checkpoint-format client parses the Checkpoint unchanged and a Witness
cosigns it unchanged; the cosignature formats make no statement about
extension lines [tlog-cosignature], which is why what the Log attests
and what a Witness attests are stated separately below.

A Consumer parses a Checkpoint as [signed-note] and [tlog-checkpoint]
define and then reads the extension lines by the rules above. A
Checkpoint whose note text has more or fewer than five lines, whose
origin is not the Anchor's `log_id`, whose line 4 or 5 differs from the
form above in any octet — a leading zero, a second space, a `sealed_at`
outside the §3.1 profile — or whose text or signature lines do not
parse under those formats is not this Log's Checkpoint: it is rejected
as `WIST3-E03`, and nothing in it is evidence. Four points those formats
leave to the verifier are fixed here, and a note failing any of them
does not parse. The root hash line is the RFC 4648 §4 base64 encoding,
padding included, of exactly 32 octets, and re-encoding the decoded
octets reproduces the line. Every signature line, the last included,
ends in a newline (U+000A). Every signature line, under a known key or
not, is an em dash (U+2014), one space, a key name that is non-empty and
contains no plus (U+002B) and no character with the Unicode White_Space
property, one space and a base64 signature [signed-note]. A note carries at most 16 signature lines: a
Consumer MUST accept 16 and MUST reject 17 or more, and the Aggregator
MUST NOT publish a Checkpoint carrying more than 16.

**The Log's signature.** A Checkpoint MUST carry at least one signature
line under an Aggregator key valid at height N in the sense §3.4 gives
that phrase, N being the `epoch_number` line, in the signer form §3.4
defines; it MAY carry more than one, as during a rotation. A Consumer
treats as known exactly the Aggregator keys valid at N and the Witness
keys it trusts, ignores every other signature line as [signed-note]
requires, and MUST reject the Checkpoint (`WIST3-E03`) when a line
naming a known key fails to verify. The signature is checked after the
Epochs up to N are walked, because the keys that can speak for Epoch N
are the ones the Log establishes at N: the Consumer parses the note,
fetches the Entries below `size(N)` it does not hold (§6), verifies
them against the tree the note states (§3.1) and that tree's
consistency with its verified head (below), applies Epoch N's Registry
Updates, computes the key set valid at N and verifies the signature
under it. Nothing rests on the order — the Entries establish the key
set only once a signature under that set closes the loop, and a
Checkpoint the loop does not close is applied by nobody. Cosignatures
change none of this: a Checkpoint's identity is its note text, whatever
signature lines it carries, and the Aggregator republishes the same
Checkpoint with each Cosignature it obtains.

The Aggregator MUST NOT publish Checkpoint N before every Entry with a
leaf index below `size(N)` is durably stored and retrievable at its §6
path. A Checkpoint is a permanent signed commitment to one root at one
size: published ahead of Entries the Aggregator can still lose, it is
honored only by serving byte-identical Entries and is otherwise
contradicted by whatever the Log serves next, which is equivocation
against itself. A Consumer holding a Checkpoint whose Entries no source
serves has a `WIST3-E01` it cannot clear, never a `WIST3-E02`: the
Checkpoint is evidence of what the Aggregator committed to, and the
Entries' absence is the Aggregator's to remedy.

- Mirrors MUST retain every Checkpoint they have ever served, with every
  signature line it carried.
- Consumers SHOULD fetch Checkpoints from more than one source — Mirrors,
  and the monitoring endpoint each trusted Witness serves under
  [tlog-witness] — and
  SHOULD retain the Checkpoints they act on. The instruction is
  performable because Mirrors are discoverable in-band: the Aggregator
  SHOULD publish `/log/mirrors.json` — an Envelope whose inner object is
  `mirrors` (schema:
  [`schemas/mirrors.schema.json`](../schemas/mirrors.schema.json)),
  carrying `wist_version`, `updated_at` (descriptive: when the Aggregator
  last rewrote the list, compared to nothing) and `mirror_urls`, the
  `https` base URLs of Mirrors it knows to re-serve the Log, each ending
  in `/`. The list verifies under the keys valid at the Consumer's
  adopted head (§3.4); one that does not verify — signed by a key since
  removed, or read before the Consumer has a head — has no error code,
  and its entries are location hints integrity never depends on (§6),
  never evidence of authorship, Log membership or independence. A
  Consumer SHOULD also
  retain Mirror URLs from any other source it trusts, because a list the
  Aggregator curates is exactly the wrong sole source for the parties
  meant to catch the Aggregator equivocating: its value is bootstrap
  convenience, and independence of at least one comparison source is
  the property that matters.
- A Consumer MUST verify every Checkpoint from its verified head to the
  one it adopts, in `epoch_number` order: each extends the tree of the
  previous one — a Consistency Proof between the two sizes (§4) — and
  each Epoch's Entries are the leaves `size(N-1)` through `size(N) - 1`
  of that tree (§3.1). A Checkpoint that fails the Consistency Proof is
  chain divergence (`WIST3-E02`), evidenced below. An Entry not covered
  by a Checkpoint the Consumer has verified MUST NOT be applied.
- A Consumer MUST reject a Checkpoint whose `epoch_number` is lower than
  the highest it has already verified (rollback protection): it keeps
  its verified head, adopts nothing from the offered Checkpoint and
  fetches the head from another source. The rejection has no error
  code and the Checkpoint is not evidence, because the Log signs a
  Checkpoint at every Epoch and a source serving an old one has shown
  only that it is behind. A Checkpoint whose `epoch_number` the
  Consumer has already verified, the head's or a lower one it retains,
  MUST have note text identical to the verified one, or the two
  equivocate (below).
- A Consumer SHOULD treat the log as stale, and SHOULD warn, when
  `sealed_at` of the newest Checkpoint it can accept lags the current
  time by more than three times the sealing cadence (§3.2); empty Epochs
  make this signal reliable.

**Witnesses.** A Checkpoint MAY carry Cosignatures: signature lines a
Witness adds under [tlog-cosignature] after verifying, through
[tlog-witness], that the Checkpoint is consistent with every Checkpoint
of this origin it cosigned before. A Cosignature attests the first three
lines of the note and nothing about the extension lines
[tlog-cosignature]; what it adds is that the tree the Aggregator signed
is the one the Witness saw, so a Consumer holding a cosigned Checkpoint
knows that no Consumer sharing that Witness was served a different tree
at that size. Which Witnesses a Consumer trusts is its configuration —
the tuples of Witness name, public key and cosignature version
[tlog-cosignature] describes, obtained as the Anchor is (§3.4) — and how
many it requires is the Parameter Registry's `checkpoint_witness_quorum`
(WIST-4 §5; default 0), read as in force at the Checkpoint's
`sealed_at`: a Consumer MUST NOT act on a Checkpoint carrying verified
Cosignatures from fewer than that many distinct trusted Witness names.
A Checkpoint short of the quorum is neither evidence nor an error: the
Consumer keeps its verified head and retries, and the staleness rule
above applies while it stays short. The quorum applies to the
Checkpoint a Consumer adopts as its head; the Checkpoints between its
previous head and that one are verified by the Log's signature and by
recomputation against the head's tree (above), which the head's
Cosignatures cover. The Aggregator submits each Checkpoint to the
Witnesses it uses through [tlog-witness]'s `add-checkpoint` call and
republishes it with the Cosignatures returned; which Witnesses it uses
is its choice and no Consumer's trust source, for the reason the Mirror
list is not (above).

While `checkpoint_witness_quorum` is 0 — the value this edition starts
at, before any Witness cosigns the Log — a Consumer that accepts a
Checkpoint carrying no Cosignature from a Witness it trusts MUST record
that acceptance as unwitnessed with the Checkpoint it retains and
SHOULD report it as it reports a stale Log. The interim is stated here
rather than left implicit because an unwitnessed Checkpoint is exactly
the split view the quorum exists to exclude.

**Equivocation** is two Checkpoints of one Log, each validly signed
under an Aggregator key valid at the height its `epoch_number` line
states (§3.4), that state the same tree size and different root
hashes, or the same `epoch_number` and a different tree size, root hash
or `sealed_at`. The first form is the one [tlog-checkpoint] forbids a
log to sign and a Witness refuses to cosign; the second is this suite's
own, because an Epoch's bounds and instant decide capacity, application
order and every day count (§3), and two partitions of one tree are two
states. The evidence bundle is exactly those two Checkpoint files —
self-contained, portable, verifiable by anyone with the Anchor and the
Log's key acts. A third form needs more: two Checkpoints of different
sizes between which no Consistency Proof exists — the smaller's root is
not the root of the larger tree's prefix at that size, a tree size
below the previous Checkpoint's included — where the evidence is both
Checkpoints and the tree hashes (§6) that reproduce the larger root,
from which anyone recomputes the prefix root the smaller contradicts.
A party holding a bundle SHOULD publish it widely; consumers verifying
it MUST stop applying new data from that Aggregator (§9, `WIST3-E02`).
Checkpoints signed by *any* key valid at their `epoch_number` count; an
Aggregator cannot escape an equivocation proof by removing the signing
key afterward (§3.4). A Consumer judging a Checkpoint at or below its
verified head therefore uses the key set valid at that Checkpoint's own
height, never the set valid at its head; after a Snapshot resume it
computes that set from the `aggregator_key` tuples, which carry removed
keys for this purpose (§7).

**Detection is in-band; dissemination is partly so.** The proof is two
small signed files anyone can verify, and "publish it widely" still
names no venue. What a Witness quorum adds is prevention rather than a
channel: a Witness cosigns nothing inconsistent with what it cosigned
before, so a split view reaches a Consumer applying the quorum only if
that many trusted Witnesses saw it — which is why a quorum of one
operator's Witnesses is not a quorum, and why the roster is the
Consumer's. Two limits remain. Below the quorum, and for every
Checkpoint accepted unwitnessed, an Aggregator that partitions its
audiences perfectly — distinct Checkpoints to distinct populations that
never compare notes — is caught only when a bundle crosses the
partition, which multi-source fetching (above) makes likely but nothing
here makes certain. And the remedy runs on evidence, not plumbing: a
proof, however it traveled, justifies the fork/succession path (§3.4)
everywhere it lands.

## 6. Static Layout

The log is distributed as static files. Transport is out of scope: any
HTTP server, CDN, torrent, or IPFS gateway works, because every file
except `/checkpoint` and `/snapshots/index.json` is immutable and
integrity is verified by hash, signature, or commitment, never by source.

The paths below are rooted at the Log's **Service Origin**,
`https://<log_id>/` (§3.4) — which is how a party holding a Log Anchor
needs no second discovery channel: the Anchor's `log_id` names the host,
and everything else is a path. The Service Origin is also the tiled-log
*prefix* of [tlog-tiles], so that the Checkpoint's origin line,
`<log_id>`, is the scheme-less prefix that format recommends and a
client of that format reads the Log from the Anchor alone: the head
Checkpoint at `/checkpoint`, the tree's hashes at
`/tile/<L>/<N>[.p/<W>]` and its Entries at `/tile/entries/<N>[.p/<W>]`,
each exactly as [tlog-tiles] defines the path, the content and the
`Content-Type`. The suite's own files sit under `/log/`, `/payloads/`
and `/snapshots/`. Mirrors re-serve the same paths at their
own origins. Two endpoints are dynamic and exist only at the Service
Origin, never on a Mirror: the Ingest Endpoint `POST
https://<log_id>/ingest` (WIST-2 §4) and the status endpoint `GET
https://<log_id>/status/<domain>` (WIST-2 §7.1).
Payload files are immutable in the same sense — their bytes never change —
but they may cease to be served (§6.1, §6.2).

```
/checkpoint                             (mutable, small, signed note; the current head — §5, [tlog-tiles])
/tile/0/000                             (immutable; a full level-0 tile: 256 leaf hashes — [tlog-tiles])
/tile/0/001.p/44                        (a partial tile, here for tree size 300; deletable once the full tile exists)
/tile/1/000.p/1
/tile/entries/000                       (immutable; an entry bundle: the leaf data of 256 Entries — [tlog-tiles])
/tile/entries/001.p/44
/log/anchor.json                        (immutable, signed; a copy of the §3.4 trust root)
/log/checkpoints/000000000              (note text immutable; every Checkpoint published, zero-padded 9-digit Epoch number — §5)
/log/checkpoints/000000001
...
/log/suffix-lists/7d33b504….dat         (immutable; a pinned Public Suffix List snapshot, WIST-4 §3.1)
/payloads/6cac5bdd….json                (one per sealed Item of kind `page` — §6.1)
/snapshots/index.json                   (mutable, signed; the discovery entry point)
/snapshots/2026-08-02/000000000/manifest.json          (immutable, signed; declares log position — one directory per Snapshot, named by its date and Epoch)
/snapshots/2026-08-02/000000000/state.json             (immutable, signed; the state artifact — §7)
/snapshots/2026-08-02/000000000/tier0/index.sqlite
/snapshots/2026-08-02/000000000/tier1/extracts.parquet
/snapshots/2026-08-02/000000000/tier1/links.parquet
/snapshots/2026-08-03/000000024/shard-0/tier0/index.sqlite   (a sharded Snapshot: shard 0's six tier files under shard-0/ — §7)
/snapshots/2026-08-03/000000024/shard-1/tier0/index.sqlite
```

**Snapshot directories are immutable.** A Snapshot is served under a
directory of its own, `/snapshots/<snapshot_date>/<epoch_number>/`, the
Epoch number zero-padded to nine digits as under `/log/checkpoints/`,
and that directory is written once: an Aggregator MUST NOT serve another
Snapshot, or other octets, at a path a served manifest or index entry
has named. The one rewrite of a served document is §3.4's re-signing
after a key removal, which replaces the signature of the manifest or
state file and nothing the signature covers. A later Snapshot, one
taken at a later Epoch of the same `snapshot_date` included, gets its
own directory and its own index entry; a Snapshot stops being served by
removing its index entry and then its files. Rewriting a directory in place would put a Consumer
that read the index before the rewrite in front of a manifest its entry
does not describe, and a Mirror that fetched a tier file before it in
front of octets no current manifest hashes. A Mirror MAY satisfy a
listed file from any copy whose `sha256` and `bytes` the manifest
states, which is how an unchanged shard crosses Snapshots without a
second fetch.

`/log/anchor.json` is served here for convenience only. It is the Log's
out-of-band trust root, and a Consumer MUST NOT accept the copy served at
this path without the verification §3.4 requires; a file an operator serves
about itself is not a trust root because of where it sits.

**Checkpoints.** `/checkpoint` is the head Checkpoint, served with
`Content-Type: text/plain; charset=utf-8` and headers that prevent
caching beyond a few seconds [tlog-tiles].
`/log/checkpoints/<epoch_number>`, the number zero-padded to nine
digits, is the archive: Checkpoint N as a signed note, served with the
same `Content-Type`, carrying every signature line the Aggregator has
obtained for it. The Aggregator MAY rewrite an archive file to add
Cosignatures (§5) and MUST NOT alter its note text. A file at that path
whose `epoch_number` line is not the path's number is `WIST3-E03`.

**Tiles and entry bundles.** The tree is served as [tlog-tiles] tiles —
256 hashes of 32 octets per full tile, a partial tile of the width the
tree size requires at its right edge — and the Entries as that format's
entry bundles: each leaf's data, the JCS serialization of the Entry
(§4), prefixed by its length as a big-endian uint16, so that each entry
hashes to the corresponding hash of the level-0 tile. Both are octets
the tree fixes, byte-identical at every source, and compressed, if at
all, at the HTTP layer as [tlog-tiles] provides. A Consumer verifies a
tile or bundle only by recomputation against the root a verified
Checkpoint states (§3.1, §4); one that does not reproduce it is
`WIST3-E03`. So is one whose form already excludes reproducing it: a
tile that is empty, whose length is not a multiple of 32 octets, or
that holds a number of hashes other than the one its path states — 256
for a full tile, `W` for `.p/<W>`, `W` being 1 through 255
[tlog-tiles]; an entry bundle whose last length
prefix or leaf data is cut short, that carries octets after its last
Entry, or that holds a number of Entries other than the one its path
states, under the same widths; and an Epoch's Entries that do not fill the leaf range
`size(N-1)` through `size(N) - 1` (§3.1). The Log serves no proof
objects (§4). The Aggregator MUST
serve, for the tree size its head Checkpoint states, the partial tiles
and the partial entry bundle that size requires, and MAY delete a
partial tile or bundle once the full one exists [tlog-tiles]; a
Consumer MUST NOT fetch a partial tile or bundle without a verified
Checkpoint whose size requires it, and falls back to the full one
[tlog-tiles].

**Epoch size.** The size of Epoch N is the number of octets its Entries
occupy in entry bundles: the sum, over Epoch N's Entries, of the length
of each JCS serialization plus two. It MUST NOT exceed the applicable
`epoch_cap_bytes` (WIST-4 §5; Registry default 256 MiB):
the Aggregator seals under the caps that section names, and a Consumer
MUST reject an Epoch that exceeds them (`WIST3-E03`). The cap counts
octets after any HTTP content-coding is removed, and it bounds what a
Consumer fetches to apply an Epoch: the Epoch's own octets, the remainder of the
at most two bundles it shares with its neighbours — each bundle at most
256 leaves of 65 537 octets (§3.3) — and 32 octets of level-0 tile per
leaf with the tiles above them. Before fetching an Epoch, a Consumer
derives a transport bound from its already verified prefix: the greatest
`epoch_cap_bytes` in the map at that prefix's last
`sealed_at` and at every accepted future `effective_at`. With no verified
Epoch, use the Registry default. Accepted pending amendments participate;
rejected candidates and the Epoch being fetched do not. This bound also
covers historical Epoch fetches because each accepted cap covers the
entire sealed prefix (WIST-4 §5). A Consumer restoring from a Snapshot uses
its authenticated parameter tuples, including pending amendments (§7),
and its manifest's `epoch_number` as its prefix. This
bootstrap bound cannot be raised by unauthenticated state. The size
guarantee itself still requires the reconstruction WIST-4 §5 specifies.

A Consumer MUST stop reading a response before buffering bytes beyond
the limit (§10) when a tile exceeds 8 192 octets, an entry bundle
exceeds 16 777 472 octets — 256 leaves of 65 537 — or the entries
attributable to the Epoch being fetched, those whose leaf indexes lie
in its range, exceed the transport bound. These failures are
`WIST3-E03`. Equality with a bound is permitted. A Mirror's claim or
the local wall clock MUST NOT raise a bound.

After authentication, replay the Epoch's parameter candidates and check
its size against WIST-4 §5's current and prospective bounds before
applying it. The transport bound alone does
not authorize use of a scheduled increase before its effective instant,
and cannot excuse exceeding an already accepted pending reduction.

Every file is verified rather than trusted, and §12's Mirror obligation
is to serve octets that verify: a tile or bundle by recomputation
against the Checkpoint's root, a Checkpoint by its signature lines
(§5), a signed object by its signature, a Payload by its commitment
(§6.1). Only the Snapshot tier files carry no verification of their
own: a signed manifest hashes their octets directly (§7), so those a
Mirror MUST serve unchanged.

**Discovery.** `/snapshots/index.json` (schema:
[`schemas/snapshot-index.schema.json`](../schemas/snapshot-index.schema.json))
is the discovery entry point: a signed, mutable index whose inner object is
`index`, carrying `wist_version`, `updated_at` (when the Aggregator last
rewrote it), and `snapshots` — the Snapshots the Aggregator currently
serves, newest `snapshot_date` first and, within one date, the higher
`epoch_number` first, each with its `tree_size`, its `manifest_url`, and
the `content_digest` (§7) that Snapshot's manifest declares. Cold start begins there (§8). The index
carries the digest so that a Consumer can check a manifest it fetches
against a second, independently signed statement of what that Snapshot
contains. An Aggregator MUST remove an entry from the index when it stops
serving that Snapshot; a withdrawal (§6.2) is the case that forces it.

**Retention.** The Log is never pruned: its minimum index under
[tlog-tiles] is 0, and the Aggregator MUST keep every entry bundle and
every full tile from genesis retrievable at its path. Replay from the Log Anchor is what
makes key validity (§3.4), the parameter schedule (WIST-4 §5) and
historical signature verification recomputable, so a Log missing an Entry in the middle is a Log
no party can verify from the Anchor at all. The Aggregator MUST likewise
retain every Checkpoint it has published, at
`/log/checkpoints/<epoch_number>` (above): `/checkpoint` names the
current head and is overwritten, so without the archive an equivocation
proof (§5) would rest on whoever happened to have kept the superseded
copy, and a Consumer, which verifies every Checkpoint between its head
and the one it adopts (§5), would have nothing to verify.

A Mirror **serves Epoch N** when it serves Checkpoint N and every entry
bundle and tile whose leaf range meets Epoch N's. A Mirror that serves
an Epoch MUST retain it for at least the Mirror
retention floor (Parameter Registry: `mirror_retention_days`; default 90
days), measured from its first service of that Epoch with the value in
force at that instant, and while it serves the Log's head it serves the
partial tiles and bundle that head requires (above). Later amendments
do not shorten that obligation.
This lets an evidence bundle be assembled after the fact rather
than only while an operator finds it convenient. §5's obligation on
Checkpoints is stricter and this floor does not relax it: a Mirror retains
every Checkpoint it has ever served, without expiry, because Checkpoints
are the equivocation evidence itself and are small enough that no retention
argument applies to them.

**Suffix-list files.** Every Public Suffix List snapshot a sealed
`suffix_list_update` names is served at `/log/suffix-lists/<hex>.dat`,
where `<hex>` is the identifier's 64-character digest (WIST-4 §3.1), as
the exact octets that hash to it, from the Epoch that seals the act and
without expiry; a Mirror that serves an Epoch MUST serve the snapshot in
force at it and every snapshot an act in that Epoch names, and retains
them as it retains Checkpoints, without expiry. A file whose octets do
not hash to its name is `WIST3-E03`, and one no source holds is
`WIST3-E01`: the Consumer cannot check the per-domain capacity of any
Epoch that snapshot governs until it obtains the file.

**Sizing.** The Log's permanent volume is the Entries it seals —
Declarations, governance acts, Catalogs, Items, Labels and disputes — plus the
tiles above them, under 33 octets per leaf across every level, and one
Checkpoint per Epoch. An idle Log accrues one
Checkpoint per cadence and nothing else, so storage growth is a function
of what Publishers and Labelers publish and of the cadence alone.

### 6.1. Payloads

An Item of kind `page` commits to its content and does not carry it
(WIST-1 §3.6). The content travels as a **Payload** (schema:
[`schemas/payload.schema.json`](../schemas/payload.schema.json)) served at

```
/payloads/<item-id-hex>.json
```

where `<item-id-hex>` is the 64 hexadecimal digits of the Item ID that
follow `sha256:` — the same naming a Publisher uses (WIST-2 §3.1). A
Payload file is immutable while it is served: an Aggregator MUST serve at
that path either the exact bytes it verified (WIST-2 §5.1; §3.3) or
nothing at all.

A Payload carries exactly three members. `wist_version` is the version of
this suite it conforms to (WIST-1 §3.1); WIST-1 §7 defines complete Payload
field/version validation and diagnostic precedence. `salt` is the base64url encoding,
unpadded, of the ≥ 16 octets that key the Item's commitment (WIST-1 §3.6);
it is the one place the salt is published, and destroying it is what makes
a withdrawal effective (§6.2). `content` is the object the commitment is
computed over: a REQUIRED `extract`, the main text; a REQUIRED
`links` object carrying a REQUIRED `total` and REQUIRED `urls` (WIST-1 §3.6);
and a REQUIRED `summary` object carrying a REQUIRED `title` and an OPTIONAL
`abstract`. Those eight names and no others: `content` is the exact
preimage of `JCS(content)`, so a Payload carrying any further field
commits to different bytes and fails verification. WIST-1 §3.6 governs the
octet caps on `extract`, `links` and `summary` and the relationship
between them and `bytes`; a Payload is unsigned, so nothing here is
authenticated except by recomputing that commitment.

Payloads are fetched in the same synchronisation pass as entry bundles,
from the same static file servers, by the same unauthenticated GETs. They
are **not** covered by the tree: no leaf hash, root or Inclusion Proof
depends on them, which is exactly why the tree is untouched when a
Payload is withdrawn.

A Consumer MUST verify each Payload against its Item's `commitment` and
`bytes` (WIST-1 §3.6) before applying its content, and MUST NOT apply
content that fails (`WIST1-E10`; the serving party is at fault under
`WIST3-E03`). Verification does not depend on where the file came from, so a
Payload MAY be fetched from any Mirror, from another Consumer, or from the
Publisher's own `.well-known` path: the commitment decides, never the
source. That is also why §6.2 binds all three: a withdrawal reaches every
serving path or it reaches none of them, since any one of them suffices to
obtain the salt.

An Item whose Payload a Consumer cannot obtain remains valid and sealed,
and the record it makes stands (§7). The Consumer applies what the Item
itself says — its URL, its kind, `observed_at` and `meta` — and
materializes no content for it.

**Availability window.** An Aggregator and any Mirror serving an Epoch (§6) MUST
serve the Payload of every Item of kind `page` that Epoch seals for at
least the payload availability window (`payload_window_days`, Parameter
Registry; default 180 days), counted from that Epoch's `sealed_at` and
read from the parameter map in force there (WIST-4 §5), except Payloads
withdrawn under §6.2, and MUST NOT serve Checkpoint N before every such
Payload of Epoch N, less those withdrawn, is
retrievable at its path: Payloads replicate first, then the Entries,
then the Checkpoint, extending the order §5 fixes between the Entries
and their Checkpoint, so a Payload is never
absent at a Mirror merely because replication has not reached it. A
Payload absent inside its window with no withdrawal sealed for it is a
`WIST3-E05` fault against that Mirror; this is what distinguishes a lawful
withdrawal from a Mirror quietly dropping content it dislikes.

After the window elapses, retention is at each Mirror's discretion, and
at the Aggregator's for a Payload whose Item is no record (**Payloads of
records**, below), and a Consumer MUST NOT read such an absence as
misbehavior. The window is therefore a detection window rather than an
archival promise: it is set long enough that a Payload's absence inside
it is evidence, and a Consumer that starts later obtains the content of
every record from the Aggregator.

**Payloads of records.** An Aggregator MUST serve the Payload of the Item
of every record its Log holds (§7), a record the one-URL rule does not
materialize included, for as long as that Item is the record, whatever
the availability window. Once an Item, narrowing or a base replaces or
removes the record, its Item's Payload keeps only the availability window
of each Epoch that sealed the Item: a superseded Payload gets no further
window at the Aggregator. A withdrawal (§6.2) ends both duties at once.
The end of a duty permits the Aggregator to delete the Payload and does
not require it; only a withdrawal obliges removal.

Holding the Payloads of current records costs the Aggregator nothing it
was not already holding — they are the content Tier 1 materializes (§7)
— and it means a Publisher cannot make its own records unverifiable by
dropping its copy: the Aggregator's copy is independent, and the
commitment makes the two interchangeable. A Consumer that can name an
Item but cannot fetch its Payload materializes no content for it (above),
which is how the suite records "there was a thing to show and it is no
longer available".

### 6.2. Withdrawal

A Payload is removed from distribution by a `payload_withdrawal` Registry
Update (WIST-4 §5.1), signed by the Aggregator, whose `subject` is the
Publisher's domain and whose `details` name, in the member `delta_id`,
the Item ID of the Item of kind `page` whose Payload it removes, the
`legal_basis` under which the content is being erased, and the
`jurisdiction` of the party demanding it; which Item IDs it may name is
its `details` contract (WIST-4 §5.1). A request covering several Items is
recorded as one entry per Item, so that each withdrawal names exactly
what it removed and can be checked on its own.

A withdrawal takes effect at the height of the Epoch that seals it, for an
Item sealed in that same Epoch included: the Item becomes its URL's record
(§3.3) and its content is never materialized. From that height:

- the Aggregator, every Mirror **and the Publisher itself** MUST stop
  serving that Payload, and a Consumer MUST NOT treat its absence as a
  fault. The Publisher is bound because its `.well-known` copy is a third
  serving path (WIST-2 §3.1), the original one, and the only one this
  document does not otherwise reach: a withdrawal that bound the two
  downstream copies and left the source published would relocate the salt
  rather than destroy it, and every claim below about what stops being
  checkable would be false at one fetch. The Publisher's own retention
  duty for the Payloads its Catalogs name (WIST-2 §3.1) ends at that
  height rather than competing with this one; a Publisher that keeps
  publishing the content lists a new Item under a fresh salt (WIST-2
  §3.1);
- no later Epoch of that Log seals the Item again: I7 fails for an Item
  named by a withdrawal sealed in an earlier Epoch (§3.3), and a pull
  admits no such Item (WIST-2 §5.1);
- Consumers MUST exclude the withdrawn content from subsequent
  materializations and remove it from any local index already built from
  it, and the Aggregator **and every Mirror** MUST stop serving any
  already published Snapshot artifact that still contains it —
  `tier1/links.parquet` no less than `tier1/extracts.parquet`, since a
  withdrawn Payload's declared links are content and leave distribution
  with it (§7);
- every party holding the Payload for protocol purposes MUST destroy it,
  its salt, and anything it retained of the content it carried.

What withdrawal does not touch is the record. The Item stays sealed, the
record it makes stands until an Item, narrowing or a base replaces or
removes it (§7), its commitment stays in the Log, its Inclusion Proofs
keep verifying, and every Label ever sealed about it remains.
Withdrawal removes content from distribution; it cannot remove history,
and it cannot recall copies already served.

**After a withdrawal the Log retains no unsalted digest of the withdrawn
content.** That is a property of the object formats, not an aspiration:
the Item commits to its content under the Payload salt (WIST-1 §3.6), and
destroying the salt makes the commitment unlinkable. The rule is general and binds any
object a later revision adds: **a content-derived value in this suite is
committed under the Payload salt or it is not carried at all.** No object,
and no `details` of any Registry Update, may carry a bare digest of
Payload content.

What remains in the Log and is derived from the withdrawn content is the
Item's `payload.bytes` length and any Label a Labeler sealed about the
URL. Neither is a digest: `bytes` corroborates a length that unboundedly
many texts share, and a Label is a registry name and an integer. What
stands between a party holding a copy and a confirmation is the destroy
obligation above — a duty on a named holder, not a property of the
format, and this specification does not present it as one (WIST-1 §9,
WIST-4 §9).

The due process is notice in the Log, a named basis, a public and
permanent record. An
operator that removes a Payload without sealing this entry has not
withdrawn it lawfully — it has dropped it, and §6.1's window makes that
observable.

Withdrawal is itself an act the Aggregator is accountable for, and it
cannot be performed quietly. Every withdrawal is signed, sealed and
enumerable, so anyone can list every Payload an operator has ever removed
together with the basis and jurisdiction it claimed, and a pattern no
legal basis explains is visible as a pattern. What the Log cannot do is
adjudicate a basis; it can only make the claim permanent and attributable
to the party that made it — the same standard this suite applies to every
other exercise of operator power.

**A withdrawal binds one Log.** Every obligation in this section runs on
Entries of the Log the withdrawal was sealed in: an Aggregator and its
Mirrors. A second, independent
Log that sealed the same Item — nothing forbids one, and
WIST-2's publication surface is one site serving whomever pulls — is
unreached by it, and a Publisher who needs content erased from two Logs
files two withdrawals. Stated once, plainly, because the alternative is
a Publisher discovering it at the worst moment: this suite's erasure
guarantees are per-Log, and every "the Aggregator" and "every Mirror" in
this section quantifies over one Log.

## 7. Snapshots and Tiers

A Snapshot is a derived artifact: the materialized state of the log up to
Epoch N. Its `manifest.json` (schema:
[`schemas/snapshot-manifest.schema.json`](../schemas/snapshot-manifest.schema.json))
is signed by the Aggregator and declares `snapshot_date`, `epoch_number`
(= N), `tree_size` (= `size(N)`, the tree size Checkpoint N states,
§3), `root_hash` (the root hash of the tree at `tree_size`,
in the `sha256:` form of §3.1), `content_digest`
(below), `state` (the state artifact, below), optionally `shards`
(below), and `files` — one entry per artifact, each carrying its `path`
relative to the manifest, its `sha256`, its `bytes`, the `tier` (`0` or
`1`) it belongs to, and, where the manifest declares `shards`, its
`shard` index. `epoch_number` is carried because a tree size names no
Epoch on its own: an empty Epoch restates the size before it (§3.2),
and the state at two such Epochs can differ by whatever their
`sealed_at` instants settle, expire or bring into force. Throughout
this section "at `tree_size`" means at Epoch N — over the Entries
whose leaf index is below `tree_size`, with Epoch N's `sealed_at` as
the instant — and "above" or "below" `tree_size` means above or
below Epoch N. Every height a Snapshot carries, in this section's
tuples and tables, is an Epoch number, never a tree size.

- **Tier 0** — summaries of every materialized record: SQLite (FTS5) + Parquet.
  Sized for any laptop; answers most agent queries alone.
- **Tier 1** — full extracts of materialized records, the link graph their
  Payloads declare, and the Labels sealed about them, as Parquet.

Both tiers are built from Payloads (§6.1), not from the Log: the Log
carries commitments, and a Snapshot is where the content a Consumer
actually queries is materialized. A Snapshot MUST NOT include content
whose commitment it did not verify.

**Companion packs.** Neither tier carries embeddings, and no artifact
this specification defines does. A vector is a content-derived value no
verification in this suite can reach: `content_digest` deliberately
covers Log-derived tuples only, float inference admits no exact
equivalence criterion, and an inexact one — a tolerance — is an attack
budget, since manipulation inside the tolerance is invisible by
construction (ADR-0009). Instead, any party — the Aggregator included —
MAY publish a **companion pack**: a signed artifact of vectors computed
over a named Snapshot. A conforming pack declares the `content_digest`
and `tree_size` it was computed against; declares its model — `name`,
`version`, `weights_hash`, `dim`, `quantization`, the distance `metric`,
and the record field embedded (`source`, e.g. `summary`) — precisely
enough that any holder of the named Snapshot can re-embed any record and
compare; and covers only records the bound digest covers, which excludes
records withdrawn at that height by construction. A pack's signature
binds provenance and its bound digest binds scope; the honesty of the
vectors themselves is neither, and this specification deliberately
defines no equivalence criterion for them — a Consumer's trust in a pack
is trust in its publisher, chosen the way a client is chosen, never a
property the protocol asserts. Packs published by the Aggregator are
Snapshot artifacts for the purposes of §6.2's withdrawal obligations; a
third-party pack containing a since-withdrawn record is a copy already
served, in the position WIST-1 §9 names, with a named holder. Discovery of
packs is out of scope: a Consumer verifies a pack against the digest of
a Snapshot it already holds, wherever the pack came from.

**The link graph.** `tier1/links.parquet` carries one row per declared
link of every materialized record: `(source_url, target_url, position)`, where
`source_url` is the record's Normalized URL, `target_url` a member of
its Payload's `links.urls`, and `position` that member's zero-based
index. The artifact is a pure function of the materialized records' Payloads —
any party holding them can rebuild and compare it row for row — and it
carries no digest of its own: `content_digest` deliberately covers
Log-derived tuples only, so that it remains computable after a
withdrawal, and the artifact's transport integrity is already pinned by
its `files` entry. It transports declarations, never a judgement: which
links are trustworthy, and what importance follows from being linked,
is ranking, and ranking is outside this protocol (WIST-4 §4, ADR-0006,
ADR-0008). That boundary is what makes carrying the graph admissible at
all: ADR-0006 keeps importance out of the protocol, and ADR-0008 records
that a page's own outbound links are a verifiable statement about the
Publisher's content rather than a claim about its own importance, so the
raw edges may be distributed while no rank, weight or aggregate of them
ever is.

**The label table.** `tier1/labels.parquet` carries one row per Label
current at `tree_size` from any Labeler the Log sealed: `(labeler,
subject, name, value, asserted_at, expires_at, delta)`, where `value` is
the Label's integer or `NULL` where absent, `expires_at` and `delta` — the
Item ID the Label binds — the Label's members or `NULL`, and a retracted
Label or one expired at Epoch `epoch_number`'s `sealed_at` has no row
(WIST-2 §3.3). Like the link graph it is a pure function of the Log —
every field is sealed in a `label` Entry — and transports statements,
never a judgement: which Labelers a Consumer believes is the Consumer's
subscription (WIST-4 §6), and no Snapshot builder applies a Label to a
record.

**The dispute table.** `tier1/disputes.parquet` carries one row per
current dispute at `tree_size`: `(label_id, disputant, reason,
asserted_at)`, `reason` `NULL` where absent (WIST-2 §3.3). A dispute
alters nothing in the label table: the two tables sit beside each
other so that a Consumer weighing a Labeler can read what the labeled
parties answered, and no builder decides between them.

**The labeler table.** `tier1/labelers.parquet` carries one row per
Labeler with any sealed `label` Entry at or below `tree_size`:
`(labeler, label_count, retraction_count, distinct_subjects,
first_seen_height)` — every sealed `label` Entry of the Labeler counted,
retractions included, the number of those with `retracted` `true`, the
number of distinct `subject` values across them, and the height of its
first sealed `label` Entry. The table reads no Label's `name` or
`value` and applies no Label: it is arithmetic over Entry counts a
Consumer could redo from the Log, materialized so that a subscription
decision can start from how a Labeler behaves rather than from
nothing. The table is tier-1 data, not state: no tuple carries its
counts, a Consumer resumed from a Snapshot MAY read it for the figures
at `tree_size`, and one that does not holds counts only for the
Entries it walked and MUST NOT present them as the Labeler's whole
history.

**Catalogs and records.** Replay of a Log's sealed Entries (§3.3) holds
the following state, each a function of those Entries alone.

| State | Held per | Value |
|---|---|---|
| Latest Catalog | Publisher and Collection name | The valid `publisher_catalog` Entry applied last: its Envelope and its sealing height |
| Floor | Publisher and Collection name | The `generated_at` of the latest Catalog. A name with no latest Catalog has no floor, and no rule bounds its first instant from below |
| Record | Publisher and URL | The Item of kind `page` that a valid `publisher_item` Entry made the URL's record (§3.3), its Collection, and the Catalog ID and `generated_at` of the Catalog it was proved against |
| Removal state | Publisher and URL | That a valid Item of kind `removed` removed the URL's record: that Item's Item ID and the Catalog ID and `generated_at` of the Catalog it was proved against |

The Publisher of a record is the Publisher of the Entry that sealed its
Item (§3.3), the signed `catalog.publisher` of the Catalog it was proved
against, authenticated under WIST-1 §3.8 and §5; it is never derived
from key ownership or the URL host, and rotation, recovery and identity
reset reassign no record. Disjoint Scopes and narrowing leave no URL of a
Publisher with a record in two Collections (WIST-1 §5.1, §5.2).

The latest Catalog and the floor stay when a Declaration stops naming
the Collection, when narrowing or a base removes the Collection's
records, and when the Publisher's identity resets (WIST-1 §5.2). A record
leaves when a valid Item replaces or removes it (§3.3), when narrowing
removes it (WIST-1 §5.2) and when a base removes it (below); a record
that narrowing or a base removed leaves no removal state. A removal state
stays through narrowing and through a base, and ends when a valid Item
of kind `page` becomes the URL's record. A withdrawal (§6.2) removes no
record. The Log retains every Entry in every case; replay shapes only the
present state.

A record carries the instant of the Catalog its Item was proved against.
A Collection carries the instant of its latest Catalog, which says that
the Publisher stated the Collection then and says nothing of any one
record. A party that holds every Item of a Collection MAY recompute the
root and compare it with the latest Catalog's; the comparison changes no
sealed value, no state tuple and no digest.

**A base.** A Catalog is a **base against the floor** when its Publisher
and Collection name have a floor and its `generated_at` is more than
`removal_retention_days` (WIST-1 §3.3), of 86 400 seconds each, later than
the floor: an Item of kind `removed` listed after the floor may have left
the list since. A Catalog later than the floor by exactly that interval
is not one. A valid Catalog that is a base against the floor at its Epoch
is a **base**. `removal_retention_days` is 180 in every Log: no Log
amends it and no parameter map carries it, so a pull and an Epoch read
the same value. No act of the Aggregator marks a base; every party
derives it from two sealed instants and that constant.

When a base applies, every record of its Publisher in its Collection is
removed, before the Items of the Epoch apply. I7 then reads no record of
that Collection: a record of the URL that another Collection carries is
read as outside a base, so an Item of kind `removed` passes I7 where such
a record exists and fails it elsewhere, and an Item of kind `page` that
no withdrawal names passes it unless it is such a record's Item. A record
is absent from the Epoch of the base until the Epoch that seals its Item
again. The capacity and the inclusion ceiling bound that interval and
nothing else does: a list of n Items under a capacity of c Entries takes
at least ⌈n / c⌉ Epochs.

An Aggregator reads I7 for the Collection in the same way from the pull
that accepts a Catalog that is a base against the floor until that
Catalog, or one that replaces it while it waits, is sealed or leaves:
every admitted Item for which I7 so holds waits (§3.3) and is sealed in
its turn. A Catalog a pull queues (WIST-1 §5.2) begins no such reading;
for a base in the queue it begins at the settlement that makes the base
the last accepted Catalog. When the base leaves unsealed, failing C1 at
its turn, I7 is read against the records again, and the Items that are
their URL's record leave unreported, as an Item for which I7 no longer
holds leaves (§3.3).

**Several Logs.** A Catalog has the same inner object and the same
Catalog ID in every Log, and its Envelope may carry another signature in
another Log; an Item has the same octets and the same Item ID in every
Log. For one Publisher and URL, a Consumer of several Logs takes the
state proved against the latest Catalog in the Catalog order (WIST-1
§3.5), among the Logs that hold a record or a removal state for the URL;
between states proved against one Catalog it takes the state of the
greater Item ID in octet order, a record's being its Item's. A record
that narrowing or a base removed in a Log leaves no state in that Log.
The order runs across the Collections of the Publisher. Neither a walk
nor a chain of change lists gives a list with two Items under one key
(WIST-1 §4.2, WIST-2 §5.3), so two states proved against one Catalog
arise only where an Aggregator sealed an Item from a list it obtained
otherwise; the rule makes the Consumers of such Logs agree.

**One URL, one Publisher.** A URL's host can lawfully sit inside two
authorities at once: its own domain's, and that of a Publisher whose
`subdomain_scope` names it (WIST-1 §3.2). Records are keyed by (Publisher
domain, Normalized URL), so the same URL can carry a record under each
Publisher, and a query needs one. Of the records of one URL whose Item no
withdrawal sealed at or below the height names, one is **materialized**.
From the height at which the first `publisher_declaration` Entry whose
`domain` is the host is sealed, only the record of the host's own
Publisher is materialized, and none where that Publisher holds none:
self-declaration prevails, and no later Entry ends it. Below that height,
and for a host that never declares, more than one Publisher can hold such
a record. The record materialized is then the **nearest ancestor**'s: the
Publisher whose domain is the longest the host descends from, the host
being `<label>.D` or a deeper descendant of that domain `D`. A Publisher
that is no ancestor of the host materializes the URL only while no
ancestor holds such a record, and among such Publishers the least domain
in ascending octet order does. The other records stay records (above), are
not materialized, and return when the preferred record leaves. Every input
to the rule — the Declaration Entry, its height, the records, the
withdrawals, the domains — is in the Log, so any two replayers agree.

**Materialization rule.** The **materialized records** at `tree_size` are
the records the rule above materializes, ordered by Publisher domain and
then by URL, each compared as the octets of its UTF-8 string. The rows of
the link graph (above) are ordered by their source records, in that
order, and then by ascending `position`. Wherever this suite serializes
or enumerates either list, the rows of a tier file included, it does so
in that order; `content_digest` (below) sorts its own serializations and
does not read it. An Item of kind `removed`,
narrowing and a base remove a record, and with it its content, from
every Snapshot produced at or above the height that removes it. A
`payload_withdrawal` (§6.2) excludes its Item's content from every
Snapshot produced at or above its sealing height, in both tiers,
including any declared link derived from it: a record whose Item it names
is not materialized. The log itself retains full history in every case —
removal and withdrawal shape the materialized present, never the
recorded past.

Both exclusions are computed from the Log, so two parties building a
Snapshot at the same `tree_size` still materialize the same record set.

Withdrawal reaches backward into Snapshots as well, because a Snapshot
already published carries the content in its tier files —
`tier1/extracts.parquet`'s text and `tier1/links.parquet`'s declared
links alike, per §6.2's rule that both are content. The Aggregator and
every Mirror MUST stop serving any Snapshot artifact containing
withdrawn content: the Aggregator either withdraws that Snapshot from
distribution or replaces it with one rebuilt under the exclusion rule
above, under a fresh signed manifest and at a `tree_size` at or above
the withdrawal's sealing height — below that height the exclusion does
not apply and the rebuild would simply reproduce the content — and a
Mirror re-serving `/snapshots/` (§6) is bound identically — a Mirror
that kept serving the superseded tier files would leave the content in
distribution no matter what the Aggregator did, which is the whole of
what withdrawal is supposed to stop.
Neither costs a Consumer anything it cannot recover, since any state a
Snapshot provides is reachable from the Log and the Payloads. A manifest's
per-file `sha256` is a digest of a whole tier file rather than of any one
record, so it is no handle onto an individual extract — deriving one from
it would require already holding the file, and with it the text.

Anyone can rebuild an equivalent Tier 0/Tier 1 from the raw log, the
Payloads it references, and the manifest's declared parameters; Snapshots
are a convenience, not an authority. Withdrawal does not cost that
property: because the exclusion is triggered by a logged entry rather than
by whether a given rebuilder happens to hold the file, two parties with
different Payload collections still materialize the same record set. A
party missing a Payload that was never withdrawn cannot rebuild, and MUST
report that rather than emit a Snapshot silently missing a record.

**Verifying a rebuild.** Snapshot files are not byte-reproducible: SQLite
and Parquet outputs vary with library version, page size and compression
settings, and none of that is a property of the state being
described. This specification therefore does not require byte equality
between independent builds. It requires **semantic equivalence**, verified
by the manifest's `content_digest`:

```
record(r)       = {"url": r.url, "publisher": r.publisher,
                   "item_id": r.item_id, "observed_at": r.observed_at,
                   "attested_at": r.attested_at}
record_bytes(r) = JCS(record(r))
content_digest  = "sha256:" + hex(SHA-256(concat(
                      sorted(record_bytes(r) for r in records))))
```

where `records` is every materialized record at `tree_size`, and
`record(r)` is its **content tuple**; `r.item_id` is the Item ID of the
record's Item, whose Payload supplied the content the tiers carry;
`r.observed_at` is that Item's `observed_at`, the string the Item carries;
`r.attested_at` is the `generated_at` of the Catalog the record's Item was
proved against, the instant the record carries (above) and the tiers carry
with it; and `sorted` is ascending octet order. Records are keyed by
(Publisher domain, Normalized URL) and the tuple carries both, so the
ordering is total and no two records can produce equal bytes. JCS objects
are self-delimiting, so the concatenation is unambiguous; an empty record
set digests the empty octet string. The root of a Collection is a separate
value, which its Publisher signs in each Catalog; the digest neither
carries nor replaces it.

Two parties that materialize the same Log prefix MUST obtain the same
`content_digest` regardless of their storage libraries; a mismatch — not a
differing file hash — is what indicates divergence. Per-file `sha256`
values remain in the manifest for transport integrity of the specific
artifacts the Aggregator published (§6).

**Every input is in the Log, and none of it is content.** The digest is a
function of the Log prefix from genesis through `tree_size` and of
nothing else. Removal and withdrawal are decided by sealed Entries, and
the Parameter Registry values that decide them are read as of
`tree_size`. Two consequences carry the design:

- **A rebuilder needs no Payload to compute it.** That is deliberate. A
  Payload may have been withdrawn since the Snapshot was published (§6.2),
  and a digest whose preimage included the withdrawn text could never be
  recomputed again — the guarantee would expire exactly when it is most
  contested. Because a withdrawal excludes the record only from Snapshots
  at or above its sealing height, and a replacement Snapshot is built at or
  above that height (above), every withdrawal a digest accounts for lies
  inside the prefix the digest is computed over: no second horizon is
  needed to say which ones those are.
- **Agreement still pins the content.** `item_id` is the SHA-256 of an
  Item's JCS serialization, which carries the salted commitment to the
  Payload (WIST-1 §3.6, §4.1). Two parties whose digests agree therefore hold the
  same commitment for every record, and §6.1 forbids materializing content
  that does not reproduce its commitment. The digest itself carries no
  content and confirms nothing a holder of a candidate text could not
  already confirm from the Log, since every field of the tuple is sealed
  there in the clear; the per-record commitment, not the digest, is what
  binds the text.

**What the digest does not say.** It describes a record set, not a height.
Two Epochs whose materialized records are identical digest identically,
which is correct — they are the same state. The height is carried by
`epoch_number` and `tree_size` and bound to a single tree by `root_hash`,
the root hash at `tree_size`, which §8 checks against the Checkpoint the
Consumer verified. A Consumer that rebuilds to a height whose record set
differs therefore sees a `content_digest` mismatch (`WIST3-E04`) rather
than silent agreement; one that rebuilds to a different height whose
record set is the same agrees, and is right to, since the manifest's
`tree_size` already says which height was meant. A manifest from a forked
Log shows a `root_hash` the Consumer's tree does not produce
(`WIST3-E02`), whatever its digest says. Nor does the digest speak for a
non-conforming builder: it proves two parties materialized the same
records, not that either verified the Payloads it indexed, which §6.1
requires of them separately.

**Sharding.** A manifest MAY declare `shards`: a `count` ≥ 1 and a
`digests` array of exactly `count` entries. When it does, every `files`
entry carries a `shard` index in `[0, count)`, a record belongs to the
shard

    first 8 octets of SHA-256(UTF-8 of the Publisher domain),
    read big-endian, mod count

— by Publisher domain, so every domain's records travel together and a
Consumer holding a shard holds whole domains, never fragments — and
`digests[i]` is the §7 construction computed over shard *i*'s records
alone. The whole-set `content_digest` is unchanged and remains REQUIRED:
the shards partition the records, so any party holding all shards
recomputes it, and any party holding some verifies each held shard
against its own digest. A **partial Consumer** MAY materialize any
subset of shards, MUST verify each held shard's digest and MUST treat
its coverage as partial — absence of a record it holds no shard for is
not evidence of anything. Sharding is what keeps two obligations
compatible at scale: a withdrawal (§6.2) invalidates the files of one
shard and the manifest, not every artifact of the Snapshot, so Mirrors
re-fetch one shard rather than terabytes; and a Consumer whose hardware
fits a fraction of the corpus verifies the fraction it holds instead of
trusting it. `shards.count` is the Aggregator's choice per Snapshot; a
manifest without `shards` is the `count` = 1 case with the bookkeeping
elided.

Where sharded, shard *i*'s six tier files (below) sit under `shard-<i>/`
relative to the manifest, `<i>` the decimal index without padding
(`shard-0/tier0/index.sqlite`), and a `files` entry's `shard` is the
index its path prefix names. A sharded manifest whose `digests` has
other than `count` entries, that lists a file without a `shard` or with
one outside `[0, count)`, lists a tier file outside its `shard-<i>/`
prefix, or has a shard in `[0, count)` with no `tier0/index.sqlite`
entry of `tier` 0, does not verify (`WIST3-E04`). Rows are assigned by
the domain rule
above applied to the domain each row is keyed by, the same keys the
state artifact's parts use (below): a record's row and its
`tier1/extracts.parquet` and `tier1/links.parquet` rows by the record's
Publisher, `tier1/labels.parquet` and `tier1/labelers.parquet` rows by
the Labeler, `tier1/disputes.parquet` rows by the disputant. A Label
is not filed under its subject's Publisher: a subject can be a URL no
record covers, and the rows a subscription decision reads (WIST-4 §6)
are a Labeler's, which this rule keeps whole in one shard.

**Tier layout is normative.** A conforming rebuild MUST produce, per
shard where sharded: `tier0/index.sqlite` — a SQLite database whose
table `records` has columns `url`, `publisher`, `item_id`,
`observed_at`, `attested_at`, `title`, `abstract`, `lang` (the content
tuple's fields, the Payload `summary`'s members, `NULL` where the Payload
declares none, and the Item's `meta.lang`), with an FTS5 index over
`title` and `abstract` — and `tier1/extracts.parquet` (`url`,
`publisher`, `item_id`, `extract`),
`tier1/links.parquet`, `tier1/labels.parquet`, `tier1/disputes.parquet`
and `tier1/labelers.parquet` (above). An implementation MAY add columns and
auxiliary tables; a Consumer MUST ignore columns it does not know, and
MUST NOT require any column this paragraph does not name. The layout is
normative for the same reason the digest is: "anyone can rebuild an
equivalent Tier 0" is exercisable only if two rebuilds answer the same
query the same way, and a first implementation's private layout would
otherwise become a de facto standard nothing checks.

**The state artifact.** The content tuples are the index's content; they
are not its law. Key validity, the parameter schedule, withdrawals,
Labels, the latest Catalogs and the records are all defined by replay from
genesis, and a Consumer that starts from a Snapshot instead of genesis
needs that state or it cannot verify the first post-rotation signature,
apply a pending amendment, hold the Label a Labeler retracts next, or
judge the next Catalog and Item of a Collection. The manifest therefore
declares `state`: the `path`, `sha256` and `bytes` of a state file, and
its `state_digest`. The state file is a signed Envelope whose inner object
is `state` (schema:
[`schemas/snapshot-state.schema.json`](../schemas/snapshot-state.schema.json)),
carrying `wist_version`, the `tree_size` (= the manifest's), and
`entries`: one tuple per item of live protocol state and per removed
Aggregator key (below), each a JSON array whose first member is its kind.
The kinds, their key fields and their value fields are:

| Kind | Key fields | Value fields | Defined by |
|---|---|---|---|
| `aggregator_key` | `key_id` | `public_key`, added height, removed height or `null`, adding act or `null`, removing act or `null` | §3.4 |
| `declaration` | domain | the current Declaration Envelope, its sealing height, the highest accepted `seq` | WIST-1 §5 |
| `pending_declaration` | domain | the pending head Envelope, its sealing height, the activation height | WIST-1 §5.2 |
| `parameter` | identifier, `effective_at` | value | WIST-4 §5 |
| `recovery_window` | domain | owner Declaration height, window end, the recovery-chain head Envelope, its sealing height | WIST-1 §5.2 |
| `suffix_list` | snapshot identifier | sealing height of the act that put it in force | WIST-4 §3.1 |
| `collection` | publisher, Collection name | the latest Catalog Envelope, its sealing height | §7 |
| `record` | publisher, URL | the Item, its Collection name, the Catalog ID and `generated_at` of the Catalog it was proved against | §7 |
| `removal` | publisher, URL | the Item ID, the Catalog ID and `generated_at` of the Catalog it was proved against | §7 |
| `withdrawal` | Item ID | the Publisher's domain, sealing height | §6.2 |
| `label` | labeler, subject, name | value or `null`, `asserted_at`, `expires_at` or `null`, `delta` or `null`, Label ID, sealing height | WIST-2 §3.3 |
| `dispute` | Label ID, disputant | `reason` or `null`, `asserted_at`, sealing height | WIST-2 §3.3 |

An `aggregator_key` tuple exists for every key admitted at or below
Epoch `epoch_number`: the genesis key, with added height 0, and every key an
accepted `aggregator_key_add` (§3.4) admitted, with that act's sealing
height. A removed key's tuple MUST remain, carrying the sealing height of the accepted
`aggregator_key_remove`; it is the one kind whose tuples outlive their
item, because a resuming Consumer evaluates §3.4's key-act failures
against removed keys and judges a lower Checkpoint under the keys valid
at its own height (§5) exactly as a replaying one does. A tuple's key is
valid at height *h* ≥ 0 iff its added height ≤ *h* and its removed height
is `null` or greater than *h*; the set valid at height −1 is the genesis
key alone (§3.4). The adding act is the accepted `aggregator_key_add`
Registry Update Envelope that admitted the key, verbatim as sealed, and
`null` for the genesis key alone; the removing act is the accepted
`aggregator_key_remove` Envelope sealed at the removed height, verbatim,
and `null` exactly when the removed height is `null`. Of two removals of
one key accepted in one Epoch (§3.4), the tuple carries the one at the
lower Entry index.

**Authenticating the key tuples.** The tuples say which keys speak for
the Log, so no signature under one of them authenticates them: a
Consumer holding the Anchor authenticates them from its genesis key
before it uses any tuple. With *E* the manifest's `epoch_number`, all of
the following MUST hold, and a state file failing any is rejected with
its Snapshot (`WIST3-E04`):

1. No two `aggregator_key` tuples carry one `key_id` or keys with one
   note key ID (§3.4).
2. Exactly one tuple has a `null` adding act. Its `key_id` and
   `public_key` are the Anchor's `genesis_key`'s and its added height is
   0.
3. Every non-`null` adding act passes WIST-4 §5.1's field validation as an
   `aggregator_key_add` whose `key_id` and `public_key` are the
   tuple's, and its added height is an integer from 0 through *E*.
4. The removing act is `null` exactly when the removed height is
   `null`. A non-`null` removing act passes WIST-4 §5.1's field
   validation as an `aggregator_key_remove` naming the tuple's
   `key_id`. A non-`null` removed height is at most *E*, at least 0 for the genesis key and greater
   than the added height for every other key.
5. Each act's signature verifies under the key of the tuple its
   `sig.key_id` names, and that key is valid at height *h* − 1 by the
   tuples' heights, *h* being the height the tuple gives the act — the
   added height for an adding act, the removed height for a removing
   one (§3.4's authentication height for key acts).

A key valid at *h* − 1 has an added height below *h* or is the genesis
key, so rule 5 chains every act to the Anchor by induction on height.
The heights themselves, and which of two removals accepted in one Epoch
a tuple carries, are assertions of the state file's signer that these
rules do not test: they are falsifiable by replay like every other
tuple, through `state_digest` (§8, `WIST3-E04`).

A Consumer that already holds key state for the Log — one catching up
through a Snapshot (§8) — applies the same rules and additionally
rejects the Snapshot (`WIST3-E04`) unless the tuples agree with its own
registry up to its verified head *V*: every key the registry holds has a
tuple with the registry's `public_key`, added height and adding act; a
key the registry holds as removed has the registry's removed height and
removing act; a key the registry holds as valid at *V* has a removed
height that is `null` or greater than *V*; and every tuple for a key
the registry does not hold has an added height greater than *V*.

A `parameter` tuple exists only for a parameter amended since genesis:
Registry defaults are constants of this suite and are not restated. One
tuple exists per amendment rather than per identifier, which is why
`effective_at` is a key field: a `parameter_change` sealed before
`tree_size` but effective after it is live state a resuming Consumer
cannot re-derive — it will never see that Entry again — and a single tuple
per identifier would force the artifact to choose between the value in
force and the one about to be. Both appear, and a Consumer applies each at
its own instant — `effective_at` inclusive, the greatest `effective_at`
at or before an instant prevailing (WIST-4 §5). An amendment that another
amendment with the same `effective_at`, sealed later in Log order,
supersedes is never in force and is not state: no tuple exists for it,
which is what keeps the key unambiguous. A `suffix_list` tuple exists
for the one snapshot in force at the first Epoch above `tree_size`
— the most recent accepted `suffix_list_update` sealed at or below it
(WIST-4 §3.1) — and for no earlier one, so that a resuming Consumer
accounts the next Epoch's capacity under the snapshot a replaying one
reads; no tuple exists while no act has been accepted. A `collection`
tuple exists for every Publisher and Collection name with a latest
Catalog, a name no Declaration in force names included; a resuming
Consumer derives the floor, C3, C4, I3 and a base from it as a replaying
one does. A `record` tuple exists for every record the Log holds at
`tree_size`, a record the one-URL rule does not materialize and one whose
Item a withdrawal names included, so the `record` tuples' keys are a
superset of the content tuples' and not the same set; it carries the
Item itself, so that a resuming Consumer judges I7, narrowing and a base,
verifies the Payload of a record that comes to be materialized, and
holds the state Several Logs combines, exactly as a replaying one does.
A `removal` tuple exists for every removal state, for the same
combination. `state_digest` is the §7
construction verbatim — `sha256:` over the concatenation of the sorted
JCS bytes of every tuple — and every field above is Log-derived, so the
digest is computable after any withdrawal, for the §7 reasons. A
Consumer that replays from genesis MAY recompute it and MUST obtain the
manifest's value; recomputability from public inputs, not the
Aggregator's signature, is what makes the artifact state rather than
testimony.

A tuple's encoding is normative: it is the JSON array `[kind, key fields…,
value fields…]` with the members in exactly the order the table gives,
none omitted and none added. Heights and Epoch numbers are JSON integers;
a "removed height or `null`" member is an integer or JSON `null`; instants
(a window end, a Catalog's `generated_at`, a parameter's `effective_at`)
are the whole-second literal-`Z` RFC 3339 strings the sealing Epochs and
the Entries they seal carry (WIST-4 §3, WIST-1 §3.5); a Label's
`asserted_at` is the Publisher timestamp its Entry carries (WIST-2 §3.3);
domains, URLs, `key_id`s, names and parameter identifiers are the strings
the sealed Entries carry; keys are raw base64url public keys; IDs and
snapshot identifiers are `sha256:`-prefixed. Several kinds need more than
that: `collection`'s value members are the latest Catalog's Envelope
verbatim as sealed, then its sealing height; `record`'s are the Item
verbatim as sealed, its Collection name, the Catalog ID and that Catalog's
`generated_at`; `removal`'s are the Item ID of the Item of kind `removed`,
the Catalog ID and that Catalog's `generated_at`; `declaration`'s value
members are the current Declaration Envelope as sealed, verbatim as one
JSON object member, then its sealing height, then the highest accepted
`seq` — WIST-1 §5.2's sequence floor, which a settlement that restores a
lower-sequence head leaves above the current `seq`; `recovery_window`'s
are the owner Declaration's sealing height, the window end, then the
recovery-chain head's Declaration Envelope verbatim and its sealing height
— the owner itself until a legitimate follower advances the head (WIST-1
§5.2), carried in full because a resuming Consumer verifies later
followers against the head's Key Set and holds no Epoch to fetch it from;
`pending_declaration`'s are the pending head's Declaration Envelope
verbatim, its sealing height and the activation height frozen at the first
pending Declaration (WIST-1 §5.2), carried in full for the same reason,
and present only while a pending head exists; a `label` tuple exists for
each (labeler, subject, name) whose current Label at `tree_size` is not
retracted and not expired at Epoch `epoch_number`'s `sealed_at` (WIST-2
§3.3), carrying that Label's value or `null`, its `asserted_at`, its
`expires_at` or `null`, its `delta` or `null`, its Label ID and its
sealing height, so that a resuming Consumer orders a later Label of the
same triple, drops the Label at its expiry, reads its binding and checks a
later dispute naming the Label (WIST-2 §3.3) exactly as a replaying one
does; a `dispute` tuple exists for each (Label ID, disputant) with a
sealed dispute, carrying the current dispute's `reason` or `null`, its
`asserted_at` and its sealing height; a `withdrawal` tuple exists for
every Item ID a withdrawal that meets its contract names, with the height
of the earliest such withdrawal (WIST-4 §5.1), since a Consumer resuming
above the withdrawal's Epoch never sees its Entry and must still exclude
the content (§6.2) and judge I7 (§3.3); no tuple names every Item sealed
at or below `tree_size`, and a resuming Consumer judges the contract of a
later act as WIST-4 §5.1 states for a Consumer resumed from a Snapshot.
The schema pins each kind's arity and member types
([`schemas/snapshot-state.schema.json`](../schemas/snapshot-state.schema.json));
the table remains the normative inventory, and a state file omitting a
kind with live instances at `tree_size`, omitting a removed key's
`aggregator_key` tuple, or carrying a kind this table does not name, does
not verify.

Sharding applies to this artifact as to the tiers: when the manifest
declares `shards`, the state file MAY be split on the same
Publisher-domain rule, one part per shard for the domain-keyed kinds
(`declaration`, `pending_declaration`, `recovery_window`, `collection`,
`record` and `removal` by their Publisher, `withdrawal` by the
withdrawn Item's Publisher, `label` by its Labeler, `dispute` by its
disputant), with the Log-wide
kinds (`aggregator_key`, `parameter`, `suffix_list`) carried in every
part, since no Consumer can validate an Entry without them.
The tuple set is a set: a Log-wide tuple appears exactly once in the
digest preimage, however many parts carry a copy.
`state_digest` remains the digest over the whole tuple set: a partial
Consumer verifies its parts against the per-shard digests and, as
above, treats its coverage as partial.

## 8. Cold Start and Continuous Operation

**Cold start:**

1. Fetch `/snapshots/index.json`; validate it against its schema;
   choose an entry (normally the newest). The signatures of the index,
   the manifest and the state file are verified in step 8, under keys
   no step before it has established (§3.4).
2. Fetch that entry's `manifest_url`; validate it against its schema;
   verify that its `snapshot_date`, `tree_size` and `content_digest` are the ones the
   index entry named (`WIST3-E04` on disagreement — the two are independently
   signed statements about the same Snapshot; since a served directory is
   never rewritten (§6), a disagreement means the index the Consumer read
   is no longer the current one, and the re-fetch is of the index).
3. Download the listed files — all of them, or, under a manifest that
   declares `shards` (§7), the state file and the files of any subset
   of shards, selected by their `shard` index — and verify each SHA-256
   and byte size.
4. Load the state artifact (§7): verify that its `tree_size` is the
   manifest's and authenticate its `aggregator_key` tuples from the
   Anchor as §7 requires (`WIST3-E04` otherwise, rejecting the
   Snapshot), and take its tuples as the protocol state at Epoch
   `epoch_number` — key registries, Declarations, parameters, the
   Public Suffix List snapshot in force (whose octets the Consumer
   fetches from `/log/suffix-lists/` and verifies by their identifier
   before it checks the next Epoch's per-domain capacity, WIST-4
   §3.1), withdrawals, Labels, latest Catalogs, records and removal
   states. Every Entry applied below is validated against this state
   exactly as a replaying Consumer validates against state it derived
   itself: a signature under a key the state does not admit, a
   `publisher_item` Entry naming a Catalog that is not a latest Catalog
   the state holds, an Item that is its URL's record, a Label older than
   the one the state holds for its triple, all fail as they would on full
   replay. A `recovery_window` tuple makes its head an
   eligible predecessor beside the current Declaration, and the Consumer
   settles it before applying the first Epoch at or after its end exactly
   as WIST-1 §5.2 directs: the head becomes current and the `declaration`
   tuple's sequence floor stays. A `pending_declaration` tuple makes its
   head an eligible predecessor beside the current Declaration, supplies
   no candidate to a Catalog's binding check, and activates or is
   reversed at the heights
   WIST-1 §5.2 fixes.
5. Fetch `/log/checkpoints/<epoch_number>` (§6) and verify it as §5
   requires under the `aggregator_key` tuples just authenticated; verify that
   it states tree size `tree_size` and the root hash
   `root_hash` carries (§3.1). A mismatch is chain divergence
   (`WIST3-E02`), not a corrupt file: it means the Snapshot describes a
   different tree from the one the Log signs. The manifest's
   `epoch_number` selects the Checkpoint and is never itself compared
   for divergence: a file at that path stating another `epoch_number`
   is the source's fault (`WIST3-E03`, §6) and is fetched again, from
   another source if needed. The same dispositions hold wherever a
   Consumer reads a manifest against a Checkpoint, a catch-up through a
   Snapshot (below) included. This
   Checkpoint is the Consumer's verified head.
6. Fetch `/checkpoint` (SHOULD: from ≥ 2 sources, the monitoring
   endpoint of each trusted Witness among them, §5) and every archived
   Checkpoint between the head and it. A Checkpoint, tile or entry
   bundle a source does not hold is `WIST3-E01`: fetch it from another,
   since integrity never depends on the source.
7. Verify each Checkpoint above the head, in `epoch_number` order, as
   §5 requires: parse it; fetch the entry bundles covering its Epoch's
   leaves and the tiles the two proofs need (§6); verify the Consistency
   Proof from the previous Checkpoint's tree size and the Epoch's leaves
   against its root (§3.1, §4); apply the Epoch's Registry Updates; then
   verify the Log's signature under the key set valid at its height.
8. Choose the Checkpoint to adopt: the newest verified one, the head of
   step 5 included, carrying the Witness quorum §5 requires, recorded as
   unwitnessed where §5's interim applies. Entries above its tree size
   are not applied. If none carries the quorum the Consumer has no state
   to act on and retries (§5). Then verify the signatures of the index,
   the manifest and every state file loaded under the keys valid at the
   adopted Checkpoint's height (§3.4) — the tuples' keys as amended by
   the key acts of the Epochs walked in step 7. A signature that does
   not verify rejects the entire Snapshot (`WIST3-E04`). Until all
   verify, the Consumer MUST NOT persist or act on anything derived
   from the Snapshot. A signature whose `sig.key_id` names a tuple's key
   and does not verify under that key verifies at no height, and the
   Consumer MAY reject the Snapshot as soon as it has authenticated the
   tuples.
9. Fetch `/payloads/<item-id-hex>.json` for the Item of every record
   it materializes whose content it does not hold and whose Item no
   withdrawal names (§6.2); verify each against its Item's commitment
   and `bytes` (§6.1).
10. Apply Entries in order to the local index, Epoch by Epoch,
    materializing content only from Payloads that verified.

A Consumer that also replays the Log from genesis MAY recompute the
Snapshot's `content_digest` and `state_digest` (§7) and compare them with
the manifest's. Doing so needs no Payload and no tier file, so it is
available to any party holding the Entries — including one checking an
Aggregator it does not otherwise sync from — and it is what keeps the
state artifact an assertion anyone can falsify rather than testimony a
cold-starting Consumer must take on trust.

**Continuous operation:**

1. Fetch `/checkpoint` (SHOULD: from ≥ 2 sources, §5). A Checkpoint whose
   `epoch_number` is lower than the highest already verified MUST be
   rejected (§5's rollback rule) before any tile or bundle is fetched
   against it, and the Consumer SHOULD warn if the newest Checkpoint's
   `sealed_at` lags the current time by more than three sealing cadences
   (§5) — a stale head and a rolled-back head are the two ways a Mirror
   can leave a Consumer verifying correctly against the wrong end of the
   tree.
2. Fetch the archived Checkpoints between the verified head and it, and
   verify each as cold start's step 7 does.
3. Choose the Checkpoint to adopt as cold start's step 8 does; short of
   the quorum, keep the verified head and retry (§5).
4. Fetch and verify the corresponding Payloads (§6.1).
5. Apply.

Payload fetching never gates tree verification: a Consumer that cannot
obtain some Payloads still verifies, applies, and advances over the
Epochs, and simply materializes no content for the affected Items. Tree
integrity and content availability are separate failures, and only the
first is ever a reason to stop.

**Catch-up decision.** A Consumer catching up through a Snapshot
performs cold start's steps against it, applying §7's additional rule
for a Consumer that holds key state. A Consumer offline for a long period compares the
Epoch distance from its position to the newest Checkpoint against the
distance covered by the newest Snapshot, and chooses whichever costs less
to process. Both paths converge to identical state — the content tuples by
`content_digest`, the protocol state by `state_digest`, each recomputable
from the Entries alone (§7) — so the choice is purely economic, except in
a Log that sealed a `payload_withdrawal` breaking its `details` contract,
which a resuming Consumer cannot always tell from a conforming one
(WIST-4 §5.1). Without
the state artifact the sentence before this one would be false: content
tuples alone carry no key registry, no governance state, no latest
Catalog and no record the one-URL rule leaves unmaterialized, and the two
paths would converge only on content while disagreeing on law.

**Following more than one Log.** Nothing in this suite binds a Publisher
to one Log: WIST-2's publication surface is one site serving whomever
pulls, so any number of Aggregators MAY pull the same Collections and
Label Feeds and a Consumer MAY follow any number of Logs. A Catalog ID,
an Item ID and a Label ID carry nothing about the Log that sealed them
(WIST-1 §4, WIST-2 §3.3), so a Consumer holding two Logs deduplicates
Catalogs, Items and Labels by ID exactly, and combines the records and
removal states of one Publisher and URL by §7's rule for several Logs.
What does not merge is everything else a Log derives. Which Catalogs,
Items and Labels an Aggregator sealed, its latest Catalogs and floors,
its parameter schedule (WIST-4 §5), its quota accounting and the reach
of a withdrawal (§6.2) are state of one Log, defined by replay of that
Log's history. A Consumer
MUST NOT carry any of them into another Log: each is a function of a
single chain, and a value mixed across chains is recomputable by nobody.
Coverage across Logs is partial in exactly the sense §7 gives a sharded
Snapshot — absence of a record from a Log a Consumer does not follow is
not evidence of anything, and neither is absence from a Log that never
ingested that Publisher. The one place state does cross chains is
succession (§3.4), where a successor Anchor names its predecessor and
the Epoch it ended at; that is one Log continued under new keys, not two
Logs reconciled, and nothing here extends it to concurrent Logs.

## 9. Error Registry

| Code | Meaning and required behavior |
|---------|--------------------------------------------------------------|
| WIST3-E01 | A Checkpoint, tile, entry bundle or Public Suffix List snapshot missing at a source (§5, §6). Fetch it from another — a Mirror, the Aggregator or, for a head Checkpoint, a trusted Witness's monitoring endpoint; integrity never depends on the source. A Consumer holding a Checkpoint whose Entries no source serves keeps this code and applies nothing above its verified head (§5). |
| WIST3-E02 | Chain divergence: a Consistency Proof that fails between two Checkpoints of the Log, or from the empty tree to a Checkpoint stating tree size 0 with a root other than §4's — that one Checkpoint is the whole evidence — two Checkpoints that equivocate under §5, or a Snapshot manifest whose `tree_size` or `root_hash` is not what Checkpoint `epoch_number` states (§7, §8). Hard failure: preserve the Checkpoints — and, for a failed Consistency Proof, the tiles that reproduce the larger root — as an evidence bundle (§5), MUST NOT apply the data. |
| WIST3-E03 | Invalid object: a Log Anchor that fails its schema (§3.4); a Checkpoint that fails §5's parsing or signature rules, states a `sealed_at` not later than its predecessor's or off the grid (§3.1), or sits at an archive path not its own (§6); a tile or entry bundle over its format size, malformed (§6) or not reproducing the tree its Checkpoint states (§3.1, §6); an Epoch over the size cap (§6, WIST-4 §5), carrying an Entry over 65 535 octets or of an unknown type, out of canonical Entry order, with two `publisher_catalog` Entries of one `publisher` and `collection` (§3.3), over the per-domain capacity or the per-Labeler cap, or sealing a Label ID a lower Entry carries (§3.2); a suffix-list file whose octets do not hash to its name (§6); or a Payload that does not reproduce its Item's commitment (WIST-1 §3.6, `WIST1-E10`). Re-download, from another source if needed, before concluding misbehavior; an Epoch the Aggregator sealed over a bound is misbehavior no source repairs. |
| WIST3-E04 | Snapshot mismatch. Three cases, one code, different responses. An index, manifest or state file that fails its schema, a file hash or byte size that disagrees with the manifest, a state file whose `tree_size` is not the manifest's or whose `aggregator_key` tuples do not authenticate from the Anchor (§7), an index, manifest or state file whose signature does not verify under the keys valid at the adopted Checkpoint's height (§3.4, §8), or a manifest that disagrees with the `/snapshots/index.json` entry that pointed to it (§8): reject the entire Snapshot and re-fetch, from another Mirror if needed. A `content_digest`, `state_digest` or per-shard digest (§7) that disagrees with the Consumer's own rebuild at `tree_size`: not a transport fault and not fixable by re-downloading — the Consumer MUST NOT treat that Snapshot as authoritative, MUST fall back to materializing from the Log and the Payloads, and SHOULD publish both digests with the `tree_size`, since a Snapshot that does not match the Log is a claim the Aggregator cannot support and anyone replaying the Log can check the report. |
| WIST3-E05 | Payload absent from a Mirror inside the availability window with no `payload_withdrawal` sealed for it (§6.1, §6.2). A fault against that Mirror, never against the Item: fetch the Payload from another Mirror or from the Publisher (WIST-2 §3.1), and keep applying the Log. A Consumer that sees `WIST3-E05` from every source it tries SHOULD publish that fact, because a Payload absent everywhere with no logged basis is the signature of suppression rather than of erasure. |
| WIST3-E06 | A `publisher_catalog` or `publisher_item` Entry out of place in the Log: a Catalog that fails C2, C3 or C4, or an Item that fails I2, I3 or I7 (§3.3). The Entry is ignored, changes no state and leaves its Epoch accepted; an Aggregator seals none. |

A Checkpoint short of the Witness quorum has no code: §5 makes it a
wait, not a fault — the Consumer keeps its verified head, retries and
reports staleness as §5 directs — and an implementation MUST NOT report
it under `WIST3-E02` or `WIST3-E03`.

A Checkpoint below the verified head has no code either: §5's rollback
rule rejects it as a stale source, and an implementation MUST NOT
report it under `WIST3-E02` or `WIST3-E03` unless its note text differs
from the Checkpoint the Consumer verified at that `epoch_number`, which
is equivocation (`WIST3-E02`).

## 10. Security Considerations

- **Equivocation** is the Aggregator's only meaningful attack. §5
  makes it self-incriminating at the cost of two small signed files,
  and a Witness quorum makes it unreachable: a Consumer requiring
  `checkpoint_witness_quorum` Cosignatures adopts a split view only if
  that many of its trusted Witnesses cosigned both sides, which the
  Witness protocol forbids each of them to do. Below the quorum, and at
  the quorum of 0 this edition starts at, the defence is the evidence
  bundle alone (§5).
- **What a Cosignature does not cover.** A Witness attests the origin,
  tree size and root hash and makes no statement about the extension
  lines [tlog-cosignature], so two Checkpoints agreeing on the tree and
  differing in `epoch_number` or `sealed_at` — §5's second form of
  equivocation, which moves Epoch bounds and day counts — pass every
  Witness and are caught by the evidence bundle alone. Only the Log's
  own signature binds those lines, which is why it is a [signed-note]
  Ed25519 signature over the whole note text (§3.4) rather than a
  cosignature type. A Witness roster the Log distributed would let the
  Aggregator choose its own auditors, which is why the roster is the
  Consumer's configuration (§5).
- **Rollback.** A Mirror serving stale data cannot regress a Consumer:
  Epoch numbers are monotonic and Consumers never accept a Checkpoint
  older than one they hold.
- **Mirror tampering.** Mirrors are trustless byte servers; any
  modification fails hash or signature verification (`WIST3-E03`). This
  covers Payloads too: a Mirror that alters one fails the Item's
  commitment, which every fetcher recomputes and which the Publisher's
  signature over the Catalog that lists the Item fixed before any Mirror
  saw it.
- **Selective payload suppression.** Tampering being useless, a hostile
  Mirror's remaining move is to serve some Payloads and not others. §6.1
  makes that a typed, attributable fault: inside the availability window,
  absence with no `payload_withdrawal` in the Log is `WIST3-E05` against
  that Mirror, and the Payload is still obtainable from the Aggregator,
  another Mirror, or the Publisher, so suppression by one party achieves
  nothing but its own detection. Lawful withdrawal looks different in
  every respect a Consumer can observe: it is announced in the Log before
  it takes effect, it names a legal basis and a jurisdiction, it applies
  at every Mirror rather than one, and it is permanent and public.
  Two limits are worth stating plainly. After the window elapses, absence
  is no longer evidence, so suppression of old Payloads is indistinguishable
  from ordinary expiry — which is tolerable because the Aggregator serves
  the Payload of every record whatever the window (§6.1). And an Aggregator that
  withholds a Payload from ingest onward, never publishing it at all,
  is visible as an Item whose content no party can verify rather than as a Mirror
  fault; WIST-2 §5.1 and §3.3 of this document close the honest path: an Aggregator admits
  no Item of kind `page` whose Payload it does not hold and checks the
  Payload again at the Item's turn.
- **Compression bombs.** The tile and entry-bundle format sizes and the
  verified-prefix transport bound (§6) MUST be enforced while a response
  is read, before buffering bytes beyond the limit and whatever
  content-coding the transport applied.
- **Key rotation repudiation.** Without an in-band, height-scoped notion
  of key validity, an Aggregator caught equivocating could retire the
  signing key and claim the proof no longer identifies a currently
  trusted key, laundering the misbehavior. §3.4 closes this: key validity
  is evaluated at the signed object's own height, computed by replaying
  the log from the Log Anchor, so a signature valid at sealing time
  remains binding evidence regardless of later rotation.
- **Snapshot state signed by a removed key.** The state artifact is
  committed by no tree, so a key that could sign it for an old Epoch
  could attach false state to the genuine Log. §3.4 therefore verifies
  the Snapshot documents at the adopted head, where a removed key is
  not valid. The holder of a removed key that also confines a Consumer
  to a head below the removal can still pass a false Snapshot, where a
  replaying Consumer would see only old truth; §5's staleness warning
  and heads fetched from more than one source, Witness monitoring
  endpoints among them, are the defence. A holder of a once-valid key
  can likewise present `aggregator_key` tuples omitting its removal, as
  it can serve a replaying Consumer a fork from before it; comparison
  across sources and the Witness quorum catch both. A key valid at the
  head can assert false state, and `state_digest` recomputation by any
  replaying party (§8) is what falsifies it.

## 11. Privacy Considerations

The log is public and permanent; WIST-1 §9's constraints on personal data
apply to everything in it. Content is deliberately not in it: Payloads are
distributed alongside the Log and are erasable under §6.2, so an erasure
order costs a file deletion plus a Log entry rather than a rewrite of
sealed history. Mirrors keep serving bytes and stay free of any obligation
to re-serialize or partially reconstruct what they hold.

Erasure is an obligation on operators, not a property of the network. A
withdrawal binds the Aggregator, its Mirrors and the Publisher that first
served the Payload; it cannot reach a copy
already downloaded, and nothing in this specification pretends otherwise.
What the design does guarantee is that after withdrawal the Log itself
stops helping: with the salt destroyed, the surviving commitment does not
let a holder of a copy establish that the copy is what was committed to
(WIST-1 §3.6, §9).

On the read side, a Consumer's sync pattern
(timing, IP) is visible to the Mirrors it uses. Mitigations: Mirrors are
dumb file servers requiring no accounts; bulk sync reveals only "this IP
follows the log", not queries (all querying is local by design); privacy-
sensitive Consumers can sync over Tor or from a Mirror they operate.

## 12. Conformance Checklist

**Aggregator:**

- [ ] Seals Epochs per §3 (sequential numbering, strict `sealed_at`
      monotonicity on the cadence grid, whole-second `sealed_at` ending
      in `Z`, canonical Entry order, the per-domain Entry capacity and
      the per-Labeler cap, no Entry over 65 535 octets, at most one
      Catalog per Publisher and Collection, no Label sealed twice, and a
      Checkpoint stating the tree's true size and root)
- [ ] Seals no Catalog or Item that fails C1–C4 or I1–I7 at the Epoch
      that seals it, no Item in the Epoch that seals the withdrawal of
      its Payload and no `payload_withdrawal` that breaks its `details`
      contract (§3.3)
- [ ] Keeps the last accepted Catalog, what waits, places, eligibility
      Epochs and the inclusion ceiling of §3.3 for Catalogs, Items, Labels
      and disputes, defers a Catalog or an Item only by its four
      deferrals and reports each at the status endpoint, holds
      publications behind a Declaration that reduces authority, gives
      the capacity to Catalogs, then Items of kind `removed`, then Items
      of kind `page`, Labels and disputes, and checks each Item's Payload
      at its turn (§3.3)
- [ ] Reads I7 for a Collection without its records from the pull that
      accepts a base against the floor until that Catalog is sealed or
      leaves (§7)
- [ ] Publishes a Checkpoint per sealed Epoch at `/checkpoint` and in
      the archive, as the five-line signed note of §5 under a key valid
      at its height, carrying at most 16 signature lines, never before
      every Entry below its tree size is durably stored and served
      (§5, §6)
- [ ] Serves the static layout of §6: the [tlog-tiles] tiles and entry
      bundles at the Service Origin's root, the partial ones its head
      requires, never pruned
- [ ] Submits each Checkpoint to the Witnesses it uses and republishes
      it, at `/checkpoint` and in the archive, with the Cosignatures
      returned and its note text unchanged (§5, §6)
- [ ] Serves the Payload of every Item of kind `page` it seals at
      `/payloads/<item-id-hex>.json` from no later than the Epoch that
      seals it, for at least the availability window from that Epoch's
      `sealed_at`, byte-identical to what it verified (§6.1)
- [ ] Serves the Payload of every record's Item, unmaterialized records
      included, while that Item is the record, and gives a superseded
      Payload no further window (§6.1)
- [ ] Withdraws a Payload only by sealing a `payload_withdrawal` naming
      the Item, the legal basis, and the jurisdiction — and then stops
      serving it, together with any Snapshot artifact still containing its
      content (§6.2, §7)
- [ ] Materializes one record per URL under §7's one-URL, one-Publisher
      rule: the self-declared host's own, else the nearest ancestor
      Publisher's, else the least non-ancestor domain in octet order
- [ ] Produces Snapshots whose manifests satisfy §7, including the
      materialization rule with the order of the materialized records
      and the link rows in every tier file, the `content_digest`, the
      state artifact —
      removed Aggregator keys and unmaterialized records included — and
      its `state_digest`, per-shard digests where sharded, and an
      `epoch_number`, `tree_size` and `root_hash` that
      Checkpoint `epoch_number` states
- [ ] Treats any companion pack it publishes itself as a Snapshot
      artifact for §6.2's withdrawal obligations (§7)
- [ ] Publishes `/snapshots/index.json`, signed, newest first — the
      higher Epoch first within one date — agreeing with each manifest it
      points to, and removes an entry when it stops serving that Snapshot
      (§6)
- [ ] Serves each Snapshot under an immutable directory of its own, a
      later Snapshot of the same date under a new one, and never rewrites
      a path a served manifest or index entry has named (§6)
- [ ] Where sharded, lists each shard's six tier files under `shard-<i>/`
      with a matching `shard` index and files Label, labeler and dispute
      rows by Labeler and disputant (§7)
- [ ] Carries each key's adding and removing act in its `aggregator_key`
      tuple (§7), and on removing a key re-signs every unsealed document
      that key signed and it still serves (§3.4)
- [ ] Retains every entry bundle and full tile from genesis and every
      Checkpoint it has published, the latter at
      `/log/checkpoints/<epoch_number>` (§6)
- [ ] Serves every Public Suffix List snapshot a sealed
      `suffix_list_update` names at `/log/suffix-lists/<hex>.dat`, from
      the sealing Epoch and without expiry, and counts the per-domain
      capacity per Registrable Domain under the snapshot in force
      (§3.2, §6, WIST-4 §3.1)
- [ ] Rebuilds a Snapshot superseded by a withdrawal at a `tree_size`
      at or above the withdrawal's height, or withdraws it (§6.2, §7)
- [ ] Seals no Epoch whose size (§6) exceeds the smallest cap WIST-4 §5
      puts in force for it
- [ ] Publishes a Log Anchor that passes its schema, admits and removes
      all later keys in-band, signs each key act under a key valid at
      the previous height and every other act and the Checkpoint under a
      key valid at the Epoch's own, and seals no key-act failure (§3.4)
- [ ] Seals every Declaration under which a pull read at or below the
      Epoch that seals the first publication that pull accepted (§3.3,
      WIST-1 §5.2)
- [ ] Seals each pulled Label that verifies as a `label` Entry and each
      dispute as a `dispute` Entry, at most once per ID and within the
      per-Labeler cap, and materializes `tier1/labels.parquet`,
      `tier1/disputes.parquet` and `tier1/labelers.parquet` from the
      Labels and disputes current at `tree_size` and every sealed
      `label` Entry (§3.2, §3.3, §7, WIST-2 §3.3)

**Mirror:**

- [ ] Serves tiles, entry bundles and Checkpoints byte-identical to the
      origin's, and signed objects whose canonical bytes reproduce their
      signatures (§6)
- [ ] Serves Snapshot tier files byte-identical to origin, since only the
      manifest's per-file `sha256` authenticates them (§6, §7)
- [ ] Retains every Epoch it serves — its Checkpoint and the bundles and
      tiles meeting its leaves — for at least `mirror_retention_days`
      (§6)
- [ ] Retains all Checkpoints ever served, with every signature line
      they carried, without expiry (§5, §6)
- [ ] Serves the Public Suffix List snapshots the Epochs it serves read
      and name, without expiry (§6)
- [ ] Serves the Payloads of every Epoch it serves for at least the
      availability window, never serves a Checkpoint before its Epoch's
      Payloads, and
      stops serving one only after a `payload_withdrawal` is sealed for
      it (§6.1, §6.2)
- [ ] Stops serving any Snapshot artifact containing withdrawn content,
      on the same terms as the Aggregator (§6.2, §7)

**Consumer:**

- [ ] Applies the tile and entry-bundle format sizes, the transport
      bound and the accepted-schedule size checks (§6); rejects a tile or
      entry bundle whose form §6 excludes and an Epoch whose Entries do
      not fill its leaf range (§3.1, §6); rejects leap
      seconds in Log-comparable timestamps (§3.1, §7)
- [ ] Verifies every Checkpoint between its head and the one it adopts —
      parse, including the 32-octet canonical root hash line, every
      signature line's terminating newline and key-name form and the
      16-line limit (§5); Consistency Proof with the size-0 root compared (§4), the
      Epoch's leaves against the root, the Log's signature under the keys valid at its height — before
      applying its Epoch (§5, §8)
- [ ] Applies §3.1's sequence dispositions: `WIST3-E01` and nothing
      applied where the Checkpoint below an offered one is unobtainable;
      `WIST3-E03`, whatever the signature does, for a `sealed_at` not
      later than the previous Checkpoint's or off the grid; and a tree
      size below the previous Checkpoint's judged under the key set valid
      at the previous height — `WIST3-E02` only where the signature
      verifies under it and the root is not that tree's root at the
      smaller size, `WIST3-E03` otherwise, and `WIST3-E02` for any
      Checkpoint failing several rules where that form applies
- [ ] When verifying an Inclusion Proof, derives sibling sides from
      `index` and `tree_size` rather than trusting side labels in the
      proof, and rejects a shape-mismatched `path`, an `index` out of
      range, or a proof `tree_size` that disagrees with the Checkpoint's
      (§4)
- [ ] Adopts as head only a Checkpoint carrying the Witness quorum in
      force, counted over a roster it configured out-of-band, and records
      an acceptance under quorum 0 as unwitnessed (§5)
- [ ] Rejects Checkpoints older than the highest already verified, before
      fetching tiles or bundles against them (§5, §8)
- [ ] Warns when the newest Checkpoint's `sealed_at` lags the current time
      by more than three sealing cadences (§5, §8)
- [ ] Verifies manifest hashes/sizes before using a Snapshot, checks the
      manifest against the `/snapshots/index.json` entry that named it and
      the state file's `tree_size` against the manifest's (`WIST3-E04`),
      and binds `tree_size` and `root_hash` to the
      Checkpoint the manifest's `epoch_number` selects, re-fetching a file
      at that path that states another `epoch_number` (`WIST3-E03`) rather
      than reading it as divergence (§8)
- [ ] Verifies every Payload against its Item's commitment and `bytes`
      before materializing its content, and never lets a missing Payload
      stop tree verification (§6.1, §8)
- [ ] Judges every `publisher_catalog` and `publisher_item` Entry once,
      at its Epoch, by C1–C4 and I1–I7, ignores one that fails, and
      applies the valid ones to the latest Catalogs, records and removal
      states, removing records at a base and by narrowing (§3.3, §7,
      WIST-1 §5.2)
- [ ] Implements all six Error Registry behaviors, including evidence
      preservation on divergence (§9)
- [ ] Enforces the format sizes and the transport bound while reading
      (§6, §10)
- [ ] Excludes removed and withdrawn content from every materialization it
      produces, and removes withdrawn content from a local index it has
      already built (§6.2, §7)
- [ ] Obtains the Anchor out-of-band, rejects one that fails its schema
      before verifying its signature (`WIST3-E03`), and resolves signing
      keys by height: key acts under the keys valid at the previous height,
      every other act and the Checkpoint under those valid at the
      Epoch's own; ignores key-act failures (`WIST4-E04`) and judges a
      Checkpoint at or below its head under the keys valid at that
      Checkpoint's height (§3.4, §5)
- [ ] Rejects Epochs off the `sealed_at` grid, carrying an unknown Entry
      type, out of canonical Entry order, with two Catalogs of one
      Publisher and Collection, sealing a Label ID a second time, over the
      per-domain Entry capacity counted per
      Registrable Domain under the snapshot in force, obtained and
      verified by its identifier, over the per-Labeler cap, or carrying
      an Entry over 65 535 octets (§3.1–§3.3, §6, WIST-4 §3.1)
- [ ] Authenticates a state file's `aggregator_key` tuples from the
      Anchor's genesis key before using them, and verifies the index,
      manifest and state file signatures under the keys valid at the
      Checkpoint it adopts, persisting nothing from the Snapshot before
      they verify (`WIST3-E04`; §3.4, §7, §8)
- [ ] On cold start from a Snapshot, loads the state artifact and
      validates subsequent Entries against it; on a sharded Snapshot,
      reads each held shard's six tier files under `shard-<i>/`,
      verifies each held shard's digest and treats coverage as partial
      (§7, §8)
- [ ] On accepting a successor Anchor, verifies the predecessor chain to
      its declared final Epoch and carries state forward (§3.4)
- [ ] When following more than one Log, deduplicates by Catalog ID, Item
      ID and Label ID, takes one state per Publisher and URL by §7's rule
      for several Logs, keeps each Log's other derived state to that Log,
      and treats coverage as partial (§7, §8)

## Appendix A. Test Vectors

The families below live under `vectors/wist3/`, beside
`vectors/multilog/catalog-order.json`; `tools/VERIFICATION.md` names the
generator and the verifier of each. Full files:
[`vectors/wist3/epoch.json`](../vectors/wist3/epoch.json),
[`vectors/wist3/inclusion-proof.json`](../vectors/wist3/inclusion-proof.json),
[`vectors/wist3/empty-epoch.json`](../vectors/wist3/empty-epoch.json),
[`vectors/wist3/aggregator-keys.json`](../vectors/wist3/aggregator-keys.json),
[`vectors/wist3/snapshot-keys.json`](../vectors/wist3/snapshot-keys.json),
[`vectors/wist3/checkpoints.json`](../vectors/wist3/checkpoints.json),
[`vectors/wist3/tile-bounds.json`](../vectors/wist3/tile-bounds.json),
[`vectors/wist3/timestamps.json`](../vectors/wist3/timestamps.json),
[`vectors/wist3/catalog-sealing.json`](../vectors/wist3/catalog-sealing.json),
[`vectors/wist3/catalog-waiting.json`](../vectors/wist3/catalog-waiting.json),
[`vectors/wist3/record-materialization.json`](../vectors/wist3/record-materialization.json),
[`vectors/wist3/materialization-preference.json`](../vectors/wist3/materialization-preference.json),
[`vectors/wist3/snapshot-records.json`](../vectors/wist3/snapshot-records.json),
[`vectors/wist3/snapshot-index.json`](../vectors/wist3/snapshot-index.json),
[`vectors/wist3/label-tables.json`](../vectors/wist3/label-tables.json).

Epoch 0 of the example Log contains four Entries, at leaf indexes 0
through 3 of a tree of size 4, in §3.3's canonical order. No Entry's
position is chosen.

**Leaf hashes (hex):**

```
leaf0 = 77aa29dd6e34f9be0dbd303285c46e63477c0b9ebd30f6578d5af89be7826596
leaf1 = 9e6b6c5fe07259c59b5057294a78e29b8ad60f62a173fddb90105791d5cc33c0
leaf2 = 18110597f7205da0830c9f065a72d2c7c4b8f7f50d4e25f12bb554c2f9804a0f
leaf3 = e7b13d6153ba83d2b02162042f72b1d88168b8ff5d7a1d2a1de211278f09f0ea
```

**Interior nodes:**

```
n01 = node(leaf0, leaf1) = b4a43a721bbc1e33b1ff9b0302a32471862d656535ffbb80a3bbb75bd0756e6b
n23 = node(leaf2, leaf3) = 3c88793e6789d9648816263022fa0c0d134b109f9123d0d979586e2244b987fa
```

**Root hash of the tree at size 4**, as `root_hash` carries it
(§3.1) and as the Checkpoint's third line carries it (§5):

```
sha256:3f973034d26336bc62b7b4c203ad53ff31d919ef3f50f45e75922ca1bc895d8b
P5cwNNJjNrxit7TCA61T/zHZGe8/UPRedZIsobyJXYs=
```

**Inclusion proof for leaf 0** — `index 0, tree_size 4 → siblings
leaf1 then n23, both right-hand` (derived, not carried in the proof):

```
h = leaf0
h = node(h, leaf1)   → b4a43a72...  (= n01)   # fn=0 < sn=3: sibling on the right
h = node(h, n23)     → 3f973034...  (= root)  # fn=0 < sn=1: sibling on the right  ✓
```

No Payload contributes to the hashes above: every figure here is
computed over Entries, which carry commitments alone, so withdrawing a
Payload leaves the leaves, the root, the Checkpoint and this proof
untouched.

This worked example only exercises `index` 0, which — being a uniform
left-child at every level — cannot by itself distinguish a correct
verifier from one that only handles the uniform-left/uniform-right cases.
`tools/validate_examples.py`'s `merkle-exhaustive` check is the actual
correctness evidence: it verifies every `index` for every tree size 1..64
against a freshly generated audit path.

The vector also fixes the Log's static surface for this tree (§6): the
level-0 partial tile `/tile/0/000.p/4`, the 128 octets `leaf0 || leaf1
|| leaf2 || leaf3`; the entry bundle `/tile/entries/000.p/4`, the four
Entries' JCS serializations each prefixed by its big-endian uint16
length; and the Consistency Proof from size 0 to size 4, which is empty
(§4). Epoch 1 is empty: Checkpoint 1 restates size 4 and the root above
one cadence later, and the Consistency Proof from 4 to 4 is the
equality of the two roots
([`vectors/wist3/empty-epoch.json`](../vectors/wist3/empty-epoch.json)).
The empty tree — the Log before Epoch 0 — has size 0 and the root §4
gives.

The corresponding Checkpoint is
[`examples/checkpoint.txt`](../examples/checkpoint.txt): the five-line
note of §5 — the `log_id` of
[`examples/log-anchor.json`](../examples/log-anchor.json), `4`, the
base64 root above, `epoch_number 0` and `sealed_at
2026-08-02T13:00:00Z` — followed by the Log's signature line under the
example Aggregator key in the signer form §3.4 fixes. The example
manifest ([`examples/snapshot-manifest.json`](../examples/snapshot-manifest.json))
uses synthetic file hashes — the SHA-256 of the literal strings
`tier0-placeholder` / `tier1-placeholder` — so the vector is verifiable
without shipping binary artifacts. Its `epoch_number` is 0, its
`tree_size` 4 and its `root_hash` the root above.

Its `content_digest` is computed over the two materialized records in
[`vectors/wist3/snapshot-records.json`](../vectors/wist3/snapshot-records.json),
which publishes their content tuples — `url`, `publisher`, `item_id`,
`observed_at` and `attested_at` — so that §7's formula is reproducible
from the file: one record of `example.com`, whose Item is
[`examples/item.json`](../examples/item.json) and whose Payload is
[`examples/payload.json`](../examples/payload.json), and one of a second
domain, so that the ordering rule is exercised. Neither Item is an Entry
of the example Epoch; the vector demonstrates the content tuple, not a
materialization of Epoch 0. Its `links` member is the link graph §7
derives from the first record's Payload. The example state file
([`examples/snapshot-state.json`](../examples/snapshot-state.json))
carries, beside the genesis key's `aggregator_key` tuple, the tuples
§7 keeps for `example.com`'s `default` Collection: its `collection`
tuple, whose Envelope is
[`examples/catalog.json`](../examples/catalog.json), the `record` tuple
of its Item [`examples/item.json`](../examples/item.json), and the
`removal` tuple of a URL it removed.
[`examples/snapshot-index.json`](../examples/snapshot-index.json) is the
corresponding discovery index, carrying the same `snapshot_date`,
`tree_size` and `content_digest` the manifest declares. The vector's
`sharded` member splits the same records into two shards by §7's domain
rule and publishes the per-shard digests, the `shard-<i>/` file paths and
the shard each Label, labeler and dispute row is filed under.
[`vectors/wist3/snapshot-index.json`](../vectors/wist3/snapshot-index.json)
exercises §6's index rules: an index naming two Snapshots of one date,
higher Epoch first, each under its own directory; an entry whose manifest
states another `tree_size` or `content_digest` (`WIST3-E04`, and the
index is re-fetched); and an index out of order.

[`vectors/wist3/checkpoints.json`](../vectors/wist3/checkpoints.json)
extends that tree with Epoch 2 and judges Checkpoints case by case; each
list carries its own candidates, including ones that contradict the
Epochs above them. `note_form_cases` covers §5's parse rules: the
five-line text, a root hash line decoding to 31 or 33 octets and two
non-canonical encodings of 32, a final signature line without its
newline, a key name carrying `+`, one carrying U+00A0 and an empty one,
and a 16-line note
accepted beside a 17-line note rejected. `sequence_cases` covers §3.1's failures at a
verified head — Checkpoint N+2 offered while N+1 is unobtainable
(`WIST3-E01`, the offered note still parsing and verifying), a
`sealed_at` equal to, earlier than, or off the grid of the previous
Checkpoint's (`WIST3-E03`, with a signature-failing twin), and a tree
size below the previous Checkpoint's: `WIST3-E02` where its root is not
that tree's root at the smaller size and its signature verifies, the
evidence being both Checkpoints and the larger tree's leaf hashes, and
`WIST3-E03` where its root is that prefix root or its signature fails.
One case breaks two rules at once — off the grid and a smaller tree
under a non-prefix root — and is `WIST3-E02`. `cold_start_cases` covers §8 steps 4–5: a state
file's `tree_size` against the manifest's (`WIST3-E04`), a manifest
naming an empty Epoch that restates the previous tree size and root
(accepted, that Epoch becoming the verified head), a `tree_size` or
`root_hash` the Checkpoint contradicts (`WIST3-E02`), and a file at the
manifest's path stating another `epoch_number` (`WIST3-E03`, never
divergence). `consistency_cases`, `rollback_cases`,
`equivocation_cases`, `archive_cases`, `quorum_cases` and
`size_zero_cases` carry the §§4–6 rules named above.

[`vectors/wist3/tile-bounds.json`](../vectors/wist3/tile-bounds.json)
carries §6's tile and entry-bundle octet bounds and §3.3's per-Entry
bound, and beside them the forms §6 excludes, all `WIST3-E03`:
`tile_form_cases` (empty, a length that is not a multiple of 32, a
full-tile path holding 255 hashes, `.p/44` holding 43, and the widths
`.p/0` and `.p/256` that lie outside 1 through 255),
`bundle_form_cases` (a length prefix and leaf data cut short, an octet
after the last Entry, a full path holding 257 Entries, `.p/44` holding
43) and `epoch_range_cases` (Entries short of, and reaching past, the
leaf range `size(N-1)`
through `size(N) - 1`). Each of those families also carries the form
that admits recomputation, which is what a Checkpoint's root then
decides (§4).

[`vectors/wist3/catalog-sealing.json`](../vectors/wist3/catalog-sealing.json)
replays histories of Epochs carrying signed Declarations,
`payload_withdrawal` Registry Updates and `publisher_catalog` and
`publisher_item` Entries under §3.3: each Catalog judged by C1 to C4 and
each Item by I1 to I7 at its Epoch's `sealed_at` under that Epoch's
parameter map, with its disposition and code; an Epoch rejected for two
Catalogs of one Publisher and Collection; records removed by narrowing,
by a base and by an Item of kind `removed`; the base at and beyond
`removal_retention_days`; C4 under the largest `catalog_refresh_seconds`
and an amendment above it ignored; I7 for a withdrawn Item and for a
withdrawal that breaks its contract; an Item sealed again after
narrowing; the latest Catalogs, records and removal states after every
Epoch; and the Aggregator's Payload duties of §6.1, a superseded Payload
keeping only the window of the Epochs that sealed its Item.
[`vectors/multilog/catalog-order.json`](../vectors/multilog/catalog-order.json)
carries §7's rule for several Logs: the Catalog order, the state each Log
holds for one URL, the state a Consumer of all of them takes, two states
proved against one Catalog, and the removal states a Snapshot carries.

[`vectors/wist3/catalog-waiting.json`](../vectors/wist3/catalog-waiting.json)
feeds an Aggregator pulls and Epochs and fixes §3.3's waiting: the last
accepted Catalog, what waits and what leaves, places and their order
across the Publishers of one Registrable Domain, eligibility with each
deferral, the inclusion ceiling, the hold of a Declaration that reduces
authority, the capacity order, two Collections listing one URL, and a
base against the floor read at a pull (§7).

[`vectors/wist3/record-materialization.json`](../vectors/wist3/record-materialization.json)
gives, per case, the record events of one Log in Log order — an Item of
kind `page` becoming a record, an Item of kind `removed`, narrowing, a
base and a withdrawal, one of them sealed in the Epoch of the Item it
names — and the records, removal states and materialized records after
each Epoch; and a Snapshot taken between two Epochs, from whose `record`
tuples a resumed Consumer reaches the materialized records a replaying
one reaches, an unmaterialized record that returns when the preferred
one leaves after the Snapshot included.
[`vectors/wist3/materialization-preference.json`](../vectors/wist3/materialization-preference.json)
fixes §7's one-URL rule from a host, whether the host's own first
Declaration Entry is sealed, and the Publishers holding a record of one
of its URLs, each marked as named by a withdrawal or not: self-declaration, a host
self-declared whose own Publisher holds no record, the nearest ancestor,
an ancestor over a non-ancestor, non-ancestors in octet order, a
withdrawn record that the rule would otherwise prefer and a
label-boundary case.

[`vectors/wist3/label-tables.json`](../vectors/wist3/label-tables.json)
carries §7's labeler table from sealed `label` Entries and §3.2's
per-Labeler cap beside the per-domain capacity, `publisher_catalog` and
`publisher_item` Entries counting toward the capacity and not toward the
cap. [`vectors/wist3/timestamps.json`](../vectors/wist3/timestamps.json)
carries §3.1's whole-second profile, Snapshot tuple fields included.

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- [RFC 4648] The Base16, Base32, and Base64 Data Encodings — the
  Checkpoint root hash line (§5)
- [RFC 6962] Certificate Transparency — Merkle hashing discipline,
  checkpoint/equivocation model
- [RFC 8785] JSON Canonicalization Scheme (JCS)
- [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) Certificate
  Transparency Version 2.0 — consistency proof verification (§4)
- [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html) SCITT
  architecture — vocabulary mapping (§2)
- [signed-note](https://c2sp.org/signed-note@v1.0.0) ·
  [tlog-checkpoint](https://c2sp.org/tlog-checkpoint@v1.0.0) ·
  [tlog-cosignature](https://c2sp.org/tlog-cosignature) ·
  [tlog-witness](https://c2sp.org/tlog-witness) ·
  [tlog-tiles](https://c2sp.org/tlog-tiles) — the C2SP Checkpoint,
  signature, Cosignature, Witness and tiled-log formats (§3.3, §3.4,
  §5, §6)
- WIST-1: Item Format & Identity · WIST-2: Site Publication ·
  WIST-4: Governance & Parameters · WIST-5: Emissions
