# ADR-0052: Publications are Items, and one signed Catalog per Collection commits to all of them

**Status:** draft · **Date:** 2026-09-27

## Context

A Publisher signs one Delta per statement about one URL, chains a URL's
Deltas by `prev`, and lists Delta IDs in a signed Feed with sealed Pages
(WIST-1 §3, WIST-2 §3). The contract asks four things of every
Publisher.

- **State.** Signing a URL's next Delta takes the ID of its last one,
  so a Publisher keeps a chain tip per URL.
- **Retention.** "A Publisher MUST keep every Delta it has ever
  published retrievable at its content-addressed path for as long as
  the domain participates" (WIST-1 §3.5). At one statement per URL per
  week, a site of 10 000 URLs serves 1 581 572 files after three years.
- **One signature per statement.** A change to a thousand pages is a
  thousand signatures and one more for the Feed, so the key stays where
  the publishing runs.
- **Freshness per URL.** An unchanged page is attested by an `attest`
  of its own. Under weekly attestation a page that never changes adds
  26 208 octets to the Log every year, and where 2 % of pages change a
  day, seven statements in eight are attestations.

Removal is a statement too: a Publisher that fails to sign a `delete`
leaves the record in every index.

Systems that distribute a set of files from plain servers sign one
statement over the whole set. The Update Framework signs target
metadata that lists every file with its hash. An AT Protocol repository
signs a commit over the root of a tree of records. In both, a reader
verifies one signature and then proves membership.

Sizes below are octets of canonical serializations in a model with a
URL of 63 octets.

| Object sealed | Octets |
|---|---|
| Delta, `update` / `attest` / `delete` | 641 / 504 / 504 |
| Catalog | 510 |
| Item with its proof, Collection of 100 / 10 000 / 1 000 000 Items | 958 / 1 431 / 1 837 |

## Decision

### Items

An **Item** is a Publisher's current statement for one URL: its
`publisher`, `url`, `observed_at`, `payload` commitment and `meta`, as
a Delta carries them. It has no `change_type`, no `prev` and no
signature.

| Value | Definition |
|---|---|
| Item ID | `"sha256:" + hex(SHA-256(JCS(item)))` |
| Key | `SHA-256(JCS(["page", url]))` |
| Leaf | `SHA-256(0x00 ‖ key ‖ SHA-256(JCS(item)))` |
| Root | The Merkle Tree Hash of WIST-3 §4 over the leaves in ascending key order; `SHA-256("")` for an empty Collection |

Every new Item takes a fresh salt, and its Payload is served under the
Item ID, as a Delta's is under the Delta ID. An Item whose content has
not changed is kept as it is.

### Removal

A URL the Publisher no longer publishes stays in the list as an Item of
kind `removed`, under the page's key, carrying the instant of removal
and no `payload`. It is sealed and proved as any Item is. The Publisher
keeps it listed for `removal_retention_days`.

### Catalogs

A **Catalog** is an Envelope (WIST-1 §4) stating the complete Item set
of one Collection (ADR-0051) at one instant: `publisher`, `collection`,
`generated_at`, `size`, `root`, and `tree`, the hash of the file from
which the list is read.

A Collection's Catalogs are ordered by `generated_at`, in the
whole-second profile of WIST-3 §3.1, and a Catalog replaces another
only with a later instant. `generated_at` is bound above by the clock
rule WIST-1 §3.4 gives `observed_at`, so no signer places a Catalog
further ahead than `clock_skew_seconds`. The signing binding's window
contains `generated_at`. Every Item's `observed_at` is at or before it.

### Files

A Publisher serves, per Collection, its Catalog at a fixed path, the
Item list as a tree of files each named by its hash, and the Payloads.
A tree file lists Items or lists child files by key prefix. New files
are written before the Catalog that names them is replaced. Replaced
files stay for a stated interval that covers a pull in progress, except
a file the Publisher must stop serving.

### Sealing

| Entry type | Body |
|---|---|
| `publisher_catalog` | The Catalog Envelope |
| `publisher_item` | The Item, its Collection, the ID of the Catalog it is proved against, and an Inclusion Proof in the form of WIST-3 §4 |

An Aggregator that pulls a Catalog rebuilds the Item list, recomputes
the root and rejects the Catalog whole when the two differ. It seals
the Catalog and an Entry for each Item that is new, changed or
`removed` against the records it holds. An Item that fails a check of
its own, or whose Payload cannot be verified, is not sealed, and the
others are.

- A Catalog's validity is judged at the Epoch that seals it and not
  again.
- An Item Entry names the latest Catalog sealed for its Collection, and
  is sealed only while the key that signed that Catalog is authorized
  for the Collection at the Item's own Epoch.
- An Epoch carries at most one Catalog of a Collection.
- A Catalog whose root equals that of the last one sealed is sealed
  only when `catalog_refresh_seconds` separate their instants, or when
  the key of the last one is no longer authorized.
- Catalog and Item Entries count toward the per-domain Epoch capacity
  (WIST-3 §3.2).
- An Item replaces its URL's record; an Item of kind `removed` removes
  it. An Item equal to the record's current one is not sealed.

A Consumer ignores a sealed Catalog that fails a check at its Epoch and
every Entry that names it, ignores an Item Entry whose proof fails or
that names another Catalog than the latest sealed, and rejects an Epoch
that carries two Catalogs of one Collection or exceeds the capacity.

### Recovery

From the Epoch that opens a recovery window (WIST-1 §5.2), no Catalog
or Item of the domain is sealed. Catalogs are queued under the union of
the two frozen sources, Collections and Scopes included. At settlement
they are validated again, and per Collection the surviving Catalog of
latest instant is sealed with the Items that follow from it.

### What a record carries

A record carries the instant of the Catalog its Item was proved
against. A Collection carries the instant of its latest sealed Catalog,
which says that the Publisher stated the Collection then and says
nothing of any one record.

A party that holds every Item of a Collection MAY recompute the root
and compare it with the Catalog's. The comparison changes no sealed
value, no state tuple and no digest.

### An Aggregator that was away

An Aggregator that has sealed no Catalog of a Collection for longer
than `removal_retention_days` may have missed an Item of kind
`removed`. It seals its next Catalog as a base: Consumers drop the
Collection's records at that Entry, and the Items sealed after it
restore them.

### What leaves the suite

The Delta Envelope, `change_type`, `prev`, chain tips and forks,
`attest` and `delete`, the Feed of Deltas, the duty to keep every Delta
retrievable, and the resolution of an anchor across a chain (WIST-3
§6.1). Labels and disputes keep the Label Feed and its Pages (WIST-2
§3.3), and a Label's `delta` binds an Item ID.

## Taking effect

This decision takes effect with the revision of WIST-1 to WIST-4 that
states every rule above, with a rule for every open point below. The
conformance reference implements each rule, and a vector discriminates
it, before that revision is written. Until it the normative text
defines Deltas and Feeds.

## Alternatives considered

- **Keep Deltas and Feeds.** Keeps per-URL history on the Publisher's
  site, a smaller Entry per change and copying of one statement between
  Logs. Keeps the four costs of the Context.
- **Removal proved by absence.** Needs no marker, but the proof seals
  the keys of the neighboring Items, a hash of a URL that guessing the
  URL confirms, including for an Item the Aggregator refused; and a
  Publisher can hold a removal back by listing a refused Item beside
  it.
- **Verification by recomputing the root, with no proof in the
  Entry.** Cuts a sealed Item to 443 octets. Makes every record of a
  Collection depend on every other, and delays a change that spans
  Epochs until its last Entry.
- **Completeness as protocol state.** Lets the Log say that an index
  holds exactly the signed list and gives every unchanged page a
  freshness. Needs state for Items that are sealed and not
  materialized, and one refused Item withholds the result from the
  whole Collection.
- **One Payload per commitment, shared by Items of equal content.**
  Binds the Payload to no Publisher, Collection or URL, so a withdrawal
  of one signer's Item reaches another's content.
- **A sequence number in place of the instant.** A signer can publish
  the largest number and leave none above it.
- **A withdrawal request signed by the Publisher.** Left for a
  decision of its own: a request sealed under the Aggregator's
  signature cannot be checked against the requester's key on replay,
  and its ordering against the Item it names is undefined.
- **Labels as Items.** Left for a decision of its own: a Label is
  current by its `asserted_at` (WIST-2 §3.3), and a removal leaves none
  to compare with, so two Logs that sealed different Catalogs of one
  Labeler would hold different current Labels.

## Consequences

- A Publisher signs once per update, keeps no state beyond the files
  it serves, and serves files in proportion to its publications: 14 013
  for 10 000 URLs against 1 581 572.
- A Log seals one Catalog per Collection per refresh interval where it
  sealed one `attest` per URL. The per-URL freshness of an unchanged
  page is no longer a protocol value, and a Catalog costs its Publisher
  almost nothing, so the Collection's instant does not tell one
  Publisher from another.
- A sealed Item is 1.5 to 2.9 times the octets of an `update` Delta for
  Collections of 100 to 1 000 000 Items, and each sealed Catalog adds
  510.
- A pull transfers less than today for a small change to a small site
  and more for changes scattered over a large one, since a tree file is
  fetched whole.
- A Publisher's site holds its present state. A Log that starts later
  obtains no earlier one, which changes what ADR-0003 says a late
  reader sees.
- A Log copies from another a Catalog and the Items proved against it.
  Items proved against earlier Catalogs cannot be proved again without
  the site's files, where a Delta is copied alone.
- For one record, a Consumer of several Logs takes the state proved
  against the Catalog of the later instant.
- Erasure stays as WIST-3 §6.2 has it: a `payload_withdrawal` under the
  Aggregator's signature, naming an Item ID.
- ADR-0003, ADR-0007, ADR-0015, ADR-0026, ADR-0029, ADR-0030, ADR-0031,
  ADR-0036, ADR-0041 and ADR-0044 are updated in place, and the subject
  of ADR-0027 is replaced.

## Open points

- The order of two Catalogs of equal instant that two Logs sealed, and
  the rule by which a Publisher's instants increase.
- The Epoch from which a Catalog that replaces an unsealed one counts
  toward the inclusion ceiling (WIST-4 §5), and whether an Item waiting
  under a sealed Catalog is sealed once a later Catalog is accepted.
- The disposition of a Catalog of unchanged root sealed inside the
  refresh interval.
- The earliest instant a Collection accepts, which a Consumer resumed
  from a Snapshot must derive from sealed Entries alone.
- The interval during which a Collection's records are absent under a
  base Catalog, and whether an Item of kind `removed` may leave the
  list early once every Log the Publisher notifies has sealed it.
- The Epoch from which an Item held by a recovery window counts toward
  the inclusion ceiling.
- The bounds on a tree file, on the depth of the tree and on `size`.
- The error codes of the dispositions above.

## Verification

Vectors carry: Item ID, key, leaf and root known answers, the empty
Collection among them; a Catalog's fields, order, clock bound and key
window; a Catalog whose list does not reproduce its root; inclusion
proofs at the first, the last and a lone leaf; an Item of kind
`removed` and its retention; an Item sealed after its Catalog's key was
removed; two Catalogs of one Collection in one Epoch; a Catalog of
unchanged root inside and outside the refresh interval; a recovery
window and its settlement; a base Catalog; the walk of a tree of files
and each of its bounds; the same Catalog sealed by two Logs.
