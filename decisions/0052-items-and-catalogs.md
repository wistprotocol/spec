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
a Delta carries them. It has no `change_type`, no `prev`, no
`wist_version` and no signature; the Catalog that lists it carries the
version and the signature.

An Item is an object of kind `page` or of kind `removed`, with exactly
the members of its kind. An object that carries a member `removed` is
read as of kind `removed`.

| Kind | Members |
|---|---|
| `page` | `publisher`, `url`, `observed_at`, `payload` and `meta`, in the forms WIST-1 §3.8, §3.2, §3.4, §3.6 and §3.7 give a Delta's |
| `removed` | `publisher`, `url` and `observed_at` in the same forms, and `removed`, the value `true` |

| Value | Definition |
|---|---|
| Item ID | `"sha256:" + hex(SHA-256(JCS(item)))` |
| Key | `SHA-256(JCS(["page", url]))`, over the string `url` as the Item spells it, for both kinds |
| Leaf | `SHA-256(0x00 ‖ key ‖ SHA-256(JCS(item)))` |
| Root | The Merkle Tree Hash of WIST-3 §4 over the leaves in ascending octet order of key, a node being `SHA-256(0x01 ‖ left ‖ right)`; `SHA-256("")` for an empty Collection |

The Payload of an Item of kind `page` is the Payload of WIST-1 §3.6
and WIST-3 §6.1, named by the Item ID where a Delta's is named by the
Delta ID. Every new Item takes a fresh salt. An Item whose content has
not changed is kept as it is.

An Item is judged with the Catalog that lists it, under the
Declaration in force at that judgment (ADR-0051). An Item that fails a
condition below is refused alone; it stays in the list, its leaf stays
in the root, and the other Items proceed.

| Code | Condition |
|---|---|
| `WIST1-E14` | A member set other than its kind's, a member of another type or form, or a `removed` that is not `true` |
| `WIST1-E03` | A `url` that is not byte-identical to its own Normalized URL, whose host lies outside the authority of the Catalog's Publisher, or that the Scope of the Catalog's Collection does not cover |
| `WIST1-E11` | `JCS(url)` above `url_cap_bytes` |
| `WIST1-E04` | `payload.bytes` above the derived cap of WIST-1 §3.6 |
| `WIST1-E06` | An `observed_at` later than the Catalog's `generated_at`, compared as exact instants |
| `WIST2-E03` | A `publisher` other than the Catalog's |

The `WIST1-E14` conditions are checked first, with the exceptions
WIST-1 §7 gives a Delta's `url` and `payload.bytes`; among the other
conditions WIST-1 §7 leaves the choice of diagnostic. `url_cap_bytes`
and the three caps behind the derived one are read at the instant
WIST-1 §3.6's size-cap parameter time gives a Delta.

### Removal

A URL the Publisher no longer publishes stays in the list as an Item of
kind `removed`, under the page's key, carrying the instant of removal
and no `payload`. It is sealed and proved as any Item is. The Publisher
keeps it listed for `removal_retention_days`, 180 days, and does not
take it out earlier, whatever Logs have sealed it: a Publisher does not
know every Log that pulls its files.

### From publications to Items

The part of a Publisher that signs derives the list of a Catalog from
the list it serves, from the publications a stream's application
leaves (ADR-0050) and from the Catalog's `generated_at`. Those
publications lie inside the Collection's Scope, since a stream with
one outside it is refused. The first condition below that an Item or
a publication meets decides. A new Item's `publisher` is the
Publisher's `domain`, and the Payload of a new Item of kind `page`
carries the `wist_version` of the Catalog. A served Item whose
`publisher` is not the Publisher's `domain` is read as an Item of kind
`page` whose Payload is not held, so a new Item takes its place.

| Condition | In the new list |
|---|---|
| A served Item whose URL the Collection's Scope does not cover under the Publisher's current Declaration | Nothing. Narrowing (ADR-0051) removes its record |
| A publication whose URL has a served Item of kind `page` with the publication's `lang` as `meta.lang` and a Payload, held by the part that signs and passing WIST-1 §7's Payload checks against the Item's `payload`, whose `JCS(content)` equals the publication's | The served Item and its Payload, unchanged, with its salt and its `observed_at` |
| Any other publication | A new Item of kind `page`: `url`, the publication's URL; `observed_at`, its `modified`; `meta`, its `lang` alone; `payload`, the commitment to its `content` under a fresh salt |
| A served Item of kind `page` whose URL has no publication | An Item of kind `removed` whose `observed_at` is the Catalog's `generated_at` |
| A served Item of kind `removed` whose URL has no publication | The served Item, unchanged, while `generated_at` is earlier than its `observed_at` plus `removal_retention_days` of 86 400 seconds each; nothing from that instant on |

A Publisher signs no Catalog that lists an Item whose `observed_at` is
later than the Catalog's `generated_at`: the part that signs refuses
with `item-instant` and publishes nothing. WIST-5 assigns the code.

### Catalogs

A **Catalog** is an Envelope (WIST-1 §4), `{"catalog": …, "sig": …}`,
stating the complete Item set of one Collection (ADR-0051) at one
instant. `sig` has the form of a Delta Envelope's. The inner object
carries exactly these members.

| Member | Form |
|---|---|
| `wist_version` | The version spelling of WIST-1 §3.1 |
| `publisher` | The Publisher's `domain`, a Canonical Host (WIST-1 §3.8) |
| `collection` | A Collection name in the form of ADR-0051 |
| `generated_at` | An instant in the whole-second profile of WIST-3 §3.1 |
| `size` | The number of Items the list holds, an integer from 0 to `catalog_items_max` |
| `root` | `"sha256:"` followed by 64 lowercase hexadecimal digits: the root of the list |
| `tree` | The same form: the SHA-256 of the octets of the root tree file |

The Catalog ID is `"sha256:" + hex(SHA-256(JCS(catalog)))`.

A Collection's Catalogs are ordered by `generated_at`, and a Catalog
replaces another only with a later instant. `generated_at` is bound
above by the clock rule WIST-1 §3.4 gives `observed_at`, with the
clock and the parameter time that section selects for a Delta at the
same stage, so no signer places a Catalog further ahead than
`clock_skew_seconds`. The binding check of WIST-1 §5.1 reads
`generated_at` where it reads a Delta's `observed_at`, over the
candidates ADR-0051 collects for the Collection the Catalog names,
from the Declaration history of exactly `publisher` (WIST-1 §3.8): a
Catalog judged under a Declaration of another `domain` has no
candidate and is `WIST1-E02`.
Every Item's `observed_at` is at or before `generated_at`.

| Code | Condition |
|---|---|
| `WIST1-E05` | An Envelope that is not valid JCS input |
| `WIST1-E14` | A member set other than the Envelope's or the inner object's, a member of another type or form, or a `size` that is not a nonnegative integer of WIST-1 §4's safe range |
| `WIST1-E15` | A major version the validator does not implement |
| `WIST1-E04` | A `size` above `catalog_items_max` |
| `WIST2-E04` | At a pull, a `publisher` or a `collection` other than the one the Catalog was fetched for |
| `WIST1-E03` | A `collection` the Declaration in force does not name |
| `WIST1-E02`, `WIST1-E01` | The binding check, as WIST-1 §5.1 distinguishes them |
| `WIST1-E06` | A `generated_at` more than `clock_skew_seconds` beyond the clock |
| `WIST2-E05` | At a pull, a `generated_at` at or before that of the Collection's last accepted Catalog, in a Catalog of another Catalog ID |

`WIST1-E05` and then the `WIST1-E14` conditions are checked first;
among the others WIST-1 §7 leaves the choice of diagnostic. Whether
`size` is an integer depends on the number's value and not on its
spelling, as WIST-1 §7 has it for `payload.bytes`. A fetched
Catalog whose Catalog ID equals that of the last accepted one is an
idempotent re-serve: it replaces nothing and is no regression.

A Publisher signs a Catalog with a `generated_at` later than that of
the Catalog it serves for the Collection: the later of its clock, cut
to the whole second, and the served instant plus one second. When
that instant is more than `clock_skew_seconds` beyond its clock, cut
to the whole second, the part that signs refuses with
`catalog-instant` and signs nothing, since its clock is wrong or no
Aggregator accepted the served Catalog. WIST-5 assigns the code.

### Files

A Publisher serves, per Collection, its Catalog at a fixed path, the
Item list as a tree of files each named by its hash, and the Payloads.
The implicit `default` is served under the name `default`.

```
/.well-known/wist/collections/<name>/catalog.json
/.well-known/wist/collections/<name>/tree/<hex>
/.well-known/wist/collections/<name>/payloads/<hex>.json
```

`<hex>` is 64 lowercase hexadecimal digits: for a tree file the
SHA-256 of its octets, for a Payload the digits of its Item ID, which
follow `sha256:`.

New files are written before the Catalog that names them is replaced.
Replaced files stay for a stated interval that covers a pull in
progress, except a file the Publisher must stop serving.

A tree file is the JCS serialization of one object with exactly one
member, and is of the kind that member names.

| Kind | Member |
|---|---|
| Bucket | `items`, an array of Items in strictly ascending octet order of key. Each element is an object with a string member `url` |
| Inner file | `children`, an array of 1 to 16 objects with exactly the members `prefix`, `count` and `file` |

Every tree file has a prefix, a string of lowercase hexadecimal
digits: the root tree file has the empty one, and a child has the
`prefix` of the entry that names it. In an inner file each `prefix` is
the file's own prefix followed by one digit, and the entries are in
strictly ascending order of `prefix`; `count` is an integer of at
least 1, the number of Items the child's subtree lists; `file` is
`"sha256:"` followed by the 64 lowercase hexadecimal digits of the
SHA-256 of the child's octets. In a bucket the lowercase hexadecimal
spelling of every Item's key begins with the bucket's prefix. A bucket
lists as many Items as the entry that names it counts, and the counts
of an inner file's entries add up to the count of the entry that names
it; the root tree file is counted by the Catalog's `size`. The root
tree file is at level 1 and a child one level below its parent; a file
at level `tree_depth_max` is a bucket.

A Publisher chooses where its tree divides. An empty Collection has
one tree file, a bucket with no Items.

| Parameter | Value |
|---|---|
| `catalog_items_max` | 16 777 216 Items in a Catalog |
| `tree_file_cap_bytes` | 65 536 octets in a tree file |
| `tree_depth_max` | 16 levels of tree files |
| `removal_retention_days` | 180 days |

None of the four is amended below 1. The first three are read at the
instant WIST-1 §3.6's size-cap parameter time gives a Delta.

An Aggregator that accepted a Catalog's fields, binding, clock and
order walks the tree from `tree`, the children of an inner file in
their order, and fetches each file it does not hold under that hash,
within the ingest budget of WIST-2 §5. The Items of the buckets in the
order of the walk are the list. The Catalog is refused whole with
`WIST2-E07`, a new code of WIST-2, and nothing of it is sealed, when:

- a tree file is unavailable, holds more than `tree_file_cap_bytes`
  octets, or has another SHA-256 than the hash that names it;
- a tree file differs from the form above, its octets not being the
  JCS serialization of the object they parse to included;
- a prefix, a count, an order or a level differs from the rules above;
- the list holds another number of Items than `size`, or its root is
  not `root`.

The refusal is reported at the status endpoint and the Catalog is
fetched again at the next pull. The bounds hold the walk to the root
tree file and, for each Item counted, at most `tree_depth_max` − 1
files below it.

### Proofs

An Inclusion Proof of an Item is the object of WIST-3 §4,
`{"index": …, "tree_size": …, "path": […]}`: `index` is the Item's
position in the list, from 0; `tree_size` is the Catalog's `size`;
`path` holds the sibling hashes from the leaf up, each 64 lowercase
hexadecimal digits. `index` and `tree_size` are nonnegative integers
of WIST-1 §4's safe range, by value and not by spelling. A proof of
another form is `WIST1-E14`.

A proof is verified against one Catalog as WIST-3 §4 verifies a proof
against a Checkpoint, from the Leaf above. It fails with `WIST1-E17`,
a new code of WIST-1 for an Item not proved against the Catalog its
Entry names, when `tree_size` is not the Catalog's `size`,
when `index` is not below `tree_size`, when the walk lacks a `path`
element or leaves one unread, or when the hash it ends with is not the
Catalog's `root`.

### Sealing

| Entry type | Body |
|---|---|
| `publisher_catalog` | The Catalog Envelope |
| `publisher_item` | An object with exactly the members `item`, the Item; `collection`, its Collection's name; `catalog`, the Catalog ID of the Catalog it is proved against; and `proof`, its Inclusion Proof |

A `publisher_item` body of another member set, or with a member of
another type or form, is `WIST1-E14`. A `collection` that is not the
named Catalog's `collection` is `WIST1-E17`. An Item whose `publisher`
is not the named Catalog's is `WIST2-E03`, as the Item conditions have
it. A body is judged by its form, by the Item conditions, by its
`collection` and by its proof, verified against the named Catalog. The
`WIST1-E14` conditions are checked first; among the others WIST-1 §7
leaves the choice of diagnostic.

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

- The order of two Catalogs of equal instant that two Logs sealed.
- The Epoch from which a Catalog that replaces an unsealed one counts
  toward the inclusion ceiling (WIST-4 §5), and whether an Item waiting
  under a sealed Catalog is sealed once a later Catalog is accepted.
- The disposition of a Catalog of unchanged root sealed inside the
  refresh interval.
- The earliest instant a Collection accepts, which a Consumer resumed
  from a Snapshot must derive from sealed Entries alone.
- The interval during which a Collection's records are absent under a
  base Catalog.
- The Epoch from which an Item held by a recovery window counts toward
  the inclusion ceiling.
- The interval for which a replaced tree file or Payload stays served.
- The error codes of the dispositions of Sealing, Recovery and the
  base Catalog.

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

The vectors of Items, Removal, From publications to Items, Catalogs,
Files and Proofs are `vectors/wist1/item-fields.json`,
`item-roots.json` and `catalog-fields.json` and
`vectors/wist2/catalog-order.json`, `catalog-tree.json`,
`catalog-items.json` and `item-lists.json`, generated by
`tools/gen_catalog_vectors.py` from the reference in `tools/items.py`,
`tools/catalogs.py` and `tools/tree_files.py`, and recomputed by
`tools/verify_catalog_vectors.py`, which was written from this text
without the other four. `catalog-items.json` carries the publications
of ADR-0051's Verification as Items of a signed Catalog.
