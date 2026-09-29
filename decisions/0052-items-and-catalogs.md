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

In a model with a URL of 63 octets, a sealed Delta is 641 octets of
canonical serialization as an `update` and 504 as an `attest` or a
`delete`.

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
| `WIST1-E11` | In an Item of kind `page`, `JCS(url)` above `url_cap_bytes` |
| `WIST1-E04` | `payload.bytes` above the derived cap of WIST-1 §3.6, or `JCS(item)` above 16 384 + `url_cap_bytes` octets, for either kind |
| `WIST1-E06` | An `observed_at` later than the Catalog's `generated_at`, compared as exact instants |
| `WIST2-E03` | A `publisher` other than the Catalog's |

The `WIST1-E14` conditions are checked first, with the exceptions
WIST-1 §7 gives a Delta's `url` and `payload.bytes`; among the other
conditions WIST-1 §7 leaves the choice of diagnostic. `url_cap_bytes`
and the three caps behind the derived one are read at the instant
WIST-1 §3.6's size-cap parameter time gives a Delta. `url_cap_bytes`
is amended to no value above 32 768, so the `publisher_item` Entry of
an Item within the `JCS(item)` bound, its proof included, stays below
the 65 535 octets WIST-3 §3.3 allows an Entry.

### Removal

A URL the Publisher no longer publishes stays in the list as an Item of
kind `removed`, under the page's key, carrying as `observed_at` the
`generated_at` of the first Catalog that lists it, and no `payload`.
It is sealed and proved as any Item is. The Publisher keeps it listed
for `removal_retention_days`, 180 days, and does not take it out
earlier, whatever Logs have sealed it: a Publisher does not know every
Log that pulls its files.

### From publications to Items

The part of a Publisher that signs derives the list of a Catalog from
the list it serves, from the publications a stream's application
leaves (ADR-0050), from the URLs the removals of an incremental stream
name, and from the Catalog's `generated_at`. It first takes out of the
publications those that the Scope of the served Declaration no longer
covers, as ADR-0050 has a stream's application do, so a Catalog signed
with no new stream lists their served Items as removed. The
publications then lie inside the Collection's Scope under the
Declaration the Publisher serves, and a served Item outside that Scope
has no publication: the two rows of a served Item whose URL has no
publication decide it. The first condition below that an Item, a
publication or a URL meets decides. A new Item's `publisher` is the
Publisher's `domain`, and the Payload of a new Item of kind `page`
carries the `wist_version` of the Catalog. A served Item whose
`publisher` is not the Publisher's `domain` is read as an Item of kind
`page` whose Payload is not held, so a new Item takes its place.

| Condition | In the new list |
|---|---|
| A publication whose URL has a served Item of kind `page` with the publication's `lang` as `meta.lang` and a Payload, held by the part that signs and passing WIST-1 §7's Payload checks against the Item's `payload`, whose `JCS(content)` equals the publication's | The served Item and its Payload, unchanged, with its salt and its `observed_at` |
| Any other publication | A new Item of kind `page`: `url`, the publication's URL; `observed_at`, its `modified`; `meta`, its `lang` alone; `payload`, the commitment to its `content` under a fresh salt |
| A served Item of kind `page` whose URL has no publication | An Item of kind `removed` whose `observed_at` is the Catalog's `generated_at` |
| A served Item of kind `removed` whose URL has no publication | The served Item, unchanged, while `generated_at` is earlier than its `observed_at` plus `removal_retention_days` of 86 400 seconds each; nothing from that instant on |
| A URL a removal of the stream names, with no publication and no served Item, whether or not the Collection's Scope covers it | An Item of kind `removed` whose `observed_at` is the Catalog's `generated_at` |

A Log in which the Declaration the Publisher serves is not yet in
force removes the record of a URL outside its Scope through the Item
of kind `removed`; a Log in which it is in force has removed that
record by narrowing (ADR-0051) and refuses the Item alone with
`WIST1-E03`.

The part that signs refuses, and signs no Catalog of the Collection,
a served list that holds two Items of one URL (`served-list`), a new
list that holds an Item whose `observed_at` is later than the
Catalog's `generated_at` (`item-instant`), or a new list longer than
`catalog_items_max` (`catalog-size`), with the first of the three, in
that order, that it meets. Each refusal stops the Catalog of its
Collection alone. WIST-5 assigns the codes.

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
candidate and is `WIST1-E02`. An Item's `observed_at` later than
`generated_at` is the Item condition `WIST1-E06` (Items), not a
Catalog condition.

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
| `WIST2-E05` | At a pull, a `generated_at` at or before that of the Collection's last accepted Catalog, in a Catalog that is not an idempotent re-serve |

`WIST1-E05` and then the `WIST1-E14` conditions are checked first;
among the others WIST-1 §7 leaves the choice of diagnostic. Whether
`size` is an integer depends on the number's value and not on its
spelling, as WIST-1 §7 has it for `payload.bytes`. A fetched Catalog
is read first against the Catalog conditions other than `WIST2-E05`:
one that meets one is reported with its code, replaces nothing and
retries nothing. Only one that meets none is read for the order and
for an idempotent re-serve. A fetched Catalog is an idempotent
re-serve when its Catalog ID is that of the Collection's last accepted
Catalog or of its latest Catalog (Waiting): it replaces nothing and is
no regression. From the discovery of a recovery rotation until the
settlement of its window (Recovery) the key counts as well: a fetched
Catalog is an idempotent re-serve when its Catalog ID and the public
key that signed it are those of a Catalog queued under its name or of
the Catalog that waits for its Collection, or when its Catalog ID is
the latest Catalog's.

A Publisher signs a Catalog with a `generated_at` later than that of
the Catalog it serves for the Collection: the later of its clock, cut
to the whole second, and the served instant plus one second. When
that instant is more than `clock_skew_seconds` beyond its clock, cut
to the whole second, the part that signs refuses with
`catalog-instant` and signs nothing, since its clock is wrong or no
Aggregator accepted the served Catalog. WIST-5 assigns the code.

A Catalog of each Collection the Publisher serves is due, whether or
not the list changed, once the clock of the part that signs, cut to
the whole second, is at or after the served Catalog's `generated_at`
plus `catalog_refresh_seconds`, and at any clock for a Collection
with no served Catalog; the part that signs signs every due Catalog
when it runs. A Catalog whose `generated_at` is more than
`removal_retention_days` after the one it replaces is a base in every
Log whose floor is the replaced one's instant (An Aggregator that was
away). The part that reads a stream or signs reads every parameter,
`clock_skew_seconds`, `removal_retention_days` and
`catalog_refresh_seconds` included, at its suite value (WIST-4 §5),
whatever a Log has amended, since a Publisher reads no Log's
parameters.

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

A Catalog names the tree files reached from its `tree` and the
Payloads of the Items of kind `page` of its list. New files are
written before the Catalog that names them is served. A file the
served Catalog does not name stays served for `replaced_file_seconds`,
86 400 seconds, counted on the Publisher's clock from the instant at
which the last Catalog that named it was replaced: at every instant
earlier than that one plus the interval. From that instant the
Publisher may stop serving the file, and no rule obliges it to. A file
named again inside the interval is served as a named one. A file the
Publisher must stop serving is removed at once, whether or not the
served Catalog names it. The files of a Collection that the served
Declaration stopped naming stay served for `replaced_file_seconds`
from the instant the Publisher began to serve that Declaration, and
the Publisher may stop serving them then. The value is the suite's and
no Log amends it, since a Publisher reads no Log's parameters.

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
| `catalog_refresh_seconds` | 604 800 seconds |

`catalog_items_max`, `tree_file_cap_bytes` and `tree_depth_max` are not
amended below the values above, to which a Publisher builds (Catalogs),
and are read at the instant WIST-1 §3.6's size-cap parameter time gives
a Delta. `removal_retention_days` is 180 in every Log: no Log amends it
and no parameter map carries it, as none does `replaced_file_seconds`,
so a pull and an Epoch read the same value. `catalog_refresh_seconds` is
amended to no value below 1 and none above 7 776 000, 90 days: a
Publisher that signs a Collection at least once in 90 days has its first
unchanged Catalog to pass C4 at most 15 552 000 seconds after the floor,
so it is never a base, and a base always passes C4. It is read from the
parameter map in force at the Epoch that judges the Catalog (Sealing).

An Aggregator reads at most 16 384 octets of `catalog.json`; a larger
answer is a failed fetch of the Catalog, as WIST-2 §8 has an object
above its bound, and is retried as WIST-2 §7 retries a Feed that
cannot be fetched (`WIST2-E01`). Fetching `catalog.json` counts
against the ingest budget of WIST-2 §5 as fetching a Feed page does.
The octets of `catalog.json` need only be valid JCS input
(`WIST1-E05`) and not the JCS serialization, since the Entry carries
the Envelope they parse to.

An Aggregator that accepted a Catalog's fields, binding, clock and
order walks the tree from `tree`, the children of an inner file in
their order, and fetches each file it does not hold under that hash,
within the ingest budget of WIST-2 §5. The Items of the buckets in the
order of the walk are the list. The Catalog is refused whole with
`WIST2-E07`, a new code of WIST-2, and nothing of it is sealed, when:

- the fetch of a tree file failed, or a tree file holds more than
  `tree_file_cap_bytes` octets or has another SHA-256 than the hash
  that names it;
- a tree file differs from the form above, its octets not being the
  JCS serialization of the object they parse to included;
- a prefix, a count, an order or a level differs from the rules above;
- the list holds another number of Items than `size`, or its root is
  not `root`.

The refusal is reported at the status endpoint and the Catalog is
fetched again at the next pull. A walk that the ingest budget suspends
is not refused and resumes at the next pull. The bounds hold the walk
to the root tree file and, for each Item counted, at most
`tree_depth_max` − 1 files below it. A walk that meets a file the
Publisher replaced fails that fetch, so the Catalog is refused with
`WIST2-E07`. An Aggregator keeps the tree files it fetched under their
hashes, so the walk resumes at the next pull, under the Catalog then
served, from the files held, and may discard a tree file that no last
accepted, waiting or queued Catalog of the Collection names.

A Catalog is refused whole with `WIST2-E07` as well when its list
holds no Item for the URL of a record that the Aggregator holds for
the Collection and that the Collection's Scope covers under the
Declaration the pull reads, unless the Catalog is a base against the
floor (An Aggregator that was away): no Entry could remove that
record. An Item the list holds for the URL counts whether or not it is
refused alone. The report of this refusal at the status endpoint names
the URL of every such record.

An Item of kind `page` whose Item ID a `payload_withdrawal` sealed in
the Log that meets its contract (Judgment) names (WIST-3 §6.2) is not
admitted, its Payload is not fetched, and it is reported with
`WIST2-E03`, whatever Item condition other than a `WIST1-E14` one it
meets. Any other Item of the list that meets none of the Item
conditions is **admitted** when it is of kind `removed`, when it is
the Item of its URL's record, whose Payload the pull does not check,
or when its Payload verifies. For an Item of kind `page` that is not
the record's, the Aggregator fetches the Payload, unless it holds one
under that Item ID, and verifies it, held or fetched, by WIST-1 §7's
Payload checks against the Item's `payload`, under the parameter map
WIST-1 §3.6 selects for a Delta's Payload at admission. Before sealing
an Item of kind `page`, however it was admitted, the Item of its URL's
record that waits under a base included, the Aggregator checks its
Payload under the map in force at the candidate Epoch's `sealed_at`,
at the Item's turn in that Epoch when the capacity has room for it,
and at no Epoch that defers it; a Payload the Aggregator does not hold
at the Item's turn fails the check. The Payloads named by the
withdrawals an Epoch seals are destroyed before its Items take their
turn, so an Aggregator seals no Item in the Epoch that seals the
withdrawal of its Payload; replay accepts such an Item, I7 reading the
withdrawals of earlier Epochs alone. An Item whose Payload is
unavailable or fails a check at the pull is not admitted; one whose
Payload fails at its turn takes no room, is not sealed and is no
longer admitted. Either is reported with `WIST2-E03`; the other Items
proceed.

A pull that accepts a Catalog or meets an idempotent re-serve judges
again, under the Declaration then in force, every Item of the list
that is not admitted, those refused or no longer admitted at their
turn included, and fetches again the Payload it does not hold of every
such Item that no withdrawal names. An idempotent re-serve replaces no
Catalog, fetches no tree file the Aggregator holds and gives no
waiting Item another place (Sealing). A pull that accepts no
Declaration and no Catalog and admits no Item resolves to `WIST2-E02`
(WIST-2 §4).

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

Within an Epoch, Entries are grouped in the order
`publisher_declaration`, `registry_update`, `publisher_catalog`,
`publisher_item`, `label`, `dispute`, within each group in the order
WIST-3 §3.3 gives the Entries of a type, and applied in that order,
the Catalogs and then the Items in ascending Entry index.

#### State

| State | Held per | Value |
|---|---|---|
| Latest Catalog | Publisher and Collection name | The valid `publisher_catalog` Entry applied last: its Envelope and its sealing height |
| Floor | Publisher and Collection name | The `generated_at` of the latest Catalog. A name with no latest Catalog has no floor, and no rule bounds its first instant from below |
| Record | Publisher and URL | The Item of kind `page`, its Collection, and the Catalog ID and `generated_at` of the Catalog it was proved against |
| Removal | Publisher and URL | That a valid Item of kind `removed` removed the URL's record, with that Item's Item ID and the Catalog ID and `generated_at` of the Catalog it was proved against (Several Logs) |

The latest Catalog and the floor stay when a Declaration stops naming
the Collection, when narrowing (ADR-0051) or a base removes the
Collection's records, and when the Publisher's identity resets (WIST-1
§5.2). Both are functions of the sealed Entries. A Snapshot carries,
under `state_digest`, the latest Catalog of every name that has one,
every record with the Collection, Catalog ID and `generated_at` it
carries, and every removal state with its Item ID, Catalog ID and
`generated_at`, so a Consumer resumed from it derives the floor and
holds the combined view (Several Logs) that a replaying one holds.
Their encoding as state tuples is left to the revision of WIST-3 §7
(Taking effect).

#### Judgment

An Entry of Epoch N is judged once, at N, and not again: under the
Declaration in force for its Publisher once every transition of Epoch
N has applied (ADR-0051), under the parameter map in force at N, and
with N's `sealed_at` as the clock. The Publisher of a Catalog Entry is
`catalog.publisher`, and that of an Item Entry is the `publisher` of
the named Catalog, whatever `item.publisher` spells. A recovery window
is open at N when its recovery Declaration was sealed at or below N
and N's `sealed_at` is earlier than the window's end. A Catalog of a
Publisher with no Declaration in force has no candidate and fails C1
with `WIST1-E02`.

A `publisher_catalog` Entry is valid when all four conditions hold.

| # | Condition |
|---|---|
| C1 | The Catalog meets none of the Catalog conditions, the two of a pull aside |
| C2 | No recovery window of the Publisher is open at N |
| C3 | The name has no floor, or `generated_at` is later than the floor |
| C4 | The name has no latest Catalog; or `root` is not the latest Catalog's; or `generated_at` is at least `catalog_refresh_seconds` later than the floor; or the latest Catalog fails the binding check at N |

A valid Catalog becomes the latest Catalog of its name.

A `publisher_item` Entry is valid when all seven conditions hold, read
once the Catalogs of Epoch N have applied.

| # | Condition |
|---|---|
| I1 | The body has the form above |
| I2 | No recovery window of the Publisher is open at N |
| I3 | `catalog` is the Catalog ID of a latest Catalog, the **named Catalog** |
| I4 | The Declaration in force names the named Catalog's Collection, and the named Catalog passes the binding check at N |
| I5 | `collection` is the named Catalog's, and the Item meets none of the Item conditions, judged with the named Catalog |
| I6 | `proof` verifies against the named Catalog |
| I7 | An Item of kind `page` is not the Item of its URL's record, and no `payload_withdrawal` sealed in an Epoch below N names its Item ID; an Item of kind `removed` has a record for its URL. The record is that of the Publisher and the URL, whatever Collection it carries |

A `payload_withdrawal` names an Item ID in `details.delta_id`, the
member in which WIST-3 §6.2 and WIST-4 §5.1 have it name a Delta ID.
I7 reads that member of each withdrawal that meets its `details`
contract (WIST-4 §5.1), and nothing else of the withdrawal. For an
Item ID the contract is that a valid `publisher_item` Entry sealed the
Item, of kind `page` since no other has a Payload, at or below the
withdrawal's Epoch, that Epoch included whatever the order of its
Entries, against a Catalog whose `publisher` is the withdrawal's
`subject`. An Aggregator seals no withdrawal that breaks it (Waiting);
replay ignores one with `WIST4-E04` (WIST-4 §7), and it names no Item
for I7.

C2 to C4 are read only for a Catalog that meets neither `WIST1-E05`
nor a `WIST1-E14` condition. Where I1 fails no other condition of the
Item is read, and I2 and I4 to I7 are read only where I3 holds, since
they read the named Catalog.

A valid Item of kind `page` becomes the record of its URL. A valid Item
of kind `removed` removes the record. An Item may be sealed in a Log
more than once: after narrowing or a base removed its URL's record,
the Item that record carried passes I7 again, unless a withdrawal
names it, and is sealed again against the latest Catalog. The rule of
WIST-3 §3.2 that a Delta is sealed once does not apply to Items.

An Entry that is not valid is ignored: it changes no state, the floor
included, and the Epoch stays accepted. An Entry that names an ignored
Catalog, a replaced one or one never sealed fails I3.

| Condition failed | Code |
|---|---|
| I1 | `WIST1-E14` |
| C1, I5 | The code of the Catalog condition, the body rule or the Item condition met |
| I4 | `WIST1-E03` for a Collection the Declaration does not name; otherwise `WIST1-E02` or `WIST1-E01`, as the binding check distinguishes them |
| I6 | `WIST1-E17` |
| C2, C3, C4, I2, I3, I7 | `WIST3-E06` |

`WIST3-E06` is a new code of WIST-3: a `publisher_catalog` or
`publisher_item` Entry out of place in the Log. `WIST1-E05` and the
`WIST1-E14` conditions are checked first; among the others WIST-1 §7
leaves the choice of diagnostic.

An Epoch is rejected whole, with `WIST3-E03`, when two of its
`publisher_catalog` Entries carry the same strings as `publisher` and
as `collection`, whether or not either is valid; an Entry in which
either member is not a string is compared with none.
`publisher_catalog` and `publisher_item` Entries, valid or ignored,
count toward the per-domain Epoch capacity (WIST-3 §3.2) with Labels
and disputes, under the Registrable Domain of `catalog.publisher` or
`item.publisher`; a body in which that member is not a Canonical Host
counts toward no domain. An Epoch above the capacity is rejected
whole, with `WIST3-E03`.

#### Waiting

An Aggregator seals no Entry the judgment ignores, no Epoch it
rejects and no `payload_withdrawal` that breaks its contract
(Judgment). The rules of this part bind the Aggregator alone: the Log
does not show an acceptance, so no Consumer derives them.

The **last accepted Catalog** of a Collection is the Catalog a pull
accepted last, unless it failed C1 at its turn, and the latest Catalog
otherwise. The order of a pull (`WIST2-E05`) and the idempotent
re-serve (Catalogs) read it. Per Collection at most one Catalog waits,
and per URL at most one Item. Where the last accepted Catalogs of two
Collections of a Publisher each list for one URL an admitted Item for
which I7 holds, at each Epoch the Item of the Collection whose Scope
covers the URL under the Declaration in force once that Epoch's
transitions have applied waits; where no Scope covers it, the Item of
the Catalog later in the order of Several Logs. At a pull the
Declaration read for this is the current one of the sealed history.
This arises between pulls that read different Declarations and inside
a window, where a pull reads two sources. The Item that waits for a
URL at an Epoch is read once that Epoch's transitions and Catalogs
have applied and takes the URL's turn in that Epoch, with the place
and the eligibility Epoch the URL has; an Item it replaces for the URL
leaves without a report, the URL having waited without interruption.
A URL that begins to wait at an Epoch or at a
settlement, and not at a pull, takes its place there. A Label or a
dispute takes its place at the pull that accepts it, after the places
that pull gives Catalogs and URLs. A place taken at an event comes
after every place taken at an earlier one, and places taken at one
Epoch, one settlement or one pull are ordered by the Publisher's
Canonical Host in ascending octet order, then by the order of the
Collections of the Declaration in force for that Publisher, a
Collection that Declaration does not name coming after the named ones
in ascending octet order of name, then by the list. For this order the
Declaration in force is, at an Epoch, the one in force once its
transitions have applied; at a settlement, the one it leaves current;
at a pull, the one the pull reads Collections from, and with two
sources the one in effect before the recovery.

| | A Collection's Catalog | A URL's Item |
|---|---|---|
| Waits | The last accepted Catalog, while it is not the latest Catalog and has not failed C4 at its turn | The Item the last accepted Catalog lists for the URL, while the Item is admitted (Files) and I7 holds for it |
| Place | Taken at the pull that accepts a Catalog while none of the Collection waits. A later accepted Catalog takes the place and the eligibility Epoch of the waiting one it replaces | Taken at the pull from which the URL waits, and kept with its eligibility Epoch while the URL waits without interruption, whichever Item waits for it |
| Leaves | When sealed. When it fails C1 at its turn, whether or not it fails C4: it is reported with C1's code alone at the status endpoint and is no longer the last accepted Catalog. When it fails C4 alone at its turn: it is not reported and stays the last accepted Catalog | When sealed. When the URL no longer waits: an Item for which I7 no longer holds once the Epoch's transitions and Catalogs have applied leaves unreported, whatever other condition it fails. When the Item fails I5 at its turn: it is reported with the code and is a refused Item of its list |

An Item is sealed in an Epoch only when, once the Epoch's Catalogs
have applied, the latest Catalog of its Collection has the `root` of
the last accepted Catalog and passes I4. The Entry names the latest
Catalog and carries the proof against it. While a Catalog of another
`root` waits, the Items of its Collection wait with it. While the
latest Catalog fails the binding check, they wait, with their places,
for the Catalog the Publisher signs next.

A Catalog or an Item is eligible for the Epoch that follows the event
at which it took its place, and the inclusion ceiling (WIST-4 §5)
counts from the Epoch it is eligible for. A replacement that keeps a
place moves no eligibility Epoch. Each of the following, and nothing
else, defers the eligibility, and the ceiling with it, to the first
Epoch at which none of them applies:

- a recovery window of the Publisher open at the Epoch (Recovery);
- no room in the capacity of the Registrable Domain, taken in the
  order below;
- for an Item, a waiting Catalog of its Collection that one of the two
  above holds out of the Epoch;
- for an Item, a latest Catalog of its Collection that fails I4 at the
  Epoch, while no Catalog of that Collection waits that nothing
  defers.

A Declaration that reduces authority orders the sealing and defers
nothing (ADR-0051, Reaching the Log). A Catalog or an Item that the
hold keeps out of an Epoch takes no room in the capacity there, and
neither the hold nor the capacity moves its eligibility Epoch or its
ceiling at that Epoch; where a recovery window of the Publisher is
open at the Epoch, the window defers it. It is reported at the status
endpoint as held where no deferral applies to it, and with the
deferral where one does. A waiting Catalog that nothing defers is
sealed at or below the Epoch that seals an Item of its Collection, so
the earliest ceiling among the waiting Items of its Collection bounds
its sealing; an Item that had reached its eligibility Epoch keeps it
and its ceiling when a Catalog of another `root` is accepted.

In an Epoch the capacity of a Registrable Domain is taken first by its
Catalogs, then by its Items of kind `removed`, then by its Items of
kind `page`, its Labels and its disputes together, and within each of
the three in the order of the places. A Catalog or an Item that fails
its judgment at its turn takes no room, and the next in order takes
it. Every deferral that applies to a Catalog or an Item at an Epoch is
reported for it at the status endpoint, in the order of the list of
deferrals above; the capacity defers only what nothing else defers at
that Epoch. C2 defers a waiting Catalog and fails none, and C3 fails
none that a pull accepted or a settlement kept, since the order of the
pull and the settlement read the floor.

### Recovery

While a recovery window of a Publisher is open (Sealing), none of its
Catalogs and Items is sealed: C2 and I2 ignore one that is. The Epoch
that seals the recovery Declaration is inside the window. The first
Epoch whose `sealed_at` is at or after the window's end is outside it
and is the Epoch of settlement.

**Discovery.** From the pull that discovers a recovery rotation until
the Epoch that seals it, a pull reads the two frozen sources
(ADR-0051) and follows every rule below for a pull inside the window:
it queues what it accepts, per Collection name and signing key, and no
URL takes a place at it: an Item of the waiting Catalog that such a
pull admits takes its place at the next Epoch. What such a pull
accepts is not sealed before settlement: the rotation is a source the
pull read, so it is sealed at or below the Epoch that seals the first
publication that pull accepted, whose inclusion ceiling bounds it
(ADR-0051, Reaching the Log), and that Epoch opens the window. A
Catalog and the Items that waited at the discovery keep waiting: they
are sealed in their turn below the Epoch that seals the rotation where
the hold (ADR-0051, Reaching the Log) allows it, and are otherwise
queued and held when the window opens. Where the rotation leaves the
eligible sealing set (WIST-1 §5.2) unsealed, the queue is settled at
that event as Settlement settles one, the Catalogs that wait being
queued first as at the opening of a window, with the current
Declaration of the sealed history as the source and the instant of the
event as the clock. What waited at the discovery keeps its place, its
eligibility Epoch and its ceiling, which a surviving Catalog queued
from the discovery takes where it replaces the Catalog that waited;
what else was queued from the discovery is eligible for the first
Epoch not sealed before the event; later pulls are pulls outside a
window.

**Queue.** A pull inside the window reads the two frozen sources
(ADR-0051) and queues a Catalog that either accepts. The queue holds,
per Collection name and per public key that signed, the Catalog of
latest `generated_at`, with its list, its admitted Items and their
Payloads; a Catalog of the same name and key with a later instant
replaces the queued one. Inside the window the order of a pull
(`WIST2-E05`) is read against the floor, against the queued Catalog of
the same name and key and, before the window opens, against the
Catalog that waits for the Collection where the same key signed it, so
a Catalog of another Catalog ID at the instant of such a Catalog is
refused and that Catalog stays, and a Catalog signed by a key the
recovery removes holds back none signed by another. A Catalog with the
Catalog ID of a queued or a waiting one under another key is no
idempotent re-serve and is queued under its own key. A Catalog that
waited when the window opened is queued as one a pull inside the
window accepted, with the place it had, unless a Catalog of its name
and key with a later instant is queued already, which stays; the Items
that waited are held with their places. Inside the window an Item is
admitted when a source that accepts its Catalog passes the Item
conditions for it, and the refusal of a list that drops a record's URL
(Files) reads the Scopes of both sources. An idempotent re-serve
(Catalogs) inside the window reads again which sources accept its
Catalog and retries its Items under those; where neither accepts it,
no Item is retried. Inside the window no URL takes a place, the Epoch
that opens it aside, where an Item that a pull from the discovery
admitted for the waiting Catalog takes its place (Discovery), and a
Catalog that failed C4 at its turn is not queued. A queued Catalog is
not a waiting one and is not the last accepted Catalog until
settlement makes it one: from the Epoch that opens the window, the
window alone defers the Items held, and they are reported at each
Epoch inside it with the window alone.

**Settlement.** The queue is settled once, where no event of Discovery
settles it first, at the first event at or after the window's end: a
pull, which settles before it reads anything and is then a pull
outside a window, the settlement and the pull being two events, the
settlement first, so the places taken at the settlement precede those
the pull gives; or the Epoch of settlement S, before any Declaration
of S applies. Every queued Catalog is judged again by C1 under the
settlement source of WIST-1 §5.2, with the instant of that event as
the clock, a pull's own instant or S's `sealed_at`. A Catalog that
fails is rejected with `WIST1-E13` and reported at the status
endpoint. A queued Catalog whose `generated_at` is not later than the
floor does not survive either and is reported with `WIST2-E05`. The
rejection is of the queued copy: the same Catalog served again is
judged as any other. Per Collection name, the surviving Catalog that
is latest in the order of Several Logs becomes the last accepted
Catalog, and among surviving Catalogs of that Catalog ID the one of
the earliest place does. The other survivors are not sealed and not
reported. Where no Catalog of a name survives, a name with nothing
queued included, the last accepted Catalog is the latest Catalog.

What then waits (Sealing) is eligible for S, and the ceiling counts
from S. A URL that waited when the window opened and waits at
settlement keeps its place. A queued Catalog has the place of the pull
that queued it, before or inside the window, and one that waited when
the window opened the place it had. A Collection's Catalog takes the
earliest place among the Catalogs queued under its name and the
Catalog that waited for it when the window opened, those that a later
Catalog of their key replaced or kept out of the queue included, as a
replacement outside a window keeps the place (Waiting). A URL that did
not wait when the window opened takes the surviving Catalog's own
place, which the queue gave it, and not an earlier place the
Collection's Catalog takes, as a URL outside a window takes its place
at the pull from which it waits; where no Catalog of its name
survived, it takes the place of the settlement. Every Entry is judged
at the Epoch that seals it, the Declarations of S included, so a
survivor is eligible and not assured of sealing.

### What a record carries

A record carries the instant of the Catalog its Item was proved
against. A Collection carries the instant of its latest sealed Catalog,
which says that the Publisher stated the Collection then and says
nothing of any one record.

The Aggregator serves the Payload of a record's Item (WIST-3 §6.1)
while that Item is the record and, once an Item, narrowing or a base
replaces or removes the record at an Epoch, at every instant earlier
than that Epoch's `sealed_at` plus `payload_window_days` (WIST-4 §5)
of 86 400 seconds each, read from that Epoch's parameter map. A
withdrawal (WIST-3 §6.2) ends the duty, and an Item whose withdrawal
is sealed in the Epoch that seals the Item, which only replay meets
(Files), has none. A window begun when an Item stopped being the
record ends no duty while that Item is the record again, and for an
Item that stopped being the record more than once the duty holds while
the window of any of those Epochs does.

A party that holds every Item of a Collection MAY recompute the root
and compare it with the Catalog's. The comparison changes no sealed
value, no state tuple and no digest.

### Several Logs

A Catalog has the same inner object and the same Catalog ID in every
Log, and its Envelope may carry another signature in another Log. An
Item has the same octets and the same Item ID in every Log. The
Catalogs of one Publisher are ordered by `generated_at` and,
between equal instants, by Catalog ID: the greater string in octet
order is the later.

For one Publisher and URL, a Consumer of several Logs takes the state
proved against the latest Catalog in that order, among the Logs that
hold a state for the URL. A record is a state. A valid Item of kind
`removed` leaves a state as well, that the URL is removed, which such
a Consumer keeps with the Item's Item ID and the Catalog ID and the
instant of the Catalog the Item was proved against. Between states
proved against one Catalog, the state of the greater Item ID in octet
order is taken, a record's being its Item's. No walk accepts a list
with two Items under one key (Files), so two such states arise only in
a Log whose Aggregator sealed an Item without the walk; the rule makes
the Consumers of such Logs agree. A record that narrowing or a base
removed in a Log leaves no state in that Log. The state that a URL is
removed stays through narrowing and through a base, and ends when a
valid Item of kind `page` becomes the URL's record. The order runs
across the Collections of the Publisher.

### An Aggregator that was away

A valid Catalog is a **base** when its name has a floor and its
`generated_at` is more than `removal_retention_days`, of 86 400 seconds
each, later than the floor: an Item of kind `removed` listed after the
floor may have left the list since. A Catalog later than the floor by
exactly that interval is not a base.

When a base applies, every record of the Publisher in the Collection
is removed, before the Items of the Epoch apply. I7 then reads no
record of that Collection: a record of the URL that another Collection
carries is read as outside a base, so an Item of kind `removed` passes
I7 where such a record exists and fails it elsewhere, and an Item of
kind `page` that no withdrawal names passes it unless it is such a
record's Item. From the pull that accepts a Catalog that is a base
against the floor until that Catalog, or one that replaces it while it
waits, is sealed or leaves, the Aggregator reads I7 for the Collection
in the same way: every admitted Item for which it holds waits, and is
sealed in its turn. A Catalog a pull queues (Recovery) begins no such
reading; for a base in the queue it begins at the settlement that
makes the base the last accepted Catalog. When the base leaves
unsealed, failing C1 at its turn, I7 is read against the records
again, and the Items that are their URL's record leave unreported, as
an Item for which I7 no longer holds leaves (Waiting).

A record is absent from the Epoch of the base until the Epoch that
seals its Item. The capacity and the ceiling bound that interval and
nothing else does: a list of n Items under a capacity of c Entries
takes at least ⌈n / c⌉ Epochs.

No act of the Aggregator marks a base. Every party derives it from two
sealed instants and the constant `removal_retention_days` (Files).

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
- **A base marked by the Aggregator.** Covers every case in which a
  list dropped a URL the Log still holds. Gives an Aggregator the
  removal of records it sealed, which no Consumer could check against
  the list.
- **Records kept under a base until proved again.** Leaves no interval
  of absence. Needs the Log to say when a list has been sealed whole,
  the protocol state this decision leaves out.
- **An unchanged Catalog inside the refresh interval taken as valid.**
  One condition fewer on replay. Leaves the refresh rule without
  effect on any party that reads the Log.
- **A Catalog accepted between the discovery and the window left
  waiting.** One Catalog waits per Collection, so a Catalog of another
  key accepted later would replace it and lose it from the queue, and
  a Catalog signed by a key the recovery removes could displace the
  owner's.
- **A queue that holds every Catalog of a window.** Settles on the
  same Catalog except where a key's window was shortened. Holds a list
  of up to `catalog_items_max` Items per pull for the length of the
  window.
- **A removal sealed in its turn among the pages.** A Collection's
  backlog of pages would delay the removals its Publisher signed.
- **A list that drops a record's URL accepted.** Keeps the Collection
  moving. Leaves in the Log a record its Publisher no longer lists,
  which no Entry can remove before a base.
- **`catalog_refresh_seconds` bounded by the length of
  `removal_retention_days`.** A Publisher that signs every 604 800
  seconds under a refresh interval of 15 552 000 has its first
  unchanged Catalog to pass C4 at the floor plus 15 724 800 seconds, a
  base, so the refresh of an unchanged Collection would remove its
  records.
- **An Entry bound among the Item conditions, with `url_cap_bytes`
  unbounded.** An Item's admission would depend on the length of its
  proof, which the size of its Collection sets, and the bound would be
  met only before sealing.
- **Two Collections that list one URL decided by the order of Several
  Logs alone.** The Item of a Catalog whose Scope no longer covers the
  URL would wait and be refused at its turn, while the Item the Scope
  in force covers waited behind it.
- **`removal_retention_days` amendable by a Log.** Below the refresh
  interval every refresh of an unchanged Collection is a base, and a
  pull and an Epoch could read different values.
- **A waiting Catalog that defers the Items of its Collection.** An
  Aggregator could hold an Item without limit while Catalogs of other
  roots arrive.
- **An Item of kind `removed` that passes I7 without a record.** Every
  Log would seal every removal, of URLs it never held included.
- **An Item with a withdrawn Payload admitted without its Payload.** A
  record sealed again after narrowing or a base would commit to content
  every party has destroyed (WIST-3 §6.2), so no party could serve or
  verify it.

## Consequences

- A Publisher signs once per update, keeps no state beyond the files
  it serves, and serves files in proportion to its publications: 14 013
  for 10 000 URLs with their Payloads, `catalog.json` and the
  Declaration, against 1 581 572. The tree of 100 Items takes 17
  files, of 10 000 Items 4 011 and of 1 000 001 Items 338 789.
- A Log seals one Catalog per Collection per refresh interval where it
  sealed one `attest` per URL. The per-URL freshness of an unchanged
  page is no longer a protocol value, and a Catalog costs its Publisher
  almost nothing, so the Collection's instant does not tell one
  Publisher from another.
- A sealed Item Entry of kind `page`, with its proof, is on average
  951, 1 400, 1 621 and 1 828 octets in Collections of 100, 10 000,
  100 000 and 1 000 000 Items, over rounds that change 10, 1 000,
  10 000 and 1 000 Items and remove and add 1, 10, 100 and 10: 1.5 to
  2.9 times the 641 octets of an `update` Delta. One of kind `removed`
  is 540, 1 282, 1 488 and 1 687 octets over the rounds that change
  10, remove 1 and add 1. Each sealed Catalog Entry adds 508 to 512.
- A pull, Payloads aside, fetches a tree file whole, so its cost
  follows how many buckets the changes reach. For changed, removed and
  added Items of 10, 1 and 1 it fetches 10 files of 19 663 octets in a
  Collection of 100 Items, 33 of 44 555 in one of 10 000 and 54 of
  95 994 in one of 1 000 000; for 1 000, 10 and 10, 1 171 files of
  1 305 185 octets in one of 10 000 and 2 675 of 5 107 547 in one of
  1 000 000; for one changed Item of 10 000, 5 files of 6 475 octets.
- A Publisher's site holds its present state. A Log that starts later
  obtains no earlier one, which changes what ADR-0003 says a late
  reader sees.
- A Log copies from another a Catalog and the Items proved against it.
  Items proved against earlier Catalogs cannot be proved again without
  the site's files, where a Delta is copied alone.
- For one record, a Consumer of several Logs takes the state proved
  against the Catalog of the later instant.
- A Catalog signed at the clock allowance holds back, for
  `clock_skew_seconds`, the Catalogs of its Collection that other keys
  sign, except from the discovery of a recovery rotation to the
  settlement of its window (Recovery).
- A Log whose floor for a Collection is more than
  `removal_retention_days` older than the next Catalog it seals,
  because it pulled none or the Publisher signed none, loses the
  Collection's records at that Catalog and seals them again at the
  rate the capacity allows. Under a base an Item of kind `removed`
  passes I7 only against a record of another Collection, so that Log
  holds no removal state for a URL of the Collection removed since its
  floor,
  and a Consumer of that Log and of one that still holds the URL's
  record shows the record until the second Log seals a later Catalog.
- A Publisher whose list holds no Item for the URL of a record a Log
  holds, a record sealed under a key an attacker held or kept through
  an identity reset included, has its Catalogs refused by that Log
  until its list holds an Item for each such URL or the Catalog is a
  base.
- A Publisher that narrows a Scope under a pending head or inside a
  recovery window keeps its Catalogs accepted, since its list holds an
  Item for every URL the earlier Scope covered.
- A Publisher that keeps emitting content whose Payload was withdrawn
  holds no Payload for its served Item (WIST-3 §6.2) and so lists a new
  Item under a fresh salt; stopping that is the Publisher's act.
- The hold of ADR-0051 (Reaching the Log) names publications; Labels
  and disputes are not held.
- Catalogs take the capacity first, so a Registrable Domain whose
  Collections have as many Catalogs to seal as the capacity of an
  Epoch seals no Item in it.
- A record that narrowing removed in one Log is shown from a Log that
  has not sealed the narrowing Declaration, as a record a base removed
  is.
- A Consumer resumed from a Snapshot accepts as consistent a
  withdrawal that names an Item sealed at or below the Snapshot
  (WIST-4 §5.1), so it differs from a replaying Consumer only in a Log
  whose Aggregator sealed a withdrawal that breaks its contract.
- Erasure stays as WIST-3 §6.2 has it: a `payload_withdrawal` under the
  Aggregator's signature, naming an Item ID.
- ADR-0003, ADR-0007, ADR-0015, ADR-0026, ADR-0029, ADR-0030, ADR-0031,
  ADR-0036, ADR-0041 and ADR-0044 are updated in place, and the subject
  of ADR-0027 is replaced.

## Open points

None.

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

They carry as well: an Item of kind `page` at the bound of
`JCS(item)`, accepted, and one octet above it, refused alone while the
others proceed; an Item of kind `removed` whose URL is above
`url_cap_bytes`, which removes its record; a valid Envelope padded
with whitespace to 16 384 octets of `catalog.json`, accepted, and to
16 385, a failed fetch; the duty to serve a replaced file, which holds
one second before the end of its `replaced_file_seconds` and not at
it; C4 and the base under a `catalog_refresh_seconds` of 7 776 000, a
weekly signer whose unchanged Catalog of week 13 passes C4 and is no
base, and an amendment to 7 776 001, ignored; an amendment of
`url_cap_bytes` to 32 769, ignored; a served list that holds two Items
of one URL, refused with `served-list`; a refresh with no new stream
after the served Declaration narrowed a Scope, which lists the
publications outside it as removed; the last accepted Catalog served
again with a signature that does not verify, and after a Declaration
removed its key, reported with the code and retrying nothing; a pull
of idempotent re-serves alone, `WIST2-E02`, and one whose re-serve
admits a retried Item; a withdrawal sealed in the Log and ignored with
`WIST4-E04`, naming an Item a later list carries, which is admitted; a
withdrawn Item that also meets another Item condition, reported with
`WIST2-E03`; the served instant and clock at which a Catalog is due;
the derivation of a served Item outside the Scope of the served
Declaration and of a URL a removal names with no served Item; a
pending head that narrows a Collection, whose Catalog the current
Declaration accepts and whose Item of kind `removed` removes the
record; a recovery that narrows a Scope, whose owner's Catalog is
queued; records sealed from an attacker's Catalog before a window,
after settlement the owner's Catalog without them refused with their
URLs reported and the Catalog listing Items of kind `removed` for them
accepted; an Item sealed again after narrowing and a later widening; a
withdrawn Item that a later list names, not admitted, its Payload not
fetched and its Entry ignored; an Item whose Payload fails a cap
amended before its candidate Epoch; two states of one URL proved
against one Catalog; places taken at one Epoch by Items of two
Publishers of one Registrable Domain under a capacity of 1; an Item
whose eligibility Epoch and ceiling stay when a Declaration that
reduces authority is discovered or a Catalog of another root is
accepted; a pull between the discovery and the sealing of a recovery
rotation; a Catalog queued between the discovery and the sealing of a
recovery rotation under a key the recovery alone lists, beside one of
the earlier key accepted later, both queued; a publication the hold
keeps out of an Epoch, which takes no room and keeps its eligibility
Epoch and ceiling; a record's Item sealed again under a base whose
Payload fails a cap amended before its candidate Epoch; an Item whose
withdrawal is sealed in the Epoch that seals it, with no serving duty;
an Item whose latest Catalog fails I4 while a Catalog of its
Collection waits that nothing defers, keeping its eligibility Epoch
and ceiling; two Collections listing one URL, decided by the Scope in
force; the queue settled when the rotation leaves the eligible sealing
set unsealed, what waited at the discovery keeping its place,
eligibility Epoch and ceiling; a queued Catalog not later than the
floor at settlement, reported with `WIST2-E05`; a URL that did not
wait when the window opened, placed at the pull that queued the
surviving Catalog; a pull that settles, the settlement's places first;
the order of Collections at a settlement read from the Declaration it
leaves current; a base beside a record of the URL in another
Collection, an Item of kind `removed` passing I7; the reports at the
Epochs of a window after the opening one; a Catalog that fails C1 and
C4 at its turn, reported with C1's code alone; a replay whose first
Epoch is rejected; an Item of the waiting Catalog admitted at a pull
after the discovery, placed at the next Epoch; an Item that fails I7
and another condition, leaving unreported; a base that fails C1 at its
turn, whose Items that are their URL's record leave unreported; a base
queued inside a window, read against the records until settlement; a
settlement with nothing queued for a name; one inner Catalog signed by
two keys, both queued; a Catalog of the Catalog ID of a queued one
under another key, queued and not an idempotent re-serve; a Catalog of
another Catalog ID at the instant of the queued Catalog of its name
and key, `WIST2-E05`; the removal states a Snapshot carries, combined
with another Log's record; the end of the serving duty of each Payload
through a base and a sealing again.

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

The vectors of Sealing's State and Judgment, Several Logs, the base
and the interval of a replaced file are
`vectors/wist3/catalog-sealing.json`,
`vectors/multilog/catalog-order.json` and
`vectors/wist2/served-files.json`, generated by
`tools/gen_sealing_vectors.py` from the reference in
`tools/sealing.py`, `tools/combined_view.py` and
`tools/served_files.py`, and recomputed by
`tools/verify_sealing_vectors.py`. The vectors of Waiting, Recovery
and the Payloads of a pull are `vectors/wist3/catalog-waiting.json`,
`vectors/wist1/catalog-recovery.json` and
`vectors/wist2/collection-pull.json`, generated by
`tools/gen_waiting_vectors.py` from the reference in
`tools/waiting.py` and `tools/recovery_queue.py`, and recomputed by
`tools/verify_waiting_vectors.py`. The histories of the sealing and
waiting vectors carry a parameter map per pull and per Epoch. Each
verifier was written from this text and the vector files without the
reference or the generator.

The octets, files and pull transfers of Consequences are measured by
`tools/measure_catalog_costs.py` on synthetic Collections built with
the reference: seed 7, URLs of 48 to 62 octets, Payloads of 1 700
octets, buckets of 16 Items, and rounds of 100 Items changing 10,
removing 1 and adding 1; of 10 000 changing 1, removing and adding 0,
changing 10, removing and adding 1, and changing 1 000, removing and
adding 10; of 100 000 changing 10, removing and adding 1, and changing
10 000, removing and adding 100; and of 1 000 000 changing 10,
removing and adding 1, and changing 1 000, removing and adding 10.
