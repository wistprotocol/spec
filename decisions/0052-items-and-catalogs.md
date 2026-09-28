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

A Catalog names the tree files reached from its `tree` and the
Payloads of the Items of kind `page` of its list. New files are
written before the Catalog that names them is served. A file the
served Catalog does not name stays served for `replaced_file_seconds`,
86 400 seconds, counted on the Publisher's clock from the instant at
which the last Catalog that named it was replaced: at every instant
earlier than that one plus the interval, and not at it. A file named
again inside the interval is served as a named one. A file the
Publisher must stop serving is removed at once, whether or not the
served Catalog names it. The value is the suite's and no
Log amends it, since a Publisher reads no Log's parameters.

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

None of the five is amended below 1, and `removal_retention_days` is
not amended above 180, the interval a Publisher keeps whatever Log
pulls it. The first three are read at the instant WIST-1 §3.6's
size-cap parameter time gives a Delta, and the last two from the
parameter map in force at the Epoch that judges a Catalog (Sealing).

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
files below it. An Aggregator keeps the tree files it fetched under
their hashes, so a walk that a replaced file interrupts resumes at the
next pull, under the Catalog then served, from the files held.

A Catalog is refused whole with `WIST2-E07` as well when its list
holds no Item for the URL of a record that the Aggregator holds for
the Collection and that the Collection's Scope covers under the
Declaration the pull reads, unless the Catalog is a base against the
floor (An Aggregator that was away): no Entry could remove that
record.

An Item of the list that meets none of the Item conditions is
**admitted** when it is of kind `removed`, when it is the Item of its
URL's record, or when its Payload verifies. For an Item of kind `page`
that is not the record's, the Aggregator fetches the Payload, unless
it holds one under that Item ID, and verifies it by WIST-1 §7's
Payload checks against the Item's `payload`. An Item whose Payload is
unavailable or fails a check is not admitted and is reported with
`WIST2-E03`; the other Items proceed.

A pull that accepts a Catalog or meets an idempotent re-serve judges
again, under the Declaration then in force, every Item of the list
that an earlier pull refused or did not admit, and fetches again the
Payload it does not hold. An idempotent re-serve replaces no Catalog, fetches no tree
file the Aggregator holds and gives no waiting Item another place
(Sealing).

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
| Removal | Publisher and URL | That a valid Item of kind `removed` removed the URL's record, with the Catalog ID and `generated_at` of the Catalog that Item was proved against (Several Logs) |

The latest Catalog and the floor stay when a Declaration stops naming
the Collection, when narrowing (ADR-0051) or a base removes the
Collection's records, and when the Publisher's identity resets (WIST-1
§5.2). Both are functions of the sealed Entries. A Snapshot carries
the latest Catalog of every name that has one, so a Consumer resumed
from it derives the floor as a replaying one does.

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
| I7 | An Item of kind `page` is not the Item of its URL's record; an Item of kind `removed` has a record for its URL. The record is that of the Publisher and the URL, whatever Collection it carries |

C2 to C4 are read only for a Catalog that meets neither `WIST1-E05`
nor a `WIST1-E14` condition. Where I1 fails no other condition of the
Item is read, and I2 and I4 to I7 are read only where I3 holds, since
they read the named Catalog.

A valid Item of kind `page` becomes the record of its URL. A valid Item
of kind `removed` removes the record.

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

An Aggregator seals no Entry the judgment ignores and no Epoch it
rejects. The rules of this part bind the Aggregator alone: the Log
does not show an acceptance, so no Consumer derives them.

The **last accepted Catalog** of a Collection is the Catalog a pull
accepted last, unless it failed C1 at its turn, and the latest Catalog
otherwise. The order of a pull (`WIST2-E05`) is read against it, and
a fetched Catalog with its Catalog ID or the latest Catalog's is an
idempotent re-serve. Per Collection at most one Catalog waits, and per
URL at most one Item. A URL that begins to wait at an Epoch or at a
settlement, and not at a pull, takes its place there, after the places
taken before and in the order of the Collections of the Declaration in
force and of the list.

| | A Collection's Catalog | A URL's Item |
|---|---|---|
| Waits | The last accepted Catalog, while it is not the latest Catalog and has not failed C4 at its turn | The Item the last accepted Catalog lists for the URL, while the Item is admitted (Files) and I7 holds for it |
| Place | Taken at the pull that accepts a Catalog while none of the Collection waits. A later accepted Catalog takes the place and the eligibility Epoch of the waiting one it replaces | Taken at the pull from which the URL waits, and kept with its eligibility Epoch while the URL waits without interruption, whichever Item waits for it |
| Leaves | When sealed. When it fails C1 at its turn: it is reported with the code at the status endpoint and is no longer the last accepted Catalog. When it fails C4 at its turn: it is not reported and stays the last accepted Catalog | When sealed. When the URL no longer waits. When the Item fails I5 at its turn: it is reported with the code and is a refused Item of its list |

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
place moves no eligibility Epoch. Each of the following defers the
eligibility, and the ceiling with it, to the first Epoch at which none
of them applies:

- a recovery window of the Publisher open at the Epoch (Recovery);
- a Declaration of the Publisher that reduces authority, discovered
  and not sealed at or below the Epoch (ADR-0051);
- for an Item, a waiting Catalog of its Collection that the Epoch does
  not seal, or a latest Catalog that fails I4 at the Epoch;
- no room in the capacity of the Registrable Domain, taken in the
  order below.

In an Epoch the capacity of a Registrable Domain is taken first by its
Catalogs, then by its Items of kind `removed`, then by its Items of
kind `page`, its Labels and its disputes together, and within each of
the three in the order of the places (ADR-0051). Items that took their
places at one pull are ordered by the order in which the pull read
their Collections and, within a Collection, by the list. A Catalog or
an Item that fails its judgment at its turn takes no room, and the
next in order takes it. Every deferral that applies to a Catalog or
an Item at an Epoch is reported for it at the status endpoint; the
capacity defers only what nothing else defers at that Epoch. C2 defers a waiting
Catalog and fails none, and C3 fails none that a pull accepted, since
the order of the pull read the floor.

### Recovery

While a recovery window of a Publisher is open (Sealing), none of its
Catalogs and Items is sealed: C2 and I2 ignore one that is. The Epoch
that seals the recovery Declaration is inside the window. The first
Epoch whose `sealed_at` is at or after the window's end is outside it
and is the Epoch of settlement.

**Queue.** A pull inside the window reads the two frozen sources
(ADR-0051) and queues a Catalog that either accepts. The queue holds,
per Collection name and per public key that signed, the Catalog of
latest `generated_at`, with its list, its admitted Items and their
Payloads; a Catalog of the same name and key with a later instant
replaces the queued one. Inside the window the order of a pull is read
against the floor and against the queued Catalog of the same name and
key, so a Catalog signed by a key the recovery removes holds back none
signed by another. A Catalog that waited when the window opened is
queued as one a pull inside the window accepted, with the place it
had, and the Items that waited are held with their places. Inside the
window an Item is admitted when a source that accepts its Catalog
passes the Item conditions for it, and the refusal of a list that
drops a record's URL (Files) reads the Scopes of both sources. An
idempotent re-serve inside the window, of a queued Catalog or of the
latest Catalog, reads again which sources accept its Catalog and
retries its Items under those; where neither accepts it, no Item is
retried. Inside the window no
URL takes a place, and a Catalog that failed C4 at its turn is not
queued. A queued Catalog is not a waiting one: from the Epoch after
the one that opens the window, the window alone defers the Items held.

**Settlement.** The queue is settled once, at the first event at or
after the window's end: a pull, which settles before it reads anything
and is then a pull outside a window, or the Epoch of settlement S,
before any Declaration of S applies. Every queued Catalog is judged
again by C1 under the settlement source of WIST-1 §5.2, with the
instant of that event as the clock, a pull's own instant or S's
`sealed_at`.
A Catalog that fails is rejected with `WIST1-E13` and reported at the
status endpoint. The rejection is of the queued copy: the same Catalog
served again is judged as any other. Per Collection name, the
surviving Catalog that is latest in the order of Several Logs becomes
the last accepted Catalog. The other survivors are not sealed and not
reported. Where no Catalog of a name survives, the last accepted
Catalog is the latest Catalog.

What then waits (Sealing) is eligible for S, and the ceiling counts
from S. A URL that waited when the window opened and waits at
settlement keeps its place. A Collection's Catalog takes the place of
the first Catalog queued under its name, and every other URL the place
of the pull that queued the surviving Catalog, or of the settlement
where no Catalog of its name survived. Every Entry is judged
at the Epoch that seals it, the Declarations of S included, so a
survivor is eligible and not assured of sealing.

### What a record carries

A record carries the instant of the Catalog its Item was proved
against. A Collection carries the instant of its latest sealed Catalog,
which says that the Publisher stated the Collection then and says
nothing of any one record.

A party that holds every Item of a Collection MAY recompute the root
and compare it with the Catalog's. The comparison changes no sealed
value, no state tuple and no digest.

### Several Logs

A Catalog and an Item have the same octets and the same IDs in every
Log. The Catalogs of one Publisher are ordered by `generated_at` and,
between equal instants, by Catalog ID: the greater string in octet
order is the later.

For one Publisher and URL, a Consumer of several Logs takes the state
proved against the latest Catalog in that order, among the Logs that
hold a state for the URL. A record is a state. A valid Item of kind
`removed` leaves a state as well, that the URL is removed, which such
a Consumer keeps with the Catalog ID and the instant of the Catalog
the Item was proved against. States proved against one Catalog are
one Item. A record that narrowing or a base removed in a Log leaves no
state in that Log. The state that a URL is removed stays through
narrowing and through a base, and ends when a valid Item of kind
`page` becomes the URL's record. The order runs across the Collections
of the Publisher.

### An Aggregator that was away

A valid Catalog is a **base** when its name has a floor and its
`generated_at` is more than `removal_retention_days`, of 86 400 seconds
each, later than the floor: an Item of kind `removed` listed after the
floor may have left the list since. A Catalog later than the floor by
exactly that interval is not a base.

When a base applies, every record of the Publisher in the Collection
is removed, before the Items of the Epoch apply. Against no record,
every Item of kind `page` of the list passes I7 and none of kind
`removed` does. From the pull that accepts a Catalog that is a base
against the floor, the Aggregator reads I7 for the Collection against
no record: every admitted Item of kind `page` waits, and is sealed in
its turn.

A record is absent from the Epoch of the base until the Epoch that
seals its Item. The capacity and the ceiling bound that interval and
nothing else does: a list of n Items under a capacity of c Entries
takes at least ⌈n / c⌉ Epochs.

No act of the Aggregator marks a base. Every party derives it from two
sealed instants.

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
- **A queue that holds every Catalog of a window.** Settles on the
  same Catalog except where a key's window was shortened. Holds a list
  of up to `catalog_items_max` Items per pull for the length of the
  window.
- **A removal sealed in its turn among the pages.** A Collection's
  backlog of pages would delay the removals its Publisher signed.
- **A list that drops a record's URL accepted.** Keeps the Collection
  moving. Leaves in the Log a record its Publisher no longer lists,
  which no Entry can remove before a base.

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
- A Catalog signed at the clock allowance holds back, for
  `clock_skew_seconds`, the Catalogs of its Collection that other keys
  sign, except inside a recovery window.
- A Log that seals no Catalog of a Collection for more than
  `removal_retention_days` loses the Collection's records at its next
  Catalog and seals them again at the rate the capacity allows.
- A Publisher that drops a URL from its list without an Item of kind
  `removed` has its Catalogs refused by every Log that holds the URL's
  record, until it lists the Item or the Catalog is a base.
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
`tools/verify_waiting_vectors.py`. Each verifier was written from this
text and the vector files without the reference or the generator.
