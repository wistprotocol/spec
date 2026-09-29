# ADR-0053: A change list carries the Items by which a Catalog differs from the one it replaced

**Status:** draft · **Date:** 2026-09-29

## Context

An Aggregator obtains the Item list of a Catalog by walking its tree of
files and fetching each file it does not hold (ADR-0052, Files). A tree
file is fetched whole, so an Item that differs brings the unchanged
Items of its bucket and every inner file above the bucket. For 1 000
changed, 10 removed and 10 added Items the walk fetches 1 171 files of
1 305 185 octets in a Collection of 10 000 Items and 2 675 files of
5 107 547 octets in one of 1 000 000 (ADR-0052, Consequences): 1 280
and 5 007 octets for each Item that differs.

A Catalog's signed `root` and `size` commit to its list, however a
party obtained the list. The part of a Publisher that signs holds the
served list and the new one when it signs (ADR-0052, From publications
to Items).

## Decision

### Change lists

A **change list** is an unsigned file that states how the list of one
Catalog differs from the list of the Catalog it replaced, its
**previous Catalog**. It is the JCS serialization of one object with
exactly these members.

| Member | Form |
|---|---|
| `previous` | The Catalog ID of the previous Catalog: `"sha256:"` followed by 64 lowercase hexadecimal digits |
| `catalog` | The same form: the Catalog ID of the Catalog the list **leads to** |
| `dropped` | An array of keys (ADR-0052, Items), each a string of 64 lowercase hexadecimal digits, in strictly ascending octet order |
| `items` | An array of Items in strictly ascending octet order of key. Each element is an object with a string member `url` |

No key of `dropped` is the key of an element of `items`. The form
asks nothing else of an element: the Item conditions judge it with the
list obtained (What an Aggregator reads).

A change list is **applied** to an Item list: every Item under a key
of `dropped` leaves the list, whatever its kind, and every element of
`items` takes the place of the Item under its key or, where the list
holds none under it, enters the list. A key of `dropped` under which
the list holds no Item and an element equal to the Item it replaces
change nothing and fail nothing.

An Item of kind `removed` that leaves the list after
`removal_retention_days` (ADR-0052, From publications to Items) is
stated by its key in `dropped`. An Item of kind `removed` that enters
the list is an element of `items`, as an Item of kind `page` is.

### What a Publisher serves

```
/.well-known/wist/collections/<name>/changes/<hex>.json
```

`<hex>` is the 64 lowercase hexadecimal digits of the Catalog ID the
list leads to.

The part that signs a Catalog of a Collection for which the Publisher
serves a Catalog writes the change list that leads to the new Catalog,
with the served Catalog as its previous Catalog:

- `items` holds every Item of the new list under whose key the served
  list holds no Item or an Item of another Item ID;
- `dropped` holds the key of every Item of the served list under whose
  key the new list holds no Item.

A Catalog whose list is the served one holds both arrays empty. Where
the file would hold more than `change_list_cap_bytes` octets, none is
written. A Catalog signed for a Collection with no served Catalog has
no change list.

A change list is written before the Catalog it leads to is served
(ADR-0052, Files). The **chain** of a Catalog is its change list, then
the change list that leads to that list's previous Catalog, and so on.
It ends at a Catalog for which no change list was written or whose
change list the Publisher had to stop serving.

The Publisher serves the first `change_chain_max` lists of the served
Catalog's chain. A list that a new Catalog puts out of those first
`change_chain_max` stays served for `replaced_file_seconds` (ADR-0052,
Files), counted on the Publisher's clock from the instant at which
that Catalog began to be served: at every instant earlier than that
one plus the interval, whatever Catalogs follow. A list that leaves
the chain because the chain ends in front of it has no interval. The
Publisher may stop serving any other change
list, and no rule obliges it to. A change list the Publisher must stop
serving is removed at once, as ADR-0052 has it of any file, wherever
the list stands in a chain and whatever interval it is inside. The
change lists that the Publisher is obliged to serve for a Collection
when the served Declaration stops naming it are among the files that
ADR-0052 keeps served for `replaced_file_seconds` from the instant the
Publisher began to serve that Declaration.

### What an Aggregator reads

An Aggregator **holds the list of a Catalog** when it holds the Item
list that it obtained for the Catalog of that Catalog ID, by a walk,
by a chain or by step 1 below, and that has the `size` and the `root`
of that Catalog. Which lists it keeps beyond those the rules of
ADR-0052 read is its own matter.

Wherever ADR-0052 has an Aggregator walk the tree of a Catalog, at a
pull outside or inside a recovery window, the Aggregator may obtain the
list as follows in place of the walk.

1. Where a list it holds for a Catalog of the Publisher and the
   Collection has `size` Items and the root `root`, that list is the
   Catalog's, and no file is fetched.
2. Otherwise, where it holds the list of some Catalog of the Publisher
   and the Collection, it fetches the change list that leads to the
   Catalog and, while the list last read names a previous Catalog
   whose list it does not hold, the change list that leads to that
   Catalog. The first list read whose previous Catalog's list it holds
   ends the reading.
3. It applies the lists read to the held list of that previous
   Catalog, the list read last first and the list that leads to the
   fetched Catalog last. The result is the fetched Catalog's list when
   it holds `size` Items and its root is `root`.
4. An Aggregator that holds no list of a Catalog of the Publisher and
   the Collection reads no change list.

The pull then proceeds as after a walk: the list obtained is judged by
the rule of a record's URL, by the Item conditions and by the Payloads
(ADR-0052, Files). The tree of a Catalog whose list was obtained so is
not fetched and is judged by no rule.

An Aggregator may leave a chain at any list and walk the tree. A chain
left so is not discarded and not reported.

### Bounds

| Parameter | Value |
|---|---|
| `change_list_cap_bytes` | 1 048 576 octets in a change list |
| `change_chain_max` | 16 change lists read for one Catalog |

Both are values of the suite. No Log amends them and no parameter map
carries them: a Publisher reads no Log's parameters, and no Consumer
derives a value from a change list.

An Aggregator reads at most `change_list_cap_bytes` octets of a change
list. Fetching a change list counts against the ingest budget of WIST-2
§5 as fetching a Feed page does: the octets of each list read are
debited, at each reading of a list read more than once, whether its
chain is accepted or discarded and whether or not the list meets
`form`, and an answer above `change_list_cap_bytes` debits nothing.
Under a per-pull limit in objects (WIST-2 §5) a change list is one
object.

A change list of as many octets as the remaining budget or a per-pull
limit leaves is read whole. One of more octets is read to that bound,
the octets read are debited, and the pull suspends there; a list read
so is read for no condition of Discarding. The chain is then left: it
is neither discarded nor reported, and the lists read are not kept.
An Aggregator that left a chain of a Collection so reads no change
list of that Collection until it has obtained a list of a Catalog of
it: at its next pulls it obtains the list of the Catalog then served
by step 1 or by the walk, which resumes from the tree files held
(ADR-0052, Files).

### Discarding

A chain is **discarded** at the first condition below that it meets.
For each list, in the order of reading, `fetch` and `size` are read in
that order, then the budget (Bounds), then `form`, then whether the
Aggregator holds the list of the previous Catalog, then `chain`.
`result` is read once the reading has ended.

| Condition | Met when |
|---|---|
| `fetch` | The fetch of a change list fails, a Publisher that serves no file at the path included |
| `size` | The answer holds more than `change_list_cap_bytes` octets; such an answer is not `fetch` |
| `form` | The octets of a change list are not the JCS serialization of an object of the form of Change lists, octets that are not valid JCS input included, or its `catalog` is not the Catalog ID that names the file |
| `chain` | `change_chain_max` lists were read and the last names a previous Catalog whose list the Aggregator does not hold |
| `result` | The lists applied give a list that holds another number of Items than `size` or has another root than `root` |

A change list that names as its previous Catalog one to which a list
already read leads is read as any other: the list that leads to that
Catalog is fetched again, so the chain meets `chain`.

A discarded chain accepts nothing and refuses nothing. The lists read
are not kept, and the Aggregator walks the tree from `tree` with the
tree files it holds (ADR-0052, Files); the walk alone accepts the
Catalog or refuses it with `WIST2-E07`. The walk belongs to the pull
that discarded the chain: it reads `tree_file_cap_bytes` and
`tree_depth_max` from the parameter map of that pull and counts
against the budget the chain left. A discard adds no noise (WIST-2 §4)
and starts no retry (WIST-2 §7): the pull resolves as ADR-0052 has it,
by what it accepts and admits. A later pull reads the chain of the
Catalog then served, whatever chain an earlier pull discarded.

A discarded chain is reported at the status endpoint (WIST-2 §7.1)
with `WIST2-E08`, a new code of WIST-2 for a change list that an
Aggregator discarded. The report carries the name of the condition,
the Catalog ID of the fetched Catalog and the Catalog ID that names
the change list at which the condition was met, for `result` the
fetched Catalog's.

## Taking effect

This decision takes effect with ADR-0052, in the revision of WIST-2
that states every rule above. The conformance reference implements
each rule, and a vector discriminates it, before that revision is
written. The encoding of the report of a discard in the status object
and the instant at which it stops pending are left to the revision of
WIST-2 §7.1.

## Alternatives considered

- **A change list named by its previous Catalog.** An Aggregator whose
  held list the Publisher's chain no longer reaches learns it at the
  first fetch. The file is written again when a Publisher restored to
  an earlier Catalog signs another successor, and an Aggregator that
  holds several lists has to choose the one it starts from.
- **A change list named by the root it leads to.** A Catalog that
  repeats a list needs no file. A root can return, the empty
  Collection's among them, so one name would stand for two lists.
- **One change list per Catalog for each of the last Catalogs.** No
  chain to follow. The part that signs computes and serves as many
  differences at every signature as it keeps earlier Catalogs.
- **A signed change list.** The `root` and `size` of the signed
  Catalog already decide the result, and the key would sign a second
  kind of object.
- **A list discarded for a dropped key it does not hold or an element
  that repeats the held Item.** Tells a Publisher that its tool wrote
  more than the difference. Discards chains whose result the signed
  root accepts.
- **Dropped Items stated by URL.** Readable without the earlier list.
  Takes the same octets at a URL of 63 and orders the array by a value
  the reader must compute.
- **Change lists kept from a suspended or a discarded chain.** Saves
  the octets of the lists read again. Holds unsigned files, which the
  Publisher can rewrite, as state between pulls.
- **A chain read again at the pull after a suspension.** No state
  between pulls. Under a per-pull limit or a budget below the octets
  of the chain every pull suspends at the same list, where a walk
  keeps its files and ends.
- **A list that leaves the first `change_chain_max` removed at once.**
  One rule fewer for a Publisher. An Aggregator that fetched the
  Catalog before the next was served fails its last fetch, and a
  conforming Publisher is reported.
- **Bounds that a Log amends.** A Publisher builds its files to the
  values of the suite, and the rules bind no party that reads the Log.
- **A cycle among the lists discarded where it is met.** Saves at most
  `change_chain_max` fetches of lists the bound already limits.
- **A change list required of every Aggregator.** An Aggregator whose
  pulls are further apart than a Publisher's chain would read
  `change_chain_max` lists before each walk.
- **A bound above the 1 MiB of a Feed page.** Carries a difference of
  more Items in one file: the 10 200 of the measured round of a
  Collection of 100 000 take 2 918 255 octets. Holds a larger unsigned
  answer in memory before any check of its result.
- **The Catalog a list starts from called its base.** ADR-0052 gives
  that name to a Catalog more than `removal_retention_days` later than
  the floor.

## Consequences

- No signed and no sealed object changes. A Consumer reads no change
  list, and replay is as ADR-0052 has it.
- A pull that obtains a list from one change list fetches
  `catalog.json` and the list, Payloads aside. For changed, removed
  and added Items of 10, 1 and 1 it fetches 3 973 octets in a
  Collection of 100 Items, 3 989 in one of 10 000 and 3 979 in one of
  100 000 and of 1 000 000, where the walk fetches 19 663, 44 555,
  68 975 and 95 994: 0.20, 0.09, 0.06 and 0.04 of the walk. For 1 000,
  10 and 10 it fetches 292 492 octets in a Collection of 10 000 and
  292 557 in one of 1 000 000, where the walk fetches 1 305 185 and
  5 107 547: 0.22 and 0.06. For one changed Item of 10 000 it fetches
  961 octets, where the walk fetches 6 475. A change list holds 286 to
  293 octets for each Item that differs, and 487 for one.
- The round that changes 10 000 Items of 100 000 and removes and adds
  100 has no change list, which would hold 2 918 255 octets, and its
  pull walks 13 214 files of 12 817 358 octets.
- An Aggregator that missed three Catalogs reads four lists. Over four
  rounds of 10, 1 and 1 in a Collection of 10 000 it fetches 5 files
  of 14 515 octets, where the walk fetches 111 of 147 923; over four
  rounds of 1 000, 10 and 10, 5 files of 1 168 623 octets, where the
  walk fetches 2 638 of 2 561 466.
- A chain costs an Aggregator at most `change_chain_max` fetches and
  16 777 216 octets for one Catalog before the walk that follows a
  discard, all of them debited to the ingest budget.
- An Aggregator keeps, to build proofs and to judge Items again
  (ADR-0052), the list of each Catalog it accepted, so a change list
  adds to its state only whether it left a chain of the Collection at
  a suspension.
- An Aggregator that obtains a list through a chain does not read the
  Catalog's tree, so a tree that breaks a rule of ADR-0052's Files
  refuses the Catalog only at an Aggregator that walks it, one that
  holds no list of the Collection among them.
- An Aggregator that obtained the lists of successive Catalogs through
  chains holds none of their tree files, so a walk it begins later
  fetches the files above every Item that changed since its last walk.
- A Publisher is obliged to serve, per Collection, the
  `change_chain_max` change lists of the chain and those inside their
  interval, of at most `change_list_cap_bytes` octets each.
- A difference above `change_list_cap_bytes` has no change list, and
  an Aggregator whose held list lies behind it walks the tree.
- Where two parts that sign write a change list of one name with
  different previous Catalogs, the file written last stands. The
  signed `root` decides the result of either.
- WIST-2 gains the code `WIST2-E08`, and the status endpoint a report
  that refuses nothing.
- ADR-0044 and ADR-0052 are updated in place: the change list joins
  the responses read to 1 MiB, and the walk of Files becomes one of
  two ways to obtain a list.

## Open points

None.

## Verification

Vectors carry: a change list and a walk that reach one Item list; the
form of a change list and each failure of it, an element nested 100
levels deep and a number beyond the finite range among them; the
application of a list, a dropped key the list does not hold and an
element equal to the held Item among it; an Item of kind `removed`
that left the list after `removal_retention_days`, stated in
`dropped`; a dropped Item of kind `page`; the list a Publisher writes
from a served list and a new one, for a Catalog that repeats the
served list, for a difference one octet within and one above
`change_list_cap_bytes`, and for a Collection with no served Catalog;
the change lists a Publisher serves at a clock along a sequence of
Catalogs, at `change_chain_max` and beyond it, inside the interval of
a list put out of the chain, one second before its end and at it,
behind a Catalog with no list, behind a list the Publisher had to stop
serving and inside the interval of one, and after the served
Declaration stops naming the Collection; a Catalog of the `root` and
`size` of a held list, for which nothing is fetched, and that list
held at a later pull; chains of one, two and `change_chain_max` lists,
accepted; a chain of `change_chain_max` lists whose last names a
previous Catalog not held; a list that names a previous Catalog not
held and whose own list is not served; a list of
`change_list_cap_bytes` octets, read, and of one octet more; a list
whose `catalog` is not the name of its file; a list whose previous
Catalog is its own; a chain whose result has another root, and one
whose result has another number of Items; an Aggregator that holds no
list of the Collection; a chain that the ingest budget suspends,
within a list and between two, in a list that is not of the form, and
a budget of exactly the octets of a chain; the pulls after a
suspension, by step 1, by a walk that accepts and by one that refuses;
the octets read in each chain, a list read more than once and a list
that meets `form` among them; the walk that follows each discarded
chain, accepting and refusing with `WIST2-E07`, under an amended
`tree_file_cap_bytes`, and within and one octet short of the budget
the chain left; the report of each discard.

The vectors are `vectors/wist2/change-lists.json`,
`change-list-serving.json` and `change-chains.json`, generated by
`tools/gen_change_list_vectors.py` from the reference in
`tools/change_lists.py`, and recomputed by
`tools/verify_change_list_vectors.py`, which was written from this text
and the vector files without the reference or the generator.

The octets and files of Consequences are measured by
`tools/measure_change_list_costs.py` on the synthetic Collections of
ADR-0052's Verification, with the same seed and rounds. A pull counts
`catalog.json` and every file it fetches, Payloads aside; the walk
fetches the tree files that an Aggregator which walked the Catalog
before the round does not hold. Each chain measured is accepted by the
reference with the list the walk gives.
