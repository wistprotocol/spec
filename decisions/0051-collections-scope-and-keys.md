# ADR-0051: A Publisher's publications are divided into Collections, each with an enforced Scope and its own keys

**Status:** draft · **Date:** 2026-09-27

## Context

A Publisher's authority is its domain and the hosts of
`subdomain_scope` (WIST-1 §3.2), and every key of its Key Set signs for
all of it. Two needs follow that the host alone cannot express.

An owner wants to fix which parts of a site may ever be published. A
URL sealed by mistake stays in the Log (WIST-1 §9), so the limit has to
hold against a fault in whatever produces the publications and cannot
be a setting of that same tool.

An owner who lets a platform publish for it hands over a signing key,
and with it the whole authority: the platform can publish any URL of
the domain and replace the Declaration. Sites commonly run several
platforms under one host, a journal under one path and a store under
another.

Deployed systems answer both needs with delegation that names what it
covers. The Update Framework delegates path patterns to keys other than
the root's and revokes a delegation by re-signing. A DKIM selector lets
one provider be revoked without touching another. An IndexNow key
covers only URLs under the directory that holds it.

## Decision

### Collections

A Declaration MAY carry `collections`: a list of **Collections**, each
with a `name`, a `scope` and `keys`. A Declaration without the member
has one Collection, `default`, whose Scope is the Publisher's whole
authority and whose keys are the Declaration's `keys`. A Declaration
with the member MAY name one of its Collections `default`; that
Collection continues the implicit one, so its records and the order of
its publications persist across the two forms.

Each Collection publishes its own signed list under its own path and is
pulled, admitted and sealed on its own.

`collections` is an array of one or more objects with exactly the
members `name`, `scope` and, optionally, `keys`. `name` is 1 to 32
octets of lowercase ASCII letters, digits and `-`, neither beginning
nor ending with `-`, and names one Collection of the array. `scope` is
an array of one or more entries. `keys` is an array of key entries in
the form of WIST-1 §5.1; an absent `keys` and an empty one are the
same. The implicit `default` has no keys of its own. A member of
another form is `WIST1-E14`; a repeated `name` is `WIST1-E16`.

An empty `collections` or `scope` is refused because a list emptied by
a fault of the tool that writes the Declaration would remove every
record it governs.

### Scope

A **Scope** is a list of entries. Each entry is a Normalized URL whose
host lies in the Publisher's authority, with a `match`: `prefix` covers
every URL that begins with the entry, and `exact` covers that URL
alone. Where `collections` is present, a URL outside every Scope cannot
be published by any key. No entry of one Collection covers an entry of
another.

An entry is an object with exactly the members `url` and `match`.
`url` is byte-identical to its own Normalized URL (WIST-1 §2) and
`JCS(url)` is within `url_cap_bytes`; `match` is `prefix` or `exact`;
any other form is `WIST1-E14`. The host of `url` equals `domain` or a
member of `subdomain_scope`; otherwise the Declaration is rejected with
`WIST1-E16`.

Coverage compares octets of Normalized URLs and reads neither path
segments nor the query: a `prefix` entry `https://example.com/blog`
covers `https://example.com/blogs` and `https://example.com/blog?p=1`.
An entry covers another entry when it covers that entry's `url`,
whatever the other's `match`. A Declaration in which an entry of one
Collection covers an entry of another is rejected with `WIST1-E16`, so
a URL lies in at most one Scope. Entries of one Collection may cover
each other or repeat.

The Scope of the implicit `default` covers every URL whose host equals
`domain` or a member of `subdomain_scope`.

An Aggregator does not admit, and a Consumer ignores, a publication
outside its Collection's Scope under the Declaration in force at the
sealing Epoch. This is WIST-1 §3.2's scope rule and `WIST1-E03`,
extended from hosts to URLs. A publication whose URL another
Collection's Scope covers is outside its own and fails the same way,
as does one that names a Collection the Declaration does not have. An
entry's host and a publication's are compared as WIST-1 §3.2 compares
hosts, without the port; coverage compares the port with the rest of
the URL.

A record is identified by its Publisher and its URL and carries its
Collection. Disjoint Scopes and narrowing leave no URL with a record
in two Collections.

### Narrowing

A Declaration that becomes current by a transition of the table below
removes, at the height the table gives, the records that do not stay
under it. The records leave as removed records do and return when an
Item of their URL is sealed again, the Item they carried included.

Narrowing reads the Publisher's live records and the Declaration that
takes effect, and no earlier Declaration. Under a Declaration that
carries `collections`, a record stays when the Declaration names the
record's Collection and that Collection's Scope covers the record's
URL. Under a Declaration without `collections`, the records of every
Collection other than `default` leave, since no Declaration in force
names their Collection, and the Declaration otherwise keeps the
present rule: a record of `default` stays whatever its host, since a
later change of `subdomain_scope` "does not revise authority at an
earlier Delta's sealing height" (WIST-1 §5.2).

The transitions that narrow, each at the height of the Epoch in which
WIST-1 §5.2 applies it:

| Transition | Height |
|---|---|
| An ordinary rotation naming the current Declaration, sealed outside a recovery window, a reversal of a pending head included. One applied in the Epoch that opens a window, before the recovery rotation that owns it, is a predecessor and not a competitor (WIST-1 §5.2) and is sealed outside that window | Its sealing Epoch |
| Settlement of a recovery window, for the recovery-chain head it makes current | The first Epoch whose `sealed_at` is at or after the window's end |
| Activation of a pending head | The activation height |

A recovery rotation, a Declaration of any class accepted inside an
open window, a fresh identity that becomes pending, a replacement of a
pending head and an idempotent re-serve remove nothing when they are
sealed. Where one Epoch settles or activates and also seals an
ordinary rotation, the transitions narrow in the order WIST-1 §5.2
applies them.

Narrowing at height N removes records sealed below N. The publications
Epoch N seals are then read under the Declaration in force once every
transition of Epoch N has applied, which is the Scope rule above.

### Keys

`keys` are the owner's: they sign Declarations and the publications of
any Collection. A Collection's `keys` sign that Collection's
publications and nothing else. A public key appears once across `keys`,
`recovery_keys` and every Collection.

Signer classification (WIST-1 §5.2) reads `keys` and `recovery_keys`
alone. A Declaration signed by a Collection key is signed by neither
set and is a fresh identity, treated as WIST-1 §5.2 treats a fresh
identity in the state in which it is accepted: pending and reversible
outside a recovery window, a competitor inside one. The Key Set
fingerprint, which `next_keys` and the DNS record carry, covers `keys`
alone.

WIST-1 §5.2's unique-key rule and its `WIST1-E08` extend to Collection
keys: a public key listed twice within one Collection, in two
Collections, or in a Collection and in `keys` or `recovery_keys`.

The binding check of WIST-1 §5.1 collects a publication's candidates
from `keys` and from the `keys` of the Collection the publication
names, in each source Declaration §5.2 authorizes. A `sig.key_id` that
names only a key of another Collection has no candidate and is
`WIST1-E02`.

Declaration signer resolution (WIST-1 §5.2) collects no candidate from
a Collection's `keys`, the predecessor's or the incoming Declaration's.
A Declaration signed by a key its predecessor lists in a Collection
authenticates only when the Declaration lists that key in its own
`keys`, and is then a fresh identity; otherwise it is `WIST1-E02`.

### Reaching the Log

An Aggregator fetches the Declaration at the start of every pull. It
seals a Declaration that reduces authority, by the test below, within
`record_seal_epochs` of its discovery, counted as WIST-1 §5.2 counts
the deadline of a recovery Declaration, and ahead of its Publisher's
publications.

A Declaration D reduces authority against the Declaration P it names
as predecessor when at least one of the following holds. Each
Declaration is read with its Collections, the implicit `default`
included.

- P lists a public key in `keys`, in `recovery_keys` or in a
  Collection that D does not list in the same member, or in the
  Collection of the same name. Keys are compared by their public
  octets.
- D lists such a key with a shorter window: a later `nbf`, an earlier
  `exp`, or an `exp` where P has none.
- P has a Collection that D does not have.
- A Collection of P has a Scope entry that the Collection of the same
  name in D does not carry with the same `url` and `match`. The Scope
  of an implicit `default` counts as one entry that another implicit
  `default` carries and no `collections` member does.
- `subdomain_scope` of P has a member that D's does not.

The test reads entries and not the URLs they cover: a Declaration that
replaces an entry by a wider one reduces authority.

A Declaration is discovered at the pull that fetches it and finds that
it passes its acceptance checks. A recovery rotation whose window,
counted from the fetch's instant under the `recovery_window_days` in
force then, would end after `9999-12-31T23:59:59Z`, which WIST-1 §5.2
forbids sealing, fails those checks at the fetch with `WIST1-E08`, the
code WIST-1 §5.2 gives an Epoch that seals one: it is not discovered,
places no hold and queues nothing, and the pull stops (below). From the
discovery of a D that reduces authority, and while D is in the eligible
sealing set (WIST-1 §5.2), the Aggregator seals no publication of D's
Publisher in an Epoch below the one that seals D. The rule holds for a
Declaration of any class, a recovery rotation and a fresh identity that
becomes pending included. The publications of the other Publishers of
the Registrable Domain proceed. The hold orders sealing and moves no
eligibility Epoch and no inclusion ceiling (WIST-4 §5): D is sealed at
or below the last Epoch that the earliest ceiling among the waiting
publications of its Publisher allows. The publications sealed in D's
Epoch or later are judged as Narrowing states. For such a D, the hold
replaces WIST-1 §5.2's allowance of sealing a Delta in the Epoch it was
queued for and the Declaration in the next.

The hold ends at the Epoch that seals D, or when D leaves the eligible
sealing set unsealed: superseded at the settlement of a recovery
window (WIST-1 §5.2), or failing its checks at its candidate Epoch or
leaving with one that fails (Size). A pending replacement that a
reversal discards is sealed at or below the reversal's Epoch, as
WIST-1 §5.2's Declaration sealing obligation requires, so its hold
ends there. Where D is a recovery rotation that opens a window, the
window's deferral (ADR-0052, Recovery) applies from the Epoch that
seals D.

A pull of a Publisher's Collections proceeds only after that fetch
succeeded in the same pull. An answer 304 is judged as an answer 200
carrying the Declaration whose validator the request sent: it is a
success where that Declaration is one a fetch accepts as served again
(Size), and a failed fetch where WIST-1 §5.2 rejects it, as it rejects
a competitor superseded at settlement. When the fetch fails, or the
fetched Declaration fails its acceptance checks, the Aggregator pulls
no Collection of that Publisher. First contact ends at the pull that
accepts the Publisher's first Declaration, sealed or not, and begins
again where no accepted Declaration remains (Size). Outside first
contact, which WIST-2 §5 step 0 disposes of with `WIST2-E04`, the
stopped pull is one failed fetch, disposed of as WIST-2 §7 disposes of
a Feed it cannot use (`WIST2-E01`): retried on that backoff and not
noise against the Ping quota (WIST-2 §4). The pull
reads Collections, Scopes and keys from the sources the table below
gives for the Publisher's state once the fetched Declaration has been
applied. The Key Set cache of WIST-1 §5.1 is removed with its
parameter: a pull under a cached Key Set would admit publications
under a Scope or a key the served Declaration has removed.

A pull reads the Collections of a Declaration in the order
`collections` lists them. A Declaration under which a pull read is
sealed at or below the Epoch that seals the first publication that
pull accepted (WIST-3 §3.3). It defers no eligibility, whether or not
it reduces authority, so the inclusion ceiling of those publications
bounds its own sealing.

| State of the Publisher | Sources the pull reads | Collections pulled |
|---|---|---|
| A current Declaration, with no pending head, no open recovery window and no recovery rotation discovered and not yet sealed | The current Declaration | Its Collections |
| A pending head, with no recovery rotation discovered and not yet sealed | The current Declaration alone. The pending head names no Collection to pull and supplies no candidate: a publication that verifies under its keys alone is `WIST1-E02` | The current Declaration's. A history's first Declaration is current (WIST-1 §5.2), so a pending head always has one beside it |
| An open recovery window, or a recovery rotation discovered and not yet sealed | The two frozen sources of WIST-1 §5.2: the Declaration in effect before the recovery and the recovery Declaration that owns the window or, before its sealing, was discovered. No Declaration accepted later is read | Those of the Declaration in effect before the recovery, then those the recovery Declaration alone names. A name both carry is pulled once |

A recovery rotation that leaves the eligible sealing set unsealed
(Size) leaves the pulls after it under the sources of the other rows.
A replacement that names the pending head is the pending head for this
table and for ADR-0052, Recovery, whatever signs it: WIST-1 §5.2 has
it open no window, so it is no recovery rotation discovered and opens
no queue. A pending head stays pending at every pull until the Epoch
at its activation height is sealed.

A fetched Declaration whose `publisher` object is that of the pending
head is a success of the fetch and changes no source. So is one whose
`publisher` object is that of the recovery-chain head of an open
window of the Publisher, although WIST-1 §5.2 answers `WIST1-E08` to
its acceptance while another accepted Declaration is current: the pull
proceeds under the two frozen sources. The window is that of
admission, open from the discovery of the recovery rotation and not
only from the Epoch that seals it.

Under the two frozen sources each source is read alone, with its own
Collections, Scopes and keys. A publication is admitted to the queue
when at least one source names its Collection, supplies a candidate
under which its binding check passes and covers its URL with that
Collection's Scope. A Collection that one source names and a key that
only the other lists admit nothing together.

### Capacity

The Collections of one Registrable Domain share its per-domain Epoch
capacity (WIST-3 §3.2), and no Collection has a share of its own. The
publications of the domain take the capacity across its Publishers and
Collections in the order ADR-0052, Waiting, gives: by class, and
within a class in the order of the places. For publications, that
order replaces the acceptance order in which WIST-3 §3.2 and WIST-4 §5
have a domain's Entries take the capacity. A Collection that fills the
capacity delays the others of its domain; the owner's remedy is a
Declaration that removes the Collection or its keys, which the hold
(Reaching the Log) seals ahead of its Publisher's publications.

### Size

A Declaration's JCS serialization fits one Log Entry (WIST-3 §3.3).
`collections_max` and `scope_entries_max` bound the counts. The octet
bound binds first: sixteen Collections of thirty-two entries at
`url_cap_bytes` would hold 1 048 576 octets.

`collections_max` is 16 Collections in a Declaration and
`scope_entries_max` is 32 entries in a Scope; no Log amends either
below that value, since a Publisher reads no Log's parameters. A
Declaration above either count is rejected with `WIST1-E16`. A
Declaration whose `publisher_declaration` Entry (WIST-3 §3.3) has a
JCS serialization above 65 535 octets is rejected with `WIST1-E04`.

The two counts and `url_cap_bytes` are read for a Declaration at the
instants WIST-1 §3.6's size-cap parameter time gives a Delta: at the
validation attempt that accepts it, and before sealing under the map
in force at the candidate Epoch's `sealed_at`. A fetched Declaration
whose `publisher` object is that of the current Declaration or of the
pending head, an idempotent re-serve (WIST-1 §5.2), or that of an open
window's recovery-chain head (Reaching the Log) is not read again
against them or the Entry bound, current and pending read in the
admission state, a discovered Declaration not yet sealed included; an
answer 304 and an answer 200
carrying that object give the same result. Neither is a
`publisher_declaration` Entry that repeats the current Declaration or
the pending head read against them on replay: it is idempotent under
any parameter map.

An accepted Declaration that fails at its candidate Epoch is not
sealed. It leaves the eligible sealing set at once, as WIST-1 §5.2
removes a superseded copy, with every accepted Declaration that names
it directly or through others; this is a further exception to WIST-1
§5.2's Declaration sealing obligation. The admission state is then
the one the accepted Declarations that remain give when applied in the
order of their acceptance, so a Declaration that a departing one
discarded or superseded is restored unless one that remains discards
or supersedes it. Where one remains, the sequence floor does not
change, so serving a departing Declaration again is rejected, with
`WIST1-E08` or with the code of a check it fails under the map the
fetch reads, WIST-1 §7 leaving the choice of diagnostic. Where none
remains, the domain returns to first contact (WIST-2 §5 step 0) and
keeps no sequence floor. The failure is reported at the status
endpoint with the code of the check that failed, for the Declaration
that failed and for each that leaves with it. A hold it placed ends
(Reaching the Log).

`WIST1-E16` is a new code of WIST-1 §7: a Collection rule violation.

## Alternatives considered

- **A limit kept in the Publisher's tool.** Fails with the tool it is
  meant to guard against.
- **A list of excluded paths.** Fails open: a path nobody thought to
  exclude is published.
- **A scope attached to each key, without Collections.** Two keys with
  different scopes cannot share one signed list, and a rotation would
  change what the scope is attached to.
- **A fingerprint that covers Collection keys.** Under a standing
  `next_keys` commitment the committed set is installed exactly
  (WIST-1 §5.2), so a stolen Collection key could not be replaced
  without a recovery rotation.
- **A hold that defers eligibility until the Declaration is sealed.**
  It let an Aggregator delay a publication `record_seal_epochs`, 24
  Epochs, where the inclusion ceiling is 4, and a routine key overlap,
  whose `exp` shortens the outgoing key's window, triggers it.
- **Counts amendable down to 1.** A Publisher reads no Log's
  parameters, so a Log that lowered a count would refuse Declarations
  written to the suite's value.
- **A share of the capacity for each Collection.** Keeps one
  Collection's backlog from delaying another's. Gives the inclusion
  ceiling a turn per Collection to account for, and differs from the
  order WIST-3 §3.2 gives the hosts of a domain.
- **Narrowing that hides records instead of removing them.** Hidden
  records would return when a Scope widens, with no statement from the
  Publisher that they are still published.
- **Narrowing of `default` by host for a Declaration without
  `collections`.** Changes what
  a change of `subdomain_scope` does to records already sealed, for
  Publishers that never asked for Collections.

## Consequences

- An owner that removes a prefix takes its records out of every index
  with one Declaration, whatever the holder of a Collection key does.
- A holder of an owner key can do the same to a whole domain in one
  Epoch, where removal one URL at a time is bounded by the per-domain
  Epoch capacity. Recovery restores authority and not records: they
  return as the owner's publications are sealed again.
- A holder of an owner key can add or replace a Collection key under a
  standing `next_keys` commitment, as it can change `subdomain_scope`
  today. The recovery key is the remedy.
- A URL that moves from one Collection to another is removed with the
  Declaration and sealed again from the second Collection's list. A
  site that introduces Collections keeps the records its `default`
  Collection still covers.
- The Collections of one Registrable Domain share its quota, its ingest
  budget and its Epoch capacity (ADR-0042).
- WIST-1 §3.2, §5.1, §5.2 and §8, WIST-2 §3 and §5, and WIST-3 §3.2
  and §7 are restated; a record and its state tuple carry the Collection.
  ADR-0002, ADR-0023, ADR-0039 and ADR-0045 are updated in place.

## Open points

None.

## Verification

Vectors carry: a Scope entry of each `match`, the home page among the
`exact` ones; two Collections whose entries overlap; a publication
inside, outside and across Scopes; a publication signed by another
Collection's key; narrowing by an ordinary rotation, by a recovery
rotation at settlement, by a fresh identity at activation, and a
pending Declaration that removes nothing; an ordinary rotation that
drops a Scope entry, applied before the recovery rotation that
restores it in the Epoch that opens its window, removing the record
at that Epoch without its return at settlement; `default` named beside
other Collections; a Declaration signed by a Collection key, pending
outside a recovery window, and one listing a former Collection key in
its own `keys` and signed by it inside a window, a competitor
superseded at settlement and never pending; a Declaration above the
Entry bound; the sealing deadline of a Declaration that removes a
key.

They are `vectors/wist1/collection-fields.json`,
`collection-scope.json`, `collection-keys.json` and
`collection-narrowing.json` and `vectors/wist2/declaration-pull.json`,
generated by `tools/gen_collection_vectors.py` from the reference in
`tools/collection_rules.py` and `tools/narrowing.py`, and recomputed by
`tools/verify_collection_vectors.py`, which was written from this text
without the other three. A publication in them is a signed probe that
stands for the Collection's signed list; the vectors of ADR-0052 carry
the list itself.

The sources of a pull under a pending head and inside a recovery window,
the order of the Collections pulled, the capacity order and the sealing
of a Declaration that reduces authority ahead of the publications that
wait are carried by `vectors/wist2/collection-pull.json`,
`vectors/wist1/catalog-recovery.json` and
`vectors/wist3/catalog-waiting.json` (ADR-0052's Verification), over
signed Catalogs. Their cases include: a Declaration that reduces
authority, discovered while an Item waits, leaving the Item's
eligibility Epoch and ceiling unchanged and sealed at or below the
ceiling's Epoch, the Item in the same Epoch after it; a competitor that
reduces authority, discovered inside a window and superseded unsealed at
settlement, whose Publisher's survivors are eligible for the Epoch of
settlement and sealed; a pending replacement that reduces authority,
discarded by a reversal, sealed at or below the reversal's Epoch, where
its hold ends; a recovery rotation whose window cannot be frozen under
an amended `recovery_window_days`, refused at the fetch, with no hold
and nothing queued; a replacement of the pending head signed by a
recovery key, read as the pending head; a pending head at a pull after
the Epoch below its activation height is sealed, still pending; a first
Declaration accepted and unsealed, then a failed fetch, `WIST2-E01` and
not noise; a competitor superseded at settlement, then an answer 304, a
failed fetch; the recovery-chain head served again while a competitor is
current, a success of the fetch under which the Collections of both
frozen sources are pulled and a Catalog under the recovery key is
queued; a recovery rotation that adds a Collection, discovered and not
yet sealed, under which a pull accepts a Catalog of that Collection
signed by a key the recovery alone lists, with that pull's place, and
admits no Item that a Catalog signed by a key the earlier Declaration
alone lists holds under a Scope entry the recovery alone carries; the
current Declaration served again, by an answer 200 and by an answer 304,
after `collections_max` was amended below its count, an idempotent
re-serve under which every Collection is pulled; an accepted Declaration
whose Scope exceeds a `scope_entries_max` amended after its discovery
and in force at its candidate Epoch, never sealed, its predecessor
current, served again `WIST1-E08`, and the Publisher's Catalogs sealed
under the predecessor; a discovered, unsealed Declaration served again
under a lowered count, an idempotent re-serve; a first Declaration that
fails at its candidate Epoch, followed by a new `seq` 0 accepted; a
competitor that fails while a follower is current, which stays current;
and a reversal that fails, restoring the pending replacement it
discarded.