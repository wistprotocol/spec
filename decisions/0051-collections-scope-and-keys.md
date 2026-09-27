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

A Declaration that carries `collections` and becomes current removes
every record whose URL its Collection's Scope no longer covers, and
every record of a Collection it no longer names. The records leave as
removed records do and return only through a new publication.

Narrowing takes effect at the sealing Epoch of an ordinary rotation
sealed outside a recovery window; at settlement for a recovery
rotation, whose own sealing opens a window, and for the Declaration a
window leaves current; and at activation for a fresh identity. A
pending Declaration and a Declaration accepted inside an open window
remove nothing. A Declaration without `collections` keeps the present
rule, under which a later change of `subdomain_scope` "does not revise
authority at an earlier Delta's sealing height" (WIST-1 §5.2).

Narrowing reads the Publisher's live records and the Declaration that
takes effect, and no earlier Declaration. Under a Declaration that
carries `collections`, a record stays when the Declaration names the
record's Collection and that Collection's Scope covers the record's
URL. Under a Declaration without `collections`, a record stays when its
Collection is `default`, whatever its host; the records of every other
Collection leave, since no Declaration in force names their Collection.

The transitions that narrow, each at the height of the Epoch in which
WIST-1 §5.2 applies it:

| Transition | Height |
|---|---|
| An ordinary rotation naming the current Declaration, sealed outside a recovery window, a reversal of a pending head included | Its sealing Epoch |
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
set and is a fresh identity, pending and reversible. The Key Set
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
`record_seal_epochs`, the deadline WIST-1 §5.2 gives a recovery
Declaration, and ahead of the publications of the same Registrable
Domain that wait for capacity. The test covers a Declaration that
removes a key, a Collection, a Scope entry or a host, or shortens a
key's window.

A pull of a Publisher's Collections proceeds only after that fetch
succeeded in the same pull; an unchanged answer to a conditional
request is a success. When the fetch fails, or the fetched Declaration
fails its acceptance checks, the Aggregator pulls no Collection of
that Publisher and retries as WIST-2 §7 retries a failed fetch. The
pull reads Collections, Scopes and keys from the Declarations WIST-1
§5.2 authorizes for admission once the fetched one has been applied
there: a fetched Declaration that becomes pending leaves the pull
under the current one. The Key Set cache of WIST-1 §5.1 is removed with its parameter:
a pull under a cached Key Set would admit publications under a Scope
or a key the served Declaration has removed.

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
replaces an entry by a wider one reduces authority. The deadline is
counted as WIST-1 §5.2 counts it for a recovery Declaration, from the
discovery of D.

### Size

A Declaration's JCS serialization fits one Log Entry (WIST-3 §3.3).
`collections_max` and `scope_entries_max` bound the counts. The octet
bound binds first: sixteen Collections of thirty-two entries at
`url_cap_bytes` would hold 1 048 576 octets.

`collections_max` is 16 Collections in a Declaration and
`scope_entries_max` is 32 entries in a Scope; neither is amended below
1. A Declaration above either count is rejected with `WIST1-E16`. A
Declaration whose `publisher_declaration` Entry (WIST-3 §3.3) has a
JCS serialization above 65 535 octets is rejected with `WIST1-E04`.
The two counts and `url_cap_bytes` are read for a Declaration at the
instant WIST-1 §3.6's size-cap parameter time gives a Delta.

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
- **Narrowing that hides records instead of removing them.** Hidden
  records would return when a Scope widens, with no statement from the
  Publisher that they are still published.
- **Narrowing for a Declaration without `collections`.** Changes what
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
- WIST-1 §3.2, §5.1 and §5.2, WIST-2 §3 and §5, and WIST-3 §3.2 and §7
  are restated; a record and its state tuple carry the Collection.
  ADR-0002, ADR-0023, ADR-0039 and ADR-0045 are updated in place.

## Open points

- The order in which the Collections of one Registrable Domain take
  the capacity they share.

## Verification

Vectors carry: a Scope entry of each `match`, the home page among the
`exact` ones; two Collections whose entries overlap; a publication
inside, outside and across Scopes; a publication signed by another
Collection's key; narrowing by an ordinary rotation, by a recovery
rotation at settlement, by a fresh identity at activation, and a
pending Declaration that removes nothing; `default` named beside other
Collections; a Declaration signed by a Collection key; a Declaration
above the Entry bound; the sealing deadline of a Declaration that
removes a key.

They are `vectors/wist1/collection-fields.json`,
`collection-scope.json`, `collection-keys.json` and
`collection-narrowing.json` and `vectors/wist2/declaration-pull.json`,
generated by `tools/gen_collection_vectors.py` from the reference in
`tools/collection_rules.py` and `tools/narrowing.py`, and recomputed by
`tools/verify_collection_vectors.py`, which was written from this text
without the other three. A publication in them is a signed probe that
stands for the Collection's signed list; the vectors of ADR-0052 carry
the list itself.
