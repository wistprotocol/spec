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

### Scope

A **Scope** is a list of entries. Each entry is a Normalized URL whose
host lies in the Publisher's authority, with a `match`: `prefix` covers
every URL that begins with the entry, and `exact` covers that URL
alone. Where `collections` is present, a URL outside every Scope cannot
be published by any key. No entry of one Collection covers an entry of
another.

An Aggregator does not admit, and a Consumer ignores, a publication
outside its Collection's Scope under the Declaration in force at the
sealing Epoch. This is WIST-1 §3.2's scope rule and `WIST1-E03`,
extended from hosts to URLs.

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

### Reaching the Log

An Aggregator fetches the Declaration at the start of every pull. It
seals a Declaration that removes a key, a Collection or a Scope entry
within `record_seal_epochs`, the deadline WIST-1 §5.2 gives a recovery
Declaration, and ahead of the publications of the same Registrable
Domain that wait for capacity.

### Size

A Declaration's JCS serialization fits one Log Entry (WIST-3 §3.3).
`collections_max` and `scope_entries_max` bound the counts. The octet
bound binds first: sixteen Collections of thirty-two entries at
`url_cap_bytes` would hold 1 048 576 octets.

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
- Whether the Key Set cache of WIST-1 §5.1 keeps a purpose once the
  Declaration is fetched at every pull.
- The values of `collections_max` and `scope_entries_max`.

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
