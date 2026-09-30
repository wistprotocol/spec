# WIST-1: Item Format & Identity

**Status:** v1.0.0-draft · **Date:** 2026-09-30 · **License:** CC-BY 4.0

## 1. Introduction

WIST is an open, verifiable, push-based web index. A Publisher publishes
**Items**, its current statements about the URLs it publishes, and commits
to every Item of a **Collection** with one signed **Catalog**. Aggregators
seal Catalogs and Items into a public, append-only Log (WIST-3), from which
Consumers materialize a local index.

A Publisher derives its Items from the content's source, which states each
publication as an Emission (WIST-5); serves each Collection's Catalog,
tree files and Payloads under `/.well-known/wist/collections/<name>/`
([WIST-2](WIST-2-site-publication.md) §5); and each sealed Item carries an
Inclusion Proof against its Catalog (§4.3,
[WIST-3](WIST-3-logbook-distribution.md) §3.3).

This document defines the two foundational objects of the suite:

- the **Item**, with the **Catalog** that commits to it, and
- the **Publisher Declaration**: how a domain declares its keys and its
  Collections.

How Items are published on a site and pulled by Aggregators is defined in
WIST-2. How they are sealed into the Log and distributed is defined in
WIST-3. How the Log is governed and its parameters amended is defined in
[WIST-4](WIST-4-governance.md).

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as
shown here.

- **Publisher**: the operator of a domain, identified by that domain, who
  publishes Items for URLs under its authority and signs the Catalogs that
  commit to them.
- **Aggregator**: the party that pulls Catalogs and Items from Publishers
  (WIST-2), seals them into the Logbook (WIST-3), and operates the
  governance actions of WIST-4. It is substitutable and gains no authority
  from the role: every artifact it produces is verifiable against
  signatures and hashes by anyone.
- **Item**: a Publisher's current statement for one URL: that it publishes
  the content a Payload Commitment binds, or that it no longer publishes
  the URL (§3.3). An Item carries no signature; the Catalog that lists it
  does.
- **Item ID**: `"sha256:"` followed by the lowercase hex SHA-256 of
  `JCS(item)` (§4.1).
- **Collection**: a named part of a Publisher's publications, declared with
  a Scope and optionally keys of its own (§5.1), and published, pulled,
  admitted and sealed on its own.
- **Scope**: the list of URL entries that bounds the URLs a Collection may
  publish (§5.1).
- **Catalog**: the signed statement of the complete Item list of one
  Collection at one instant (§3.5).
- **Catalog ID**: `"sha256:"` followed by the lowercase hex SHA-256 of a
  Catalog's Canonical Bytes (§4).
- **Key**, **leaf** and **root**: the hash under which an Item is ordered,
  the hash that commits to an Item at that key, and the hash that commits
  to a list of Items (§4.1). An Item's key is not a signing key.
- **Tree file**: a served file of the tree that carries a Catalog's list
  (§4.2).
- **Inclusion Proof**: the path that proves an Item's leaf under a
  Catalog's root (§4.3).
- **Publisher Declaration**: the signed document at a domain's well-known
  path that declares its keys and its Collections (§5.1).
- **Payload**: the content an Item of kind `page` commits to — the main
  text, the external links and the structured summary — carried as a
  separate, unsigned file named by the Item ID (§3.6, WIST-3 §6.1). A
  Payload is never part of an Item, a Catalog, an Epoch or the Log.
- **Payload Commitment**: the salted keyed hash of a Payload's content
  that an Item of kind `page` carries in place of that content (§3.6).
- **Envelope**: the JSON container `{"<inner>": {...}, "sig": {...}}` that
  pairs an inner object with a detached signature. Every signed object in
  the suite is signed the one way §4 defines, and every one but the
  Checkpoint (WIST-3 §5), which §4 accounts for, carries exactly this
  shape.
- **Canonical Bytes**: the octet sequence produced by applying JCS
  [RFC 8785] to the inner object.
- **Key Set**: the signing keys a Publisher Declaration lists in `keys`
  (§5.1). The `keys` of a Collection are not part of it.
- **Canonical Host**: a hostname IDN-encoded to its A-label form by
  **UTS #46 processing** with `UseSTD3ASCIIRules=true`,
  `CheckHyphens=false`, `CheckBidi=true`, `CheckJoiners=true`,
  `Transitional_Processing=false` and `VerifyDnsLength=true`, whose output
  labels are the IDNA2008 A-labels of RFC 5891 encoded with Punycode
  [RFC 3492]; with any trailing dot removed and no port. Case is folded by
  UTS #46's own mapping step and by nothing before it: an implementation
  MUST NOT lowercase the input first. Every Unicode property read by the
  suite uses **Unicode 16.0**, including these mapping tables. Moving the
  version changes the specification and, after deployment, requires a new
  major version under
  [PUBLICATION.md](../PUBLICATION.md#deployment-boundary).
  Algorithm and flag rationale: [ADR-0014](../decisions/0014-canonical-host-flag-profile.md);
  version rationale: [ADR-0017](../decisions/0017-one-pinned-unicode-version.md).
- **Normalized URL**: an `https` URL after RFC 3986 §6.2.2 syntax-based
  normalization — percent-encoding hex digits uppercased and
  percent-encoded octets that correspond to unreserved characters decoded,
  and dot-segments removed from the path — with its host replaced by the
  Canonical Host, its port read as a decimal integer (an empty port and a
  port equal to 443 removed, any other written without leading zeros, and a
  port above 65535 leaving no Normalized URL), an empty path replaced by
  `/`, and no fragment. The query string, if present, receives the same
  percent-encoding normalization as the rest of the URL but is otherwise
  copied byte-for-byte from the input: it is never parsed into parameters
  or reordered, so parameter order is significant. Two URLs are **the
  same URL** in this specification if and only if their Normalized URLs
  are byte-identical.

  A string has a Normalized URL only if it is an `https` URI under
  RFC 3986's grammar, whose host may also be spelled with U-labels that
  UTS #46 processing accepts, with no userinfo component. A string holding a raw
  space, a control character (U+0000 to U+001F, U+007F), or a non-ASCII
  character outside the host, a string with a userinfo component, a
  percent-escape that is not two hexadecimal digits, and a host label
  UTS #46 processing rejects have no Normalized URL. A validator MUST NOT
  repair, guess at or compare unnormalized a string that has none. This
  rule governs an Item's `url` (§3.2), a Scope entry's `url` (§5.1) and a
  declared link (§3.6) alike; each field's section gives its diagnostic.

Hash strings throughout the suite are serialized as `"sha256:" + lowercase
hex`. Signatures are Ed25519 [RFC 8032], detached, base64url-encoded
without padding [RFC 4648 §5].

**Canonical base64url.** Every field specified as base64url anywhere in the
suite MUST use the URL-safe alphabet, omit padding and whitespace, and set
all unused low bits of its final character to zero. Validators MUST reject
other encodings, including length congruent to 1 modulo 4; they MUST NOT
repair or normalize them. Decoding followed by unpadded base64url encoding
MUST reproduce the original string exactly. Field-specific byte lengths
still apply: an Ed25519 key entry's `x` is 32 octets (43 characters),
`sig.value` is 64 octets (86 characters), and a Payload `salt` is at least
16 octets. Empty strings are invalid for these fields.

A malformed base64url field is `WIST1-E14`. Check the encoding before using
that field for key exclusion, signer resolution, signature or commitment
verification; an unused malformed Declaration key still rejects the whole
Declaration under §5.1. This is distinct from a canonically encoded public
key whose point §4 excludes. The signature-field check also applies when
idempotence would otherwise waive signature verification. Existing
object-level rejection rules and transport wrappers remain in force; the
object's encoding diagnostic identifies the underlying failure, including
beneath first-contact `WIST2-E04` or invalid-object `WIST3-E03` handling.
Item and Catalog diagnostic precedence is specified in §7; this establishes
no precedence between unrelated failures in other objects.

Key membership and disjointness compare decoded public bytes after encoding
validation; equality of these bytes is equivalent to equality of their
canonical strings. Preserve original signed entries for JCS, hashes and
recovery-set protection. A key entry's `kid` is derived from the canonical
string of `x` (§5.1); alternate base64url spellings cannot introduce a
second entry for one key.

## 3. The Item and the Catalog

An Item is an object of kind `page` or `removed` (§3.3). A Catalog (§3.5)
lists the Items of one Collection and carries their version and their
signature. The machine-readable schemas are
[`schemas/item.schema.json`](../schemas/item.schema.json),
[`schemas/catalog.schema.json`](../schemas/catalog.schema.json) and
[`schemas/tree-file.schema.json`](../schemas/tree-file.schema.json); where
prose and schema disagree, the schema governs syntax and this document
governs semantics.

### 3.1. `wist_version`

The version of this specification the object conforms to, as a semver
string. This document defines version `1.0.0`. A Catalog, a Payload and a
Declaration carry `wist_version`; an Item carries none and is read under
the version of the Catalog that lists it. Every Catalog, Payload or
Declaration validator, including a Publisher checking its output, an
Aggregator admitting an object or a Consumer replaying a sealed one, MUST
reject an object whose major version it does not implement before treating
the object as valid. A validator implementing this revision supports major
`1`; any other major is `WIST1-E15` under §7. A different minor or patch
component alone MUST NOT cause rejection; all rules of the implemented
revision still apply.

For a Catalog or a Payload, the version string MUST contain exactly three
dot-separated nonnegative ASCII decimal components, with no leading zeros
except `0` itself and no prerelease or build suffix. Components have no
numeric upper bound; validators MUST NOT impose a machine-integer range on
them. Malformed spelling is `WIST1-E14`; a well-formed unsupported major is
`WIST1-E15` under §7. Validate each object's version independently; no
equality between a Payload's version and the version of a Catalog that
lists its Item is required. Never rewrite a version field during
validation. See [ADR-0030](../decisions/0030-delta-version-eligibility.md).

**Draft revisions and extensibility.** Before stable publication or the first
Log sealing Epochs consumed by a third party, whichever occurs first,
incompatible draft revisions MAY retain the unreleased version `1.0.0`,
including when they add required fields. The rules of the exact specification
commit being implemented determine acceptance, not the shared version string.
Older draft objects have no implicit compatibility exemption. See
[PUBLICATION.md](../PUBLICATION.md) and
[ADR-0028](../decisions/0028-unreleased-object-version.md).

After that boundary, new fields and other substantive changes require a new
major version. Within each revision, objects MUST NOT carry fields not defined
by that revision. Every schema in the suite therefore sets
`additionalProperties: false` on each object whose full field set a document
of this suite defines, and a minor version never adds a field. Two places are
deliberately open, and both delegate rather than extend: an Epoch Entry's
`body` (WIST-3 §3.3), which is validated in full by the schema of its Entry
type, and a Registry Update's `details` (WIST-4 §5.1), whose shape is fixed
per `action` and never licensed to carry what that section's closing rules
forbid. The rule exists so that a consumer encountering an unknown field
knows it is looking at a non-conforming object rather than at a newer minor
version it could safely ignore, which is what makes rejection the safe
default.

### 3.2. `url`

The URL an Item states. An Item's `url` is `WIST1-E03`, and the Item is
refused alone (§7), when:

- it is not byte-identical to its own Normalized URL, or has none (§2);
- its host lies outside the authority of the Catalog's Publisher (§3.8):
  its Canonical Host equals neither that Publisher's `domain` nor a member
  of its `subdomain_scope` (the **scope rule**); or
- the Scope of the Catalog's Collection (§5.1) does not cover it. A URL
  that another Collection's Scope covers is outside its own.

The scope rule compares Canonical Hosts without the port; Scope coverage
compares the port with the rest of the URL (§5.1). An absent
`subdomain_scope` adds no host beyond `domain`. A host inside a parent's
`subdomain_scope` may also declare for itself; both Publishers' Items for
it are valid, and which record materializes is decided by WIST-3 §7's
one-URL-one-Publisher rule — self-declaration prevails from the height its
Declaration seals.

Authority, Scope and signing bindings MUST come from the same authenticated
Declaration of the Catalog's `publisher`, selected for the stage by §5.2: at
a pull, the sources of §5.2's pull table; at sealing and on replay, the
Declaration in force at the sealing Epoch once every transition of that
Epoch has applied. Under the two frozen sources of a recovery each source
is read alone (§5.2, **Sources of a pull**).

The UTF-8 octet length of `JCS(url)` — the JSON string literal with its
enclosing quotes and any escapes — in an Item of kind `page` MUST NOT
exceed `url_cap_bytes` (WIST-4 §5); a larger one is `WIST1-E11`. An Item of
kind `removed` is not held to `url_cap_bytes`, so it removes the record of
a URL sealed under a larger cap; §7's bound on `JCS(item)` bounds it.
`url_cap_bytes` is amended to no value above 32 768 octets, so the
`publisher_item` Entry of an Item within the `JCS(item)` bound, its proof
included, stays within the 65 535 octets WIST-3 §3.3 allows an Entry. The
schema's `maxLength` counts code points and is a structural first pass;
this octet bound governs (§3.6 states the rule once for every cap in this
suite). The temporal profile is §3.6's **Size-cap parameter time**.

### 3.3. Kinds `page` and `removed`

An Item is an object of kind `page` or of kind `removed`, with exactly the
members of its kind. An object that carries a member `removed` is read as
of kind `removed`.

| Kind | Members |
|---|---|
| `page` | `publisher` (§3.8), `url` (§3.2), `observed_at` (§3.4), `payload` (§3.6) and `meta` (§3.7) |
| `removed` | `publisher`, `url` and `observed_at`, in the same forms, and `removed`, the value `true` |

An Item of kind `page` states that the Publisher publishes at `url`, as of
`observed_at`, the content its `payload` commits to. An Item of kind
`removed` states that the Publisher no longer publishes `url` as of
`observed_at`; it has no Payload. An Item is judged with the Catalog that
lists it by the Item conditions of §7. An Item that fails one is refused
alone: it stays in the list, its leaf stays in the root, and the other
Items of the list proceed.

**Removal.** A URL the Publisher no longer publishes stays listed as an
Item of kind `removed` under the key of the page (§4.1), whose
`observed_at` is the `generated_at` of the first Catalog that lists it. The
Publisher MUST keep it listed for `removal_retention_days` (WIST-4 §5),
180 days, and MUST NOT take it out earlier, whatever Logs have sealed it:
a Publisher does not know every Log that pulls its files. An Item of kind
`removed` is sealed and proved as any Item is. How a Publisher derives the
list of each Catalog from its publications, removals included, is WIST-5's.

### 3.4. `observed_at` and `generated_at`

`observed_at` is the instant for which the Publisher asserts an Item's
statement, as a **Publisher timestamp** in the profile below. A missing,
non-string or malformed `observed_at` is `WIST1-E14`. An Item whose
`observed_at` is later than its Catalog's `generated_at`, compared as exact
instants, is refused alone with `WIST1-E06`.

`generated_at` is a Catalog's instant (§3.5), in the whole-second,
literal-`Z` profile of WIST-3 §3.1; another spelling is `WIST1-E14`. It
MUST NOT be more than `clock_skew_seconds` (WIST-4 §5) beyond the
validation clock selected below (`WIST1-E06`). Validate a timestamp's
format before comparing it with a clock, another instant or a key window.

**Clock parameter time.** For a Catalog not yet sealed, capture the
validator's clock and the accepted WIST-4 §5 schedule when its validation
attempt begins. Read `clock_skew_seconds` at that instant and retain both
values through the attempt. A new attempt takes a new clock and schedule.
At a recovery settlement the clock is the instant of the settling event
(§5.2).

Before sealing a Catalog, the Aggregator MUST repeat this check using the
candidate Epoch's `sealed_at` as the clock and the accepted schedule at
that instant. For a sealed Catalog, every validator MUST use its sealing
Epoch's `sealed_at` for both the clock and the parameter anchor. An
amendment effective exactly then participates; later amendments, replay
time and `generated_at` do not replace either value. Historical clock
eligibility therefore requires no supplied wall clock. This rule checks the
Publisher's timestamp against Log time; it does not certify the accuracy of
the Aggregator's clock.

The check is `generated_at <= clock + clock_skew_seconds`, with an
inclusive endpoint and exact arithmetic. Negative allowances retain their
sign; bounds outside the timestamp spelling range are compared
arithmetically without clamping or formatting them as dates. Field
precedence and semantic diagnostic selection follow §7.

**Publisher timestamp profile.** `observed_at` MUST use this RFC
3339-derived Gregorian profile:

- ASCII `YYYY-MM-DD`, `T` or `t`, `hh:mm:ss`, an optional decimal point
  followed by one or more ASCII fractional digits, then `Z`, `z`, or a
  numeric `+hh:mm`/`-hh:mm` offset. No spaces or trailing characters.
- Written years 0000–9999 and valid Gregorian dates, including leap year
  zero. Hours are 00–23; minutes and seconds are 00–59. Numeric offset
  hours are 00–23 and minutes 00–59. There is no fractional precision cap.
- Second 60 MUST be rejected without clamping or normalization, even at
  an actual leap insertion or its equivalent local offset. Every Gregorian
  day has exactly 86,400 seconds and every minute permits second 59,
  independent of positive or negative leap announcements. This clock rule
  replaces RFC 3339 §5.7's event-dependent second eligibility. Validators
  MUST NOT consult a leap table, wall-clock date or announcement horizon
  to determine field validity. Ordinary future dates remain valid fields;
  the comparison with the Catalog's `generated_at` still applies.

For comparisons and arithmetic, subtract the numeric offset from the
Gregorian day/hour/minute/second value, using 1970-01-01T00:00:00Z as zero,
and add the exact decimal fraction. `-00:00` denotes a known instant with
unknown local offset and contributes zero, as do `Z`, `z` and `+00:00`.
Offset subtraction MAY produce an arithmetic instant outside the written
four-digit year range; it does not invalidate a well-formed field. Compare
all fractional digits without rounding or truncation. Preserve the original
string for JCS, hashing and signatures. For example, the distance from
2016-12-31T23:59:59Z to 2017-01-01T00:00:00Z is one second; from
`10:00:00Z` to `10:00:00.5Z` on the same date it is half a second.

This profile does not redefine descriptive timestamps elsewhere in the
suite. See [ADR-0026](../decisions/0026-publisher-timestamp-profile.md).

### 3.5. The Catalog

A Catalog is an Envelope (§4), `{"catalog": …, "sig": …}`, stating the
complete Item list of one Collection at one instant. `sig` has the form §4
gives. The inner object carries exactly these members.

| Member | Form |
|---|---|
| `wist_version` | The version spelling of §3.1 |
| `publisher` | The Publisher's `domain`, a Canonical Host (§3.8) |
| `collection` | A Collection name in the form of §5.1 |
| `generated_at` | An instant in the whole-second profile of WIST-3 §3.1 (§3.4) |
| `size` | The number of Items the list holds, a nonnegative integer of §4's safe range; a value above `catalog_items_max` (WIST-4 §5) is `WIST1-E04` (§7) |
| `root` | `"sha256:"` followed by 64 lowercase hexadecimal digits: the root of the list (§4.1) |
| `tree` | The same form: the SHA-256 of the octets of the root tree file (§4.2) |

The Catalog ID is `"sha256:" + hex(SHA-256(JCS(catalog)))` (§4).

The **list** of a Catalog is the Items of the buckets of its tree in the
order of the walk (§4.2, WIST-2 §5), or the same list obtained from change
lists (WIST-2 §5). Every rule of this suite reads the list however it was
obtained.

**Order.** A Collection's Catalogs are ordered by `generated_at`, and a
Catalog replaces another of its Collection only with a later instant. The
**Catalog order** of one Publisher's Catalogs reads `generated_at` and,
between equal instants, the Catalog ID: the greater string in octet order is
the later. §5.2 applies it at a recovery settlement and WIST-3 §7 across
Logs.

A Catalog is authenticated by the binding check of §5.1, which reads
`generated_at`, and bound above by the clock rule of §3.4. The Catalog
conditions, and the Item conditions its list is judged by, are §7's. The
rule by which a Publisher chooses the `generated_at` of its next Catalog,
when a Catalog is due, and the refusals of the part of a Publisher that
signs are WIST-5's.

### 3.6. `payload` — the Payload Commitment

An Item of kind `page` commits to its content; it does not carry it. The
content — the main text (`extract`), the external links (`links`), and the
structured summary (`summary`) — travels as a separate **Payload**, named by
the Item ID (WIST-3 §6.1). The Item carries only the **Payload
Commitment**:

    commitment = "hmac-sha256:" + hex(HMAC-SHA256(key = salt,
                                                  message = JCS(content)))

where `content` is the object `{"extract": <string>, "links": <object>,
"summary": <object>}` and `salt` is at least 16 octets drawn from a
cryptographically secure random source, fresh for every new Item. An Item
whose content has not changed is kept as it is, its salt included. The salt
travels with the Payload and never appears in the Log.

The salt is what makes withdrawal effective. A bare hash of a withdrawn
extract would still let anyone holding a copy of the text demonstrate that
it was the text committed to; with a salt that is destroyed alongside the
bytes, the commitment becomes unlinkable to any candidate text.

**Size caps, and the unit they are measured in.** Every cap in this
section counts **octets of a JCS serialization**, never characters and
never code points, because a cap a Consumer uses to bound a fetch has to
be a count of the bytes on the wire. Precisely:

- the `extract` cap is the UTF-8 octet length of `JCS(<the extract
  string>)` — the JSON string literal, its enclosing quotes and any
  escapes included — and MUST NOT exceed `extract_cap_bytes` (WIST-4 §5);
- the `links` cap is the UTF-8 octet length of `JCS(<the links
  object>)` and MUST NOT exceed `links_cap_bytes` (WIST-4 §5), and each
  member of `links.urls`, measured as the UTF-8 octet length of
  `JCS(<the url string>)`, MUST NOT exceed `link_url_cap_bytes`
  (WIST-4 §5);
- the `summary` cap is the UTF-8 octet length of `JCS(<the summary
  object>)` and MUST NOT exceed `summary_cap_bytes` (WIST-4 §5);
- `bytes` is the octet length of `JCS(content)` and MUST NOT exceed the
  **derived cap** `extract_cap_bytes + summary_cap_bytes + links_cap_bytes
  + 32`, 38944 under the default values: `JCS(content)` is
  `{"extract":<E>,"links":<L>,"summary":<S>}`, whose 32 octets of
  structure surround the three serialized values. Amending any of the
  three parameters moves it.

A validator MUST reject a Payload that, once retrieved, does not have
exactly the declared length, exceeds any of the caps above, or does not
reproduce `commitment` under the accompanying salt (`WIST1-E04`,
`WIST1-E10`). What an Aggregator does with the Item is WIST-2 §5's.

**Size-cap parameter time.** The caps `url_cap_bytes`, `extract_cap_bytes`,
`links_cap_bytes`, `link_url_cap_bytes` and `summary_cap_bytes`, the derived
cap, §7's bound on `JCS(item)`, and `catalog_items_max`,
`tree_file_cap_bytes` and `tree_depth_max` (WIST-4 §5) use one parameter
map per validation attempt:

- For admission of a Catalog not yet sealed and of the Items of its list,
  read WIST-4 §5's accepted schedule at the validator clock when the
  Catalog's validation attempt begins. Retain that map through the walk
  and through the retrieval and verification of the Payloads of its
  Items. A new attempt after restart or refusal reads a new map; resuming
  the same attempt requires retaining its map or reconstructing it from
  its clock and authenticated prefix.
- Before sealing, the Aggregator MUST recheck every candidate Catalog and
  Item against the map in force at the candidate Epoch's `sealed_at`, and
  the Payload of an Item of kind `page` under that map at the Item's turn
  in that Epoch (WIST-3 §3.3). Admission does not freeze eligibility for
  sealing; pending amendments do not constrain a candidate before they
  become effective. A cap failure retains §3.2, §3.6 and §7's diagnostic
  and prevents inclusion.
- For an Entry sealed in the Log being verified, every validator MUST use
  the map in force at its Epoch's `sealed_at`, reconstructed from the
  authenticated accepted schedule through that Epoch. Retain this profile
  for later Payload retrieval, verification, replay and restart. A Payload
  read for a sealed Item retains the profile of the Entry that sealed the
  Item, wherever it is read.

An amendment effective exactly at the selected instant participates.
Timestamps in the object, later amendments and a later validator clock
MUST NOT change a sealed Entry's profile. These rules choose size caps
only; they do not change signature authority, clock-skew checks, Payload
integrity, availability or withdrawal obligations. See WIST-4 §5 and
[ADR-0020](../decisions/0020-parameter-schedules.md).

**The `links` member.** `links` declares the external links of the
published content. Where the content is emitted as an HTML fragment, they
are extracted from that fragment by WIST-2 §11's procedure; where it is
emitted as text, the Emission lists them in content order (WIST-5). `urls`
carries them as Normalized URLs (§2), deduplicated (the first occurrence
holds the position), truncated to the longest prefix whose serialized
`links` object fits `links_cap_bytes`; `total` is the count of all distinct
external links before truncation. A link is **external** when its
Canonical Host (§2) is neither the Publisher's domain nor a subdomain of
it. Only a Normalized URL can be a link: a candidate with no normalization
— a non-`https` scheme, a malformed percent-escape, a rejected host label —
is not a link for this specification, the same fail-closed posture §2
takes for an Item's URL. A link whose `JCS` serialization exceeds
`link_url_cap_bytes` is discarded as such a candidate is and not counted
in `total`; a Payload that declares one is `WIST1-E04`. `{"total": 0, "urls": []}`
is the REQUIRED form for content with no external links; an Emission of
text without `links` declares it.

A validator MUST reject with `WIST1-E12` a `links` member carrying a
duplicate, an entry that is not byte-identical to its own Normalized URL
(§2), a fragment, a non-`https` entry, an entry whose Canonical Host is
internal to the Publisher, or `len(urls)` greater than `total`. The
normalization rule is what makes the dedup rule mean anything: sameness
in this specification is byte-identity *of Normalized URLs* (§2), so
`https://EXAMPLE.ORG/reference` and `https://example.org/reference` are
one link declared twice. A member carrying both passes a bare byte-wise
uniqueness test, and the entry that is not its own Normalized URL then
joins against nothing in the graph consumers build across Payloads
(WIST-3 §7), where the URL string is itself the join key. Requiring each
entry to be already normalized keeps that key exact and the dedup rule
enforceable at ingest, against a Payload the validator sees on its own.
Equality of `len(urls)` and `total` follows once the full set fits.
WIST-2 §11 and §12 remain the suite's deterministic procedures. They apply
to the content a Publisher emits, and to a served page only for a party
that chooses to compare the page with the publication.

The Payload schema's `extract.maxLength` and `links.urls` item
`maxLength` describe the default profile; validators MUST apply the active
JCS-octet caps instead, without rejecting a value those caps permit.
`summary.title` and `summary.abstract` retain independent field limits of
256 and 1500 Unicode scalar values, respectively, without normalization,
in addition to the active summary octet cap. Field and semantic diagnostics
follow §7.

The commitment is what carries the Publisher's accountability across the
boundary, and it carries two distinct properties. It is **binding**:
producing a second content and salt that reproduce a commitment already
signed would require a SHA-256 collision, and the Publisher's freedom to
choose its own salt does not help, because the salt is an input to that
same hash and not a trapdoor. A Publisher therefore cannot serve one text
and later claim it declared another, and this holds against the Publisher
itself, not merely against third parties. It is **hiding**: once the salt
is destroyed, the commitment is the output of a keyed function under a key
nobody holds, so a party holding a copy of the original text cannot
demonstrate that the copy is what was committed to. Binding survives
withdrawal for the Items whose Payloads still exist; hiding begins at
withdrawal. The salt is what separates them, which is why it MUST be
unpredictable and unique per new Item: a Publisher that derives salts from
the content, or reuses one across Items, keeps the binding and forfeits the
hiding.

### 3.7. `meta`

Descriptive metadata of an Item of kind `page`: `lang` is REQUIRED and uses
the schema's lexical language-tag profile: two or three lowercase ASCII
letters followed by zero or more hyphen-separated subtags of one to eight
ASCII alphanumerics. Validation requires this complete spelling, without
language-registry lookup, subtag ordering or uniqueness checks. `topics`
permits at most ten free-form strings of at most 64 Unicode scalar values
each; `license` is a string of at most 64 scalar values declaring the
content's license.

`meta` is the one descriptive field that lives inside the Item rather than
in the Payload, so it is sealed with the Item's Entry and is outside the
withdrawal mechanism entirely: it can never be erased. A Publisher MUST NOT
place personal data in `meta`, `topics` included, whatever the published
content carries — the allowance §9 grants a Payload does not extend here,
because the basis for that allowance is that a Payload can be withdrawn and
`meta` cannot. Where the content's subject is a person, that belongs in the
Payload's `summary`.

### 3.8. `publisher`

The REQUIRED Canonical Host (§2) of the Publisher, in a Catalog and in every
Item. It MUST equal its own Canonical Host bytes, using the same host
profile as Declaration `domain` (§5.1). Missing, non-string or noncanonical
values are `WIST1-E14`, checked before semantic rejection or idempotent
acceptance. Validators MUST NOT normalize or insert this field into signed
bytes.

A Catalog's `publisher` is its Publisher's `domain`. Only the Declaration
history of exactly that domain supplies the authority, the Collections, the
Scopes and the signing bindings for the Catalog and for the Items it lists
(§5): a Catalog judged under no Declaration of that domain has no candidate
and is `WIST1-E02`, even when another domain has a verifying key. An Item
whose `publisher` is not its Catalog's is refused alone with `WIST2-E03`
(§7); the Publisher of an Item's Entry is its named Catalog's (WIST-3
§3.3). A matching key in another domain's Declaration, a URL hostname or
ancestor, a serving location or a materialization preference MUST NOT
substitute another Publisher. An Item's URL must satisfy this named
Publisher's literal scope (§3.2), including explicitly listed hostnames
outside its ancestry.

Every Canonical Host is a separate Publisher identity. It is not a
separate accounting unit: the Ping quota, the ingest budget and the
per-domain Epoch capacity are keyed on the host's Registrable Domain
under the Public Suffix List snapshot in force (WIST-4 §3.1), so two
hosts under one registrable name share those bounds while sharing no
key, Collection or Scope.

`publisher` is inside `JCS(catalog)` and `JCS(item)`: the signature and the
Catalog ID bind the Catalog's, and the Item ID and the leaf, hence the
root, bind each Item's. Changing it requires signing changed bytes and
produces a different ID; changing only `sig.key_id` cannot change the
Publisher. Re-signing an unchanged inner object after a rotation preserves
the Catalog ID. Public-key sharing and copied public bindings do not
transfer authorship or invalidate another domain's otherwise valid Catalog.
See [ADR-0029](../decisions/0029-signed-delta-publisher.md).

## 4. Canonicalization and Identity

Signing JSON requires a byte-exact canonical form. WIST uses the
JSON Canonicalization Scheme (JCS) [RFC 8785]:

1. **Canonical Bytes** = `JCS(catalog)` — the inner object only, never the
   Envelope.
2. **Catalog ID** = `"sha256:" + hex(SHA-256(Canonical Bytes))`.
3. **Signature** = `Ed25519-sign(private_key, Canonical Bytes)`,
   base64url without padding under §2. A correctly encoded signature that
   does not verify against Canonical Bytes under the key `sig.key_id` names
   is `WIST1-E01`.

**Valid JCS input.** Valid JCS input is UTF-8 octets that parse under
JSON's grammar [RFC 8259] with no repeated member name in any object, every
string a sequence of Unicode scalar values (an escaped lone surrogate is
none), every number denoting a finite IEEE-754 double, and arrays and
objects nested at most 64 levels deep, the top-level value being level 1.
Anything else is `WIST1-E05`, for every object the suite parses; where a
containing object is refused whole for an object inside it, the
container's code stands: a tree file `WIST2-E07` and a change list
`WIST2-E08` (WIST-2 §5). Member
names are compared after their escapes are decoded, as I-JSON [RFC 7493]
compares them.

**A number is the double it denotes.** RFC 8785 §3.2.2.3 serializes a JSON
number by the ECMA-262 `Number::toString` algorithm over the IEEE-754
double the literal denotes, so canonicalization is defined on that double
and on nothing else. Two consequences follow, each a way for two parties
to disagree about the identity of the same octets.

The first is on the parse side. Canonicalization is only well defined if
every party recovers the *same* double from the same octets, which requires
the correctly-rounded conversion ECMA-262 already specifies: the double
nearest the literal's exact value, ties to even. A parser off by one unit
in the last place produces a different double, hence different Canonical
Bytes, hence a different ID for a document neither party has altered.
A validator MUST convert with correct rounding, and a validator that cannot
MUST NOT seal what it read.

The second is on the identity side. Distinct literals can denote one
double — `9007199254740993` and `9007199254740992` are the same double —
so identity in this suite is identity of the double, not of the literal a
producer typed. A producer therefore MUST NOT rely on integer precision
beyond ±(2^53 − 1) to distinguish two objects, and every integer member the
suite defines MUST lie inside that range, in addition to its field-specific
bounds; a number outside it is a producer's error, not a second identity.
What has no double at all — a magnitude beyond the finite range, or a form
outside JSON's grammar — has no canonicalization either, and is
`WIST1-E05`. A finite double, integral or not, always has one: a validator
MUST NOT reject a number merely for carrying a fractional part, since
WIST-4 §5.1 leaves the `details` of several Registry Update actions
unconstrained and one such member would otherwise make an entire Epoch
unverifiable.

**What verification means, exactly.** RFC 8032 §5.1.7 leaves choices open
that a Log cannot leave open: two verifiers resolving them differently
disagree about whether a sealed Entry is valid, and that disagreement is a
fork. This suite pins them, for every signature it defines:

- The verification equation is the **cofactorless** one, `[s]B = R + [k]A`,
  checked without multiplying either side by the cofactor. Recomputing `R`
  and comparing its encoding to the signature's is the same check and is
  permitted.
- `s` MUST be canonically reduced, `0 ≤ s < L`. Adding `L` to `s` leaves
  `[s]B` unchanged, so a verifier that omits this check accepts a second
  signature for the same message under the same key.
- `A` and `R` MUST each be canonically encoded — the encoded `y` less than
  `p = 2^255 − 19` — and MUST NOT be a point of small order.

A signature failing any of these is `WIST1-E01`. A key entry (§5.1) whose
public key is non-canonically encoded or of small order is not admitted to
any usable set at all, and a Catalog naming it is `WIST1-E02`: the check
belongs where the key enters, so that a Publisher cannot publish a key
every verifier would otherwise reject one Catalog at a time, and so that
the keys a Consumer replays are the keys the Aggregator ingested against.

**Excluded Declaration keys.** Exclusion derives usable key sets; it does
not remove or rewrite entries in the signed Declaration, and an unused
excluded key alone MUST NOT cause the Declaration to be rejected. After
§5.1's field checks, exclude any entry whose decoded public bytes do not
decode to a canonical Ed25519 point or represent a small-order point. Apply
this to `keys`, `recovery_keys` and the `keys` of every Collection, before
collecting §5.2's signer candidates, classifying the verified public key or
collecting a Catalog's candidates. For Declaration authentication, a named
identifier with only excluded bindings has no candidate (`WIST1-E02`); at
least one usable named binding but no verifying signature is `WIST1-E01`.
Check every usable named binding from the eligible predecessor and incoming
signing array, even if another binding of that identifier was excluded. The
same exclusion applies when deriving keys for Catalogs and Labels. A
Catalog's binding check also applies §5.1's per-binding window before
signature diagnostics; Declaration authentication applies no such time
filter.

Retain the original Envelope for signatures, hashes, predecessor links,
idempotence and recovery-set byte protection. Key uniqueness and cross-set
disjointness in §5.2 apply to all signed entries before exclusion; excluded
entries cannot hide a duplicate or permit an otherwise forbidden
recovery-set change. A structurally nonempty `keys` array MAY yield an empty
usable signing set: a replacement authenticated by a usable predecessor key
is still accepted, but no Catalog can authenticate under that empty set.
An initial Declaration with no usable signing key cannot self-authenticate
and is `WIST1-E02`. Likewise, a nonempty signed `recovery_keys` array with no
usable recovery key remains protected; exclusion gives no signing key the
authority to change it. A Publisher must keep a usable recovery key to retain
that recovery path. Declaration authentication does not filter keys by their
`nbf` and `exp` window; §5.1 applies it when checking a Catalog.

The profile chosen is the one libsodium applies by default and the one
`ed25519-dalek`'s strict verification implements, so an implementation
inherits it from its library rather than hand-rolling a WIST-specific mode
— which is the practical difference between a pinned rule and a followed
one. The alternative profile (cofactored verification, non-canonical
encodings accepted) also yields agreement among verifiers that adopt it,
but it admits a small-order `A` under which one signature verifies for many
keys, and this suite anchors identity to keys.

The Envelope carries the result:

```json
{
  "catalog": { ... },
  "sig": {
    "key_id": "1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y",
    "alg": "Ed25519",
    "value": "<base64url signature, 86 characters>"
  }
}
```

**One construction, for every signed object in the suite.** Every signed
object in WIST is built exactly as above: the Envelope's single inner
object is canonicalized with JCS, those Canonical Bytes are signed with
Ed25519, and the signature is detached into `sig`. Where WIST-1 to WIST-4
define other signed objects — the Publisher Declaration, the Label Feed
and its Pages, the Log Anchor, the Snapshot Index and Manifest, the Label,
the Registry Update — this rule applies unchanged, and each of those
documents names only which inner object it wraps. A verifier that
implements it once implements it for the whole suite, and there is no
per-object signing variant to get wrong.

The Checkpoint (WIST-3 §5) is the one signed object outside this
construction: it is a signed note in the C2SP formats WIST-3 §5 names,
signed with the same Ed25519 Aggregator keys over the note text rather
than over JCS bytes, so that Witnesses and generic transparency-log
clients verify it unmodified. A Log Entry carries no signature of its
own: it is a leaf of the tree (WIST-3 §3.3, §4), authenticated by an
Inclusion Proof against a Checkpoint; the Envelope inside it is verified
under this construction, and an Item inside it by its Inclusion Proof
against a Catalog (§4.3).

Identity is content-derived: two Catalogs or two Items that differ in any
octet of their Canonical Bytes are distinct objects, and the same octets
have the same ID in every Log. A Catalog served again is an idempotent
re-serve under §7, not an error.

The Payload is outside every construction. The Canonical Bytes of an Item
cover its `payload` commitment, never the content it commits to, so the
Item ID, the leaf, the root, the Catalog ID, the signature and every Merkle
root derived from them are computed without the content and stay valid
when the content is withdrawn (WIST-3 §6.2). A Payload is authenticated by
recomputing the commitment (§3.6), not by any signature of its own.

### 4.1. Item Identity and the Root

| Value | Definition |
|---|---|
| Item ID | `"sha256:" + hex(SHA-256(JCS(item)))` |
| Key | `SHA-256(JCS(["page", url]))`, over the string `url` as the Item spells it, for both kinds |
| Leaf | `SHA-256(0x00 ‖ key ‖ SHA-256(JCS(item)))` |
| Root | The Merkle Tree Hash of WIST-3 §4 whose leaf hashes are the leaves, taken in ascending octet order of key and not hashed again, a node being `SHA-256(0x01 ‖ left ‖ right)`; `SHA-256("")` for an empty list |

An Item of kind `removed` takes the key of the page at its URL, so it
replaces that page's Item in the list. A list holds at most one Item per
key (§4.2). The Payload of an Item of kind `page` is named by its Item ID
(WIST-3 §6.1).

### 4.2. Tree Files

A Catalog's list is served as a tree of files, each named by the SHA-256 of
its octets, at the paths of WIST-2 §5. A tree file is the JCS serialization
of one object with exactly one member, and is of the kind that member
names.

| Kind | Member |
|---|---|
| Bucket | `items`, an array of Items in strictly ascending octet order of key. Each element is an object with a string member `url` |
| Inner file | `children`, an array of 1 to 16 objects with exactly the members `prefix`, `count` and `file` |

Every tree file has a **prefix**, a string of lowercase hexadecimal digits:
the root tree file has the empty one, and a child has the `prefix` of the
entry that names it. In an inner file each `prefix` is the file's own
prefix followed by one digit, and the entries are in strictly ascending
order of `prefix`; `count` is an integer of at least 1, the number of Items
the child's subtree lists; `file` is `"sha256:"` followed by the 64
lowercase hexadecimal digits of the SHA-256 of the child's octets. In a
bucket the lowercase hexadecimal spelling of every Item's key begins with
the bucket's prefix. A bucket lists as many Items as the entry that names it
counts, and the counts of an inner file's entries add up to the count of
the entry that names it; the root tree file is counted by the Catalog's
`size`. The root tree file is at level 1 and a child one level below its
parent; a file at level `tree_depth_max` (WIST-4 §5) is a bucket. No tree
file holds more than `tree_file_cap_bytes` octets (WIST-4 §5), and no list
more than `catalog_items_max` Items (WIST-4 §5).

A Publisher chooses where its tree divides. An empty Collection has one
tree file, a bucket with no Items. A bucket element is judged as an Item by
§7's Item conditions; the tree rules read only its `url`, from which its key
is computed. A Catalog whose tree breaks a rule of this section is refused
whole under WIST-2 §5 (`WIST2-E07`).

### 4.3. Inclusion Proofs

An Inclusion Proof of an Item is the object of WIST-3 §4,
`{"index": …, "tree_size": …, "path": […]}`: `index` is the Item's
position in the list, from 0; `tree_size` is the Catalog's `size`; `path`
holds the sibling hashes from the leaf up, each 64 lowercase hexadecimal
digits. `index` and `tree_size` are nonnegative integers of §4's safe
range, by value and not by spelling. A proof of another form is
`WIST1-E14`.

A proof is verified against one Catalog as WIST-3 §4 verifies a proof
against a Checkpoint, from the leaf of §4.1. It fails with `WIST1-E17`
when `tree_size` is not the Catalog's `size`, when `index` is not below
`tree_size`, when the walk lacks a `path` element or leaves one unread, or
when the hash it ends with is not the Catalog's `root`. The Entry that
carries an Item with its proof is WIST-3 §3.3's `publisher_item`.

## 5. Publisher Identity and Key Discovery

### 5.1. The Publisher Declaration

A Publisher declares its identity at:

```
https://<domain>/.well-known/wist/publisher.json
```

The document is an Envelope whose inner object is `publisher` (schema:
[`schemas/publisher.schema.json`](../schemas/publisher.schema.json)),
containing: `wist_version`, `domain`, `seq` (a monotonic Declaration
counter, starting at 0; see §5.2), `prev_declaration` (the hash of the
Declaration this one replaces; REQUIRED when `seq` > 0, absent only for
`seq` 0; see §5.2), optional `subdomain_scope` (hostnames the Publisher's
authority also covers), the `keys` array of signing entries (see **Key
entries** below), optional `recovery_keys` (same item shape as `keys`; see
§5.2), optional `next_keys` (a Key Set fingerprint committing to the next
signing set; see §5.2), optional `collections` (see **Collections** below),
and optional `contact`.

**Key entries.** Each entry of `keys`, of `recovery_keys` and of a
Collection's `keys` is an Ed25519 JSON Web Key (RFC 8037) with exactly the
members `kty` (`"OKP"`), `crv` (`"Ed25519"`), `x` (the raw public key in
canonical base64url, §2), `kid`, `nbf` and optionally `exp`. `kid` MUST
equal the entry's JWK thumbprint (RFC 7638): the unpadded base64url
encoding of SHA-256 over the JCS serialization of `{"crv": "Ed25519",
"kty": "OKP", "x": <x>}`. The `keys` array is the `keys` member of a JWK
Set (RFC 7517), and a signature block (§4) names an entry by its `kid` in
`key_id`. `nbf` and `exp` are NumericDate integers (RFC 7519 §2): seconds
since 1970-01-01T00:00:00Z ignoring leap seconds, from 0 to 253402300799.
`exp`, when present, MUST be greater than `nbf`. A `kid` that is not the
thumbprint of `x`, or an `exp` not greater than `nbf`, is `WIST1-E14`.

**Owner and Collection keys.** `keys` are the owner's: they sign
Declarations and the Catalogs of every Collection. A Collection's `keys`
sign that Collection's Catalogs and nothing else. A public key appears once
across `keys`, `recovery_keys` and every Collection (§5.2, **Unique
keys**).

**Key Set fingerprint.** The fingerprint of a signing set is
`"sha256:" + hex(SHA-256(JCS(kids)))`, where `kids` is the JSON array of
the set's `kid` strings in ascending byte order. The fingerprint of a
Declaration's signing set covers `keys` alone, never a Collection's `keys`.
§5.2 uses it for `next_keys`; the DNS record below publishes it.

**DNS fingerprint record.** A Publisher MAY publish a TXT record at
`_wist.<domain>` whose content is `v=wist1; keys=<fingerprint>` for the
signing set of its current Declaration, and SHOULD update it with every
change of that set. The record carries no key and is not a discovery
channel (§8): a validator MAY query it and report a mismatch or an absent
record, and MUST NOT let the result change whether a Declaration or a
Catalog is accepted.

**Collections.** A Declaration MAY carry `collections`, an array of one or
more objects with exactly the members `name`, `scope` and, optionally,
`keys`:

| Member | Form |
|---|---|
| `name` | 1 to 32 octets of lowercase ASCII letters, digits and `-`, neither beginning nor ending with `-`; it names one Collection of the array |
| `scope` | An array of one or more entries, each an object with exactly the members `url` and `match` |
| `keys` | An array of key entries in the form above; an absent `keys` and an empty one are the same |

A Scope entry's `url` is byte-identical to its own Normalized URL (§2) and
`JCS(url)` is within `url_cap_bytes` (WIST-4 §5); its `match` is `prefix`
or `exact`. A member of another form, an empty `collections` and an empty
`scope` included, is `WIST1-E14`: a list emptied by a fault of the tool that
writes the Declaration would otherwise remove every record it governs. The
Declaration is rejected with `WIST1-E16` when a `name` repeats, when an
entry's host, compared as a Canonical Host without the port, equals neither
`domain` nor a member of `subdomain_scope`, when an entry of one Collection
covers an entry of another, or when `collections` holds more than
`collections_max` (WIST-4 §5) Collections or a `scope` more than
`scope_entries_max` (WIST-4 §5) entries.

A `prefix` entry covers every Normalized URL that begins with the entry's
`url`; an `exact` entry covers that URL alone. Coverage compares octets of
Normalized URLs, the port included, and reads neither path segments nor the
query: a `prefix` entry `https://example.com/blog` covers
`https://example.com/blogs` and `https://example.com/blog?p=1`. An entry
covers another entry when it covers that entry's `url`, whatever the other's
`match`, so a URL lies in at most one Collection's Scope. Entries of one
Collection may cover each other or repeat. A Collection's Scope covers the
URLs its entries cover.

A Declaration without `collections` has one Collection, `default`, whose
Scope covers every URL whose host equals `domain` or a member of
`subdomain_scope`, and which has no keys of its own. A Declaration with
`collections` MAY name one of them `default`; that Collection continues the
implicit one, so its records and the order of its Catalogs persist across
the two forms. Where `collections` is present, a URL outside every Scope
cannot be published by any key. `vectors/wist1/collection-fields.json`,
`collection-scope.json` and `collection-keys.json` carry the Collection
forms, coverage, disjointness and keys.

**Size.** A Declaration whose `publisher_declaration` Entry (WIST-3 §3.3)
has a JCS serialization above 65 535 octets is rejected with `WIST1-E04`.
The counts `collections_max` and `scope_entries_max` and `url_cap_bytes` are
read for a Declaration at the instants §3.6's size-cap parameter time
gives: at the validation attempt that accepts it, and before sealing under
the map in force at the candidate Epoch's `sealed_at`. A fetched
Declaration whose `publisher` object is that of the current Declaration or
of the pending head, both read in the admission state, where a discovered
Declaration not yet sealed counts, or that of an open window's
recovery-chain head (§5.2), is not read against them or against the Entry
bound again; an answer 304 and an answer 200 carrying that object give the
same result (WIST-2 §5). Neither is a `publisher_declaration` Entry that
repeats the current Declaration or the pending head read against them on
replay: it is idempotent under any parameter map. §5.2, **An accepted
Declaration that fails at sealing**, gives the effect of a failure at the
candidate Epoch.

**Signed host representation.** `domain` and each `subdomain_scope` member
MUST be byte-identical to its own Canonical Host (§2), using the pinned
Unicode version and flag profile. This is the `wist-canonical-host` format:
canonicalization must succeed and reproduce the original string exactly.
It replaces JSON Schema's `hostname` format for these fields. A regular
expression for ASCII labels alone does not validate an `xn--` A-label;
its decoded label must also satisfy §2's processing rules.

Uppercase, a trailing dot and U-label spellings are therefore invalid signed
representations even when they canonicalize to an eligible host. A Publisher
canonicalizes names before signing; a validator MUST NOT normalize signed
members. Leading, trailing and third/fourth-position hyphens remain permitted
where §2 accepts them. The format adds no requirement for two labels, an
alphabetic final label, a public suffix or DNS registration; discovery and
role-specific requirements still apply.

After field validation, Publisher identity equality is byte equality of
`domain`, including sequence/conflict grouping, recovery heads, identity
resets and references to that Publisher. Noncanonical spellings do not form
separate identities or merge into an accepted Declaration: they fail field
validation before grouping. Scope members use the same representation but
do not change the Declaration's Publisher identity. Label Feed and status
`domain`, Publisher-domain Snapshot fields, and Registry Update `subject`
when it names a Publisher use this same format and exact identity. This does
not apply a hostname format to subjects that name parameters or keys. Each
object's existing failure disposition and diagnostic remains applicable.

**Declaration field validation.** A validator MUST reject a canonicalizable
Declaration Envelope that violates its schema or the integer range in §4
with `WIST1-E14`. This includes missing required members, wrong JSON types,
unknown members, optional members present as `null`, empty `keys`, string
bounds, noncanonical or malformed host fields, a key entry whose `kid` is
not its thumbprint or whose `exp` is not greater than `nbf`, a Collection
or Scope entry of another form, and malformed signature-field encodings.
Schema `format` constraints are assertions, not optional annotations. Apply
the fields' specified formats; `nbf` and `exp` are integers, never timestamp
strings. A valid encoding that fails cryptographic key or signature
verification is governed by §4 and §5.2, not this syntax error. The
schema's fixed `maxItems` on `collections` and on a Scope's entries and its
`maxLength` on a Scope entry's `url` describe the default profile: a
validator applies `collections_max` and `scope_entries_max` (`WIST1-E16`)
and `url_cap_bytes` (`WIST1-E14`) from the parameter profile required at its
validation stage (WIST-4 §5), and the fixed schema values MUST NOT reject a
Declaration that profile permits.

Perform this field validation before the Collection checks above,
Declaration sequencing, same-Epoch conflict comparison, idempotence or
signer resolution, including for a re-serve of the current `publisher`
object. Do not repair, strip, coerce or normalize signed members to make a
malformed Envelope acceptable. Invalid JCS input remains `WIST1-E05`. For a
structurally valid Declaration, §5.2's semantic sequence, predecessor and
key checks retain `WIST1-E08`; for example, absence of `prev_declaration`
at `seq` > 0 is that semantic error, while a present malformed hash is
`WIST1-E14`. A failed Declaration check during Epoch replay rejects the
whole Epoch under §5.2, including its tentative settlements and other
domains' transitions. First-contact Declaration pull failure remains
wrapped as `WIST2-E04` under WIST-2 §5; the WIST-1 code identifies the
underlying failure.

Discovery MUST use HTTPS; there is no alternative channel. A validator MUST
NOT accept a Publisher Declaration served over plain HTTP, and MUST NOT
follow a redirect whose target host is outside the Publisher's authority
(WIST-2 §8). An Aggregator fetches the Declaration at the start of every
pull and pulls the Publisher's Collections only under the sources §5.2
gives (WIST-2 §5); no Declaration is read from a cache in its place.
Historical replay and sealing use their Log-derived sources (§5.2); they
MUST NOT substitute live discovery for those sources.

**Binding check.** `nbf` and `exp` bound each signing binding's use. After
field validation, collect every signing entry whose `kid` equals the
Catalog's `sig.key_id` from `keys` and from the `keys` of the Collection the
Catalog names, in the source Declaration §5.2 authorizes for exactly
`catalog.publisher` (§3.8); where §5.2 authorizes two sources, each is read
alone. No other domain's bindings and no other
Collection's keys participate: a `sig.key_id` that names only a key of
another Collection has no candidate. Exclude unusable public keys under §4,
then exclude each binding whose window does not contain the Catalog's
`generated_at`: a binding is eligible when `nbf` ≤ `generated_at` and, if
`exp` is present, `generated_at` < `exp`, comparing the instant as integer
seconds with the NumericDate integers. If no binding remains, reject with
`WIST1-E02`. Otherwise verify the signature against every remaining
candidate until one succeeds under §4; accept this key check if any
succeeds, or reject with `WIST1-E01` if none does.

An eligible binding must itself satisfy both the window and the signature
check. A verifying signature under a binding outside its window cannot
borrow another binding's window. In particular, one eligible binding with a
failed signature plus one out-of-window binding with a valid signature is
`WIST1-E01`; all named bindings being excluded or out of window is
`WIST1-E02`, regardless of their signature results. The field failures of
§2 and §3.4 retain `WIST1-E14` precedence. Other Catalog checks and
object-specific dispositions, including recovery settlement's `WIST1-E13`,
remain applicable; across distinct checks, §7 permits any established
applicable diagnostic, and the binding check itself retains the E02/E01
distinction above.

Preserve complete `(kid, nbf, exp)` bindings across the authorized sources;
one key listed by two sources with different windows keeps both. Candidate
or source iteration order MUST NOT affect acceptance or its diagnostic.
Recovery-only entries and pending Declarations (§5.2) supply no Catalog
authority. Backdating a Catalog to before every authorized binding existed
therefore fails this check, as does dating it after every binding expired.
An Item is not signed: it is authenticated through its Catalog, by the
binding check of the Catalog its Entry names (WIST-3 §3.3) and its
Inclusion Proof (§4.3).

### 5.2. Sequencing, Rotation and Recovery

Every Publisher Declaration carries a monotonic `seq`, starting at 0. A
Declaration with `seq` > 0 MUST include `prev_declaration`,
`"sha256:" + hex(SHA-256(JCS(publisher)))` computed over the *previous*
Declaration's inner `publisher` object — the Declaration this one
replaces. A validator MUST reject a Declaration under `WIST1-E08` when:
`seq` is not greater than the highest it has already accepted for that
domain; or `seq` > 0 and `prev_declaration` is absent; or
`prev_declaration` does not equal the hash of an eligible predecessor's
`publisher` object under the recovery-head rules below. Outside recovery,
that predecessor is the current Declaration. This makes replay of a
superseded Declaration detectable rather than silent.

Re-serving the current Declaration is not that replay: a Declaration
whose inner `publisher` object is byte-identical under JCS to the one
current for the domain — equivalently, one with the same hash of its own
`publisher` object — is an idempotent acceptance, not `WIST1-E08`. An
Aggregator fetches the Declaration at every pull (§5.1), so a rule
rejecting what that fetch returns would reject every stable Publisher in
the system. A Declaration carrying an already-accepted `seq` with any other
bytes is `WIST1-E08` as above — that is precisely the superseded-replay and
same-`seq`-mutation case the rule exists to catch.

Key rotation is performed by publishing a Declaration whose envelope is
signed by a key from the **previous** Key Set. The first Declaration a
domain publishes (`seq` 0) is self-signed. A key is revoked by publishing
a Declaration that omits it. A Declaration that lists the outgoing key
with an `exp` beside the incoming key gives the two an overlap window in
which Catalogs verify under either (§5.1); the outgoing key keeps its
Declaration signing authority until omitted. The `nbf` and `exp` windows
bound Catalogs only: signer resolution and classification below use set
membership regardless of the window.

**Rotation commitment.** A Declaration MAY carry `next_keys`, the Key Set
fingerprint (§5.1) of the signing set its next ordinary rotation will
install. When the eligible predecessor carries `next_keys`, a replacement
classified below as an ordinary rotation MUST either keep the
predecessor's signing `kid` set and its `next_keys` unchanged, or list a
signing set whose fingerprint equals the predecessor's `next_keys`; any
other ordinary rotation is `WIST1-E08`. The replacement MAY carry its own
`next_keys`. A recovery rotation and a fresh identity are not bound by the
predecessor's commitment. The commitment reads `keys` alone: a Collection's
`keys` change under it freely. Publishers SHOULD generate the committed
keys before committing and hold them apart from the current signing keys,
so that a party holding only the current signing key can rotate to nothing
it controls.

**Recovery keys.** A Declaration MAY list `recovery_keys` alongside its
signing `keys`. Recovery keys sign nothing but Declarations and are
meant to be held offline. They are the protocol's only proof of
publisher continuity, because domain control alone cannot distinguish a
Publisher recovering from key loss from a party that has merely acquired
the domain.

Recovery keys protect themselves. Once a Declaration lists a non-empty
`recovery_keys`, every later Declaration not signed by one of them MUST
carry a byte-identical `recovery_keys` — a Declaration signed by a
signing key and one signed by neither set, the fresh identity below,
alike; a Declaration that adds, removes, or alters a recovery key MUST be
signed by one of the recovery keys it is replacing, and is rejected with
`WIST1-E08` otherwise. Without this rule the mechanism would be worthless:
a thief holding a signing key could rotate and drop the recovery keys in
the same Declaration, permanently severing the owner's path back — and a
thief holding only the web server could do the same with a fresh identity,
which is why the rule reads the signer and not the classification:
whatever a Declaration is, only a recovery key can change the recovery
keys. A Publisher whose previous Declaration lists no recovery keys MAY
establish them with an ordinary signing-key signature — there is nothing
yet to protect — which is how a Publisher adopts recovery keys after the
fact.

The two sets are disjoint. A Declaration MUST NOT list the same public
key (`x`, equivalently `kid`) in both `keys` and `recovery_keys`, and one
that does is rejected with `WIST1-E08`. A recovery key that is also a signing
key is neither held offline nor signing only Declarations, so it offers
nothing the signing key it duplicates does not already offer, and stealing
one steals both. The rule is also what keeps the classification below
answerable: whether a Declaration opens a recovery window is state every
replaying party must derive identically, and a signer present in both sets
would leave two defensible answers.

**Unique keys.** A Declaration MUST NOT list the same public key twice
within `keys`, within `recovery_keys` or within one Collection's `keys`,
or in any two of `keys`, `recovery_keys` and the `keys` of each Collection,
even when the repeated entries are identical. Reject such a Declaration
with `WIST1-E08`, including a first (`seq` 0) Declaration. Because `kid` is
the key's thumbprint (§5.1), an identifier names at most one key and a key
carries one identifier: for a Catalog, `sig.key_id` selects at most one
entry within each authorized source, and §5.1 checks the selected
binding of each source read alone. This rule is a semantic constraint
beyond the Declaration schema.

**Declaration signer resolution.** For a replacement Declaration, collect
the entries named by its `sig.key_id` from the eligible predecessor named
by `prev_declaration` (as defined below), using that Declaration's `keys`
and `recovery_keys`, and from the incoming Declaration's `keys`. No
candidate comes from a Collection's `keys`, the predecessor's or the
incoming Declaration's. Verify the Envelope against those candidate public
keys using §4's signature profile, excluding unusable bindings under §4
first. No usable named candidate is `WIST1-E02`; usable named candidates
but no verifying signature is `WIST1-E01`. The same `kid` in both sources
names the same key. The first Declaration instead resolves its signer only
from its own `keys`. A Declaration signed by a key its predecessor lists in
a Collection therefore authenticates only when it lists that key in its own
`keys`, and is then a fresh identity; otherwise it is `WIST1-E02`.

Classify the authenticated public key by membership in the predecessor's
`keys` and `recovery_keys` alone: membership in the previous signing set is
ordinary rotation, membership in the previous recovery set is recovery
rotation, and membership in neither is fresh identity. A Declaration signed
by a Collection key is signed by neither set and is a fresh identity,
treated as a fresh identity is in the state in which it is accepted:
pending and reversible outside a recovery window, a competitor inside one.
Recovery-key protection still applies to the resulting classification. The
rule does not authorize an incoming recovery key to authenticate its own
installation.

**Same-Epoch Declaration conflicts.** For each domain, process the Epoch's
Declarations in groups of equal `seq`, in ascending `seq`, after settling
any due recovery window. Evaluate each group against the state after all
lower-sequence groups, before applying any member of this group. If every
member's canonical `publisher` bytes equal the current Declaration's, the
group is idempotent: it installs no Declaration or signature. Otherwise,
every member MUST have identical canonical Envelope bytes, including `sig`;
validate and apply that one Envelope once. Exact repeats have no additional
effect. For structurally valid Envelopes, test group equality before any
member's signature; do not filter invalid signatures to select a winner.
Distinct Envelopes in such a group invalidate the entire Epoch
under `WIST1-E08`, even if each would be admissible alone, or they differ
only in signatures over the same `publisher` object. This applies to initial
(`seq` 0) Declarations and inside recovery windows as well as outside them.
Equal sequences for different domains do not conflict. Canonical leaf order
MUST NOT select a winner or make another member an idempotent re-serve by
installing the first member. A repeated Envelope does not waive any ordinary
sequence, predecessor, key or signature check on its first installation.

An Aggregator MUST NOT seal an Epoch with a conflicting Declaration group.
A Consumer encountering one MUST reject the entire Epoch, retaining its
previous accepted prefix and state; no Entry or settlement from that Epoch
takes effect. The same whole-Epoch rejection applies when a Declaration
fails its acceptance checks during Epoch replay, with that check's error
code. If different domains have different acceptance failures, a validator
MAY report any of those applicable error codes; no cross-domain diagnostic
order is required. Rejection and retained state MUST agree regardless of
which error is reported. This rule governs sealed Epochs; it assigns no
winner among unsealed submissions or obligation to seal a rejected candidate.

**Accepted sequence and recovery heads.** For each domain, retain the
highest accepted `seq` independently of which Declaration is current.
Supersession MUST NOT decrease that sequence floor: every new Declaration,
including a legitimate recovery follower, MUST exceed it. A rejected
candidate and an idempotent re-serve change neither the floor nor any head.
For Log replay, acceptance here means acceptance in ascending
`(Epoch number, seq)` application order; unsealed submissions are not part
of the replayed floor.

Without an open recovery window or a pending head (below), only the
current Declaration is an eligible predecessor. Accepting a replacement
makes it current. A recovery rotation also establishes the
**recovery-chain head**, initially that same Declaration. While the window
is open, a new Declaration MAY name either the current Declaration (the
latest accepted replacement) or the recovery-chain head. No other ancestor
is eligible; an ineligible predecessor is `WIST1-E08`. The named
predecessor supplies every previous signing/recovery set used for
signature resolution, classification and recovery-key protection above.
Accepting a replacement always makes it current. It advances the
recovery-chain head only if it names that head and authenticates as an
ordinary or recovery rotation against it. A fresh identity, or a replacement
of a competitor, does not join the recovery chain. A later recovery rotation
inside the window does not change its owner or deadline.

For the Publisher's Catalogs and Items, the window contains Epochs from its
opening Epoch through those whose `sealed_at` is strictly earlier than its
end (**Publications during recovery**). Declaration competition instead
starts immediately after the owner's application in ascending
`(Epoch number, seq)` order. A Declaration applied earlier in the opening
Epoch is a predecessor, not a competitor, and is not superseded by this
window. Before applying any Declaration in the first Epoch at or after that
end, settle the window: make its recovery-chain head current, supersede its
accepted non-chain competitors, and close the window without changing the
sequence floor. Only the restored current head is then an eligible
predecessor; a superseded competitor is `WIST1-E08`. The same transition
applies to admission at or after the window's end. Re-serving the current
Declaration remains idempotent even when its `seq` is below the retained
floor. Re-serving any other accepted Declaration is `WIST1-E08`, including a
recovery-chain head that is not current while the window is still open.
Idempotence installs no new Declaration or signature and does not reopen a
window.

**Unsealed Declarations at settlement.** Admission and Log replay retain
their own accepted heads and sequence floors. At admission settlement, the
restored current head includes legitimate followers already accepted there,
even when they have not sealed. Queue settlement still uses only the
settlement source below, the last recovery-chain Declaration sealed
strictly before the deadline. An unsealed follower MUST NOT supply that
authority. Closing the admission window is persistent: later pulls and the
first deadline Epoch MUST NOT repeat that admission transition over
replacements already accepted after it. The sealed-history window closes
separately when a valid Epoch at or after the deadline applies.

Remove every superseded, still-unsealed non-chain Declaration from the
eligible sealing set, including ordinary, fresh and recovery descendants of
a competitor. Such a copy MUST NOT first install after the deadline. This is
an exception to the Declaration sealing obligation of WIST-3 §3.3: it
prevents a competing act from becoming a fresh identity or a new recovery
merely through delayed inclusion. Supersession adds no new rejection diagnostic; a re-serve
remains subject to the retained admission floor and current-object
idempotence. Previously sealed competitors remain in the Log and undergo
normal replay supersession. A Consumer cannot infer unsealed admission
history from an Epoch; the removal duty belongs to the Aggregator that
accepted those copies.

Retain pending legitimate recovery-chain followers in predecessor order.
They remain subject to every acceptance check at their actual sealing Epoch,
whose sequence floor excludes unsealed admission. In particular, a retained
recovery-signed follower first applied at or after the old deadline opens a
new window if none is then open; the first recovery in application order
owns it. Earlier admission inside the old window cannot suppress that
Log-derived effect. A new Declaration admitted at or after settlement
uses the restored current admission head and a sequence above the retained
admission floor. Its fresh or recovery classification has the normal
post-settlement admission semantics, rather than inheriting the closed
window's protection. Actual Log effects still follow sealing application
order: if a retained recovery follower opens a new window before a fresh
successor applies, that successor is a competitor inside the new window and
does not reset identity. `vectors/wist1/recovery-admission.json` separates
these admission and sealing traces, including the exact deadline and a copy
sealed just before it.

For example, let recovery R have `seq` 1, and let a fresh competitor F with
`seq` 2 name R. During the window a legitimate D signed by R's signing or
recovery key names R, not F, and uses `seq` greater than 2. If settlement
occurs before D arrives, R becomes current again, but D still needs `seq`
greater than 2. Naming F after settlement fails even with a valid signature.
These are Declaration acceptance and key-continuity rules.

For an admissible competing branch, suppose R replaces signing key k1 with
k2 and recovery key r1 with r2. A fresh F naming R may install k1 again only
while preserving R's r2 recovery set, with a valid signature under an incoming
signing entry. F's ordinary successor naming F remains outside R's recovery
chain, even if its authenticated signer also belongs to R's signing set.
That signer advances recovery only by naming the current recovery-chain head.
Restoring r1 without r2's signature fails recovery-key protection; such a
Declaration is rejected, not accepted for later supersession. Signed cases
and rejection twins appear in `vectors/wist1/recovery-settlement.json`.

**Pending identities and activation.** A fresh identity accepted outside
an open recovery window does not take effect at once. It is sealed as a
`publisher_declaration` Entry and becomes the domain's **pending head**;
the current Declaration is unchanged. Read `declaration_activation_epochs`
(WIST-4 §5) from the parameter map in force at the Epoch sealing the first
pending Declaration and freeze the **activation height**: that Epoch's
height plus the parameter. While a pending head exists, the eligible
predecessors are the current Declaration and the pending head. A
replacement naming the pending head is authenticated, classified and
checked against it as its predecessor, opens no recovery window whatever
signs it, and on acceptance becomes the pending head without moving the
activation height. A Declaration whose `publisher` object is byte-identical
to the pending head is an idempotent acceptance, exactly as a re-serve of
the current Declaration is: it installs nothing, does not raise the
sequence floor and is not `WIST1-E08`. A pull fetches a served Declaration
throughout the activation delay, so the rule that catches a superseded
replay must not catch the pending head its Publisher is still serving. A
replacement naming the current Declaration MUST authenticate as an ordinary
or recovery rotation against it; a fresh identity naming the current
Declaration beside a pending head is `WIST1-E08`. On acceptance that
replacement becomes current and the pending head and every Declaration that
named it are discarded: superseded, never current, and excluded from every
later predecessor and key resolution. This is the **reversal**, the answer
a Publisher that still holds a listed signing or recovery key gives to a
Declaration published from its web host alone. A recovery rotation that
reverses a pending head opens a recovery window as any recovery rotation
does. Before applying any Declaration in the Epoch at the activation
height, activate: the pending head becomes current, the pending state ends,
and the domain's identity resets at that height, so a party reading its
history from the Log reads it from the activation height.

With `declaration_activation_epochs` at 0 the activation height is the
sealing height itself: the fresh identity becomes current at once, when its
Declaration applies. A Declaration of higher `seq` applied later in the
same Epoch meets it as current and cannot reverse it, and the activation
narrows (below) before that Declaration applies.

A pending Declaration supplies no authority: a Catalog signed under its
keys alone is `WIST1-E02` until activation, and Catalogs continue to verify
under the current Declaration. Signed histories for a delayed activation, a
reversal by each key class and a zero delay appear in
`vectors/wist1/key-directory.json`, with the thumbprint known answer,
entry field cases, window boundaries and commitment cases §5.1 and this
section fix. A fresh identity accepted inside an open recovery window is a
competitor under the rules below, never pending. The sequence floor counts
pending Declarations, so a reversal MUST exceed the pending head's `seq`.
The pending head, its sealing height and the activation height are
Snapshot state (WIST-3 §7).

**Compromise recovery.** A Declaration with a higher `seq` is classified
by what signs it, using the authenticated public key resolved above:

- Signed by a key in the previous Key Set — an ordinary rotation.
  Accepted; the identity is preserved.
- Signed by a key in the previous Declaration's `recovery_keys` — a
  **recovery rotation**. The recovery window (`recovery_window_days`,
  WIST-4 §5) opens at the `sealed_at` of the Epoch sealing that
  Declaration's own `publisher_declaration` Entry, and during it the
  Publisher's Catalogs and Items are queued rather than sealed
  (**Publications during recovery**). Read `recovery_window_days` from the
  parameter map in force at that opening Epoch, including amendments
  effective exactly then. Freeze the end at that Epoch's `sealed_at` plus
  that many 86,400-second days. Later parameter amendments and in-window
  recovery rotations MUST NOT move the end. An end later than
  `9999-12-31T23:59:59Z`, the last instant a Log timestamp denotes
  (WIST-3 §3.1), cannot be frozen: an Aggregator MUST NOT seal a recovery
  Declaration whose window would end there, and an Epoch sealing one is
  rejected as a whole under `WIST1-E08`, exactly as an Epoch sealing a
  superseded Declaration; WIST-4 §5 keeps `recovery_window_days`
  amendments inside that range from their own `effective_at`. A fetch
  refuses such a recovery rotation earlier (**Reaching the Log**).
  A Catalog is queued when either the Declaration in effect immediately
  before the recovery or the recovery Declaration accepts it, each read
  alone (**Sources of a pull**): the Publisher that has just recovered
  must be able to keep publishing under its new keys, and the compromised
  key's Catalogs must still reach the queue, which is where the settlement
  rejects them in the open rather than at an ingest no replaying party can
  see. Freeze both source Declarations, with their keys, Collections and
  Scopes, at the owner's application, including any lower-sequence
  predecessor in the same Epoch. Later in-window Declarations, including
  legitimate recovery-chain followers, MUST NOT replace either admission
  source; neither a competitor nor a legitimate follower can expand,
  shrink or replace their keys or Scopes. Apply §5.1's complete-binding
  check under each of these two sources alone, with each key's validity
  bounds in that source. The two sources authorize queue admission only, not
  sealing or historical verification.
  At the end of the window the recovery Declaration takes effect with its
  identity preserved, and **every** Declaration accepted after the owner
  while the window is open other than the recovery Declaration and the
  chain legitimately following it is superseded — an ordinary rotation and
  a fresh identity alike, so a thief holding only a signing key cannot
  outrun the holder of the recovery key by rotating *or* by generating a
  new key pair and starting over under the same domain. A Declaration
  legitimately follows when its authenticated signing public key belongs
  to its named predecessor's `keys` or `recovery_keys`, that predecessor
  being the current recovery-chain head under the rules above: the
  recovering Publisher may therefore rotate again inside its own window
  without forfeiting it. The **settlement source** is that chain's newest
  Declaration — the recovery Declaration's own unless a legitimate
  follower was sealed inside the window — fixed immediately before
  applying any Declarations in the first Epoch at or after the deadline.
  Admission at or after the deadline first performs the settlement; new
  candidates use the then-current Declaration, including any replacements
  already accepted at admission.
  The window is derived from the Declaration's own sealing height, so a
  Consumer replaying the Log computes the same window, the same effective
  height, and the same historical keys; no Aggregator act opens or
  describes it, because the suite's only answer to a stolen signing key
  MUST NOT rest on the Aggregator choosing to file. The sealing itself is
  a duty with a deadline for the same reason: on discovering a served
  recovery Declaration that verifies — by pull, by hint, or by the
  Publisher's Ping — the Aggregator MUST seal its Entry within the number
  of Epochs `record_seal_epochs` (WIST-4 §5) fixes. Supersession of a
  still-unsealed non-chain copy at the recovery deadline cancels that
  copy's remaining sealing duty, without excusing a sealing-latency
  violation already incurred before supersession. Legitimate followers
  retain their sealing duty. A recovery the operator can shelve
  indefinitely would leave the suite's only answer to a stolen key resting
  on the operator's goodwill. The violation is attributable — the
  Declaration is signed, dated by its own `seq` and `prev_declaration`,
  and any third party can fetch the well-known path and observe the Log
  not sealing it — but it is not derivable from the Log alone, because
  the Log cannot see an unserved file; that residue is recorded here
  rather than papered over, and it is the fork-level remedy (WIST-3 §3.4)
  that ultimately answers an Aggregator that sits on recoveries.
  Two recovery Declarations sealed inside one open window — two holders
  of recovery keys, or one holder twice — are resolved in ascending
  `(Epoch number, seq)` order for that domain. Within an Epoch, validate
  and apply Declarations in ascending `seq`, including their signatures
  and predecessor links, before selecting the first accepted recovery
  Declaration as the window owner. The canonical leaf-hash storage index
  MUST NOT select the owner or override sequence precedence. This ordering
  does not waive any Declaration acceptance check. The first-sealed
  recovery Declaration in this application order is the one the window
  belongs to, and a second sealed inside that window is a competing claim
  that does not open a second window and does not supersede the first;
  whichever party prevails does so by holding the recovery keys the
  *first* Declaration now lists.
- Signed by neither — a **fresh identity**, a Declaration signed by a
  Collection key included. The Declaration is accepted. Outside an open
  recovery window it becomes pending under the rule above and resets the
  domain's identity only at its activation height. Inside an already-open
  window it is a competing Declaration: acceptance changes the current
  Declaration and sequence floor, but MUST NOT reset identity, in an open
  prefix or after settlement. It is superseded at the window's end by the
  rule above; fresh classification alone is never a `WIST1-E08`. The
  sequence, predecessor and recovery-key checks still apply. Rejecting an
  otherwise valid fresh identity at ingest would leave the attempt
  invisible to a party replaying the Log.

A Publisher that loses both its signing keys and its recovery keys
starts over; that is the honest outcome, because with no cryptographic
continuity left nothing distinguishes the Publisher from a new owner of
the same name, and preserving standing on domain control alone would let
anyone buy an aged domain and inherit its history.

**Historical verification.** Accepted Declarations are sealed into the Log
as `publisher_declaration` Entries (WIST-3 §3.3), except the unsealed
copies this section removes from the eligible sealing set. The Declaration
in force for a Publisher at Epoch N, which judges its `publisher_catalog`
and `publisher_item` Entries sealed in Epoch N (WIST-3 §3.3), is the
Declaration current for that domain once Epoch N's Declaration Entries,
settlements and activations have applied under this section: normally the
domain's highest-`seq` Declaration Entry sealed at a height ≤ N — except
that a recovery Declaration which took effect under the Compromise
recovery rule above prevails over every off-chain competitor accepted after
its owner while the recovery window is open, regardless of `seq`, and that
a pending Declaration supplies nothing before its activation height and a
reversed one never. A Consumer replaying the Log therefore excludes
superseded, reversed and not-yet-activated Declarations from the "highest
`seq`" comparison and treats the recovery Declaration (and whatever
legitimately follows it) as applicable instead, for every height from the
recovery Declaration's own sealing height onward. Because `seq`,
`prev_declaration`, each Declaration's signer, Entry order, the recovery
window's own anchor — the `sealed_at` of the Epoch sealing the recovery
Declaration — and the activation height, derived from a sealing height,
are all present in the Log itself, this resolution — ordinary case,
recovery exception and activation alike — is fully deterministic from log
order alone, with no fetch and no trust in the Aggregator. "Took effect
under the Compromise recovery rule" is therefore a predicate every
replaying party evaluates identically, rather than a claim resting on an
entry the Aggregator may or may not have filed.

The selected Declaration supplies the keys, the Collections and the Scopes
by which a Catalog and an Item sealed at that height are judged. A later
change of `subdomain_scope` or of a Scope does not revise authority at an
earlier sealing height; narrowing (below) removes records instead. No
Catalog or Item seals during an open recovery window. A settlement survivor
is judged again at its actual sealing Epoch, the Declarations of that Epoch
included, so it is eligible and not assured of sealing.

The Declaration so resolved is not always the one the Aggregator pulled
under: a Declaration accepted between the pull and the seal can remove the
key that signed a Catalog, remove its Collection or narrow a Scope. An
Aggregator seals no Entry that fails its judgment at its Epoch, and a
replaying Consumer that meets one — an Aggregator's breach — ignores it
(WIST-3 §3.3). **Reaching the Log** below orders the sealing of a
Declaration that reduces authority ahead of its Publisher's publications,
and the Publisher's remedy for a Catalog that fails the binding check is
the next Catalog it signs under its keys (WIST-3 §3.3).

**Narrowing.** A Declaration that becomes current by a transition of the
table below removes, at the height the table gives, the Publisher's records
(WIST-3 §7) that do not stay under it. Narrowing reads the Publisher's live
records and the Declaration that takes effect, and no earlier Declaration.
Under a Declaration that carries `collections`, a record stays when the
Declaration names the record's Collection and that Collection's Scope
covers the record's URL. Under a Declaration without `collections`, the
records of every Collection other than `default` leave, since no
Declaration in force names their Collection, and a record of `default`
stays whatever its host, since a later change of `subdomain_scope` does not
revise authority at an earlier sealing height. The records leave as removed
records do and return when an Item of their URL is sealed again, the Item
they carried included.

| Transition | Height |
|---|---|
| An ordinary rotation naming the current Declaration, sealed outside a recovery window, a reversal of a pending head included. One applied in the Epoch that opens a window, before the recovery rotation that owns it, is a predecessor and not a competitor and is sealed outside that window | Its sealing Epoch |
| Settlement of a recovery window, for the recovery-chain head it makes current | The first Epoch whose `sealed_at` is at or after the window's end |
| Activation of a pending head | The activation height |

A recovery rotation, a Declaration of any class accepted inside an open
window, a fresh identity that becomes pending, a replacement of a pending
head and an idempotent re-serve remove nothing when they are sealed. Where
one Epoch settles or activates and also seals an ordinary rotation, the
transitions narrow in the order this section applies them. Narrowing at
height N removes records sealed below N. The Catalogs and Items Epoch N
seals are then judged under the Declaration in force once every transition
of Epoch N has applied (§3.2). `vectors/wist1/collection-narrowing.json`
carries narrowing at each transition.

**Reaching the Log.** A Declaration is **discovered** at the pull that
fetches it and finds that it passes its acceptance checks. A recovery
rotation whose window, counted from the fetch's instant under the
`recovery_window_days` in force then, would end after
`9999-12-31T23:59:59Z` fails those checks at the fetch with `WIST1-E08`: it
is not discovered, places no hold and queues nothing, and the pull stops
(WIST-2 §5).

A Declaration D **reduces authority** against the Declaration P it names
as predecessor when at least one of the following holds, each Declaration
read with its Collections, the implicit `default` included:

- P lists a public key in `keys`, in `recovery_keys` or in a Collection
  that D does not list in the same member, or in the Collection of the
  same name. Keys are compared by their public octets.
- D lists such a key with a shorter window: a later `nbf`, an earlier
  `exp`, or an `exp` where P has none.
- P has a Collection that D does not have.
- A Collection of P has a Scope entry that the Collection of the same name
  in D does not carry with the same `url` and `match`. The Scope of an
  implicit `default` counts as one entry that another implicit `default`
  carries and no `collections` member does.
- `subdomain_scope` of P has a member that D's does not.

The test reads entries and not the URLs they cover: a Declaration that
replaces an entry by a wider one reduces authority.

An Aggregator MUST seal a D that reduces authority within
`record_seal_epochs` (WIST-4 §5) of its discovery, counted as the
recovery sealing deadline above counts, and ahead of its Publisher's
publications: from the discovery of D, and while D is in the eligible
sealing set, it seals no Catalog or Item of D's Publisher in an Epoch below
the one that seals D. This **hold** applies to a Declaration of any class,
a recovery rotation and a fresh identity that becomes pending included. The
publications of the other Publishers of the Registrable Domain proceed.
The hold orders sealing and moves no eligibility Epoch and no inclusion
ceiling (WIST-4 §5): D is sealed at or below the last Epoch that the
earliest ceiling among the waiting publications of its Publisher allows.
The publications sealed in D's Epoch or later are judged as **Narrowing**
states. The hold ends at the Epoch that seals D, or when D leaves the
eligible sealing set unsealed: superseded at the settlement of a recovery
window, or failing its checks at its candidate Epoch or leaving with one
that fails (below). A pending replacement that a reversal discards is
sealed at or below the reversal's Epoch, as the Declaration sealing
obligation requires, so its hold ends there. Where D is a recovery rotation
that opens a window, the window defers the Publisher's publications from
the Epoch that seals D (**Publications during recovery**).

A Declaration under which a pull read is sealed at or below the Epoch that
seals the first publication that pull accepted (WIST-3 §3.3). It defers no
eligibility, whether or not it reduces authority, so the inclusion ceiling
of those publications bounds its own sealing.

**Sources of a pull.** A pull reads Collections, Scopes and keys from the
sources the table gives for the Publisher's state once the fetched
Declaration has been applied, and reads the Collections of a Declaration
in the order `collections` lists them. A fetched Declaration whose
`publisher` object is that of the pending head is a success of the fetch
and changes no source. So is one whose `publisher` object is that of the
recovery-chain head of an open window of the Publisher, although its
acceptance answers `WIST1-E08` while another accepted Declaration is
current: the pull proceeds under the two frozen sources. That window is
the window of admission, open from the discovery of the recovery rotation
and not only from the Epoch that seals it. The fetch itself, and when a
pull proceeds, are WIST-2 §5's.

| State of the Publisher | Sources the pull reads | Collections pulled |
|---|---|---|
| A current Declaration, with no pending head, no open recovery window and no recovery rotation discovered and not yet sealed | The current Declaration | Its Collections |
| A pending head, with no recovery rotation discovered and not yet sealed | The current Declaration alone. The pending head names no Collection to pull and supplies no candidate: a Catalog that verifies under its keys alone is `WIST1-E02` | The current Declaration's. A history's first Declaration is current, so a pending head always has one beside it |
| An open recovery window, or a recovery rotation discovered and not yet sealed | The two **frozen sources**: the Declaration in effect before the recovery and the recovery Declaration that owns the window or, before its sealing, was discovered. No Declaration accepted later is read | Those of the Declaration in effect before the recovery, then those the recovery Declaration alone names. A name both carry is pulled once |

A recovery rotation that leaves the eligible sealing set unsealed leaves
the pulls after it under the sources of the other rows. A replacement that
names the pending head is the pending head for this table and for
**Publications during recovery**, whatever signs it: it opens no window,
so it is no recovery rotation discovered and opens no queue. A pending head
stays pending at every pull until the Epoch at its activation height is
sealed.

Under the two frozen sources each source is read alone, with its own
Collections, Scopes and keys. A Catalog is accepted, and queued, when at
least one source names its Collection and supplies a candidate under which
its binding check passes; an Item of its list passes the Item conditions
when a source that accepts its Catalog passes them for it. A Collection
that one source names and a key that only the other lists admit nothing
together: each source judges the Catalog alone by §7's Catalog conditions,
a Catalog that no source accepts is refused, and a validator MAY report
any code a source established (§7).

**An accepted Declaration that fails at sealing.** An accepted Declaration
that fails its checks at its candidate Epoch, a count or the Entry bound of
§5.1 under the map in force there included, is not sealed. It leaves the eligible sealing set at once, as a superseded
copy is removed, with every accepted Declaration that names it directly or
through others; this is a further exception to the Declaration sealing
obligation. The admission state is then the one the accepted Declarations
that remain give when applied in the order of their acceptance, so a
Declaration that a departing one discarded or superseded is restored unless
one that remains discards or supersedes it. Where one remains, the sequence
floor does not change, so serving a departing Declaration again is
rejected, with `WIST1-E08` or with the code of a check it fails under the
map the fetch reads, §7 leaving the choice of diagnostic. Where none
remains, the domain returns to first contact (WIST-2 §5) and keeps no
sequence floor. The failure is reported at the status endpoint (WIST-2
§7.1) with the code of the check that failed, for the Declaration that
failed and for each that leaves with it. A hold it placed ends.

**Publications during recovery.** While a recovery window of a Publisher
is open, none of its Catalogs and Items is sealed (WIST-3 §3.3). A window
is open at Epoch N when its recovery Declaration was sealed at or below N
and N's `sealed_at` is earlier than the window's end: the Epoch that seals
the recovery Declaration is inside the window, and the first Epoch whose
`sealed_at` is at or after the end is outside it and is the **Epoch of
settlement**. A Catalog or an Item admitted before the Epoch that opens a
window and not sealed below it is queued or held with its place (*Queue*)
and is not sealed in that Epoch. The last accepted Catalog, the latest
Catalog, the floor, waiting, places, eligibility Epochs and the inclusion
ceiling read below are WIST-3 §3.3's and §7's.

*Discovery.* From the pull that discovers a recovery rotation until the
Epoch that seals it, a pull reads the two frozen sources (**Sources of a
pull**) and follows every rule below for a pull inside the window: it
queues what it accepts, per Collection name and signing key, and no URL
takes a place at it; an Item of the waiting Catalog that such a pull admits
takes its place at the next Epoch. What such a pull accepts is not sealed
before settlement: the rotation is a source the pull read, so it is sealed
at or below the Epoch that seals the first publication that pull accepted,
whose inclusion ceiling bounds it (**Reaching the Log**), and that Epoch
opens the window. A Catalog and the Items that waited at the discovery keep
waiting: they are sealed in their turn below the Epoch that seals the
rotation where the hold allows it, and are otherwise queued and held when
the window opens. Where the rotation leaves the eligible sealing set
unsealed, the queue is settled at that event as *Settlement* settles one,
the Catalogs that wait being queued first as at the opening of a window,
with the current Declaration of the sealed history as the source and the
instant of the event as the clock. What waited at the discovery keeps its
place, its eligibility Epoch and its ceiling, which a surviving Catalog
queued from the discovery takes where it replaces the Catalog that waited;
what else was queued from the discovery is eligible for the first Epoch not
sealed before the event; later pulls are pulls outside a window.

*Queue.* A pull inside the window reads the two frozen sources and queues a
Catalog that either accepts. The queue holds, per Collection name and per
public key that signed, the Catalog of latest `generated_at`, with its
list, its admitted Items and their Payloads; a Catalog of the same name and
key with a later instant replaces the queued one. Inside the window the
order of a pull (`WIST2-E05`, §7) is read against the floor, against the
queued Catalog of the same name and key and, before the window opens,
against the Catalog that waits for the Collection where the same key signed
it, so a Catalog of another Catalog ID at the instant of such a Catalog is
refused and that Catalog stays, and a Catalog signed by a key the recovery
removes holds back none signed by another. A Catalog with the Catalog ID of
a queued or a waiting one under another key is no idempotent re-serve and
is queued under its own key. A Catalog that waited when the window opened
is queued as one a pull inside the window accepted, with the place it had,
unless a Catalog of its name and key with a later instant is queued
already, which stays; the Items that waited are held with their places.
The refusal of a list that drops the URL of a record (WIST-2 §5) reads the
Scopes of both sources. An idempotent re-serve (§7) inside the window reads
again which sources accept its Catalog and retries its Items under those;
where neither accepts it, no Item is retried. Inside the window no URL
takes a place, the Epoch that opens it aside, where an Item that a pull
from the discovery admitted for the waiting Catalog takes its place
(*Discovery*), and a Catalog that failed C4 at its turn (WIST-3 §3.3) is
not queued. A queued Catalog is not a waiting one and is not the last
accepted Catalog until settlement makes it one: from the Epoch that opens
the window, the window alone defers the Items held, and they are reported
at each Epoch inside it with the window alone.

*Settlement.* The queue is settled once, where no event of *Discovery*
settles it first, at the first event at or after the window's end: a pull,
which settles before it reads anything and is then a pull outside a window,
the settlement and the pull being two events, the settlement first, so the
places taken at the settlement precede those the pull gives; or the Epoch
of settlement S, before any Declaration of S applies. Every queued Catalog
is judged again by C1 (WIST-3 §3.3) under the settlement source, with the
instant of that event as the clock, a pull's own instant or S's
`sealed_at`. A Catalog that fails is rejected with `WIST1-E13` and reported
at the status endpoint (WIST-2 §7.1). A queued Catalog whose `generated_at`
is not later than the floor does not survive either: it is reported with
`WIST2-E05` alone, and C1 is not judged for it. The rejection is of the queued copy and not of the Catalog's
identity: the same Catalog served again is judged as any other, so replay
agreement needs no per-Log list of dropped IDs. A Catalog signed by a key
the recovery rotated out is exactly the case this settles. Per Collection
name, the surviving Catalog that is latest in the Catalog order (§3.5)
becomes the last accepted Catalog, and among surviving Catalogs of that
Catalog ID the one of the earliest place does. The other survivors are not
sealed and not reported. Where no Catalog of a name survives, a name with
nothing queued included, the last accepted Catalog is the latest Catalog.

What then waits is eligible for S, and the ceiling counts from S: a queued
publication is out of the ceiling's reach while the window holds it, or
the window and the ceiling would be two duties one Aggregator cannot both
keep. A URL that waited when the window opened and waits at settlement
keeps its place. A queued Catalog has the place of the pull that queued
it, before or inside the window, and one that waited when the window opened
the place it had. A Collection's Catalog takes the earliest place among the
Catalogs queued under its name and the Catalog that waited for it when the
window opened, those that a later Catalog of their key replaced or kept out
of the queue included, as a replacement outside a window keeps the place.
A URL that did not wait when the window opened takes the surviving
Catalog's own place, which the queue gave it, and not an earlier place the
Collection's Catalog takes, as a URL outside a window takes its place at
the pull from which it waits; where no Catalog of its name survived, it
takes the place of the settlement. Every Entry is judged at the Epoch that
seals it, the Declarations of S included, so a survivor is eligible and not
assured of sealing. `vectors/wist1/catalog-recovery.json` carries signed
histories of discovery, queue and settlement.

## 6. Deliberate Normative Absence

This specification defines no field by which a publisher may declare the
importance, relevance, or ranking of its own content. This absence is
deliberate and constitutional; see WIST-4.

An Item may say "I changed" and "my content is this". It cannot say "I
matter". Importance is measured at consumption, outside this protocol.

## 7. Error Registry

**Payload diagnostics.** Invalid JCS input is `WIST1-E05`. For a
canonicalizable Payload, validate the complete `payload.schema.json` field
structure, §2's canonical base64url salt of at least 16 decoded octets and
§3.1's version spelling before any semantic rejection. Missing or unknown
members, wrong types, explicit null in optional `summary.abstract`, and
malformed fields are `WIST1-E14`. `links.total` MUST be a nonnegative
integer within §4's safe-integer range; eligibility depends on its numeric
value, so `1`, `1.0` and `1e0` are equivalent. String lengths count Unicode
scalar values without normalization.

The §3.6 size-cap exceptions to schema lengths retain E04. Each `links.urls`
entry MUST be a string (E14); normalization, externality, duplicates and
`len(urls) > total` retain E12, even when a schema constraint also describes
that failure. After all E14 checks pass, a validator MAY report any
established applicable semantic failure: size cap exceeded (E04), commitment
or declared-length mismatch (E10), invalid links (E12), or unsupported major
(E15). Acceptance requires every applicable check. This order governs
Payload validation once the Item that commits to it and its parameter
profile are supplied; it imposes no precedence between independent Item and
Payload failures. WIST-2 §5 retains its `WIST2-E03` pull wrapper, and WIST-3
§6.1 retains its availability and materialization dispositions. See
[ADR-0034](../decisions/0034-payload-field-diagnostics.md).

**Item conditions.** An Item is judged with the Catalog that lists it,
under the Declaration in force at that judgment (§3.2). An Item that meets
a condition below is refused alone (§3.3).

| Code | Condition |
|---|---|
| `WIST1-E14` | A member set other than its kind's, a member of another type or form, or a `removed` that is not `true` |
| `WIST1-E03` | A `url` that is not byte-identical to its own Normalized URL, whose host lies outside the authority of the Catalog's Publisher, or that the Scope of the Catalog's Collection does not cover (§3.2) |
| `WIST1-E11` | In an Item of kind `page`, `JCS(url)` above `url_cap_bytes` (§3.2) |
| `WIST1-E04` | `payload.bytes` above the derived cap of §3.6, or `JCS(item)` above 16 384 + `url_cap_bytes` octets, for either kind |
| `WIST1-E06` | An `observed_at` later than the Catalog's `generated_at`, compared as exact instants |
| `WIST2-E03` | A `publisher` other than the Catalog's |

The `WIST1-E14` conditions are checked first, with these exceptions:

- A string `url` retains `WIST1-E03` for normalization, authority and
  Scope and `WIST1-E11` for its size bound; a missing or non-string `url`
  is `WIST1-E14`.
- A nonnegative integral `payload.bytes` within §4's safe-integer range
  but exceeding §3.6's active derived cap retains `WIST1-E04`; a negative,
  fractional, nonnumeric or unsafe-integer value is `WIST1-E14`. Integer
  eligibility depends on the JSON number's value, not decimal or exponent
  spelling.

The schema's fixed `url.maxLength` and `payload.bytes.maximum` describe
the default profile. For these two checks, validators MUST instead apply
§3.2's JCS-octet URL cap and §3.6's derived cap from the parameter profile
required at their validation stage; the fixed schema values MUST NOT reject
an object permitted by that active profile. String lengths in schema field
checks count Unicode scalar values, without normalization; octet caps
retain their own rules. Among the conditions other than `WIST1-E14`, a
validator MAY report any it has established.

**Catalog conditions.**

| Code | Condition |
|---|---|
| `WIST1-E05` | An Envelope that is not valid JCS input (§4) |
| `WIST1-E14` | A member set other than the Envelope's or the inner object's, a member of another type or form, or a `size` that is not a nonnegative integer of §4's safe range |
| `WIST1-E15` | A major version the validator does not implement (§3.1) |
| `WIST1-E04` | A `size` above `catalog_items_max` |
| `WIST2-E04` | At a pull, a `publisher` or a `collection` other than the one the Catalog was fetched for |
| `WIST1-E03` | A `collection` the Declaration in force does not name |
| `WIST1-E02`, `WIST1-E01` | The binding check, as §5.1 distinguishes them |
| `WIST1-E06` | A `generated_at` more than `clock_skew_seconds` beyond the clock (§3.4) |
| `WIST2-E05` | At a pull, a `generated_at` at or before that of the Collection's last accepted Catalog, in a Catalog that is not an idempotent re-serve |

`WIST1-E05` and then the `WIST1-E14` conditions are checked first; among
the others a validator MAY report any it has established. Whether `size` is
an integer depends on the number's value and not on its spelling. A fetched
Catalog is read first against the Catalog conditions other than
`WIST2-E05`: one that meets one is reported with its code, replaces nothing
and retries nothing. Only one that meets none is read for the order and for
an idempotent re-serve.

A fetched Catalog is an **idempotent re-serve** when its Catalog ID is that
of the Collection's last accepted Catalog or of its latest Catalog
(WIST-3 §3.3, §7): it replaces nothing and is no regression. From the
discovery of a recovery rotation until the settlement of its window
(§5.2), the key counts as well: a fetched Catalog is then an idempotent
re-serve when its Catalog ID and the public key that signed it are those of
a Catalog queued under its name or of the Catalog that waits for its
Collection, or when its Catalog ID is the latest Catalog's. What a pull
does on an idempotent re-serve is WIST-2 §5's.

**Inclusion Proof.** A proof of another form than §4.3's is `WIST1-E14`,
and one that does not prove the Item against the named Catalog is
`WIST1-E17` (§4.3). The body of a `publisher_item` Entry and its
diagnostics are WIST-3 §3.3's.

**Choice of diagnostic.** A validator MUST NOT accept an Item, a Catalog, a
Payload or a Declaration that fails any required check. The freedom above
governs diagnostic selection only, not acceptance, source authority or the
meaning of an error: an invalid signature and excess skew permit either
`WIST1-E01` or `WIST1-E06`; excess skew and a Collection the Declaration
does not name permit either `WIST1-E06` or `WIST1-E03`. A validator MAY
stop after establishing a rejection and need not perform unrelated checks
solely to choose a different diagnostic. Every prerequisite of a check it
performs still applies. Lack of a performed check is not evidence of its
failure. `WIST1-E01` and `WIST1-E02` remain mutually exclusive outcomes of
the complete binding check in §5.1. Status rejection entries and Ping noise
accounting retain WIST-2 §7.1 and §4's rules.

Object and stage dispositions remain authoritative: this permission does
not replace recovery settlement's `WIST1-E13`, change idempotent
acceptance, retroactively invalidate a sealed Entry, or bypass transport
wrappers. `WIST1-E10` is a Payload diagnostic, not a selectable Item
rejection; the Payload cap checks of §3.6 and pull rejection under
WIST-2 §5's `WIST2-E03` remain required.

| Code | Meaning |
|---------|--------------------------------------------------------------|
| WIST1-E01 | Invalid signature: for a Catalog, no signature verifies under any usable, time-eligible named binding authorized by §5.1/§5.2, although at least one such binding exists; for a Declaration, usable named signer candidates exist but none verifies (§5.2) |
| WIST1-E02 | No usable, time-eligible named Catalog signing binding in the sources authorized by §5.1/§5.2, a key of another Collection, a pending Declaration's key and a Publisher with no Declaration in force included; or no usable Declaration signer candidate (§5.2) |
| WIST1-E03 | An Item's `url` out of scope, not normalized or not normalizable: host outside `domain` and `subdomain_scope`, not covered by the Scope of the Catalog's Collection, not byte-identical to its own Normalized URL, or with no Normalized URL (§2, §3.2); a Catalog's `collection` the Declaration in force does not name (§3.5) |
| WIST1-E04 | Size cap exceeded, in JCS octets: `payload.bytes` above §3.6's derived cap; `JCS(item)` above 16 384 + `url_cap_bytes`; a Catalog's `size` above `catalog_items_max`; a Declaration whose `publisher_declaration` Entry exceeds 65 535 octets (§5.1); a retrieved Payload whose `JCS(extract)`, `JCS(links)`, `JCS(url)` of a `links.urls` entry or `JCS(summary)` exceeds its cap (§3.6) |
| WIST1-E05 | Invalid canonicalization: the object is not valid JCS input (§4). For a number this means it denotes no IEEE-754 double — a magnitude beyond the finite range, or a form outside JSON's grammar. A finite double is always canonicalizable, fractional part included |
| WIST1-E06 | A Catalog's `generated_at` beyond the clock plus the active signed allowance selected by §3.4; an Item's `observed_at` later than its Catalog's `generated_at` |
| WIST1-E07 | Retired; not reused |
| WIST1-E08 | Declaration sequence or key violation: `seq` not greater than the highest accepted, including superseded and pending Declarations, except an idempotent re-serve of the current Declaration's or the pending head's own `publisher` object (§5.2); a conflicting same-domain, same-sequence Declaration group in an Epoch (§5.2); `prev_declaration` absent when `seq` > 0 or not naming an eligible predecessor under §5.2, including a fresh identity naming the current Declaration beside a pending head; an ordinary rotation that neither keeps nor installs the predecessor's `next_keys` commitment (§5.2); the named predecessor's nonempty `recovery_keys` changed without a signature from that set; a public key listed twice within or across `keys`, `recovery_keys` and the `keys` of any Collection (§5.2); a recovery Declaration whose window would end after `9999-12-31T23:59:59Z`, at its fetch or at the Epoch that seals it (§5.2) |
| WIST1-E09 | Retired; not reused |
| WIST1-E10 | Payload commitment mismatch: a retrieved Payload does not reproduce its Item's `payload.commitment` under the salt it carries, or the octet length of `JCS(content)` is not exactly `payload.bytes` |
| WIST1-E11 | An Item of kind `page` whose `JCS(url)` exceeds `url_cap_bytes` octets |
| WIST1-E12 | `links` violates a structural rule of §3.6 |
| WIST1-E13 | Queued Catalog invalidated by recovery settlement: a Catalog queued during a §5.2 recovery window or from its discovery fails C1 (WIST-3 §3.3) at the settling event under the settlement source or, where the rotation left the eligible sealing set unsealed, under the current Declaration of the sealed history (§5.2). The queued copy is dropped and never sealed, and the drop is visible to the Publisher via the status endpoint (WIST-2 §7.1); the Catalog's identity is not barred, so the same Catalog served again is judged as any other |
| WIST1-E14 | Malformed Declaration Envelope (§5.1), including an out-of-range integer, a key entry whose `kid` is not its thumbprint or whose `exp` is not greater than `nbf`, and a Collection or Scope entry of another form; malformed Catalog Envelope, Item, Inclusion Proof or Payload fields under §7, subject to their semantic exceptions; or malformed base64url under §2. Canonicalization failure remains `WIST1-E05` |
| WIST1-E15 | Catalog, Payload or Declaration major version not implemented by the validator (§3.1); malformed version spelling remains `WIST1-E14` |
| WIST1-E16 | Collection rule violation in a Declaration: a repeated Collection `name`, a Scope entry whose host lies outside `domain` and `subdomain_scope`, an entry of one Collection that covers an entry of another, or more than `collections_max` Collections or `scope_entries_max` entries in a Scope (§5.1) |
| WIST1-E17 | An Item not proved against the Catalog its Entry names: an Inclusion Proof that fails §4.3's verification, or a `publisher_item` Entry whose `collection` is not the named Catalog's (WIST-3 §3.3) |

An idempotent re-serve of a Catalog, and a fetched Declaration whose
`publisher` object is byte-identical to the domain's current one or to its
pending head (§5.2), are idempotent acceptances, not errors.

`WIST1-E10` rejects the Payload, never the Item. A sealed Item stays sealed
and valid, because nothing in its identity, its leaf or its Catalog's
signature depends on content the Log never held; the party that served the
mismatched Payload is the one at fault (WIST-3 §9, `WIST3-E03`).

## 8. Security Considerations

- **Key theft.** A stolen owner signing key can sign fraudulent Catalogs
  for every Collection and can even perform a rotation that looks entirely
  valid: a Declaration signed by a key from the previous Key Set is
  accepted as an ordinary rotation immediately, with no window (§5.2). The
  actual mitigation is the recovery key: because a recovery key signs
  nothing but Declarations and is meant to be held offline, separately
  from the signing key, compromising the signing key alone does not expose
  it, and a Declaration signed by the recovery key supersedes any ordinary
  rotation sealed during its 7-day recovery window, while the Catalogs the
  thief signed inside the window are dropped at settlement (§5.2) — so a
  thief holding only the signing key gets a temporary, always-reversible
  foothold, never a permanent one. A Publisher that commits to its next
  signing set (`next_keys`, §5.2) narrows even that foothold: the thief can
  rotate only to keys the Publisher generated and holds elsewhere.
  Recovery restores authority and not records: a record sealed from a
  thief's Catalog before the window stays until the owner's list removes
  it, and a Log refuses a list that holds no Item for the URL of a record
  it holds (WIST-2 §5), so the owner lists an Item of kind `removed` for
  each such URL or narrows the Scope that covers it (§5.2). Publishers
  SHOULD generate recovery keys independently of signing keys and keep
  them offline, SHOULD keep owner signing keys off the web server that
  serves content, and SHOULD rotate on any suspicion of compromise. A
  Publisher that loses its signing key without ever having provisioned a
  recovery key has no cryptographic path back (§5.2).
- **Collection keys.** A key of a Collection signs that Collection's
  Catalogs alone, for URLs its Scope covers, and signs no Declaration: a
  Declaration it signs is a fresh identity, pending and reversible outside
  a recovery window (§5.2). A Publisher that lets a platform publish for it
  hands over a Collection key and keeps its owner keys. It removes the key
  or the Collection with a Declaration that reduces authority, which an
  Aggregator seals ahead of the Publisher's publications (§5.2, **Reaching
  the Log**), and whose narrowing removes the Collection's records from
  every Log that seals it, whatever the holder of the Collection key does.
  A holder of an owner key can add or replace a Collection key even under
  a standing `next_keys` commitment, which covers `keys` alone, as it can
  change `subdomain_scope`; the recovery key is the remedy.
- **Scope enforcement and narrowing.** The Scope of a Collection is
  enforced by every Aggregator and Consumer (§3.2), so a fault in whatever
  produces a Publisher's publications cannot publish a URL outside it. An
  owner that removes a Scope entry or a Collection takes its records out
  of every Log with one Declaration. A holder of an owner key can do the
  same to a whole domain in one Epoch, where removal by Items of kind
  `removed` is bounded by the per-domain Epoch capacity (WIST-3 §3.2).
- **Removal retention.** A Publisher keeps an Item of kind `removed`
  listed for `removal_retention_days` (§3.3) because it does not know
  which Logs pull its files. A Catalog whose `generated_at` is more than
  that interval later than the last Catalog a Log sealed for its
  Collection is a base there: a removal may have left the list since, so
  the Log removes the Collection's records and seals them again from the
  list (WIST-3 §7).
- **Domain transfer.** A Key Set replacement does not transfer history
  by itself: §5.2 classifies a replacing Declaration by what signs it,
  and one signed by neither the previous Key Set nor the previous
  `recovery_keys`, a Collection key included, is a fresh identity, visible
  in the Log as such, outside an open recovery window, and pending for
  `declaration_activation_epochs` Epochs, during which any still-held
  signing or recovery key reverses it (§5.2). A competing fresh Declaration
  inside that window cannot take over the recovering identity or reset it
  (§5.2). A party that acquires a domain's hosting without also acquiring
  an owner signing or recovery key therefore cannot inherit its
  predecessor's history — only cryptographic continuity does that, never
  possession of the name alone — and a Consumer reading a domain's age or
  publication history from the Log reads it from the fresh identity's
  activation height (WIST-4 §8).
- **Payload substitution.** A Mirror, a Publisher, or anyone else in the
  serving path can offer any bytes at a Payload's URL. None of it matters:
  a validator accepts a Payload only when it reproduces the Item's
  `commitment` (§3.6), which was fixed when the Item was listed, so
  substituting content is detectable by every party independently and
  rejected under `WIST1-E10`. What an adversary controlling the serving
  path can do is withhold a Payload, which is an availability failure,
  handled by WIST-3 §6.1 and distinguishable from a lawful withdrawal.
- **Signature malleability.** Ed25519 signatures as specified in RFC 8032
  are deterministic; validators MUST verify against Canonical Bytes only,
  under the verification profile §4 pins. That profile is what closes the
  malleability RFC 8032 leaves to the verifier: an unreduced `s` is a second
  valid signature for a message already signed, and a small-order `A` is a
  key under which one signature verifies for many keys — either would let
  two honest verifiers disagree about a sealed Entry.
- **Canonicalization attacks.** JCS removes serialization ambiguity
  (whitespace, key order, number forms). Input that is not valid JCS input
  (§4), repeated member names, lone surrogates and nesting deeper than 64
  levels included, MUST be rejected (`WIST1-E05`), never repaired.
- **URL authority spoofing.** The scope rule and the Scope of the
  Catalog's Collection (§3.2), plus HTTPS-only key discovery (§5.1), bind
  every Item to a domain the signer demonstrably controls and to a
  Collection its owner declared. Validators MUST NOT relax either check.
- **Single discovery channel.** Key discovery is HTTPS-only by design. Any
  unauthenticated alternative channel would let an off-path spoofer inject
  a signing key for a domain whose HTTPS endpoint is made to fail,
  defeating every other guarantee in this document; no such channel is
  defined. The mechanism this rules out is a `_wist.<domain>` DNS TXT
  record carrying the Key Set as a fallback when the well-known path is
  unreachable. Plain DNS is unauthenticated, and DNSSEC is neither
  universally deployed nor universally validated, so such a fallback would
  offer an attacker able to force an HTTPS failure — a strictly easier act
  than breaking HTTPS — a path to publishing keys for a domain it does not
  control. Conditioning it on DNSSEC does not help: a fallback that is only
  sometimes authenticated is one whose security depends on a property no
  verifier can check at the moment it matters. No DNS-based, and no other
  non-HTTPS, discovery mechanism may be introduced within this major
  version. The `_wist.<domain>` fingerprint record §5.1 permits carries no
  key and changes no acceptance decision; it is monitoring, not discovery,
  and stays outside this prohibition.

## 9. Privacy Considerations

Catalogs and Items are public and, once sealed into the Log (WIST-3),
permanent. Content is not: it lives in Payloads, outside the Log, and is
erasable under the logged due process of WIST-3 §6.2. That split is
deliberate. Extracts are drawn from public web pages, public web pages
routinely carry personal data, and erasure rights attach to whoever
redistributes that data. An index that sealed extract bytes into an
append-only structure replicated across mirrors it does not control would
be promising a deletion it could not perform.

Publishers MUST NOT include in a Payload's `extract`, `links`, or `summary`
personal data beyond what the page at its URL itself publicly serves —
a link URL carrying a profile path or a query-string identifier is as
much a carrier of personal data as extract text is — and MUST NOT
include personal data in an Item's `meta` at all (§3.7) — the difference
being that a Payload can be withdrawn and `meta`, sealed in the Item,
cannot. An Item of kind `removed`, and narrowing (§5.2), remove a record
from future snapshots (the materialized index honors removal) but do not
erase Log history, and a `payload_withdrawal` (WIST-3 §6.2), naming an
Item ID, erases the content without erasing the record that the content
existed.

What remains in the Log permanently, and cannot be withdrawn, is:

- the `publisher` domain binding the statement to its author;
- the `url` itself, which is the minimum public identifier a web index
  needs and which may contain a name — the same residue Certificate
  Transparency carries in domain names;
- the fact that the URL was published, changed or removed, and when: the
  Item's `observed_at` and its Catalog's `generated_at`, `collection` and
  `size`;
- the Payload commitment and `bytes`. The commitment reveals nothing about
  the content once the salt is destroyed (§3.6). `bytes` reveals the
  content's exact length: it is corroborating rather than demonstrative,
  because unboundedly many texts share any given length, but a party
  holding a candidate text can observe that the length is consistent with
  it. It is carried because a Consumer must be able to bound a fetch and
  detect truncation before it can verify anything;
- `meta` in full — `lang`, `topics` and `license`. These are content-derived
  and sit inside the Item, so unlike a Payload they are permanent and
  unwithdrawable, which is why §3.7 forbids personal data in them outright
  rather than bounding it by what the page serves;
- every sealed Declaration in full, its Collection names and Scope entries
  included (§5.1);
- everything any Registry Update about the URL or its Publisher carries in
  its `details` — the Aggregator's `legal_basis` and `jurisdiction`. These
  are sealed and unwithdrawable like `meta`, which is why WIST-4 §5.1 and
  §9 forbid personal data in any of them outright rather than in a list
  of named fields;
- every Label a Labeler sealed about the URL or its Publisher (WIST-2
  §3.3): a registry name, an integer and an instant, sealed and
  unwithdrawable like `meta`.

Publishers should understand that this residue is permanent, and that
withdrawal removes the content from future distribution rather than from
copies already served.

## 10. Conformance Checklist

**Publisher:**

- [ ] Includes its Canonical Host as `publisher` in every Catalog and
      every Item (§3.8)
- [ ] Signs `domain` and every `subdomain_scope` member in Canonical Host
      form (§5.1)
- [ ] Serves `publisher.json` at the well-known path over HTTPS (§5.1)
- [ ] Declares Collections with distinct names and Scopes that lie in its
      authority and do not cover each other, within `collections_max`,
      `scope_entries_max` and the Entry bound (§5.1)
- [ ] Lists each key as an Ed25519 JWK whose `kid` is its thumbprint, with
      `nbf` and an optional `exp`, and each public key once across `keys`,
      `recovery_keys` and every Collection (§5.1, §5.2)
- [ ] Signs every Catalog over JCS Canonical Bytes with an owner key or a
      key of the Collection the Catalog names, valid at its `generated_at`
      (§4, §5.1)
- [ ] Lists only Items whose `url` is a Normalized URL inside its authority
      and the Scope of the Catalog's Collection (§3.2)
- [ ] Gives each Catalog a `generated_at` in the whole-second profile later
      than that of the Catalog it replaces, and no Item an `observed_at`
      later than it (§3.4, §3.5)
- [ ] Lists a URL it no longer publishes as an Item of kind `removed` for
      `removal_retention_days` (§3.3)
- [ ] Serves a tree whose files follow §4.2 and reproduce the Catalog's
      `size`, `root` and `tree` (§4.1, §4.2)
- [ ] Commits to content instead of carrying it: a fresh CSPRNG salt of
      ≥ 16 octets per new Item, `commitment` over `JCS(content)`, `bytes`
      equal to that length and within the derived cap (§3.6)
- [ ] Respects the content caps in JCS octets and declares `links` from
      the emitted content (§3.6)
- [ ] Rotates keys by signing the new Key Set with a previous key, and
      keeps keys committed through `next_keys` apart from the current
      signing keys (§5.2)
- [ ] Increments `seq` and sets `prev_declaration` on every new
      Declaration (§5.2)

**Aggregator and Consumer (any party validating):**

- [ ] Rejects input §4 does not accept as valid JCS input (`WIST1-E05`)
- [ ] Applies §7's Item, Catalog and Payload conditions, with their field
      precedence, and reports only an established applicable diagnostic
- [ ] Checks Catalog and Payload version spelling and supported major
      under §3.1 and §7, preserving same-major minor/patch values
- [ ] Recomputes the Catalog ID, verifies the Ed25519 signature under §4's
      profile, and recomputes Item IDs, keys, leaves and roots (§4, §4.1)
- [ ] Authenticates a Catalog by §5.1's binding check over `keys` and the
      keys of the Collection it names, filtering usability and window
      before `WIST1-E02`/`WIST1-E01`, from exactly its `publisher`'s
      Declarations (§3.8, §5.1)
- [ ] Enforces the scope rule and the Scope of the Catalog's Collection
      on every Item, comparing URLs and hosts only after normalization
      (§2, §3.2)
- [ ] Recomputes a retrieved Payload's commitment and length before using
      its content, and rejects a mismatch under `WIST1-E10` without
      invalidating the Item (§3.6, §7)
- [ ] Applies §3.4's clock parameter time and §3.6's size-cap parameter
      time at the attempt, at the candidate Epoch and on replay
- [ ] Validates Publisher timestamps without leap-event data, rejects
      `:60` and compares exact offset-adjusted fractions (§3.4)
- [ ] Rejects non-monotonic Declarations, resolves the Declaration in
      force by Epoch number, and holds a fresh identity pending until its
      activation height with no authority meanwhile (§5.2)
- [ ] Applies narrowing at the heights §5.2 gives

**Aggregator:**

- [ ] Rejects Declarations served over plain HTTP and reads a Publisher's
      Collections only from the sources §5.2 gives for the pull (§5.1,
      §5.2)
- [ ] Seals a Declaration that reduces authority within
      `record_seal_epochs` of its discovery and ahead of its Publisher's
      Catalogs and Items (§5.2)
- [ ] Seals a recovery Declaration within `record_seal_epochs` of its
      discovery, queues Catalogs per Collection name and signing key from
      the discovery, and settles the queue once (§5.2)
- [ ] Removes from the eligible sealing set every superseded unsealed
      copy and every accepted Declaration that fails at its candidate
      Epoch, with those that name it (§5.2)

**Consumer:**

- [ ] Verifies every sealed Item's Inclusion Proof against the Catalog
      its Entry names (§4.3)
- [ ] Judges every sealed Catalog and Item under the Declaration in force
      at its Epoch once that Epoch's transitions have applied (§5.2)

## Appendix A. Test Vectors

Deterministic vectors generated by `tools/gen_vectors.py` (regenerate:
`tools/.venv/bin/python tools/gen_vectors.py`; verify:
`tools/.venv/bin/python tools/validate_examples.py`). The key below is a
**test vector key — never use in production**.

**Seed (Ed25519 private key, hex):**

```
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

**Public key (base64url, raw), and its `kid`:**

```
A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg
1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y
```

**Payload ([`examples/payload.json`](../examples/payload.json)), served at
`/.well-known/wist/collections/default/payloads/d807cca1e53ef2260d01a6405d2519d2967b437058320bc1b42113b894c8a006.json`:**

```json
{
  "wist_version": "1.0.0",
  "salt": "caQADX8cVHuEd7RZhUUZNA",
  "content": {
    "extract": "WIST is an open, verifiable, push-based web index protocol.",
    "links": {
      "total": 3,
      "urls": ["https://example.org/reference", "https://spec.example.net/wist-1",
               "https://example.org/~user"]
    },
    "summary": {"title": "Post 1", "abstract": "An introduction to WIST."}
  }
}
```

`JCS(content)` is 263 octets and the salt is the 16 octets
`71a4000d7f1c547b8477b45985451934`. A conforming Publisher draws that salt
from a CSPRNG; this vector derives it — `SHA-256("wist-test-salt|"
‖ url)[0..16]` — because the generator has no random source and must stay
byte-reproducible.

**Item of kind `page` ([`examples/item.json`](../examples/item.json)):**

```json
{
  "publisher": "example.com",
  "url": "https://example.com/blog/post-1",
  "observed_at": "2026-08-02T12:00:00Z",
  "payload": {
    "commitment": "hmac-sha256:25d23a19718b942a02241f8aae07a3837b9e648fb3836dd9623c3aa8ce4702b3",
    "alg": "HMAC-SHA256",
    "bytes": 263
  },
  "meta": {
    "lang": "en",
    "topics": [
      "software"
    ],
    "license": "CC-BY-4.0"
  }
}
```

| Value | Result |
|---|---|
| Item ID | `sha256:d807cca1e53ef2260d01a6405d2519d2967b437058320bc1b42113b894c8a006` |
| Key, `SHA-256(JCS(["page", url]))` | `3cd5176d1d915a0d933ec7e19f472dbb2750fa4cc61d5813b61a2ce5b7cff58b` |
| Leaf | `de2a9142fb6818563ab345a80f3ad2fc36892989474d8d197078349295e4752c` |
| Root of the one-Item list | `sha256:de2a9142fb6818563ab345a80f3ad2fc36892989474d8d197078349295e4752c` |

**Root tree file ([`examples/tree-file.json`](../examples/tree-file.json)),
a bucket with the empty prefix, served at
`/.well-known/wist/collections/default/tree/775bcd4124a92cdabdc37c6d0dfc2fceafb0e9c2e88778b2991a1be043846ff7`;
its octets are the JCS serialization:**

```
{"items":[{"meta":{"lang":"en","license":"CC-BY-4.0","topics":["software"]},"observed_at":"2026-08-02T12:00:00Z","payload":{"alg":"HMAC-SHA256","bytes":263,"commitment":"hmac-sha256:25d23a19718b942a02241f8aae07a3837b9e648fb3836dd9623c3aa8ce4702b3"},"publisher":"example.com","url":"https://example.com/blog/post-1"}]}
```

**Catalog (inner object):**

```json
{
  "wist_version": "1.0.0",
  "publisher": "example.com",
  "collection": "default",
  "generated_at": "2026-08-02T12:00:00Z",
  "size": 1,
  "root": "sha256:de2a9142fb6818563ab345a80f3ad2fc36892989474d8d197078349295e4752c",
  "tree": "sha256:775bcd4124a92cdabdc37c6d0dfc2fceafb0e9c2e88778b2991a1be043846ff7"
}
```

**Canonical Bytes (JCS, 282 octets, first bytes shown as hex; full form in
[`vectors/wist1/catalog.canonical`](../vectors/wist1/catalog.canonical)):**

```
7b22636f6c6c656374696f6e223a2264656661756c74222c2267656e65726174
65645f6174223a22323032362d30382d30325431323a30303a30305a222c2270
...
```

JCS sorts member names, so `collection` comes first regardless of authoring
order.

**Catalog ID ([`vectors/wist1/id.txt`](../vectors/wist1/id.txt)):**

```
sha256:aa5c561390ba098ab186583627f9e04022aef500db67f0e04383dd705e1178b7
```

**Signature (base64url):**

```
izPZd8unAqUfo6TuZ4neLq2VvvXdLniA4ev854L2T6mU7Ejqoo0ikG73ErKVOg6kTOkjWsBx3kgcnxaS98fHDA
```

The complete Envelope is
[`vectors/wist1/envelope.json`](../vectors/wist1/envelope.json) and doubles
as [`examples/catalog.json`](../examples/catalog.json). Neither the
extract, the links, nor the summary appears in the Item, the tree file or
the Catalog.

## References

- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels
- [RFC 8174] Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words
- [RFC 8259] The JavaScript Object Notation (JSON) Data Interchange Format
- [RFC 7493] The I-JSON Message Format
- [RFC 8785] JSON Canonicalization Scheme (JCS)
- [RFC 8032] Edwards-Curve Digital Signature Algorithm (EdDSA)
- [RFC 4648] The Base16, Base32, and Base64 Data Encodings
- [RFC 3339] Date and Time on the Internet: Timestamps
- [RFC 3986] Uniform Resource Identifier (URI): Generic Syntax
- [RFC 5890] Internationalized Domain Names for Applications (IDNA):
  Definitions and Document Framework — the terminology (A-label, U-label)
  §2's Canonical Host uses
- [RFC 5891] Internationalized Domain Names in Applications (IDNA):
  Protocol — the IDNA2008 registration and lookup rules
- [RFC 3492] Punycode: A Bootstring encoding of Unicode for IDNA — the
  A-label encoding
- [UTS #46] Unicode Technical Standard #46, Unicode IDNA Compatibility
  Processing — the normative processing algorithm §2's Canonical Host is
  computed by, at the Unicode version §2 pins
- [UNICODE] The Unicode Standard, Version 16.0 — the one release every
  Unicode property in this suite is read from (§2)
