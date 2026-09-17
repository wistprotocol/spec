# WIST-1: Delta Format & Identity

**Status:** v1.0.0-draft · **Date:** 2026-08-02 · **License:** CC-BY 4.0

## 1. Introduction

WIST is an open, verifiable, push-based web index. Sites publish signed
**deltas** describing new, updated, deleted or unchanged URLs. Aggregators
sequence them into a public, hash-chained Log (WIST-3), from which Consumers
materialize a local index.

This document defines the two foundational objects of the suite:

- the **Delta**: the unit of information a publisher signs, and
- the **Publisher Declaration**: how a domain declares its signing keys.

How deltas are published on a site and discovered by aggregators is defined
in [WIST-2](WIST-2-site-publication.md). How they are sequenced into the log and
distributed is defined in [WIST-3](WIST-3-logbook-distribution.md). How the Log is
governed and its parameters amended is defined in
[WIST-4](WIST-4-governance.md).

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as
shown here.

- **Publisher**: the operator of a domain, identified by that domain, who
  signs deltas for URLs under it.
- **Aggregator**: the party that pulls Deltas from Publishers (WIST-2), seals
  them into the Logbook (WIST-3), and operates the governance actions of
  WIST-4. It is substitutable and gains no authority from the role: every
  artifact it produces is verifiable against signatures and hashes by
  anyone.
- **Delta**: a signed statement by a Publisher about one URL at one moment.
- **Publisher Declaration**: the signed document at a domain's well-known
  path that declares its Key Set (§5.1).
- **Payload**: the content a Delta describes — the page's main text and its
  structured summary — carried as a separate, unsigned file alongside the
  Block (WIST-3 §6.1). A Payload is never part of a Delta, of a Block, or of
  the Log.
- **Payload Commitment**: the salted keyed hash of a Payload's content that
  a Delta carries in place of that content (§3.6).
- **Envelope**: the JSON container `{"<inner>": {...}, "sig": {...}}` that
  pairs an inner object with a detached signature. Every signed object in
  the suite is signed the one way §4 defines, and every one but the Log
  Block (WIST-3 §3.1) carries exactly this shape; the Block adds `entries`
  beside its signed `header`, which §4 accounts for.
- **Canonical Bytes**: the octet sequence produced by applying JCS
  [RFC 8785] to the inner object.
- **Delta ID**: `"sha256:"` followed by the lowercase hex SHA-256 of a
  Delta's Canonical Bytes.
- **Key Set**: the list of active Ed25519 public keys in a Publisher
  Declaration.
- **Canonical Host**: a hostname IDN-encoded to its A-label form by
  **UTS #46 processing** with `UseSTD3ASCIIRules=true`,
  `CheckHyphens=false`, `CheckBidi=true`, `CheckJoiners=true`,
  `Transitional_Processing=false` and `VerifyDnsLength=true`, whose output
  labels are the IDNA2008 A-labels of RFC 5891 encoded with Punycode
  [RFC 3492]; with any trailing dot removed and no port. Case is folded by
  UTS #46's own mapping step and by nothing before it: an implementation
  MUST NOT lowercase the input first. Every Unicode property read by the
  suite uses **Unicode 16.0**, including these mapping tables. Moving the version changes the specification and,
  after deployment, requires a new major version under
  [PUBLICATION.md](../PUBLICATION.md#deployment-boundary).
  Algorithm and flag rationale: [ADR-0014](../decisions/0014-canonical-host-flag-profile.md);
  version rationale: [ADR-0017](../decisions/0017-one-pinned-unicode-version.md).
- **Normalized URL**: an `https` URL after RFC 3986 §6.2.2 syntax-based
  normalization — percent-encoding hex digits uppercased and
  percent-encoded octets that correspond to unreserved characters decoded,
  and dot-segments removed from the path — with its host replaced by the
  Canonical Host, an explicit `:443` removed, an empty path replaced by
  `/`, and no fragment. The query string, if present, receives the same
  percent-encoding normalization as the rest of the URL but is otherwise
  copied byte-for-byte from the input: it is never parsed into parameters
  or reordered, so parameter order is significant. Two URLs are **the
  same URL** in this specification if and only if their Normalized URLs
  are byte-identical. Not every input has a Normalized URL: a percent-escape
  that is not two hexadecimal digits, or a host label UTS #46 processing
  rejects, has no normalization at all. A validator MUST reject a `url` it
  cannot normalize with `WIST1-E03` rather than repair it, guess at it, or
  compare it unnormalized — the same treatment §3.2 gives a `url` that is
  normalizable but not already normalized.

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

A malformed base64url field is `WIST1-E14`. Check the
encoding before using that field for key exclusion, signer resolution, signature or commitment
verification; an unused malformed Declaration key still rejects the whole
Declaration under §5.1. This is distinct from a canonically encoded public
key whose point §4 excludes. The signature-field check also applies when
idempotence would otherwise waive signature verification. Existing
object-level rejection rules and transport wrappers remain in force;
the object's encoding diagnostic identifies the underlying failure, including
beneath first-contact `WIST2-E04` or invalid-Block-file `WIST3-E03` handling.
Delta diagnostic precedence is specified in §7; this establishes no
precedence between unrelated failures in other objects.

Key membership and disjointness compare decoded public bytes after encoding
validation; equality of these bytes is equivalent to equality of their
canonical strings. Preserve original signed entries for JCS, hashes and
recovery-set protection. A key entry's `kid` is derived from the canonical
string of `x` (§5.1); alternate base64url spellings cannot introduce a
second entry for one key.

## 3. The Delta Object

A Delta is the inner object of a Delta Envelope. Its machine-readable
schema is [`schemas/delta.schema.json`](../schemas/delta.schema.json);
where prose and schema disagree, the schema governs syntax and this
document governs semantics.

### 3.1. `wist_version`

The version of this specification the object conforms to, as a semver
string. This document defines version `1.0.0`. Consumers MUST reject
objects whose major version they do not implement. Every Delta, Payload or
Declaration validator, including a Publisher checking its output, an
Aggregator admitting an object or a Consumer replaying a sealed one, MUST
enforce this rejection before treating the object as valid. For Deltas,
Payloads and Declarations, a validator implementing this revision supports
major `1`; any other major is `WIST1-E15` under §7. A different minor or
patch component alone MUST NOT cause rejection; all rules of the implemented
revision still apply.

For a Delta or Payload, the version string MUST contain exactly three dot-separated
nonnegative ASCII decimal components, with no leading zeros except `0`
itself and no prerelease or build suffix. Components have no numeric upper
bound; validators MUST NOT impose a machine-integer range on them. Malformed
spelling is `WIST1-E14`; a well-formed unsupported major is `WIST1-E15`
under §7. Validate each object's version independently; no equality between
a Payload's version and its committing Delta's version is required. Never
rewrite a version field during validation. See
[ADR-0030](../decisions/0030-delta-version-eligibility.md).

**Draft revisions and extensibility.** Before stable publication or the first
Log sealing Blocks consumed by a third party, whichever occurs first,
incompatible draft revisions MAY retain the unreleased version `1.0.0`,
including when they add required fields. The rules of the exact specification
commit being implemented determine acceptance, not the shared version string.
Older draft objects have no implicit compatibility exemption. See
[PUBLICATION.md](../PUBLICATION.md) and
[ADR-0028](../decisions/0028-unreleased-object-version.md).

After that boundary, new fields and other substantive changes require a new
major version. Within each revision, objects MUST NOT carry fields not defined
by that revision. Every schema in the suite therefore
sets `additionalProperties: false` on each object whose full field set a
document of this suite defines, and a minor version never adds a field. Two
places are deliberately open, and both delegate rather than extend: a Block
Entry's `body` (WIST-3 §3.3), which is an Envelope validated in full by its
own schema, and a Registry Update's `details` (WIST-4 §5.1), whose shape is
fixed per `action` and never licensed to carry what that section's closing
rules forbid. The
rule exists so that a consumer encountering an unknown field knows it is
looking at a non-conforming object rather than at a newer minor version it
could safely ignore, which is what makes rejection the safe default.

### 3.2. `url`

The URL the Delta describes. It MUST use the `https` scheme. It MUST be
within the authority of `delta.publisher` (§3.8): the URL's host MUST equal that Publisher's
`domain` or one of the hostnames in its `subdomain_scope` (the **scope
rule**). A validator MUST reject a Delta whose `url` is outside the signing
Publisher's authority (error `WIST1-E03`). A host inside a parent's
`subdomain_scope` may also declare for itself; both Publishers' Deltas for
it are valid, and which one materializes is decided by WIST-3 §7's
one-URL-one-Publisher rule — self-declaration prevails from the height its
Declaration seals.

The value of `url` MUST already be a Normalized URL; a Delta whose `url`
is not byte-identical to its own normalization MUST be rejected with
`WIST1-E03`. The scope rule compares Canonical Hosts. Scope and signing
bindings MUST come from the same authenticated Declaration for `delta.publisher`.
Outside recovery queue admission, use the Declaration selected for that
validation instant or sealing height under §5.2; an absent `subdomain_scope`
adds no hosts beyond `domain`. During recovery queue admission, retain each
frozen source Declaration's scope alongside its signing bindings. A Delta
passes authority only if at least one source both covers its URL host and
contains a usable, time-eligible named binding that verifies its signature.
A signature from one source MUST NOT borrow another source's scope, even
when both belong to the same Publisher. Preserve source provenance when
identifiers, public keys or validity bounds repeat across Declarations.

The §5.1 binding check still considers all authorized source bindings before
any scope restriction: no eligible named binding is `WIST1-E02`, and eligible
bindings with no verifying signature are `WIST1-E01`. If a signature verifies
under an eligible binding but no such binding's own source covers the host,
the scope failure is `WIST1-E03`. An independently established failure, such
as no source covering the host at all, remains reportable under §7. Fields
retain their existing precedence; settlement uses §5.2's `WIST1-E13` disposition.

The UTF-8 octet length of `JCS(url)` — the JSON string literal with its
enclosing quotes and any escapes — MUST NOT exceed `url_cap_bytes`
(Parameter Registry: 2048). A validator MUST reject a Delta whose `url`
exceeds the cap with `WIST1-E11`. The schema's `maxLength` counts code
points and is a structural first pass; this octet bound governs (§3.6
states the rule once for every cap in this suite). The temporal profile is
defined in §3.6, **Size-cap parameter time**.

### 3.3. `change_type`

One of four values:

- `new` — the Publisher asserts this URL now carries content; if the URL
  has prior Deltas, `prev` MUST be present (§3.5). `payload` MUST be
  present.
- `update` — the URL's content changed. `payload` MUST be present.
  `prev` MUST be present.
- `delete` — the URL no longer serves the content its chain last committed
  to: it is gone, or what it now serves is no longer that content. A page
  whose text has been replaced by unrelated text is truthfully described
  by a `delete`; one still serving the committed content is not. The Delta MUST omit
  `payload`. `prev` MUST be present.
- `attest` — the Publisher asserts the URL's content is unchanged as of
  `observed_at` (a freshness attestation). The Delta MUST omit `payload`.
  `prev` MUST be present.

A Delta that carries `payload` is **content-bearing** and MUST have the
corresponding Payload retrievable (WIST-2 §3.1); a Delta that omits it
asserts nothing about content and has no Payload to serve. The two
requirements above therefore make `new` and `update` exactly the
content-bearing change types: a validator MUST reject a `new` or an
`update` with no `payload` under `WIST1-E09`, and such a Delta MUST NOT be
sealed. A Delta claiming that content appeared or changed while committing
to none says what happened and not what it is — a claim with nothing to
show, sealed permanently, and free.

An `attest` Delta carries no content of its own precisely because it claims
none: it stands on the anchor Payload as of itself (WIST-3 §6.1), which is
why §3.5's chain and WIST-2 §3.1's retention obligation reach further back
than the Delta itself. The same holds for a `delete`, whose claim is that exactly that
content is no longer served.

### 3.4. `observed_at`

The instant the Publisher observed the state being described, as a
**Publisher timestamp** in the profile below. It MUST NOT be more than
`clock_skew_seconds` beyond the validation clock selected below (default
600 seconds; error `WIST1-E06`), and MUST be strictly
greater than the `observed_at` of the Delta referenced by `prev` (error
`WIST1-E07`). A missing, non-string or malformed `observed_at` is
`WIST1-E14`; validate its format before comparing it with a clock, predecessor
or key validity bound.

**Clock parameter time.** For an unsealed Delta, capture the validator's
clock and the accepted WIST-4 §5 schedule when its validation attempt
begins. Read `clock_skew_seconds` at that instant and retain both values
through the attempt, including retrieval and Declaration retries. A new
attempt takes a new clock and schedule.

Before sealing a queued Delta, the Aggregator MUST repeat this check using
the candidate Block's `sealed_at` as the clock and the accepted schedule at
that instant. For a sealed Delta, every validator MUST use its committing
Block's `sealed_at` for both the clock and the parameter anchor. An amendment
effective exactly then participates; later amendments, replay time and
`observed_at` do not replace either value. Historical clock eligibility therefore requires no supplied
wall clock. This rule checks the Publisher's timestamp against Log time;
it does not certify the accuracy of the Aggregator's clock.

The check is `observed_at <= clock + clock_skew_seconds`, with an inclusive
endpoint and exact arithmetic under the timestamp profile below. Negative
allowances retain their sign; bounds outside the timestamp spelling range
are compared arithmetically without clamping or formatting them as dates.
Field precedence and semantic diagnostic selection follow §7.

**Publisher timestamp profile.** `observed_at` and every Declaration
`valid_from` (§5.1) MUST use this RFC 3339-derived Gregorian profile:

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
  the Delta's clock-skew check still applies separately.

For comparisons and arithmetic, subtract the numeric offset from the
Gregorian day/hour/minute/second value, using 1970-01-01T00:00:00Z as zero,
and add the exact decimal fraction. `-00:00` denotes a known instant with
unknown local offset and contributes zero, as do `Z`, `z` and `+00:00`.
Offset subtraction MAY produce an arithmetic instant outside the written
four-digit year range; it does not invalidate a well-formed field. Compare
all fractional digits without rounding or truncation, including for the
inclusive `valid_from` bound and the active skew bound. Preserve the
original string for JCS, hashing and signatures. For example, the distance
from 2016-12-31T23:59:59Z to 2017-01-01T00:00:00Z is one second; from
`10:00:00Z` to `10:00:00.5Z` on the same date it is half a second.

The whole-second literal-Z Log profile remains distinct. This profile does
not redefine descriptive timestamps elsewhere in the suite. See
[ADR-0026](../decisions/0026-publisher-timestamp-profile.md).

### 3.5. `prev`

The Delta ID of the most recent prior Delta with the same `publisher` (§3.8)
and `url`. A predecessor with a different Publisher or URL is `WIST1-E07`,
even when the same public key authenticates both Deltas. Together, `prev` links form a **per-URL chain**: an ordered,
verifiable history of everything the Publisher has said about one page.
The first Delta for a URL MUST omit `prev`; every subsequent Delta for
that URL MUST include it (error `WIST1-E07` on violation).

The chain for a `(publisher, url)` pair never restarts, including after
ordinary rotation, recovery or a fresh identity reset. Those events change
authority or standing, not historical Delta authorship or predecessor ownership. A `new` Delta for a URL that has prior
Deltas (for example, a page recreated after a `delete`) MUST carry `prev`
pointing at the most recent prior Delta; only the very first Delta a
Publisher ever emits for a URL omits `prev`.

**Forks are invalid.** Two Deltas from the same Publisher for the same URL
naming the same `prev` are a fork. An Aggregator MUST accept whichever it
seals first and MUST reject the other with `WIST1-E07`; a Consumer replaying
the Log MUST treat the first-sealed Delta as canonical and ignore any later
Entry that forks an already-sealed chain.

**Data availability.** A validator that has not seen the Delta named by
`prev` MUST attempt to retrieve it from the Publisher (WIST-2 §3.1) before
concluding `WIST1-E07`. A Publisher MUST keep every Delta it has ever
published retrievable at its content-addressed path for as long as the
domain participates; unavailability of a `prev` Delta is a `WIST1-E07`
rejection of the *new* Delta, never a retroactive invalidation of the
sealed chain.

For an Aggregator, to have seen a Delta is to have sealed it or to hold
it accepted for sealing: a retrieved `prev` enters ingest as any served
Delta does (WIST-2 §5, under the same per-domain budget), and a Delta is
never sealed ahead of the Delta its `prev` names. A `prev` that is not
sealed at a lower Log position and cannot be — unavailable, or itself
rejected — leaves the Delta naming it `WIST1-E07`; a Log in which every
`prev` resolves to a lower Entry is what lets every replaying party walk a
chain from the Log alone.

### 3.6. `payload` — the Payload Commitment

A Delta commits to its content; it does not carry it. The content — the
main text (`extract`), the page's external links (`links`), and the
structured summary (`summary`) — travels as a separate **Payload** (WIST-3
§6.1). The Delta carries only the **Payload Commitment**:

    commitment = "hmac-sha256:" + hex(HMAC-SHA256(key = salt,
                                                  message = JCS(content)))

where `content` is the object `{"extract": <string>, "links": <object>,
"summary": <object>}` and `salt` is at least 16 octets drawn from a
cryptographically secure random source, fresh for every Delta. The salt
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
  escapes included — and MUST NOT exceed `extract_cap_bytes` (Parameter
  Registry: 32768);
- the `links` cap is the UTF-8 octet length of `JCS(<the links
  object>)` and MUST NOT exceed `links_cap_bytes` (Parameter Registry:
  4096), and each member of `links.urls`, measured as the UTF-8 octet
  length of `JCS(<the url string>)`, MUST NOT exceed
  `link_url_cap_bytes` (Parameter Registry: 2048);
- the `summary` cap is the UTF-8 octet length of `JCS(<the summary
  object>)` and MUST NOT exceed `summary_cap_bytes` (Parameter Registry:
  2048);
- `bytes` is the octet length of `JCS(content)` and MUST NOT exceed
  **38944**, which is not an independent constant: `JCS(content)` is
  `{"extract":<E>,"links":<L>,"summary":<S>}`, whose 32 octets of
  structure surround the three serialized values, so the bound is
  `extract_cap_bytes + summary_cap_bytes + links_cap_bytes + 32`.
  Amending any of the three parameters moves it.

A validator MUST reject a Delta whose Payload, once retrieved, does not
have exactly the declared length, exceeds any of the caps above, or does
not reproduce `commitment` under the accompanying salt (`WIST1-E04`,
`WIST1-E10`).

**Size-cap parameter time.** The five caps `url_cap_bytes`,
`extract_cap_bytes`, `links_cap_bytes`, `link_url_cap_bytes` and
`summary_cap_bytes`, including the derived commitment bound, use one
parameter map per validation attempt:

- For admission into a Log where the Delta is not yet sealed, read
  WIST-4 §5's accepted schedule at the validator clock when that Delta's
  validation attempt begins. Retain that map through retrieval and
  validation of its Payload. A separately
  retrieved predecessor starts its own attempt. A new attempt after restart
  or rejection reads a new map; resuming the same attempt requires retaining
  its map or reconstructing it from its clock and authenticated prefix.
- Before sealing, the Aggregator MUST recheck every candidate Delta and its
  retrieved Payload against the map in force at the candidate Block's
  `sealed_at`. Admission does not freeze eligibility for sealing; pending
  amendments do not constrain a candidate before they become effective.
  A cap failure retains §3.2/§3.6's diagnostic and prevents inclusion;
  §3.5 governs successors whose predecessor cannot be included.
- For a Delta sealed in the Log being verified, every validator MUST use
  the map in force at its Block's `sealed_at`, reconstructed from the
  authenticated accepted schedule through that Block. Retain this profile
  for later Payload retrieval, verification, replay and restart. A Payload
  retains its own committing Delta's profile wherever it is read.

An amendment effective exactly at the selected instant participates.
`observed_at`, later amendments and a later validator clock MUST NOT change
a sealed Delta's profile. These rules choose size caps only; they do not
change signature authority, clock-skew checks, Payload integrity,
availability or withdrawal obligations. See WIST-4 §5
and [ADR-0020](../decisions/0020-parameter-schedules.md).

**The `links` member.** `urls` carries the page's external links as
Normalized URLs (§2) in raw-HTML document order, deduplicated (the first
occurrence holds the position), truncated to the longest prefix whose
serialized `links` object fits `links_cap_bytes`; `total` is the count
of all distinct external links before truncation. A link is **external**
when its Canonical Host (§2) is neither the Publisher's domain nor a
subdomain of it. Only a Normalized URL can be a link: an href with no
normalization — a non-`https` scheme, a malformed percent-escape, a
rejected host label — is not a link for this specification, the same
fail-closed posture §2 takes for the subject URL. `{"total": 0, "urls":
[]}` is the REQUIRED form for a page with no external links and for any
non-HTML representation (WIST-2 §11 fixes which representations are HTML).
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
entry to be already normalized is what keeps that key exact and the
dedup rule above enforceable at ingest, against a Payload the validator
sees on its own. Which links a page has, and whether the declared
prefix is the correct (longest-fitting) prefix — equality of `len(urls)`
and `total` follows automatically once the full set fits, per the
truncation rule above — is checkable only against the page, which no
party in this suite is obliged to fetch; the extraction procedure itself
is defined in WIST-2 §11 for the Publisher declaring.

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
withdrawal for the Deltas whose Payloads still exist; hiding begins at
withdrawal. The salt is what separates
them, which is why it MUST be unpredictable and unique per Delta: a
Publisher that derives salts from the content, or reuses one across
Deltas, keeps the binding and forfeits the hiding.

### 3.7. `meta`

Descriptive metadata: `lang` is REQUIRED and uses the schema's lexical
language-tag profile: two or three lowercase ASCII letters followed by zero
or more hyphen-separated subtags of one to eight ASCII alphanumerics.
Validation requires this complete spelling, without language-registry lookup,
subtag ordering or uniqueness checks. `topics` permits at most ten free-form
strings of at most 64 Unicode scalar values each; `license` is a string of
at most 64 scalar values declaring the content's license.

`meta` is the one descriptive field that lives inside the signed Delta
rather than in the Payload, so it is sealed with the Delta and is outside
the withdrawal mechanism entirely: it can never be erased. A Publisher
MUST NOT place personal data in `meta`, `topics` included, whatever the
page itself publishes — the allowance §9 grants a Payload does not extend
here, because the basis for that allowance is that a Payload can be
withdrawn and `meta` cannot. Where a page's subject is a person, that
belongs in the Payload's `summary`.

### 3.8. `publisher`

The REQUIRED Canonical Host (§2) of the Publisher making this statement.
It MUST equal its own Canonical Host bytes, using the same host profile as
Declaration `domain` (§5.1). Missing, non-string or noncanonical values are
`WIST1-E14`, checked before semantic rejection or idempotent acceptance.
Validators MUST NOT normalize or insert this field into signed bytes.

Only the Declaration history for this exact domain supplies the authority
and signing bindings for the Delta (§5). A matching key in another domain's
Declaration, a URL hostname or ancestor, a Feed location, or materialization
preference MUST NOT substitute another Publisher. An unavailable authorized
Key Set is `WIST1-E02` under §5.1, even when another domain has a verifying
key. The URL must satisfy this named Publisher's literal scope (§3.2),
including explicitly listed hostnames outside its ancestry.

Every Canonical Host is a separate Publisher identity. It is not a
separate accounting unit: the Ping quota, the ingest budget and the
per-domain Block capacity are keyed on the host's Registrable Domain
under the Public Suffix List snapshot in force (WIST-4 §3.1), so two
hosts under one registrable name share those bounds while sharing no
key, chain or scope.

`publisher` is inside `JCS(delta)`: both signature and Delta ID bind it.
Changing this field requires signing the changed bytes and produces a different
ID; changing only `sig.key_id` cannot change the Publisher. Re-signing unchanged
inner bytes after a rotation still preserves the ID. Public-key sharing and
copied public bindings do not transfer authorship or invalidate another
domain's otherwise valid Delta. See
[ADR-0029](../decisions/0029-signed-delta-publisher.md).

## 4. Canonicalization and Identity

Signing JSON requires a byte-exact canonical form. WIST uses the
JSON Canonicalization Scheme (JCS) [RFC 8785]:

1. **Canonical Bytes** = `JCS(delta)` — the inner object only, never the
   envelope.
2. **Delta ID** = `"sha256:" + hex(SHA-256(Canonical Bytes))`.
3. **Signature** = `Ed25519-sign(private_key, Canonical Bytes)`,
   base64url without padding under §2. A correctly encoded signature that
   does not verify against Canonical Bytes under the key `sig.key_id` names
   is `WIST1-E01`.

**A number is the double it denotes.** RFC 8785 §3.2.2.3 serializes a JSON
number by the ECMA-262 `Number::toString` algorithm over the IEEE-754
double the literal denotes, so canonicalization is defined on that double
and on nothing else. Two consequences are stated here rather than left to
be discovered, because each is a way for two parties to disagree about the
identity of the same octets.

The first is on the parse side. Canonicalization is only well defined if
every party recovers the *same* double from the same octets, which requires
the correctly-rounded conversion ECMA-262 already specifies: the double
nearest the literal's exact value, ties to even. A parser off by one unit
in the last place produces a different double, hence different Canonical
Bytes, hence a different Delta ID for a document neither party has altered.
A validator MUST convert with correct rounding, and a validator that cannot
MUST NOT seal what it read.

The second is on the identity side. Distinct literals can denote one
double — `9007199254740993` and `9007199254740992` are the same double —
so identity in this suite is identity of the double, not of the literal a
producer typed. A producer therefore MUST NOT rely on integer precision
beyond ±(2^53 − 1) to distinguish two objects, and every integer member the
suite defines MUST lie inside that range, in addition to its field-specific
bounds; a number outside
it is a producer's error, not a second identity. What has no double at all
— a magnitude beyond the finite range, or a form outside JSON's grammar —
has no canonicalization either, and is `WIST1-E05`. A finite double,
integral or not, always has one: a validator MUST NOT reject a number
merely for carrying a fractional part, since §9.1 leaves the `details` of
several Registry Update actions unconstrained and one such member would
otherwise make an entire Block unverifiable.

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

A signature failing any of these is `WIST1-E01`. A `keys` or
`recovery_keys` entry (§5.1) whose `public_key` is non-canonically encoded
or of small order is not admitted to the Key Set at all, and a Delta naming
it is `WIST1-E02`: the check belongs where the key enters, so that a
Publisher cannot publish a key every verifier would otherwise reject one
Delta at a time, and so that the Key Set a Consumer replays is the same set
the Aggregator ingested against.

**Excluded Declaration keys.** Exclusion derives a usable Key Set; it does
not remove or rewrite entries in the signed Declaration, and an unused
excluded key alone MUST NOT cause the Declaration to be rejected. After
§5.1's field checks, exclude any entry whose decoded public bytes do not
decode to a canonical Ed25519 point or represent a small-order point. Apply
this to both `keys` and `recovery_keys`, before collecting §5.2's signer
candidates or classifying the verified public key. For Declaration
authentication, a named identifier with only excluded bindings has no
candidate (`WIST1-E02`); at least one usable
named binding but no verifying signature is `WIST1-E01`. Check every usable
named binding from the eligible predecessor and incoming signing array,
even if another binding of that identifier was excluded. The same exclusion
applies when deriving keys for Deltas and Labels. Deltas also
apply §5.1's per-binding timestamp eligibility before signature diagnostics;
Declaration authentication applies no such time filter.

Retain the original Envelope for signatures, hashes, predecessor links,
idempotence and recovery-set byte protection. Identifier uniqueness and
cross-set disjointness in §5.2 apply to all signed entries before exclusion;
excluded entries cannot hide a duplicate or permit an otherwise forbidden
recovery-set change. A structurally nonempty `keys` array MAY yield an empty
usable signing set: a replacement authenticated by a usable predecessor key
is still accepted, but no Delta can authenticate under that empty set.
An initial Declaration with no usable signing key cannot self-authenticate
and is `WIST1-E02`. Likewise, a nonempty signed `recovery_keys` array with no
usable recovery key remains protected; exclusion gives no signing key the
authority to change it. A Publisher must keep a usable recovery key to retain
that recovery path. These rules do not filter keys by `valid_from` during
Declaration authentication; §5.1 applies that bound when checking a Delta.

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
  "delta": { ... },
  "sig": {
    "key_id": "1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y",
    "alg": "Ed25519",
    "value": "<base64url signature, 86 characters>"
  }
}
```

**One construction, for every signed object in the suite.** Every signed
object in WIST is built exactly as above: the Envelope's single
inner object is canonicalized with JCS, those Canonical Bytes are signed
with Ed25519, and the signature is detached into `sig`. Where WIST-2, WIST-3
and WIST-4 define new signed objects — the Feed and its Pages, the Publisher
Declaration, the Block header, the Checkpoint, the Log Anchor, the
Snapshot Index and Manifest, the Label, the Registry Update — this
rule applies unchanged, and each of those documents names only which inner
object it wraps. A verifier that implements it once implements it for the
whole suite, and there is no per-object signing variant to get wrong.

The Log Block (WIST-3 §3.1) is the one object that carries a second member
beside its signed one, and it does not except the rule: the inner object is
`header`, and `entries` sits alongside it, authenticated indirectly through
the `merkle_root` and `entry_count` the header commits to. A verifier signs
and checks `JCS(header)` exactly as it would any other inner object, and
recomputes those two fields over `entries` before using them.

Because identity is content-derived, resubmitting an identical Delta
yields the same Delta ID; validators MUST treat duplicates as idempotent
acceptances, not errors. Two Deltas differing in any byte of Canonical
Bytes are distinct objects.

The Payload is outside all three constructions. Canonical Bytes cover the
Delta's `payload` commitment, never the content it commits to, so the
Delta ID, the signature, and every Merkle root and Block Hash derived from
them are computed without the content and stay valid when the content is
withdrawn (WIST-3 §6.2). A Payload is authenticated by recomputing the
commitment (§3.6), not by any signature of its own.

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
`seq` 0; see §5.2), optional `subdomain_scope` (hostnames the Key Set
also covers), the `keys` array of signing entries (see **Key entries**
below), optional `recovery_keys` (same item shape as `keys`; see §5.2),
optional `next_keys` (a Key Set fingerprint committing to the next signing
set; see §5.2), and optional `contact`.

**Key entries.** Each `keys` or `recovery_keys` entry is an Ed25519 JSON
Web Key (RFC 8037) with exactly the members `kty` (`"OKP"`), `crv`
(`"Ed25519"`), `x` (the raw public key in canonical base64url, §2), `kid`,
`nbf` and optionally `exp`. `kid` MUST equal the entry's JWK thumbprint
(RFC 7638): the unpadded base64url encoding of SHA-256 over the JCS
serialization of `{"crv": "Ed25519", "kty": "OKP", "x": <x>}`. The `keys`
array is the `keys` member of a JWK Set (RFC 7517), and a signature block
(§4) names an entry by its `kid` in `key_id`. `nbf` and `exp` are
NumericDate integers (RFC 7519 §2): seconds since 1970-01-01T00:00:00Z
ignoring leap seconds, from 0 to 253402300799. `exp`, when present, MUST
be greater than `nbf`. A `kid` that is not the thumbprint of `x`, or an
`exp` not greater than `nbf`, is `WIST1-E14`.

**Key Set fingerprint.** The fingerprint of a signing set is
`"sha256:" + hex(SHA-256(JCS(kids)))`, where `kids` is the JSON array of
the set's `kid` strings in ascending byte order. §5.2 uses it for
`next_keys`; the DNS record below publishes it.

**DNS fingerprint record.** A Publisher MAY publish a TXT record at
`_wist.<domain>` whose content is `v=wist1; keys=<fingerprint>` for the
signing set of its current Declaration, and SHOULD update it with every
change of that set. The record carries no key and is not a discovery
channel (§8): a validator MAY query it and report a mismatch or an absent
record, and MUST NOT let the result change whether a Declaration or a
Delta is accepted.

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
do not change the Declaration's Publisher identity. Feed and status `domain`,
Publisher-domain Snapshot fields, and Registry Update `subject` when it names
a Publisher use this same format and exact identity. This does not apply a
hostname format to subjects that name parameters or keys. Each object's existing failure
disposition and diagnostic remains applicable.

**Declaration field validation.** A validator MUST reject a canonicalizable
Declaration Envelope that violates its schema or the integer range in §4
with `WIST1-E14`. This includes missing required members, wrong JSON types,
unknown members, optional members present as `null`, empty `keys`, string
bounds, noncanonical or malformed host fields, a key entry in either array
whose `kid` is not its thumbprint or whose `exp` is not greater than
`nbf`, and malformed signature-field encodings. Schema `format` constraints
are assertions, not optional annotations. Apply the fields' specified
formats; `nbf` and `exp` are integers, never timestamp strings. A valid
encoding that fails cryptographic key or signature verification is
governed by §4 and §5.2, not this syntax error.

Perform this field validation before Declaration sequencing, same-Block
conflict comparison, idempotence or signer resolution, including for a
re-serve of the current `publisher` object. Do not repair, strip, coerce or
normalize signed members to make a malformed Envelope acceptable. Invalid
JCS input remains `WIST1-E05`. For a structurally valid Declaration, §5.2's
semantic sequence, predecessor and key-set checks retain `WIST1-E08`;
for example, absence of `prev_declaration` at `seq` > 0 is that semantic
error, while a present malformed hash is `WIST1-E14`. A failed Declaration
field check during Block replay rejects the whole Block under §5.2,
including its tentative settlements and other domains' transitions.
First-contact Declaration pull failure remains wrapped as `WIST2-E04`
under WIST-2 §5; `WIST1-E14` identifies the underlying field failure.

Discovery MUST use HTTPS; there is no alternative channel. A validator MUST
NOT accept a Publisher Declaration served over plain HTTP, and MUST NOT
follow a redirect whose target host is outside the Publisher's authority
(WIST-2 §8).

A validator MAY cache a Key Set for at most 24 hours (Parameter Registry:
Key Set cache TTL). While a cached Key Set is valid, a discovery failure
does not block validation. When no valid cached Key Set exists and
discovery fails, the validator MUST fail closed: Deltas are rejected with
`WIST1-E02` and MUST NOT be sealed. The cache is a ceiling on staleness,
not a licence for it: a signature that fails under a cached Key Set is
the one observation that tells a validator the cache may be behind a
rotation. For live Delta ingestion, either binding failure below
(`WIST1-E01` or `WIST1-E02`) triggers the Declaration retry procedure in
WIST-2 §5. Historical replay and sealing use their Log-derived sources
(§5.2); they MUST NOT substitute live discovery for those sources.

`nbf` and `exp` bound each signing binding's use. After field validation,
collect every signing entry whose `kid` equals the Delta's `sig.key_id`
from the source Key Set or sets authorized by §5.2 for exactly
`delta.publisher` (§3.8). No other domain's bindings participate. Exclude
unusable public keys under §4, then exclude each binding whose window does
not contain the Delta's `observed_at`: a binding is eligible when `nbf` ≤
`observed_at` and, if `exp` is present, `observed_at` < `exp`, comparing
the exact instant under §3.4 with the NumericDate integer. If no binding
remains, reject with `WIST1-E02`. Otherwise verify the signature against
every remaining candidate until one succeeds under §4; accept this key
check if any succeeds, or reject with `WIST1-E01` if none does.

An eligible binding must itself satisfy both the window and the
signature check. A verifying signature under a binding outside its window
cannot borrow another binding's window. In particular, one eligible binding
with a failed signature plus one out-of-window binding with a valid
signature is `WIST1-E01`; all named bindings being excluded or out of
window is `WIST1-E02`, regardless of their signature results. The field failures specified in §2
and §3.4 retain `WIST1-E14` precedence. Other Delta checks and object-specific dispositions,
including recovery settlement's `WIST1-E13`, remain applicable.
Across distinct Delta checks, §7 permits any established applicable semantic
diagnostic; the binding check itself retains the E02/E01 distinction above.

Preserve complete `(kid, nbf, exp)` bindings across the authorized
sources; one key listed by two sources with different windows keeps both.
Candidate or source iteration order MUST NOT affect acceptance or its
diagnostic. Recovery-only entries and pending Declarations (§5.2) supply
no Delta authority. Backdating a Delta to before every authorized binding
existed therefore fails this check, as does dating it after every binding
expired.

### 5.2. Sequencing, Rotation and Revocation

Every Publisher Declaration carries a monotonic `seq`, starting at 0. A
Declaration with `seq` > 0 MUST include `prev_declaration`,
`"sha256:" + hex(SHA-256(JCS(publisher)))` computed over the *previous*
Declaration's inner `publisher` object — the Declaration this one
replaces. A validator MUST reject a Declaration under `WIST1-E08` when:
`seq` is not greater than the highest it has already accepted for that
domain; or `seq` > 0 and `prev_declaration` is absent; or
`prev_declaration` does not equal the hash of an eligible predecessor's
`publisher` object under the recovery-head rules below. Outside recovery,
that predecessor is the current Declaration. This makes replay of a superseded
Declaration (for example from a stale cache) detectable rather than
silent, the same way `WIST1-E07` treats a missing or mismatched `prev` on
a Delta.

Re-serving the current Declaration is not that replay: a Declaration
whose inner `publisher` object is byte-identical under JCS to the one
current for the domain — equivalently, one with the same hash of its own
`publisher` object — is an idempotent acceptance, not `WIST1-E08`,
exactly as a duplicate Delta is (§7). §5.1 caps a cached Key Set at 24 hours, so a validator MUST
re-fetch the Declaration of a Publisher whose keys never change, and a
rule rejecting what that fetch returns would reject every stable
Publisher in the system. A Declaration carrying an already-accepted
`seq` with any other bytes is `WIST1-E08` as above — that is precisely
the superseded-replay and same-`seq`-mutation case the rule exists to
catch.

Key rotation is performed by publishing a Declaration whose envelope is
signed by a key from the **previous** Key Set. The first Declaration a
domain publishes (`seq` 0) is self-signed. A key is revoked by publishing
a Declaration that omits it. A Declaration that lists the outgoing key
with an `exp` beside the incoming key gives the two an overlap window in
which Deltas verify under either (§5.1); the outgoing key keeps its
Declaration signing authority until omitted. The `nbf` and `exp` windows
bound Deltas only: signer resolution and classification below use set
membership regardless of the window.

**Rotation commitment.** A Declaration MAY carry `next_keys`, the Key Set
fingerprint (§5.1) of the signing set its next ordinary rotation will
install. When the eligible predecessor carries `next_keys`, a replacement
classified below as an ordinary rotation MUST either keep the
predecessor's signing `kid` set and its `next_keys` unchanged, or list a
signing set whose fingerprint equals the predecessor's `next_keys`; any
other ordinary rotation is `WIST1-E08`. The replacement MAY carry its own
`next_keys`. A recovery rotation and a fresh identity are not bound by the
predecessor's commitment. Publishers SHOULD generate the committed keys
before committing and hold them apart from the current signing keys, so
that a party holding only the current signing key can rotate to nothing
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
alike; a Declaration that adds,
removes, or alters a recovery key MUST be signed by one of the recovery
keys it is replacing, and is rejected with `WIST1-E08` otherwise. Without
this rule the mechanism would be worthless: a thief holding a signing
key could rotate and drop the recovery keys in the same Declaration,
permanently severing the owner's path back — and a thief holding only
the web server could do the same with a fresh identity, which is why the
rule reads the signer and not the classification: whatever a Declaration
is, only a recovery key can change the recovery keys. A Publisher whose previous
Declaration lists no recovery keys MAY establish them with an ordinary
signing-key signature — there is nothing yet to protect — which is how a
Publisher adopts recovery keys after the fact.

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
within `keys`, within `recovery_keys`, or across them, even when the
repeated entries are identical. Reject such a Declaration with
`WIST1-E08`, including a first (`seq` 0) Declaration. Because `kid` is
the key's thumbprint (§5.1), an identifier names at most one key and a
key carries one identifier: for a Delta, `sig.key_id` selects at most one
entry within each authorized source set, and §5.1 checks every selected
binding when recovery admission authorizes two sets. This rule is a
semantic constraint beyond the Declaration schema.

**Declaration signer resolution.** For a replacement Declaration, collect
the entries named by its `sig.key_id` from the eligible predecessor named
by `prev_declaration` (as defined below), using that
Declaration's `keys` and `recovery_keys` and from the incoming Declaration's
`keys`. Verify the Envelope against those candidate public keys using §4's
signature profile, excluding unusable bindings under §4 first. No usable
named candidate is `WIST1-E02`; usable named candidates but
no verifying signature is `WIST1-E01`. The same `kid` in both sources
names the same key. The first Declaration instead resolves its signer only
from its own `keys`.

Classify the authenticated public key by set membership: membership in
the previous signing set is ordinary rotation, membership in the previous
recovery set is recovery rotation, and membership in neither is fresh
identity. Recovery-key protection still applies to the resulting
classification. The rule does not authorize
an incoming recovery key to authenticate its own installation.

**Same-Block Declaration conflicts.** For each domain, process the Block's
Declarations in groups of equal `seq`, in ascending `seq`, after settling
any due recovery window. Evaluate each group against the state after all
lower-sequence groups, before applying any member of this group. If every
member's canonical `publisher` bytes equal the current Declaration's, the
group is idempotent: it installs no Declaration or signature. Otherwise,
every member MUST have identical canonical Envelope bytes, including `sig`;
validate and apply that one Envelope once. Exact repeats have no additional
effect. For structurally valid Envelopes, test group equality before any
member's signature; do not filter invalid signatures to select a winner.
Distinct Envelopes in such a group invalidate the entire Block
under `WIST1-E08`, even if each would be admissible alone, or they differ
only in signatures over the same `publisher` object. This applies to initial
(`seq` 0) Declarations and inside recovery windows as well as outside them.
Equal sequences for different domains do not conflict. Canonical leaf order
MUST NOT select a winner or make another member an idempotent re-serve by
installing the first member. A repeated Envelope does not waive any ordinary
sequence, predecessor, key or signature check on its first installation.

An Aggregator MUST NOT seal a Block with a conflicting Declaration group.
A Consumer encountering one MUST reject the entire Block, retaining its
previous accepted prefix and state; no Entry or settlement from that Block
takes effect. The same whole-Block rejection applies when a Declaration
fails its acceptance checks during Block replay, with that check's error
code. If different domains have different acceptance failures, a validator
MAY report any of those applicable error codes; no cross-domain diagnostic
order is required. Rejection and retained state MUST agree regardless of
which error is reported. This rule governs sealed Blocks; it assigns no
winner among unsealed submissions or obligation to seal a rejected candidate.

**Accepted sequence and recovery heads.** For each domain, retain the
highest accepted `seq` independently of which Declaration is current.
Supersession MUST NOT decrease that sequence floor: every new Declaration,
including a legitimate recovery follower, MUST exceed it. A rejected
candidate and an idempotent re-serve change neither the floor nor any head.
For Log replay, acceptance here means acceptance in ascending
`(Block height, seq)` application order; unsealed submissions are not part
of the replayed floor.

Without an open recovery window or a pending head (below), only the
current Declaration is an eligible predecessor. Accepting a replacement makes it current. A recovery rotation
also establishes the **recovery-chain head**, initially that same Declaration.
While the window is open, a new Declaration MAY name either the current
Declaration (the latest accepted replacement) or the recovery-chain head.
No other ancestor is eligible; an ineligible predecessor is `WIST1-E08`.
The named predecessor supplies every previous signing/recovery set used for
signature resolution, classification and recovery-key protection above.
Accepting a replacement always makes it current. It advances the
recovery-chain head only if it names that head and authenticates as an
ordinary or recovery rotation against it. A fresh identity, or a replacement
of a competitor, does not join the recovery chain. A later recovery rotation
inside the window does not change its owner or deadline.

For Delta queuing, the window contains Blocks from its opening Block through
those whose `sealed_at` is strictly earlier than its end. Declaration
competition instead starts immediately after the owner's application in
ascending `(Block height, seq)` order. A Declaration applied earlier in the
opening Block is a predecessor, not a competitor, and is not superseded by
this window. Before applying any Declaration in the first Block at or after that end, settle the window: make its
recovery-chain head current, supersede its accepted non-chain competitors, and close the
window without changing the sequence floor. Only the restored current head
is then an eligible predecessor; a superseded competitor is `WIST1-E08`.
The same transition applies to admission at or after the window's end.
Re-serving the current Declaration remains idempotent even when its `seq`
is below the retained floor. Re-serving any other accepted Declaration is
`WIST1-E08`, including a recovery-chain head that is not current while the
window is still open. Idempotence installs no new Declaration or signature
and does not reopen a window.

**Unsealed Declarations at settlement.** Admission and Log replay retain
their own accepted heads and sequence floors. At admission settlement, the
restored current head includes legitimate followers already accepted there,
even when they have not sealed. Queue revalidation still uses only the last
recovery-chain Declaration sealed strictly before the deadline, as specified
below. An unsealed follower MUST NOT supply that queue-settlement authority.
Closing the admission window is persistent: later pulls and the first
deadline Block MUST NOT repeat that admission transition over replacements
already accepted after it. The sealed-history window closes separately when
a valid Block at or after the deadline applies.

Remove every superseded, still-unsealed non-chain Declaration from the
eligible sealing set, including ordinary, fresh and recovery descendants of
a competitor. Such a copy MUST NOT first install after the deadline. This is
an exception to the Declaration sealing obligation below: it prevents a
competing act from becoming a fresh identity or a new recovery merely through
delayed inclusion. Supersession adds no new rejection diagnostic; a re-serve
remains subject to the retained admission floor and current-object idempotence.
Previously sealed competitors remain in the Log and undergo normal replay
supersession. A Consumer cannot infer unsealed admission history from a Block;
the removal duty belongs to the Aggregator that accepted those copies.

Retain pending legitimate recovery-chain followers in predecessor order.
They remain subject to every acceptance check at their actual sealing Block,
whose sequence floor excludes unsealed admission. In particular, a retained
recovery-signed follower first applied at or after the old deadline opens a
new window if none is then open; the first recovery in application order
owns it. Earlier admission inside the old window cannot suppress that
Log-derived effect. A new Declaration admitted at or after settlement
uses the restored current admission head and a sequence above the retained
admission floor. Its fresh or recovery classification has the normal
post-settlement admission semantics, rather than inheriting the closed window's
protection. Actual Log effects still follow sealing application order: if a
retained recovery follower opens a new window before a fresh successor applies,
that successor is a competitor inside the new window and does not reset identity.
`vectors/wist1/recovery-admission.json` separates these admission and sealing
traces, including the exact deadline and a copy sealed just before it.

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
the current Declaration is unchanged. Read `declaration_activation_blocks`
(Parameter Registry, default 24) from the parameter map in force at the
Block sealing the first pending Declaration and freeze the **activation
height**: that Block's height plus the parameter. While a pending head
exists, the eligible predecessors are the current Declaration and the
pending head. A replacement naming the pending head is authenticated,
classified and checked against it as its predecessor, opens no recovery
window whatever signs it, and on acceptance becomes the pending head
without moving the activation height. A Declaration whose `publisher`
object is byte-identical to the pending head is an idempotent acceptance,
exactly as a re-serve of the current Declaration is: it installs nothing,
does not raise the sequence floor and is not `WIST1-E08`. Discovery
re-fetches a served Declaration throughout the activation delay, so the
rule that catches a superseded replay must not catch the pending head its
Publisher is still serving. A replacement naming the current
Declaration MUST authenticate as an ordinary or recovery rotation against
it; a fresh identity naming the current Declaration beside a pending head
is `WIST1-E08`. On acceptance that replacement becomes current and the
pending head and every Declaration that named it are discarded:
superseded, never current, and excluded from every later predecessor and
Key Set resolution. This is the **reversal**, the answer a Publisher that
still holds a listed signing or recovery key gives to a Declaration
published from its web host alone. A recovery rotation that reverses a
pending head opens a recovery window as any recovery rotation does.
Before applying any Declaration in the Block at the activation height,
activate: the pending head becomes current, the pending state ends, and
the domain's identity resets at that height, so a party reading its
history from the Log reads it from the activation height. With
`declaration_activation_blocks` at 0 the activation height is the sealing
height itself and the fresh identity activates in the Block that seals it.

A pending Declaration supplies no authority: a Delta signed under its
keys is `WIST1-E02` until activation, and Deltas continue to verify under
the current Declaration. Signed histories for a delayed activation, a
reversal by each key class and a zero delay appear in
`vectors/wist1/key-directory.json`, with the thumbprint known answer,
entry field cases, window boundaries and commitment cases §5.1 and this
section fix. A fresh identity accepted inside an open recovery
window is a competitor under the rules below, never pending. The sequence
floor counts pending Declarations, so a reversal MUST exceed the pending
head's `seq`. The pending head, its sealing height and the activation
height are Snapshot state (WIST-3 §7).

**Compromise recovery.** A Declaration with a higher `seq` is classified
by what signs it, using the authenticated public key resolved above:

- Signed by a key in the previous Key Set — an ordinary rotation.
  Accepted; the identity is preserved.
- Signed by a key in the previous Declaration's `recovery_keys` — a
  **recovery rotation**. The recovery window (Parameter Registry:
  `recovery_window_days`, 7 days) opens at the `sealed_at` of the Block
  sealing that Declaration's own `publisher_declaration` Entry, and during
  it the domain's Deltas are queued rather than sealed. Read
  `recovery_window_days` from the parameter map in force at that opening
  Block, including amendments effective exactly then. Freeze the end at
  that Block’s `sealed_at` plus that many 86,400-second days. Later parameter
  amendments and in-window recovery rotations MUST NOT move the end. An end
  later than `9999-12-31T23:59:59Z`, the last instant a Log timestamp
  denotes (WIST-3 §3.1), cannot be frozen: an Aggregator MUST NOT seal a
  recovery Declaration whose window would end there, and a Block sealing
  one is rejected as a whole under `WIST1-E08`, exactly as a Block sealing
  a superseded Declaration; WIST-4 §5 keeps `recovery_window_days`
  amendments inside that range from their own `effective_at`.
  A Delta is queued
  when it verifies under **either** the Key Set in effect immediately
  before the recovery **or** the recovery Declaration's own — the union,
  because the Publisher that has just recovered must be able to keep
  publishing under its new keys, and the compromised key's Deltas must
  still reach the queue, which is where the settlement below rejects them
  in the open rather than at an ingest no replaying party can see.
  Freeze both source Declarations, including their signing bindings and scopes,
  at the owner's application, including any lower-sequence predecessor in the
  same Block. Later in-window Declarations,
  including legitimate recovery-chain followers, MUST NOT replace either
  admission source. Apply §5.1's complete-binding check across these two
  sources, preserving reused identifiers and their distinct validity bounds.
  Apply §3.2 using those same frozen sources; neither a competitor nor a
  legitimate follower can expand, shrink or replace their admission scopes.
  This union authorizes queue admission only, not sealing or historical
  Delta verification.
  At the end of the window the recovery Declaration takes effect with its
  identity preserved, and **every** Declaration accepted
  after the owner while the window is open
  other than the recovery Declaration and the chain legitimately following
  it is superseded — an ordinary rotation and a fresh identity alike, so a
  thief holding only a signing key cannot outrun the holder of the
  recovery key by rotating *or* by generating a new key pair and starting
  over under the same domain. A Declaration legitimately follows when its
  authenticated signing public key belongs to its named predecessor's
  `keys` or `recovery_keys`, that predecessor being the current
  recovery-chain head under the rules above: the recovering Publisher may
  therefore rotate again inside its own window without forfeiting it. At the window's end the queue is
  settled deterministically: each queued Delta is revalidated against the
  signing bindings and scope of that chain's newest Declaration — the recovery
  Declaration's own unless a legitimate follower was sealed inside the window.
  This source is fixed immediately before applying any Declarations in the
  first Block at or after the deadline. Admission at or after the deadline
  first performs this settlement; new candidates use the then-current
  Declaration, including any replacements already accepted at admission.
  After mandatory field checks, a queued copy failing either the complete
  binding check or the scope check against the settlement source is rejected
  with `WIST1-E13` and surfaced
  on the status endpoint (WIST-2 §7.1) like any other typed rejection.
  The rejection is of the queued copy and not of the Delta's identity: the
  same Delta re-served later and satisfying the signing and scope authority
  then in force is eligible like any other, subject to all remaining checks.
  This keeps replay agreement free of a per-Log list of dropped IDs that
  every Consumer would have to carry.
  A Delta signed by the superseded signing key is exactly the case this
  settles: if the recovery rotated that key out, the Delta dies with it,
  which is the point of the rotation. The survivors become eligible
  (WIST-4 §5) for the first Block whose `sealed_at` is at or after the
  window's end, in their original acceptance order, and the WIST-4 §5
  inclusion ceiling counts from that Block — a queued Delta is out of
  the ceiling's reach while the window holds it, or the window and the
  ceiling would be two MUSTs one Aggregator cannot both keep.
  The window is derived from the Declaration's own sealing height, so a
  Consumer replaying the Log computes the same window, the same effective
  height, and the same historical Key Set; no Aggregator act opens or
  describes it, because the suite's only answer to a stolen signing key
  MUST NOT rest on the Aggregator choosing to file. The sealing itself is
  a duty with a deadline for the same reason: on
  discovering a served recovery Declaration that verifies — by pull, by
  hint, or by the Publisher's Ping — the Aggregator MUST seal its Entry
  within the number of Blocks `record_seal_blocks` fixes (WIST-4 §5's
  discovery sealing deadline, default 24). Supersession of a still-unsealed
  non-chain copy at the recovery deadline cancels that copy's remaining
  sealing duty, without excusing a sealing-latency violation already incurred
  before supersession. Legitimate followers retain their sealing duty.
  A recovery the operator can
  shelve indefinitely would leave the suite's only answer to a stolen key
  resting on the operator's goodwill. The violation is attributable — the
  Declaration is signed, dated by its own `seq` and `prev_declaration`,
  and any third party can fetch the well-known path and observe the Log
  not sealing it — but it is not derivable from the Log alone, because
  the Log cannot see an unserved file; that residue is recorded here
  rather than papered over, and it is the fork-level remedy (WIST-3 §3.4)
  that ultimately answers an Aggregator that sits on recoveries.
  Two recovery Declarations sealed inside one open window — two holders
  of recovery keys, or one holder twice — are resolved in ascending
  `(Block height, seq)` order for that domain. Within a Block, validate
  and apply Declarations in ascending `seq`, including their signatures
  and predecessor links, before selecting the first accepted recovery
  Declaration as the window owner. The canonical leaf-hash storage index
  MUST NOT select the owner or override sequence precedence. This ordering
  does not waive any Declaration acceptance check. The first-sealed recovery
  Declaration in this application order is the one the window belongs to,
  and a second sealed
  inside that window is a competing claim that does not open a second
  window and does not supersede the first; whichever party prevails does
  so by holding the recovery keys the *first* Declaration now lists.
- Signed by neither — a **fresh identity**. The Declaration is accepted.
  Outside an open recovery window it becomes pending under the rule above
  and resets the domain's identity only at its activation height. Inside an
  already-open window it is a competing Declaration: acceptance changes
  the current Declaration and sequence floor, but MUST NOT reset
  identity, in an open prefix or after settlement. It is superseded at the window's end by the
  rule above; fresh classification alone is never a `WIST1-E08`. The sequence,
  predecessor and recovery-key checks still apply. Rejecting an otherwise
  valid fresh identity at ingest would leave the attempt invisible to a party
  replaying the Log.

A Publisher that loses both its signing keys and its recovery keys
starts over; that is the honest outcome, because with no cryptographic
continuity left nothing distinguishes the Publisher from a new owner of
the same name, and preserving standing on domain control alone would let
anyone buy an aged domain and inherit its history.

**Historical verification.** Accepted Declarations are sealed into the Log
as `publisher_declaration` Entries (WIST-3 §3.3), except unsealed non-chain
copies removed by recovery supersession above. The Key Set applicable to a
`publisher_delta` Entry sealed in Block N is the Declaration current for
its signed `delta.publisher` domain once Block N's Declaration Entries,
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
window's own anchor — the `sealed_at` of the Block sealing the recovery
Declaration — and the activation height, derived from a sealing height,
are all present in the Log itself, this resolution — ordinary case,
recovery exception and activation alike — is fully deterministic from log
order alone, with no fetch and no trust in the Aggregator. "Took effect under the Compromise recovery rule" is
therefore a predicate every replaying party evaluates identically, rather
than a claim resting on an entry the Aggregator may or may not have filed.

The selected Declaration also supplies the scope for historical Delta
verification under §3.2. A later scope change does not revise authority at
an earlier Delta's sealing height. Deltas cannot seal during an open recovery
window. Recovery settlement does not exempt a survivor from revalidation
against the Declaration applicable at its actual sealing height, including
Declarations in the deadline Block. A scope failure at sealing is `WIST1-E03`;
a Consumer ignores such an Entry and advances no chain tip. A settlement
survivor is therefore only authority-eligible, not guaranteed inclusion.

The Key Set so resolved is the one a sealed Delta MUST verify under, and
it is not always the one the Aggregator ingested against. Ingest
verifies a Delta against the Key Set current at the pull; a Declaration
accepted between that pull and the seal can retire the key that signed
it; and WIST-3 §3.3 applies a Block's Declaration Entries before its
Deltas, so a Delta sealed in the same Block as — or above — the
Declaration retiring its signing key fails under the resolution above on
every replay. An Aggregator therefore MUST NOT seal a Delta that does not
verify under the Key Set resolved at its sealing height, the sealing
Block's own Declaration Entries included. While the Block it queued the
Delta for is still open, sealing the Delta there and the Declaration in
the next Block satisfies this — Block membership is the Aggregator's
choice — and otherwise the Delta is rejected with `WIST1-E02` at
sealing, reported through the status endpoint (WIST-2 §7.1), and never
sealed. The Publisher's remedy is to re-sign the Delta under its new Key
Set: the Delta ID is over the inner object (§4) and is unchanged, and a
rejected ID is pulled again (WIST-2 §5). A replaying Consumer that meets
such a Delta in a Log — an Aggregator's breach — ignores the Entry: it is
applied to nothing and moves no chain tip (WIST-3 §7), exactly as a
Delta whose `prev` is not the tip.

## 6. Deliberate Normative Absence

This specification defines no field by which a publisher may declare the
importance, relevance, or ranking of its own content. This absence is
deliberate and constitutional; see WIST-4.

A Delta may say "I changed" and "my content is this". It cannot say "I
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
Payload validation once its committing Delta and parameter profile are
supplied; it imposes no precedence between independent Delta and Payload
failures. WIST-2 §5 retains its WIST2-E03 pull wrapper, and WIST-3 §6.1 retains
its availability and materialization dispositions. See
[ADR-0034](../decisions/0034-payload-field-diagnostics.md).

**Delta diagnostics.** Invalid JCS input is `WIST1-E05`. For a
canonicalizable Delta Envelope, validate its complete field structure under
`delta.schema.json`, including §2 base64url, §3.4 timestamps and §3.8
Publisher spelling, before semantic rejection or idempotent acceptance.
Missing required members, unknown members, wrong types, explicit null in an
optional member, malformed strings and forbidden `payload` on `attest` or
`delete` are `WIST1-E14`, with these exceptions:

- A string `url` retains E03 for normalization/authority and E11 for its
  §3.2 size bound; a missing or non-string `url` is E14.
- Absent `prev` required by §3.3/§3.5 retains E07; a present malformed
  `prev` is E14. Absence alone requires no network retrieval.
- Absent `payload` on `new` or `update` retains E09; a present malformed
  commitment object is E14.
- A nonnegative integral `payload.bytes` within §4's safe-integer range
  but exceeding §3.6's active derived cap retains E04; a negative, fractional,
  nonnumeric or unsafe-integer value is E14. Integer eligibility
  depends on the JSON number's value, not decimal or exponent spelling.

The schema's fixed `url.maxLength` and `payload.bytes.maximum` describe
the default profile. For these two checks, validators MUST instead apply
§3.2's JCS-octet URL cap and §3.6's derived commitment cap from the parameter
profile required at their validation stage under WIST-4 §5; the fixed schema
values MUST NOT reject an object permitted by that active profile.

Apply all E14 checks before these semantic exceptions. String lengths in
schema field checks count Unicode scalar values, without normalization;
URL/content octet caps retain their own rules. Field validation does not
change other objects' diagnostics. Version spelling is an E14 field check;
an unsupported major is the semantic error E15 (§3.1), after all E14 checks.

After those checks pass, a validator MAY report any applicable semantic
error whose conditions it has established. No priority is imposed between
the binding check (`WIST1-E02` or `WIST1-E01`), URL authority/normalization
(`WIST1-E03`), clock allowance (`WIST1-E06`), predecessor chain
(`WIST1-E07`), version support (`WIST1-E15`), or other Delta semantic checks.
Thus an invalid signature and excess skew permit either E01 or E06; excess
skew and an out-of-scope URL permit either E06 or E03. A validator MUST NOT accept a Delta that
fails any required check. This freedom governs diagnostic selection only,
not acceptance, source authority or the meaning of an error.

A validator MAY stop after establishing a rejection and need not perform
unrelated checks solely to choose a different diagnostic. Every prerequisite
of a check it performs still applies: a live Delta binding failure (E01 or
E02) still requires the Declaration retry in §5.1/WIST-2 §5 before counting
the failure; missing predecessor data still requires the retrieval attempt in
§3.5 before concluding E07. Lack of a performed check is not evidence of
its failure. E01 and E02 remain mutually exclusive outcomes of the complete
binding check in §5.1. Status rejection entries and Ping noise accounting
retain WIST-2 §7.1 and §4's rules.

Object and stage dispositions remain authoritative: this permission does
not replace recovery settlement's E13 or sealing's E02 for a Delta stranded
by a later-accepted Declaration (§5.2), change idempotent acceptance,
retroactively invalidate a sealed Delta, or bypass transport wrappers.
In particular, E10 is a Payload diagnostic, not a selectable Delta rejection;
the Payload cap checks in §3.6 and pull rejection under WIST-2 §5's
WIST2-E03 remain required. See
[ADR-0027](../decisions/0027-delta-diagnostic-selection.md).

| Code | Meaning |
|---------|--------------------------------------------------------------|
| WIST1-E01 | Invalid signature (for a Delta, no signature verifies under any usable, time-eligible named binding authorized by §5.1/§5.2, although at least one such binding exists) |
| WIST1-E02 | No usable, time-eligible named Delta signing binding in the source Key Set(s) authorized by §5.1/§5.2, including the frozen recovery-admission union, or under a pending Declaration (§5.2); or no usable Declaration signer candidate (§5.2). At sealing, a Delta stranded by a Declaration accepted since the pull is never sealed |
| WIST1-E03 | URL out of scope, not normalized, or not normalizable (host not covered by domain/`subdomain_scope`; `url` not byte-identical to its own Normalized URL; or `url` has no normalization at all — §2) |
| WIST1-E04 | Size cap exceeded, in JCS octets as §3.6 defines them (`payload.bytes` > 38944, or a retrieved Payload whose `JCS(extract)` exceeds 32768 octets, whose `JCS(links)` exceeds 4096 octets, whose `JCS(url)` on any `links.urls` entry exceeds 2048 octets, or whose `JCS(summary)` exceeds 2048 octets) |
| WIST1-E05 | Invalid canonicalization: the object is not valid JCS input. For a number this means it denotes no IEEE-754 double — a magnitude beyond the finite range, or a form outside JSON's grammar (§4). A finite double is always canonicalizable, fractional part included |
| WIST1-E06 | `observed_at` exceeds the clock plus active signed allowance selected by §3.4 |
| WIST1-E07 | `prev` chain violation: missing, not sealed at a lower Log position (§3.5), wrong Publisher or URL, non-monotonic `observed_at`, a fork (a later Delta naming a `prev` an earlier Delta has already claimed) rejected in favor of the first-sealed Delta, or a named `prev` that remains unavailable after the validator attempts retrieval per WIST-2 §3.1 |
| WIST1-E08 | Declaration sequence or recovery-key violation (`seq` not greater than the highest accepted, including superseded and pending Declarations, except an idempotent re-serve of the current Declaration's own `publisher` object (§5.2); a conflicting same-domain, same-sequence Declaration group in a Block (§5.2); `prev_declaration` absent when `seq` > 0 or not naming an eligible predecessor under §5.2, including a fresh identity naming the current Declaration beside a pending head; an ordinary rotation that neither keeps nor installs the predecessor's `next_keys` commitment (§5.2); the named predecessor's nonempty `recovery_keys` changed without a signature from that set; or a repeated `key_id` anywhere in the Declaration, or the same `public_key` named in both `keys` and `recovery_keys`); a recovery Declaration whose window would end after `9999-12-31T23:59:59Z` (§5.2) |
| WIST1-E09 | Content-bearing change type with no commitment: a `new` or an `update` that omits `payload` (§3.3). Rejected and never sealed; the Delta claims content while committing to none |
| WIST1-E10 | Payload commitment mismatch: a retrieved Payload does not reproduce the Delta's `payload.commitment` under the salt it carries, or the octet length of `JCS(content)` is not exactly `payload.bytes` |
| WIST1-E11 | `url` exceeds `url_cap_bytes` octets |
| WIST1-E12 | `links` violates a structural rule of §3.6 |
| WIST1-E13 | Queued Delta invalidated by recovery: a Delta queued during a §5.2 recovery window whose signature/binding or URL scope fails against the recovery-chain head selected at the window's end (§5.2). The queued copy is dropped and never sealed, and the drop is visible to the Publisher via the status endpoint (WIST-2 §7.1); the Delta's identity is not barred, so the same Delta re-served later and satisfying the authority then in force remains eligible subject to all other checks (§5.2) |
| WIST1-E14 | Malformed Declaration Envelope (§5.1), including an out-of-range integer, a key entry whose `kid` is not its thumbprint or whose `exp` is not greater than `nbf`; malformed Delta Envelope or Payload fields under §7, subject to their semantic exceptions; or malformed base64url under §2. Canonicalization failure remains WIST1-E05 |
| WIST1-E15 | Delta, Payload or Declaration major version not implemented by the validator (§3.1); malformed version spelling remains WIST1-E14 |

Duplicate submission of an identical Delta, and re-fetching a Declaration
whose `publisher` object is byte-identical to the domain's current one
(§5.2), are idempotent acceptances, not errors.

`WIST1-E10` rejects the Payload, never the Delta. A sealed Delta stays
sealed and stays valid, because nothing in its identity or signature
depends on content the Log never held; the party that served the
mismatched Payload is the one at fault (WIST-3 §9, `WIST3-E03`).

## 8. Security Considerations

- **Key theft.** A stolen Publisher signing key can sign fraudulent
  Deltas and can even perform a rotation that looks entirely valid: a
  Declaration signed by a key from the previous Key Set is accepted as
  an ordinary rotation immediately, with no window (§5.2). The actual
  mitigation is the recovery key: because a recovery key signs nothing
  but Declarations and is meant to be held offline, separately from the
  signing key, compromising the signing key alone does not expose it,
  and a Declaration signed by the recovery key supersedes any ordinary
  rotation sealed during its 7-day recovery window — so a thief holding
  only the signing key gets a temporary, always-reversible foothold,
  never a permanent one. A Publisher that commits to its next signing
  set (`next_keys`, §5.2) narrows even that foothold: the thief can
  rotate only to keys the Publisher generated and holds elsewhere.
  Publishers SHOULD generate recovery keys
  independently of signing keys and keep them offline, SHOULD keep
  signing keys off the web server that serves content, and SHOULD rotate
  on any suspicion of compromise; publications signed before recovery
  remain attributed to the domain. A Publisher that loses its signing key
  without ever having
  provisioned a recovery key has no cryptographic path back (§5.2).
- **Domain transfer.** A Key Set replacement does not transfer history
  by itself: §5.2 classifies a replacing Declaration by what signs it,
  and one signed by neither the previous Key Set nor the previous
  `recovery_keys` is a fresh identity, visible in the Log as such, outside
  an open recovery window, and pending for `declaration_activation_blocks`
  Blocks, during which any still-held signing or recovery key reverses it
  (§5.2). A competing fresh Declaration inside that window
  cannot take over the recovering identity or reset it (§5.2). A
  party that acquires a domain's hosting without also acquiring a
  signing or recovery key therefore cannot inherit its predecessor's
  history — only cryptographic continuity does that, never possession of
  the name alone — and a Consumer reading a domain's age or publication
  history from the Log reads it from the fresh identity's activation
  height (WIST-4 §8).
- **Payload substitution.** A Mirror, a Publisher, or anyone else in the
  serving path can offer any bytes at a Payload's URL. None of it matters:
  a validator accepts a Payload only when it reproduces the Delta's
  `commitment` (§3.6), which was fixed at signing time, so substituting
  content is detectable by every party independently and rejected under
  `WIST1-E10`. What an adversary controlling the serving path can do is
  withhold a Payload, which is an availability failure, handled by WIST-3
  §6.1 and distinguishable from a lawful withdrawal.
- **Signature malleability.** Ed25519 signatures as specified in RFC 8032
  are deterministic; validators MUST verify against Canonical Bytes only,
  under the verification profile §4 pins. That profile is what closes the
  malleability RFC 8032 leaves to the verifier: an unreduced `s` is a second
  valid signature for a message already signed, and a small-order `A` is a
  key under which one signature verifies for many keys — either would let
  two honest verifiers disagree about a sealed Entry.
- **Canonicalization attacks.** JCS removes serialization ambiguity
  (whitespace, key order, number forms). Objects that cannot be canonically
  represented MUST be rejected (`WIST1-E05`), never repaired.
- **URL authority spoofing.** The scope rule (§3.2) plus HTTPS-only key
  discovery (§5.1) bind every Delta to a domain the signer demonstrably
  controls. Validators MUST NOT relax either check.
- **Single discovery channel.** Key discovery is HTTPS-only by design. Any
  unauthenticated alternative channel would let an off-path spoofer inject
  a signing key for a domain whose HTTPS endpoint is made to fail,
  defeating every other guarantee in this document; no such channel is
  defined. The concrete mechanism this rules out is worth naming, because a
  closed door is only visible if you can see what it closed: an earlier
  draft of this specification allowed a `_wist.<domain>` DNS TXT
  record carrying the Key Set as a fallback when the well-known path was
  unreachable. Plain DNS is unauthenticated, and DNSSEC is neither
  universally deployed nor universally validated, so the fallback offered an
  attacker able to force an HTTPS failure — a strictly easier act than
  breaking HTTPS — a path to publishing keys for a domain it does not
  control. It was removed rather than conditioned on DNSSEC, because a
  fallback that is only sometimes authenticated is one whose security
  depends on a property no verifier can check at the moment it matters. No
  DNS-based, and no other non-HTTPS, discovery mechanism may be
  reintroduced within this major version. The `_wist.<domain>` fingerprint
  record §5.1 permits carries no key and changes no acceptance decision;
  it is monitoring, not discovery, and stays outside this prohibition.

## 9. Privacy Considerations

Deltas are public and, once sealed into the log (WIST-3), permanent. Content
is not: it lives in Payloads, outside the Log, and is erasable under the
logged due process of WIST-3 §6.2. That split is deliberate. Extracts are
drawn from public web pages, public web pages routinely carry personal
data, and erasure rights attach to whoever redistributes that data. An
index that sealed extract bytes into an append-only structure replicated
across mirrors it does not control would be promising a deletion it could
not perform.

Publishers MUST NOT include in a Payload's `extract`, `links`, or `summary`
personal data beyond what the referenced page itself publicly serves —
a link URL carrying a profile path or a query-string identifier is as
much a carrier of personal data as extract text is — and MUST NOT
include personal data in a Delta's `meta` at all (§3.7) — the difference
being that a Payload can be withdrawn and `meta`, sealed in the Delta,
cannot. A `delete` Delta removes content from future snapshots (the
materialized index honors deletion) but does not erase log history, and a
`payload_withdrawal` (WIST-3 §6.2) erases the content without erasing the
record that the content existed.

What remains in the Log permanently, and cannot be withdrawn, is:

- the `publisher` domain binding the statement to its author;
- the `url` itself, which is the minimum public identifier a web index
  needs and which may contain a name — the same residue Certificate
  Transparency carries in domain names;
- the fact that the URL existed, changed, or was deleted, and when the
  Publisher observed it;
- the Payload commitment and `bytes`. The commitment reveals nothing about
  the content once the salt is destroyed (§3.6). `bytes` reveals the
  content's exact length: it is corroborating rather than demonstrative,
  because unboundedly many texts share any given length, but a party
  holding a candidate text can observe that the length is consistent with
  it. It is carried because a Consumer must be able to bound a fetch and
  detect truncation before it can verify anything;
- `meta` in full — `lang`, `topics` and `license`. These are content-derived
  and sit inside the signed Delta, so unlike a Payload they are permanent
  and unwithdrawable, which is why §3.7 forbids personal data in them
  outright rather than bounding it by what the page serves;
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

- [ ] Includes its Canonical Host in every signed Delta’s `publisher` (§3.8)
- [ ] Signs `domain` and every `subdomain_scope` member in Canonical Host form (§5.1)
- [ ] Serves `publisher.json` at the well-known path over HTTPS (§5.1)
- [ ] Signs every Delta with a key in its current Key Set, over JCS
      Canonical Bytes (§4)
- [ ] Only emits Deltas for URLs within its authority (§3.2)
- [ ] Maintains correct per-URL chains: first Delta omits `prev`, later
      ones reference the immediately prior Delta (§3.5)
- [ ] Commits to content instead of carrying it: a fresh CSPRNG salt of
      ≥ 16 octets per Delta, `commitment` over `JCS(content)`, `bytes`
      equal to that length and ≤ 38944 (§3.6)
- [ ] Serves every content-bearing Delta's Payload, and keeps the anchor
      Payload of any URL it attests retrievable (WIST-2 §3.1)
- [ ] Respects the content caps in JCS octets: `JCS(extract)` ≤ 32768,
      `JCS(links)` ≤ 4096 (each `links.urls` entry's `JCS(url)` ≤ 2048),
      `JCS(summary)` ≤ 2048 (§3.6)
- [ ] Carries `payload` on every `new` and `update`, and omits it on
      `attest` and on `delete` (§3.3)
- [ ] Lists each key as an Ed25519 JWK whose `kid` is its thumbprint,
      with `nbf` and an optional `exp` (§5.1)
- [ ] Rotates keys by signing the new Key Set with a previous key, and
      keeps keys committed through `next_keys` apart from the current
      signing keys (§5.2)
- [ ] Increments seq and sets prev_declaration on every new Declaration
      (§5.2)
- [ ] Emits only Normalized URLs and keeps published Deltas retrievable
      (§3.2, §3.5)

**Validator (any party checking Deltas):**

- [ ] Applies §7's complete Payload field checks and §3.1's independent
      Payload version policy before using retrieved content
- [ ] Checks Delta version spelling and supported major under §3.1/§7,
      preserving same-major minor/patch values and field-error precedence
- [ ] Enforces the required canonical `publisher` field before semantic checks;
      uses only that domain’s authority and preserves Publisher/URL chain ownership (§3.5, §3.8)
- [ ] Recomputes Canonical Bytes with JCS and verifies the Ed25519
      signature against them (§4)
- [ ] Recomputes a retrieved Payload's commitment and length before using
      its content, and rejects a mismatch under `WIST1-E10` without
      invalidating the Delta (§3.6, §7)
- [ ] Enforces the scope rule (§3.2) and all Error Registry checks (§7)
- [ ] Treats identical resubmissions as idempotent (§4)
- [ ] Rejects Declarations served over plain HTTP (§5.1)
- [ ] Applies §3.4's attempt, sealing and historical clock/allowance anchors to `observed_at`, preserving exact endpoints and signed allowances
- [ ] Validates Publisher timestamps without leap-event data, rejects `:60`
      and compares exact offset-adjusted fractions (§3.4, §5.1)
- [ ] Checks complete named Delta bindings, filtering usability and time
      before E02/E01 diagnostics; preserves both frozen recovery-admission
      sources through later Declarations without using that union at sealing
      (§5.1, §5.2)
- [ ] Applies §7's Delta field precedence and reports only an established
      applicable semantic error, retaining retrieval/refresh prerequisites
      and object/stage dispositions
- [ ] Rejects non-monotonic Declarations and resolves historical Key Sets
      by Block height (§5.2)
- [ ] Enforces `next_keys` on ordinary rotations, holds a fresh identity
      pending until its activation height with no authority meanwhile, and
      discards it on reversal (§5.2)
- [ ] Seals a Delta only where it verifies under the Key Set resolved at
      its sealing height, the sealing Block's own Declarations included —
      a Delta a later-accepted Declaration stranded is `WIST1-E02`, not
      sealed (§5.2)
- [ ] Compares URLs and hosts only after normalization (§2)

## Appendix A. Test Vectors

Deterministic vectors generated by `tools/gen_vectors.py` (regenerate:
`tools/.venv/bin/python tools/gen_vectors.py`; verify:
`tools/.venv/bin/python tools/validate_examples.py`). The key below is a
**test vector key — never use in production**.

**Seed (Ed25519 private key, hex):**

```
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

**Public key (base64url, raw):**

```
A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg
```

**Payload ([`examples/payload.json`](../examples/payload.json)), served at
`/payloads/37e4e7246e5bcb20781adf26611128bb3b7b8d9b9ceff02f2630cdb645266860.json`:**

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

**Delta (inner object):**

```json
{
  "wist_version": "1.0.0",
  "publisher": "example.com",
  "url": "https://example.com/blog/post-1",
  "change_type": "new",
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

**Canonical Bytes (JCS, first bytes shown as hex; full form in
[`vectors/wist1/delta.canonical`](../vectors/wist1/delta.canonical)):**

```
7b226368616e67655f74797065223a226e6577222c226d657461223a7b226c61
6e67223a22656e222c226c6963656e7365223a2243432d42592d342e30222c22
...
```

Note how JCS sorts keys (`change_type` first) regardless of authoring
order.

**Delta ID:**

```
sha256:37e4e7246e5bcb20781adf26611128bb3b7b8d9b9ceff02f2630cdb645266860
```

**Signature (base64url):**

```
19vAYmF_OdKuBJwYBRS4BHskqn5zELhnGpds1N7ic0au8aM-Pe4RV9QJxz6N6QuXkgmKiPG1rdQ7j9Ntcx_zDg
```

The complete envelope is
[`vectors/wist1/envelope.json`](../vectors/wist1/envelope.json) and doubles as
[`examples/delta.json`](../examples/delta.json). Neither the extract, the
links, nor the summary appears anywhere in it.

## References

- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels
- [RFC 8174] Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words
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
