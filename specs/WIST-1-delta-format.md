# WIST-1: Delta Format & Identity

**Status:** v1.0.0-draft · **Date:** 2026-08-02 · **License:** CC-BY 4.0

## 1. Introduction

WIST is an open, verifiable, push-based web index. Instead of being
crawled, a site describes its own changes: for each URL it controls, it
publishes small signed objects called **deltas** — "this page is new", "this
page changed, here is its main text", "this page was deleted", "this page is
unchanged as of this date". Deltas flow into a public, hash-chained log
(WIST-3) from which consumers materialize a compact, fresh local index.

This document defines the two foundational objects of the suite:

- the **Delta**: the unit of information a publisher signs, and
- the **Publisher Declaration**: how a domain declares its signing keys.

How deltas are published on a site and discovered by aggregators is defined
in [WIST-2](WIST-2-site-publication.md). How they are sequenced into the log and
distributed is defined in [WIST-3](WIST-3-logbook-distribution.md). How they
are audited, and how domain reputation is derived, is defined in
[WIST-4](WIST-4-audit-reputation-governance.md).

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
  MUST NOT lowercase the input first. The algorithm is
  pinned rather than named because IDNA2003 and IDNA2008 disagree on
  characters such as `ß` (U+00DF) and final sigma (U+03C2) — IDNA2003 maps
  them away, IDNA2008 keeps them — so two implementers following "IDN
  encoding" loosely produce different bytes for the same input, which is
  precisely the failure this definition exists to prevent. RFC 5890 defines
  the terminology these terms come from; it defines no algorithm. Every
  flag is pinned for the same reason, and the two values that are not the
  strictest available are chosen deliberately. `CheckHyphens=false` matches
  the profile every browser applies: hyphen position inside a label is
  registry policy, not identity, and the strict value rejects hosts that
  resolve and serve today — which would bar them as Publishers *and* drop
  them from the citation graph of every Consumer, since WIST-2 §11
  normalizes link targets through this same definition. `CheckBidi` and
  `CheckJoiners` stay on, because those rules govern visual confusability,
  and a domain-anchored identity is exactly what confusable labels attack.
  A separate lowercasing step is excluded for the reason the paragraph
  above gives: a context-sensitive full lowercase maps a word-final Σ to ς
  and a UTS #46 mapping maps it to σ, so the extra step changes the input
  of the algorithm at the very character this definition cites, and it can
  only ever disagree with the mapping it precedes.
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

## 3. The Delta Object

A Delta is the inner object of a Delta Envelope. Its machine-readable
schema is [`schemas/delta.schema.json`](../schemas/delta.schema.json);
where prose and schema disagree, the schema governs syntax and this
document governs semantics.

### 3.1. `wist_version`

The version of this specification the object conforms to, as a semver
string. This document defines version `1.0.0`. Consumers MUST reject
objects whose major version they do not implement.

**Extensibility is by major version only.** Within a major version, objects
MUST NOT carry fields not defined by this specification; new fields are
introduced only in a new major version. Every schema in the suite therefore
sets `additionalProperties: false` on each object whose full field set a
document of this suite defines, and a minor version never adds a field. Two
places are deliberately open, and both delegate rather than extend: a Block
Entry's `body` (WIST-3 §3.3), which is an Envelope validated in full by its
own schema, and a Registry Update's `details` (WIST-4 §9.1), whose shape is
fixed per `action` — unconstrained only for the actions WIST-4 §9.1 names,
and never licensed to carry what that section's closing rules forbid. The
rule exists so that a consumer encountering an unknown field knows it is
looking at a non-conforming object rather than at a newer minor version it
could safely ignore, which is what makes rejection the safe default.

### 3.2. `url`

The URL the Delta describes. It MUST use the `https` scheme. It MUST be
within the Publisher's authority: the URL's host MUST equal the Publisher's
`domain` or one of the hostnames in its `subdomain_scope` (the **scope
rule**). A validator MUST reject a Delta whose `url` is outside the signing
Publisher's authority (error `WIST1-E03`). A host inside a parent's
`subdomain_scope` may also declare for itself; both Publishers' Deltas for
it are valid, and which one materializes is decided by WIST-3 §7's
one-URL-one-Publisher rule — self-declaration prevails from the height its
Declaration seals.

The value of `url` MUST already be a Normalized URL; a Delta whose `url`
is not byte-identical to its own normalization MUST be rejected with
`WIST1-E03`. The scope rule compares Canonical Hosts.

The UTF-8 octet length of `JCS(url)` — the JSON string literal with its
enclosing quotes and any escapes — MUST NOT exceed `url_cap_bytes`
(Parameter Registry: 2048). A validator MUST reject a Delta whose `url`
exceeds the cap with `WIST1-E11`. The schema's `maxLength` counts code
points and is a structural first pass; this octet bound governs (§3.6
states the rule once for every cap in this suite).

### 3.3. `change_type`

One of four values:

- `new` — the Publisher asserts this URL now carries content; if the URL
  has prior Deltas, `prev` MUST be present (§3.5). `payload` MUST be
  present.
- `update` — the URL's content changed. `payload` MUST be present.
  `prev` MUST be present.
- `delete` — the URL no longer serves the content its chain last committed
  to: it is gone, or what it now serves is no longer that content. That is
  the claim an audit measures (WIST-4 §5), so a page whose text has merely
  been replaced by unrelated text is a truthful `delete` and one still
  serving the committed content is a false one. The Delta MUST omit
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
to none says what happened and not what it is, so no audit could ever
confirm or refute it (WIST-4 §5 would record `not_auditable` forever) — a
claim that is unfalsifiable by construction, sealed permanently, and free.

An `attest` Delta carries no content of its own precisely because it claims
none: an audit measures it against the anchor Payload as of the Record's
reference Delta (WIST-4 §5) — its chain's newest sealed Delta at the
audit's fetch, which may follow the `attest`. That is why §3.5's chain and
WIST-2 §3.1's retention obligation reach further back than the Delta
itself. The same holds for a `delete`, whose claim is that exactly that
content is no longer served.

### 3.4. `observed_at`

The instant the Publisher observed the state being described, as an
RFC 3339 UTC timestamp. It MUST NOT be more than 10 minutes in the future
relative to the validator's clock (error `WIST1-E06`), and MUST be strictly
greater than the `observed_at` of the Delta referenced by `prev` (error
`WIST1-E07`).

### 3.5. `prev`

The Delta ID of this Publisher's most recent prior Delta for the same
`url`. Together, `prev` links form a **per-URL chain**: an ordered,
verifiable history of everything the Publisher has said about one page.
The first Delta for a URL MUST omit `prev`; every subsequent Delta for
that URL MUST include it (error `WIST1-E07` on violation).

The chain for a URL never restarts. A `new` Delta for a URL that has prior
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
truncation rule above — is checkable only against the page; that is
WIST-4 §5's link dimension, not an ingest rule. The extraction procedure
itself is defined in WIST-2 and is the same procedure for the Publisher
declaring and the Auditor checking.

`schemas/payload.schema.json` bounds `extract`, `links.urls` and
`summary.title`/`summary.abstract` with JSON Schema `maxLength`, which
counts **code points**. Those bounds are a cheap structural first pass and
are neither equal to nor implied by the octet caps above — a code point
can occupy four octets — so a validator MUST enforce the octet caps
itself. Where the two differ, this section governs.

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
withdrawal for the Deltas whose Payloads still exist and for every verdict
already recorded; hiding begins at withdrawal. The salt is what separates
them, which is why it MUST be unpredictable and unique per Delta: a
Publisher that derives salts from the content, or reuses one across
Deltas, keeps the binding and forfeits the hiding.

### 3.7. `meta`

Descriptive metadata: `lang` (REQUIRED; BCP 47 primary tag, e.g. `en`,
`pt-BR`), `topics` (≤ 10 free-form strings), and `license` (the declared
license of the page content, e.g. `CC-BY-4.0` or `proprietary`).

`meta` is the one descriptive field that lives inside the signed Delta
rather than in the Payload, so it is sealed with the Delta and is outside
the withdrawal mechanism entirely: it can never be erased. A Publisher
MUST NOT place personal data in `meta`, `topics` included, whatever the
page itself publishes — the allowance §9 grants a Payload does not extend
here, because the basis for that allowance is that a Payload can be
withdrawn and `meta` cannot. Where a page's subject is a person, that
belongs in the Payload's `summary`.

## 4. Canonicalization and Identity

Signing JSON requires a byte-exact canonical form. WIST uses the
JSON Canonicalization Scheme (JCS) [RFC 8785]:

1. **Canonical Bytes** = `JCS(delta)` — the inner object only, never the
   envelope.
2. **Delta ID** = `"sha256:" + hex(SHA-256(Canonical Bytes))`.
3. **Signature** = `Ed25519-sign(private_key, Canonical Bytes)`,
   base64url without padding. A signature that does not verify against
   Canonical Bytes under the key `sig.key_id` names is `WIST1-E01`.

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
    "key_id": "test-k1",
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
Snapshot Index and Manifest, the Audit Record, the Registry Update — this
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
also covers), the `keys` array (each entry: `key_id`, `alg`, raw Ed25519
`public_key` base64url, `valid_from`), optional `recovery_keys` (same
item shape as `keys`; see §5.2), and optional `contact`.

Discovery MUST use HTTPS; there is no alternative channel. A validator MUST
NOT accept a Publisher Declaration served over plain HTTP, and MUST NOT
follow a redirect whose target host is outside the Publisher's authority
(WIST-2 §8).

A validator MAY cache a Key Set for at most 24 hours (Parameter Registry:
Key Set cache TTL). While a cached Key Set is valid, a discovery failure
does not block validation. When no valid cached Key Set exists and
discovery fails, the validator MUST fail closed: Deltas are rejected with
`WIST1-E02` and MUST NOT be sealed.

`valid_from` bounds a key's use: a Delta whose `observed_at` precedes the
`valid_from` of the key named in `sig.key_id` MUST be rejected with
`WIST1-E02`. Backdating a Delta to before a key existed is therefore not a
route around key history.

### 5.2. Sequencing, Rotation and Revocation

Every Publisher Declaration carries a monotonic `seq`, starting at 0. A
Declaration with `seq` > 0 MUST include `prev_declaration`,
`"sha256:" + hex(SHA-256(JCS(publisher)))` computed over the *previous*
Declaration's inner `publisher` object — the Declaration this one
replaces. A validator MUST reject a Declaration under `WIST1-E08` when:
`seq` is not greater than the highest it has already accepted for that
domain; or `seq` > 0 and `prev_declaration` is absent; or
`prev_declaration` does not equal the hash of the previously accepted
Declaration's `publisher` object. This makes replay of a superseded
Declaration (for example from a stale cache) detectable rather than
silent, the same way `WIST1-E07` treats a missing or mismatched `prev` on
a Delta.

Re-serving the current Declaration is not that replay: a Declaration
whose inner `publisher` object is byte-identical under JCS to the one
already accepted for the domain — equivalently, one with the same
`prev_declaration` hash — is an idempotent acceptance, not `WIST1-E08`,
exactly as a duplicate Delta is (§7). §5.1 caps a cached Key Set at 24 hours, so a validator MUST
re-fetch the Declaration of a Publisher whose keys never change, and a
rule rejecting what that fetch returns would reject every stable
Publisher in the system. A Declaration carrying an already-accepted
`seq` with any other bytes is `WIST1-E08` as above — that is precisely
the superseded-replay and same-`seq`-mutation case the rule exists to
catch.

Key rotation is performed by publishing a Declaration whose envelope is
signed by a key from the **previous** Key Set (`sig.key_id` names the old
key). The first Declaration a domain publishes (`seq` 0) is self-signed. A
key is revoked by publishing a Declaration that omits it.

**Recovery keys.** A Declaration MAY list `recovery_keys` alongside its
signing `keys`. Recovery keys sign nothing but Declarations and are
meant to be held offline. They are the protocol's only proof of
publisher continuity, because domain control alone cannot distinguish a
Publisher recovering from key loss from a party that has merely acquired
the domain.

Recovery keys protect themselves. Once a Declaration lists a non-empty
`recovery_keys`, every later Declaration signed only by a signing key
MUST carry a byte-identical `recovery_keys`; a Declaration that adds,
removes, or alters a recovery key MUST be signed by one of the recovery
keys it is replacing, and is rejected with `WIST1-E08` otherwise. Without
this rule the mechanism would be worthless: a thief holding a signing
key could rotate and drop the recovery keys in the same Declaration,
permanently severing the owner's path back. A Publisher whose previous
Declaration lists no recovery keys MAY establish them with an ordinary
signing-key signature — there is nothing yet to protect — which is how a
Publisher adopts recovery keys after the fact.

The two sets are disjoint. A Declaration MUST NOT name the same `key_id`,
or the same `public_key`, in both `keys` and `recovery_keys`, and one that
does is rejected with `WIST1-E08`. A recovery key that is also a signing
key is neither held offline nor signing only Declarations, so it offers
nothing the signing key it duplicates does not already offer, and stealing
one steals both. The rule is also what keeps the classification below
answerable: whether a Declaration opens a recovery window is state every
replaying party must derive identically, and a signer present in both sets
would leave two defensible answers.

**Compromise recovery.** A Declaration with a higher `seq` is classified
by what signs it:

- Signed by a key in the previous Key Set — an ordinary rotation.
  Accepted; `A` and `C` (WIST-4 §6) are preserved.
- Signed by a key in the previous Declaration's `recovery_keys` — a
  **recovery rotation**. The recovery window (Parameter Registry:
  `recovery_window_days`, 7 days) opens at the `sealed_at` of the Block
  sealing that Declaration's own `publisher_declaration` Entry, and during
  it the domain's Deltas are queued rather than sealed. A Delta is queued
  when it verifies under **either** the Key Set in effect immediately
  before the recovery **or** the recovery Declaration's own — the union,
  because the Publisher that has just recovered must be able to keep
  publishing under its new keys, and the compromised key's Deltas must
  still reach the queue, which is where the settlement below rejects them
  in the open rather than at an ingest no replaying party can see.
  At the end of the window the recovery Declaration takes effect with `A`
  and `C` preserved, and **every** Declaration sealed inside the window
  other than the recovery Declaration and the chain legitimately following
  it is superseded — an ordinary rotation and a fresh identity alike, so a
  thief holding only a signing key cannot outrun the holder of the
  recovery key by rotating *or* by generating a new key pair and starting
  over under the same domain. A Declaration legitimately follows when its
  signer is named in its predecessor's `keys` or `recovery_keys`, the
  predecessor being the recovery Declaration or an earlier link of the
  same chain: the recovering Publisher may therefore rotate again inside
  its own window without forfeiting it. At the window's end the queue is
  settled deterministically: each queued Delta is revalidated against the
  Key Set of that chain's newest Declaration — the recovery Declaration's
  own unless a legitimate follower was sealed inside the window — and one
  that no longer verifies is rejected with `WIST1-E13` and surfaced
  on the status endpoint (WIST-2 §7.1) like any other typed rejection.
  The rejection is of the queued copy and not of the Delta's identity: the
  same Delta re-served later and verifying under the Key Set then in force
  is sealed like any other, which is what keeps replay agreement free of a
  per-Log list of dropped IDs that every Consumer would have to carry.
  A Delta signed by the superseded signing key is exactly the case this
  settles: if the recovery rotated that key out, the Delta dies with it,
  which is the point of the rotation. The survivors become eligible
  (WIST-4 §6.4) for the first Block whose `sealed_at` is at or after the
  window's end, in their original acceptance order, and the §6.4
  inclusion ceiling counts from that Block — a queued Delta is out of
  the ceiling's reach while the window holds it, or the window and the
  ceiling would be two MUSTs one Aggregator cannot both keep.
  The Aggregator MUST also record a `notice`
  (WIST-4 §7) carrying `details.kind` `"recovery"`, but that entry
  **describes** the window and does not open it: the window is derived
  from the Declaration's own sealing height, so a Consumer replaying the
  Log computes the same window, the same effective height, and the same
  historical Key Set whether or not the notice was ever sealed. The suite's
  only answer to a stolen signing key MUST NOT rest on the Aggregator
  choosing to file — and a recovery whose effect depended on that entry
  would leave "took effect under the Compromise recovery rule" with no
  truth value for the resolution below, and the thief's ordinary rotation
  standing. The window is derived from the sealing height, and the
  sealing itself is a duty with a deadline for the same reason: on
  discovering a served recovery Declaration that verifies — by pull, by
  hint, or by the Publisher's Ping — the Aggregator MUST seal its Entry
  within the number of Blocks `record_seal_blocks` fixes (WIST-4 §4's
  sealing-latency constant, default 24). A recovery the operator can
  shelve indefinitely is the notice-layer goodwill dependency
  reconstituted one layer down. The violation is attributable — the
  Declaration is signed, dated by its own `seq` and `prev_declaration`,
  and any third party can fetch the well-known path and observe the Log
  not sealing it — but it is not derivable from the Log alone, because
  the Log cannot see an unserved file; that residue is recorded here
  rather than papered over, and it is the fork-level remedy (WIST-3 §3.4)
  that ultimately answers an Aggregator that sits on recoveries.
  Two recovery Declarations sealed inside one open window — two holders
  of recovery keys, or one holder twice — are resolved by Log order
  like every other race in this suite: the first-sealed recovery
  Declaration is the one the window belongs to, and a second sealed
  inside that window is a competing claim that does not open a second
  window and does not supersede the first; whichever party prevails does
  so by holding the recovery keys the *first* Declaration now lists.
- Signed by neither — a **fresh identity**. The Declaration is accepted,
  but `A` and `C` reset to zero and the domain re-enters Provisional
  (WIST-4 §6). Served inside an open recovery window it is accepted like
  any other Declaration and superseded at the window's end by the rule
  above; it is never a `WIST1-E08`, because nothing about it is a
  sequencing violation, and rejecting it at ingest would leave the
  attempt invisible to a party replaying the Log.

A Publisher that loses both its signing keys and its recovery keys
starts over; that is the honest outcome, because with no cryptographic
continuity left nothing distinguishes the Publisher from a new owner of
the same name, and preserving standing on domain control alone would let
anyone buy an aged domain and inherit its reputation.

**Historical verification.** Accepted Declarations are sealed into the Log
as `publisher_declaration` Entries (WIST-3 §3.3). The Key Set applicable to a
`publisher_delta` Entry sealed in Block N is normally the one from that
domain's highest-`seq` Declaration Entry sealed at a height ≤ N — except
that a recovery Declaration which took effect under the Compromise
recovery rule above prevails over every ordinary rotation sealed during
its recovery window, regardless of `seq`. A Consumer replaying the Log
therefore excludes any such superseded rotation from the "highest `seq`"
comparison and treats the recovery Declaration (and whatever legitimately
follows it) as applicable instead, for every height from the recovery
Declaration's own sealing height onward. Because `seq`, `prev_declaration`,
each Declaration's signer, Entry order, and the recovery window's own
anchor — the `sealed_at` of the Block sealing the recovery Declaration —
are all present in the Log
itself, this resolution — ordinary case and recovery exception alike — is
fully deterministic from log order alone, with no fetch and no trust in
the Aggregator. "Took effect under the Compromise recovery rule" is
therefore a predicate every replaying party evaluates identically, rather
than a claim resting on an entry the Aggregator may or may not have filed.

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

| Code | Meaning |
|---------|--------------------------------------------------------------|
| WIST1-E01 | Invalid signature (does not verify against the named key) |
| WIST1-E02 | Unknown key (`sig.key_id` not in the current Key Set at ingest, or, at sealing, not in the Key Set §5.2 resolves at the Delta's sealing height — a Delta a Declaration accepted since the pull has stranded, never sealed) |
| WIST1-E03 | URL out of scope, not normalized, or not normalizable (host not covered by domain/`subdomain_scope`; `url` not byte-identical to its own Normalized URL; or `url` has no normalization at all — §2) |
| WIST1-E04 | Size cap exceeded, in JCS octets as §3.6 defines them (`payload.bytes` > 38944, or a retrieved Payload whose `JCS(extract)` exceeds 32768 octets, whose `JCS(links)` exceeds 4096 octets, whose `JCS(url)` on any `links.urls` entry exceeds 2048 octets, or whose `JCS(summary)` exceeds 2048 octets) |
| WIST1-E05 | Invalid canonicalization (object not valid JCS input, e.g. non-JSON-safe numbers) |
| WIST1-E06 | `observed_at` in the future beyond the 10-minute skew allowance |
| WIST1-E07 | `prev` chain violation: missing, not sealed at a lower Log position (§3.5), wrong URL, non-monotonic `observed_at`, a fork (a later Delta naming a `prev` an earlier Delta has already claimed) rejected in favor of the first-sealed Delta, or a named `prev` that remains unavailable after the validator attempts retrieval per WIST-2 §3.1 |
| WIST1-E08 | Declaration sequence or recovery-key violation (`seq` not greater than the highest accepted, except a re-serve of the accepted Declaration's own `publisher` object, which is idempotent (§5.2); `prev_declaration` absent when `seq` > 0; `prev_declaration` mismatched against the previously accepted Declaration; `recovery_keys` added, removed, or altered by a Declaration not signed by one of the recovery keys it replaces; or the same `key_id` or `public_key` named in both `keys` and `recovery_keys`) |
| WIST1-E09 | Content-bearing change type with no commitment: a `new` or an `update` that omits `payload` (§3.3). Rejected and never sealed; the Delta claims content while committing to none, which no audit can ever check (WIST-4 §5) |
| WIST1-E10 | Payload commitment mismatch: a retrieved Payload does not reproduce the Delta's `payload.commitment` under the salt it carries, or the octet length of `JCS(content)` is not exactly `payload.bytes` |
| WIST1-E11 | `url` exceeds `url_cap_bytes` octets |
| WIST1-E12 | `links` violates a structural rule of §3.6 |
| WIST1-E13 | Queued Delta invalidated by recovery: a Delta queued during a §5.2 recovery window whose signature does not verify against the Key Set in effect at the window's end. The queued copy is dropped and never sealed, and the drop is visible to the Publisher via the status endpoint (WIST-2 §7.1); the Delta's identity is not barred, so the same Delta re-served later and verifying under the Key Set then in force is sealed (§5.2) |

Duplicate submission of an identical Delta, and re-fetching a Declaration
whose `publisher` object is byte-identical to the domain's accepted one
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
  never a permanent one. Publishers SHOULD generate recovery keys
  independently of signing keys and keep them offline, SHOULD keep
  signing keys off the web server that serves content, and SHOULD rotate
  on any suspicion of compromise; fraud committed before recovery is
  still attributed to the domain and handled by WIST-4 audit and
  sanctions. A Publisher that loses its signing key without ever having
  provisioned a recovery key has no cryptographic path back (§5.2).
- **Domain transfer.** A Key Set replacement does not transfer standing
  by itself: §5.2 classifies a replacing Declaration by what signs it,
  and one signed by neither the previous Key Set nor the previous
  `recovery_keys` is a fresh identity whose `A`/`C` reset to zero. A
  party that acquires a domain's hosting without also acquiring a
  signing or recovery key therefore cannot inherit its predecessor's
  history — only cryptographic continuity does that, never possession of
  the name alone.
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
  reintroduced within this major version.

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
- the verdicts and `similarity` values of any Audit Records about the URL.
  Those Records observe the page directly, so every content-derived value
  in them is committed under the same Payload salt rather than digested
  bare, and expires with it (WIST-4 §5, WIST-4 §12);
- everything any Registry Update about the URL or its Publisher carries in
  its `details` and `evidence` — the Aggregator's `legal_basis`, `reason`,
  `reasoning` and `sanction_lift` text, and the Publisher's own text on an
  `appeal` alike. These are sealed and unwithdrawable like `meta`,
  which is why WIST-4 §9.1 and §12 forbid personal data in any of them
  outright rather than in a list of named fields.

Publishers should understand that this residue is permanent, and that
withdrawal removes the content from future distribution rather than from
copies already served.

## 10. Conformance Checklist

**Publisher:**

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
- [ ] Rotates keys by signing the new Key Set with a previous key (§5.2)
- [ ] Increments seq and sets prev_declaration on every new Declaration
      (§5.2)
- [ ] Emits only Normalized URLs and keeps published Deltas retrievable
      (§3.2, §3.5)

**Validator (any party checking Deltas):**

- [ ] Recomputes Canonical Bytes with JCS and verifies the Ed25519
      signature against them (§4)
- [ ] Recomputes a retrieved Payload's commitment and length before using
      its content, and rejects a mismatch under `WIST1-E10` without
      invalidating the Delta (§3.6, §7)
- [ ] Enforces the scope rule (§3.2) and all Error Registry checks (§7)
- [ ] Treats identical resubmissions as idempotent (§4)
- [ ] Rejects Declarations served over plain HTTP (§5.1)
- [ ] Applies the 10-minute clock-skew allowance to `observed_at` (§3.4)
- [ ] Rejects non-monotonic Declarations and resolves historical Key Sets
      by Block height (§5.2)
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
`/payloads/6cac5bdd…5120.json`:**

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

`JCS(content)` is 266 octets and the salt is the 16 octets
`71a4000d7f1c547b8477b45985451934`. A conforming Publisher draws that salt
from a CSPRNG; this vector derives it — `SHA-256("wist-test-salt|"
‖ url)[0..16]` — because the generator has no random source and must stay
byte-reproducible.

**Delta (inner object):**

```json
{
  "wist_version": "1.0.0",
  "url": "https://example.com/blog/post-3",
  "change_type": "new",
  "observed_at": "2026-08-02T12:00:00Z",
  "payload": {
    "commitment": "hmac-sha256:25d23a19718b942a02241f8aae07a3837b9e648fb3836dd9623c3aa8ce4702b3",
    "alg": "HMAC-SHA256",
    "bytes": 266
  },
  "meta": {"lang": "en", "topics": ["software"], "license": "CC-BY-4.0"}
}
```

**Canonical Bytes (JCS, first bytes shown as hex; full form in
[`vectors/wist1/delta.canonical`](../vectors/wist1/delta.canonical)):**

```
7b226368616e67655f74797065223a226e6577222c2264635f76657273696f6e22
3a22312e302e30222c226d657461223a7b226c616e67223a22656e222c226c6963
...
```

Note how JCS sorts keys (`change_type` first) regardless of authoring
order.

**Delta ID:**

```
sha256:bb28d0f30208ef88cdb4d88aadb3531a7b023eb6639c8642d91fa503ea0a78e4
```

**Signature (base64url):**

```
EshjAnghqOe3hJ5oq3_cVmc04RsR02-EifxmlpB9yIOOlQBjmYoF7ul5QXSEf1GmHdNfKSRW1DvkouwAWEsECA
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
  computed by
