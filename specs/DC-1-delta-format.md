# DC-1: Delta Format & Identity

**Status:** v1.0.0-draft · **Date:** 2026-08-02 · **License:** CC-BY 4.0

## 1. Introduction

DeltaCommons is an open, verifiable, push-based web index. Instead of being
crawled, a site describes its own changes: for each URL it controls, it
publishes small signed objects called **deltas** — "this page is new", "this
page changed, here is its main text", "this page was deleted", "this page is
unchanged as of this date". Deltas flow into a public, hash-chained log
(DC-3) from which consumers materialize a compact, fresh local index.

This document defines the two foundational objects of the suite:

- the **Delta**: the unit of information a publisher signs, and
- the **Publisher Declaration**: how a domain declares its signing keys.

How deltas are published on a site and discovered by aggregators is defined
in [DC-2](DC-2-site-publication.md). How they are sequenced into the log and
distributed is defined in [DC-3](DC-3-commons-log-distribution.md). How they
are audited, and how domain reputation is derived, is defined in
[DC-4](DC-4-audit-reputation-governance.md).

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as
shown here.

- **Publisher**: the operator of a domain, identified by that domain, who
  signs deltas for URLs under it.
- **Delta**: a signed statement by a Publisher about one URL at one moment.
- **Payload**: the content a Delta describes — the page's main text and its
  structured summary — carried as a separate, unsigned file alongside the
  Block (DC-3 §6.1). A Payload is never part of a Delta, of a Block, or of
  the Log.
- **Payload Commitment**: the salted keyed hash of a Payload's content that
  a Delta carries in place of that content (§3.6).
- **Envelope**: the JSON container `{"<inner>": {...}, "sig": {...}}` that
  pairs an inner object with a detached signature. All signed objects in
  the suite use this shape.
- **Canonical Bytes**: the octet sequence produced by applying JCS
  [RFC 8785] to the inner object.
- **Delta ID**: `"sha256:"` followed by the lowercase hex SHA-256 of a
  Delta's Canonical Bytes.
- **Key Set**: the list of active Ed25519 public keys in a Publisher
  Declaration.
- **Canonical Host**: a hostname lowercased, IDN-encoded to its A-label
  form (RFC 5890), with any trailing dot removed and no port.
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
  are byte-identical.

Hash strings throughout the suite are serialized as `"sha256:" + lowercase
hex`. Signatures are Ed25519 [RFC 8032], detached, base64url-encoded
without padding [RFC 4648 §5].

## 3. The Delta Object

A Delta is the inner object of a Delta Envelope. Its machine-readable
schema is [`schemas/delta.schema.json`](../schemas/delta.schema.json);
where prose and schema disagree, the schema governs syntax and this
document governs semantics.

### 3.1. `dc_version`

The version of this specification the object conforms to, as a semver
string. This document defines version `1.0.0`. Consumers MUST reject
objects whose major version they do not implement.

### 3.2. `url`

The URL the Delta describes. It MUST use the `https` scheme. It MUST be
within the Publisher's authority: the URL's host MUST equal the Publisher's
`domain` or one of the hostnames in its `subdomain_scope` (the **scope
rule**). A validator MUST reject a Delta whose `url` is outside the signing
Publisher's authority (error `DC1-E03`).

The value of `url` MUST already be a Normalized URL; a Delta whose `url`
is not byte-identical to its own normalization MUST be rejected with
`DC1-E03`. The scope rule compares Canonical Hosts.

### 3.3. `change_type`

One of four values:

- `new` — the Publisher asserts this URL now carries content; if the URL
  has prior Deltas, `prev` MUST be present (§3.5). `payload` MUST be
  present.
- `update` — the URL's content changed. `payload` MUST be present.
  `prev` MUST be present.
- `delete` — the URL no longer exists (or no longer carries indexable
  content). The Delta MUST omit `payload`. `prev` MUST be present.
- `attest` — the Publisher asserts the URL's content is unchanged as of
  `observed_at` (a freshness attestation). The Delta MUST omit `payload`.
  `prev` MUST be present.

A Delta that carries `payload` is **content-bearing** and MUST have the
corresponding Payload retrievable (DC-2 §3.1); a Delta that omits it
asserts nothing about content and has no Payload to serve. The two
requirements above therefore make `new` and `update` exactly the
content-bearing change types: a validator MUST reject a `new` or an
`update` with no `payload` under `DC1-E09`, and such a Delta MUST NOT be
sealed. A Delta claiming that content appeared or changed while committing
to none says what happened and not what it is, so no audit could ever
confirm or refute it (DC-4 §5 would record `not_auditable` forever) — a
claim that is unfalsifiable by construction, sealed permanently, and free.

An `attest` Delta carries no content of its own precisely because it claims
none: what it is measured against is the Payload of the last
content-bearing Delta *at or before it* in the same per-URL chain (DC-4
§5's Reference Payload), which is why §3.5's chain and DC-2 §3.1's
retention obligation reach further back than the Delta itself. The same
holds for a `delete`, whose claim is that exactly that content is no longer
served.

### 3.4. `observed_at`

The instant the Publisher observed the state being described, as an
RFC 3339 UTC timestamp. It MUST NOT be more than 10 minutes in the future
relative to the validator's clock (error `DC1-E06`), and MUST be strictly
greater than the `observed_at` of the Delta referenced by `prev` (error
`DC1-E07`).

### 3.5. `prev`

The Delta ID of this Publisher's most recent prior Delta for the same
`url`. Together, `prev` links form a **per-URL chain**: an ordered,
verifiable history of everything the Publisher has said about one page.
The first Delta for a URL MUST omit `prev`; every subsequent Delta for
that URL MUST include it (error `DC1-E07` on violation).

The chain for a URL never restarts. A `new` Delta for a URL that has prior
Deltas (for example, a page recreated after a `delete`) MUST carry `prev`
pointing at the most recent prior Delta; only the very first Delta a
Publisher ever emits for a URL omits `prev`.

**Forks are invalid.** Two Deltas from the same Publisher for the same URL
naming the same `prev` are a fork. An Aggregator MUST accept whichever it
seals first and MUST reject the other with `DC1-E07`; a Consumer replaying
the Log MUST treat the first-sealed Delta as canonical and ignore any later
Entry that forks an already-sealed chain.

**Data availability.** A validator that has not seen the Delta named by
`prev` MUST attempt to retrieve it from the Publisher (DC-2 §3.1) before
concluding `DC1-E07`. A Publisher MUST keep every Delta it has ever
published retrievable at its content-addressed path for as long as the
domain participates; unavailability of a `prev` Delta is a `DC1-E07`
rejection of the *new* Delta, never a retroactive invalidation of the
sealed chain.

### 3.6. `payload` — the Payload commitment

A Delta commits to its content; it does not carry it. The content — the
main text (`extract`) and the structured summary (`summary`) — travels as
a separate **Payload** (DC-3 §6.1). The Delta carries only:

    commitment = "hmac-sha256:" + hex(HMAC-SHA256(key = salt,
                                                  message = JCS(content)))

where `content` is the object `{"extract": <string>, "summary": <object>}`
and `salt` is at least 16 octets drawn from a cryptographically secure
random source, fresh for every Delta. The salt travels with the Payload
and never appears in the Log.

The salt is what makes withdrawal effective. A bare hash of a withdrawn
extract would still let anyone holding a copy of the text demonstrate that
it was the text committed to; with a salt that is destroyed alongside the
bytes, the commitment becomes unlinkable to any candidate text.

`bytes` is the octet length of `JCS(content)` and MUST NOT exceed 34816
(32768 for the extract plus 2048 for the summary). A validator MUST reject
a Delta whose Payload, once retrieved, does not have exactly that length
or does not reproduce `commitment` under the accompanying salt
(`DC1-E04`, `DC1-E11`).

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

Signing JSON requires a byte-exact canonical form. DeltaCommons uses the
JSON Canonicalization Scheme (JCS) [RFC 8785]:

1. **Canonical Bytes** = `JCS(delta)` — the inner object only, never the
   envelope.
2. **Delta ID** = `"sha256:" + hex(SHA-256(Canonical Bytes))`.
3. **Signature** = `Ed25519-sign(private_key, Canonical Bytes)`,
   base64url without padding.

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

Because identity is content-derived, resubmitting an identical Delta
yields the same Delta ID; validators MUST treat duplicates as idempotent
acceptances, not errors. Two Deltas differing in any byte of Canonical
Bytes are distinct objects.

The Payload is outside all three constructions. Canonical Bytes cover the
Delta's `payload` commitment, never the content it commits to, so the
Delta ID, the signature, and every Merkle root and Block Hash derived from
them are computed without the content and stay valid when the content is
withdrawn (DC-3 §6.2). A Payload is authenticated by recomputing the
commitment (§3.6), not by any signature of its own.

## 5. Publisher Identity and Key Discovery

### 5.1. The Publisher Declaration

A Publisher declares its identity at:

```
https://<domain>/.well-known/deltacommons/publisher.json
```

The document is an Envelope whose inner object is `publisher` (schema:
[`schemas/publisher.schema.json`](../schemas/publisher.schema.json)),
containing: `dc_version`, `domain`, `seq` (a monotonic Declaration
counter, starting at 0; see §5.2), `prev_declaration` (the hash of the
Declaration this one replaces; REQUIRED when `seq` > 0, absent only for
`seq` 0; see §5.2), optional `subdomain_scope` (hostnames the Key Set
also covers), the `keys` array (each entry: `key_id`, `alg`, raw Ed25519
`public_key` base64url, `valid_from`), optional `recovery_keys` (same
item shape as `keys`; see §5.2), and optional `contact`.

Discovery MUST use HTTPS; there is no alternative channel. A validator MUST
NOT accept a Publisher Declaration served over plain HTTP, and MUST NOT
follow a redirect whose target host is outside the Publisher's authority
(DC-2 §8).

A validator MAY cache a Key Set for at most 24 hours (Parameter Registry:
Key Set cache TTL). While a cached Key Set is valid, a discovery failure
does not block validation. When no valid cached Key Set exists and
discovery fails, the validator MUST fail closed: Deltas are rejected with
`DC1-E02` and MUST NOT be sealed.

`valid_from` bounds a key's use: a Delta whose `observed_at` precedes the
`valid_from` of the key named in `sig.key_id` MUST be rejected with
`DC1-E02`. Backdating a Delta to before a key existed is therefore not a
route around key history.

### 5.2. Sequencing, Rotation and Revocation

Every Publisher Declaration carries a monotonic `seq`, starting at 0. A
Declaration with `seq` > 0 MUST include `prev_declaration`,
`"sha256:" + hex(SHA-256(JCS(publisher)))` computed over the *previous*
Declaration's inner `publisher` object — the Declaration this one
replaces. A validator MUST reject a Declaration under `DC1-E08` when:
`seq` is not greater than the highest it has already accepted for that
domain; or `seq` > 0 and `prev_declaration` is absent; or
`prev_declaration` does not equal the hash of the previously accepted
Declaration's `publisher` object. This makes replay of a superseded
Declaration (for example from a stale cache) detectable rather than
silent, the same way `DC1-E07` treats a missing or mismatched `prev` on
a Delta.

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
keys it is replacing, and is rejected with `DC1-E08` otherwise. Without
this rule the mechanism would be worthless: a thief holding a signing
key could rotate and drop the recovery keys in the same Declaration,
permanently severing the owner's path back. A Publisher whose previous
Declaration lists no recovery keys MAY establish them with an ordinary
signing-key signature — there is nothing yet to protect — which is how a
Publisher adopts recovery keys after the fact.

**Compromise recovery.** A Declaration with a higher `seq` is classified
by what signs it:

- Signed by a key in the previous Key Set — an ordinary rotation.
  Accepted; `A` and `C` (DC-4 §6) are preserved.
- Signed by a key in the previous Declaration's `recovery_keys` — a
  **recovery rotation**. The Aggregator MUST record a `notice` (DC-4 §7)
  carrying `details.kind` `"recovery"`, opening a recovery window
  (Parameter Registry: recovery window, 7 days) during which the
  domain's Deltas are queued rather than sealed. At the end of the
  window the recovery Declaration takes effect with `A` and `C`
  preserved, and it supersedes any ordinary rotation sealed during that
  window — so a thief holding only a signing key cannot outrun the
  holder of the recovery key.
- Signed by neither — a **fresh identity**. The Declaration is accepted,
  but `A` and `C` reset to zero and the domain re-enters Provisional
  (DC-4 §6).

A Publisher that loses both its signing keys and its recovery keys
starts over; that is the honest outcome, because with no cryptographic
continuity left nothing distinguishes the Publisher from a new owner of
the same name, and preserving standing on domain control alone would let
anyone buy an aged domain and inherit its reputation.

**Historical verification.** Accepted Declarations are sealed into the Log
as `publisher_declaration` Entries (DC-3 §3.3). The Key Set applicable to a
`publisher_delta` Entry sealed in Block N is normally the one from that
domain's highest-`seq` Declaration Entry sealed at a height ≤ N — except
that a recovery Declaration which took effect under the Compromise
recovery rule above prevails over every ordinary rotation sealed during
its recovery window, regardless of `seq`. A Consumer replaying the Log
therefore excludes any such superseded rotation from the "highest `seq`"
comparison and treats the recovery Declaration (and whatever legitimately
follows it) as applicable instead, for every height from the recovery
Declaration's own sealing height onward. Because `seq`, `prev_declaration`,
each Declaration's signer, and Entry order are all present in the Log
itself, this resolution — ordinary case and recovery exception alike — is
fully deterministic from log order alone, with no fetch and no trust in
the Aggregator.

## 6. Deliberate Normative Absence

This specification defines no field by which a publisher may declare the
importance, relevance, or ranking of its own content. This absence is
deliberate and constitutional; see DC-4.

A Delta may say "I changed" and "my content is this". It cannot say "I
matter". Importance is measured at consumption, outside this protocol.

## 7. Error Registry

| Code | Meaning |
|---------|--------------------------------------------------------------|
| DC1-E01 | Invalid signature (does not verify against the named key) |
| DC1-E02 | Unknown key (`sig.key_id` not in the current Key Set) |
| DC1-E03 | URL out of scope or not normalized (host not covered by domain/`subdomain_scope`, or `url` not byte-identical to its own Normalized URL) |
| DC1-E04 | Size cap exceeded (`payload.bytes` > 34816, or a retrieved Payload whose `extract` exceeds 32768 bytes or whose `summary` exceeds 2048 bytes) |
| DC1-E05 | Invalid canonicalization (object not valid JCS input, e.g. non-JSON-safe numbers) |
| DC1-E06 | `observed_at` in the future beyond the 10-minute skew allowance |
| DC1-E07 | `prev` chain violation: missing, non-existent, wrong URL, non-monotonic `observed_at`, a fork (a later Delta naming a `prev` an earlier Delta has already claimed) rejected in favor of the first-sealed Delta, or a named `prev` that remains unavailable after the validator attempts retrieval per DC-2 §3.1 |
| DC1-E08 | Declaration sequence or recovery-key violation (`seq` not greater than the highest accepted; `prev_declaration` absent when `seq` > 0; `prev_declaration` mismatched against the previously accepted Declaration; or `recovery_keys` added, removed, or altered by a Declaration not signed by one of the recovery keys it replaces) |
| DC1-E09 | Content-bearing change type with no commitment: a `new` or an `update` that omits `payload` (§3.3). Rejected and never sealed; the Delta claims content while committing to none, which no audit can ever check (DC-4 §5) |
| DC1-E11 | Payload commitment mismatch: a retrieved Payload does not reproduce the Delta's `payload.commitment` under the salt it carries, or the octet length of `JCS(content)` is not exactly `payload.bytes` |

Duplicate submission of an identical Delta is an idempotent acceptance,
not an error.

`DC1-E11` rejects the Payload, never the Delta. A sealed Delta stays
sealed and stays valid, because nothing in its identity or signature
depends on content the Log never held; the party that served the
mismatched Payload is the one at fault (DC-3 §9, `DC3-E03`).

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
  still attributed to the domain and handled by DC-4 audit and
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
  `DC1-E11`. What an adversary controlling the serving path can do is
  withhold a Payload, which is an availability failure, handled by DC-3
  §6.1 and distinguishable from a lawful withdrawal.
- **Signature malleability.** Ed25519 signatures as specified in RFC 8032
  are deterministic; validators MUST verify against Canonical Bytes only.
- **Canonicalization attacks.** JCS removes serialization ambiguity
  (whitespace, key order, number forms). Objects that cannot be canonically
  represented MUST be rejected (`DC1-E05`), never repaired.
- **URL authority spoofing.** The scope rule (§3.2) plus HTTPS-only key
  discovery (§5.1) bind every Delta to a domain the signer demonstrably
  controls. Validators MUST NOT relax either check.
- **Single discovery channel.** Key discovery is HTTPS-only by design. Any
  unauthenticated alternative channel would let an off-path spoofer inject
  a signing key for a domain whose HTTPS endpoint is made to fail,
  defeating every other guarantee in this document; no such channel is
  defined.

## 9. Privacy Considerations

Deltas are public and, once sealed into the log (DC-3), permanent. Content
is not: it lives in Payloads, outside the Log, and is erasable under the
logged due process of DC-3 §6.2. That split is deliberate. Extracts are
drawn from public web pages, public web pages routinely carry personal
data, and erasure rights attach to whoever redistributes that data. An
index that sealed extract bytes into an append-only structure replicated
across mirrors it does not control would be promising a deletion it could
not perform.

Publishers MUST NOT include in a Payload's `extract` or `summary` personal
data beyond what the referenced page itself publicly serves, and MUST NOT
include personal data in a Delta's `meta` at all (§3.7) — the difference
being that a Payload can be withdrawn and `meta`, sealed in the Delta,
cannot. A `delete` Delta removes content from future snapshots (the
materialized index honors deletion) but does not erase log history, and a
`payload_withdrawal` (DC-3 §6.2) erases the content without erasing the
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
  bare, and expires with it (DC-4 §5, §11);
- the free text of any Registry Update about the URL or its Publisher — a
  withdrawal's `legal_basis`, a `notice`'s `reason`, an `appeal_ruling`'s
  `reasoning`. These are sealed and unwithdrawable like `meta`, which is
  why DC-4 §11 forbids personal data in them outright.

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
      equal to that length and ≤ 34816 (§3.6)
- [ ] Serves every content-bearing Delta's Payload, and keeps the anchor
      Payload of any URL it attests retrievable (DC-2 §3.1)
- [ ] Respects content caps: extract ≤ 32768 bytes, summary ≤ 2048 bytes (§3.6)
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
      its content, and rejects a mismatch under `DC1-E11` without
      invalidating the Delta (§3.6, §7)
- [ ] Enforces the scope rule (§3.2) and all Error Registry checks (§7)
- [ ] Treats identical resubmissions as idempotent (§4)
- [ ] Rejects Declarations served over plain HTTP (§5.1)
- [ ] Applies the 10-minute clock-skew allowance to `observed_at` (§3.4)
- [ ] Rejects non-monotonic Declarations and resolves historical Key Sets
      by Block height (§5.2)
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
`/payloads/7bee228c…1047.json`:**

```json
{
  "dc_version": "1.0.0",
  "salt": "GTCxEvdFpRzrjA6G5StpLQ",
  "content": {
    "extract": "DeltaCommons is an open, verifiable, push-based web index protocol.",
    "summary": {"title": "Post 1", "abstract": "An introduction to DeltaCommons."}
  }
}
```

`JCS(content)` is 156 octets and the salt is the 16 octets
`1930b112f745a51ceb8c0e86e52b692d`. A conforming Publisher draws that salt
from a CSPRNG; this vector derives it — `SHA-256("deltacommons-test-salt|"
‖ url)[0..16]` — because the generator has no random source and must stay
byte-reproducible.

**Delta (inner object):**

```json
{
  "dc_version": "1.0.0",
  "url": "https://example.com/blog/post-1",
  "change_type": "new",
  "observed_at": "2026-08-02T12:00:00Z",
  "payload": {
    "commitment": "hmac-sha256:de7cd99162e130dc9560185aef449f10d56afdbae59c1322fdb9b7b773193593",
    "alg": "HMAC-SHA256",
    "bytes": 156
  },
  "meta": {"lang": "en", "topics": ["software"], "license": "CC-BY-4.0"}
}
```

**Canonical Bytes (JCS, first bytes shown as hex; full form in
[`vectors/dc1/delta.canonical`](../vectors/dc1/delta.canonical)):**

```
7b226368616e67655f74797065223a226e6577222c2264635f76657273696f6e22
3a22312e302e30222c226d657461223a7b226c616e67223a22656e222c226c6963
...
```

Note how JCS sorts keys (`change_type` first) regardless of authoring
order.

**Delta ID:**

```
sha256:7bee228cf3db50847cdf2e8b82e99e455c6091a7678b51153025378fd80a1047
```

**Signature (base64url):**

```
HrmcgUNFqNF_k9eP3PCjhK8gpktKoJl1bWEHnezOBJvVDKGG7DvMxeWBiwy7TnY1yOghZhg3vwQQiYI_6cXHDg
```

The complete envelope is
[`vectors/dc1/envelope.json`](../vectors/dc1/envelope.json) and doubles as
[`examples/delta.json`](../examples/delta.json). Neither the extract nor
the summary appears anywhere in it.

## References

- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels
- [RFC 8174] Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words
- [RFC 8785] JSON Canonicalization Scheme (JCS)
- [RFC 8032] Edwards-Curve Digital Signature Algorithm (EdDSA)
- [RFC 4648] The Base16, Base32, and Base64 Data Encodings
- [RFC 3339] Date and Time on the Internet: Timestamps
- [RFC 3986] Uniform Resource Identifier (URI): Generic Syntax
- [RFC 5890] Internationalized Domain Names for Applications (IDNA):
  Definitions and Document Framework
