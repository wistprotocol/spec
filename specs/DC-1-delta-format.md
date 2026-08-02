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
  has prior Deltas, `prev` MUST be present (§3.5). `extract` and `summary`
  SHOULD be present.
- `update` — the URL's content changed. `extract` and `summary` SHOULD be
  present. `prev` MUST be present.
- `delete` — the URL no longer exists (or no longer carries indexable
  content). The Delta MUST omit `extract`. `prev` MUST be present.
- `attest` — the Publisher asserts the URL's content is unchanged as of
  `observed_at` (a freshness attestation). The Delta MUST omit `extract`
  and `summary`. `prev` MUST be present.

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

### 3.6. `extract`

The main text of the page — boilerplate removed, content preserved — as
UTF-8. Its serialized length MUST NOT exceed 32768 bytes (error
`DC1-E04`). When present, `extract_hash` MUST equal `"sha256:"` + hex
SHA-256 of the UTF-8 bytes of `extract`.

### 3.7. `summary`

A short structured summary: `title` (REQUIRED within `summary`, ≤ 256
characters) and optional `abstract`. The JSON-serialized `summary` object
MUST NOT exceed 2048 bytes (error `DC1-E04`).

### 3.8. `meta`

Descriptive metadata: `lang` (REQUIRED; BCP 47 primary tag, e.g. `en`,
`pt-BR`), `topics` (≤ 10 free-form strings), and `license` (the declared
license of the page content, e.g. `CC-BY-4.0` or `proprietary`).

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
  but `A` and `C` reset to zero and the domain re-enters Quarantine
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
| DC1-E04 | Size cap exceeded (`extract` > 32768 bytes or `summary` > 2048 bytes) |
| DC1-E05 | Invalid canonicalization (object not valid JCS input, e.g. non-JSON-safe numbers) |
| DC1-E06 | `observed_at` in the future beyond the 10-minute skew allowance |
| DC1-E07 | `prev` chain violation: missing, non-existent, wrong URL, non-monotonic `observed_at`, a fork (a later Delta naming a `prev` an earlier Delta has already claimed) rejected in favor of the first-sealed Delta, or a named `prev` that remains unavailable after the validator attempts retrieval per DC-2 §3.1 |
| DC1-E08 | Declaration sequence or recovery-key violation (`seq` not greater than the highest accepted; `prev_declaration` absent when `seq` > 0; `prev_declaration` mismatched against the previously accepted Declaration; or `recovery_keys` added, removed, or altered by a Declaration not signed by one of the recovery keys it replaces) |

Duplicate submission of an identical Delta is an idempotent acceptance,
not an error.

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

Deltas are public and, once sealed into the log (DC-3), permanent.
Publishers MUST NOT include in `extract` or `summary` personal data beyond
what the referenced page itself publicly serves. A `delete` Delta removes
content from future snapshots (the materialized index honors deletion) but
does not erase log history; publishers should understand that the *fact*
that a page existed, and any previously published extracts of it, remain
in the log permanently.

## 10. Conformance Checklist

**Publisher:**

- [ ] Serves `publisher.json` at the well-known path over HTTPS (§5.1)
- [ ] Signs every Delta with a key in its current Key Set, over JCS
      Canonical Bytes (§4)
- [ ] Only emits Deltas for URLs within its authority (§3.2)
- [ ] Maintains correct per-URL chains: first Delta omits `prev`, later
      ones reference the immediately prior Delta (§3.5)
- [ ] Respects field caps: extract ≤ 32768 bytes, summary ≤ 2048 bytes (§3.6, §3.7)
- [ ] Omits `extract`/`summary` on `attest`, omits `extract` on `delete` (§3.3)
- [ ] Rotates keys by signing the new Key Set with a previous key (§5.2)
- [ ] Increments seq and sets prev_declaration on every new Declaration
      (§5.2)
- [ ] Emits only Normalized URLs and keeps published Deltas retrievable
      (§3.2, §3.5)

**Validator (any party checking Deltas):**

- [ ] Recomputes Canonical Bytes with JCS and verifies the Ed25519
      signature against them (§4)
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

**Delta (inner object):**

```json
{
  "dc_version": "1.0.0",
  "url": "https://example.com/blog/post-1",
  "change_type": "new",
  "observed_at": "2026-08-02T12:00:00Z",
  "extract": "DeltaCommons is an open, verifiable, push-based web index protocol.",
  "extract_hash": "sha256:280b420ff2d23150e67553ca0bca7825529e96f53b4df3f523beecfcdfd9a7c1",
  "summary": {"title": "Post 1", "abstract": "An introduction to DeltaCommons."},
  "meta": {"lang": "en", "topics": ["software"], "license": "CC-BY-4.0"}
}
```

**Canonical Bytes (JCS, first bytes shown as hex; full form in
[`vectors/dc1/delta.canonical`](../vectors/dc1/delta.canonical)):**

```
7b226368616e67655f74797065223a226e6577222c2264635f76657273696f6e22
3a22312e302e30222c2265787472616374223a2244656c7461436f6d6d6f6e7320
...
```

Note how JCS sorts keys (`change_type` first) regardless of authoring
order.

**Delta ID:**

```
sha256:e3ba905f6a994d67e5286ca3264c894a72283c2bdaf07b4a5600cdd0000187b1
```

**Signature (base64url):**

```
aDRvbB3J4L2Chht8V_Up_-pXzBZX6quUq9XBBb2H2znmbX8TbJ3IuXYiz6f_9wePwvyTIYG-TPFj5Y_vkvAuAw
```

The complete envelope is
[`vectors/dc1/envelope.json`](../vectors/dc1/envelope.json) and doubles as
[`examples/delta.json`](../examples/delta.json).

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
