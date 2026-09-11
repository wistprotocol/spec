# ADR-0023: Declaration key binding and continuity

**Status:** draft · **Date:** 2026-09-10

## Context

WIST-1 §5.2 protects recovery keys and classifies replacements by the key
that signs them. Duplicate identifiers within a Declaration leave key lookup
ambiguous. Reusing an identifier across Declarations can denote different
public keys; renaming unchanged public bytes does not lose the cryptographic
continuity WIST-4 §6.3 requires for identity preservation.

## Decision

Require each key identifier to occur once across a Declaration's signing and
recovery arrays, including identical duplicates. Reject violations with
WIST1-E08. Permit aliases of one public key within a single set; retain the
prohibition on public-key overlap between signing and recovery sets.

Resolve a replacement signature against the named entries in the previous
signing/recovery sets and the incoming signing set. Check the incoming binding
even when an old binding of the identifier fails signature verification.
Classify the authenticated public bytes by membership in the previous sets:
signing preserves ordinary continuity, recovery preserves recovery authority,
and neither establishes fresh identity. An incoming recovery key cannot
self-authorize. Apply recovery-set protection after classification.

Derive usable signing and recovery sets by excluding public bytes that do
not decode to a canonical Ed25519 point or are small-order. An unused
excluded entry does not invalidate an otherwise admissible Declaration.
Keep all original signed entries for signatures, hashes, idempotence,
identifier uniqueness, cross-set disjointness and recovery-set protection.
Filter before resolving signer candidates: an identifier with only excluded
bindings is E02; usable candidates with no verifying signature are E01.
An excluded predecessor binding does not suppress a usable incoming binding
of the same identifier, or conversely. Classification uses usable previous
sets. This derivation also governs Delta and frozen appeal Key Sets.

For Delta authentication, retain every complete named signing binding from
the source sets authorized by WIST-1 §5.2. Filter usability, then each
binding's inclusive `valid_from` bound using the exact Publisher timestamp
profile. No remaining binding is E02; at least one remaining binding but
no verifying signature is E01. Accept the key check if any remaining
binding verifies. The same binding must satisfy both conditions. A valid
signature under a future binding plus an invalid signature under an
eligible binding is E01; even a valid signature cannot authorize a Delta
when every named binding is future or excluded.

The recovery admission union preserves both source sets at the owner's
application. A later follower or competitor cannot replace either source.
Identifier reuse and repeated public bytes cannot discard distinct bounds;
source or array iteration order cannot affect the result. Other aliases and
recovery-only entries supply no Delta authority. This refines diagnostics
within the existing key-binding mechanism under PUBLICATION.md, with no
object-field or schema change. Encoding and Publisher timestamp errors retain E14 precedence;
settlement retains its E13 disposition, and neither Declaration nor appeal
authentication acquires a Delta timestamp filter.

A nonempty signing array can yield no usable key. A replacement can still
be authorized by its predecessor, while an initial Declaration with no
usable signing key fails E02. A nonempty recovery array remains protected
even if all its keys are excluded; without a usable recovery key, no signer
can authorize a change to that array. Declaration authentication applies no
Delta `valid_from` bound.

Assume the strictly verified Ed25519 signature identifies its signing public
key; repeated references to identical public bytes do not create distinct
signers. Object fields and versions are unchanged. The undeployed draft is
updated under PUBLICATION.md.

## Alternatives and consequences

First-match lookup lets array order select authority. Rejecting every reused
identifier across time prevents an otherwise valid fresh identity, while
classifying solely by identifier lets a renamed key erase standing and
sanctions without losing key possession. Binding continuity to authenticated
public bytes avoids both outcomes. Aliases within one set remain unambiguous
because each signature names one identifier and its own validity bound.

Validators must enforce identifier uniqueness beyond JSON Schema's structural
constraints. Signed cases in `vectors/wist1/declaration-binding.json` distinguish
duplicate identifiers, reused identifiers, renamed keys, recovery protection,
and invalid signatures. The independent reference derives their outcomes;
these cases do not resolve recovery-window ordering or supersession.

Rejecting the entire Declaration for an unused excluded key would give §4's
key exclusion a separate object-rejection effect. Removing the signed entry
would change the object hash, destroy its signature and potentially bypass
recovery protection. Deriving usable sets while preserving the Envelope
keeps these concerns distinct. The resulting unusable-key failure is visible
at the object that needs the key; no unusable key acquires authority.
`vectors/wist1/declaration-key-eligibility.json` exercises initial, ordinary,
recovery and fresh authentication; invalid named and unused bindings; mixed
order keys that are not small-order; and protection of excluded entries.
Conditional appeal probes distinguish excluded identifiers from invalid
signatures under usable notice-era bindings, taking accepted notices and
selected Declaration sources as inputs. They establish no notice evidence
or appeal-process result. Its canonical base64url fixtures do not establish
a complete Declaration field profile. [ADR-0025](0025-canonical-base64url.md)
separately rejects malformed encodings before this key derivation.

First-match Delta lookup can suppress an eligible owner binding behind a
future or invalid predecessor binding. Deduplicating by public bytes can
likewise erase a different bound. Trying signatures first and using the
bound of whichever key verifies would assign E02 to mixed failures;
filtering candidates first instead makes E02 mean absence of eligible
authority and E01 mean failed authentication under authority that exists.
Combining successful checks from different bindings would authorize a
signature before that binding's own activation. These alternatives either
depend on iteration order, obscure the rejection condition or broaden
authority.

`vectors/wist1/recovery-bindings.json` supplies authenticated Declaration
histories and independent signed Delta probes for reused identifiers,
excluded points, same-public-key bounds, aliases, exact fractions and
offsets, malformed fields, mixed failures and owner bindings retained after
a legitimate follower. Reversed-array histories rebuild signatures and
hashes. The independent reference derives the sources and checks their
complete bindings. Successful key verification alone establishes no Delta
chain eligibility, live clock check, durable queue, Payload availability,
quota result, sealing, settlement or Snapshot restoration.
