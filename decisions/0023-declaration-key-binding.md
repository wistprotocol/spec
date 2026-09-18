# ADR-0023: Declaration key binding and continuity

**Status:** draft · **Date:** 2026-09-10

## Context

WIST-1 §5.2 protects recovery keys and classifies replacements by the key
that signs them. Duplicate entries within a Declaration leave key lookup
ambiguous, and continuity must follow the key, not a Publisher-chosen name.
Under [ADR-0045](0045-key-directory.md) each entry's `kid` is its
thumbprint, so an identifier denotes one public key everywhere and the
continuity question reduces to which previous set the authenticated key
belongs to.

## Decision

Require each public key to occur once across a Declaration's signing and
recovery arrays, including identical duplicates. Reject violations with
WIST1-E08. Identifier uniqueness follows, because `kid` is the key's
thumbprint; retain the prohibition on public-key overlap between signing
and recovery sets.

Resolve a replacement signature against the entries whose `kid` matches in
the previous signing/recovery sets and the incoming signing set; the same
`kid` in two sources names the same key. Classify the authenticated public bytes by membership in the previous sets:
signing preserves ordinary continuity, recovery preserves recovery authority,
and neither establishes fresh identity. An incoming recovery key cannot
self-authorize. Apply recovery-set protection after classification.

Derive usable signing and recovery sets by excluding public bytes that do
not decode to a canonical Ed25519 point or are small-order. An unused
excluded entry does not invalidate an otherwise admissible Declaration.
Keep all original signed entries for signatures, hashes, idempotence,
identifier uniqueness, cross-set disjointness and recovery-set protection.
Filter before resolving signer candidates: a `kid` with only excluded
bindings is E02; usable candidates with no verifying signature are E01.
Classification uses usable previous sets. This derivation also governs Delta and frozen appeal Key Sets.

For Delta authentication, retain every complete named signing binding from
the source sets authorized by WIST-1 §5.2. Filter usability, then each
binding's `nbf`/`exp` window, comparing the exact Publisher instant with
the NumericDate integers. No remaining binding is E02; at least one
remaining binding but no verifying signature is E01. Accept the key check
if any remaining binding verifies. The same binding must satisfy both
conditions. A valid signature under an out-of-window binding plus an
invalid signature under an eligible binding is E01; even a valid signature
cannot authorize a Delta when every named binding is out of window or
excluded.

The recovery admission union preserves both source sets at the owner's
application. A later follower or competitor cannot replace either source.
One key listed by both sources with distinct windows keeps both; source or
array iteration order cannot affect the result. Recovery-only entries and
pending Declarations supply no Delta authority. This refines diagnostics
within the existing key-binding mechanism under PUBLICATION.md, with no
object-field or schema change. Encoding and Publisher timestamp errors retain E14 precedence;
settlement retains its E13 disposition, and neither Declaration nor appeal
authentication acquires a Delta timestamp filter.

A nonempty signing array can yield no usable key. A replacement can still
be authorized by its predecessor, while an initial Declaration with no
usable signing key fails E02. A nonempty recovery array remains protected
even if all its keys are excluded; without a usable recovery key, no signer
can authorize a change to that array. Declaration authentication applies no
Delta `nbf`/`exp` window.

Assume the strictly verified Ed25519 signature identifies its signing public
key; repeated references to identical public bytes do not create distinct
signers. Object fields and versions are unchanged. The undeployed draft is
updated under PUBLICATION.md.

Sealed Pages use the named-entry verification and current/first-next fallback
in WIST-2 §3.2. This refines the same binding mechanism without changing
Declaration source cutoffs, recovery supersession or schemas.

## Alternatives and consequences

First-match lookup lets array order select authority, and classifying
solely by a Publisher-chosen identifier would let a name carry standing.
Binding continuity to the authenticated public bytes avoids both outcomes;
with thumbprint identifiers the name and the bytes coincide.

Validators must enforce key uniqueness beyond JSON Schema's structural
constraints. Signed cases in `vectors/wist1/declaration-binding.json`
distinguish duplicate keys, thumbprint mismatches, recovery protection and
invalid signatures. The independent reference derives their outcomes;
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
histories and independent signed Delta probes for excluded points, one key
with two windows, exact fractions and offsets, malformed fields, mixed failures and owner bindings retained after
a legitimate follower. Reversed-array histories rebuild signatures and
hashes. The independent reference derives the sources and checks their
complete bindings. Successful key verification alone establishes no Delta
chain eligibility, live clock check, durable queue, Payload availability,
quota result, sealing, settlement or Snapshot restoration.

For Pages, the named entry is looked up by `kid` in each permitted source
independently: a Page cut under a key the current Declaration has since
retired verifies under the first-next fallback, and a key the current
Declaration excludes does not suppress that fallback. Independent
named-entry verification in each permitted source preserves both cases
without borrowing historical authority. `vectors/wist2/page-bindings.json`
distinguishes these predicates with signed Declaration chains and Page
probes; supplied sealing positions do not establish authenticated Epoch
inclusion or recovery supersession.
