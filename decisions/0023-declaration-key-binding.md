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
