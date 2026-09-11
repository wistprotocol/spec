# ADR-0029: Signed Delta Publisher identity

**Status:** draft · **Date:** 2026-09-11

## Context

A Delta signature over URL, content commitment and time alone does not bind
its Publisher domain. Two scoped Declarations can share a named public key;
a copied public binding can make an existing signature appear attributable
to another domain. Even with different private keys, identical inner Delta
bytes have identical IDs, so Log deduplication cannot distinguish the two
Publishers' statements. Materialization preferences operate after authorship
and cannot authenticate it.

## Decision

WIST-1 §3.8 requires `publisher` inside the signed Delta. Its value is the
canonical Publisher domain, with the Declaration host profile. Missing or
malformed values are E14 before semantic checks. Only this domain supplies
Declaration history, literal URL scope and applicable complete signing
bindings. Another domain's keys cannot repair a missing or ineligible source.

The Publisher is included in both signature and ID input. Key aliases stay
outside that input and cannot change authorship. Shared keys remain possible;
copying public bytes does not give the private key needed to sign a statement
naming a different domain. Ordinary re-signing after rotation retains the ID.

Chains use the exact `(publisher, url)` pair; a foreign predecessor is E07.
Rotation, recovery and fresh identity preserve those chain keys. Existing
reset rules scope credit, penalties and sanction evidence by the audited
Delta's sealing height; they do not rewrite its author. Audit references,
canary ownership and materialization all use the authenticated signed domain.
This establishes attribution independently of materialization preference.

A well-shaped Delta naming a foreign Publisher in an authenticated Feed or
Page is WIST2-E03, including a fetched predecessor or an ID already accepted
for another domain. Check the logical Feed domain, never a redirect or
Mirror's physical hostname. This per-Delta rejection leaves the Feed's
existing authentication and noise rules intact. Malformed Publisher fields
retain E14 precedence.

This required field retains `1.0.0` under ADR-0028's unreleased-draft rule.
The changed canonical bytes require regenerated signatures, IDs and every
dependent commitment. There is no implicit conversion of earlier signed
objects. [PUBLICATION.md](../PUBLICATION.md) governs the freeze boundary.

## Alternatives and consequences

Rejecting ambiguous matches does not solve identical inner bytes signed by
distinct keys, and lets copied public bindings invalidate an honest author.
Choosing the first matching key makes replay depend on traversal order.
Namespacing `sig.key_id` leaves both the signature and ID unbound to identity.
Inferring the author from the URL would forbid explicitly scoped publication.

The signed field adds up to 268 JCS octets per Delta, including its member
syntax and separator, while preserving Log-independent IDs and all existing
scope, key-time, recovery and chain constraints. It does not prove domain
control itself: authenticated Declaration discovery/history remains required.

`vectors/wist1/delta-attribution.json` supplies signed identity, field and
Feed-association probes, an authenticated Declaration/Delta history spanning
rotation, recovery competition, settlement and reset, and chain/binding probes
at its prefixes. Conditional projections verify current-identity attribution
separately from materialization; they do not establish Audit Record eligibility,
confirmation, notice acceptance or live transport. The independent reference
recomputes signatures, hashes, source selection and chain ownership.
