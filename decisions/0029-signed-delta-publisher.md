# ADR-0029: Signed Catalog Publisher identity

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

WIST-1 §3.8 requires `publisher` inside the signed Catalog and inside every
Item it lists ([ADR-0052](0052-items-and-catalogs.md)). Its value is the
canonical Publisher domain, with the Declaration host profile. Missing or
malformed values are E14 before semantic checks. Only the Catalog's domain
supplies Declaration history, Collections, literal URL scope and applicable
complete signing bindings. Another domain's keys cannot repair a missing or
ineligible source. An Item whose `publisher` is not its Catalog's is
refused alone with WIST2-E03, and the Publisher of an Item's Entry is its
named Catalog's.

The Publisher is included in the Catalog's signature and ID input and in
each Item's ID, leaf and hence the root. Key aliases stay
outside that input and cannot change authorship. Shared keys remain possible;
copying public bytes does not give the private key needed to sign a statement
naming a different domain. Ordinary re-signing after rotation retains the ID.

A record is keyed by the exact `(publisher, url)` pair, which rotation,
recovery and fresh identity preserve; reset rules do not rewrite a sealed
Item's author. Materialization uses the authenticated signed domain. This
establishes attribution independently of materialization preference.

A Catalog fetched for one Publisher or Collection that names another is
WIST2-E04 at the pull. Check the logical domain the Catalog was fetched
for, never a redirect or Mirror's physical hostname. Malformed Publisher
fields retain E14 precedence.

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

The field adds up to 268 JCS octets per Catalog and per Item, including its
member syntax and separator, while preserving Log-independent IDs and all
existing scope, key-time and recovery constraints. It does not prove domain
control itself: authenticated Declaration discovery/history remains required.

`vectors/wist1/catalog-fields.json` supplies a Catalog of another Publisher
signed by a key of the Declaration and noncanonical `publisher` spellings;
`vectors/wist1/item-fields.json` Items whose `publisher` is not their
Catalog's; `vectors/wist1/item-roots.json` a `publisher_item` body whose Item
names another Publisher. They do not establish live transport.
