# ADR-0038: Feed and Page `next` targets

**Status:** draft · **Date:** 2026-09-16

## Context

WIST-2 §3.2 required `next` to be an absolute `https` URL within the
Publisher's authority under `/.well-known/wist/` without naming the
Declaration that supplied the authority for a live Feed or a historical
Page, fixing whether containment was judged before or after path
normalization, treating a port, userinfo or encoded dot segment, or saying
whether an Aggregator reads `next` on an object it has fully ingested. Two
validators could fetch different targets from one Page, and a target's
disposition could change with a rotation or recovery settlement.

## Decision

`next` is read only when the walk continues past its object. A read
`next` must be byte-identical to its Normalized URL and begin with
`https://`, the requested Canonical Host and `/.well-known/wist/`; a query
is fetched as written. No Declaration is consulted. Failure is `WIST2-E01`
for the walk: the target is never fetched and the Deltas already fetched
proceed. Schema failures — a non-string, a non-`https` scheme, a fragment
— remain field failures of the whole object under §5.

## Alternatives and consequences

Admitting `subdomain_scope` hosts would make a Page's pointer depend on
the Key Set selected for it, so a retry or settlement could flip a fetched
target, and a scope host publishing its own Feed would place two
Publishers' Pages under one layout. Pages live in the Publisher's own
layout (§3.1), so equality costs Publishers nothing, and §8's redirect
rule still lets a host move an accepted target.

Normalizing before comparing would accept `%2E%2E` and `:443` spellings
and let URL libraries repair inputs differently. Byte-identity, as WIST-1
§3 requires of Delta `url`, makes every validator fetch the Publisher's
exact octets or nothing. A port would point outside the default-port
layout §3.1 defines.

Rejecting the whole object for a bad target would discard Deltas the
Publisher signed and the Aggregator authenticated, and would differ from
an unfetchable Page, whose Deltas the walk keeps. Reading `next` on a
fully ingested object would diagnose a pointer no conforming walk follows.

`vectors/wist2/feed-next.json` fixes the dispositions. A live test must
show that an invalid target is never requested and that a query survives
fetching.
