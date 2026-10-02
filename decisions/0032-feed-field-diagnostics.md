# ADR-0032: Label Feed field diagnostics

**Status:** draft · **Date:** 2026-09-12

## Context

A Label Feed or Page that is unusable can fail three checks at once: a
noncanonical `domain` fails both the field checks and the comparison with
the requested host, and a malformed signature fails both the schema and
cryptographic verification. Without an order, two Aggregators read one
such object differently. The Feed's version pattern also admitted
non-semver spellings.

## Decision

WIST-2 §3.2 checks a Label Feed or Page in a fixed order: the field gate,
then the comparison of `domain` with the requested host, then the
signature. The field gate covers the complete Envelope, required format
checks and canonicalizability, preserving signed values. Release spelling
uses unbounded ASCII decimal components, matching the release form of a
Catalog's `wist_version` (WIST-1 §3.1). WIST-2 does not determine the code
an Aggregator reports for a Label Feed that fails one of the three checks,
or for a Page that fails the first two
([CONFORMANCE.md](../CONFORMANCE.md)); a Page that verifies under neither
of its sources is `WIST2-E04`. This decision does not define other
objects' unsupported-major diagnostics or change Page source selection.

## Alternatives and consequences

Checking identity first gives a malformed domain the disposition of a
foreign one while other malformed fields receive another. Checking
signatures first lets invalid fields acquire an authentication diagnostic.
Field precedence gives malformed content one disposition independent of
either overlap. A field-valid foreign domain cannot be repaired by the
requested domain's Declaration, which every pull already fetches.

Complete format checks require Canonical Host processing, Gregorian calendar
validation and canonical base64url, beyond typed JSON deserialization or a
pattern match. Rejecting malformed signed spelling instead of normalizing it
preserves authentication. Numeric conversion would impose an unspecified
version-component bound.

`vectors/wist2/feed-fields.json` exercises signed Label Feed mutations,
simultaneous failures and supplied pull dispositions. These probes do not
establish Page publication, history partitioning, monotonic Label Feed
state, supported-major policy, complete transport authority or durable
source provenance.
