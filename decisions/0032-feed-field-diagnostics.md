# ADR-0032: Feed field diagnostics

**Status:** draft · **Date:** 2026-09-12

## Context

WIST-2 assigns unusable fields to E01 and foreign domains or failed
authentication to E04, with different quota and retry consequences. A
noncanonical domain can fail both conditions; malformed signatures can
likewise fail both schema validation and cryptographic verification.
The Feed version pattern also admitted non-semver spellings.

## Decision

WIST-2 §5 defines the Feed/Page field gate before domain comparison and
signature verification. It covers the complete Envelope, required format
checks and canonicalizability, preserving signed values. Field failures
retain E01; a field-valid foreign domain retains E04 without a Declaration
retry. Release spelling uses unbounded ASCII decimal components, matching
the release form used for Deltas. This decision does not define other
objects' unsupported-major diagnostics or change Page source selection.

## Alternatives and consequences

Checking identity first makes malformed domains noise while other malformed
fields receive backoff. Checking signatures first lets invalid fields consume
Declaration retries or acquire an authentication diagnostic from the keys
currently cached. Field precedence gives malformed content one disposition
independent of either overlap. A field-valid foreign domain cannot be repaired
by refreshing the requested domain's keys.

Complete format checks require Canonical Host processing, Gregorian calendar
validation and canonical base64url, beyond typed JSON deserialization or a
pattern match. Rejecting malformed signed spelling instead of normalizing it
preserves authentication. Numeric conversion would impose an unspecified
version-component bound.

`vectors/wist2/feed-fields.json` exercises signed mutations, simultaneous
failures and supplied pull dispositions. These probes do not establish
Page publication, history partitioning, monotonic Feed state, supported-major
policy, complete transport authority or durable source provenance.
