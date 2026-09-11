# ADR-0024: Declaration field failure diagnostics

**Status:** draft · **Date:** 2026-09-11

## Context

WIST-1 §5.2 makes failed Declaration acceptance invalidate its Block with
the failing check's error. Canonicalizable malformed fields have neither
§4's canonicalization failure nor §5.2's semantic sequence/key-set failure.
Malformed `valid_from` and Delta `observed_at` cannot support a time-bound
comparison and must not be diagnosed as an otherwise valid unknown key.

## Decision

Assign `WIST1-E14` to Declaration Envelope schema/format failures and §4
integer-range failures, and to missing, non-string or malformed Delta
`observed_at`. Validate Declaration fields before sequencing, conflict
comparison, idempotence and authentication. A re-serve retains the schema
requirement even when its inner bytes match an accepted Declaration.
Do not mutate signed fields. Block rejection remains atomic, including
settlement and changes for other domains. WIST-2 first-contact pull failures
retain their `WIST2-E04` wrapper and noise accounting.

Existing field formats are unchanged: format checks are required,
`valid_from` and `observed_at` retain RFC 3339, and Log timestamps retain
their separately specified profile. This decision assigns diagnostics; it
does not redefine leap-second eligibility, hostname canonicalization,
cryptographic key admission or object-version compatibility.

## Alternatives and consequences

Reusing `WIST1-E05` would conflate valid JCS input with failure to produce
canonical bytes. Reusing `WIST1-E08` would hide the distinction between a
malformed field and a well-formed but stale sequence or wrong predecessor.
Using `WIST1-E02` for a malformed time bound would claim a key-eligibility
result without a valid comparison. A distinct code preserves those meanings.

Validators must perform field checks before deriving Declaration state.
The schema now restates the already-required safe-integer maximum for
`seq`. Signed mutations and authenticated Block rejection cases in
`vectors/wist1/declaration-fields.json` distinguish field errors, semantic
errors, signature errors, idempotence and rollback. The reference exercises
a documented subset of field formats; this evidence does not establish
complete RFC 3339, hostname or live admission/restart conformance.

The undeployed draft changes under [PUBLICATION.md](../PUBLICATION.md).
