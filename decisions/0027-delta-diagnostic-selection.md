# ADR-0027: Delta diagnostic selection

**Status:** draft, subject replaced by [ADR-0052](0052-items-and-catalogs.md) (2026-09-30: Item and Catalog diagnostics) · **Date:** 2026-09-11

## Context

WIST-1 assigns diagnostics to signature, authority, clock and chain failures
but a single Delta can fail several checks. A common rejection result is
necessary for conformance; a common first semantic diagnostic is not needed
to determine whether the Delta can be accepted. Field failures already have
precedence over cryptographic use, and individual checks have prerequisites
such as refreshing stale keys or attempting predecessor retrieval.

## Decision

WIST-1 §7 requires JCS eligibility followed by complete Delta E14 field
checks before selecting a semantic rejection. It permits any established
applicable semantic error afterward. E02 versus E01 remains determined by
complete binding eligibility, not by which candidate a validator tries first.
A rejected Delta need not undergo unrelated checks solely to select another
error. Performing a check retains all its prerequisites and side effects.
Acceptance still requires every applicable validation obligation.

This decision assumes the Publisher authority, key sources and validation
context have been selected under their own rules. WIST-1 §3.8 and ADR-0029
supply signed Publisher attribution and its E14 field check. This decision
does not prescribe replay's clock context. Payload rejection, recovery
settlement, idempotence, transport wrapping and error accounting retain
their existing dispositions.

## Alternatives and consequences

A universal signature-before-clock-before-chain order would serialize work
that can safely be rejected by another established failure, potentially
requiring network access solely to obtain a preferred diagnostic. A universal
cheapest-check-first order is not portable across cached and uncached state.
Unrestricted error reporting would permit codes unsupported by the inputs
and would erase the E02/E01 and field-precedence guarantees.

Permitted diagnostic sets preserve these guarantees while allowing validators
to order independent semantic checks. Clients must accept any member of the
applicable set rather than depend on one validator's first reported failure.
E14 covers structural failures while the explicit URL, size, missing-chain
and missing-content diagnostics retain their meaning. Treating every schema
failure as E14 would erase those established distinctions; wrapping every
malformed Delta as a transport error would make the same signed object
receive different field diagnoses during pull and replay. Unknown members
and optional nulls are rejected without rewriting signed bytes.

Metadata validation uses the schema's lexical language-tag profile. Requiring
a language registry or full BCP 47 semantic parsing would add unspecified
versioned data and reject spellings that this schema permits. Schema lengths
count scalar values; octet caps and JSON numeric-value integer checks remain
separate. Complete-string patterns prevent trailing-newline acceptance.

`vectors/wist1/delta-diagnostics.json` supplies signed Declaration sources,
signed predecessors and candidate combinations covering binding, scope,
clock and predecessor-time failures, plus field-precedence twins. The
reference independently derives the allowed sets. The contexts supply prior
acceptance, current source selection and validator time; they do not prove
Log inclusion, live discovery, Payload availability, recovery, complete
Delta eligibility or ambiguous-author attribution.


`vectors/wist1/delta-fields.json` adds signed structural mutations, valid
boundaries, amended size caps, semantic-exception and invalid-signature twins,
plus ID and Feed
association precedence. It supplies fresh authority and tests field/static
diagnostics without establishing chain history, clock admission, live
refresh/retrieval, Payload availability, Log inclusion or restart.

The undeployed draft changes under [PUBLICATION.md](../PUBLICATION.md).
