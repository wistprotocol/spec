# ADR-0027: Delta diagnostic selection

**Status:** draft · **Date:** 2026-09-11

## Context

WIST-1 assigns diagnostics to signature, authority, clock and chain failures
but a single Delta can fail several checks. A common rejection result is
necessary for conformance; a common first semantic diagnostic is not needed
to determine whether the Delta can be accepted. Field failures already have
precedence over cryptographic use, and individual checks have prerequisites
such as refreshing stale keys or attempting predecessor retrieval.

## Decision

WIST-1 §7 requires JCS eligibility followed by the existing Delta E14 field
checks before selecting a semantic rejection. It permits any established
applicable semantic error afterward. E02 versus E01 remains determined by
complete binding eligibility, not by which candidate a validator tries first.
A rejected Delta need not undergo unrelated checks solely to select another
error. Performing a check retains all its prerequisites and side effects.
Acceptance still requires every applicable validation obligation.

This decision assumes the Publisher authority, key sources and validation
context have been selected under their own rules. WIST-1 §3.8 and ADR-0029
supply signed Publisher attribution and its E14 field check. This decision
does not prescribe replay's clock context or assign diagnostics to other
fields. Payload rejection, recovery settlement, idempotence, transport wrapping and error accounting retain their existing dispositions.

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
The diagnostic-selection mechanism requires no wire field or schema changes.

`vectors/wist1/delta-diagnostics.json` supplies signed Declaration sources,
signed predecessors and candidate combinations covering binding, scope,
clock and predecessor-time failures, plus field-precedence twins. The
reference independently derives the allowed sets. The contexts supply prior
acceptance, current source selection and validator time; they do not prove
Log inclusion, live discovery, Payload availability, recovery, complete
Delta eligibility or ambiguous-author attribution.

The undeployed draft changes under [PUBLICATION.md](../PUBLICATION.md).
