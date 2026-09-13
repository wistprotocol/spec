# ADR-0034: Payload field diagnostics

**Status:** draft · **Date:** 2026-09-12

## Context

The Payload schema defines structure, while WIST-1 §3.6 assigns separate
size and link diagnostics. Schema-only validation can mask those errors,
apply default lengths after cap amendments, or inherit parser-dependent
integer and optional-null acceptance. WIST-2's E03 pull wrapper does not
settle standalone diagnostic precedence.

## Decision

WIST-1 §7 defines JCS eligibility, then complete Payload E14 field checks,
then any established applicable semantic diagnostic. ADR-0030 supplies
version eligibility. WIST-1 §3.6 distinguishes amendable octet caps from
the fixed summary field lengths. Integer fields use numeric values under
WIST-1 §4, and validation preserves the received bytes for distribution.

The supplied Delta must already be eligible and its size-cap profile selected
under its own rules. These checks establish neither content availability nor
the accuracy of a Payload against the page. Existing transport wrappers,
withdrawal and materialization rules retain their dispositions.

## Alternatives and consequences

Treating every schema failure as E14 would erase explicit E04/E12 rules.
Skipping structural checks when a commitment verifies would accept unknown
fields and nulls that the object format forbids. Fixed extract and URL
lengths would prevent accepted cap increases from taking effect.
Removing the summary field limits would discard independent schema bounds;
their scalar counts and the summary's octet cap constrain different things.

Requiring a Payload's version string to equal its Delta's would add a
cross-object constraint unrelated to either object's supported semantics.
Numeric lexical restrictions would reject equivalent JCS values. A total
semantic diagnostic order would force unnecessary work after rejection;
permitted sets preserve field precedence without that requirement.

`vectors/wist1/payload-fields.json` supplies signed Delta commitments,
Payload mutations, cap contexts and expected diagnostic sets. It covers
fields, version support, scalar/numeric boundaries and semantic combinations;
live retrieval, historical profile reconstruction and independent role
adoption remain validation obligations under [CONFORMANCE.md](../CONFORMANCE.md).

The undeployed draft changes under [PUBLICATION.md](../PUBLICATION.md).
