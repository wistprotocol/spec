# ADR-0035: Audit Record field and version dispositions

**Status:** draft · **Date:** 2026-09-13

## Context

The Record schema constrains the entire Envelope, but the error registry
previously named only selected evidence defects. Coverage may count malformed
evidence as publication, so treating every schema failure alike could credit
an unauthenticated object or erase a demonstrated duty discharge. Record
version support also lacked a role-independent diagnostic and spelling rule.

## Decision

WIST-4 §10.1 defines the complete field partition, diagnostic precedence,
version support and discharge conditions.
WIST-1 §2 routes Record signature encoding failures to this field gate; its
canonical base64url requirements remain unchanged. WIST-1 §4 similarly
defers Record signature-failure diagnostics without changing verification.

The Record schema uses exact whole-string ASCII patterns, including version
spelling without machine-integer limits. Calendar validity and numeric-value
integer checks retain WIST-3 §3.1 and WIST-1 §4 respectively.

## Alternatives and consequences

Rejecting every field defect without discharge would erase §3's treatment of
published but malformed evidence. Letting every malformed object discharge
would permit unknown structure, unsupported semantics or fabricated authorship
to satisfy duties. A field partition preserves the distinction and provides a
diagnostic for unknown members without interpreting them as future extensions.

Returning E02 before a signature check saves work for reputation exclusion
but cannot justify coverage credit. Evaluating discharge separately preserves
that optimization while requiring every premise of the credit. An unsupported
major remains disqualifying when an evidence error takes diagnostic precedence.

Exact-version equality would reject compatible minor/patch spellings; silent
acceptance of another major would apply rules its author did not claim.
This decision assumes a pinned revision under [PUBLICATION.md](../PUBLICATION.md).

## Validation

`vectors/wist4/record-fields.json` carries original JSON Envelopes, signed
mutations and explicit standing contexts. Its independent checker verifies
signatures, schema-derived field categories, version support and conditional
discharge. It exercises malformed evidence together with forged signatures,
unsupported majors, missing duties and the removal/coverage carve-outs.
The contexts do not reconstruct rosters, selection, extension allocation,
reference histories or live sealing; those remain integrated-role obligations
in [CONFORMANCE.md](../CONFORMANCE.md#audit-record-field-and-version-dispositions).
