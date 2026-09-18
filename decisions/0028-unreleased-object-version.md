# ADR-0028: One unreleased signed-object version

**Status:** draft · **Date:** 2026-09-11

## Context

An editable draft can need incompatible schema corrections before its roles
have been validated together. A wire version alone cannot identify which
of those draft revisions a validator implements. Requiring a major version
for each correction makes draft iteration consume versions without providing
compatibility with an edition that has been frozen for use.

## Decision

WIST-1 §3.1 and [PUBLICATION.md](../PUBLICATION.md) permit incompatible
revisions of the unreleased suite, including required fields, to retain
`wist_version = 1.0.0`. Every validator enforces an exact specification
revision, and compatibility claims identify its commit. Unknown fields
remain forbidden. An older draft object is not acceptable merely because
its version string is unchanged; no implicit translation or legacy profile
is introduced.

This exception ends at the earlier of stable publication and the first Log
sealing Epochs consumed by a third party. A draft label never exempts such
a deployment. The frozen edition is immutable; corrections follow its
errata policy, and substantive changes require a new major version and
explicit adoption.

## Alternatives and consequences

A new major version for every incompatible draft would preserve the earlier
version rule but add transitions before a compatibility baseline exists.
Accepting every object labelled `1.0.0` would erase schema rejection and
permit disagreement about authenticated bytes. A draft exception without a
deployment boundary would break consumers of a deployed draft.

The selected rule assumes an edition has not crossed either freeze boundary.
Its cost is mandatory revision pinning during draft interoperability work;
its benefit is one object version describing the edition eventually validated
and frozen. It grants no exception after that boundary and changes no
cryptographic canonicalization or unknown-major rejection rule.

`vectors/wist1/delta-attribution.json` includes signed objects with the
current field set, the same version missing its required Publisher, an
unknown field and an unimplemented major. These discriminate object
acceptance at an exact revision; the publication boundary is an operational
fact that these offline fixtures cannot establish.
