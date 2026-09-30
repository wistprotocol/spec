# ADR-0026: Deterministic Publisher timestamps

**Status:** draft · **Date:** 2026-09-11

## Context

Declaration `valid_from` and Delta `observed_at` determine key eligibility
and chain order. [RFC 3339 §5.7](https://www.rfc-editor.org/rfc/rfc3339.html#section-5.7)
conditions second 60 on an inserted leap second and excludes second 59 at a deleted one. Future insertions cannot
be inferred from the calendar. Leaving event authority, table version and
announcement timing unspecified makes historical validation depend on
external data, including for keys declared before their future activation.

The Log already uses a Gregorian clock with 86,400 seconds per day
([ADR-0022](0022-log-timestamp-seconds.md)). Publisher timestamps need
fractional precision and numeric offsets, but do not need leap-event data
to establish a stable ordering or an inclusive key bound.

## Decision

WIST-1 §3.4 defines the Publisher timestamp profile used by an Item's
`observed_at`. A Catalog's `generated_at`, which key windows and the clock
rule read, uses the whole-second Log profile
([ADR-0052](0052-items-and-catalogs.md)). Retain RFC 3339's ASCII
grammar, four-digit Gregorian dates, arbitrary decimal fractions, lowercase
`t`/`z`, and numeric offsets, including `-00:00`. Permit seconds 00–59
only. Reject every `:60` spelling, including actual historical insertions
and offset-equivalent representations. Never normalize signed fields.

Use exactly 86,400 seconds per Gregorian day for eligibility and arithmetic,
with no external leap-event input. Ordinary future dates remain eligible
as fields; `valid_from` has no announcement horizon. Every minute permits
second 59 even if an external authority announces a negative leap. This
explicitly replaces RFC 3339's leap-event restrictions; it is not a claim
to implement physical UTC or a strict RFC 3339 subset at a deleted second.
Producers must represent observations using this clock and the specified
grammar; event-specific clock synchronization or smearing is not prescribed.

Compare exact instants after subtracting the numeric offset, preserving
every fractional digit. The written year must be 0000–9999; arithmetic may
cross that range after offset subtraction. `WIST1-E14` field precedence
applies, and an `observed_at` later than its Catalog's `generated_at`,
compared as exact instants, is `WIST1-E06`.
The separate whole-second literal-Z Log profile and descriptive timestamp
fields are unchanged.

## Alternatives and consequences

A pinned historical leap table would preserve historical `:60` spellings
but require a protocol revision to admit later events, while ordinary
future `valid_from` values could straddle an unknown deletion. A live IERS
table would make validation depend on retrieval, versioning and availability
outside authenticated history. Recording authenticated table updates would
add governance and replay machinery solely for timestamp eligibility.
Accepting any syntactic `:60` would invent instants and leave clock arithmetic
ambiguous. Applying the Log grammar verbatim would unnecessarily discard
Publisher fractions and offsets.

The selected profile removes those dependencies at the cost of rejecting
historical leap-second spellings previously permitted by the draft. It also
chooses civil-clock labels over physical elapsed SI seconds across leap
events. This is a normative revision under [PUBLICATION.md](../PUBLICATION.md),
not an erratum. After deployment, changing the accepted timestamp language
or clock interpretation requires a new major version.

## Verification

`vectors/wist1/item-fields.json` contains positive and negative
`observed_at` cases and its comparison with `generated_at` across offsets and
long fractions; `vectors/wist1/declaration-fields.json` contains signed key
window cases and authenticated Epoch rejection through recovery settlement
with separate acceptance cases.
Historical insertions, equivalent offsets, wrong dates/minutes, unannounced
future labels, a hypothetical negative-leap boundary, year zero, offset
overflow beyond the written year range and sub-nanosecond fractions
distinguish this profile from library defaults and event-table validation.
The hypothetical deletion is a protocol-clock probe, not an event prediction.
The independent reference uses Gregorian calendar validation and exact
rational arithmetic. Live admission, replay, sealing, restoration and full
Catalog clock validation remain separate conformance obligations.
