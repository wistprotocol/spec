# ADR-0022: Leap-free Log timestamps

**Status:** draft · **Date:** 2026-09-10

## Context

WIST-3 §3.1 requires whole-second UTC timestamps. WIST-4 §6.1 converts
them to integer seconds with exactly 86,400 seconds per day and no leap
seconds. RFC 3339 also represents an inserted leap second with `:60`;
accepting that spelling without a mapping leaves clock comparisons and
cadence checks dependent on a parser's normalization.

## Decision

The whole-second, literal-`Z` timestamp profile permits seconds `00`
through `59` only. Reject `:60`; never clamp, roll forward or otherwise
normalize it. Conversion uses the Gregorian calendar and exactly 86,400
seconds per day relative to 1970-01-01T00:00:00Z. Consequently the distance
from 2016-12-31T23:59:59Z to 2017-01-01T00:00:00Z is one second.
Digits are ASCII as in RFC 3339; its four-digit year range includes `0000`.
Gregorian year zero is a leap year. A parser's narrower date range does
not change the profile.

This profile applies to Block and Checkpoint `sealed_at`, Feed
`generated_at`, Audit Record `fetched_at`, Registry Update `effective_at`,
notice `appeal_deadline`, and every Snapshot state timestamp specified by
WIST-3 §7 in that same form. Calendar validity remains required in addition
to matching a schema pattern. Other fields retaining the broader RFC 3339
format are outside this decision; their precision and offset rules do not
change.

## Consequences and alternatives

Clamping a leap second to `:59` aliases two spellings; rolling it forward
aliases the next midnight. Either interpretation can move a deadline or
cadence test. Explicit rejection preserves an unambiguous integer clock
without a leap-second table. Publishers of Log-comparable timestamps must
emit a value in the specified profile.

## Verification

`vectors/wist3/timestamps.json` exercises integer epoch conversion,
calendar boundaries, leap-second rejection and field-level mutations in
all affected schemas, including the timestamp positions in Snapshot tuples.
Year-zero and non-ASCII-digit cases distinguish library acceptance from
the specified profile.
`tools/validate_examples.py` checks the profile independently of optional
JSON Schema format validation and uses calendar validation for dates.
