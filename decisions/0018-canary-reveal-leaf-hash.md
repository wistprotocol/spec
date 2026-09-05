# ADR-0018: Canary reveals seal the proof starting hash

**Status:** accepted; amended by ADR-0030 (2026-09-05: Log-wide canary Delta uniqueness and score deduplication) · **Date:** 2026-09-05
**Amends:** ADR-0012

## Context

WIST-4 §5.1 requires membership verification from the Log alone. A reveal
previously carried an index, Delta ID and sibling hashes, but no starting
leaf hash. Served bytes are off-Log, and a Delta ID does not hash them.
A multi-leaf proof therefore lacked an input its verifier needs.

## Decision

Require `leaf_hash` on each revealed leaf: `sha256:` followed by the
lowercase hex of `SHA-256(0x00 ‖ served bytes)`. Replay starts the WIST-3
§4 walk at this sealed hash, with the committed tree size and revealed
index and path. Missing or malformed hashes and incomplete or surplus
paths reject the reveal as `WIST4-E08`.

The scorer separately verifies that the served bytes hash to this leaf.
The embedded nonce and its secrecy requirements remain unchanged. The
Log proves membership of a declared hash; it does not prove what a
server returned.

## Consequences

The reveal schema changes incompatibly. Existing reveals lacking the
field must be regenerated. No raw page bytes enter the Log, and scoring
retains its existing off-Log byte and Reference Payload dependencies.

## Alternatives considered

Putting served bytes in the reveal defeats the suite's retention design.
Dropping Log-only membership verification would prevent replay from
rejecting a false proof. Adding the missing hash preserves both duties.
