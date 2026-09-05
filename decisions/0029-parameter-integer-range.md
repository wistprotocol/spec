# ADR-0029: Parameter wire bounds preserve integer reputation

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012

## Context

WIST-1 §4 claimed every integer's own bounds kept it in the interoperable
range, but Registry values lacked that bound. A negative Provisional cap
also made §6.2 return a negative reputation.

## Decision

Require all suite integer members to fit ±(2^53−1), inclusive, in addition
to field-specific bounds. Apply that range in the parameter schema and
require `provisional_cap_u` ≥ 0. Intermediate arithmetic stays exact and
may exceed the wire range. Schema acceptance never replaces semantic
amendment validation.

## Consequences

A large JSON number cannot silently round to another parameter value.
Zero Provisional reputation remains possible; negative reputation does not.
