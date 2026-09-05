# ADR-0033: A predecessor hash alone earns no exemption

**Status:** accepted · **Date:** 2026-09-05
**Amends:** ADR-0012, ADR-0024

## Context

A signer can fabricate a missing predecessor hash without holding any
preimage. Treating a signed successor as proof of publication gave every
shirker a way to exclude all unattested duties from its failure count.

## Decision

Remove the bare-gap exemption. Retain the pair-specific exemption backed
by the Aggregator's signed `found` receipt, and completion-based discharge.
Correct the security claim: complete withholding and nonpublication may
leave indistinguishable Log prefixes.

## Consequences

A fabricated predecessor cannot erase a failure. An Aggregator's receipt
binds its own acknowledgment to one duty; it does not exempt other duties.
The fallback preserves countability at the cost of counting an honest
Auditor when the Aggregator withholds both publication and receipt.
