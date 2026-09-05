# ADR-0019: Audit duty accounting from authenticated Log prefixes

**Status:** draft · **Date:** 2026-09-05

## Context

WIST-4 §4 makes coverage failures and extension allocation derivable from
the Log. Publication and sealing are distinct events: delayed transport can
leave a complete duty temporarily unseen, while a missing predecessor hash
does not prove that its signer published any Record. Accounting must use
available authenticated evidence without rewriting an earlier prefix.

## Decision

### Extension allocation

Evaluate triggers in ascending Block height and Entry index. Eligibility
and ration use the strict prefix before each trigger, including earlier
Entries in its Block. Peer exclusion also includes the trigger itself.
Extract and link inconsistency Records share the per-Delta trigger sequence
and per-Auditor ration. The earlier eligible Entry spends the last slot;
a later Record remains valid and may confirm a finding without summoning
another extension. A later filing cannot cancel an earlier trigger or
retroactively remove its summoned peers.

### Completion and late sealing

Read duty completion from the available Log prefix. A complete discharge
removes the pair from the current coverage-failure count from its completion
Block, without requiring suppression evidence. Partial completion does not.
Apply the standing and void-discharge rules; an empty selection still needs
its coverage attestation. Late completion changes no prior prefix or sealed
removal and establishes completion rather than timely publication.

### Authenticated suppression evidence

A missing `prev_record` can be fabricated without holding its preimage.
It therefore earns no exemption by itself. For a pair-specific exemption,
the missing ID must appear in that pull attestation's signed `found` list.
The same Auditor's successor in the same Log must seal at or above the
attestation height, including the same Block. Read the successor and
missing-ID test from the prefix through the evaluation height. Once the
missing item seals, ordinary discharge determines completion.

Empty or unrelated receipts exempt no pair. Complete withholding and
nonpublication can leave indistinguishable Log prefixes: the fallback
preserves countability but can count an honest Auditor when the Aggregator
withholds both its publication and a receipt.

## Consequences and alternatives

Canonical position resolves ration competition without adding ordering
freedom. Completion can repair the current count without claiming that a
deadline was met. An Aggregator's signed receipt supplies authenticated
attribution; a signer-created gap cannot erase arbitrary duties.

Keeping every late-sealed failure would confuse permitted transport delay
with shirking. Accepting unauthenticated predecessor gaps would let a
shirker manufacture exemptions. Neither choice is compatible with evidence
limited to what the Log actually authenticates.

## Verification

`vectors/wist4/extension.json` and `coverage.json` exercise ordering,
completion and receipt-backed exemptions. Publication timing and honest
availability remain live-service obligations under WIST-4's checklists.
