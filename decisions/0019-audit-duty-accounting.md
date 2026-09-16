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

Only a Record that a validator recomputing reputation accepts under WIST-4
§3 and §10.1 counts as a trigger, as an earlier filing that suppresses a
trigger, as an already-sealed filer that excludes dependent peers, or as a
member of either contradiction quorum. A rejected filing spends no ration.
Coverage failure at the Record's own Block rejects the same way. The
coverage carve-outs under which a rejected Record still discharges its duty
are unchanged. The ration reads `extension_triggers_max` at B₁, as WIST-4 §9
anchors every parameter of that extension.

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

Counting every sealed `inconsistent` filing regardless of validity would let
a malformed, unauthentic or standing-less Record, which costs its author
nothing, suppress the extension path for a whole confirmation window and
shrink the summoned set by naming filers whose Records carry no weight.
Counting authentic filings only would still admit mis-scored ones. Evidence-only
counting keeps the trigger, the summoned set and the closed contradiction
test on the Record set that reputation reads, so no party can summon or
block peers without a Record that also counts against it.

Keeping every late-sealed failure would confuse permitted transport delay
with shirking. Accepting unauthenticated predecessor gaps would let a
shirker manufacture exemptions. Neither choice is compatible with evidence
limited to what the Log actually authenticates.

## Verification

`vectors/wist4/extension.json` and `coverage.json` exercise ordering,
completion and receipt-backed exemptions. The `evidence_cases` of
`extension.json` carry signed Records pairing rejected filings with later
valid ones for the same Delta; their checker derives each rejection from the
signed bytes, version, score bands and supplied standing, removal and
coverage-failure contexts before recomputing triggers, ration, summoned sets
and contradiction outcomes over the surviving evidence. Standing, roster,
reference chains and coverage-failure state are supplied contexts, not
derived from an authenticated history. Publication timing and honest
availability remain live-service obligations under WIST-4's checklists.
