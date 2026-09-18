# ADR-0019: Audit duty accounting from authenticated Log prefixes

**Status:** draft, superseded by [ADR-0041](0041-signed-publications.md) (2026-09-16: the Auditor role is removed) · **Date:** 2026-09-05

## Context

WIST-4 §4 makes coverage failures and extension allocation derivable from
the Log. Publication and sealing are distinct events: delayed transport can
leave a complete duty temporarily unseen, while a missing predecessor hash
does not prove that its signer published any Record. Accounting must use
available authenticated evidence without rewriting an earlier prefix.

## Decision

### Extension allocation

Evaluate triggers in ascending Epoch number and Entry index. Eligibility
and ration use the strict prefix before each trigger, including earlier
Entries in its Epoch. Peer exclusion also includes the trigger itself.
Extract and link inconsistency Records share the per-Delta trigger sequence
and per-Auditor ration. The earlier eligible Entry spends the last slot;
a later Record remains valid and may confirm a finding without summoning
another extension. A later filing cannot cancel an earlier trigger or
retroactively remove its summoned peers.

Only a Record that a validator recomputing reputation accepts under WIST-4
§3 and §10.1 counts as a trigger, as an earlier filing that suppresses a
trigger, as an already-sealed filer that excludes dependent peers, or as a
member of either contradiction quorum. A rejected filing spends no ration.
Coverage failure at the Record's own Epoch rejects the same way. The
coverage carve-outs under which a rejected Record still discharges its duty
are unchanged. The ration reads `extension_triggers_max` at B₁, as WIST-4 §9
anchors every parameter of that extension.

### Attestation eligibility

Validate both attestation classes under WIST-4 §9.1 first, then their
signing rule — the Log key for a pull attestation, the subject's key at the
attestation's Epoch or the duty Epoch's carve-out key for a coverage
attestation — then the named Epoch and duty, then the coverage proof.
Field failures are WIST4-E11 or WIST4-E04, authentication failures
WIST4-E11, an unsealed Epoch or absent duty WIST4-E04, and a failing proof
WIST4-E01. A verifying attestation for a nonempty duty set reveals the draw
and discharges nothing. The earliest pull attestation per pair fixes the
attested height and `found` list; every sealed act's ID counts as sealed for
the missing-item test, whatever its validity.

### Reading the sealed prefix

A pair with no verifying proof sealed by its Auditor is failed without a
draw. The state at an Epoch reads that Epoch's discharges and attestations
before the evidence status of its Records. An attested pair stays exempt
while contradicted even when the fallback established it first. Only a
successor with valid non-evidence fields and an authentic signature is the
Auditor's publication.

### Removal for coverage failure

The removal names the key the Auditor holds at the removal's Epoch and lists
as `evidence` the Block Hashes (the former name of a per-Epoch header hash
since removed) of every failed duty Epoch counting at that Epoch, in
ascending octet order. Block Hashes rather than Record IDs, because a failed
duty has no Record to cite; every counting Epoch rather than the first
`coverage_failures_max` + 1, so the evidence is the count itself.

### Completion and late sealing

Read duty completion from the available Log prefix. A complete discharge
removes the pair from the current coverage-failure count from its completion
Epoch, without requiring suppression evidence. Partial completion does not.
Apply the standing and void-discharge rules; an empty selection still needs
its coverage attestation. Late completion changes no prior prefix or sealed
removal and establishes completion rather than timely publication.

### Authenticated suppression evidence

A missing `prev_record` can be fabricated without holding its preimage.
It therefore earns no exemption by itself. For a pair-specific exemption,
the missing ID must appear in that pull attestation's signed `found` list.
The same Auditor's successor in the same Log must seal at or above the
attestation height, including the same Epoch. Read the successor and
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

Reading the duty before authenticity would let an unauthentic act name an
Epoch the prefix lacks and be reported as a duty failure rather than a
forgery; reading authenticity first keeps the diagnostic honest. Letting a
malformed Record's signature supply an exemption would let a forged shape
carry the Aggregator's acknowledgment; requiring valid non-evidence fields
keeps the successor a publication the Auditor could have made. Settling an
Epoch's discharges before its Records' weight lets an Auditor that catches
up inside one Epoch regain standing there, while the alternative would
reject Records the same Epoch already shows discharging duties.

Keeping every late-sealed failure would confuse permitted transport delay
with shirking. Accepting unauthenticated predecessor gaps would let a
shirker manufacture exemptions. Neither choice is compatible with evidence
limited to what the Log actually authenticates.

## Verification

`vectors/wist4/extension.json` and `coverage.json` exercise ordering,
completion and receipt-backed exemptions. `coverage.json`'s
`attestation_cases` carry signed pull and coverage attestations under
supplied duty contexts, checked through the schema partition, Ed25519 and
ECVRF with an authenticity-before-duty twin; its `derivation_cases` and
`same_block_case` (a removed vector's case, under its former name) trace
the readings above with twins for the ruled-out
ones; its `removal_cases` carry a signed coverage-failure removal whose
evidence is checked against the counting Epochs, with a Record-ID twin. The `evidence_cases` of
`extension.json` carry signed Records pairing rejected filings with later
valid ones for the same Delta; their checker derives each rejection from the
signed bytes, version, score bands and supplied standing, removal and
coverage-failure contexts before recomputing triggers, ration, summoned sets
and contradiction outcomes over the surviving evidence. Standing, roster,
reference chains and coverage-failure state are supplied contexts, not
derived from an authenticated history. Publication timing and honest
availability remain live-service obligations under WIST-4's checklists.
