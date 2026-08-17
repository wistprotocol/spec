# Vector verification anchors

The specification prose is normative; every vector is derived from it and
never the reverse. This file inventories, per vector family, what that
derivation is verified *against* — because "the harness passes" can mean
two different things. Where a family is anchored to an answer published
outside this repository, a shared misreading of the prose by the vector
generator and the harness cannot survive: the external answer breaks the
tie. Where no such anchor exists, generator and harness — which share
authorship (see `AI-USAGE.md`) — could in principle share one
misreading and still agree, so those rows are the suite's open
verification surface, listed here to stay visible rather than implicit.

## Anchor kinds

- **external-KAT** — known answers published outside this repository,
  transcribed verbatim into `tools/` and re-proved on every harness run.
- **third-party-lib** — the computation runs through an independently
  maintained library (Ed25519 via `cryptography`, JCS via `rfc8785`,
  SHA-256 via the standard library), so the primitive itself is not of
  this repository's authorship.
- **property-test** — structural exhaustion (every size/index in a
  range), which catches whole classes of construction bugs but cannot
  certify that the construction is the *intended* one.
- **prose-figures** — recomputation checked against worked figures in
  the specification's own appendices; ties vectors to the normative text
  but shares its authorship.
- **self-consistency** — the harness recomputes what the generator
  produced, plus mutation twins proving the check is not blind.

Every family additionally has mutation twins or negative cases where
applicable; those prove sensitivity, not correctness, and are not listed
as anchors.

## Inventory

| Family | Anchor | Kind | Status |
|---|---|---|---|
| wist1 envelope, `delta.canonical`, `id.txt`, `keypair.json` | Ed25519 via `cryptography`, JCS via `rfc8785` | third-party-lib | anchored |
| wist1 `ed25519-strictness.json` | the §4 profile that certifies it is pinned to the ed25519-speccheck corpus (`ed25519:speccheck-corpus`) | external-KAT | anchored |
| wist1 `host-canonicalization.json` | flags pinned to §2; A-label structure and Punycode round-trip recomputed; full UTS #46 mapping deliberately not reimplemented here (`requirements.txt`), so byte-level recomputation happens in consumers' independent UTS #46 libraries | structural + external | partial |
| wist1 `declaration-sequence.json` | prose-traced sequencing rules | self-consistency | self-consistency-only |
| wist1 `recovery-settlement.json` | prose-traced settlement rules | self-consistency | self-consistency-only |
| wist2 `link-extraction.json`, `text-extraction.json` | recomputed by `tools/link_extraction.py` over the fixture page | self-consistency | self-consistency-only |
| wist3 `block.json`, `inclusion-proof.json` | Merkle hashing vs the Certificate Transparency reference answers (`merkle:ct-reference-vectors`); exhaustive inclusion property test; signatures via third-party libs | external-KAT + property-test | anchored |
| wist3 `empty-block.json` | the deliberate deviation from RFC 6962's empty root, with both constants pinned side by side | external-KAT (documented deviation) | anchored |
| wist3 `snapshot-records.json` | materialization re-derived from the Payload | self-consistency | self-consistency-only |
| multilog `dedup.json` | prose-traced dedup rules | self-consistency | self-consistency-only |
| wist4 `sampling.json` | ECVRF primitive vs RFC 9381 Appendix B.3 (`ecvrf:rfc9381-b3-vectors`); the sampling rule above the primitive is harness-recomputed only | external-KAT (primitive) | partial |
| wist4 `audit-commitments.json` | SHA-256 from the standard library; commitment structure recomputed | third-party-lib (hash) | partial |
| wist4 `decay-table.json`, `reputation.json` | recomputed and checked against the WIST-4 appendix figures | prose-figures | self-consistency-only |
| wist4 `confirmation.json`, `derivation.json`, `coverage.json`, `extension.json`, `sanctions.json`, `link-agreement.json` | replay semantics recomputed by the generator's own logic | self-consistency | self-consistency-only |

## Reading the table

"Anchored" families are safe against a shared misreading: drift breaks a
harness check against an answer this repository did not produce.
"Partial" families anchor their primitive but not the protocol rule
built on it. "Self-consistency-only" families — above all the WIST-4
replay and reputation mathematics, which no external reference can
exist for — are internally coherent and prose-traced, nothing more; an
independent re-derivation from the prose is the only way to close them,
and until one exists, a conforming implementation's disagreement with
these vectors deserves investigation rather than reflexive deference to
the vector (the prose, as always, wins).

A new vector family added without a row here, or a row claiming an
anchor the harness does not enforce, should be treated as a defect of
the change that introduced it.
