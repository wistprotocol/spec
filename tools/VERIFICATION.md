# Vector verification anchors

This inventory identifies each vector family's verification anchors and
limits under [PUBLICATION.md](../PUBLICATION.md#developing-the-draft).
External answers detect shared generator/verifier errors in the behavior
they exercise; agreement without such an anchor may preserve a shared error.

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
as anchors. `negative:wist2-normalization` is stronger than most: it
recomputes each normalization case under the one reading that case exists
to rule out — a lowercase instead of a case fold, no NFC, a whitespace
split instead of UAX #29, code points instead of grapheme clusters — and
fails if the two readings agree, so a fixture that discriminates nothing
cannot enter the vector unnoticed.

## Inventory

| Family | Anchor | Kind | Status |
|---|---|---|---|
| wist1 envelope, `delta.canonical`, `id.txt`, `keypair.json` | Ed25519 via `cryptography`, JCS via `rfc8785` | third-party-lib | anchored |
| wist1 `ed25519-strictness.json` | the §4 profile that certifies it is pinned to the ed25519-speccheck corpus (`ed25519:speccheck-corpus`) | external-KAT | anchored |
| wist1 `host-canonicalization.json` | flags pinned to §2; A-label structure and Punycode round-trip recomputed; full UTS #46 mapping deliberately not reimplemented here (`requirements.txt`), so byte-level recomputation happens in consumers' independent UTS #46 libraries | structural + external | partial |
| wist1 `declaration-hosts.json` | signed host spellings and authenticated atomic Block rejection/acceptance; independent ASCII/DNS-length checks and Punycode round trips with explicit fixture-only decoded eligibility (including Unicode 16 U+1C89/U+1C8A and Unicode 17 U+1E6C0 exclusion), schema-field agreement and immutable signed bytes; full Unicode 16.0 UTS #46 mapping requires independent vector consumption; no live field validation, discovery, process eligibility or Snapshot recovery | third-party-lib (signatures/Punycode) + self-consistency (spelling/identity/rollback) | partial |
| wist1 `declaration-sequence.json` | prose-traced sequencing rules | self-consistency | self-consistency-only |
| wist1 `declaration-binding.json` | independently derived signer resolution and continuity; real Ed25519 signatures | third-party-lib + self-consistency | partial |
| wist1 `declaration-key-eligibility.json` | signed initial/replacement cases, independently derived usable point sets, immutable signed entries and predecessor/recovery protection; strict verification uses the existing speccheck-anchored profile; conditional appeal-key probes, without notice/process eligibility; canonical base64url fixtures only, without a complete field profile or service replay | external-KAT (verification profile) + third-party-lib (signatures) + self-consistency (key derivation) | partial |
| wist1 `base64url.json` | RFC 4648 §10 byte anchors (padding omitted), independently checked unused bits and lengths, exhaustive final sextets, schema agreement, signed aliases and authenticated Block rollback/acceptance twins; no full field formats, service adoption or transport-wrapper integration | external-KAT (encoding) + property-test (sextets/schema) + third-party-lib (signatures) + self-consistency (diagnostics/rollback) | partial |
| wist1 `declaration-fields.json` | independently checked signed field mutations and authenticated atomic Block rejection, including due settlement and idempotent re-serves; structural schema, ASCII hostname examples, event-independent Publisher timestamp rejection/acceptance, exact rational key bounds, >4300-digit fractions, civil-clock elapsed boundaries and isolated signed E06/E07 comparison twins; no complete hostname, integrated Delta chain/clock eligibility or live service result | third-party-lib (signatures/schema/calendar/rationals) + self-consistency (diagnostics/rollback/clock policy) | partial |
| wist1 `declaration-conflicts.json` | authenticated Block chains and Declaration signatures; independently replayed equal-sequence groups, distinct-content and distinct-signature conflicts, idempotence, domain separation and atomic rejection | third-party-lib (signatures) + self-consistency (batch transitions) | partial |
| wist1 `delta-fields.json` | signed structural/version mutations, schema-derived field diagnoses, scalar/safe-integer boundaries, supplied active caps, independent signature/ID checks and supplied Feed association; valid commitments recomputed, signed newline-invalid commitment probes rejected; independent major eligibility with E14 precedence, E15 combinations and unbounded same-major components; no complete admission, chain/clock history, live transport or durability | third-party-lib (schema/signatures/hashes) + self-consistency (diagnostics) | partial |
| wist1 `payload-fields.json` | signed Delta commitments and explicit preimages; complete Payload schema/semantic separation, version policy, numeric/scalar boundaries, cap overrides, diagnostic combinations and raw JSON duplicate/Unicode/number rejection; supplied profiles, without schedule replay, HTTP, sealing, restart or page agreement | third-party-lib (schemas/signatures/HMAC/JCS) + self-consistency (diagnostic sets) | partial |
| wist1 `payload-links.json` | 31 signed Deltas with independently recomputed commitments and explicit E12 outcomes for count, uniqueness, exact normalized spelling and signed-Publisher externality; normalization uses the reference resolver with its documented limitations; no complete fields, page comparison, live admission, sealing or durability | third-party-lib (signatures/hashes) + self-consistency (link rules) | partial |
| wist1 `delta-cap-time.json` | 509 signed hourly Blocks, 24 Deltas/Payloads, one attestation, 264 stage probes, two reference-Payload probes and six invalid candidate Blocks; authenticated inclusion and cap amendments, separate Delta-only/Payload checks, exact boundaries, reductions/increases, delayed retrieval and in-memory reconstruction; no live queues, crash durability, complete governance acceptance, cross-Log behavior or audit verdicts | third-party-lib (schemas/signatures/hashes) + self-consistency (temporal selection and cap checks) | partial |
| wist1 `delta-diagnostics.json` | signed Declaration sources, signed predecessor/hash links and independent exact rational comparisons; exhaustive binding/scope/clock/predecessor-time combinations with field-precedence twins and complete allowed error sets; source selection, prior acceptance and clock are supplied context, without Log replay, live refresh/retrieval, other semantic checks or Payload/recovery/transport dispositions | external-KAT (signature profile) + third-party-lib (signatures/calendar/rationals) + self-consistency (permitted diagnostics) | partial |
| wist1 `delta-attribution.json` | signed author/key/scope/Feed and version cases; authenticated hourly Block/Declaration/Delta history with independent source/chain replay through rotation, recovery and reset; conditional credit/penalty/notice identity attribution, without Audit Record eligibility, confirmation, notice acceptance, live transport or operational freeze-boundary verification | external-KAT (signature profile) + third-party-lib (signatures/hashes/schema) + self-consistency (source/chain/identity replay) | partial |
| wist1 `recovery-settlement.json` | independently replayed signed hourly Declaration histories, predecessor and recovery-key rejection twins; signed Delta verification over full key bindings, queue order and settlement eligibility; separate reuse, alias and whole-second valid-from probes; no integrated Publisher timestamp profile or actual survivor inclusion | third-party-lib (signatures) + self-consistency (settlement) | partial |
| wist1 `recovery-order.json` | independently replayed signed Block chains, Declaration signatures and predecessor links; reversed leaf-hash order discriminates recovery ownership from storage order | third-party-lib (signatures) + self-consistency (ordering) | partial |
| wist1 `recovery-bindings.json` | authenticated Declaration histories and independent signed Delta probes; complete frozen source bindings, exact rational timestamp eligibility, strict point/signature checks, mixed-failure diagnostics and reversed signed arrays; no full Delta/chain or live-clock eligibility, durable queue, Payload/quotas, sealing, settlement or Snapshot restoration | external-KAT (signature profile) + third-party-lib (signatures/calendar/rationals) + self-consistency (sources/diagnostics) | partial |
| wist1 `recovery-scope.json` | authenticated differing-scope Declaration histories; independently derived frozen source pairs, exact binding eligibility, competitor/follower exclusion, settlement and sealing authority, deadline changes, re-serving and tampered-signature rejection; stage probes do not establish complete Delta/chain/clock admission, durable queues, Payload/quotas or actual inclusion | third-party-lib (signatures/schema/calendar/rationals) + self-consistency (scope provenance and temporal authority) | partial |
| wist1 `recovery-heads.json` | independently replayed signed hourly Block chain and candidate probes; named-predecessor authentication, retained sequence floor, deadline settlement and restored-head idempotence; no identity or Snapshot result | third-party-lib (signatures) + self-consistency (state transitions) | partial |
| wist1 `recovery-admission.json` | independently authenticated hourly Block prefix and signed Declaration Envelopes with supplied admission events; separate admission/sealed heads and floors, pending competitor removal, retained followers, exact deadline, repeated settlement and composed post-deadline recovery effects; signed alternate Blocks demonstrate replay-valid but admission-forbidden revival; no live durability, Delta eligibility/E13 execution, Payload/quotas or Snapshot result | third-party-lib (signatures) + self-consistency (admission/sealing transitions) | partial |
| wist4 `recovery-identity.json` | independently replayed signed Declaration histories and candidate probes; same-Block reset order, open-prefix identity continuity and deadline boundaries; separately supplied eligible event projections test age, credit, decay, findings, rungs and notice identity scope, without authenticating those events or appeals | third-party-lib (Declaration/Block signatures) + self-consistency (identity projections) | partial |
| wist4 `recovery-appeals.json` | independently authenticated Declaration/notice histories and appeal signatures; frozen key bindings across open and settled prefixes, identifier reuse/aliases, future valid-from entries, repeated notices and author-rejection twins; notice evidence eligibility is a supplied stage input, not established by the histories, and probes assert no appeal process acceptance or live sealing | third-party-lib (Declaration/notice/appeal/Block signatures) + self-consistency (authority selection) | partial |
| wist1 `keyset-at-height.json` | prose-traced resolution rule | self-consistency | self-consistency-only |
| wist2 `link-extraction.json` | recomputed by `tools/link_extraction.py` over the fixture page | self-consistency | self-consistency-only |
| wist2 `text-extraction.json` | extraction and the containment quotient are harness-recomputed; the WIST-4 §5 normalization beneath them segments by `tools/segmentation.py`, checked in full against the Unicode Consortium's `WordBreakTest.txt` and `GraphemeBreakTest.txt` (`unicode:uax29-conformance`) | external-KAT (segmentation) | partial |
| wist2 `feed-fields.json` | signed schema/format mutations, unbounded release spelling, exact Gregorian timestamps and supplied field/domain/signature dispositions; no HTTP, Page publication/partitioning, Feed regression state, supported-major policy or durable provenance | third-party-lib (schema/calendar/signatures) + self-consistency (precedence) | partial |
| wist2 `feed-regression.json` | signed ordered live Feed observations, equal timestamps, authentication/field precedence and full timestamp range; no actual persistence, HTTP, Page/Delta work or Declaration transitions | third-party-lib (schema/calendar/signatures) + self-consistency (state transitions) | partial |
| wist2 `declaration-refresh.json` | 30 signed ordinary-rotation transport cases; Feed/Delta signatures, fields and Publisher association, shared Feed/Page and independent per-ID attempts, predecessor reinsertion, content-budget boundaries and Page current/first-next versus unsealed authority; supplied responses/sealing positions and empty Pages, without HTTP, authenticated Block inclusion, complete Page fields/publication, recovery settlement, cache expiry, resume or durability | third-party-lib (schema/signatures/hashes) + self-consistency (retry, source and budget transitions) | partial |
| wist2 `page-keyset.json` | prose-traced resolution rule | self-consistency | self-consistency-only |
| wist2 `page-bindings.json` | signed ordinary Declaration chains and 16 Page probes; independent named-entry verification, alias-renaming discriminator, reused identifiers, excluded points, exact source cutoffs and signature-invalid twins; supplied sealing positions and empty Delta lists establish no Block inclusion, recovery supersession, Page size, publication, refresh or durable provenance | external-KAT (strict signature profile) + third-party-lib (signatures) + self-consistency (source selection) | partial |
| wist3 `block.json`, `inclusion-proof.json` | Merkle hashing vs the Certificate Transparency reference answers (`merkle:ct-reference-vectors`); exhaustive inclusion property test; signatures via third-party libs | external-KAT + property-test | anchored |
| wist3 `empty-block.json` | the deliberate deviation from RFC 6962's empty root, with both constants pinned side by side | external-KAT (documented deviation) | anchored |
| wist3 `block-frames.json` | raw frame layout traced to RFC 8878 §3.1.1; an independently structured fixture decoder checks sizes and EOF, with concatenation/truncation mutations; general entropy decoding and checksums are outside that decoder | self-consistency (framing) | partial |
| wist3 `timestamps.json` | integer epoch answers checked through Python's Gregorian calendar, including year zero and the last second of year 9999; leap-second, out-of-range-year and schema-field mutations, including Snapshot tuple positions | third-party-lib (calendar) + self-consistency (profile) | partial |
| wist3 `snapshot-records.json` | materialization re-derived from the Payload | self-consistency | self-consistency-only |
| wist3 `chain-materialization.json` | prose-traced chain-tip rule | self-consistency | self-consistency-only |
| multilog `dedup.json` | prose-traced dedup rules | self-consistency | self-consistency-only |
| wist4 `sampling.json` | ECVRF primitive vs RFC 9381 Appendix B.3 (`ecvrf:rfc9381-b3-vectors`); sampling rates independently recomputed with exact rationals, including signed slope wire endpoints, zero and sanction/escalation overrides; negative-slope twins reject unsigned conversion; supplied profiles do not establish amendment or standing replay | external-KAT (primitive) + self-consistency (sampling) | partial |
| wist4 `extension-proof.json` | ECVRF primitive as above; which Block a proof binds a Record to is harness-recomputed only | external-KAT (primitive) | partial |
| wist4 `link-agreement.json` verdict profiles | supplied accepted amendments, audited-Block anchors, increasing/decreasing link thresholds, exact boundaries and reference change-type applicability; independent schedule/band recomputation and alternative-anchor rejection, without signed history or complete Record eligibility | self-consistency | partial |
| wist4 `parameter-in-force.json` | prose-traced in-force rule | self-consistency | self-consistency-only |
| wist4 `parameter-combinations.json` | the §9 coverage sum checked against simulated §4 counts; prospective schedules, frozen recovery-window anchors over supplied eligible events/accepted amendments, cadence transitions, retention and Block-size/transport traces with negative boundary cases | self-consistency | self-consistency-only |
| wist4 `unauditable.json` | prose-traced predicate | self-consistency | self-consistency-only |
| wist4 `audit-commitments.json` | SHA-256 from the standard library; commitment structure recomputed | third-party-lib (hash) | partial |
| wist4 `canary.json` | HMAC and SHA-256 from the standard library; the leaf's Merkle inclusion checked from signed reveal envelopes without served bytes, and re-walked by the verifier's fn/sn algorithm (WIST-3 §4) rather than the generator's PATH construction; the similarity beneath the hard hit segments by `tools/segmentation.py` (`unicode:uax29-conformance`); credit, hard hit, reveal timing and the scoreboard are harness-recomputed only | third-party-lib (hash) + external-KAT (segmentation) | partial |
| wist4 `observer-checkpoints.json` | prose-traced budget allocation, epoch boundaries and checkpoint coverage | self-consistency | self-consistency-only |
| wist4 `decay-table.json`, `reputation.json` | recomputed and checked against the WIST-4 appendix figures | prose-figures | self-consistency-only |
| wist4 `confirmation.json`, `derivation.json`, `coverage.json`, `extension.json`, `sanctions.json`, `superseded-audit.json`, `roster.json`, `selection-domain.json`, `link-agreement.json` | replay semantics recomputed by the generator's own logic; confirmation quorum windows also checked by the harness through distinct two-label suffix counts | self-consistency | self-consistency-only |

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
