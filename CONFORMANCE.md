# Conformance validation

The specification is authoritative. Passing the reference harness does not
establish conformance for behavior it does not exercise. Known reference
divergences below must be resolved with discriminating vectors before a
stable edition can be published under [PUBLICATION.md](PUBLICATION.md).

## URL resolution

WIST-2 §11 step 5 specifies RFC 3986 §5. The `normalize_url` function in
`tools/link_extraction.py` delegates relative resolution to `urljoin`, which
does not implement that procedure for these inputs:

| Candidate | Base | Required result | Reference result |
|---|---|---|---|
| `https:///x` | `https://example.com/blog/post-1` | Reject the empty host | `https://example.com/x` |
| `a//b` | `https://example.com/blog/post-1` | `https://example.com/blog/a//b` | `https://example.com/blog/a/b` |
| `x//` | `https://example.com/blog/post-1` | `https://example.com/blog/x//` | `https://example.com/blog/x/` |

An explicitly empty authority cannot inherit the base host. Empty path
segments survive merging and removal of dot segments. The link-extraction
vectors do not exercise these cases. Correct the reference resolver and
add positive and negative cases without changing the specified algorithm.

## Recovery history resolution

### Declaration field and key eligibility

WIST-1 §§3.4, 5.1 and 7 assign `WIST1-E14` to malformed Declaration
Envelope fields and missing, non-string or malformed Delta `observed_at`.
[ADR-0024](decisions/0024-declaration-field-diagnostics.md) fixes field-check
precedence before Declaration sequencing, conflicts, idempotence and signer
resolution. `vectors/wist1/declaration-fields.json` supplies signed field
mutations and authenticated rejection Blocks, including another domain's
valid transition, open recovery, due settlement and malformed current re-serves.
Canonicalization, semantic sequencing and cryptographic failures retain their
separate codes; first-contact pull failure retains the `WIST2-E04` wrapper.
Adoption in admission, historical replay, sealing and durable restoration
remains required. The reference checks the supplied structural, ASCII hostname
and non-leap RFC 3339 cases; these vectors do not establish the complete
hostname or timestamp profile, leap-second eligibility, Delta chain/clock
checks, or full key eligibility. Unsupported leap-second inputs fail this
field-vector checker explicitly rather than silently selecting a policy.

WIST-1 §4 and draft ADR-0023 derive usable signing and recovery sets while
preserving every signed entry. Exclusion precedes signer-candidate resolution;
no usable candidate is E02, and usable candidates without a valid signature
are E01. An unused excluded key alone does not reject the Declaration.
Identifier uniqueness, cross-set disjointness, predecessor hashes and
recovery-set byte protection still use the original signed entries.
`vectors/wist1/declaration-key-eligibility.json` exercises signed initial,
ordinary, recovery and fresh authentication; unusable named bindings, unused
excluded entries, empty usable sets, identifier reuse, and protected recovery
entries. The reference verifies signatures under the §4 profile and derives
key eligibility with the curve arithmetic anchored by the strictness corpus.
Conditional signed appeal probes use supplied eligible notices and selected
Declaration sources to distinguish an excluded identifier (WIST4-E05) from
a usable key with an invalid signature (WIST1-E01), including a future
`valid_from` signing entry. They do not establish notice evidence, temporal
authority selection or accepted appeal processes.
Adoption in services, authenticated Delta history, frozen appeal authority
and durable restoration remains required. These fixtures assume ordinary
valid fields and canonical base64url; they do not establish full field or
encoding eligibility.

WIST-1 §2 and [ADR-0025](decisions/0025-canonical-base64url.md) require
canonical unpadded base64url in every protocol field using that encoding.
Malformed encodings are underlying `WIST1-E14` failures before cryptographic
use; existing object dispositions and transport wrappers remain applicable.
`vectors/wist1/base64url.json` exhausts final-character choices for public
keys, signatures and three salt lengths, with alphabet, type and length
failures. Signed Declaration cases distinguish encoding rejection from
public-key alias/disjointness checks and excluded-point derivation. Signed
signature aliases decode to valid signatures but still reject; canonical
Block twins distinguish field validation from conflict comparison and
idempotence, including rollback of due recovery settlement and another
domain's transition. The reference checks bits independently of decoder
library policy and checks schema agreement, immutable signed input and
Block authentication. The key-eligibility reference now uses this canonical
decoder. Full field formats, role admission/replay/sealing/restoration,
frozen appeal authority and transport-wrapper integration remain required.
These vectors do not establish those operational obligations.

The `publisher.schema.json` `wist-canonical-host` and `date-time` formats require checks
beyond typed JSON deserialization. Optional fields present as `null`, empty
signing arrays, string bounds and §4's safe-integer bound also need validation.
Declaration idempotence exempts re-verifying a signature, not the requirement
for a structurally valid Envelope. The Declaration field and host checkers in `tools/validate_examples.py` enable
the documented format subsets. Other Declaration schema checks do not enable
format assertions; their passing results establish neither complete host
nor date-time format conformance.

### Unresolved field profiles and recovery binding diagnostics

WIST-1 §§2 and 5.1 and draft ADR-0014 require signed Declaration `domain`
and every `subdomain_scope` member to equal its own Canonical Host. The
`wist-canonical-host` format preserves the pinned UTS #46 profile, including
positional hyphens and A-label eligibility; it rejects alternate signed
spellings before grouping or idempotence. Feed/status Publisher domains,
Publisher-domain Snapshot fields and Publisher Registry subjects use the same
representation. Auditor/Observer admission restrictions remain separate.
`vectors/wist1/declaration-hosts.json` supplies 40 host spellings, 80 signed
Declaration probes and 92 authenticated candidate Blocks, covering identity
conflicts, alternate spellings, immutable signatures and whole-state
rejection through due recovery settlement. Shared schema-field probes cover
the Publisher reference surfaces without asserting object/process eligibility.

The Python reference independently checks ASCII spelling/length and Punycode
round trips, with explicitly enumerated decoded eligibility for the fixture
corpus (`bücher`, `faß`, `ασ`, and rejected control, joiner and bidi labels).
Unknown decoded A-labels stop that checker; it does not implement the complete
Unicode 16.0 mapping/validation algorithm or recompute every input's
canonical output. Independent UTS #46 vector consumption, live field
validation, discovery, admission, sealing and restoration remain required.
These vectors do not resolve full RFC 3339 eligibility or Snapshot recovery.

**Single-label eligibility remains unresolved.** Canonical Host and
Declaration representation impose no two-label minimum, but WIST-4 §5.1
permits a canary planter to be any domain holding a Declaration while
rationing by its two-label suffix; the canary subject schemas require two
labels. That existing minimum is retained while correcting the signed host
representation. Define single-label canary eligibility and any applicable
suffix handling with discriminating vectors before claiming canary admission
conformance. WIST-4 §9's claim that `https://a.b/` is the shortest Normalized
URL also needs reconciliation with §2's acceptance of single-label hosts.
No new suffix policy or global host restriction is selected here.

**Host-field diagnostics outside Declarations remain unresolved.** WIST-2
§7 assigns schema failure to WIST2-E01 (backoff, no noise), while §4 and
WIST2-E04 require a Feed domain differing from the fetched host to be
discarded as noise. A signed `EXAMPLE.com` Feed fetched for `example.com`
now violates both conditions. Define their precedence, including malformed
domain types and other simultaneous field failures, with signed pull vectors
before live Feed format adoption. Field-only host probes select no diagnostic.

Likewise, WIST-4 §10's WIST4-E04 covers `details`/`evidence` contracts,
WIST4-E03 signatures, and WIST4-E05 process/evidence failures. None assigns a
general malformed Publisher `subject` diagnostic. WIST-1 §5.1's host-field
WIST1-E14 applies to Declarations; it does not extend that code to governance.
Define the subject-field diagnostic and precedence relative to unavailable
process authority and signature failure, preserving the applicable ignored-act
disposition, with signed Registry Update cases before authenticated governance
admission/replay. Schema-field checks do not establish this result.

RFC 3339 field eligibility also needs a deterministic leap-event policy.
WIST-1 §§3.4 and 5.1 retain RFC 3339; its
[§5.7](https://www.rfc-editor.org/rfc/rfc3339.html#section-5.7)
permits second 60 only at actual insertions, adjusted for the numeric offset,
and excludes second 59 at a negative leap. The suite specifies no event-data
authority/version or future-announcement treatment for `valid_from`.
Ordering a represented leap second does not establish its eligibility.
Resolve that policy with actual and offset-equivalent insertion cases,
wrong-day and wrong-minute rejections, future-date handling and applicable
negative-leap boundaries. No event table or narrower timestamp profile is
selected here.

WIST-1 §5.2 recovery admission requires verification under either the
pre-recovery or window-owner signing Key Set. Complete bindings must remain
available when the sets reuse an identifier; selecting only the first
identifier match or replacing the owner with an in-window descendant does
not satisfy that acceptance rule. The rejection diagnostic remains unspecified
when usable named bindings fail different `valid_from` and signature checks.
Resolve the mixed-failure WIST1-E01/WIST1-E02 result with signed union probes
before selecting a diagnostic. Separately, WIST-2 §3.2 sealed-Page verification
must retain the selected Declaration's key provenance: gathering every
historical binding with its identifiers can authenticate against the wrong
Declaration. Validation must distinguish reused identifiers and excluded
bindings without broadening the permitted source Key Set.

### Authenticated recovery state

WIST-1 §5.2 and WIST-4 §9 freeze each recovery window’s length at its
owner Block’s in-force parameter map. `recovery_window_cases` in
`vectors/wist4/parameter-combinations.json` exercises exact effective-time
and settlement boundaries, later shortening/lengthening, in-window followers,
new windows and exact arithmetic beyond signed 64-bit seconds. Accepted
amendments and eligible recovery events are supplied inputs; integrated
replay must derive them from authenticated history before applying the rule.

WIST-1 §5.2 and WIST-3 §3.3 select recovery ownership in ascending
`(Block height, seq)` order. `vectors/wist1/recovery-order.json` exercises
signed Declarations and predecessor links in authenticated Block chains,
including reversed leaf-hash order. WIST-1 §5.2 separately retains the highest
accepted sequence through settlement and defines eligible predecessor heads.
`vectors/wist1/recovery-heads.json` authenticates a complete hourly Block chain
and probes ordinary/recovery followers across competitors, stale predecessor
rejection, named-predecessor classification, the deadline transition and
idempotent re-serving of the restored lower-sequence head. Its reference
validates Declaration authorship separately from Block inclusion. It asserts
no identity-reset or conflicting-batch result.

WIST-1 §5.2 and WIST-3 §3.3 reject conflicting equal-sequence Declaration
groups as an entire Block under `WIST1-E08`, preserving the accepted prefix
and state. Only already-current publisher re-serves or identical first-install
Envelopes are nonconflicting; differing signatures cannot choose a new
Declaration's ordinary/recovery authority by leaf order.
`vectors/wist1/declaration-conflicts.json` exercises signed sibling and
signature conflicts, initial and open-window cases, idempotence, independent
domains and atomic rejection. Service admission and replay must adopt these
rules; a Block signature alone does not establish Declaration admissibility.

WIST-4 §6.3 preserves the recovery owner's identity from its application
onward. In-window fresh competitors cause no reset or sanction lift in any
prefix; settlement does not restore opening values or reverse ordinary
process effects. A fresh predecessor earlier in the owner's Block resets
normally, as does a valid fresh replacement after settlement unless a new
window has opened. `vectors/wist4/recovery-identity.json` authenticates two
hourly Declaration histories with reversed owner/competitor storage order
and deadline probes. Its separate abstract projections exercise identity
scope for age, credit, penalties, findings, rungs and notice targets with
already-eligible inputs. They do not authenticate or establish eligibility
of Audit Records, notices, lifts or appeals, or Snapshot resume conformance.

`vectors/wist1/recovery-settlement.json` authenticates seven 170-Block hourly
histories through the settlement boundary, with admissible fresh competitors,
ordinary descendants and legitimate ordinary/recovery followers. Signed
rejection twins enforce recovery-key protection, predecessor eligibility and
Declaration authorship. A shared key naming a competitor cannot advance the
recovery chain. Signed Delta inputs exercise admission under the frozen union
and signature-eligible settlement survivors; separate binding probes cover
identifier reuse, aliases, `valid_from`, bad signatures and later re-serving
of a rejected ID. These replace inadmissible abstract recovery-set rotations.
The histories do not establish durable queuing, Payload availability, quotas,
actual survivor inclusion, status reporting or complete historical Delta
verification. Its timestamp comparisons exercise whole-second literal-Z
fixtures only; full RFC 3339 `observed_at` and `valid_from` validation, including
fractional-second ordering, remains required. Those remain integrated
validation obligations.

WIST-3 §7's Snapshot `declaration` tuple carries only the current Envelope
and sealing height, and `recovery_window` carries only owner height and end.
These do not supply the retained accepted sequence floor after restoration
of a lower-sequence head, or both open-window heads. Define sufficient
Snapshot state or required authenticated history reconstruction, with
Snapshot-versus-full-history vectors, before Snapshot recovery replay can
establish conformance. The full-history head vectors do not resolve this
Snapshot representation question.

WIST-4 §7 freezes each sanction notice's appeal Key Set after due settlement
and its Block's complete Declaration stage. An open window selects the
recovery-chain head; otherwise the current Declaration supplies the keys.
Later history cannot rewrite the notice's authority. Signing identifiers
retain their frozen public-key bindings; recovery entries and the Delta
admission union supply no authority. Appeals have no `valid_from` time filter.
`vectors/wist4/recovery-appeals.json` authenticates two 172-Block hourly
Declaration/notice histories, including reversed Declaration sequence/leaf order
and notice leaf hashes that cannot override canonical type grouping,
fresh competitors, a follower with future-dated signing aliases, deadline
rotation, a new recovery window and later identity reset. Independent signed
appeal probes distinguish missing authority from bad signatures and preserve
notice bindings across prefixes and repeated notice inclusion. Signed Block
twins detect invalid author signatures: an invalid Declaration rejects its
Block, while an invalid notice supplies no authority. A signed ordering twin
rejects a Registry Update stored before the Declaration group.

The appeal vectors condition key selection on separately supplied eligible
notice IDs. Their notice evidence and activation identifiers are abstract
inputs, not authenticated findings; Block inclusion and notice authorship
alone do not establish §7 notice eligibility. The unsealed appeal probes
establish signature authority only. Integrated validation must derive notice
eligibility, reject invalid appeals before slot allocation, preserve frozen
bindings on restart, and exercise live publication, sealing, deadlines,
rulings and retention. No Snapshot resume behavior is established.

## Validation still required

The vector-family inventory in `tools/VERIFICATION.md` distinguishes
independent anchors from self-consistency. The following acceptance evidence
must also be supplied before stable publication; isolated signature or
arithmetic checks do not establish live-service behavior.

| Surface | Required evidence |
|---|---|
| WIST-1 §4 canonicalization | Correctly rounded binary64 edge cases, fractional JSON values in signed objects and rejection outside the finite range |
| WIST-1 §5.2 Declaration key binding | Initial admission, replacement and historical replay consume `declaration-binding.json`; duplicate identifiers reject and reused identifiers or aliases preserve the authenticated public key's correct identity/recovery class |
| WIST-1 §5.2 recovery ownership and heads | Replay consumes `recovery-order.json`, `recovery-heads.json` and `declaration-conflicts.json`, authenticating each Declaration against its eligible named predecessor, retaining the accepted sequence floor and settling before deadline-Block Declarations. Reject conflicting groups and failed Declaration acceptance atomically; canonical storage order cannot choose a winner or replace a recovery owner. Snapshot state requires the resolution listed above. |
| WIST-1 §5.2 recovery settlement | Consume `recovery-settlement.json`, authenticating Declaration acceptance separately from Block inclusion and verifying full Delta key bindings. Preserve the fixed admission union, named recovery chain, original queue order and WIST1-E13 status effects. Demonstrate durable queue recovery, applicable quotas, Payload availability and actual survivor sealing; signature eligibility alone does not establish these duties. |
| WIST-4 §6.3 recovery identity | Consume `recovery-identity.json`; integrate its reset boundaries with authenticated Delta/Audit Record history, candidate-Block parameter profiles, notice evidence and due process. Recovery preserves identity without freezing state or retroactively altering earlier prefixes. Abstract projection inputs do not establish these integrated obligations. |
| WIST-4 §7 appeal authority | Consume `recovery-appeals.json` with independently established notice eligibility. Preserve notice-era signing bindings across recovery, rotations, resets, repeated notice inclusion and restart; apply signature eligibility before appeal-slot allocation and process replay. Exercise live appeal publication/sealing, deadlines and resulting retention with authenticated finding histories. |
| WIST-2 §§3–5, 7 Feed pulls | Domain mismatch and unusable-Feed classification; Declaration refresh before counting signature failure; seen-ID bookkeeping; Page creation/sealing timestamps |
| WIST-2 §7 and WIST-4 §6.4 quotas | Error-code accounting, `WIST2-E05` exclusion, UTC-day parameter/reputation anchor and live quota application |
| WIST-2 §§6, 8 scheduling and redirects | Hints change audit timing without creating a selection duty; redirect termination and authority restrictions under live pulls |
| WIST-3 §§5–6 publication | Durable Block publication before its Checkpoint; Payload replication before the Block; acquisition of cited evidence before serving a notice |
| WIST-3 §§3.1, 6 transport parsing | Independent decoding of the Block-frame vectors and general compressed/checksummed frames; rejection of extra frames, skippable data and trailing bytes; leap-second rejection in all Log-comparable timestamp fields and Snapshot tuples; the full four-digit Gregorian year range, including late December 9999 independently of library timestamp limits. The raw-frame reference in `tools/block_frames.py` does not implement entropy decoding or checksum verification. |
| WIST-3 §§3.4, 5 Log key succession | A rotated Aggregator key authenticates Blocks and Checkpoints at the correct height, including rejected keys |
| WIST-4 §§4–5 audit execution | Small-order VRF key rejection; actual fetch byte, time and redirect limits; reference/observed failures; WARC capture and required evidence retention |
| WIST-4 §6.4 inclusion | Acceptance and per-domain turn accounting under backlog, overload and recovery; the Log alone does not reveal acceptance time |
| WIST-4 §§3.1, 5.1–5.2, 7 integration | Observer and canary publication, authenticated admission evidence, accepted notice service and complete appeal processes across the four roles |

These are validation requirements, not assertions that every boundary lacks
unit coverage. Current vectors already exercise, among other cases,
normalization, key-set selection, late appeals and notice activation targets.
Provide an exact specification commit and the exercised obligations when
claiming that any row is satisfied.

## Object-version policy

WIST-1 §3.1 prohibits new fields in a minor object version. Draft changes
include required Audit Record fields and additional Registry Update actions
while objects still carry `wist_version = 1.0.0`. Before final consolidation
or an adopted wire-format change, determine explicitly whether successive
drafts define one unreleased object version or require a new major object
version. Align document labels and signed objects with that decision and
add discriminating vectors. The draft publication policy itself changes
neither object acceptance nor version semantics.
