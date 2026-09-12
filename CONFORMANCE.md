# Conformance validation

Known reference divergences and outstanding validation requirements follow.
Resolution and publication criteria: [PUBLICATION.md](PUBLICATION.md).
Vector anchors and exercised cases: [tools/VERIFICATION.md](tools/VERIFICATION.md).

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

Field validation and diagnostic precedence are defined by WIST-1 §§3.4,
5.1 and 7 and [ADR-0024](decisions/0024-declaration-field-diagnostics.md).
`declaration-fields.json` covers signed field mutations and atomic Block
rejection. Admission, historical replay, sealing and durable restoration
must adopt those checks. The reference's structural, ASCII-host and Publisher
timestamp checks do not establish complete hostname, Delta chain/clock,
key-eligibility or live-service conformance.

Usable-key derivation and original-entry protections are defined by WIST-1
§4 and [ADR-0023](decisions/0023-declaration-key-binding.md).
`declaration-key-eligibility.json` anchors curve checks to the strictness
corpus but assumes valid ordinary fields and canonical base64url. Conditional
appeal probes supply eligible notices and selected Declaration sources;
they distinguish excluded-identifier WIST4-E05 from usable-key signature
WIST1-E01, including future `valid_from` entries. They do not establish
notice evidence, temporal authority selection or accepted appeal processes.
Full field/encoding validation, authenticated Delta history, frozen appeal
authority and durable service adoption remain required.

Canonical encoding and its diagnostics are defined by WIST-1 §2 and
[ADR-0025](decisions/0025-canonical-base64url.md). `base64url.json` checks
unused bits independently of decoder policy, schema agreement, signed aliases,
field-before-conflict/idempotence ordering and atomic Block rejection.
The key-eligibility reference uses this decoder. Complete field formats,
role admission/replay/sealing/restoration, frozen appeal authority and
transport-wrapper integration remain unvalidated by this corpus.

The `publisher.schema.json` formats `wist-canonical-host` and
`wist-publisher-timestamp` require checks beyond typed JSON deserialization. Optional fields present as `null`, empty
signing arrays, string bounds and §4's safe-integer bound also need validation.
Declaration idempotence exempts re-verifying a signature, not the requirement
for a structurally valid Envelope. The Declaration field and host checkers in `tools/validate_examples.py` enable
the documented format subsets. Other Declaration schema checks do not enable
format assertions; their passing results establish neither complete host
nor Publisher timestamp format conformance.

Canonical Host backends must remain pinned to Unicode 16.0 even when their
package versions or default data change. `declaration-hosts.json` includes
U+1C89/U+1C8A (assigned in Unicode 16) and U+1E6C0 (disallowed in Unicode 16),
with signed A-label counterparts and authenticated Block rejection. A backend
that admits `xn--uv5h.example` violates WIST-1 §2 despite accepting every
older hostname example. The external anchor is the
[Unicode 16 IDNA Mapping Table](https://www.unicode.org/Public/idna/16.0.0/IdnaMappingTable.txt):
U+1C89 maps to U+1C8A, and U+1E6C0 lies in its disallowed U+1E600–U+1E7DF range.
The reference's fixture-limited checks do not establish exhaustive mapping
agreement; independent role validation must exercise the pinned backend.

### Unresolved field profiles and recovery binding diagnostics

Signed host representation is specified by WIST-1 §§2 and 5.1 and
[ADR-0014](decisions/0014-canonical-host-flag-profile.md), including the
Publisher reference surfaces and separate Auditor/Observer restrictions.
`declaration-hosts.json` exercises signed spelling, identity conflicts and
atomic rejection through recovery settlement. Its shared schema-field probes
do not establish object or process eligibility.

The Python reference independently checks ASCII spelling/length and Punycode
round trips, with explicitly enumerated decoded eligibility for the fixture
corpus (`bücher`, `faß`, `ασ`, U+1C8A, and rejected control, joiner, bidi and
post-Unicode-16 labels).
Unknown decoded A-labels stop that checker; it does not implement the complete
Unicode 16.0 mapping/validation algorithm or recompute every input's
canonical output. Independent UTS #46 vector consumption, live field
validation, discovery, admission, sealing and restoration remain required.
These host vectors do not establish Publisher timestamp validation or
Snapshot recovery.

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

**Publisher timestamp eligibility** follows WIST-1 §3.4 and
[ADR-0026](decisions/0026-publisher-timestamp-profile.md).
`wist-publisher-timestamp` needs Gregorian calendar checks beyond its schema
pattern, including year zero and offset arithmetic outside the written year
range. The specified clock is independent of physical UTC leap events.

`declaration-fields.json` exercises signed field mutations in both key
arrays and Delta `observed_at`, preserved recovery-key protection, exact
inclusive key bounds, isolated signed E06/E07 clock-skew and predecessor
comparison twins, and authenticated whole-Block rejection through due
settlement. Historical insertion labels and their offset equivalents
reject; wrong dates/minutes, future dates, a hypothetical negative-leap
boundary, arbitrary fractions beyond common parser limits and offset/year
boundaries discriminate alternative readings. The reference uses Python's
Gregorian calendar and exact rational arithmetic, independently of the
hard-coded expected cases. The hypothetical event predicts no real leap
announcement. This evidence does not establish live admission, authenticated
Delta chains, live clock acquisition/skew enforcement, recovery-union
diagnostics, sealing or durable restoration. Independent vector consumption and adoption in
every role remain required. An implementation that merely orders `:60`
without rejecting it, rounds fractions, or rejects offset-adjusted values
beyond its calendar range does not conform to this profile.

**Resolved recovery-binding diagnostics — WIST-1 §5.1/§5.2 and draft
ADR-0023.** Queue admission retains the pre-recovery and window-owner
signing sets, including complete reused-identifier/public-key/time bindings.
Filter unusable and future named bindings before signature verification:
none remaining is WIST1-E02; remaining bindings with no verifying signature
is WIST1-E01. A single binding must satisfy both checks. Encoding and
Publisher timestamp errors retain
WIST1-E14 precedence, and settlement retains WIST1-E13. The signed
`recovery-bindings.json` histories and independent reference exercise mixed
failures, exact fractional/offset bounds, exclusions, aliases, reversed
signed arrays and fixed owner sources after a legitimate follower. They
establish source selection and key diagnostics, not full Delta/chain
eligibility, live clock checks, durable queues, Payload availability, quotas,
sealing, settlement or Snapshot restoration. Independent role consumption
and integrated admission/replay/restoration remain required. Selecting only
the first identifier match, merging distinct bounds or substituting a later
Declaration does not conform.

Separately, WIST-2 §3.2 sealed-Page verification
must retain the selected Declaration's key provenance: gathering every
historical binding with its identifiers can authenticate against the wrong
Declaration. Validation must distinguish reused identifiers and excluded
bindings without broadening the permitted source Key Set.
Full validation also requires authenticated applicable Declaration history,
including recovery supersession. Both timestamp lookups read sealed Entries;
an accepted but unsealed Declaration does not establish the first following
Block's Key Set. Verification over supplied key sets alone does not establish
these source-selection obligations or Page publication and immutability.

**Unresolved Page alias fallback — WIST-2 §3.2.** The first-next resolution
applies where current does not hold "the key that signed it". WIST-1 §2
defines a Key Set in terms of public keys, while §4 requires verification
under the entry named by `sig.key_id`. If current contains public bytes A
under identifier `old` and first-next contains A under `new`, a Page naming
`new` distinguishes public-byte membership from named-binding membership.
An implementation using named-binding fallback accepts this case; the
wording does not explicitly select that predicate. Resolve it with signed
alias-renaming vectors and independent verification before claiming full
Page key-history conformance. This does not authorize looking beyond the
current and first-next Declarations or pooling their identifiers with
unrelated historical bindings.

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
fixtures only; integrated §3.4 Publisher timestamp validation for `observed_at`
and `valid_from`, including exact fractional-second ordering, remains an
integrated validation obligation.

WIST-3 §7's Snapshot `declaration` tuple carries only the current Envelope
and sealing height, and `recovery_window` carries only owner height and end.
These do not supply the retained accepted sequence floor after restoration
of a lower-sequence head, or both open-window heads. Define sufficient
Snapshot state or required authenticated history reconstruction, with
Snapshot-versus-full-history vectors, before Snapshot recovery replay can
establish conformance. The full-history head vectors do not resolve this
Snapshot representation question.

Recovery deadline range also needs a Snapshot representation decision.
WIST-1 §5.2 fixes the end as the opening instant plus
`recovery_window_days × 86,400`; `parameter-combinations.json` includes exact
ends beyond signed 64-bit seconds. WIST-3 §3.1 requires four-digit
Log-comparable and Snapshot timestamps, while §7's `recovery_window` tuple
carries that end. Some permitted ends therefore have no timestamp spelling.
Specify a faithful representation or an explicit normative parameter
constraint, with discriminating full-history/Snapshot vectors, before
claiming full-range recovery Snapshot publication. No encoding, clamping or
parameter restriction is selected here. Implementations must retain exact
replay arithmetic; rejection before publication does not establish full-range
serving conformance.

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

## Delta cross-check diagnostics

WIST-1 §7 and [ADR-0027](decisions/0027-delta-diagnostic-selection.md)
require the complete E14 field checks before semantic rejection and permit
any established applicable semantic error afterward. The complete binding
check retains its E02/E01 distinction; choosing one failed semantic check
does not waive retrieval/refresh prerequisites or object/stage dispositions.

`vectors/wist1/delta-diagnostics.json` covers 96 signed candidates: all
combinations of valid/failed/missing/future bindings, in/out-of-scope URLs,
inclusive/excess clock bounds and increasing/non-increasing predecessor
times, with malformed timestamp and noncanonical signature-encoding twins.
The reference authenticates Declaration sources and predecessors and derives
the complete permitted sets for these checks independently of fixture labels.
Prior acceptance, current source selection and validation times are supplied
context, not authenticated Log history. The corpus does not establish full
Delta field validation, other semantic checks, live clock acquisition,
Declaration re-fetches, predecessor retrieval, Payload handling, recovery,
transport wrapping, status accounting or restart. Integrated role validation
must exercise those obligations and consume permitted sets rather than
require one semantic diagnostic order. Publisher attribution is specified separately below.

The isolated clock vectors in `vectors/wist1/declaration-fields.json` and
the diagnostic combinations use the inclusive default 600-second relation.
WIST-4 §9's signed integer parameter `clock_skew_seconds` controls the active
allowance, including negative values; the clock relation uses exact signed
addition at the validator instant.

## Delta Publisher attribution

WIST-1 §3.8 and ADR-0029 require a canonical Publisher domain inside each
signed Delta. It selects the sole Declaration history supplying authority;
copying keys or changing an unsigned identifier cannot change the author.
Chains use `(publisher, url)` across rotations, recovery and fresh identities.
WIST-2 §5 rejects foreign-Publisher Deltas in a Feed/Page with WIST2-E03;
physical redirect and Mirror hosts do not determine this association.

`vectors/wist1/delta-attribution.json` exercises shared and distinct keys,
copied bindings, author tampering, missing/ineligible author sources, literal
nonancestor scope, canonical host fields, Feed association and exact-draft
version acceptance. Its signed hourly Block history authenticates ordinary
rotation, recovery ownership/competition/followers, settlement and fresh reset,
with scoped chain and binding probes. Conditional projections test which
Publisher/current identity can receive credit, penalties and notice evidence;
they do not establish the eligibility of an Audit Record or notice itself.

Required independent role adoption remains: emit and validate the signed
field without synthesizing it into old bytes; select only its authenticated
Declaration/key history; enforce Publisher/URL predecessors and logical Feed
association before idempotence; preserve domain-scoped recovery queues and
chain tips across restart; derive sampling, reference chains, canary ownership,
reputation and sanction evidence from the same author. Update every dependent
ID, signature, Payload path, Block and Snapshot when changing fixture bytes.
Existing signed objects without the field fail this exact draft, even when
they say `1.0.0`. Passing supplied-source or conditional projection tests
establishes neither live discovery nor integrated audit/process conformance.

### Recovery scope authority and remaining materialization questions

WIST-1 §3.2/§5.2 and draft ADR-0015 pair each frozen recovery-admission
Declaration's scope with its complete signing bindings. A candidate cannot
borrow scope across sources. Settlement checks the newest recovery-chain
Declaration before deadline-Block Declarations and drops either binding or
scope failures with E13; actual sealing checks its own applicable Declaration.
Historical scope remains tied to the Delta's sealing height.

`vectors/wist1/recovery-scope.json` authenticates differing-scope Declaration
histories and independently verifies signed stage probes, including same-Block
source selection, repeated keys, exact timestamp bounds, deadline changes,
re-serving and signature-invalid twins. These probes supply validation stages;
they do not prove complete Delta admission, chain/clock eligibility, durable
queue restoration, Payload/quotas, status publication or survivor inclusion.
Independent role implementations must consume the vectors and retain complete
source provenance through admission, settlement, sealing and restart. Existing
signature-only settlement checks do not establish this authority requirement.
No wire fields or schema constraints change.

Source-paired checks alone do not establish source selection. An implementation
that selects the highest sealed sequence without excluding recovery-superseded
competitors violates WIST-1 §5.2, even if each supplied source's binding and
scope are checked correctly. Validation must demonstrate a legitimate survivor
sealing despite a higher-sequence competitor, and distinguish the last follower
sealed inside the window from an accepted but unsealed replacement. Admission
at or after the deadline must settle first and use the resulting current
Declaration. Replay must preserve the accepted sequence floor, allow both
eligible predecessor heads while the window is open, and allow only the
restored current head after settlement. Restoring a sealed head must not
introduce a new first installation.
Dropped queue copies must not permanently suppress their IDs or leave invalid
chain tips: test re-serving after authority changes, including after restart.
Queue validation must also cover Deltas accepted before the recovery opening
but excluded from intermediate Blocks by capacity. They still require recovery
settlement, including E13 rejection and deadline-based inclusion-turn accounting.
Movement between pending and recovery queues must preserve original acceptance
order across both populations; canonical leaf order is only storage order.
Test reversed leaf hashes under a restrictive per-domain capacity at settlement.
Also test a rejected predecessor with otherwise eligible accepted descendants:
none may seal with an unresolved lower predecessor, and removing those copies
must restore the surviving tip without suppressing later re-serving. Upgrading
persistent queues must not invent original acceptance order from row identifiers
that prior transfers may have assigned in leaf order. Demonstrate either
independent order evidence or rejection of ambiguous restoration, preserving
copies and status atomically on failure.
These are requirements of the existing rules, not alternative interpretations.

Admission validation must distinguish an ordinary successor of a competing
Declaration from a recovery follower when both authenticate with the same
public key: only a candidate naming the recovery-chain head may advance it.
Persistent restoration must repair or reject a summary that classified the
former as the latter, using authenticated sealed history and retained pending
admissions. A partial Block must not erase still-pending recovery continuations
from admission state. Test independent sequence-floor persistence through
settlement, current-object idempotence below that floor, malformed re-serves,
and rollback when a head write fails after a floor update.

Capacity validation must also exercise two pending Declarations for one domain
that name different eligible heads. Sealing a higher sequence while retaining
a lower sequence can make the lower candidate permanently ineligible under
WIST-1 §5.2. Predecessor closure alone does not prevent this: a valid subsequent
Block and continued queue progress must be demonstrated after capacity deferral.

WIST-1 §5.2 and draft ADR-0015 resolve the fate of competing Declarations
admitted inside recovery but still unsealed at expiry. Remove those superseded
copies and their non-chain descendants from sealing eligibility while retaining
the admission sequence floor and legitimate pending followers. The exception
to Declaration sealing does not remove already-sealed evidence. A Consumer
cannot infer an unpublished admission time: a removed competitor could otherwise
pass its Log's post-deadline acceptance checks and acquire a new identity effect.
`vectors/wist1/recovery-admission.json` supplies signed Declaration Envelopes
with separately supplied chronological admission events and authenticated hourly
Block histories. It distinguishes
the pending admission head from the sealed queue-settlement source, ordinary
and recovery descendants, legitimate pending followers, a last-second admission,
exact-deadline replacement, repeated settlement and an already-sealed competitor.
Signed alternate Blocks demonstrate why Log validation alone cannot detect the
forbidden revival. A pending recovery-signed follower first sealed after expiry
opens a new window at that sealing instant if none is open. The first such
follower owns the window; later Entries inherit its protection. Supersession
cancels a removed recovery copy's remaining sealing duty without excusing an
already-incurred latency violation.

Independent role consumption and live adoption remain required. Demonstrate
atomic restoration/removal with queue, status, seen-ID and chain-tip effects;
preserve completion of admission settlement across reopen and the first deadline
Block so later accepted replacements are not overwritten or their new Deltas
revalidated as copies from the closed window. Exercise capacity-deferred
Declaration chains and failure/retry before committing a new Block. The signed
traces establish Declaration stages and selected source identity, not full
Delta eligibility, actual E13 processing, inclusion turns, Payload availability,
quotas, Snapshot restoration or authenticated Audit Record eligibility.

WIST-1 §3.2 permits an explicitly listed hostname without an ancestor
restriction. WIST-3 §7's one-URL-one-Publisher rule selects self-declaration
over a scoped parent, but supplies no winner between multiple scoped
Publishers when the URL host has no Declaration of its own, including
nonancestor Publishers. Resolve preference, eligibility or multiplicity with
vectors before complete materialization and dependent audit selection.
Signed authorship and separate chains are already determined; the attribution
vectors choose no materialization winner for these cases.

## Validation still required

The vector-family inventory in `tools/VERIFICATION.md` distinguishes
independent anchors from self-consistency. The following acceptance evidence
must also be supplied before stable publication; isolated signature or
arithmetic checks do not establish live-service behavior.

| Surface | Required evidence |
|---|---|
| WIST-1 §4 canonicalization | Correctly rounded binary64 edge cases, fractional JSON values in signed objects and rejection outside the finite range |
| WIST-1 §5.2 Declaration key binding | Initial admission, replacement and historical replay consume `declaration-binding.json`; duplicate identifiers reject and reused identifiers or aliases preserve the authenticated public key's correct identity/recovery class |
| WIST-1 §5.1/§5.2 Delta recovery bindings | Consume `recovery-bindings.json` with independent signature and timestamp implementations. Preserve frozen source provenance and complete bindings in admission, authenticated replay and durable restoration; distinguish E14 fields, E02 absence of eligible authority and E01 failed signatures without borrowing the union for sealing or historical verification. Exercise complete Delta/chain and live-clock eligibility separately. |
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

WIST-1 §3.1, ADR-0028 and [PUBLICATION.md](PUBLICATION.md) permit incompatible
revisions of the unreleased draft under `wist_version = 1.0.0`. Validators and
compatibility claims must identify an exact specification commit and enforce
its complete field set. The exception ends on stable publication or the first
Log sealing Blocks consumed by a third party, whichever happens first.

The signed version cases in `delta-attribution.json` exercise current fields,
a same-version object lacking its Publisher, unknown fields and an
unimplemented major. Independent role consumption and publication-boundary
verification remain required; an offline vector cannot establish deployment
status or waive the frozen edition's immutability.

## Complete Delta field diagnostics

WIST-1 §§3.7/7 and ADR-0027 define field validation and its semantic
exceptions; WIST-2 §5 preserves those diagnostics during pull.
`vectors/wist1/delta-fields.json` tests 200 signed field/version candidates, scalar-length
and safe-integer boundaries, supplied active caps, signature precedence and
eight Feed/ID association cases. Parameter schedule replay is not asserted.
The reference uses the schema independently of the generator's expected
labels and verifies signatures and IDs. This does not establish complete
Delta admission, authenticated chain replay, live transport/refresh/retrieval,
Payload validation or durable rejection handling; integrated roles must
exercise those obligations and consume the vectors independently.

WIST-1 §§3.1/7 and ADR-0030 resolve Delta version eligibility for every
validator role. Signed cases in `delta-fields.json` exercise E14 precedence,
E15 semantic combinations, unsupported majors, supported minor/patch values
and components exceeding machine-integer ranges. The reference independently
checks schema spelling and derives major eligibility and permitted errors.
Integrated roles must enforce these checks before acceptance, including
fetched predecessors, duplicate handling and restoration. These Delta cases
do not establish version support for other objects or complete chain replay.
