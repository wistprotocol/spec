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

The resolver also depends on the interpreter preserving an explicit empty
query. On Python 3.13, resolving `https://example.org/?` against itself drops
`?`, failing `vectors/wist1/payload-links.json`'s existing `empty query` case;
Python 3.14 preserves it. Correct resolution independently of that library
difference and verify the existing case on both versions.

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

**Feed field diagnostics** follow WIST-2 §5 and
[ADR-0032](decisions/0032-feed-field-diagnostics.md). Signed
`vectors/wist2/feed-fields.json` probes exercise complete schema/format
validation, release spelling, exact Log timestamps and field/domain/signature
precedence. The reference checks supplied dispositions independently of the
generator. Live transport, Page publication/partitioning, Feed regression
state, supported-major policy and durable selected-source provenance require
separate validation.

**Feed regression state** follows WIST-2 §3.2 and
[ADR-0033](decisions/0033-feed-regression-state.md).
`vectors/wist2/feed-regression.json` supplies 21 signed observations covering
equality, rejection precedence, unauthenticated-baseline exclusion and the full
timestamp range. The independent reference derives their per-host maximum;
the empty Feeds do not establish Page retrieval or Delta admission. Durable
comparison, restart, later failures, Page isolation and preservation through
Declaration changes require integration validation. A restored backup must
retain the observations needed for the claimed rollback protection.

**Feed and Page `next` targets.** WIST-2 §3.2's target rule and
`vectors/wist2/feed-next.json` fix when `next` is read and which spellings
are fetched. The reference derives each case's disposition from the
supplied schema, domain, signature, live-regression and seen-set inputs,
normalizes the target with `tools/link_extraction.py` and requires
byte-identity plus the requested host's well-known prefix. It fetches
nothing: that an invalid target is never requested, that a query survives
retrieval and that the fetched Deltas are admitted after a stopped walk
require live tests against a serving Publisher.

**Publisher-signed Registry subjects.** WIST-4 §9.1 and draft
[ADR-0036](decisions/0036-registry-update-eligibility.md) assign a `subject`
outside its action's contract shape WIST4-E04, other field failures
WIST4-E11, and place both before authenticity and process diagnostics; an
act whose `subject` selects no Key Set or notice-era authority fails
authentication (WIST4-E11, or the code §7 names for an `appeal`). Only
roster acts are exercised by `vectors/wist4/roster-acts.json`. Signed
`canary_commitment`, `canary_reveal`, `payload_withdrawal` and process
cases must still show the schema's Canonical Host format, Key Set
selection at the sealing Block and the E04/E11/E05 precedence before
authenticated governance admission/replay of those acts.

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

**Resolved Page alias fallback — WIST-2 §3.2 and draft ADR-0023.**
`vectors/wist2/page-bindings.json` supplies 16 signed probes over three
ordinary Declaration chains. The independent reference authenticates those
chains and exercises renamed aliases, reused identifiers, excluded entries,
exact cutoffs, first contact, forbidden later sources and absence of a
following Declaration. Signature-invalid twins and reversed source order
check rejection and ordering independence; future `valid_from` values
distinguish Page verification from Delta filtering. Sealing positions are
supplied inputs, not authenticated Block evidence. Empty Delta lists isolate
key/source selection and establish no Page-size or publication conformance.
Full role validation still requires authenticated inclusion and recovery
supersession, live refresh, durable source provenance and immutable Page
publication.

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
addition at the clock selected by WIST-1 §3.4.

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

## Declaration refresh boundaries

WIST-1 §5.1, WIST-2 §5 and draft ADR-0031 define live Delta E01/E02
refresh, per-requested-ID attempts within a pull and Declaration discovery's
exclusion from the content budget. `vectors/wist2/declaration-refresh.json`
carries 30 signed transport sequences. The reference independently checks
signatures, fields, ordinary replacement authority, retry counts, predecessor
ordering and content-budget suspension using supplied responses. It includes
revalidation of an ID after another candidate changes authority. Eleven Page
cases exercise the shared Feed/Page attempt, unsealed-source exclusion,
current/first-next selection, unsuccessful responses, independent Delta retries
and the exact content-budget boundary. Supplied Declaration sealing positions
hold the Page source prefix fixed; they do not establish Block inclusion.

These vectors do not establish complete HTTP ingestion, authenticated Page
source reconstruction, complete Page fields/publication, recovery settlement,
cache expiry, resumption, durable admission or bounded fetch/work. Integrated
implementations must exercise those obligations; excluding discovery from the content budget does not bound
Declaration response sizes or total discovery traffic.

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

### Delta size-cap parameter time

WIST-1 §3.6, WIST-4 §9 and ADR-0020 fix admission-attempt, sealing and
historical cap profiles. `vectors/wist1/delta-cap-time.json` supplies 509
signed hourly Blocks, 24 signed content-bearing Deltas with complete
Payloads, one attestation, 264 stage probes, two reference-Payload probes
and six invalid signed candidate Blocks. The reference verifies Block
chaining, ordering, signatures, roots and pinned heads; it derives profiles
from signed amendments and recomputes IDs, commitments and JCS sizes.
Separate Delta-only and retrieved-Payload results distinguish all five caps
and the derived bound at exact limits and one octet above, across reductions
and increases, delayed retrieval and reconstruction after restart.

The fixture checks amendment signatures, grace and the affected size
combinations; it does not establish complete governance acceptance.
Restart probes reconstruct supplied inputs in memory, not durable state.
Integrated roles must independently consume these vectors and enforce
attempt-profile retention, candidate-Block rechecks, historical inclusion
profiles and reference-Payload provenance. Live queue rejection and
successor handling, HTTP retrieval, crash recovery, cross-Log validation
and complete audit behavior remain unexercised. Supplied-cap field vectors
alone establish no temporal adoption.

## Payload link validation

`vectors/wist1/payload-links.json` isolates WIST-1 §3.6's WIST1-E12
checks in 31 signed, correctly committed candidates. It covers duplicates,
exact URL normalization, internal hosts, count bounds, ports, query identity
and permitted incomplete prefixes. The reference verifies signatures and
commitments independently; its normalization coverage retains the URL
resolution limits above. These cases do not establish live admission,
source retrieval, sealing, restart, full Payload fields or the correctness
of a declared prefix against the page. Role adoption and those obligations
remain required.

## Payload field and version eligibility

WIST-1 §§3.1/3.6/7, WIST-3 §6.1 and draft ADR-0030/0034 define complete
Payload fields, version support and field-before-semantic diagnostics.
`vectors/wist1/payload-fields.json` supplies independently signed Delta
commitments, explicit preimages, Payload mutations and size-cap contexts.
The reference checks complete fields, unbounded release components,
optional nulls, numeric-value safe integers, scalar boundaries, cap overrides
and E04/E10/E12/E15 combinations after E14 precedence. Raw Payload probes
exercise RFC 8785 §§3.1/3.2.2's E05 rejection of duplicate decoded member
names, lone surrogates and invalid/nonfinite numbers before field checks.
They include escaped-name and nested-duplicate cases. Other objects' raw
input boundaries still require duplicate-rejection validation; ordinary
JSON object parsing can discard that evidence before JCS or schema checks.

Supplied profiles do not establish accepted parameter schedules, retrieval,
sealing, historical reference selection, restart or page agreement. Each role
must adopt these rules independently; typed deserialization alone is
insufficient, and accepted Payload distribution must preserve original bytes.

## Historical Delta clock parameter time

WIST-1 §3.4, WIST-4 §9 and draft ADR-0020 select the committing Block's
`sealed_at` for both the historical clock and `clock_skew_seconds` anchor.
Unsealed attempts freeze their clock and accepted schedule; sealing rechecks
against the candidate Block. Later clocks or amendments cannot repair an
invalid inclusion or invalidate an earlier valid one.

`vectors/wist1/delta-clock-time.json` supplies signed Deltas and parameter
candidates with explicit inclusion contexts. Its independent reference checks
signatures, amendment eligibility for this unbounded parameter, exact rational
clock comparisons, amendment endpoints, frozen attempts and alternate anchors.
These supplied contexts establish no Block inclusion, complete Declaration or
Delta eligibility, live queue behavior or restart conformance. Each role must
bind the check to authenticated history and exercise sealing and replay.

## Mirror-list signing-key time

WIST-3 §5 defines a signed `mirrors` Envelope but makes `updated_at`
descriptive and "compared to nothing". Its list names no Block height,
while §3.4 defines Log-key validity at a height. Resolve which key state
authenticates the list across additions/removals and how stale lists are
handled, with signed rotation vectors before claiming authenticated
Mirror-list adoption. No time anchor is selected here. WIST-3 §6.1 permits
Payload retrieval from any source; using list entries as unauthenticated
location hints establishes no list authorship, Log membership or source
independence.

## Registry Update eligibility and roster replay timing

WIST-4 §9.1 and draft [ADR-0036](decisions/0036-registry-update-eligibility.md)
define the Registry Update gate: raw JSON eligibility, schema-partitioned
field diagnostics (WIST4-E11 general, WIST4-E04 contract), version support
and authenticity under each action's signing rule, in that precedence, with
rejected acts excluded from §3.1's batch. WIST-4 §§3, 3.1 and draft
[ADR-0037](decisions/0037-roster-replay-inputs.md) fix checkpoint `head`
checks to spelling, read a checkpoint's key after its Block's batch, read an
admission's Observer history and citable checkpoints below its Block, and
admit an unusable `public_key` as a string that fails every verification.
`vectors/wist4/roster-acts.json` supplies 70 signed histories;
`tools/validate_examples.py` independently derives the E11/E04 partition from
the schema, verifies signatures, replays the batch and flips each ruled-out
reading.

The histories are unsigned Block contexts sealed by the consumer. They
establish no live pulling, Declaration verification before sealing,
scoreboard derivation, epoch budgeting, Publisher-signed acts, durable
restoration or Record standing beyond the one small-order probe. Integrated
roles must apply the gate before sealing and in replay, and must seal the
same histories under their own Log keys to reproduce every outcome.

## Audit verdict parameter profiles

WIST-4 §5 fixes extraction and both verdict dimensions at the audited
Delta's Block. `vectors/wist4/link-agreement.json` supplies accepted amendment
contexts with increases, decreases, inclusive effectiveness, threshold endpoints,
reference changes and later query instants. The independent reference recomputes
profiles and verdicts and checks that alternative time anchors change results.
These contexts establish no amendment signatures, complete Record eligibility,
retrieval, withdrawal, live audit behavior or durable restoration. Integrated
roles must reconstruct accepted schedules and preserve the audited profile
through reference changes and restart. No schema field changes are required.

## Audit Record field and version dispositions

WIST-4 §10.1 and draft ADR-0035 define complete field diagnostics, version
support and conditional coverage discharge. `vectors/wist4/record-fields.json`
supplies signed original-JSON mutations and explicit standing contexts;
`tools/validate_examples.py` independently derives schema field categories,
verifies signatures and checks version/discharge combinations. Raw JSON
eligibility includes decoded duplicate names, nested objects, trailing input
and non-JCS values. No schema-valid version bypasses the pinned revision.

Integrated roles must independently consume these cases and reconstruct the
roster, signing bindings, ordinary/extension duty, reference history and
coverage carve-outs from authenticated Log prefixes. The supplied contexts
establish none of those histories, live pulling/sealing, reputation exclusion
or durable restoration. A rejected evidence field alone never establishes
coverage discharge; full replay must establish every §10.1 premise while
preserving §4's sealing obligations and the original signed bytes.

## Extension evidence eligibility

WIST-4 §4 (**Only evidence counts**) and draft ADR-0019 make the extension
trigger, the earlier-filing lookback, the already-sealed filer set and both
contradiction quorums read only Records that §3 and §10.1 do not reject.
`vectors/wist4/extension.json` `evidence_cases` supply signed Records in Log
order with per-Auditor keys; `tools/validate_examples.py` derives each
rejection from the signed bytes (structure, signature and key binding,
version support, evidence fields and §5 score bands) plus supplied standing,
removal and coverage-failure contexts, then recomputes eligibility, ration,
summoned sets and contradiction outcomes over the surviving evidence. Its
twin recomputes every case under the reading that counts every sealed filing
and requires the two to disagree.

The supplied contexts establish no VRF or extension standing, roster,
`fetched_at` interval, reference chain or coverage-failure state; an
integrated role must derive each of those from its authenticated prefix
before applying this rule. The vector reads the default band thresholds and
`extension_triggers_max` at B₁ without a parameter amendment; amendment
replay is exercised by `parameter-in-force.json` and `link-agreement.json`.

## Attestation eligibility and coverage derivation inputs

WIST-4 §4 (**Attestation eligibility**, **What the sealed prefix decides**),
§7's identity-scoped rung rule and draft ADR-0018/0019 fix the diagnostics
of pull and coverage attestations and of `sanction_lift`, which sealed items
reveal a draw, when a Block's own discharges are read, which successors
contradict an attestation, and which findings arm a fresh identity's rungs.
`vectors/wist4/coverage.json` `attestation_cases` and
`vectors/wist4/sanctions.json` `lift_cases` carry signed Envelopes that
`tools/validate_examples.py` checks through the §9.1 schema partition,
Ed25519 and ECVRF under supplied contexts; `derivation_cases`,
`same_block_case` and `identity_scope_cases` are prose-traced semantic
cases with twins for the ruled-out readings.

The supplied contexts establish no sealed Block, roster tenure, duty set,
selection or finding; an integrated role derives each from its
authenticated prefix. No case exercises live pulling, the extension-deadline
pull, level-3/4 notice processes or the `auditor_remove` a coverage failure
requires.

## Sanction records, state tuples and enforcement instants

WIST-4 §6.1 counts every sealed Delta of the identity for age, §7 records an
unnoticed `sanction` and treats a cited Record as available once sealed,
§7's enforcement-instant sentence and WIST-3 §7's `sanction_state` row fix
what an Aggregator enforces between Blocks and what the tuple carries under
derived rungs, and §4 fixes a coverage-failure removal's evidence.
`vectors/wist4/derivation.json` (excluded first Delta), `sanctions.json`
(`primary` additions, `instant_cases`) and `coverage.json` (`removal_cases`)
carry the discriminating cases; `tools/validate_examples.py` recomputes each
with a twin for the ruled-out reading and verifies the signed removal.

The tuple change alters no schema arity or member type; a Consumer that read
Registry Update IDs from the member reads Audit Record IDs now, which an
implementation following the earlier row would report as an unknown ID.
Live enforcement between Blocks, Snapshot production and the removal's
sealing remain integrated-role obligations the vectors do not exercise.
