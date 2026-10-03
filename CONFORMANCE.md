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

`normalize_url` and `is_canonical_host` in `tools/collection_rules.py` accept
only ASCII letter-digit-hyphen host labels: a host spelled with U-labels,
which WIST-1 §2 has a Normalized URL, yields none in the reference, and an
`xn--` label is not judged at all. The vectors of Items, Catalogs, Scopes and
declared links therefore carry ASCII hosts only; Canonical Host processing
is exercised by `vectors/wist1/declaration-hosts.json` and
`host-canonicalization.json` through the harness's pinned UTS #46 backend.
An implementation must apply §2's processing to every host, not the
reference's subset.

## Recovery history resolution

### Declaration field and key eligibility

Field validation and diagnostic precedence are defined by WIST-1 §§3.4,
5.1 and 7 and [ADR-0024](decisions/0024-declaration-field-diagnostics.md).
`declaration-fields.json` covers signed field mutations and atomic Epoch
rejection. Admission, historical replay, sealing and durable restoration
must adopt those checks. The reference's structural, ASCII-host and Publisher
timestamp checks do not establish complete hostname, Catalog clock,
key-eligibility or live-service conformance.

Usable-key derivation and original-entry protections are defined by WIST-1
§4 and [ADR-0023](decisions/0023-declaration-key-binding.md).
`declaration-key-eligibility.json` anchors curve checks to the strictness
corpus but assumes valid ordinary fields and canonical base64url. It does
not establish temporal authority selection. Full field/encoding validation,
authenticated Catalog history and durable service adoption remain required.

Canonical encoding and its diagnostics are defined by WIST-1 §2 and
[ADR-0025](decisions/0025-canonical-base64url.md). `base64url.json` checks
unused bits independently of decoder policy, schema agreement, noncanonical key spellings,
field-before-conflict/idempotence ordering and atomic Epoch rejection.
The key-eligibility reference uses this decoder. Complete field formats,
role admission/replay/sealing/restoration and transport-wrapper integration
remain unvalidated by this corpus.

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
with signed A-label counterparts and authenticated Epoch rejection. A backend
that admits `xn--uv5h.example` violates WIST-1 §2 despite accepting every
older hostname example. The external anchor is the
[Unicode 16 IDNA Mapping Table](https://www.unicode.org/Public/idna/16.0.0/IdnaMappingTable.txt):
U+1C89 maps to U+1C8A, and U+1E6C0 lies in its disallowed U+1E600–U+1E7DF range.
The reference's fixture-limited checks do not establish exhaustive mapping
agreement; independent role validation must exercise the pinned backend.

### Unresolved field profiles and recovery binding diagnostics

Signed host representation is specified by WIST-1 §§2 and 5.1 and
[ADR-0014](decisions/0014-canonical-host-flag-profile.md), including the
Publisher reference surfaces.
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

**Single-label hosts.** Canonical Host and Declaration representation
impose no two-label minimum, and WIST-4 §5's `url_cap_bytes` and
`link_url_cap_bytes` rationale names the two-label shortest URL while a
one-label host's shorter URL stays nameable.

**Label Feed field checks** follow WIST-2 §3.2, which orders the schema,
domain and signature checks of a Label Feed or Page and assigns their
failures no code. `vectors/wist2/feed-fields.json` carries 134 signed Label
Feed Envelopes exercising complete schema/format validation, release
spelling, exact Log timestamps and the order of the three checks; each case
names the first check failed and states no code, noise or second
Declaration request. The reference checks supplied dispositions
independently of the generator.
Live transport, Page publication/partitioning, Label Feed regression state,
supported-major policy and durable selected-source provenance require
separate validation.

**Label Feed regression state** follows WIST-2 §3.2 and
[ADR-0033](decisions/0033-feed-regression-state.md).
`vectors/wist2/feed-regression.json` supplies 21 signed observations covering
equality, rejection precedence, unauthenticated-baseline exclusion, the
discard of a regressed Label Feed under `WIST2-E05` and the full timestamp
range. The independent reference derives their per-host maximum; the empty
Label Feeds do not establish Page retrieval or Label admission. Durable
comparison, restart, later failures, Page isolation and preservation through
Declaration changes require integration validation. A restored backup must
retain the observations needed for the claimed rollback protection.

**Label Feed and Page `next` targets.** WIST-2 §3.2's target rule and
`vectors/wist2/feed-next.json` fix when `next` is read and which spellings
are fetched. The reference derives each case's disposition from the
supplied schema, domain, signature, live-regression and seen-set inputs,
normalizes the target with `tools/link_extraction.py` and requires
byte-identity plus the requested host's well-known prefix, and states a
code only where §3.2 assigns one (`WIST2-E01` for a target, `WIST2-E05` for
a regressed live object); an answer 304 to the ingested Label Feed it
validates lists no new ID. It fetches nothing: that an invalid target is never requested,
that a query survives retrieval and that the fetched Labels are admitted
after a stopped walk require live tests against a serving Labeler.

**Undetermined pull behaviors.** WIST-2 does not determine the following,
and an implementation following its text literally may choose either way:

- The code an Aggregator reports for a Label Feed that fails §3.2's
  schema, domain or signature check and for a Page that fails its schema or
  domain check; a Page that verifies under neither source is `WIST2-E04`
  (§3.2, §7). Whether any of these failures, a Page's `WIST2-E04`
  included, counts as Ping noise (§4), and whether it triggers a
  Declaration request beside the one that opens the pull (§5.1). Such an
  implementation rejects the object and may report any code, or none,
  where §3.2 assigns none.
- What an Aggregator records when the live `label-feed.json` cannot be
  fetched: it may report a failure or treat the Labeler as serving no Label
  Feed in that pull.
- When a typed rejection stops being pending at the status endpoint
  (§7.1): an implementation may keep every rejection it ever recorded, or
  drop one at a later clean pull, when the rejected object is replaced, or
  after an age.
- What counts as an object under a per-pull limit in objects (§5.2): §5.3
  makes a change list one object, and nothing says whether an answer 304
  counts, or whether the Declaration, a held tree file or a held Payload
  does. One implementation may count every request it issues, another every
  file it receives, another every file it fetches and does not hold.
  The `vectors/wist2/collection-pull.json` fixture counts each fetched
  `catalog.json`, tree file and Payload as one object and a held file and
  the Declaration as none, which the text states only for a change list.
- What an answer 304 for `label-feed.json` means for an ID previously
  rejected and not yet seen (§3.2, §5.5): §3.2 says an answer 304 lists no
  new ID, while §5.5 pulls a rejected ID again at the next pull. An
  implementation may refetch the Label or dispute of every ID the validated
  Label Feed lists that is not seen, or fetch nothing until the Label Feed
  changes.
- How the height at which a `payload_withdrawal` is sealed maps to the
  instant at which a Publisher must stop serving the Payload (§3.1): the
  Publisher reads no Log and the duty is counted on its clock. An
  implementation may stop at the `sealed_at` of that Epoch in any Log that
  pulls it, at the instant it learns of the withdrawal, or at the first
  Catalog it signs after it.
- What a failed fetch debits other than an object above its own response
  bound (§5.2): a `404` body, a transfer cut short, a refused destination
  and a redirect chain longer than §8 allows. An implementation may debit
  the octets it read or nothing.
- The order of `urls` in the report of a list that drops a record's URL
  (§5.1 step 3, §7.1): an implementation may list them in octet order, in
  record order or in any order.
- Where a pull resumes among Collections after a suspension (§5.2): an
  implementation that restarts from the first Collection the sources name
  may, under a per-pull limit smaller than the first Collections' work,
  never reach a later Collection, while one that resumes at the suspended
  Collection reaches each in turn.

No vector carries §11's rule on which representations are HTML.

**Withdrawal acts.** WIST-4 §5.1 and `vectors/wist4/withdrawal.json` fix
the `payload_withdrawal` contract. The reference checks each act against
the schema and Log key, resolves `delta_id` against the supplied sealed
Items, keeps the earliest accepted withdrawal's height and validates the
resulting WIST-3 §7 `withdrawal`, `record` and `removal` tuples. A
Consumer resumed from a Snapshot judges each act, as WIST-4 §5.1 states,
against a `record` tuple of the subject or of another Publisher, kept
after a walked Entry replaces it, a `withdrawal` tuple of the subject or
of another Publisher, a `removal` tuple, walked Items of another
Publisher or of kind `removed`, or finds the Item nowhere, and a
Consumer resumed again reads only the tuples of its later Snapshot; each
case gives the replaying Consumer's result beside it, and the two differ
only for acts the Aggregator breaks its contract by sealing and for what
follows from such an act in that Log, a later withdrawal of the same
Item reading another earliest height. Signed Checkpoint histories, live withdrawal
sealing, Payload destruction and Snapshot exclusion require integration
validation.

**Registrable domains.** WIST-4 §3.1, WIST-2 §4 and WIST-3 §3.2 key the
Ping quota, the ingest budget and the per-domain Epoch capacity on the
Registrable Domain under a pinned Public Suffix List snapshot, and draft
[ADR-0042](decisions/0042-registrable-domain-accounting.md) records why.
`vectors/wist4/registrable-domain.json` carries two fixture snapshots,
the Public Suffix List project's own `checkPublicSuffix` cases
(`tools/psl_test_cases.txt`, transcribed verbatim) over the first, shared
and private-section hosts, signed `suffix_list_update` acts with their
WIST4-E11/E04 dispositions, the snapshot in force at each height across
an advance, capacity and quota accounting under it and the WIST-3 §7
`suffix_list` tuple. The reference derives every Registrable Domain with
its own implementation of the algorithm and checks it against the
project's answers, which anchors the algorithm outside this repository;
the fixture's rules are copied from the real list, and its labels need
no UTS #46 mapping beyond case folding and Punycode. Serving the
snapshot octets, live quota and budget accounting per Registrable
Domain, capacity rejection in a replaying Consumer and cold-start
adoption of the tuple require integration validation.

**Registry Update eligibility.** WIST-4 §5.1 and draft
[ADR-0036](decisions/0036-registry-update-eligibility.md) assign a `subject`
outside its action's contract shape WIST4-E04, other field failures
WIST4-E11, and place both before authenticity and semantic diagnostics.
The reference derives the E11/E04 partition from the schema: a failure
inside an action's conditional branch is the contract, any other is a
field failure, except two failures of a `parameter_change`: a string
`details.parameter` that names no §5 identifier, with a `subject` that is
the same string, and an integer `details.value` outside its §5 bound,
which WIST-4 §5.1 makes `WIST4-E03` after authentication; a non-string
`parameter` stays `WIST4-E04`; `vectors/wist4/parameter-combinations.json`
gives each wire case its code, with twins for both failures under a
signature that fails (`WIST4-E11`), another `subject` and a non-string
`parameter` (`WIST4-E04`). `payload_withdrawal` and `suffix_list_update` acts are
exercised with signed Envelopes; `aggregator_key_add`,
`aggregator_key_remove` and `parameter_change` acts are exercised
through the schema and the parameter vectors. A repeated Registry Update
ID is exercised as an idempotent occurrence and as one whose Envelope fails
field validation (`WIST4-E11`) in `vectors/wist4/withdrawal.json` and
`vectors/wist3/catalog-sealing.json`; live sealing and durable restoration
need integrated validation.

**Labels.** WIST-2 §3.3 and WIST-4 §6 fix the Label object, the Label
Feed, self-labeling, the registry name form and which Label is current.
`vectors/wist2/labels.json` carries signed Labels over the example
Declaration with field, form, cap, self-labeling, expiry, `delta`-binding
and signature dispositions, the binding check over `keys` alone with a
Collection's key taking no part, current-Label replays with the WIST-3 §7
tuple each leaves at a Snapshot instant, and binding cases against the Item
the subject URL's record carries; the reference recomputes every disposition, the
Label IDs and the tuples, and its twins flip the self-labeling scope,
the registry term set and the tie order. Every case is validated at the
vector's `clock` under its `clock_skew_seconds`, with `asserted_at` at
the inclusive bound in two spellings, a second beyond it and a fraction
beyond it (WIST-1 §3.4's clock rule read over a Label); which clock an
attempt or a sealed Label selects is fixed for Catalogs and Labels alike by
WIST-1 §3.4, which `vectors/wist1/catalog-fields.json` exercises for a
Catalog at a supplied clock. Live Label Feed pulls,
`WIST2-E06` reporting, sealing as `label` Entries under the inclusion
ceiling, `tier1/labels.parquet` and Consumer subscription need
integrated validation.

**Label accountability.** WIST-2 §3.3, WIST-3 §§3.2/7 and WIST-4 §§5/6
add label definitions, disputes, the per-Labeler cap, the recommended
default profile and the labeler statistics (draft
[ADR-0043](decisions/0043-label-accountability.md)).
`vectors/wist2/disputes.json` carries signed disputes over a fixture
disputant Declaration with field, clock-allowance, unsealed-Label,
third-party, signature and binding dispositions and current-dispute
replays with
their tuples; `vectors/wist2/label-definitions.json` carries signed
definitions with their served paths and every treatment;
`vectors/wist3/label-tables.json` carries the labeler statistics rows,
per-Labeler cap cases beside the per-domain cap, and the persistence
and inactivity rules of the recommended profile. The reference
recomputes each. Live dispute pulls, `dispute` Entry sealing, the two
tier-1 tables, Consumer reading of definitions and a profile applying
the treatments need integrated validation.

**Publisher timestamp eligibility** follows WIST-1 §3.4 and
[ADR-0026](decisions/0026-publisher-timestamp-profile.md).
`wist-publisher-timestamp` needs Gregorian calendar checks beyond its schema
pattern, including year zero and offset arithmetic outside the written year
range. The specified clock is independent of physical UTC leap events.

`declaration-fields.json` exercises signed field mutations in both key
arrays, preserved recovery-key protection, exact key windows and
authenticated whole-Epoch rejection through due settlement;
`item-fields.json` exercises `observed_at` spellings and its comparison with
`generated_at` across offsets and fractions of 5 000 digits. Historical insertion labels and their offset equivalents
reject; wrong dates/minutes, future dates, a hypothetical negative-leap
boundary, arbitrary fractions beyond common parser limits and offset/year
boundaries discriminate alternative readings. The reference uses Python's
Gregorian calendar and exact rational arithmetic, independently of the
hard-coded expected cases. The hypothetical event predicts no real leap
announcement. This evidence does not establish live admission, live clock
acquisition/skew enforcement, recovery-source diagnostics, sealing or
durable restoration. Independent vector consumption and adoption in
every role remain required. An implementation that merely orders `:60`
without rejecting it, rounds fractions, or rejects offset-adjusted values
beyond its calendar range does not conform to this profile.

**Resolved recovery-binding diagnostics — WIST-1 §5.1/§5.2 and draft
ADR-0023.** Queue admission retains the pre-recovery and window-owner
Declarations, each read alone with its keys, Collections, Scopes and
complete per-key `nbf`/`exp` bindings. Filter unusable and out-of-window
named bindings before signature verification: none remaining is WIST1-E02;
remaining bindings with no verifying signature is WIST1-E01. A single
binding must satisfy both checks. Encoding and timestamp errors retain
WIST1-E14 precedence, and settlement retains WIST1-E13.
`catalog-fields.json` exercises binding windows at `nbf` and `exp` and keys
of other Collections; `catalog-recovery.json` exercises the two frozen
sources, a shortened key window at settlement and fixed owner sources after
a follower sealed in the owner's Epoch. Validation must also exercise one
key listed by the two sources with different windows, and the `WIST1-E03`
of a Catalog verifying only under a source that does not name its
Collection. These establish source selection and key diagnostics, not live clock
checks, durable queues, Payload availability, quotas, sealing or Snapshot
restoration. Independent role consumption and integrated
admission/replay/restoration remain required. Selecting only the first
identifier match, merging distinct windows or substituting a later
Declaration does not conform.

**Resolved key directory, commitment and activation — WIST-1 §5.1/§5.2
and draft ADR-0045.** A Declaration key entry is an Ed25519 JWK whose `kid`
is its RFC 7638 thumbprint, so an identifier names one key and a key one
identifier; a `kid` that is not that thumbprint, or an `exp` not greater
than `nbf`, is WIST1-E14 and is checked before the WIST1-E08 uniqueness
rule. A signing binding admits a Catalog whose `generated_at` satisfies
`nbf` ≤ `generated_at` < `exp`, comparing the instant with the
NumericDate integers; Declaration signer resolution and classification
ignore the window, so an expired or not-yet-started entry still rotates.
Under a predecessor's `next_keys`, an ordinary rotation either keeps that
signing set and commitment or installs exactly the committed set. A fresh
identity accepted outside a recovery window is pending: it supplies no
authority, resets identity only at its activation height, and is discarded
by a replacement of the current Declaration sealed before that height.
`vectors/wist1/key-directory.json` carries the thumbprint known answer,
entry field cases, window boundaries, satisfied and unsatisfied
commitments, and authenticated histories for a delayed activation, a
signing-key reversal, a recovery-key reversal and a zero delay, with their
`pending_declaration` tuples. The histories establish Declaration state
transitions and Catalog key checks (`catalog_probes`), not queuing, Payload availability,
quotas, sealing or live discovery. The `_wist.<domain>` TXT record is
published for comparison only; a validator that lets its content change an
acceptance decision does not conform.

Separately, WIST-2 §3.2 sealed-Page verification
must retain the selected Declaration's key provenance: gathering every
historical binding with its identifiers can authenticate against the wrong
Declaration. Validation must distinguish retired keys and excluded
bindings without broadening the permitted source Key Set.
Full validation also requires authenticated applicable Declaration history,
including recovery supersession. Both timestamp lookups read sealed Entries;
an accepted but unsealed Declaration does not establish the first following
Epoch's Key Set. Verification over supplied key sets alone does not establish
these source-selection obligations or Page publication and immutability.

**Resolved Page named-entry fallback — WIST-2 §3.2 and draft ADR-0023.**
`vectors/wist2/page-bindings.json` supplies signed probes over ordinary
Declaration chains. The independent reference authenticates those chains
and exercises rotated keys, excluded entries, exact cutoffs, first contact,
forbidden later sources and absence of a following Declaration.
Signature-invalid twins and reversed source order check rejection and
ordering independence; future `nbf` values distinguish Page verification
from the binding-check window. Sealing positions are
supplied inputs, not authenticated Epoch evidence. Empty ID lists isolate
key/source selection and establish no Page-size or publication conformance.
Full role validation still requires authenticated inclusion and recovery
supersession, live Declaration fetches, durable source provenance and
immutable Page publication.

### Authenticated recovery state

WIST-1 §5.2 and WIST-4 §5 freeze each recovery window’s length at its
owner Epoch’s in-force parameter map. `recovery_window_cases` in
`vectors/wist4/parameter-combinations.json` exercises exact effective-time
and settlement boundaries, later shortening/lengthening, in-window followers,
new windows, the largest representable window, an amendment rejected for
ending past the Log timestamp range (WIST4-E03) and an opening near the
range end that cannot seal. Accepted amendments and eligible recovery events
are supplied inputs; integrated replay must derive them from authenticated
history before applying the rule, and an Epoch sealing an unsealable
recovery Declaration is rejected under WIST1-E08.

WIST-1 §5.2 and WIST-3 §3.3 select recovery ownership in ascending
`(Epoch number, seq)` order. `vectors/wist1/recovery-order.json` exercises
signed Declarations and predecessor links in authenticated Checkpoint
histories,
including reversed leaf-hash order. WIST-1 §5.2 separately retains the highest
accepted sequence through settlement and defines eligible predecessor heads.
WIST-3 §7 and draft [ADR-0040](decisions/0040-snapshot-recovery-state.md)
carry the sequence floor in `declaration` and the recovery-chain head in
`recovery_window`. `snapshot_tuples` and `resume_cases` in
`vectors/wist1/recovery-heads.json` show a Consumer resuming from those
tuples reaching every full-replay probe result at the tuple's height, and
that dropping the floor or the head changes one; live Snapshot production
from authenticated replay and Consumer adoption of the tuples require
integration validation.

`vectors/wist1/recovery-heads.json` authenticates a complete hourly Checkpoint history
and probes ordinary/recovery followers across competitors, stale predecessor
rejection, named-predecessor classification, the deadline transition and
idempotent re-serving of the restored lower-sequence head. Its reference
validates Declaration authorship separately from Epoch inclusion. It asserts
no identity-reset or conflicting-batch result.

WIST-1 §5.2 and WIST-3 §3.3 reject conflicting equal-sequence Declaration
groups as an entire Epoch under `WIST1-E08`, preserving the accepted prefix
and state. Only already-current publisher re-serves or identical first-install
Envelopes are nonconflicting; differing signatures cannot choose a new
Declaration's ordinary/recovery authority by leaf order.
`vectors/wist1/declaration-conflicts.json` exercises signed sibling and
signature conflicts, initial and open-window cases, idempotence, independent
domains and atomic rejection. Service admission and replay must adopt these
rules; a Checkpoint signature alone does not establish Declaration
admissibility.

WIST-1 §5.2 preserves the recovery owner's identity from its application
onward: in-window fresh competitors cause no reset in any prefix, a fresh
predecessor earlier in the owner's Epoch resets normally, and so does a
valid fresh replacement after settlement unless a new window has opened.
`vectors/wist1/declaration-conflicts.json` carries the reset height each
history leaves; Snapshot resume conformance is not established.

`vectors/wist1/recovery-settlement.json` authenticates seven 170-Epoch hourly
histories through the settlement boundary, with admissible fresh competitors,
ordinary descendants and legitimate ordinary/recovery followers. Signed
rejection twins enforce recovery-key protection, predecessor eligibility and
Declaration authorship. A shared key naming a competitor cannot advance the
recovery chain. Queue settlement of publications is exercised by
`catalog-recovery.json`. The histories do not establish durable queuing,
Payload availability, quotas, actual survivor inclusion, status reporting
or complete historical Catalog verification.

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

## Catalog and Item diagnostics

WIST-1 §7 checks a Catalog for `WIST1-E05` and then its `WIST1-E14`
fields, and an Item for its `WIST1-E14` conditions with the `url` and
`payload.bytes` exceptions, before any other diagnostic, and permits any
established applicable diagnostic among the rest. The complete binding
check retains its E02/E01 distinction; choosing one failed check does not
waive a prerequisite of a check performed or an object or stage
disposition.

`vectors/wist1/catalog-fields.json` judges signed Catalogs under a
Declaration with Collections and one with the implicit `default`: owner and
Collection keys, a key of another Collection, a recovery key, a Catalog of
another Publisher, binding windows at `nbf` and `exp`, the inclusive clock
bound under positive and zero allowances with fractional and offset
clocks, `size` at and above `catalog_items_max` and by value, a Collection
the Declaration does not name, version spellings and unsupported majors,
Envelope and inner-object field mutations, and `catalog.json` read bounds
and `WIST1-E05` inputs. `vectors/wist1/item-fields.json` judges Items of
both kinds with their Catalog: member sets and forms, Normalized URL,
authority and Scope, `url_cap_bytes` and the `JCS(item)` bound, the derived
cap and `observed_at` against `generated_at` across offsets and long
fractions. The Declaration, the clock and the parameter map are supplied,
not authenticated Log history. The corpora do not establish live pulls,
the walk, Payload retrieval, recovery, status accounting or restart;
integrated role validation must exercise those obligations and consume
permitted diagnostic sets rather than require one diagnostic order.

WIST-1 §§3.1/7 and ADR-0030 resolve Catalog and Payload version
eligibility for every validator role: E14 spelling first, E15 for an
unsupported major, supported minor/patch values accepted and components
beyond machine-integer ranges accepted. Integrated roles must enforce these
checks before acceptance, idempotent re-serves and restoration included.

## Catalog and Item Publisher attribution

WIST-1 §3.8 and ADR-0029 require a canonical Publisher domain inside each
signed Catalog and each Item. The Catalog's selects the sole Declaration
history supplying authority, Collections, Scopes and keys; copying keys or
changing an unsigned identifier cannot change the author. An Item whose
`publisher` is not its Catalog's is refused alone with `WIST2-E03`, and the
Publisher of a `publisher_item` Entry is its named Catalog's (WIST-3 §3.3).

`vectors/wist1/catalog-fields.json` carries a Catalog of another Publisher
signed by a key of the Declaration and noncanonical `publisher` spellings;
`vectors/wist1/item-fields.json` carries Items of both kinds whose
`publisher` is not the Catalog's; `vectors/wist1/item-roots.json` carries a
`publisher_item` body whose Item names another Publisher. Independent role
adoption remains required: emit and validate the signed field without
synthesizing it into signed bytes, select only the authenticated
Declaration history of that domain, derive the Publisher of an Item Entry
from its named Catalog, and derive Label authorship and materialization
from the same author.

### Recovery sources and remaining materialization questions

WIST-1 §5.2 reads the two frozen sources of a recovery each alone: a
Catalog is queued when a source names its Collection and supplies a
candidate under which its binding check passes, and an Item passes the
Item conditions only under a source that accepts its Catalog. Settlement
judges every queued Catalog again by C1 (WIST-3 §3.3) under the settlement
source and drops a failing copy with `WIST1-E13`; a survivor is judged
again at its sealing Epoch.

`vectors/wist1/catalog-recovery.json` carries signed Declarations, Catalog
Envelopes and tree files fed to an Aggregator as events in time order: the
two frozen sources before and after the rotation is sealed, the queue per
Collection name and signing key, settlement at a pull and at the Epoch,
equal instants decided by Catalog ID, places after settlement, a survivor
refused by a Declaration of the settlement Epoch, an idempotent re-serve
inside the window, a competitor that reduces authority, a recovery that
narrows a Scope, records sealed under a key an attacker held, and a
rotation that fails at its candidate Epoch. The events stand for pulls and
Epochs; the histories do not establish live fetches, durable queues,
Payload retrieval, status publication or restart.

Source-paired checks alone do not establish source selection. An implementation
that selects the highest sealed sequence without excluding recovery-superseded
competitors violates WIST-1 §5.2, even if each supplied source's binding and
Scope are checked correctly. Validation must demonstrate a legitimate survivor
sealing despite a higher-sequence competitor, and distinguish the last follower
sealed inside the window from an accepted but unsealed replacement. Admission
at or after the deadline must settle first and use the resulting current
Declaration. Replay must preserve the accepted sequence floor, allow both
eligible predecessor heads while the window is open, and allow only the
restored current head after settlement. Restoring a sealed head must not
introduce a new first installation. A dropped queued copy must not suppress
its Catalog ID: test serving the same Catalog again after authority changes,
including after restart. Queue validation must also cover Catalogs and
Items that waited when the window opened, with their places, eligibility
Epochs and ceilings through settlement. Persistent queues must restore each
queued Catalog's key and place; restoration must not derive a place from
storage order, and must reject an ambiguous restoration, preserving queue
and status atomically on failure.
These are requirements of the existing rules, not alternative interpretations.

Admission validation must distinguish an ordinary successor of a competing
Declaration from a recovery follower when both authenticate with the same
public key: only a candidate naming the recovery-chain head may advance it.
Persistent restoration must repair or reject a summary that classified the
former as the latter, using authenticated sealed history and retained pending
admissions. A partial Epoch must not erase still-pending recovery continuations
from admission state. Test independent sequence-floor persistence through
settlement, current-object idempotence below that floor, malformed re-serves,
and rollback when a head write fails after a floor update.

Capacity validation must also exercise two pending Declarations for one domain
that name different eligible heads. Sealing a higher sequence while retaining
a lower sequence can make the lower candidate permanently ineligible under
WIST-1 §5.2. Predecessor closure alone does not prevent this: a valid subsequent
Epoch and continued queue progress must be demonstrated after capacity deferral.

WIST-1 §5.2 and draft ADR-0015 resolve the fate of competing Declarations
admitted inside recovery but still unsealed at expiry. Remove those superseded
copies and their non-chain descendants from sealing eligibility while retaining
the admission sequence floor and legitimate pending followers. The exception
to Declaration sealing does not remove already-sealed evidence. A Consumer
cannot infer an unpublished admission time: a removed competitor could otherwise
pass its Log's post-deadline acceptance checks and acquire a new identity effect.
`vectors/wist1/recovery-admission.json` supplies signed Declaration Envelopes
with separately supplied chronological admission events and authenticated hourly
Checkpoint histories. It distinguishes
the pending admission head from the sealed queue-settlement source, ordinary
and recovery descendants, legitimate pending followers, a last-second admission,
exact-deadline replacement, repeated settlement and an already-sealed competitor.
Signed alternate Epochs demonstrate why Log validation alone cannot detect the
forbidden revival. A pending recovery-signed follower first sealed after expiry
opens a new window at that sealing instant if none is open. The first such
follower owns the window; later Entries inherit its protection. Supersession
cancels a removed recovery copy's remaining sealing duty without excusing an
already-incurred latency violation.

Independent role consumption and live adoption remain required. Demonstrate
atomic restoration/removal with queue and status effects; preserve completion
of admission settlement across reopen and the first deadline Epoch so later
accepted replacements are not overwritten or their new Catalogs revalidated as
copies from the closed window. Exercise capacity-deferred Declaration chains
and failure/retry before committing a new Epoch. The signed traces establish
Declaration stages and selected source identity, not full Catalog
eligibility, actual E13 processing, inclusion turns, Payload availability,
quotas or Snapshot restoration.

WIST-3 §7 and draft [ADR-0039](decisions/0039-scoped-host-materialization.md)
select one record per URL among those whose Item no withdrawal names: from
the sealing of the host's first Declaration Entry the host's own, which
nothing ends, else the nearest ancestor Publisher's, else the least
non-ancestor domain in octet order. Every record stays a record and a
Snapshot's `record` tuples carry the unmaterialized ones with their Items.
`vectors/wist3/materialization-preference.json` fixes the outcomes from a
host, whether the host's first Declaration Entry is sealed, and the
Publishers holding records, each with whether a withdrawal names its
Item; the reference recomputes each case and shows the shortest-ancestor,
descending-order, raw-suffix and withdrawal-blind readings differ.
`vectors/wist3/record-materialization.json` carries the records, removal
states and materialized records of one Log after each Epoch, and a
record's return when a preferred record leaves after a Snapshot resume.

## WIST-3 sealing, waiting and records

WIST-3 §3.3 judges each `publisher_catalog` Entry by C1 to C4 and each
`publisher_item` Entry by I1 to I7 at its Epoch, and §7 holds the latest
Catalogs, floors, records and removal states they leave, the base and the
combination of several Logs. `vectors/wist3/catalog-sealing.json`,
`vectors/wist3/catalog-waiting.json` and `vectors/multilog/catalog-order.json`
carry them over signed histories (`tools/VERIFICATION.md`).

Not carried by any vector: an Epoch rejected with `WIST3-E03` for an
unknown Entry type or for a Label ID a lower Entry carries (the
per-Labeler cap, the per-domain capacity and Entries out of canonical
order are carried, as is an Epoch meeting both a Declaration rejection
and `WIST3-E03`).
`vectors/wist3/catalog-waiting.json` carries Labels and a dispute taking
places at one pull after its Catalogs and URLs, in the order the pull
accepts them, their eligibility Epoch, inclusion ceiling and `capacity`
deferral under the per-domain capacity and under the per-Labeler cap, an
eligible Item and Label left unsealed taking no room, a Label and a
dispute leaving with a `WIST2-E06` rejection when the check of WIST-2
§3.3 repeated at their turn fails under the candidate Epoch's map and
clock, each beside a twin sealed before the map changes, and the
inclusion ceiling read from the map in force at the eligibility Epoch
and again when a deferral moves it.

WIST-3 §3.3 does not fix whether a recovery window open for a Labeler or
a disputant defers its Labels and disputes: an implementation may defer
them under `recovery_window` or seal them as if no window were open.

## Validation still required

The vector-family inventory in `tools/VERIFICATION.md` distinguishes
independent anchors from self-consistency. The following acceptance evidence
must also be supplied before stable publication; isolated signature or
arithmetic checks do not establish live-service behavior.

| Surface | Required evidence |
|---|---|
| WIST-1 §4 canonicalization | Correctly rounded binary64 edge cases, fractional JSON values in signed objects, rejection outside the finite range, and `WIST1-E05` for repeated member names, lone surrogates and nesting deeper than 64 levels in every object a role parses; `catalog-fields.json` carries such inputs for `catalog.json` alone |
| WIST-1 §5.2 Declaration key binding | Initial admission, replacement and historical replay consume `declaration-binding.json`; duplicate keys and thumbprint mismatches reject, and the authenticated public key's set membership fixes its identity/recovery class |
| WIST-1 §§3, 4 Items, Catalogs, roots and proofs | Consume `item-fields.json`, `catalog-fields.json` and `item-roots.json` with independent JCS, SHA-256 and Ed25519 implementations: recompute every Item ID, key, leaf, root, Catalog ID and Inclusion Proof, the empty Collection and the lone leaf included, and apply the Item and Catalog conditions with their field precedence. `envelope.json`, `catalog.canonical` and `id.txt` are the known answer. The walk of tree files, its bounds and `WIST2-E07` are WIST-2 §5's and are carried by `vectors/wist2/catalog-tree.json` |
| WIST-1 §5.1 Collections and Scopes | Consume `collection-fields.json`, `collection-scope.json`, `collection-keys.json` and `collection-narrowing.json`: Collection and Scope forms (`WIST1-E14`), names, host authority, disjointness and counts (`WIST1-E16`), the Entry bound (`WIST1-E04`), coverage with the port, a publication signed by another Collection's key, unique keys across `keys`, `recovery_keys` and every Collection, a Declaration signed by a Collection key as a fresh identity, and narrowing at each transition's height. Live pulls under the sources of WIST-1 §5.2, the hold and durable Declaration state remain integrated obligations |
| WIST-1 §5.1/§5.2 Catalog bindings under recovery | Consume `catalog-fields.json` and `catalog-recovery.json` with independent signature and timestamp implementations. Read each frozen source alone with its keys, Collections and Scopes in admission, authenticated replay and durable restoration; distinguish E14 fields, E02 absence of eligible authority and E01 failed signatures, and never borrow the two sources for sealing or historical verification. |
| WIST-1 §5.2 recovery ownership and heads | Replay consumes `recovery-order.json`, `recovery-heads.json` and `declaration-conflicts.json`, authenticating each Declaration against its eligible named predecessor, retaining the accepted sequence floor and settling before deadline-Epoch Declarations. Reject conflicting groups and failed Declaration acceptance atomically; canonical storage order cannot choose a winner or replace a recovery owner. Snapshot state requires the resolution listed above. |
| WIST-1 §5.1/§5.2 key directory and activation | Consume `key-directory.json`: recompute every thumbprint and fingerprint, apply the entry field rules before uniqueness, admit Catalogs only inside a binding's window, enforce `next_keys` on ordinary rotations, and replay the histories so that a pending identity supplies no authority, activates at its frozen height, at once under a zero delay, and is discarded on reversal (`catalog_probes`). `keyset-at-height.json` resolves the Key Set at each height for Catalogs. Snapshot resumption requires the `pending_declaration` tuple. Live discovery, the DNS record's retrieval and integrated role behavior remain separate obligations. |
| WIST-1 §5.2 recovery settlement | Consume `recovery-settlement.json`'s Declaration histories, authenticating Declaration acceptance separately from Epoch inclusion, and `catalog-recovery.json`'s settlement of the queue. Preserve the frozen sources, the named recovery chain, queued places and WIST1-E13 status effects. Demonstrate durable queue recovery, applicable quotas, Payload availability and actual survivor sealing; signature eligibility alone does not establish these duties. |
| WIST-2 §§3, 5, 7 Collection pulls | The Declaration fetched at every pull with an answer 304 judged as the Declaration it validates; the served-file duties of §3.1 over time; `catalog.json` read to 16 384 octets, judged and ordered, a fetch failure retried as `WIST2-E01`; held lists, change lists with each discard condition, the order of `size` and the budget, suspension and the `WIST2-E08` report, and the walk that stops at its first refusal with `WIST2-E07`, fetching no child of an inner file that fails a rule read from that file alone; the refusal of a list that drops a held record's URL; Item and Payload admission with `WIST2-E03` and the retry at an idempotent re-serve; pull resolution against the quota; the status object's `collections` and rejection members. `catalog-order.json`, `catalog-tree.json`, `change-lists.json`, `change-list-serving.json`, `change-chains.json`, `served-files.json`, `collection-pull.json`, `declaration-pull.json`, `declaration-refresh.json` and `fetch-bounds.json` carry the offline parts, and the harness validates a status object assembled from their reports against its schema. `change-chains.json` carries the bound met first for a change list and for a root tree file, the depth-first walk with its twin and a per-pull limit in objects that leaves no object before a change list; `collection-pull.json` carries the list held after a dropped-record refusal and remaining Items judged only where the same Catalog is met again as an idempotent re-serve; `fetch-bounds.json` carries objects above their own bound at, one octet above and equal to the remaining allowance; the harness checks a bucket element against its `url` alone (`schema:wist2-tree-file-bucket-members`) and refuses a status code outside WIST-1 and WIST-2. Not carried: HTTP, durable suspension state, a status object an Aggregator produces, §5.1 step 3's refusal of a list obtained from change lists, and a concrete pull history for a discarded chain followed by a refused walk or for a pull that admits only Labels, both of which `fetch-bounds.json`'s resolution cases decide from a supplied summary |
| WIST-2 §3.2 Label Feeds | Label Feed and Page checks, regression state, Page sealing timestamps, the target rule and seen-ID bookkeeping under live pulls; the codes of a Label Feed's field, domain and signature failures are not determined by §3.2 (Undetermined pull behaviors above) |
| WIST-2 §§3.3, 5 Labels | Live Label Feed pulls under the ingest budget, `WIST2-E06` reporting with the Label or Dispute ID, sealing as `label` and `dispute` Entries under the inclusion ceiling, the per-domain capacity and the per-Labeler cap, `tier1/labels.parquet`, `tier1/disputes.parquet`, `tier1/labelers.parquet` and the `label` and `dispute` tuples from authenticated Log replay, expiry and the `delta` binding to a record's Item applied at materialization |
| WIST-2 §7 and WIST-4 §5 quotas | Error-code accounting, `WIST2-E05` exclusion, UTC-day anchor and live quota and ingest-budget application per Registrable Domain under the snapshot in force |
| WIST-2 §§6, 8 scheduling and redirects | Hints change pull timing without creating a duty; redirect termination and authority restrictions under live pulls |
| WIST-3 §§5–6 publication | Every Entry below the Checkpoint's tree size durably stored and retrievable at its tile path before that Checkpoint is published; Payload replication before the Epoch; the partial tiles and entry bundle the head's tree size requires served while that head stands, and every full tile, entry bundle and archived Checkpoint retained from genesis |
| WIST-3 §§3.2–3.3, 6.1, 7 sealing and records | Live sealing that judges every candidate Catalog and Item at its Epoch, seals none that fails and no Item in the Epoch that seals its Payload's withdrawal; the last accepted Catalog, places, eligibility, each deferral and the hold reported at the status endpoint; the capacity order with Labels and disputes; the Payload check at an Item's turn; the Payload duties of §6.1 over time, a superseded Payload included; a replaying Consumer and one resumed from a Snapshot reaching the same latest Catalogs, records, removal states and materialized records, an unmaterialized record restored after the resume included; several Logs combined per Publisher and URL |
| WIST-3 §§6–7 Snapshot directories and sharding | Each Snapshot served under its own immutable `/snapshots/<snapshot_date>/<epoch_number>/` directory, a later Epoch of the same date under a new one, the index newest date first and higher Epoch first within a date, and an entry disagreeing with its manifest answered by re-fetching the index (`WIST3-E04`); where sharded, shard *i*'s tier files under `shard-<i>/` with a matching `shard`, per-shard digests recomputed by grouping the loaded records with §7's domain rule, and Label, labeler and dispute rows filed by Labeler and disputant. `vectors/wist3/snapshot-index.json` supplies the index cases and `vectors/wist3/snapshot-records.json`'s `sharded` member the shard assignment, digests, paths and rows. Not supplied: a partial Consumer holding a subset of shards, and a directory rewritten in place, observable only over time against a live Aggregator |
| WIST-3 §§3.1, 3.3, 6 transport parsing | Independent decoding of tiles and entry bundles, including the big-endian uint16 length prefix, a partial tile or bundle and the fallback to the full one; recomputation against a verified Checkpoint's root rather than trust in the source; refusal to buffer past the 8 192-octet tile bound, the 16 777 472-octet entry-bundle bound, the 65 535-octet Entry bound and the derived transport bound, with equality permitted; leap-second rejection in all Log-comparable timestamp fields and Snapshot tuples; the full four-digit Gregorian year range, including late December 9999 independently of library timestamp limits. `vectors/wist3/tile-bounds.json` fixes the bounds and the malformed forms §6 excludes — an empty tile, a length that is not a multiple of 32, a hash or Entry count other than the path's, a partial width outside 1 through 255, a length prefix or leaf data cut short, an octet after the last Entry, and an Epoch's Entries short of or reaching past its leaf range — over synthetic leaf data no Checkpoint states a root over, leaving the recomputation against a root, the partial-to-full fallback and the reading limit to be exercised on served files |
| WIST-3 §§3.4, 5 Checkpoint notes | Independent signed-note parsing: exactly five lines, the origin equal to the Anchor's `log_id`, the extension lines rejected on any octet of deviation, a root hash line that decodes to exactly 32 octets and re-encodes to itself, every signature line ending in a newline under a non-empty key name free of `+` and of every character with the Unicode White_Space property, at most 16 signature lines, unknown signature lines ignored and a line naming a known key required to verify; the note key ID derived per §3.4 and an `aggregator_key_add` colliding with an admitted key's note key ID rejected in replay. `vectors/wist3/aggregator-keys.json` supplies the multi-key side of the rule — the note key ID of every key valid at the height, a rotation Checkpoint carrying two verifying lines, a line from a key removed at that Epoch or admitted after it, and both collision forms — leaving unvalidated the Witness-side configuration of a rotated verifier key and the serving of Checkpoints across a rotation |
| WIST-3 §§3.1, 4–5 proofs and head adoption | Consistency Proofs generated and verified by independent implementations across every tree size, including the empty-tree and equal-size cases and the size-0 root compared rather than the empty proof skipped; every Checkpoint from the verified head to the adopted one verified in `epoch_number` order; a lower `epoch_number` rejected as rollback and an equal one with differing note text treated as equivocation; each of §5's three equivocation forms recognized from its stated evidence bundle; §3.1's sequence failures distinguished at a live head — a Checkpoint above an unobtainable one reported as `WIST3-E01` while remaining a valid object, a `sealed_at` not later than the previous Checkpoint's or off the cadence grid rejected as `WIST3-E03` whatever its signature does, and a tree size below the previous Checkpoint's judged under the key set valid at the previous height — `WIST3-E02` only where its signature verifies under that set and its root is not that tree's root at the smaller size, and `WIST3-E02` for a Checkpoint failing several rules where that form applies. The vectors supply the cadence rather than replaying an `epoch_cadence_seconds` schedule across an amendment, run the tree-size cases under a single Log key, and supply no source retry |
| WIST-3 §5, WIST-4 §5 Witness quorum | Cosignatures verified against a Consumer-configured Witness roster, distinct trusted names counted against `checkpoint_witness_quorum` as in force at the Checkpoint's `sealed_at`, a short-of-quorum Checkpoint neither adopted nor reported as an error, and every acceptance made while the quorum is 0 recorded as unwitnessed with the retained Checkpoint |
| WIST-3 §§7–8 Snapshot position | A manifest's `epoch_number` selecting the archived Checkpoint and its `tree_size` and `root_hash` reconciled against that Checkpoint at cold start and at every later manifest read, with the state file's `tree_size` checked against the manifest's (`WIST3-E04`) and a file at the selected path stating another `epoch_number` re-fetched as a source fault (`WIST3-E03`) rather than read as divergence; the transport bound bootstrapped from the manifest's authenticated parameter tuples. `vectors/wist3/checkpoints.json` fixes the dispositions; the re-fetch across sources, the per-file hash and size checks and shard coverage are separate obligations |
| WIST-3 §§3.4, 5 Log key succession | A rotated Aggregator key authenticates Checkpoints at the correct height, including rejected keys. `vectors/wist3/aggregator-keys.json` replays the key acts themselves: each read at the height §3.4 fixes, every key-act failure ignored as `WIST4-E04` with its Epoch kept, an Epoch whose accepted removals leave no valid key never applied, a Checkpoint at or below the head judged under the keys valid at its own height, and the `aggregator_key` tuples §7 keeps for removed keys. Not supplied: an operating Log rotating across serving and Snapshot production, the Aggregator-side refusal to seal a key-act failure, and a successor Anchor's `predecessor` carry |
| WIST-3 §§3.4, 7–8 Snapshot key authentication | A resuming Consumer authenticates a state file's `aggregator_key` tuples from the Anchor's genesis key before it uses any of them, persists nothing derived from the Snapshot until the index, the manifest and every state file verify under the keys valid at the adopted Checkpoint's height, and reports `WIST3-E04` on any failure. `vectors/wist3/snapshot-keys.json` supplies whole Snapshots of one signed Log: §7's rules 1 through 5 each broken alone, forgeries whose Checkpoint and documents verify under the tuples they carry, each document judged at the adopted head against a signer removed at or below it, a signer admitted above the Snapshot's Epoch and learned from the walked Epochs' key acts, and a signature failing under its named tuple, each of the catch-up clauses falsified in turn against a Consumer-held registry beside a registry the tuples agree with, and the two `state_digest`s two removals of one key in one Epoch produce, which rules 1 through 5 do not separate. Not supplied: an Aggregator re-signing every unsealed document it still serves under a key valid at a removing Epoch's height, adding a replacement below the removal it answers, the re-fetch across Mirrors a rejected Snapshot triggers, and a sharded Snapshot (the sharded layout is exercised without key rotation by the row above) |
| WIST-3 §5 Mirror list | The list verifies under the keys valid at the Consumer's adopted head (§3.4) and one that does not verify — a since-removed signer, or a list read before the Consumer has a head — is no error: its entries stay location hints, never evidence of authorship, Log membership or source independence, and §6.1 already permits retrieval from any source. `vectors/wist3/snapshot-keys.json` carries all three signed cases. Not supplied: live fetching and refresh of the list, its staleness handling, retention of Mirror URLs from other trusted sources, and the Aggregator's rewrite of the list across a rotation |
| WIST-4 §5 inclusion | Acceptance, places and the turn of Catalogs, Items, Labels and disputes in the per-domain capacity and the per-Labeler cap under backlog, overload and recovery, the inclusion ceiling read at the eligibility Epoch, and the discovery sealing deadline counted from the first Epoch sealed after the discovery; the Log alone does not reveal acceptance or discovery time |
| WIST-4 §§3, 5.1 governance | Key registration and removal, parameter schedules, withdrawals and suffix-list snapshots sealed, served, replayed and restored across the three roles, including per-Registrable-Domain capacity rejection in a replaying Consumer |
| WIST-5 §§3–7 Emissions | A content system and a signing tool written separately exchanging complete and incremental streams; each refusal of §3.3 and §6.3 leaving the served files unchanged; the plan matching the Catalog then signed; unchanged content keeping its Item, salt and `observed_at` across runs; a due Catalog signed with no stream; a marked-page Emitter over live pages, emitting nothing from an unmarked one |

These are validation requirements, not assertions that every boundary lacks
unit coverage. Current vectors already exercise, among other cases,
normalization, key-set selection and Label dispositions.
Provide an exact specification commit and the exercised obligations when
claiming that any row is satisfied.

## Object-version policy

WIST-1 §3.1, ADR-0028 and [PUBLICATION.md](PUBLICATION.md) permit incompatible
revisions of the unreleased draft under `wist_version = 1.0.0`. Validators and
compatibility claims must identify an exact specification commit and enforce
its complete field set. The exception ends on stable publication or the first
Log sealing Epochs consumed by a third party, whichever happens first.

The version cases in `catalog-fields.json` exercise current fields, unknown
members, malformed spellings, supported minor/patch values and an
unimplemented major. Independent role consumption and publication-boundary
verification remain required; an offline vector cannot establish deployment
status or waive the frozen edition's immutability.

## Declaration refresh boundaries

WIST-1 §5.1, WIST-2 §5.1 and §5.2 and draft ADR-0031 fetch the Declaration
at the start of every pull and exclude Declaration requests from the content
budget. `vectors/wist2/declaration-refresh.json` carries 22 signed pull
sequences: one Declaration request per pull, Catalogs refused under a key
or window the served Declaration does not grant and accepted at a later
pull under the rotated one, stopped pulls with `WIST2-E01` and, at first
contact, `WIST2-E04`, content-budget boundaries with no Declaration octets
debited, and five Page cases selecting current or first-following sources
from supplied sealing instants, which hold the Page source prefix fixed
without establishing Epoch inclusion. `vectors/wist2/declaration-pull.json`
carries an answer 304 for the Declaration.

These vectors do not establish complete HTTP ingestion, authenticated Page
source reconstruction, complete Page fields/publication, recovery settlement,
resumption, durable admission or bounded fetch/work. Integrated
implementations must exercise those obligations; excluding discovery from the content budget does not bound
Declaration response sizes or total discovery traffic.

## Size-cap parameter time

WIST-1 §3.6, WIST-4 §5 and ADR-0020 fix admission-attempt, sealing and
historical cap profiles for Items, their Payloads, Catalogs and
Declarations. `item-fields.json` reads `url_cap_bytes` and the Payload caps
from a supplied map, an amendment to 32 768 read and one to 32 769
refused; `catalog-fields.json` reads `catalog_items_max` amended above its
value; `payload-fields.json` supplies size-cap contexts. The histories of
`vectors/wist3/catalog-sealing.json` and `vectors/wist3/catalog-waiting.json`
carry a parameter map per pull and per Epoch.

Integrated roles must independently consume these vectors and retain the
attempt map through the walk and Payload retrieval, recheck every candidate
Catalog and Item at the candidate Epoch and a Payload at its Item's turn,
and apply the sealing Epoch's map on replay. Live queue refusal, HTTP
retrieval, crash recovery and cross-Log validation remain unexercised.
Supplied-map field vectors alone establish no temporal adoption.

## Payload link validation

`vectors/wist1/payload-links.json` isolates WIST-1 §3.6's WIST1-E12
checks in correctly committed candidates, each with the Item that commits
to it. It covers duplicates, exact URL normalization, internal hosts, count
bounds, ports, query identity and permitted incomplete prefixes. The
reference verifies commitments independently; its normalization coverage
retains the URL resolution limits above. These cases do not establish live
admission, Payload retrieval, sealing, restart, full Payload fields or the
extraction of the declared links from emitted content (WIST-2 §11). Role
adoption and those obligations remain required.

## Payload field and version eligibility

WIST-1 §§3.1/3.6/7, WIST-3 §6.1 and draft ADR-0030/0034 define complete
Payload fields, version support and field-before-semantic diagnostics.
`vectors/wist1/payload-fields.json` supplies committing Items, explicit
preimages, Payload mutations and size-cap contexts.
The reference checks complete fields, unbounded release components,
optional nulls, numeric-value safe integers, scalar boundaries, cap overrides
and E04/E10/E12/E15 combinations after E14 precedence. Raw Payload probes
exercise RFC 8785 §§3.1/3.2.2's E05 rejection of duplicate decoded member
names, lone surrogates and invalid/nonfinite numbers before field checks.
They include escaped-name and nested-duplicate cases. Other objects' raw
input boundaries, the nesting bound of WIST-1 §4 included, still require
rejection validation; ordinary JSON object parsing can discard that
evidence before JCS or schema checks.

Supplied profiles do not establish accepted parameter schedules, retrieval,
sealing, historical reference selection, restart or page agreement. Each role
must adopt these rules independently; typed deserialization alone is
insufficient, and accepted Payload distribution must preserve original bytes.

## Clock parameter time

WIST-1 §3.4, WIST-4 §5 and draft ADR-0020 bound a Catalog's
`generated_at` by the validator's clock and `clock_skew_seconds` at an
unsealed attempt, by the candidate Epoch's `sealed_at` before sealing, by
the sealing Epoch's `sealed_at` for both the clock and the parameter
anchor on replay, and by the settling event's instant at a recovery
settlement. Later clocks or amendments cannot repair an invalid inclusion
or invalidate an earlier valid one.

`catalog-fields.json` fixes the inclusive bound at a supplied clock under
positive and zero allowances, with fractional and offset clocks.
`catalog-recovery.json` settles queues at a pull's instant and at the
settlement Epoch's `sealed_at`. These supplied contexts establish no
selection of the clock from authenticated history; each role must bind the
check to authenticated history and exercise sealing and replay.
