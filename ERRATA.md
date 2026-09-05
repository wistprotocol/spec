# Errata

The suite was frozen on 2026-08-05. This file records every change made to a
document after that date, so that "frozen" stays a legible claim rather than
one a reader has to reconstruct from the commit log.

An entry belongs here when it meets both conditions:

- it cannot break an implementation that conformed to the text before it, and
- it states something the suite already implied, or corrects something the
  suite got wrong.

A change that fails either condition is not errata. It is a revision — and
revisions are expected rather than forbidden. Implementation finds genuine
defects, and the sharpest kind is a contradiction between two sections, which
no implementation can conform to either way, so resolving one necessarily
breaks whoever guessed the other branch. What the freeze buys is not the
absence of such changes but their shape: a revision is scoped to the defect
that provoked it and reopens the suite no further.

**What ends the freeze.** A freeze with a start and no exit criterion is a
preference, and the first strong argument overturns it. This one holds until
two independent implementations pass the vector suite, one of them the
pure-Python conformance reference in `tools/`, kept independent for exactly
this reason, so that neither can quietly become the oracle. The
disagreements found on the way there are the errata this file expects to
collect.

**Why the documents are edited in place.** A published RFC never changes; its
corrections live in a database outside it, because implementations shipped
against those bytes and interoperability is what immutability protects.
Nothing has shipped against this suite. While that holds, editing the document
and recording the edit here is cheaper and more honest than an errata list
every reader must cross-reference against a text that contradicts it. It stops
holding the moment a deployment exists: from the first Log sealing Blocks a
third party consumes, a document's text is fixed, corrections are recorded
here and nowhere else, and a substantive change takes a new major version —
which is what WIST-4 §8 already requires of the constitutional invariants, and
which is a fork that must win adoption on its own merits.

Each entry names its status honestly. **Exercised** means the vector suite
covers the behavior. **Unexercised** means the text rests on reading alone,
because nothing in the harness reaches it — a distinction that matters most
for text added after the vectors were built.

---

## 2026-08-06 — WIST-3 §8, §12: following more than one Log

Adds the paragraph *Following more than one Log* at the end of §8, and one
Consumer line to the §12 checklist.

**What it states.** A Delta ID is the SHA-256 of the Delta's Canonical Bytes
(WIST-1 §4), which carry nothing about the Log that sealed them, and `prev`
chains a URL's Deltas on the Publisher's side — so one Delta has one identity
in every Log that sealed it, and a Consumer holding two Logs deduplicates by
Delta ID exactly. What a Log derives rather than transports does not merge:
its ingest set, its Auditor roster, and every reputation, sanction, exclusion
and quota computed from that roster's Records are state of one chain, and a
Consumer MUST NOT carry them into another. Coverage across Logs is partial in
the sense §7 already gives a sharded Snapshot. §3.4 succession is excluded: it
is one Log continued under new keys, not two Logs reconciled.

**Why it qualifies.** WIST-4 §6 already defines reputation as a function of
one Log's history evaluated at a Block height, so mixing chains was already
non-conforming; the `MUST NOT` forbids nothing that was previously permitted.
A Consumer following a single Log is unaffected, and no prior text addressed
the multi-Log case at all. Before this, the only acknowledgement that
concurrent Logs exist was §6.2's note that a withdrawal binds one Log.

**Status.** Unexercised. No vector seals the same Delta into two Logs, so the
identity-stability claim is verified by reading WIST-1 §4 rather than by
execution. A vector that does so belongs with the first multi-Log consumer.

**Status update (2026-08-15).** Exercised: `vectors/multilog/dedup.json`
(entry below) seals the same Declaration and Delta into two Logs at
different heights and asserts the merged record's `sources`.

## 2026-08-08 — WIST-2 §11 step 5: `link_extraction.py` and empty authority

No document text changes. This entry records a divergence in the pure-Python
reference tool's `normalize_url`, found by checking the tool against an
independent implementation of the same procedure, from what WIST-2 §11
step 5 already pins.

**What it states.** `urllib.parse.urljoin` treats a candidate such as
`https:///x` — a scheme, a `//` authority marker, and no host — as carrying
no authority at all, and falls back to the base's host: resolved against
`https://example.com/blog/post-1`, it yields `https://example.com/x`. RFC
3986 §5.3 Component Recomposition takes the opposite reading: once a
transformed reference carries a `//` marker, its authority (here, the empty
string) is what gets recomposed, not the base's. An implementation
following §5.3 literally extracts that empty authority, and the empty
host it produces then fails the Normalized URL's
LDH-host check (WIST-1 §2), so `normalize_url("https:///x", base)` returns
`None` rather than falling back to any host.

**Why it qualifies.** WIST-2 §11 step 5 already named RFC 3986 §5 as the
resolution algorithm; this states what that pin already implied about
empty-authority candidates rather than adding a rule. `tools/link_extraction.py`'s
own fixtures never construct a `scheme:///path` candidate, so no vector
result changes.

**Status.** Unexercised. Neither `vectors/wist2/link-extraction.json` nor
`tools/link_extraction.py`'s fixtures carry an empty-authority candidate.
The tool's own fix is left to a later change to the tool.

## 2026-08-08 — WIST-2 §11 step 5: `link_extraction.py` and empty path segments

No document text changes. Same pin as the entry above, a second divergence
in the same function.

**What it states.** `urllib.parse.urljoin` merging `a//b` against
`https://example.com/blog/post-1` collapses the doubled `/` and yields
`https://example.com/blog/a/b`. RFC 3986 §5.2.3 Merge Paths and §5.2.4
Remove Dot Segments — the algorithm WIST-2 §11 step 5 pins — merge the
base's directory prefix with the reference's path unchanged and remove only
`.` and `..` segments; an empty segment between two `/` characters is
neither, so the RFC-correct result is `https://example.com/blog/a//b`.
An implementation following §5.2.3/§5.2.4 literally produces exactly
this: `a//b` against this base normalizes to
`https://example.com/blog/a//b`, and `x//` to `https://example.com/blog/x//`.

**Why it qualifies.** Same pin as the entry above: WIST-2 §11 step 5 already
named RFC 3986 §5, so this states what the existing text implied rather than
adding a rule. `tools/link_extraction.py`'s own fixtures never carry an
empty interior path segment in a relative reference, so no vector result
changes.

**Status.** Unexercised: `vectors/wist2/link-extraction.json` carries no
candidate with an empty interior path segment. The tool's own fix is left to a later
change to the tool.

## 2026-08-11 — WIST-4 §5, §9, registry-update schema: bounded Auditor fetches (revision, not errata)

Adds the fetch-bounds passage to §5 (four parameters:
`audit_fetch_cap_bytes`, `audit_domain_budget_bytes_day`,
`audit_redirect_max`, `audit_fetch_timeout_seconds`), extends the
`unreachable` and `not_auditable` rows of the §5 verdict table and the
blocking-Record definition to name them, adds their §9 registry rows,
bounds and combination rule, adds two Auditor conformance-checklist items,
and registers the four identifiers (with floors for three) in
`schemas/registry-update.schema.json`. Decision record: ADR-0010.

**Why it is a revision.** It fails the first errata condition: an Auditor
that conformed to the prior text by reading arbitrarily large responses, or
following unbounded redirects, now has behavior the text bounds, and a
`parameter_change` naming one of the four identifiers was schema-invalid
before this change and is valid after it. The defect that provoked it is
scoped and stated in ADR-0010: every other fetch magnitude in the suite was
bounded, and two honest Auditors with different implicit limits could reach
different verdicts on the same URL — the disagreement §4's integer
arithmetic exists to eliminate, reproduced one layer down.

**What it does not change.** No verdict is added, no Record field changes,
no error code is added; `unreachable` and `not_auditable` already omit the
commitment fields for exactly the cases the bounds produce.

**Status.** Unexercised. No vector reaches the fetch layer; the bounds
enter the vector suite only when audit-behavior vectors exist at all
(none exist — the suite carries no §4/§5 audit-behavior vectors).

## 2026-08-13 — WIST-4 §4, §9: `contradictions_max` vs the extension ration (revision, not errata)

Changes the `contradictions_max` default from 5 to 2 (§4 and the §9
defaults table), states in §4 that the extension ration is also the
ceiling on contradictions per 30-day window, and adds the coupling to
§9's combination rules: `contradictions_max` MUST be below
`extension_triggers_max`. No schema change: the coupling is between two
amendable parameters, which §9's combination paragraph already declares
inexpressible as a fixed bound. Found while ADR-0012's minority-cap
argument was being verified against §4's mechanics.

**The defect.** Only a Record that triggered an extension can be
contradicted (§4's definition reads "the extension it triggered"), and
a Record extends nothing once its filer has `extension_triggers_max`
(3) triggers in the trailing 30 days — so a fourth trigger inside 30
days of the first finds three in its window and summons nobody. At most
3 of one Auditor's Records can therefore be contradicted in any 30-day
window, while divergence required more than 5. The predicate was
unreachable for any history whatsoever: no lying Auditor could ever be
removed by it, and §4's own sentence — "a lying Auditor pays it three
times before its own removal is derivable from the Log by anyone" —
was false as parameterized. The derivation §4 introduced precisely so
that the answer to a lying Auditor would not rest on Aggregator
discretion did not exist.

**Why it is a revision.** It fails the first errata condition: a
validator conforming to the prior default never derives divergence, so
under the new default the same Log can put an Auditor in divergence and
void Records the prior text counted. The scope is the dead predicate
and nothing further: 2 is the largest value below the ration, it arms
the threshold at exactly the ration ceiling — every rationed trigger
in a window contradicted — and it is the value at which §4's "three
times" sentence becomes true as written.

**Alternative rejected.** Redefining contradiction to reach
non-extension Records (two independent `consistent` filings where peers
happened to audit the Delta anyway) would also make the predicate
reachable, but it widens the surface honest filers face — a
coincidence-based eviction with no summons — and reopens the suite
past the defect. ADR-0012's proposed rework of contradiction's
*consequence* (no-fault escalated sampling) is a separate proposal, gated
on the freeze exit, and neither depends on nor supersedes this fix; the frozen suite
has to be coherent on its own.

**What it does not change.** The definition of contradiction, the
extension ration, the rejection semantics of divergence, and the
schema's `contradictions_max` floor (≥ 1) are all untouched.

**Status.** Unexercised. No vector constructs an extension, a
contradiction, or a divergence state — the suite still carries no §4
audit-behavior vectors, as the 2026-08-11 entry notes.

## 2026-08-13 — WIST-4 §9: the `contradictions_max` bounds-row rationale

No behavior changes; one bounds-table cell's justification is
corrected. The row for `contradictions_max` justified its ≥ 1 floor
with "at zero an Auditor is in divergence before it has filed
anything, so no Auditor's Records ever count." That misreads the
predicate it cites: divergence requires contradictions *more than*
`contradictions_max`, so at zero it arms at the first contradiction —
an event that requires filing an extension-triggering Record and
having its window close contradicted — and an Auditor that has filed
nothing has zero contradictions and is not in divergence.

**What it states.** The floor is justified, for the reason the cell
now gives: a transiently wrong page — a defacement reverted before the
summoned peers fetch, an edge cache out of sync — can contradict an
honest filer, which is why the predicate carries a threshold at all.
At zero that single contradiction carries the whole divergence
consequence, removal and 30 days of voided Records, so the predicate
measures an event rather than the systematic divergence §4 derives,
and filing `inconsistent` becomes the risk the extension rule exists
to remove.

**Why it qualifies.** Both conditions hold. The floor, the schema's
minimum of 1, and everything any party computes are unchanged, so no
conforming implementation can break; and the correction supplies the
justification the bound already needed rather than a new rule. In a
table whose stated standard is that each bound marks the point at
which the mechanism beside it stops existing, a false justification is
what invites a future argument that the bound is arbitrary.

**Status.** Unexercised. The cell is prose about a bound; the schema's
floor is unchanged, and no vector or example carries a
`parameter_change` at this boundary.

## 2026-08-15 — WIST-4 §2, §5, §7: the confirmation window is pairwise; replay-derivation vectors

Rewords three sentences — §2's Confirmed Link Inconsistency definition,
§5's Confirmed Inconsistency window sentence, §7's Confirmed Link
Inconsistency paragraph — that measured the confirmation window from "the
first such Record", and adds five vector files under `vectors/wist4/`
(`confirmation.json`, `derivation.json`, `coverage.json`,
`extension.json`, `sanctions.json`) generated by `tools/gen_vectors.py`,
covering §5/§7 confirming-block selection and severity, §6.1/§6.3
A/C/penalty inputs, §4 coverage-failure counting and extension
rationing, and §7 ladder state.

**What it states.** The window is pairwise and ends at the confirming
Record's Block: a Record confirms when an earlier `inconsistent` (or
`link_inconsistent`) Record for the same Delta, from an Auditor
independent of the confirmer, was sealed no more than
`confirm_window_hours` before it. Read as anchored to the first-ever such
Record instead, a Delta whose lone first Record went stale unconfirmed
could never confirm — yet §4's extension rule already speaks of "the §5
confirmation window ending at *B₁*", a phrase with no referent under the
first-anchor reading, and re-summons the roster on exactly such a later
lone Record so that a Record "published at the deadline can still seal
inside the window it exists to serve", which is false unless that later
Record can anchor a window of its own. §2's short definition ("within 72
hours measured on Block `sealed_at`") is the pairwise reading. §6.1's
confirming-Block selection ("the earliest Audit Record, in Log order, at
which the applicable confirmation predicate is first satisfied") and §7's
closed confirming set are unchanged and hold under it.

**Why it qualifies.** Both conditions hold. The first-anchor reading was
never one an implementation could conform to: it leaves §4's extension
duty summoning Auditors to confirm Deltas the predicate had already made
unconfirmable, the same standard §9 applies to parameter values — a
reading that removes a mechanism is not a reading of the suite. The
vectors state readings the text already carries: "no more than 72 hours
after" is inclusive; every "30 whole days ending at" window is the set of
instants whose §6.1 whole-day distance from the window's end is below 30
(end-inclusive, start-exclusive); §4's "has triggered fewer than
`extension_triggers_max` extensions" counts an Auditor's earlier
summoning triggers, so a rationed-out Record consumes no ration; §7's
"cannot precede what it reports" makes an early `"unappealed"` ruling
absent; and a ruling sealed after its deadline does not revive a state
already void at that deadline.

**Status.** Exercised. `vectors/wist4/confirmation.json` carries the
stale-first case ("stale first later pair") that separates the two window
readings, the closed-set severity extremum, and the independence table;
the other four files exercise the derivations above, boundary rows
included.

## 2026-08-15 — WIST-2 §7: `WIST2-E05` and the noise set

Rewords the `WIST2-E05` registry row: the discarded pull does not count
against the Ping quota.

**What it states.** §4 defines the quota's noise accounting as a closed
set — "Only pings resolving to `WIST2-E02` or `WIST2-E04` count against
the domain's daily quota Q" — and the §10 conformance checklist restates
exactly that set, citing §4. The §7 registry row for `WIST2-E05` said the
opposite ("counts against the quota as noise"), a contradiction no
implementation could conform to both ways. The row now follows §4.

**Why it qualifies.** Both conditions hold. §4 states the rule twice —
once normatively, once as the conformance checklist item — while the §7
row said it once in a table whose column describes per-code handling, not
the quota's definition; an implementation that conformed to §4's closed
set conformed to the suite's own accounting rule and is not broken by the
row now agreeing with it. An implementation following the old row
literally over-counts a regressing Feed against Q, which §4 already
forbade.

**Status.** Unexercised. No vector reaches Ping-quota accounting; the
rule rests on the §4 text and the §10 checklist.

## 2026-08-15 — WIST-3 §8: multi-Log dedup vector

No document text changes. Adds `vectors/multilog/dedup.json`, generated by
`tools/gen_multilog_vector.py`, exercising the *Following more than one
Log* paragraph the 2026-08-06 entry added to §8.

**What it states.** States what WIST-1 §4 and WIST-3 §8 already imply: a
Delta ID is the SHA-256 of the Delta's Canonical Bytes, which carry
nothing about the Log that sealed them, so the identical Declaration and
Delta envelopes sealed by two Logs at different heights — `log-a` seals
the Declaration in Block 0 and the Delta in Block 1; `log-b` seals the
same Declaration in Block 0, an empty heartbeat Block 1, and the same
Delta in Block 2 — carry one Delta ID, and a Consumer holding both Logs
deduplicates by it. The vector's `expected.merged_records` entry names
both Logs in `sources`.

**Why it qualifies.** WIST-3 §8 already states the identity-stability
claim in prose; the vector executes it rather than adding to it, and no
implementation that conformed to §8 is broken by a vector confirming what
the paragraph already required.

**Status.** Exercised. `vectors/multilog/dedup.json` seals one Delta into
two Logs at unequal heights and asserts the merged record's `sources`.

## 2026-08-16 — WIST-4 §4, §9.1, registry-update schema: what a `coverage_attestation` carries

Rewords §4's coverage-duty sentence, gives `coverage_attestation` its own
§9.1 entry, and adds `vrf_proof` to the schema's required `details` for
that action.

**What it states.** §4 required the attestation to carry "that Block's VRF
proof and nothing else", while the same document's §9.1 required it to
carry `prev_record` as well and the schema required `prev_record` alone —
so the one field §4 makes the mechanism out of was the one field nothing
enforced, and a schema-valid attestation could carry no proof at all. §4
now names both members, §9.1 states them as the two REQUIRED ones with
`subject` the `auditor_id`, and the schema requires them. Nothing else
changes: the attestation still reports no verdict, which is what "nothing
else" was there to say.

**Why it qualifies.** Both conditions hold. §4's "MUST … carrying that
Block's VRF proof" is the older and normative statement, and the whole
coverage derivation reads it: "the duty is verifiable in-band, because the
VRF proof reaches the Log for every Block whether or not anything was
selected". An implementation that conformed to it already emits the proof
and is untouched; one that emitted an attestation without it never
conformed to §4, whatever the schema admitted. The direction of the fix is
the one WIST2-E05's entry above takes: the outlier is corrected to the
rule the document states twice.

**Status.** Exercised. `tools/validate_examples.py`'s
`schema:wist4-coverage-attestation` builds an attestation carrying
`vectors/wist4/sampling.json`'s proof and asserts that one omitting
`vrf_proof`, or `prev_record`, fails schema validation.

**What it leaves open.** How a *sealed* attestation binds to its audited
Block: served, it sits at a Block-Hash-named path (§4), but the Registry
Update carries no `block` member, so on replay the pair is recovered from
the `pull_attestation` that names it. That is a question about §4's
transport, not about this entry's fields, and it is recorded rather than
answered here.

## 2026-08-16 — WIST-4 §5, References: the WARC capture's format

Adds a *capture format* paragraph to §5 and an [ISO 28500] reference.

**What it states.** The suite named "the WARC capture" throughout and
never cited the format. It now does, and states the consequence the text
already carried: no version is pinned, because every duty over the capture
is over its octets — `evidence_commitment` commits to them (§5), and a
party checking a Record recomputes over the same octets — so the version
changes no value any party computes. An Auditor SHOULD nonetheless write
WARC 1.1, so that the appellant §5 sends to
`/.well-known/wist/evidence/<record-id-hex>.warc` can read the evidence
with ordinary tooling.

**Why it qualifies.** Both conditions hold. The commitment construction,
the retention duty, the serving path and the recomputation procedure are
unchanged, and the SHOULD constrains no implementation's conformance — an
Auditor writing another WARC version still conforms. What the paragraph
adds is the citation the term always implied and the statement of why the
version is not load-bearing, which is what stops a future reader from
inferring a pin that was never there.

**Status.** Unexercised. No vector reaches the capture; §5's fetch and
evidence layer has no vectors at all, as the 2026-08-11 entry notes.

## 2026-08-16 — WIST-3 §7, snapshot-state schema: the `parameter` tuple's `effective_at`

Names `effective_at` in §7's list of tuple members that are instants, and
retypes the `parameter` tuple's fourth member in
`schemas/snapshot-state.schema.json` from an integer to the RFC 3339
string every other instant member of that schema already uses.

**What it states.** `effective_at` is a Registry Update field, and
`schemas/registry-update.schema.json` types it as a whole-second
literal-`Z` RFC 3339 instant, "the form `block.schema.json` fixes for
`sealed_at`", because every window it takes part in is compared against a
Block `sealed_at`. The state artifact restates that same value for an
amended parameter, so it is that same instant. §7's type prose listed the
instants and omitted this one, and the schema typed the member as a
non-negative integer — a height. A Consumer resuming from a Snapshot would
then compare a height against the `sealed_at` instants §9's grace period
is measured in.

**Why it qualifies.** Both conditions hold. The registry-update schema,
§9.1's `parameter_change` entry and WIST-4 §9's grace period all read
`effective_at` as an instant, and §7's own encoding rule says instants are
written as the RFC 3339 strings the sealed Entries carry; the corrected
member is the only place in the suite that said otherwise. An
implementation that wrote the instant conformed to the suite's definition
of the field and is not broken by the schema now agreeing with it.

**Status.** Exercised. `tools/validate_examples.py`'s
`schema:wist3-parameter-effective-at` validates a `parameter` tuple
carrying an instant and rejects one carrying a height, an offset form, or
a date.

## 2026-08-16 — WIST-1 §5.2, §7: re-serving the current Declaration is idempotent

Adds a paragraph to §5.2, extends §7's `WIST1-E08` row and §7's
idempotence sentence, and adds
`vectors/wist1/declaration-sequence.json` (generated by
`tools/gen_vectors.py`).

**What it states.** §5.2 required rejection under `WIST1-E08` when "`seq`
is not greater than the highest it has already accepted for that domain",
which reads on the re-fetch of an unchanged Declaration — and §5.1
requires that re-fetch, capping a cached Key Set at 24 hours. Under the
literal reading a Publisher whose keys never change fails validation on
every re-poll, and fails closed under §5.1's discovery rule, so no stable
Publisher could be validated at all. A Declaration whose inner `publisher`
object is byte-identical under JCS to the accepted one — equivalently, one
with the same `prev_declaration` hash — is therefore an idempotent
acceptance, exactly as a duplicate Delta is under §7. One carrying an
already-accepted `seq` with any other bytes stays `WIST1-E08`: that is the
superseded-replay case the rule exists to catch.

**Why it qualifies.** Both conditions hold. The rejection surface is
unchanged for every Declaration that differs in any byte, so nothing an
implementation previously rejected is now accepted except the case where
its input equals its own stored state; and the reading being corrected is
one no implementation could operate under, the standard §9 of WIST-4
applies to parameter values and the 2026-08-15 confirmation-window entry
applies to §5 — a reading that removes a mechanism is not a reading of the
suite.

**Status.** Exercised. `vectors/wist1/declaration-sequence.json` carries
nine cases over one stored Declaration: the identical re-serve, a same-`seq`
mutation, a stale lower `seq`, a missing and a mismatched
`prev_declaration`, an ordinary rotation, a recovery rotation, a
recovery-key alteration signed by a signing key, and a fresh identity.
`vectors:wist1-declaration-sequence` proves every case's envelopes are
schema-valid and verify under the key they name, so an expected
`WIST1-E08` is earned by sequencing and never by a broken signature.
## 2026-08-16 — WIST-2 §4, §7: the Feed-domain mismatch is `WIST2-E04` (revision, not errata)

Types §4's `feed.domain` mismatch rejection and extends the §7 `WIST2-E04`
row from two cases to three.

**What it states.** §4 required an Aggregator to "reject a Feed whose
`feed.domain` differs from the host it was fetched from" and named no
code, in a suite where §7's registry is the code inventory and typed
rejections are what a Publisher reads from the status endpoint (§7.1).
The rejection is now `WIST2-E04`, whose two existing cases are the same
failure — the Feed does not authenticate as this domain's — and whose
quota accounting is the one that fits: a misaddressed Feed is noise the
domain produced. §4's noise set is untouched and stays closed at
`WIST2-E02`/`WIST2-E04`, and the §10 checklist item that restates it needs
no change. The row's existing duty to distinguish its cases in the status
`detail` field now covers three.

**Why it is a revision.** It fails the first errata condition. The prior
text determined that the Feed is rejected and not what the rejection is
called, so an implementation that reported it as `WIST2-E01` conformed,
and under this change it does not. The defect is scoped and is the reason
the pin is worth making: `WIST2-E01` is "Feed unreachable after Ping" and
carries the 1/4/16/64-minute backoff, so that implementation retries four
times against a Feed that cannot become correct by being fetched again,
and reports an outage to a Publisher whose actual remedy is to fix one
string in a signed file. No new code is added and no other row moves.

**Status.** Unexercised. No vector serves a Feed at all;
`spec:wist2-feed-domain-mismatch` checks only that §4's sentence and the
§7 row name the same code and that §4's noise set is unmoved.

## 2026-08-16 — WIST-1 §4, §8: the Ed25519 verification profile (revision, not errata)

Adds a *What verification means, exactly* passage to §4, extends §8's
malleability bullet to point at it, and adds
`vectors/wist1/ed25519-strictness.json` (generated by
`tools/gen_vectors.py`). Decision record: ADR-0013.

**What it states.** Verification is cofactorless (`[s]B = R + [k]A`, no
cofactor on either side); `s` MUST be canonically reduced; `A` and `R` MUST
each be canonically encoded and MUST NOT be of small order. A signature
failing any of these is `WIST1-E01`, and a `keys` or `recovery_keys` entry
whose `public_key` is non-canonical or small-order is not admitted to the
Key Set, so a Delta naming it is `WIST1-E02`.

**Why it is a revision.** It fails the first errata condition. RFC 8032
§5.1.7 permits the cofactored equation, and recommends rather than requires
rejecting non-canonical encodings, so a verifier that took either option
conformed to §4's previous text — "a signature that does not verify against
Canonical Bytes under the key `sig.key_id` names is `WIST1-E01`" — and now
does not. The defect it is scoped to is stated in ADR-0013: a public key
carrying a torsion component admits signatures that satisfy the cofactored
equation and fail the cofactorless one, so two honest verifiers reading the
same Block reach opposite verdicts on the same Entry, which in a Log is a
fork with no attacker required.

**What it does not change.** No error code is added, the Envelope is
unchanged, and every signature an honest signer has ever produced still
verifies: canonical `R`, reduced `s`, prime-order `A`.

**Status.** Exercised. `vectors/wist1/ed25519-strictness.json` carries
seven cases — a valid signature, an unreduced `s`, a non-canonical and a
small-order `A`, a non-canonical and a small-order `R`, and a torsion-key
signature that the cofactored equation accepts and this profile rejects.
`vectors:wist1-verification-profile` recomputes every outcome from the
group arithmetic in `tools/ecvrf.py` rather than asserting the file.

## 2026-08-16 — WIST-1 §2: the Canonical Host flag profile (revision, not errata)

Pins `CheckHyphens=false`, `CheckBidi=true` and `CheckJoiners=true`
alongside the three flags §2 already named, forbids any lowercasing before
UTS #46 processing, and adds
`vectors/wist1/host-canonicalization.json`. Decision record: ADR-0014.

**What it states.** UTS #46's mapping step is the case operation and
nothing precedes it; the three previously unstated flags take the values
above. `CheckHyphens=false` is the profile browsers apply, on the grounds
that hyphen position inside a label is registry policy rather than
identity; `CheckBidi` and `CheckJoiners` stay on because they govern visual
confusability, which is what a domain-anchored identity is exposed to.

**Why it is a revision.** It fails the first errata condition twice over.
An implementation that reached for a library's strict entry point got
`CheckHyphens=true` and rejected hosts this text now accepts, and one that
lowercased with a context-sensitive full lowercase produced `xn--mxa8a`
where this text produces `xn--mxa0b` for the same input — so a Canonical
Host, a Record key and therefore a `content_digest` can change. The scope
is the three flags and the case step, and nothing further: `UseSTD3ASCIIRules`,
`Transitional_Processing` and `VerifyDnsLength` keep the values they had.

**What it does not change.** No host that was valid before becomes invalid.
The direction is one-way: `CheckHyphens=false` only admits labels the
stricter value rejected, and removing the lowercase step changes the result
only for inputs carrying an uppercase character whose full lowercase differs
from its UTS #46 mapping — final sigma being the case §2 already cited.

**Status.** Exercised. `vectors/wist1/host-canonicalization.json` carries
thirteen cases: the positional-hyphen and leading-hyphen discriminators,
the uppercase-sigma case that separates the two readings of the case step,
nontransitional `ß`, an A-label passthrough, and rejections for
`UseSTD3ASCIIRules`, `VerifyDnsLength`, `CheckJoiners` and `CheckBidi`.
`vectors:wist1-host-canonicalization` checks the vector's flag block against
§2's text and the shape of every accepted result; the expected A-labels are
independently reproduced by a second UTS #46 implementation.

## 2026-08-16 — WIST-1 §5.2, §7: what the recovery window admits, supersedes and settles (revision, not errata)

Extends §5.2's recovery-rotation bullet and its fresh-identity bullet, adds
the key-set disjointness rule to the recovery-keys paragraph, extends §7's
`WIST1-E08` and `WIST1-E13` rows, and adds
`vectors/wist1/recovery-settlement.json` plus two cases to
`vectors/wist1/declaration-sequence.json`. Decision record: ADR-0015.

**What it states.** A Delta is queued when it verifies under the union of
the pre-recovery Key Set and the recovery Declaration's own. At the window's
end every Declaration sealed inside it other than the recovery Declaration
and the chain legitimately following it is superseded — an ordinary rotation
and a fresh identity alike — and settlement revalidates each queued Delta
against that chain's newest Key Set. `WIST1-E13` drops the queued copy and
not the Delta's identity. Separately, `keys` and `recovery_keys` MUST name no
`key_id` and no `public_key` in common.

**Why it is a revision.** It fails the first errata condition in three
places. An implementation reading "queued rather than sealed" as admitting
only the pre-recovery set conformed and now does not; one rejecting an
in-window fresh identity with `WIST1-E08` conformed and now must accept and
supersede it; and one settling against "the recovery Declaration's" Key Set
literally conformed and must now follow the chain. The disjointness rule is
new prose that invalidates a previously schema-valid Declaration — including
this suite's own `examples/publisher.json`, which reused one test public key
under two `key_id`s and has been regenerated onto a second keypair.

**What it does not change.** The window's start, its length, the queueing
behavior, the `A`/`C` preservation, and the two-recovery-Declarations race
rule are untouched. No error code is added.

**Status.** Exercised. `vectors/wist1/recovery-settlement.json` carries five
cases over both derivations — admission by union, a superseded thief
rotation, a superseded fresh identity, a legitimate post-recovery rotation
that moves the chain head, and a chain extended through a recovery key —
recomputed by `vectors:wist1-recovery-settlement` from the case inputs.
`vectors/wist1/declaration-sequence.json` adds the in-window fresh-identity
acceptance and a Declaration naming one key in both sets.

## 2026-08-16 — WIST-2 §3.2: a sealed Page's `generated_at`

Adds a paragraph fixing which instant a sealed Page carries.

**What it states.** §3.2 resolves a Page's Key Set through its
`generated_at` — the bridge it calls "the only conversion permitted" — but
never said whether that field is the cutover instant or the instant the
Page's entries were first added to the Feed. It is the cutover: the same
value the `feed.json` published at that cutover carries.

**Why it qualifies.** Both conditions hold. The alternative reading is one
no implementation could conform to: a Page is signed at cutover by
whichever key the Publisher then holds, so stamping it with an earlier
instant resolves a Key Set that need not contain that key, and a Page
honestly sealed after a rotation would fail verification under its own
signature — while §3.2's neighbouring sentence forbids rejecting a Page
"solely because its signing key has since been retired". The reading now
stated is the one that leaves the mechanism standing, the same standard the
2026-08-15 confirmation-window entry applies.

**Status.** Unexercised. No vector seals a Feed Page; the rule rests on
§3.2's bridge and the signing order it implies.

## 2026-08-16 — WIST-4 §7: the escalation windows are measured like every other

Restates §7's escalation criteria in the window arithmetic §4 and §6.1
already use.

**What it states.** "3 within 90 days" and "3 severity-3 within 180 days"
are the 90 or 180 **whole days ending at** Block N's `sealed_at`: a
Confirmed Inconsistency counts when its confirming Block's §6.1 whole-day
distance from N is below 90 (or below 180), end-inclusive and
start-exclusive — the reading the 2026-08-15 entry pinned for every "30
whole days ending at" window.

**Why it qualifies. ** Both conditions hold. §6.1 defines whole-day distance
and §4 states the window form three times over; the escalation criteria are
the only spans in the document that named a number of days without the
phrase, and no other arithmetic is available to a conforming implementation.
Nothing that counted before stops counting except at the exact boundary,
where the suite's own convention already gave the answer.

**Status.** Exercised. `vectors/wist4/sanctions.json` carries the 89-day and
91-day rows; the boundary rows at exactly 90 and 180 days are added with
this change.

## 2026-08-16 — WIST-4 §4: `ECVRF_validate_key` is required (revision, not errata)

States that `ECVRF_verify` runs RFC 9381's optional key-validation step.

**What it states.** A `vrf_proof` under an Auditor public key that fails
key validation — a small-order or non-canonically encoded point — does not
verify, and the Record is void for standing (`WIST4-E01`).

**Why it is a revision.** RFC 9381 makes the step optional, so an
implementation that skipped it conformed to §4's citation of the ciphersuite
and now does not. The defect is scoped and stated: §11 relies on `beta`
being the unique correct output for a Block, and without key validation a
small-order Auditor key admits more than one valid `beta`, so an Auditor
could grind selection sets until one omitted the Deltas it preferred not to
audit — the steering §4 exists to make impossible. It is also the standard
WIST-1 §4 now applies to the Ed25519 keys this ciphersuite shares.

**Status.** Unexercised for the failure case: `tools/ecvrf.py` validates by
default and `vectors/wist4/sampling.json` carries a valid key, so no vector
yet presents a small-order Auditor key to be rejected.

## 2026-08-16 — WIST-4 §6.4: which height a Ping quota reads (revision, not errata)

States that `reputation_u` for the Ping quota is read at the highest Block
sealed before the current UTC day began.

**What it states.** Q is a per-UTC-day quantity, so it is computed once for
that day from the Log as it stood when the day began. A domain whose Log has
no earlier Block reads the empty log, which is the new-domain value §6.4
already gives.

**Why it is a revision.** §6.4 fixed the formula and left the height
unstated, so an implementation reading the current chain head at check time
conformed and now does not. The defect is that `WIST4-E06` makes a published
quota recomputation-checkable: under the chain-head reading, Q drifts every
hour inside one quota day and no third party can reproduce the Q a rejection
was measured against without knowing the instant of the check, which is not
in the Log.

**Status.** Unexercised. No vector computes a live quota; `vectors/wist4/
reputation.json` carries Q for given `reputation_u` values, which this
change does not touch.

## 2026-08-16 — WIST-4 §7: a late appeal is recorded and changes nothing (revision, not errata)

Adds a bullet fixing the disposition of an `appeal` served after its window
closed.

**What it states.** It MAY be sealed and SHOULD be, because it is a signed
Publisher statement and a rule permitting a silent drop is the suppression
§4's `pull_attestation` exists to end. It discharges no **T**, starts no
ruling deadline, and does not by itself alter the sanction's state; a
`sanction_lift` remains available and is recorded as the discretionary act
it is.

**Why it is a revision.** §7 fixed the duty only for an appeal "served
inside the appeal window", so an implementation that sealed a late appeal
and started a ruling clock conformed and now does not. The defect is that
under that behavior the appeal window is advisory: a filing weeks overdue
reopens a closed process and can void a sanction's state on a deadline the
Aggregator can no longer meet.

**Status.** Unexercised. No vector carries an appeal; the rule rests on §7's
deadline arithmetic.

## 2026-08-16 — WIST-4 §4, §9.1, registry-update schema: a `coverage_attestation` names its Block (revision, not errata)

Adds `block` to the attestation's REQUIRED `details`, completing the
2026-08-16 entry above.

**What it states.** The attestation names the audited Block by Block Hash —
the same value that names the Auditor's well-known records file — so its
`vrf_proof` has an input to verify against.

**Why it is a revision.** It adds a required field: an attestation that was
valid under the entry above is invalid under this one. The defect is the one
that entry recorded as open: a sealed attestation was bound to its Block
only by the `pull_attestation` that happened to list it, so a replaying party
holding an attestation without one could neither verify the proof nor tell
which duty it discharged.

**Status.** Exercised. `schema:wist4-coverage-attestation` now asserts that
an attestation omitting `block`, `vrf_proof` or `prev_record` fails schema
validation.

## 2026-08-16 — WIST-3 §5, `schemas/mirrors.schema.json`: the Mirror list has a shape (revision, not errata)

Pins the shape of `/log/mirrors.json`, adds its schema and an example.

**What it states.** It is an Envelope whose inner object is `mirrors`,
carrying `wist_version`, `updated_at` (descriptive; no window reads it) and
`mirror_urls` — `https` base URLs ending in `/`, so a Consumer resolves Log
paths by concatenation rather than by a join rule two implementations could
differ on.

**Why it is a revision.** §5 required the file to be signed and to list base
URLs and nothing more, so an implementation that invented an inner name and
field set conformed and now does not. The defect is that §5 instructs
Consumers to read the file: it was the only artifact in the suite a party is
told to consume and given no shape for, which made the in-band Mirror
discovery it describes unusable across implementations.

**Status.** Exercised. `examples/mirrors.json` is generated by
`tools/gen_vectors.py`, validated against the new schema, and its signature
recomputed by the harness's envelope sweep.

## 2026-08-16 — WIST-3 §7: the `parameter` tuple is keyed by identifier and `effective_at` (revision, not errata)

Moves `effective_at` from the `parameter` tuple's value fields to its key
fields, and states why.

**What it states.** One tuple exists per amendment, not per identifier. A
`parameter_change` sealed at or before `log_position` but effective after it
is live state a resuming Consumer cannot re-derive — it will never see that
Entry again — so the artifact carries both the value in force and any
pending one, and the Consumer applies each at its own instant.

**Why it is a revision.** The member order of a tuple is normative and the
`state_digest` is computed over the tuples, so a state artifact written
under the previous table produces a different digest. The defect is that the
previous key admitted one tuple per identifier: a snapshot taken between a
`parameter_change`'s sealing and its `effective_at` had to drop either the
value in force or the one about to take effect, and a Consumer resuming from
it applied the wrong value from that instant onward.

**Status.** Exercised. `schema:wist3-parameter-effective-at` validates the
re-ordered tuple and rejects a height, an offset form and a date in the
`effective_at` position.

## 2026-08-16 — WIST-3 §4: the empty-Block vector

No document text changes. Adds `vectors/wist3/empty-block.json`, generated by
`tools/gen_vectors.py`.

**What it states.** What §4 already states: a Block with no Entries carries
`merkle_root` = SHA-256(0x00), this suite's one deviation from RFC 6962,
whose empty-tree constant is SHA-256 of the empty string. The vector
publishes both constants side by side, with a signed heartbeat Block whose
`block_hash` is SHA-256 over its header's JCS bytes.

**Why it qualifies.** §4 states the rule and warns that "implementers wiring
in an existing Certificate Transparency library MUST special-case empty
Blocks"; the vector executes that warning rather than adding to it. It is
also the case implementations demonstrably get wrong: wiring in a CT
library without the special case rejects legal heartbeat Blocks.

**Status.** Exercised. `vectors:wist3-empty-block` recomputes both
constants, the Block Hash and the signature.

## 2026-08-21 — WIST-4 §3, §5, §6.1, §7, §10, §11, §13; WIST-3 §6.1; WIST-2 §3.1; WIST-1 §3.3; audit-record schema: the audit reference is the chain tip at fetch (revision, not errata)

Adds `reference_delta` to the Audit Record — the newest Delta of the
audited Delta's per-URL chain sealed at or before `fetched_at` — and
resolves the Reference Payload, the change type the `delete` mirror and
the link dimension read, and §6.1's `C` as of that Delta instead of the
audited one. §3 and the `WIST4-E02` row gain three rejections over the
reference; §7's severity bands, §11's `C` and severity readings and
§13's Auditor checklist all read the reference Delta's change type.
WIST-3 §6.1's resolution rule is unchanged in substance and restated
relative to the named Delta; WIST-2 §3.1's retention sentence now says
what the retention serves; WIST-1 §3.3's description of what an `attest`
is measured against is restated to name the reference Delta rather than
the last content-bearing Delta at or before the `attest`.
`decisions/0016-audit-reference-follows-the-chain.md` records the
decision. Adds `vectors/wist4/superseded-audit.json`, generated by
`tools/gen_vectors.py`; `examples/audit-record.json` and
`vectors/wist4/audit-commitments.json` regenerate with the member.

**What it states.** An audit measures the page against the Publisher's
latest sealed claim at the instant of the fetch. Under the previous text
an honest rewrite sealed inside the audit window of the Delta it
replaced scored as fabricated content against every Auditor that
fetched after it — the extension rule summons them all after the first
divergence — and a single such confirmation is level 3 of the ladder.
The alternative of reading the maximum over later Payloads sealed before
the Record's Block is rejected in the ADR: a Publisher alternating false
and true `update`s defeats it without detecting the fetch.

**Why it is a revision.** It fails the first condition. A Record
conforming to the previous text carries no `reference_delta` and is
schema-invalid now; and for a URL whose chain advanced before the fetch,
the previous text and this one read different verdicts from the same
fetch. It is scoped to the defect: selection, coverage, the extension
rule, confirmation, severity and the penalty's identity are untouched.

**Status.** Exercised. `vectors:wist4-superseded-audit` recomputes every
case — the reference an honest Auditor names, the anchor as of it, the
reading change type, the verdict, `C` eligibility and the three
rejections — and its twin proves the check sees a moved reference; the
example Record carries the member.

## 2026-08-22 — WIST-4 §6.1, vectors: a vector states no rule or formula (revision, not errata)

Removes `note` from `vectors/wist4/decay-table.json` and `formula` from
`vectors/wist4/reputation.json`; shortens the file-level `note` of
`vectors/wist3/empty-block.json` and of `vectors/wist4/{confirmation,
coverage,derivation,extension,link-agreement,sanctions,superseded-audit}.json`
to a section pointer and the file's member layout; and rewrites two
per-case notes in `reputation.json` to describe the input only. Each
removed sentence restated the rule or formula the file's values are
computed from — the §6.1 formulas, the hashing rule, window endpoints,
tiebreaks, the link-agreement formula, an expected `Q`.
`tools/gen_vectors.py` no longer emits them. The §6.1 pin on the decay
table's bytes moves from
`f0cd1eb48cbfb1647a083b4ba06e7f69e6c42d5b5f4bf8e4f42b97c6bfdf7dc1` to
`1ef9e9be20c99e595c1c75c5ab63409e1cc4f9540b466b67ecebf4e2959986b9`. No
value in any file changes.

**What it states.** A rule has one statement, in the prose; a vector
holds inputs and expected outputs. A paraphrase inside a vector is
checked by nothing — the validator recomputes values, not notes — so it
drifts from the prose silently, and being shorter it is the copy an
implementer reads first; and a reader deriving the expected values from
the prose alone, the check that detects a wrong vector, gets the answer
handed to them by the file they are meant to check. The per-case `why`
members of the WIST-1 vectors are kept: they cite the clause a case
exercises, which is what a failing case needs, and state no procedure.

**Why it is a revision.** It fails the first condition. §6.1 makes the
decay table normative as bytes, so an implementation carrying the
previous file — which conformed — no longer hashes to the pinned digest.
Every other edit is to text no implementation reads. The change is
scoped to the prose members and the pin; every value is unchanged.

**Status.** Exercised. `vectors:wist4-decay-table` asserts the file's
structure and that its digest is the one §6.1 pins; every other vector
check recomputes the values the removed text described.

## 2026-09-04 — WIST-4 §3, §4, §5, §9, §10, §13: an extension Record's proof is over B₁ (revision, not errata)

Fixes which Block an Audit Record produced under §4's extension rule
carries its `vrf_proof` for: *B₁*, the Block that sealed the triggering
Record, as §4 stated — and not the Block carrying the audited Delta, as
§3's rejection bullet and §5's field definition stated. §3's proof
bullet now names both paths to standing and says the proof names which;
§3's `fetched_at` interval opens at the Block the proof is over; §4's
extension paragraph says what the proof over *B₁* binds and that the
Record is served at *B₁*'s records path and counted against the
(Auditor, *B₁*) pair; §4's transport paragraph reads "for a Block" and
pulls after the later deadline; §5's definition names the Block "in
whose selection set the Auditor holds `audited_delta`"; §9's combination
rules bound the extension span by `coverage_deadline_hours`; the
`WIST4-E01` row and the Auditor checklist follow. Adds
`vectors/wist4/extension-proof.json`, generated by `tools/gen_vectors.py`.

**What it states.** The extension rule enters a Delta into the selection
set *for B₁*: the Auditor must be admitted at *B₁*'s `sealed_at`, its
deadline runs from *B₁*, and the transport keys every duty on one Block.
A proof over the audited Block cannot serve that Record — an Auditor
admitted after the audited Block and summoned at *B₁* holds no key that
was admitted at the audited Block, and the draw such a proof demonstrates
is one that did not select the Delta, which establishes nothing. A proof
over *B₁* is verified under the key admitted there and located from the
Log: *B₁* is the Block that sealed the Record which named the Delta for
this Auditor. The `fetched_at` interval follows the same Block, because
the reason its lower end holds — a selection derived from a Block Hash
cannot precede that Block — is a reason about the Block the proof is
over. The new §9 bound keeps the Aggregator's single pull per Block after
every duty that Block carries, which the defaults (36 and 72 hours)
already satisfied.

**Why it is a revision.** It fails the first condition. Two sections
stated different Blocks, so an implementation could conform to either;
one following §3 and §5 produced extension Records whose proofs are over
the audited Block, and those are `WIST4-E01` now. The `fetched_at` lower
bound tightens for extension Records. It is scoped to the defect: the
VRF path, the rule's trigger, ration, summons and deadline are untouched.

**Status.** Exercised. `vectors:wist4-extension-proof` recomputes, for
one Auditor key, the audited Block and *B₁*, the standing each of four
proofs earns — over *B₁* with the summons, over the audited Block with an
unselected Delta, over neither Block, and over *B₁* without the
summons — and its twin proves the check sees a proof moved to the other
Block and a summons withdrawn.

## 2026-09-04 — WIST-4 §3, §4, §10, §13: one admitted key per Auditor per height

Extends §3's paragraph on the shared key with the rule that an
`auditor_id` holds at most one admitted key at any height, states which
key a Block's proof and a Record's signature read across a rotation,
and names the rejection of an overlapping `auditor_admit`; §4's rotation
paragraph gains the same-Block ordering — a removal sealed at an
instant ends the old key's tenure before an admission sealed at that
instant is read — and the rejection of an `auditor_remove` naming a key
its subject does not hold. §10 gains `WIST4-E07`, the roster row, for
the rejections §3 and §4 already mandated without a code; the
recomputing-party checklist follows. Adds `vectors/wist4/roster.json`,
generated by `tools/gen_vectors.py`.

**What it states.** §3 already says the one admitted `public_key`
verifies signatures and proofs alike and that "no second key is
admitted", and §4 fixes every duty to "the key admitted at the relevant
Block's `sealed_at`" in the singular. What neither said in so many words
is what follows when an `auditor_admit` lands beside a live key: the
Auditor would hold two draws for every Block and could publish whichever
selected less, which is the steering §4 exists to remove. The tenure
bounds make "admitted at" and "removed at or before" one reading —
held from the admit's `sealed_at` to the remove's, the latter excluded —
and the same-Block ordering is what §4's rotation, a removal and an
admission "sealed" together, needs in order to be lawful under the
one-key rule. A remove naming a key the subject does not hold is
rejected because it retires nothing; the text made no other reading
available.

**Why it qualifies.** Both conditions hold. No conforming roster held
two keys at once — the text said no second key is admitted — so nothing
a conforming implementation sealed is rejected now; a Log that did seal
an overlapping admission was not conforming to §3, and this entry
states which of its acts a replayer ignores. The codes name rejections
already required.

**Status.** Exercised. `vectors:wist4-roster` recomputes eight Log
prefixes — a same-Block rotation, an overlapping admission, a retired
`key_id` re-admitted, a subject barred for cause, an exit followed by
re-entry, a removal's instant, a subject dependent on `log_id`, and a
remove of a key not held — reporting the rejected indices and the key
held at queried instants; its twin proves the check sees a rotation
whose removal is missing and the instant before a removal.

## 2026-09-04 — WIST-1 §3.5, §7; WIST-2 §5; WIST-3 §7, §8: a `prev` is sealed before the Delta naming it (revision, not errata)

Adds a paragraph to WIST-1 §3.5 fixing what "seen" means for an
Aggregator and the order in which a chain seals; rewords the `WIST1-E07`
row's "non-existent" as "not sealed at a lower Log position"; has WIST-2
§5's pull step retrieve and validate an unsealed `prev` first, in chain
order; and restates WIST-3 §7's fork sentence and §8's cold-start check
as one tip rule — a Delta whose `prev` is not the chain tip the state
carries for its key is ignored and moves no tip, whether it forks a
sealed chain or names a `prev` nothing sealed. Adds
`vectors/wist3/chain-materialization.json`, generated by
`tools/gen_vectors.py`.

**What it states.** §3.5's retrieval duty exists so that the Aggregator
can seal the `prev` first: a retrieved Delta enters ingest as any served
one does, under the same budget, and a Delta is never sealed ahead of the
Delta its `prev` names. A `prev` that is not and cannot be sealed lower —
unavailable, or itself rejected — is `WIST1-E07` for the Delta naming
it. On the Consumer side the fork rule and this one are the same test:
`prev` equals the tip, or the Delta is ignored. Reading it as one rule
is what a state artifact makes checkable — it carries chain tips, not
every sealed ID — and what keeps WIST-4 §5's chain walk and §7's anchor
resolution over Deltas the Log actually holds.

**Why it is a revision.** It fails the first condition. "Non-existent"
admitted a reading under which the Aggregator retrieved the `prev` to
check that it existed and sealed the successor without it; a Consumer
applying such a Delta conformed to the fork rule as written, and ignores
it now. It is scoped to the ordering invariant: what a Delta must carry,
what a fork is, and what retrieval obliges are unchanged.

**Status.** Exercised. `vectors:wist3-chain-materialization` recomputes
seven Logs — a linear chain, a fork, an unsealed `prev`, the successor of
an ignored Delta, a chain continuing through a `delete`, a second
`prev`-less Delta, and two Publishers on one URL — reporting the ignored
indices and the tips; its twin proves the check sees the `prev` a Delta
names and which Delta sealed first.

## 2026-09-04 — WIST-4 §4, §10, §13: a parent's Delta for a self-declared host is not selectable (revision, not errata)

Defines a Block's **selection domain** in §4 — its `publisher_delta`
Deltas less those WIST-3 §7's one-URL, one-Publisher rule excludes from
materialization at the Block's height, a parent's Delta for a host whose
own `seq`-0 Declaration Entry is sealed at or below the Block — and runs
the VRF test over it; a Delta outside the domain is in no Auditor's
selection set by either path, so a Record for it is `WIST4-E01` and
triggers no extension. The `WIST4-E01` row and the Auditor checklist
follow. Adds `vectors/wist4/selection-domain.json`, generated by
`tools/gen_vectors.py`.

**What it states.** WIST-1 §3.2 keeps both Publishers' Deltas valid for
a host inside two authorities, and WIST-3 §7 decides which one
materializes: from the subdomain's own Declaration onward, only the
subdomain's. §4 as written drew over every Delta of the Block, so the
parent's later Deltas for that host — sealed, valid, and consumed by no
party — were audited like any other, spending fetches on inert claims
and measuring the parent's Payload against a page the subdomain serves.
The domain excludes exactly the materialization exclusion, and reads
Declaration heights every Auditor replays already; selection stays
recomputable from the Log alone.

**Why it is a revision.** It fails the first condition. Records for such
Deltas verified under §4 as written and enter no replay now, and an
Auditor that skipped them was in coverage failure as written and is not
now. It is scoped to the domain the draw runs over: the draw, the
extension rule and the coverage duty are unchanged.

**Status.** Exercised. `vectors:wist4-selection-domain` recomputes
seven Blocks — a Publisher's own host, a parent's Delta before, at and
after the subdomain's Declaration height, the subdomain's own Delta, an
unrelated Declaration, and a mixed Block — reporting the excluded
indices; its twin proves the check sees the Declaration's height and
whose Delta it is.

## 2026-09-04 — WIST-3 §5, §12: a Block is durable before its Checkpoint

Adds to §5 that the Aggregator MUST NOT publish the Checkpoint for Block
N before Block N and every lower Block are durably stored and
retrievable at their §6 paths, what a Checkpoint published earlier
commits it to, and that a Consumer holding a Checkpoint whose Block no
source serves has an uncleared `WIST3-E01`, never a `WIST3-E02`. The
Aggregator checklist line follows.

**What it states.** §5 already makes a Checkpoint the equivocation
evidence — two validly signed Checkpoints for one `block_number` with
different hashes — and §6 already requires every Block retrievable from
genesis. A Checkpoint published before its Block is durable can only be
honored by re-sealing the same bytes; any other Block N the Aggregator
seals after losing the first is the second Checkpoint's hash, and the
Aggregator has equivocated against itself with no adversary. The order
was implied by what the two artifacts are; this states it, and says what
a Consumer that meets the gap concludes.

**Why it qualifies.** Both conditions hold. An Aggregator that published
Checkpoints only for Blocks it served conformed and still does; a
Consumer already fetched a missing Block from another source under
`WIST3-E01`, and the entry only forbids it from reading the absence as
divergence.

**Status.** Unexercised. The order is a serving discipline over two
artifacts the harness verifies separately; nothing recomputable
distinguishes a Checkpoint published before its Block from one published
after.

## 2026-09-04 — WIST-4 §6.1, §6.3: an audit belongs to the identity whose Delta it audited (revision, not errata)

Restates §6.1's identity scope so that an Audit Record — the
`consistent` one `C` counts, the confirming one a Confirmed
Inconsistency rests on — belongs to an identity by the sealing height
of its `audited_delta`, never by its own; the `C` and penalty bullets of
§6.1 and §6.3 follow. Adds the straddling case to
`vectors/wist4/derivation.json`, whose Records now carry
`audited_height`, generated by `tools/gen_vectors.py`.

**What it states.** §6.3 says a fresh identity "starts clean" because
"it is a different party as far as the protocol can tell", and scopes
`A` by the Delta's own height. Scoping a finding by its confirming
Record's height instead let a Delta the previous identity sealed at or
below `R`, audited inside its own window or under §4's extension rule
and confirmed above `R`, land its penalty — and under §7 its ladder rung
— on the party that never published it; the same asymmetry credited a
fresh identity with `C` for a `consistent` Record on the previous
identity's Delta. The finding follows the claim: a Record counts against
N by its own height, as before, and against the reset by the height of
the Delta it audited.

**Why it is a revision.** It fails the first condition. A replayer
scoping by the confirming Record's height conformed to §6.1 as written
and derives a different `C` and `penalty_n` wherever an audit straddles
a reset. It is scoped to the reset bound: the ≤ N bound, `t_i`'s
measurement from the confirming Block, and what an identity reset is are
unchanged.

**Status.** Exercised. `derivation.json`'s straddling case seals
`consistent` and confirming Records above `R` for Deltas on both sides
of it, and its expected `c` and `penalty_inputs` count only those whose
`audited_height` is above `R`.

## 2026-09-04 — WIST-4 §10: which `WIST4-E01` voids still discharge the coverage duty

Rewords the `WIST4-E01` row's closing clause. It read "no coverage
discharge" over every void case; it now applies §3's carve-out — a
Record void only because its key was removed after the audited Block's
`sealed_at`, or because its Auditor is in coverage failure at sealing,
still discharges the §4 duty anchored at the audited Block — and says
of the remaining cases that no duty existed to discharge. Adds
`discharge_cases` to `vectors/wist4/coverage.json`, generated by
`tools/gen_vectors.py`.

**What it states.** §3 already says so in as many words: the removal and
coverage-failure rejections "are scoped to reputation and do not reach
coverage", because the duty is anchored to the audited Block's
`sealed_at` and not to the height at which the Record lands, and an
Auditor in coverage failure "still discharges — and can still recover
from — the duty by publishing". §4 anchors the duty the same way. The
§10 row contradicted both, and a party following the row would count an
Auditor's Records as failures for the Blocks it covered while removed
or in coverage failure — extending a removal into the coverage failures
§4 says removal does not create, and making coverage failure a state no
publication could end. The other four cases are Records for which §4
names no duty: a key never admitted at the audited Block, a proof that
binds the Record to no Block that selected or named the Delta for it, a
Delta outside the selection domain, a self-audit.

**Why it qualifies.** Both conditions hold. §3's carve-out is normative
text a conforming coverage derivation already applied; the row is the
registry's summary of it and now agrees. Nothing a party derived under
§3 and §4 changes.

**Status.** Exercised. `coverage.json`'s `discharge_cases` list each
`WIST4-E01` case with whether a Record void for that reason discharges
the duty; only the two §3 carve-outs and a standing Record do.

## 2026-09-04 — WIST-1 §5.2, §7, §10; WIST-2 §5; WIST-3 §3.3, §12: a Delta is sealed only where the Key Set at its height verifies it (revision, not errata)

Adds a paragraph to WIST-1 §5.2's historical verification: the Key Set
it resolves is the one a sealed Delta MUST verify under, and an
Aggregator MUST NOT seal a Delta that fails it at its sealing height,
the sealing Block's own Declaration Entries included — a Delta a
Declaration accepted since the pull has stranded is sealed below that
Declaration while its Block is open, or is `WIST1-E02` at sealing,
reported and never sealed; a Consumer that meets one in a Log ignores
the Entry as it ignores a fork. The `WIST1-E02` row, WIST-2 §5's queue
step, WIST-3 §3.3's application-order paragraph and the three
checklists follow. Adds `vectors/wist1/keyset-at-height.json`,
generated by `tools/gen_vectors.py`.

**What it states.** §5.2 resolved a Delta's Key Set by the highest-`seq`
Declaration sealed at a height ≤ N, and WIST-3 §3.3 applies Declarations
before Deltas inside a Block; nothing said whether ingest-time
verification was sufficient for sealing. It is not: a Delta signed by a
key the Publisher retires between the pull and the seal verifies at
ingest and fails on every replay once sealed beside or above the
retiring Declaration. The only hold rule in the suite covers an unsealed
Declaration, not a Delta the next Declaration strands. The remedy is
the Publisher's and cheap — the Delta ID is over the inner object, so a
re-signed copy has the same ID and is pulled again — and sealing the
stranded Delta anyway would honor a key the Publisher's newest
statement retired, which is the wrong side of a rotation performed
because that key was lost.

**Why it is a revision.** It fails the first condition. An Aggregator
that verified at ingest only conformed, and can seal a Delta every
replayer rejects; it now must revalidate at sealing. It is scoped to the
seal: the resolution rule, the recovery exception and the
Declaration-first application order are unchanged, and a Consumer's
disposition of the breach is the fork rule it already applies.

**Status.** Exercised. `vectors:wist1-keyset-at-height` recomputes the
Key Set at every height of three cases — a rotation retiring the old
key, one keeping it, and a Delta below every Declaration — and which
Deltas verify: the discriminating Delta is the one sealed beside the
retiring Declaration, which its twin proves the check rejects only
because the Declaration is read at its own Block and not one later.

## 2026-09-04 — WIST-1 §5.1; WIST-2 §5, §7, §10: a Feed signature failure re-fetches the Declaration before it counts (revision, not errata)

Adds to WIST-2 §5 step 1 that a Feed whose signature does not verify
against the Key Set the Aggregator holds MUST trigger one re-fetch of
`publisher.json`, evaluated under WIST-1 §5.2, and a second
verification of the same Feed bytes, before the pull is `WIST2-E04`;
the `WIST2-E04` row and the Aggregator checklist follow, and WIST-1 §5.1
says of its cache that a signature failing under it is the observation
that obliges the re-fetch.

**What it states.** WIST-1 §5.1 lets a validator cache a Key Set for 24
hours, and WIST-2 §5 re-fetched the Declaration only on first contact.
A Publisher that rotates and signs its next Feed under the new key was
therefore `WIST2-E04` on every pull until the cache expired — noise
against its own quota, with its Deltas stalled for up to a day — for
doing exactly what §5.2 tells it to do. A failing signature is the one
observation that distinguishes a stale cache from a bad Feed, and one
re-fetch settles which: a Feed that fails under the current Declaration
too is the rejection it always was.

**Why it is a revision.** It fails the first condition. An Aggregator
that re-fetched only on first contact conformed to §5 as written and
does not now. It is scoped to the failing pull: the TTL, first contact,
the noise set and every other rejection are unchanged, and an
Aggregator that already re-fetches the Declaration on every pull
satisfies it as it stands.

**Status.** Unexercised. No vector serves a Feed; the rule is a fetch
discipline over two artifacts the harness verifies separately.

## 2026-09-04 — WIST-1 §5.2: recovery keys protect themselves against a fresh identity too

Rewords the recovery-keys rule's first sentence: every later Declaration
*not signed by one of the recovery keys* MUST carry a byte-identical
`recovery_keys` — one signed by a signing key and one signed by neither
set alike — and says why the rule reads the signer and not the
classification. Adds the fresh-identity-dropping-recovery-keys case to
`vectors/wist1/declaration-sequence.json`, generated by
`tools/gen_vectors.py`.

**What it states.** The sentence bound the byte-identical rule to
Declarations "signed only by a signing key", while the fresh-identity
bullet accepts a Declaration "signed by neither", so a fresh identity
omitting `recovery_keys` read as `WIST1-E08` under the paragraph's
second sentence — "a Declaration that adds, removes, or alters a
recovery key MUST be signed by one of the recovery keys it is
replacing" — and as an accepted reset under the first. The second
sentence already decided it: it names no signer class, and the
rationale beside it needs the reading — a thief holding only the web
server could otherwise shed the owner's recovery keys with a fresh
identity as surely as a thief holding a signing key could with a
rotation, severing the path back the mechanism exists to keep open.

**Why it qualifies.** Both conditions hold. The second sentence
required the rejection already; the first now agrees with it, and a
fresh identity that carries the recovery keys byte-identical — the
vector's existing case — is accepted as before.

**Status.** Exercised. `vectors:wist1-declaration-sequence` carries a
fresh identity that omits the stored `recovery_keys`, expected
`WIST1-E08`, beside the existing fresh identity that carries them.

## 2026-09-04 — WIST-2 §3.2, §10: a Page cut before its Declaration sealed (revision, not errata)

Adds a second resolution to §3.2's Page verification: a Page whose
signing key the Key Set current at `generated_at` does not hold
verifies if that key is in the Key Set of the first applicable
Declaration sealed after `generated_at`; a Page that verifies under
neither is `WIST2-E04`. The paragraph explaining the gap follows the
bridge, and the Aggregator checklist gains the line. Adds
`vectors/wist2/page-keyset.json`, generated by `tools/gen_vectors.py`.

**What it states.** §3.2 resolved a Page's Key Set by the Declaration
with the greatest `sealed_at` not later than `generated_at`, and only
that. A Publisher that rotates and cuts a Page in one act signs it
under a key no sealed Declaration yet holds, because the Declaration
seals only when an Aggregator next pulls it; a Publisher that cuts
Pages before any Aggregator has pulled it at all has every one of them
dated before its first Declaration sealed, so the rule as written
resolved no Key Set for them and its entire history was unpullable.
Deltas have a hold and a seal-time check (WIST-1 §5.2, WIST-3 §3.3); a
Page is never sealed, so the only place the gap can close is the
validator's resolution. The first Declaration after `generated_at` is
the Publisher's own act attested one seal late, and reading only the
first keeps a Page from claiming a key two rotations ahead.

**Why it is a revision.** It fails the first condition. A validator
applying the single resolution conformed, and rejected Pages that now
verify. It is scoped to Pages: the bridge's ordering, the recovery
exception and every Delta rule are unchanged.

**Status.** Exercised. `vectors:wist2-page-keyset` recomputes both
resolutions for four cases — a Page cut after its Declaration sealed,
one cut between a rotation and its sealing, one cut before first
contact, and one whose `generated_at` equals a sealing instant — and
which a Page verifies under; its twin proves the check rejects a key
from the second Declaration ahead and does not verify the between-case
Page from the current Key Set alone.

## 2026-09-04 — WIST-4 §9, §13; WIST-3 §7: when a `parameter_change` is in force

Adds an **In force** paragraph to §9: an amendment is in force at every
instant at or after its `effective_at`, the endpoint included; the value
in force is that of the amendment with the greatest `effective_at` at or
before the instant, the default where none; an equal pair is broken by
Log order, the later prevailing and the earlier never in force; and Log
order decides nothing else, so two pending amendments take effect each
at its own instant whichever sealed first. WIST-3 §7's `parameter`
tuple paragraph restates the endpoint and says a superseded amendment
is not state; the recomputing-party checklist gains the line. Adds
`vectors/wist4/parameter-in-force.json`, generated by
`tools/gen_vectors.py`.

**What it states.** "In force at T" when `effective_at` equals T was
undefined, and the case is not marginal: the grace period is seven
days after a `sealed_at`, which on the Block grid is itself a
`sealed_at`, and WIST-3 §3.1 reads the cadence "in force at the
previous Block's `sealed_at`" — so every cadence change lands its
endpoint on exactly the instant the next Block reads. Inclusive is the
reading under which the change governs the Block it was timed for.
WIST-3 §7 already had a Consumer apply each of two pending amendments
"at its own instant", which is the greatest-`effective_at` rule stated
from the other side, and a pair sharing an instant needed the one
order every replayer holds.

**Why it qualifies.** Both conditions hold. Nothing in the text
supported the exclusive reading against the inclusive one; WIST-3 §7
implied the ordering; and the tie rule is the suite's standing answer
to a race, Log order, applied where the text was silent.

**Status.** Exercised. `vectors:wist4-parameter-in-force` recomputes
the value in force at queried instants for five cases — the endpoint
itself, a pair whose Log order and `effective_at` order disagree, an
equal pair across Blocks, an equal pair inside one Block, and a
superseded pair followed by a later amendment; its twin proves the
check fails an exclusive endpoint and sees which of an equal pair
sealed later.

## 2026-09-04 — WIST-4 §5: the unauditable horizon is measured like every other window

Rewords §5's unauditable predicate: each blocking Record is sealed
"inside the 30 whole days ending at Block N's `sealed_at`" —
end-inclusive and start-exclusive, as §4 and §7 measure theirs — in
place of "no more than 30 whole days before", and the clearing Record
is sealed at or below N. Adds `vectors/wist4/unauditable.json`,
generated by `tools/gen_vectors.py`.

**What it states.** "No more than 30 whole days before" admitted a
Record sealed exactly 30 whole days before N; every other window in the
document — the coverage and ration windows of §4, the escalation
windows of §7, as the 2026-08-16 entry on the latter records — excludes
its start, so a blocking Record on the thirtieth day would have been in
one implementation's predicate and outside another's. The common form
is the one the document already declares to be the only way a window
is measured. That a clearing Record must be at or below N was implied
by the predicate being evaluated "at height N" over the Log the party
holds.

**Why it qualifies.** Both conditions hold. The document states one
window discipline and applied it everywhere else; this row now follows
it. No implementation computed the predicate under the other reading.

**Status.** Exercised. `vectors:wist4-unauditable` recomputes the
predicate for nine cases, among them a second blocking Record sealed
exactly 30 whole days before N (aged out) and one sealed a second
inside the horizon (counted); its twin proves the check flips on a
horizon read end-inclusive at 30.

## 2026-09-04 — WIST-4 §6.1, §9; registry-update schema: the decay constant carries no identifier, and the horizon amends only downward (revision, not errata)

Removes `decay_constant_days` from §9's bounds table, the identifier
column of its defaults table and the `parameter_change` enum in
`schemas/registry-update.schema.json`; bounds `decay_horizon_days` at
the table's last index, 1825, in §9 and the schema; has §6.1 say that
changing the table is not a `parameter_change` and that `decay(t)` is
zero above the horizon in force rather than above 1825; corrects §9's
abbreviated decay-table digest to the value §6.1 pins; and adds a
schema twin to `tools/validate_examples.py`.

**What it states.** §6.1 makes the decay table normative as bytes —
"implementations MUST read it and MUST NOT recompute it at runtime" —
while §9 listed the constant it was generated from as an amendable
identifier, so a schema-valid `parameter_change` to
`decay_constant_days` had no defined effect: no party may regenerate
the table, and the table in force still hashed to the pinned digest.
§9's own second reason for an identifier's absence — a value "changed
by publishing a new artifact rather than a bare number, as the decay
table digest is" — already covered the constant, and §6.1's closing
sentence, which called a table change "a `parameter_change` like any
other constant", contradicted it. The horizon is different: a shorter
one reads a prefix of the table and is well-defined, a longer one
reads entries the table does not have, so it stays amendable with the
table's length as its ceiling. The §9 digest row still abbreviated the
value the 2026-08-22 entry replaced.

**Why it is a revision.** It fails the first condition. An Aggregator
that sealed a `parameter_change` to `decay_constant_days`, or to a
horizon above 1825, conformed to the schema; a replayer now rejects
both as `WIST4-E03`. It is scoped to the two rows: the table, its
digest and every reputation computed from it are unchanged.

**Status.** Exercised. `spec:parameter-registry-enum` holds §9's table
and the schema's enum to the same identifier set, so neither can
re-admit the constant alone; `negative:wist4-decay-parameters` proves
the schema rejects a change to the constant and a horizon of 1826 and
accepts 1825 and a horizon inside the table, and that the bound is the
table's length.

## 2026-09-04 — WIST-2 §5, §10: what "already seen" means

Adds to §5 step 2 that an ID is seen when the Aggregator has sealed it
or holds it accepted for sealing — queued, or held under a recovery
window — and not otherwise, so a rejected ID is pulled again on the
next pull, rejected again if it still fails, and disposed of against
the quota as §4 says for its code; the Aggregator checklist follows.

**What it states.** "The IDs it has already seen" was undefined. Under
the natural reading — anything ever fetched — an ID rejected for a
transient cause was never pulled again, and because a byte-identical
republication has the same ID, a Publisher could not recover from a
momentary `404` or a skewed clock without changing its Delta. WIST-1
§3.5 already fixed the term for an Aggregator's `prev` retrieval —
"to have seen a Delta is to have sealed it or to hold it accepted for
sealing" — and step 2 now reads the same definition. Nothing in §4's
noise set changes: a re-pull is a pull, and its code decides the rest.

**Why it qualifies.** Both conditions hold. The term was defined once,
in WIST-1 §3.5, and §5 now points at it; an Aggregator that re-pulled
rejected IDs conformed and still does.

**Status.** Unexercised. No vector serves a Feed; the rule is a
bookkeeping discipline over pulls the harness does not model.

## 2026-09-04 — WIST-4 §6.4, §13; WIST-3 §3.2: the inclusion ceiling runs from a Delta's turn under the per-domain capacity (revision, not errata)

Adds to §6.4's inclusion-latency rule that eligibility is gated by
WIST-3 §3.2's per-domain Block capacity — a domain's eligible Deltas
take the capacity in acceptance order, and one the cap holds out of a
Block becomes eligible for the first Block with room for it, where its
ceiling's clock starts; WIST-3 §3.2's capacity paragraph and the
Aggregator checklist say the same from their side.

**What it states.** §3.2 caps a domain at `domain_block_entries_max`
Entries per Block (default 10 000) and §6.4 requires an accepted Delta
sealed within `max_inclusion_blocks` (default 4) of its eligibility
Block, and nothing related them: a backfill of 50 000 Deltas accepted
at once had to breach one MUST or the other. The cap is a bound on
rate and the ceiling a bound on the Aggregator's delay; making the cap
a gate on eligibility keeps both, since a Delta whose turn has not come
is not one the Aggregator is shelving. Acceptance order is the only
order the Aggregator can be held to — the ceiling is already
observable by the Publisher rather than derivable from the Log — and
it is the order §6.4's duty was implicitly stated over.

**Why it is a revision.** It fails the first condition. An Aggregator
that sealed a domain's surplus above the cap conformed to §6.4 and
breached §3.2, or the reverse; neither is conforming now, and an
Aggregator's seal must apply both bounds. It is scoped to the
relation: both values, the eligibility latencies and the recovery hold
are unchanged.

**Status.** Unexercised. The ceiling is a duty over acceptances the Log
does not carry; nothing recomputable distinguishes a Delta sealed at
its turn from one sealed late.

## 2026-09-04 — WIST-3 §6.1, §12: Payloads replicate before their Block

Adds to §6.1's availability window that an Aggregator or Mirror MUST NOT
serve a Block before every Payload its content-bearing Deltas commit
to, less those withdrawn, is retrievable at its path; the Aggregator
and Mirror checklists follow.

**What it states.** §6.1 made "any Mirror serving a Block MUST serve
that Block's Payloads" hold at every instant with no grace, so the
ordinary replication order — a Block file first, its Payloads seconds
later — was a `WIST3-E05` fault by the letter, and a Consumer reading
the letter would report suppression where there was only latency. A
rule with no grace period needs an order instead, and the order is the
one §5 already imposes between a Block and its Checkpoint: the
artifact that makes a claim checkable is served before the artifact
that makes the claim. WIST-2 §5 has the Aggregator publish Payloads
"alongside the Block that seals them"; this fixes which side of
alongside.

**Why it qualifies.** Both conditions hold. A Mirror that served
Payloads with or before its Blocks conformed and still does; the entry
only removes the reading under which honest replication was a fault.

**Status.** Unexercised. The order is a serving discipline over
artifacts the harness verifies separately.

## 2026-09-04 — WIST-2 §6: a hint times an audit, it never creates one

Rewords §6's second paragraph: a hint MAY advance an Auditor's fetch of
a Delta already in its selection set, and nothing more; a Record for a
Delta outside the selection set is `WIST4-E01` whatever prompted it, so
a hint never creates a Record.

**What it states.** §6 said a hint-triggered fetch of a URL with signed
Deltas "enters the log as an Audit Record (WIST-4 §5)", but WIST-4 §3
and §4 admit a Record only for a Delta the Auditor's VRF draw or the
extension rule selected, and void every other; the two documents
contradicted each other, and WIST-4's rule is the one every replayer
enforces. What a hint can lawfully do is bring forward a fetch the
Auditor already owes for that URL's Delta, which is scheduling — the
only role §6 gives hints for URLs without signed Deltas, now the role
for every URL.

**Why it qualifies.** Both conditions hold. A Record a hint created
was void under WIST-4 as written; §6 now says so instead of promising
otherwise, and an Auditor that used hints only to schedule conformed
and still does.

**Status.** Unexercised. Hints are an input the harness does not model;
the Record-standing rule §6 now defers to is exercised by
`vectors:wist4-selection-domain` and `vectors:wist4-extension-proof`.

## 2026-09-04 — WIST-4 §4: a barred Delta is in none of that Auditor's selection sets (revision, not errata)

Adds to §4's selection paragraph that a Delta §3's self-audit rule bars
an Auditor from is in none of that Auditor's selection sets by either
path — the Auditor owes no Record for it, a Record it publishes anyway
is `WIST4-E01`, and the bar consults no draw — and reads the coverage
duty over the selection set so defined. Adds `self_audit_cases` to
`vectors/wist4/selection-domain.json`, generated by
`tools/gen_vectors.py`.

**What it states.** §3 forbids an Auditor to audit a Delta whose
Publisher fails the independence test against its `auditor_id`; §4
made it audit every Delta its VRF selected and counted an unaudited
selected Delta as a coverage failure; §10 voided the Record either way.
An Auditor whose own domain — or any host under its two-label suffix —
publishes Deltas therefore accrued coverage failures it could not
lawfully discharge, and the only text that excused a barred Auditor was
the extension rule's. The bar now applies where the extension rule
already applied it: at the selection set, before any duty exists. It
reads two hostnames the Log carries, so every party derives the same
selection set for the same Auditor.

**Why it is a revision.** It fails the first condition, as a resolved
contradiction must: an Auditor that audited its own domain's selected
Deltas conformed to §4 and breached §3, one that did not conformed to
§3 and failed §4's duty, and a replayer counting those failures
conformed to §4 and now does not. It is scoped to the bar: the draw,
the domain, the extension rule and the void are unchanged.

**Status.** Exercised. `vectors:wist4-selection-domain` recomputes
`self_audit_cases` — an independent Publisher, one under the Auditor's
suffix, the Auditor's own host, a shared two-label public suffix, and
an Auditor under the Publisher's suffix — and its twin proves the check
reads the Publisher's suffix.

## 2026-09-04 — WIST-3 §7: a deleted URL keeps its chain tip in the state artifact (revision, not errata)

Adds to §7's materialized-state paragraph that a `delete` removes the
record's content and moves the chain tip like any other Delta, and to
the state-artifact prose that one `record` tuple exists per (Publisher
domain, Normalized URL) the state carries a tip for, a deleted URL
included, so the `record` tuples' keys are a superset of the content
tuples' keys. `examples/snapshot-state.json` gains the tuple for a
deleted URL, and `examples/snapshot-manifest.json` its `state_digest`.

**What it states.** §7 said a `delete` "removes the record", and the
`record` tuple — the only carrier of a chain tip in the artifact — was
read from the records, so a state built that way held no tip for a
deleted URL. WIST-1 §3.5 says the chain for a URL never restarts: the
Delta that recreates a page names the `delete` as `prev`. A Consumer
resuming from a Snapshot held no tip for that key and, by §7's own tip
rule, ignored that Delta as a fork of nothing; a Consumer replaying from
genesis applied it. Two conforming Consumers diverged on that URL from
then on, and the artifact stopped being the state a replay derives —
the property §7 makes it an assertion anyone can falsify. The tip now
survives the delete in both places: a `delete` is a tip like any Delta,
and the state carries it.

**Why it is a revision.** It fails the first condition. A state
artifact built from the content tuples conformed and no longer does —
it omits a tuple the digest now covers — and a resuming Consumer that
treated a missing key as "no chain" conformed and no longer does. It is
scoped to the tip: the content tuples, the tier layout and
`content_digest` are unchanged, and no Delta means anything new.

**Status.** Exercised. `examples/snapshot-state.json` carries a
`record` tuple for a URL that has no content tuple, and the manifest's
`state_digest` covers it; `tools/validate_examples.py` recomputes both.

## 2026-09-04 — WIST-4 §3, §10, §13: a malformed Record discharges the duty, and the carve-out reads the anchor Block

Adds to §3 that a Record rejected as malformed evidence (`WIST4-E02`)
discharges the §4 duty it answers, that a Record void for more than one
reason discharges only if every reason is a discharging one, and that
the removal carve-out is read at the Block the duty is anchored to — the
audited Block for a VRF selection, *B₁* for a Delta the extension rule
names; rewords the §10 `WIST4-E01` and `WIST4-E02` rows and the §13
Auditor line to match. `vectors/wist4/coverage.json`'s
`discharge_cases` now list every reason a Record is void, and it gains
`anchor_cases`.

**What it states.** The `WIST4-E02` row ended "Ignored as WIST4-E01"
without saying which of that row's two coverage readings applied, and
the `E01` row's carve-out named "the audited Block" although §4 counts
an extension Record's duty against the (Auditor, *B₁*) pair. Both were
already decided elsewhere. §3 scopes the standing rejections it excuses
"to reputation" because the Auditor "met its duty" by publishing; a
`WIST4-E02` Record was published under standing, so the duty it answers
is met and only its weight as evidence is withheld — §4 discharges the
duty "by any verdict", `unreachable` included, so publication, not
evidentiary quality, was always the test. And a removal is read against
whichever Block the duty is anchored to, because that anchoring is what
the carve-out exists to respect: an Auditor removed between the audited
Block and *B₁* was never admitted at *B₁*, so §4's extension rule never
named it and there is no duty to discharge.

**Why it qualifies.** Both conditions hold. An implementation that
discharged on a `WIST4-E02` Record conformed to §4's "any verdict" and
still does; one that read the extension carve-out at *B₁* conformed to
§4's pair and still does. The many-reasons sentence states what the
`E01` row's "in every other case there was no duty" already implied: a
reason under which no duty existed cannot be cured by a second reason.

**Status.** Exercised. `vectors:wist4-coverage` recomputes the twelve
`discharge_cases`, including the malformed case, both carve-outs
together, and a carve-out beside a no-duty reason, and the five
`anchor_cases` — a draw removed after and at the audited Block, an
extension removed after *B₁*, between the audited Block and *B₁*, and
at *B₁*.

## 2026-09-04 — WIST-2 §3.2, §10: a Block that seals two rotations resolves a Page to its Key Set (revision, not errata)

Rewords §3.2's second resolution from "the first applicable Declaration
sealed after `generated_at`" to the Key Set of the first Block after
`generated_at` sealing an applicable Declaration of the domain — the
highest `seq`'s where that Block seals several — and states the same
tie for the current resolution; the §10 Aggregator line follows. Adds
the case *two rotations sealed in one block* to
`vectors/wist2/page-keyset.json`.

**What it states.** Two Declarations of one domain can seal in one
Block, `seq` *n* and *n*+1 at one `sealed_at`. WIST-1 §5.2 resolves the
Key Set at that height to the highest `seq`, so `seq` *n*'s keys were
the Key Set at no height — no Delta was ever sealed under them. Read
literally, "the first Declaration sealed after `generated_at`" named
`seq` *n*, and a Page cut before that Block verified under a key that
never held, while one signed under `seq` *n*+1 — the key every Delta of
that Block verifies under — was `WIST2-E04`. Both resolutions now read
the Block's Key Set: the same lookup a validator already performs for
that Block's Deltas, with a timestamp in place of a height.

**Why it is a revision.** It fails the first condition. A validator
that read the lowest `seq` conformed to the words and now rejects a
Page it accepted and accepts one it rejected. It is scoped to the
same-Block tie: a Block sealing one Declaration resolves as before, and
the first-Block-not-any-later rule is unchanged.

**Status.** Exercised. `vectors:wist2-page-keyset` recomputes the new
case — `seq` 2's key verifies under `next` for a Page cut before the
Block and under `current` for one cut at its instant, `seq` 1's under
neither — and its twin proves the check reads the Block's Key Set
rather than its lowest `seq`.

## 2026-09-04 — WIST-4 §3, §10: two admits for one subject in one Block are both rejected

Adds to §3 that two `auditor_admit` Entries naming one `subject` in one
Block are both rejected (`WIST4-E07`), and the case to the §10 row.
Adds *two admits for one subject in one block both rejected* and
*rotation beside a second admit in one block* to
`vectors/wist4/roster.json`.

**What it states.** §3 holds one admitted key per `auditor_id` at any
height, and WIST-3 §3.3 reads Registry Updates at Block granularity,
their position within a Block carrying no meaning. Two admits for one
`subject` in one Block therefore had no first: accepting one and
rejecting the other read a position §3.3 says means nothing, and two
replayers ordering the Block's Entries differently would derive two
rosters from one Log. Rejecting both is the only reading that consults
no position, and it costs nothing a conforming Aggregator would seal —
an Auditor admitted twice at once was never a valid state.

**Why it qualifies.** Both conditions hold. No text determined which
admit stood, so no implementation conformed by picking one; the rule
follows from the one-key invariant and §3.3's position rule together,
and a rotation — remove then admit at one instant — is unchanged.

**Status.** Exercised. `vectors:wist4-roster` recomputes both cases —
two admits alone, and a rotation whose admit is joined by a second —
and its twin proves the check accepts a lone admit.

## 2026-09-04 — WIST-4 §4, §9.1; registry-update schema: a removal is for cause exactly when its `evidence` names something

Adds to §4 that a removal "carrying evidence" is one whose `evidence`
member names at least one ID and that a removal carrying none has the
member absent, and to §9.1 that an `auditor_remove`'s `evidence`, where
present, MUST name at least one ID; `schemas/registry-update.schema.json`
gains an appended `auditor_remove` branch with `minItems` 1.
`vectors/wist4/roster.json` carries `evidence` as the Registry Update
does — present for a removal for cause, absent for an exit.

**What it states.** §4 decided a bar by whether the removal was
"carrying evidence", and the schema typed `evidence` as an optional
array with no lower bound, so `"evidence": []` was schema-valid and
carried a member that named nothing. One reader took presence as
evidence and barred the `auditor_id`; another took the empty list as
none and let it rotate. The words meant the second — evidence is what
the array names, and an empty one names nothing — and an array that
names nothing is now not an `auditor_remove` at all, so no replayer has
to decide.

**Why it qualifies.** Both conditions hold. An Aggregator that named
its evidence conformed and still does; an empty array was never a
removal §4 described. The schema change forbids a form the text gave
no meaning to.

**Status.** Exercised. `schema:wist4-auditor-remove-evidence` validates
a removal with one ID and one with the member absent, rejects an empty
array, and checks the vector carries both a removal for cause and an
exit; `vectors:wist4-roster` recomputes the bar from the member's
presence.

## 2026-09-04 — WIST-4 §3, §4, §10: a removal retires the key, not only its label, and no two admissions share one (revision, not errata)

Adds to §4 that an `auditor_remove` retires the `public_key` admitted
under its `key_id` as permanently as the `key_id` itself, and that an
`auditor_admit` naming a `key_id` or a `public_key` another admission
holds at its Block is rejected; §3 states the one-key-one-Auditor
invariant beside its one-Auditor-one-key one, and the §10 `WIST4-E07`
row lists both cases. `vectors/wist4/roster.json` entries carry an
abstract `public_key`, and three cases are added.

**What it states.** §4 retired "its `key_id`" and said nothing of the
`public_key`, so the same thirty-two octets re-admitted under a fresh
label were accepted, and nothing stopped two live `auditor_id`s from
holding one `key_id` string — which §3's Record binding, "the `subject`
of the `auditor_admit` that admitted the key named in its `sig.key_id`",
presumes unique — or one `public_key`, which is one party that §3's
independence test would read as two. The rule now mirrors WIST-1 §5.2's
for a Publisher's key sets: no shared `key_id`, no shared `public_key`,
retirement binding both.

**Why it is a revision.** It fails the first condition. A replayer that
accepted a retired key under a fresh label, or a second admission of a
held string, conformed to the words and now rejects those acts. It is
scoped to the roster: the bar for cause, the rotation mechanism and the
one-key-per-`auditor_id` rule are unchanged.

**Status.** Exercised. `vectors:wist4-roster` recomputes the three
cases — a removed key re-admitted under a fresh `key_id`, a `public_key`
held by another Auditor, a `key_id` held by another Auditor — and its
twin proves the check reads the `public_key` a re-admission names.

## 2026-09-04 — WIST-4 §6.1, §6.3: a Delta sealed at the reset height belongs to the fresh identity (revision, not errata)

Changes every reset bound on a Delta in §6.1 and §6.3 from "above `R`"
to "at or above `R`" — `A`'s first Block, `C`'s audited Delta, the
Deltas whose Confirmed Inconsistencies count — and states why: a Delta
sealed at `R` is the fresh identity's own. Adds the case *delta sealed
at the reset height* to `vectors/wist4/derivation.json`.

**What it states.** WIST-3 §3.3 lets a fresh identity's Declaration
seal in the same Block as the first Delta it authorizes, and applies
Declarations before Deltas within a Block; WIST-1 §5.2 seals a Delta
only where the Key Set at its height verifies it. At `R` that Key Set
is already the fresh identity's, so nothing of the previous identity
seals there and a Delta at `R` is the fresh identity's statement. Read
strictly, it started no `A`, counted no `C`, and a Confirmed
Inconsistency on it left `penalty_n` entirely — the one Delta the reset
could not have been meant to excuse.

**Why it is a revision.** It fails the first condition: a replayer that
read the strict bound conformed to the words and now derives a
different `A`, `C` or `penalty_n` for a domain whose first post-reset
Delta sealed at `R`. It is scoped to that one height; a Delta below
`R` is the previous identity's as before.

**Status.** Exercised. `vectors:wist4-derivation` recomputes the new
case: an accepted Delta at `R` starts `A`, its `consistent` audit
counts one URL, and the Confirmed Inconsistency on it enters
`penalty_inputs` while the one on a Delta at `R` − 1 does not.

## 2026-09-04 — WIST-4 §5: vectors that tell the normalization apart

No document text changes. Adds five cases to
`vectors/wist2/text-extraction.json`, implements §5's normalization in
`tools/link_extraction.py` — which had stood in for it with a lowercase
and a whitespace split — and adds `tools/segmentation.py`,
`tools/unicode_tables.py` and the Unicode Consortium's own segmentation
test files under `tools/ucd/`.

**What it states.** What §5 already states, in cases that can tell it
apart from the readings it excludes. Every text fixture in the suite was
ASCII letters and spaces, where a lowercase, a whitespace split and a
code-point count all agree with default full case-folding, untailored
UAX #29 segmentation and extended grapheme clusters — so the vectors
could not distinguish a conforming Auditor from one that had implemented
none of it, and the reference tool itself had implemented none of it. The
new cases separate them: sharp s folds to `ss` where a lowercase leaves
it; a decomposed and a precomposed spelling are one text under NFC; a Han
page written without spaces has as many words as characters and clears
the mass guard, where a whitespace split sees one word and rules it
`not_auditable`; a punctuation segment carries no L* or N* character and
is discarded; and the short branch counts six grapheme clusters where a
code-point reading counts twelve, which caps the shingle length
differently and scores the pair differently.

**Why it qualifies.** Each case executes sentences already in §5; none
adds to them. `tools/segmentation.py` implements UAX #29 from the annex
rather than from a library, for the reason `ecvrf.py` gives for the VRF,
and is checked in full against the Consortium's `WordBreakTest.txt` and
`GraphemeBreakTest.txt` on every harness run — 1826 word cases and 1093
grapheme cases — so the reading is anchored outside this repository
rather than against a second reading of the same text.

**Status.** Exercised, and anchored. `vectors:wist2-text-extraction`
recomputes all five cases, `unicode:uax29-conformance` proves the
segmentation beneath them against the Consortium's published answers, and
`negative:wist2-normalization` recomputes each case under the one reading
it exists to rule out and fails if the two agree — so a fixture that
discriminates nothing cannot enter the vector unnoticed.

## 2026-09-04 — WIST-1 §2, §13; WIST-4 §5, §13: one pinned Unicode version (revision, not errata)

Adds the Unicode version pin to WIST-1 §2's Canonical Host and WIST-4
§5's normalization, names the release in both reference lists, and
records the decision as ADR-0017, which amends ADR-0014.

**What it states.** Every Unicode property the suite reads comes from
Unicode 16.0: NFC, default full case-folding, UAX #29 word boundaries
and extended grapheme clusters, General Category, and the UTS #46
mapping and validity tables. Moving the version is a change to the
documents — after a deployment exists, a new major version — because it
changes identities and verdicts already sealed. An implementation whose
platform offers only a later release is not conforming for these
sections.

**Why it is a revision.** It fails the first condition. An implementation
reading its platform's current Unicode release conformed to the previous
text, which named the algorithms and not the release, and a platform
already past 16.0 now has to pin. The defect it closes is one both
sections claim not to have: §5 states that no two conforming Auditors can
disagree about a boundary case and that selection is recomputable rather
than reproducible-in-practice, and ADR-0014 pinned the UTS #46 flags to
stop two implementations deriving different A-labels for one host. The
Character Database reaches both. A character unassigned in one release is
General Category `Cn`, so §5's step 4 discards the segment holding it
while the release that assigns it keeps the segment — a different word
sequence, a different `similarity`, a different verdict — and UTS #46's
mapping table, being derived from the same database, sends one host to
two A-labels across two releases.

**Status.** Unexercised at the point that matters. The vector suite's
text fixtures are ASCII, where every release agrees, so nothing in the
harness would notice a party reading a different one. The discriminating
cases belong with the normalization vectors recorded in the entry that
follows this one.

## 2026-09-04 — WIST-4 §5, §9: `shingle_size` governs the branch threshold too (revision, not errata)

Rewrites §5's *Shingles* paragraph and the `shingle_size` row of §9's
Parameter Registry, and adds two cases to
`vectors/wist2/text-extraction.json`.

**What it states.** §5 wrote the literal 8 twice — once as the word
count at which the word branch is taken, once as the shingle length —
while §9 registered one amendable `shingle_size` and never said whether
it moved both. It moves both. The threshold is not an independent
choice but the length's own precondition: a text of fewer than
`shingle_size` words has no shingle of that length to contribute.
Reading the threshold as a fixed 8 while honouring an amended
`shingle_size` would put a 6-word text on the word branch with a 6-word
shingle set the rule never defines, or leave a 9-word text on the
grapheme branch under a `shingle_size` of 10 — either way the two sides
of the quotient are built by different rules.

**Why it is a revision.** It fails the first condition. An Auditor that
read the two 8s as one parameter and one that read the threshold as a
constant both conformed to the words, and under an amended
`shingle_size` they compute different `similarity` for the same pair,
which is a different verdict and a different Confirmed Inconsistency.
Under the Registry default nothing changes, which is why the divergence
could sit unnoticed until the first amendment.

**Status.** Exercised. `vectors:wist2-text-extraction` carries a
`shingle_size` per case and two amended ones over the pair the default
scores at 500 000: at 10 the reference's 9 words fall below the
threshold and the grapheme branch scores it 885 714, at 4 the word
branch with a shorter shingle scores it 833 333. The check also proves
each amendment changes the score, so a reader that ignored the
parameter would fail it.

## 2026-09-04 — WIST-4 §7: a notice may share its sanction's Block (revision, not errata)

Adds the bullet *"Preceded by" bounds the Aggregator's conduct, not the
Block* to §7.

**What it states.** The `notice` for a level-3 or level-4 `sanction` is
sealed in that `sanction`'s Block or a lower one, and the same Block is
permitted. What the Aggregator MUST NOT do is act before the notice is
sealed: no `403` on that domain's Pings or Feed pulls, and no
withholding of its Deltas from materialization, at any height below the
notice's Block.

**Why it is a revision.** It fails the first condition. "MUST be
preceded by a `notice`" reads naturally as a strictly lower Block, and
an Aggregator that sealed the two together conformed only under the
looser reading. Permitting the same Block costs the Publisher nothing
that was ever available: §7's own derivation puts the level-3 and
level-4 states in force from the height their criteria are met, whatever
the Aggregator has sealed, so a Block of filing delay delays the state
by nothing and only delays the Publisher learning of it. What the
ordering rule secures is what the derivation cannot — that the appeal
window opens no later than the enforcement, leaving no height at which a
Publisher is acted on with no way to answer.

**Status.** Unexercised. No vector seals a notice and its sanction at
all; the ordering rests on reading. It belongs with the first governance
Block fixtures.

## 2026-09-04 — WIST-4 §7: what each reversal reaches (revision, not errata)

Adds the bullet *What each reversal reaches* to §7, and a `ladder_cases`
block to `vectors/wist4/sanctions.json`.

**What it states.** §7 listed four reversals in one sentence and gave
none of them a scope. The three that hang on a `notice` — an
`"overturned"` ruling, a lapsed ruling deadline, a lapsed appeal-sealing
deadline — reverse only the state the notice was required for: the
level-3 ingestion rejection or the level-4 exclusion. The rungs below
stand, because no notice put them in force. A `sanction_lift` reaches
every rung in force at its own height, which is why it needs neither an
appeal nor a notice; it erases no evidence and grants no immunity, since
the criteria keep running and a rung met again after the lift is in
force again from the height it is met.

**Why it is a revision.** It fails the first condition twice over, and
in opposite directions. A party that read the void rules as clearing the
whole ladder now leaves a level-3 domain at level 2 or 1 and ingests its
Deltas again at that rung; a party that read a `sanction_lift` as
reaching only the level-3 and level-4 states now clears the rungs below
it too. Both readings were available, so resolving one necessarily
breaks whoever guessed the other. The asymmetry is not arbitrary: it
follows from what each reversal is a fact about — a lapsed deadline is a
fact about the process the notice opened, and a lift is the
Aggregator's statement about the domain.

**Status.** Exercised. `vectors:wist4-sanctions` recomputes the new
`ladder_cases`: a void leaves level 2 where the level-2 criterion is
met and level 1 where only that one is, a level-4 void leaves level 2,
a lift clears every rung, and a criterion met after a lift is in force
again.

## 2026-09-04 — WIST-2 §3.2, §5, §7: a Feed fetched but unusable (revision, not errata)

Rewrites the `WIST2-E01` row of §7, the first sentence of §5 step 1, and
adds a code to §3.2's `next` rule.

**What it states.** `WIST2-E01` covered a Feed that could not be fetched
and nothing else, so a Feed the Aggregator retrieved but could not use
had no code at all: not well-formed JSON, failing the Feed schema, or
naming a `next` outside the Publisher's authority — a constraint §3.2
stated without saying what violating it costs. All of them are now
`WIST2-E01`, retried on the same backoff, and none is noise against the
quota. They share a code because they share a remedy and a remedier: the
Aggregator holds no usable Feed either way, nothing about the domain's
state has changed, and only the Publisher can fix it. The backoff, not
the quota, is what bounds a domain that keeps serving one.

**Why it is a revision.** It fails the first condition. The suite named
no code for these cases, so an implementation that reached for the
nearest one — `WIST2-E04`, which is metered as noise — conformed as
defensibly as one that reached for `WIST2-E01`, and now must stop
charging the quota for them. Leaving it unstated was worse than either
answer: the same malformed Feed cost one Publisher its quota and another
nothing, and a Publisher reading §7.1 could not tell which had happened
to it.

**Status.** Unexercised. No vector serves a malformed Feed or a `next`
outside the Publisher's authority; the classification rests on reading.
Both belong with the first pull-behavior fixtures.

## 2026-09-04 — WIST-2 §8: a redirect chain terminates (revision, not errata)

Adds two bounds and their rationale to §8's *Cache poisoning of
`.well-known`* bullet.

**What it states.** §8 constrained a redirect's target and nothing else,
and the target rule alone does not terminate: two hosts both listed in a
Publisher's `subdomain_scope` may point at each other for ever, and every
hop satisfies the rule. An Aggregator now MUST NOT follow a redirect to a
URL it has already fetched in the same chain, and MUST NOT follow more
than five in one. A resource whose chain exceeds either bound is not
retrieved, which for a Feed is `WIST2-E01` like any other failure to
fetch. The five is the allowance WIST-4 §9's `audit_redirect_max` already
gives an Auditor, chosen for symmetry rather than derived.

**Why it is a revision.** It fails the first condition. An Aggregator
that followed an in-scope chain of six hops conformed to the previous
text and does not conform now, and the Publisher it was reaching becomes
unreachable to it. The defect it closes is worse than the break: a
Publisher able to set two in-scope redirects could hold an Aggregator's
fetch open indefinitely, at no cost to itself, from inside the authority
the target rule exists to confine it to.

**Status.** Unexercised. No vector exercises redirects at all; the bounds
rest on reading. They belong with the first fetch-behavior fixtures,
which no vector format currently covers.

## 2026-09-04 — WIST-3 §5: which Aggregator key signs a Checkpoint

Adds three sentences to §5.

**What it states.** A Checkpoint for Block N is signed by a `key_id`
valid at height N in §3.4's sense, and a Consumer verifies it against
that key set rather than against the genesis key alone. The verification
order follows: the key set valid at N is what the Blocks up to N
establish, so the Checkpoint's signature is checked after those Blocks
are walked, and nothing rests on checking it earlier — each Block
authenticates itself under §3.4, and the Checkpoint's `block_hash` binds
it to the Block at N.

**Why it qualifies.** §3.4 already defines validity at a height and
already governs every Aggregator signature the suite defines; §5 simply
never said which of those keys a Checkpoint carries. An Aggregator that
never rotated is unaffected, since the genesis key is valid at every
height until an `aggregator_key_remove` retires it, and a Consumer that
verified against the genesis key alone was reading the only key it had.
Nothing that verified before fails now: the genesis key remains in the
set until retired.

**Status.** Unexercised. No vector rotates an Aggregator key, so both
the Block rule §3.4 states and the Checkpoint rule this adds rest on
reading. A vector that admits a second Aggregator key and seals a Block
under it belongs with the first Log-succession fixtures.

## 2026-09-04 — WIST-1 §4: a JSON number is parsed with correct rounding

Adds the first half of the paragraph *A number is the double it denotes*
to §4.

**What it states.** RFC 8785 §3.2.2.3 canonicalizes a number by
serializing the IEEE-754 double the literal denotes, so the scheme is
well defined only where every party recovers the same double from the
same octets. ECMA-262 already specifies that conversion as correctly
rounded — the nearest double, ties to even — and §4 now requires it. A
parser off by one unit in the last place derives different Canonical
Bytes from an unaltered document, and with them a different Delta ID and
a signature that verifies for nobody else.

**Why it qualifies.** It states what RFC 8785 already rests on. A
validator whose conversion was correctly rounded conformed before and
conforms now; one whose conversion was not could never interoperate,
because the Delta IDs it computed were nobody else's. Nothing that
verified under the previous text fails under this one.

**Status.** Unexercised. No vector carries a number whose correctly
rounded double differs from a naive conversion's; the requirement is
verified by reading ECMA-262 rather than by execution. A vector belongs
with the first suite of canonicalization edge cases.

## 2026-09-04 — WIST-1 §4, §7: identity is the double's, not the literal's (revision, not errata)

Adds the second half of the paragraph *A number is the double it denotes*
to §4 and rewrites the `WIST1-E05` row of §7.

**What it states.** Distinct literals can denote one double, so identity
in this suite is identity of the double: a producer MUST NOT rely on
integer precision beyond ±(2^53 − 1) to distinguish two objects, and
every integer member the suite defines already sits inside that range by
its own bounds. `WIST1-E05` now names what it covers for a number: a
value that denotes no double at all — a magnitude beyond the finite
range, or a form outside JSON's grammar. A finite double is always
canonicalizable, and a validator MUST NOT reject one for carrying a
fractional part.

**Why it is a revision.** It fails the first condition. `WIST1-E05`
previously read "object not valid JCS input, e.g. non-JSON-safe
numbers", and "JSON-safe" was undefined; a validator that read it as the
I-JSON integer range and rejected every fractional number conformed to
those words. It now MUST accept one. The change is forced: §9.1 leaves
the `details` of `sanction_lift`, `coverage_attestation` and `appeal`
unconstrained, so under the previous reading a single fractional member
anywhere in a sealed Registry Update made the whole Block unverifiable
for every party — a defect no Aggregator could detect before sealing and
no Consumer could repair after.

**Status.** Unexercised. No vector carries a fractional number in a
sealed object, nor a magnitude outside the double range. Both cases
belong with the canonicalization edge-case vectors named above.

## 2026-09-04 — WIST-4 §3, §4, §5: vectors for resolutions the suite left unexercised

No document text changes. Adds cases to `vectors/wist4/extension-proof.json`
(a rotation between the audited Block and *B₁*), `vectors/wist4/unauditable.json`
(a clearing Record at the later blocking instant, one exactly at N, and
three blockers with one pair uncleared) and `vectors/wist4/roster.json`
(a retired `key_id` re-admitted by another `auditor_id`, a rejected
removal for cause, and a removal for cause beside an admit in one
Block), generated by `tools/gen_vectors.py`.

**What it states.** What the text already states. §3 reads each duty
and proof at the key held at that Block's `sealed_at`, so an Auditor
that rotated between the audited Block and *B₁* proves its extension
standing under the key held at *B₁* and its *B₁* proof under the older
key gives no standing (`WIST4-E01`). §5 clears the unauditable predicate
only by a Record sealed after the later blocking Record and at or
below N, per independent pair: a clearing Record at the later blocking
instant does not clear, one at N does, and a third blocker leaves the
pair its clearing Auditor depends on uncleared. §4 retires a `key_id`
for every `subject`, lets a rejected removal retire and bar nothing,
and reads a removal for cause before an admit sealed at the same
instant, so the admit is barred.

**Why it qualifies.** Each case executes a sentence already in the
text; none adds to it. They are added because each resolution rested
on reading alone, and the cases an implementation gets wrong are
exactly the boundaries and rotations these cover.

**Status.** Exercised. `vectors:wist4-extension-proof` recomputes the
rotation cases under the key held at each Block, and its twin proves
the check reads that key; `vectors:wist4-unauditable` and
`vectors:wist4-roster` recompute the new cases.

## 2026-09-04 — WIST-4 §4, §13: a derived state is dated where it becomes derivable

Adds the paragraph *The state is dated where it becomes derivable* to §4,
one clause to the divergence sentence, the establishing height to both
transport rules, one clause to the §13 validator checklist line that
stops counting a coverage-failed Auditor's Records, and the
`establishing_cases` array to `vectors/wist4/coverage.json`.

**What it states.** §4 defined coverage failure "at a height N when the
Log shows it failing the duty for more than `coverage_failures_max`
Blocks inside the 30 whole days ending at Block N's `sealed_at`", and
defined divergence in the same shape, without saying when the Log shows
it. The evidence for a Block's duty cannot exist at that Block: the
Aggregator pulls after the coverage deadline and seals within
`record_seal_blocks` of the pull, so the earliest height at which any
party can derive the failure is far above the Block whose duty was
failed. *Shows* is now read at N and nowhere else, and each case has an
**establishing height**: the Block sealing the `pull_attestation` for
the pair, or, for an unattested pair, the `record_seal_blocks`-th Block
sealed after that Auditor's coverage deadline. The 30 whole days stay
anchored to the audited Blocks, so a Block whose establishing height
falls outside its own window counts at no height at all.

**Why it qualifies.** The alternative — dating the state to the audited
Block and applying it once the evidence arrives — was never available.
`reputation_u` sets `p_1e7`, quotas and ingestion suspension (§6.4), so
a state that reached back would change the sampling and the acceptance
of every Block sealed between the audited Block and its evidence, which
§8 invariant 3 forbids; and WIST-3 §7's `coverage_failure` state kind is
written at a Snapshot's `log_position` alone, so a Consumer resuming
there could not carry a state dated below it that the Log had not yet
established. No implementation could conform to the reading this
removes.

**Status.** Exercised. `vectors/wist4/coverage.json` gains four
establishing cases — an attestation's own Block, the unattested case's
count of Blocks past the deadline, a deadline not yet passed by
`record_seal_blocks` Blocks, and evidence arriving past the audited
Block's window — each with the heights at which the failure counts and
does not. The family's anchor status is the row `tools/VERIFICATION.md`
already carries for it.

## 2026-09-04 — WIST-4 §4, §9.1, §13, audit-record schema: the `prev_record` chain is per Log (revision, not errata)

Rewrites the `prev_record` sentence in §4's transport paragraph, the two
§9.1 restatements, the §13 Auditor checklist line and the schema's
`prev_record` description, and adds the `chain_scope_cases` array to
`vectors/wist4/coverage.json`.

**What it states.** `prev_record` names the same Auditor's immediately
preceding Record or attestation published for the same Log, and is
`null` for its first there. The chain is per (Auditor, Log).

**Why it is a revision.** It fails the first condition: the previous
text said "in its own publication order", one order across everything
the Auditor publishes, and an Auditor serving two Logs that chained its
items in that single order conformed to those words. It now MUST keep
one chain per Log, so its published `prev_record` values change. The
change is forced by what the chain feeds. WIST-3 §8 makes an Auditor
roster, and every state computed from that roster's Records, a function
of one chain's replay; §4's gap discriminator reads a sealed item whose
`prev_record` names an ID its Log does not contain as proof that the
Aggregator suppressed or failed to pull a published item, and excludes
every unattested pair for that Auditor in the window. Under a single
cross-Log order, every item an Auditor publishes for one Log names a
predecessor published for another, which no Log can find or attribute —
so each Log holds a permanent gap, and *The gate is not an amnesty*
inverts into a permanent amnesty scaled to the number of Logs an Auditor
joined. No Log-side test can repair it: a Log cannot tell a missing ID
belonging to a peer Log from one its own Aggregator withheld.

**Status.** Exercised. The two chain-scope cases run one Auditor's five
publications interleaved across two Logs — nothing suppressed, then one
item withheld by one of them — and carry, beside the per-Log chain and
each Log's gap verdict, the chain and verdicts the ruled-out cross-Log
order produces, so a party checking the vector proves the two readings
disagree rather than assuming it.

## 2026-09-04 — WIST-4 §4: which window an establishing height must fall in

Rewrites the closing sentence of §4's *The state is dated where it
becomes derivable* paragraph.

**What it states.** The operative rule is unchanged: a Block counts
toward the coverage-failure count at a height N when its establishing
height is at or below N and the Block itself is inside the 30 whole days
ending at N's `sealed_at`. Their consequence, which the paragraph
glossed, is that a Block whose evidence seals 30 whole days or more after
the Block itself counts at no height at all — from the height that
evidence arrives at, the duty it records has already aged out of the
window read there. The gloss named the wrong window, "the 30 whole days
ending at its own `sealed_at`", one that closes before any establishing
height can fall inside it.

**Why it qualifies.** It corrects a sentence no implementation could have
conformed to, and changes nothing computed. Read with the audited Block
as the antecedent, the gloss excluded every Block, since evidence always
seals after the duty it records; read with the establishing height as the
antecedent, it excluded none, since a height is inside any window ending
at itself. Neither is the count the surrounding text defines, and the
count is what implementations recompute.

**Status.** Exercised. `vectors/wist4/coverage.json`'s establishing case
for evidence arriving 30 whole days after the audited Block already
carries the heights at which that failure does not count, the boundary
the corrected sentence describes.
## 2026-09-04 — WIST-4 §4, §9: the parameters must leave a coverage failure countable (revision, not errata)

Adds a combination rule to §9, a cross-reference to it from §4's
establishing-height sentence, `vectors/wist4/parameter-combinations.json`
and the harness checks over it.

**What it states.** `coverage_deadline_hours` × 3600 +
(`record_seal_blocks` + `coverage_failures_max`) ×
`block_cadence_seconds` MUST be shorter than 30 whole days, and a party
replaying the Log MUST reject a `parameter_change` that leaves it
otherwise. §4 counts a failed duty from its establishing height and only
while the audited Block is inside the 30 whole days ending at the height
read, so the lag before the evidence seals and the span that
`coverage_failures_max` + 1 consecutive failures occupy come out of one
window. At or past the sum, no height carries more than the tolerance
however completely an Auditor shirks.

**Why it is a revision.** It fails the first condition: parameter sets
the previous text permitted MUST now be rejected. One of them is not
hypothetical. `block_cadence_seconds` = 86 400, the ceiling §9's own
bounds table publishes, with every other value at its default gives the
unattested path 51 days to fit into 30 — a tolerance of 24 Blocks is 24
days of them, and their evidence seals 27 days after the Blocks it speaks
to. An Aggregator that stopped attesting under those parameters would
hand the whole roster the permanent amnesty *The gate is not an amnesty*
(§4) exists to close, and no per-parameter bound catches it: the coupling
§9's opening paragraph states between `coverage_failures_max` and the
cadence had no form a replayer could check.

**Status.** Exercised. `vectors/wist4/parameter-combinations.json`
carries five parameter sets with, for each, the sum the rule bounds and —
from a simulation of an Auditor that fails every Block on a fully sealed
grid — the greatest number of failures any single height carries, under
the unattested establishing height and under an attestation sealed in the
next Block. The registry defaults reach 624 against a tolerance of 24;
the published cadence ceiling reaches 3 unattested and 26 attested, which
is the amnesty; and `record_seal_blocks` 623 and 624 reach 25 and 24, so
the boundary decides the rule's strict inequality rather than leaving it
to reading. The harness recomputes the count rather than the rule, and
its twin fails a bound written at the endpoint instead of below it.

## 2026-09-05 — WIST-4 §4, §9, §11, §13; WIST-3 §7; registry-update and snapshot-state schemas: a contradiction escalates the audited domain, not the filer (revision, not errata)

Rewrites §4's contradiction paragraph, amends its selection-test and
removal-evidence sentences, removes `contradictions_max` from §9's bounds
table, combination rules, registry table and the schema's identifier
enum, rewrites the §11 sentence on divergence, adds one replayer line to
§13, adds the `escalation` kind to WIST-3 §7's state artifact and the
schema, and replaces `vectors/wist4/extension.json`'s divergence cases
with contradiction cases.

**What it states.** A summoning `inconsistent` or `link_inconsistent`
Record is contradicted when its extension **closes** — at the first Block
sealed more than `confirm_window_hours` after *B₁* — with no confirmation
pairing it and an independent `consistent` pair sealed inside the
window, endpoint included; the closing Block is the contradiction's
establishing height. Its only consequence is **escalated sampling** for
`domain(d)`: `p_1e7` is `sampling_ceiling`, as under a level-1 sanction,
for the 30 whole days from that height. Nothing attaches to the filer:
no derived removal, no voided Records. Divergence, and the
`contradictions_max` that measured it, are gone; a run of contradicted
filings is evidence for `auditor_remove` read by the admission judgement.

**Why it is a revision.** It fails the first condition twice. A replayer
that voided the Records of an Auditor past `contradictions_max` conformed
before and MUST NOT now, and a `parameter_change` naming
`contradictions_max` validated before and is `WIST4-E03` now; sampling
rates change for every escalated domain. The change is ADR-0012's
divergence decision. The Log cannot tell a lying filer from an honest one
at a cloaked vantage, and ADR-0016 already named a conforming case the
predicate would have punished: a Publisher answering a sealed
`inconsistent` with a truthful `update` before the summoned Auditors
fetch has them file `consistent`, contradicting a filer that did
everything right. A derived removal landed on that filer exactly as often
as on a liar. The old text was also non-computable as written: "closes"
named no instant, so the height a contradiction was dated to — and with
it the whole divergence count — was one no two replayers could agree on.

**Status.** Exercised. `vectors/wist4/extension.json` carries nine
contradiction cases over one hourly grid: the closing Block, a
confirmation inside the window, a dependent `consistent` pair, a second
`consistent` past the window, a `consistent` and a confirming
`inconsistent` each exactly at the window's end, a confirmation one Block
past it, a rationed-out trigger, and a `consistent` sealed in *B₁*
itself — each with the heights at which escalation is in force and aged
out. The harness recomputes every case and its twin fails an
endpoint-exclusive window in both directions.

## 2026-09-05 — WIST-4 §4, §9, §13: an extension Record seals inside the window it serves (revision, not errata)

Adds the extension pull to §4's transport paragraph, a combination rule
to §9, one Aggregator line to §13, and `extension_window_cases` to
`vectors/wist4/parameter-combinations.json`.

**What it states.** For a *B₁* that names a Delta for an Auditor under
the extension rule, the Aggregator MUST also fetch that Auditor's path
once the extension deadline passes and before it seals its next Block,
and MUST seal what it finds within `record_seal_blocks` Blocks of that
fetch, with no attestation; the coverage-deadline pull and its
attestation are unchanged. `confirm_window_hours / 2` × 3600 +
`record_seal_blocks` × `block_cadence_seconds` MUST NOT exceed
`confirm_window_hours` × 3600, and a replayer MUST reject a
`parameter_change` that leaves it otherwise.

**Why it is a revision.** It adds a duty and rejects parameter sets the
previous text permitted, and the defect it closes is not hypothetical.
The only pull the previous text required came after the coverage
deadline — `coverage_deadline_hours` after *B₁*, which §9's own rule puts
at or after the extension deadline — so at the registry defaults the
earliest an extension Record could seal through the mandated transport
was 73 hours after *B₁*, one Block past the 72-hour window §5 confirms
inside. The extension rule, "the only path to confirmation that does not
wait on coincidence", could confirm nothing and contradict nothing unless
an Aggregator volunteered a pull no sentence required. Found by checking
whether the section's windows compose.

**Status.** Exercised. The five cases give, per parameter set, the sum
and the latest instant after *B₁* at which a Record published at the
extension deadline seals on a fully sealed grid: the defaults seal at 60
hours against 72, the cadence ceiling 23 days past the window,
`record_seal_blocks` 36 and 37 on either side of the endpoint, and a
deadline between two Blocks earlier than the sum reads. The harness
recomputes the seal rather than the rule, and its twin fails a strict
bound and one that leaves `record_seal_blocks` out.

## 2026-09-05 — WIST-4 §7: a lift clears rungs, never findings

Adds four sentences to §7's *What each reversal reaches* bullet and
`reversal_cases` to `vectors/wist4/sanctions.json`.

**What it states.** Every Confirmed Inconsistency sealed before a
`sanction_lift` stays inside the windows the escalation criteria read,
so a count criterion is met again at the first finding after the lift
that completes its count. Level 4's three-severity-3 branch is the first
to fire only where the level-3 state was cleared between the findings, by
a lift or a void, and it is kept for exactly that: three fabrications
inside 180 days delist whatever the process between them did.

**Why it qualifies.** The bullet already said a lift "is not an erasure
of the evidence" and that "the escalation criteria keep running from that
height", and the ladder vectors already counted every finding; what was
unstated was which findings a criterion reads after a lift, and why a
branch that never fires first on an unreversed ladder is in the table at
all. Nothing computed changes.

**Status.** Exercised. Three cases: three severity-3 findings across two
lifts reach level 4 at the third by the count branch alone, the same
findings without the lifts reach it at the second by accrual, and three
severity-1 findings around a lift reach level 2 at the third. The harness
recomputes the rungs from the findings and its twin fails a lift read as
erasing the findings before it, and a ladder without the count branch.

## 2026-09-05 — WIST-4 §2, §3.1, §4, §5, §5.1, §5.2, §9, §9.1, §10, §11, §12, §13; WIST-2 §3; WIST-3 §7; registry-update, audit-record and snapshot-state schemas: Observers, canary domains and the credit commitment (revision, not errata)

Adds §3.1 *Observers*, §5.1 *Canary Domains* and §5.2 *Credit and the
Hard Hit*; the actions `observer_register`, `observer_checkpoint`,
`canary_commitment` and `canary_reveal` with their §9.1 contracts and the
submissions path they reach the Log by; `credit_commitment` on every
measured Audit Record; `track_record` on an `auditor_admit` of a former
Observer; seven parameters with bounds and two combination rules in §9;
`WIST4-E08` and additions to `WIST4-E02`, `E04` and `E07`; six §11
exposure bullets; a §12 paragraph; §13 lines for Observers, planters,
Aggregators and replayers; two paths in WIST-2 §3's layout; the
`observer` and `canary_commitment` kinds in WIST-3 §7's state artifact;
`vectors/wist4/canary.json` and `vectors/wist4/observer-checkpoints.json`;
and the `credit_commitment` entry in `vectors/wist4/audit-commitments.json`.
This is the revision ADR-0012 records, whose addendum states what was
pinned and where a reading was chosen.

**What it states.** Anyone may register as an Observer under a
domain-anchored identity and perform an Auditor's duties voluntarily —
same selection, same Records, same chain — with nothing it publishes
counting anywhere; it serves an `observer_checkpoint` naming its chain
head, which the Aggregator seals under a derivable per-epoch budget
allocated per two-label suffix by a hash over the epoch number, and a
Record credits only under a checkpoint sealed below the reveal that
scores it. A planter commits to future served bytes as a Merkle root over
leaves each carrying a fresh nonce, at least `canary_lead_blocks` before
the Deltas they cover; the canary domain reveals the binding inside a
window bounded below by `canary_reveal_min_blocks` plus one rotation of
the checkpoint budget and above by `canary_lifetime_blocks`, then serves
the bytes and their Reference Payloads for `payload_window_days`. Every
measured Record carries `credit_commitment`, the Reference Payload's salt
over the served bytes with the signer's `auditor_id` appended: credit is
byte possession before the reveal, a miss is no demerit, and the hard hit
— possession proved and a verdict two bands from the bytes — is the one
derivable demerit, reaching removal only through the judgement. An
`auditor_admit` of a former Observer cites the newest checkpoint and a
three-tier scoreboard; a reveal voids no sanction.

**Why it is a revision.** It fails the first condition throughout. A
measured Record without `credit_commitment` validated before and is
`WIST4-E02` now; the action enum grows; an Aggregator gains pull and
sealing duties; the state artifact gains kinds a resuming Consumer must
carry; WIST-2's layout gains paths. The reason is the one ADR-0012 gives:
admission stays a judgement, and everything the judgement weighs becomes
a fact anyone can recompute, against evidence — served bytes unknowable
before a fetch — that no party can fabricate after the outcome is known.

**Status.** Exercised. `canary.json` carries a four-leaf commitment (three
revealed) whose leaves the harness re-hashes and re-walks to the root by
the verifier's algorithm; ten credit cases — the fetcher, the Payload-bytes
guesser, the copier of another's value, both hard-hit forms, both
buffer-band verdicts, the cloaked fetch, the wrong salt — recomputed from
the served bytes and the example Payload's salt; seven reveal-timing cases
on either side of the minimum, the lifetime, the lead, and the
over-budget rotation; and two per-tier scoreboards. Its twin fails a
credit without the signer, a hard hit read one band away, and a proof
under the wrong index. `observer-checkpoints.json` carries the budget
allocation under three rosters across epochs, epoch boundaries across a
mid-Log change of `epoch_blocks`, and what a checkpoint fixes before a
reveal; its twin fails a static queue and an epoch read from the Block's
own value. The four acts and `track_record` are validated as schema
instances with each REQUIRED member removed in turn.

## 2026-09-05 — WIST-4 §6.1: the Identity scope sentence reads the reset bound inclusively

Rewrites one sentence of §6.1's *Identity scope* paragraph.

**What it states.** An event counts toward `A`, `C` or the set of
Confirmed Inconsistencies when the height it belongs by — a Delta's own
sealing height, an Audit Record's `audited_delta` height — is at or
above the domain's most recent identity reset. The paragraph's opening
sentence still said "greater than", while the `C` bullet, the Confirmed
Inconsistency bullet and every bound in §6.3 read "at or above" and
§6.3 explains why: Declarations apply before Deltas within a Block
(WIST-3 §3.3), so at the reset height the Key Set is already the fresh
identity's and nothing of the previous identity seals there.

**Why it qualifies.** The 2026-09-04 revision that made every reset
bound inclusive missed this sentence, leaving §6.1 contradicting itself
on a Delta sealed at the reset height — an event the bullets count and
the opening sentence excludes. The bullets are the operative definitions
and the sentence a summary of them; the correction makes the summary say
what the definitions already do, and changes nothing computed.

**Status.** Exercised. `vectors/wist4/derivation.json`'s case for a
Delta sealed at the reset height already discriminates the two readings
on all three inputs: under the inclusive bound the Delta at `R` starts
`A`, its URL counts toward `C` and its Confirmed Inconsistency enters
`penalty_n`; under the strict bound none of the three does.

## 2026-09-05 — WIST-4 §6.3: what a reset buys is the formula's rate, not the ceiling

Rewrites one clause of §6.3's *Sanction state binds the key identity too*
paragraph and adds `rate_cases` to `vectors/wist4/sampling.json`.

**What it states.** A domain that resets re-enters Provisional at
`reputation_u` 100 000, and §4's formula at that reputation gives
`p_1e7` = 200 000 + 3 × 900 000 = 2 900 000. The paragraph called that
"the sampling ceiling §4 applies at that reputation", but §4 displaces
the formula to `sampling_ceiling` (5 000 000) under exactly two states —
a level-1 sanction and an escalation — and a reset lifts the rung, so
the reset domain reads the formula. The clause now names the value and
what the lift trades: the ceiling for the formula's near-maximum, never
for an established domain's rate.

**Why it qualifies.** The sentence explained a rule and misstated the
number the rule produces; §4's formula, the Parameter Registry and
Appendix A all give 2 900 000 at the cap and were never in doubt. No
implementation could have conformed to the gloss without contradicting
§4, and the correction changes nothing computed.

**Status.** Exercised. `sampling.json`'s `rate_cases` give the rate at
the Provisional cap with no rung in force (the formula's 2 900 000),
the same reputation under a level-1 rung (the ceiling), and the two ends
of the formula with and without an escalation; `vectors:wist4-sampling`
recomputes each and requires §6.3 to name the cap's value, and its twin
fails a reading that puts the ceiling at the cap.

## 2026-09-05 — WIST-4 §13: the link checklist line defers to §5's SHOULD

Rewrites the Auditor checklist line on `link_agreement`.

**What it states.** §5 says a Record that produced a measured verdict for
a non-`delete` audit of an HTML representation SHOULD carry
`link_agreement`, and spends a paragraph on what an omission is: a
dimension left visibly unaudited for that Delta, a fact any recomputing
party can see and weigh, not a silent gap and not malformed evidence.
The §13 line said the Auditor seals the field "whenever the link
dimension applies", with no qualification — a MUST by another name. The
line now computes the reading where the dimension applies, seals it as
§5 says it SHOULD, and never seals a link verdict without it, which is
the one case the schema does require.

**Why it qualifies.** A checklist restates requirements and creates
none; where it read stronger than the section it cites, an Auditor
following it lost nothing and a validator following it would have
rejected Records §5 and the schema accept. No implementation could
conform to both, and the correction changes no rule.

**Status.** Exercised. `schema:wist4-link-agreement-optional` validates
the example Record with `link_agreement` removed, fails a `link_variance`
and a `link_inconsistent` Record without it, fails a `not_auditable`
Record carrying it, and requires the checklist line to defer to §5.

## 2026-09-05 — WIST-4 §6: the four divisions are reputation's, not the suite's

Rewrites the sentence introducing §6's evaluation-order table.

**What it states.** The table lists the four integer divisions that
reputation and its consumers perform — the day count, `base_u`, the
formula and `Q` — and the sentence said the suite carried "exactly
four, all of them here". §4's extension deadline divides
`confirm_window_hours / 2`, explicitly marked integer division, and
§5's link dimension floors two quotients, each written out with its
operands where it stands. The sentence now says which four the table
holds, names the divisions outside §6, and states that the same
parenthesization rule governs them.

**Why it qualifies.** The count was a claim about the text, not a rule
in it; every division the claim omitted was already fully specified
where it appears, so no implementation computed anything differently
under either reading. The correction removes a false statement a
reader checking the claim would have caught, and changes no value.

**Status.** Exercised. `vectors/wist4/extension.json`'s deadline case at
`confirm_window_hours` 73 floors the half-window, and
`vectors/wist4/link-agreement.json`'s one-dropped case floors 2/3 to
666 666; `spec:wist4-evaluation-order` now requires §6 to name the
divisions outside it and §4 and §5 to write them out.

## 2026-09-05 — WIST-4 §4: the establishing height is the earlier evidence the Log carries

Adds one clause and two sentences to §4's *The state is dated where it
becomes derivable* paragraph, and corrects `vectors/wist4/coverage.json`'s
`establishing_cases`.

**What it states.** A failed duty has two possible evidences, each fixed
by the transport: the Block sealing the `pull_attestation` for the pair,
and the `record_seal_blocks`-th Block sealed after the coverage deadline,
from which an unattested pair counts. Where the Log carries both, the
failure counts from the earlier. A party reading the Log at a height
between the unattested rule's Block and an attestation sealed later
carries no attestation, derives the unattested failure and counts it;
the attestation, when it seals, confirms a failure already counted and
moves nothing, because nothing sealed above a height changes what the
Log shows at it.

**Why it qualifies.** The paragraph already said *Shows* is read at N
and nowhere else and that every state is a function of the Log up to the
height it is read at. The vectors nonetheless dated a failure to the
attestation's Block wherever an attestation existed anywhere in the
case, so at a height below that Block — with the unattested rule's
evidence already sealed — they expected the failure not to count. That
is a reading from above N, which the paragraph's own words exclude; the
two expectations it produced (heights 179 and 819 of the former cases 0
and 3) were wrong, and an implementation following the text disagreed
with them. The correction states what the text implied and changes no
rule.

**Status.** Exercised. `coverage.json`'s establishing cases now hold an
attestation sealed before the unattested rule's Block (establishing at
the attestation), one sealed after it (establishing at the unattested
Block, with probes on both sides of the later attestation), the
unattested case, the not-yet-passed deadline, and evidence outside the
audited Block's window — the last rebuilt so that no evidence of either
kind falls inside it. `vectors:wist4-coverage-establishing` recomputes
every height and probe, and its twin fails the reading under which a
later attestation moves the height.

## 2026-09-05 — WIST-4 §3.1, §5.1: the scoring window's endpoints

Adds one sentence to §5.1's account of the scoring window, one clause to
§3.1's Observer serving duty, `payload_window_days` to
`vectors/wist4/canary.json`'s parameters and `scoring_window_cases` to
the vector.

**What it states.** A reveal's scoring window is open at a Block N when
the whole days (§6.1) from the reveal's Block `sealed_at` to N's are
fewer than `payload_window_days`: open at the reveal's own Block, lapsed
at the first Block sealed `payload_window_days` whole days or more after
it — end-inclusive and start-exclusive, as every window in the document
is measured. §5.2 reads the scoreboard at N over exactly the reveals open
there. An Observer's duty to keep serving what it publishes for
`payload_window_days` runs from the publication, an instant only the
Observer holds, and no derivation reads it; what replay reads is the
scoring window on the reveal's Block.

**Why it qualifies.** §5.1 said the domain serves the bytes "for
`payload_window_days`" and that the window "lapses as a Reference
Payload's does", and §5.2 read scoreboards over reveals whose window "is
open at N", without saying which Block is the last one inside. Every
other window here — §4's 30 days, §5's horizon, §7's escalation spans —
is measured the same way and says so; the sentence applies that
measurement to the one window that lacked it and changes nothing an
implementation following the document's own convention computed.

**Status.** Exercised. `canary.json`'s `scoring_window_cases` probe the
reveal's own Block, a Block inside the window, the last Block inside it,
the first Block a whole window later and one after; `vectors:wist4-canary`
recomputes each and requires §5.1 to state the rule, and its twin fails an
end-inclusive reading of the closing endpoint.

## 2026-09-05 — WIST-4 §5.2: no band, no hard hit

Adds a paragraph to §5.2's *The hard hit*, a fifth leaf to
`vectors/wist4/canary.json` and the credit and scoreboard cases over it.

**What it states.** The hard hit is a verdict two bands from the derived
band over the revealed bytes. Where §5 derives no band — an observed
text below `min_observed_words` — there is none, on any verdict. The
other observed-side route to `not_auditable` reads the response's media
type, a header the leaf does not commit to, so a hit resting on either
would rest on evidence the reveal does not carry, and a party
recomputing the scoreboard MUST NOT infer one. Credit still reads byte
possession. The honest Record on such a leaf is `not_auditable`, carries
no `credit_commitment` and is an encounter without credit; the planter
spends the leaf on nothing, and two such Records from independent
Auditors make the URL unauditable at the planter's own cost.

**Why it qualifies.** The hit was defined over the derived band and over
nothing else, so where no band exists none can fire: the paragraph
states the consequence rather than adding a rule. The alternative —
reading a measured verdict on unmeasurable bytes as itself a hit — was
considered and closed, because the media-type rule cannot be recomputed
from the leaf, and a demerit only some recomputations could reach would
not be the derivable one §5.2 promises.

**Status.** Exercised. `canary.json`'s fifth leaf falls below the mass
guard; a `consistent` Record over its bytes credits and is no hit, the
honest `not_auditable` Record carries no commitment and is an encounter
without credit, and both appear on the scoreboards.
`vectors:wist4-canary` recomputes the missing band and every case, and
its twin fails a reading that treats a missing band as the
`inconsistent` band.
