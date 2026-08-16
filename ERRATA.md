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
