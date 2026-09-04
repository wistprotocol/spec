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
