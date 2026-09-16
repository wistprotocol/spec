# ADR-0018: Confirmation, sanction activations and due process

**Status:** draft · **Date:** 2026-09-05

## Context

A Consumer must derive the same findings, active sanctions and process
deadlines from the same Log prefix. Evidence ages, parameters change and
several findings or conflicting registry acts can share a Block. A sanction
notice must identify the particular activation it governs, so an old appeal
cannot reverse a later rearming.

WIST-4 §§4, 5 and 7 define confirmation and sanctions; §9 defines parameter
anchors. WIST-3 §6 defines evidence availability through proceedings.

## Decision

### Confirmation and severity

Every quorum member lies inside one closed `confirm_window_hours` window
ending at the confirming Record's Block. Count pairwise independent Auditors
separately for extract and link verdicts. The earliest Record completing
`confirm_auditors` members establishes the finding under that candidate's
Block profile. Later parameter changes do not move this first success.
Severity reads the full closed confirming set, not a selected witness.

A triggered extension closes contradicted only if no complete quorum of
the triggering verdict includes that trigger and a complete independent
consistent quorum sealed inside its closed window. The contradiction test
uses the triggering profile and closes once. Later confirmation does not
rewrite it. A roster too small for the quorum supplies no implicit reduction.

### Rung activation and reversal

Latch each rung independently until reversal or identity reset. Counting
windows govern entry, not automatic expiry. A high-rung void clears only
its activation; lower latched rungs survive aged evidence. A lift clears
all rungs before the Block's confirming Records. A same-Block finding may
then rearm a rung, but merely rereading unchanged evidence cannot. A
finding for a Delta sealed below the identity's most recent reset arms no
rung of the fresh identity, whenever it confirms; a `sanction_lift` is
authenticated under the Log key and a rejected one clears nothing.

Evaluate each branch on new qualifying findings in confirming-Record order.
Keep pre-reversal findings within their counting windows. Level 4's
further-finding branch reads level 3 immediately before the new finding:
two findings in one Block may establish levels 3 and then 4, but one finding
cannot supply both the initial level 3 and its own further finding.

### Notice identity and evidence

A notice names level 3 or 4 and `details.activation`, the confirming Audit
Record ID that armed the target. Accept one notice per subject, level and
activation: the first eligible Block's unique candidate, rejecting distinct
simultaneous eligible conflicts together. Invalid candidates cannot veto a
valid notice. The activation must be active or newly armed in that Block.
Further notices restart no clock; recovery notices are outside this process.

Cite complete quorums at the original confirming Records for the activating
finding and enough distinct findings to establish an arming branch. Read
counts at the activation's original window and severity from the full closed
confirming set even when a notice cites only a quorum. Level 4's further-
finding branch must also support the actual prior level-3 activation's
criterion at its own window, including its activating finding's quorum.
Replay supplies intervening reversals and identity boundaries.

Every optional citation must resolve to an Audit Record available by the
notice Block. Well-shaped evidence failures are `WIST4-E05`. Extra evidence
cannot change the primary finding's severity, substitute a cleared
activation or move the counting window to the notice date.

A `sanction` separately identifies its primary finding through
`details.finding`. That finding's first confirming Record and a complete
quorum must appear in its evidence. Its full closed confirming set determines
`details.severity`; optional findings cannot change that primary severity.
The ladder still derives from every qualifying finding, independently of
which finding a sanction selects.

### Appeals and rulings

Each notice has one accepted appeal, one merits ruling and one unappealed-
statement slot. Deduplicate Registry Update IDs at their first sealing
Block. The first eligible act fills its slot; distinct simultaneous eligible
acts all fail as `WIST4-E05`, leaving the slot open. Later distinct acts
cannot replace an accepted one. Resolve appeals before rulings regardless
of stored Entry order, and let invalid acts occupy no slot.

Merits rulings require a timely accepted appeal, must seal by its ruling
deadline and must follow the target activation's Block. A same-Block notice
and appeal can therefore be valid while a merits ruling there is invalid.
This prevents a Registry Update from attempting to reverse a finding that
the Block's application order has not established yet.

Appeal and seal clocks read the notice profile; the ruling clock reads
the accepted appeal. Unappealed statements use the specified window-close-
to-T interval and cannot defeat a timely sealed appeal. A notice-scoped
reversal clears only its still-matching activation. Once a merits ruling
closes the process, a discretionary change uses `sanction_lift`, not another
ruling over the same notice.

### Evidence retention

A Mirror serving an accepted notice acquires the cited Audit Record Blocks
before serving its Block and retains both through the process's actual
closing instant, including that endpoint. Without an accepted appeal the
process closes at T, even if an unappealed statement sealed earlier. With
an accepted appeal it closes at the ruling deadline or an earlier accepted
merits ruling. Preserve prefix causality and all overlapping process duties.

Ordinary Block retention reads its value at first service. A later parameter
reduction cannot discard evidence during an open proceeding. These are
Block duties; Payload availability and withdrawal keep their own rules.

## Consequences and alternatives

Canonical findings and explicit activation identities allow deterministic
replay across aging, reversals and rearming. Entry order remains relevant
where findings are sequential, while simultaneous eligible process conflicts
choose no winner by position.

Derived sanctions prevent an Aggregator from sparing a qualifying domain
by withholding registry acts. Public evidence lets any party recompute and
contest the basis; notice additionally obliges the Aggregator to open a
process before exercising its own ingestion or exclusion authority. Requiring
a notice in a strictly earlier Block would delay that process without
delaying derived state. Levels 1–2, including weight reduction, require no
notice because their evidence and severity are already public. This design
does not guarantee that third-party materialization waits for an appeal.

An appeal clock based on `effective_at` could expire before its notice seals.
A clock starting only when an appeal seals would let the Aggregator suppress
that appeal indefinitely. The notice-anchored sealing deadline instead
requires a timely appeal or an `"unappealed"` ruling to preserve state.
Publisher silence earns neither reprieve nor penalty. Suppressing a served
appeal then requires a signed, public assertion falsifiable by that appeal;
sealing nothing voids state. The resulting process burden gives Aggregators
an incentive to omit notices, but omission also bars their own enforcement.
If no notice seals, public evidence can still invalidate derived state, and
WIST-4 §8 preserves the ability to follow another Log.

Level 4's count branch matters after reversals: a third severity-3 finding
is the first to meet that branch only where the level-3 state was cleared
in between. Otherwise the second finding already reaches level 4 through
the further-finding branch. Reversals never alter evidence-derived `penalty_n`.

Automatic expiry would contradict latched sanctions; reversing every future
activation would let an old process reach a new offense. Accepting partial
quorums would let citation selection fabricate support or severity. Retention
computed from only the current parameter map would fail when older notices
and later appeals use different clocks. Explicit identities, historical
profiles and actual process lifetimes avoid those failures.

## Verification

`vectors/wist4/confirmation.json`, `extension.json` and `sanctions.json`
exercise quorums, activation targets, conflicting acts and citation support;
`sanctions.json`'s `identity_scope_cases` and signed `lift_cases` cover
pre-reset findings, resets and rejected lifts.
`parameter-combinations.json` exercises temporal profiles and retention.
Live notice publication and acquisition of cited Blocks remain obligations
of the WIST-3 and WIST-4 role checklists.
