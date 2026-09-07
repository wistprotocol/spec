# ADR-0012: Auditor track record becomes derivable

**Status:** draft · **Date:** 2026-08-13

## Context

Reputation controls a Log's sampling, quotas and ingestion suspension.
These operations require one canonical answer to which Audit Records count,
so Auditor admission remains an Aggregator-signed judgement. An Observer
must nevertheless be able to build a public record before admission, and
the evidence behind admission must be independently inspectable.

Coverage and non-contradiction alone cannot establish fetch-work: a party
can copy a Reference Payload and report a matching page without fetching
it. The evidence needs bytes that cannot be predicted from the Payload,
and a commitment authenticated before those bytes become public.

Normative definitions are in WIST-4 §§3.1, 4, 5.1, 5.2 and 9.1;
WIST-2 §3 specifies transport and WIST-3 §7 specifies restoration state.

## Decision

### Observers and roster admission

Anyone satisfying the domain-identity and independence requirements may
register as an Observer. Observers use the Auditor's selection, Record and
publication machinery, but their Records carry no reputation, confirmation,
extension or sanction weight. The Aggregator verifies their Declarations
and seals budgeted checkpoints of their Record-chain heads. A checkpoint
authenticates a history without requiring transport of every Observer Record.

Resolve simultaneous roster acts in stages. Validate removals against the
pre-Block admitted roster, deduplicate identical acts and apply valid
removals together. A distinct subject or key not held in that roster makes
the removal invalid. If several valid removals name the same incumbent,
any for-cause removal establishes the readmission bar.

After removals, reject duplicate same-subject admission or registration
groups. Check remaining candidates against the resulting incumbent map;
an admission displaces a same-subject registration candidate. Reject all
cross-subject key-ID or public-key collisions among survivors and apply
those left together. Rejected candidates are not retried. A released
Observer key becomes available to another subject only in a later Block.
This prevents Entry position from selecting a roster winner.

### Checkpoint allocation

Checkpoint slots are budgeted by the two-label suffix defined in WIST-4 §3.
Sort suffixes by `SHA-256(suffix)`, breaking equal hashes by canonical
suffix UTF-8 octets. Each epoch walks one budget from the position
`epoch × budget mod S`, where S is the suffix count. Within a suffix,
the selection hash uses the epoch and `auditor_id`, with canonical
`auditor_id` UTF-8 octets breaking ties.

For an unchanged suffix set and budget, the walk bounds delay by
`ceil(S / budget)` epochs. A fresh random ordering each epoch supplies
no such bound; a fixed priority queue can starve every suffix past its
budget. Roster churn requires the actual-opportunity checks below.

Admission evidence names the newest eligible checkpoint by greatest
`(sealing height, Update ID)`, comparing IDs as raw digest octets.
Checkpoint identity is therefore unique even at equal sealing heights.

### Canary commitments and reveals

A planter seals a Merkle commitment to served bytes before the Deltas it
will cover exist. Each leaf embeds a fresh, unpredictable nonce and stays
byte-stable for its Delta. The commitment identifies its planter without
identifying the Canary Domain; only that domain's keys may reveal it.
The reveal binds leaves to the domain's own Deltas after their required lead.

A watermark canary keeps its normalized truthful content while placing the
nonce in discarded markup. It supplies recurring byte-possession evidence
without deliberately making a false claim. A fraud canary deliberately
serves content inconsistent with its Payload, providing verdict-discipline
evidence at the cost of ordinary sanctions. Revealing a canary never
reverses its sanctions.

Each reveal seals `leaf_hash = SHA-256(0x00 ‖ served bytes)`, encoded as
`sha256:` plus lowercase hex, together with the leaf index and sibling
path. The Log can verify membership from that hash, the committed tree
size and WIST-3 §4's inclusion walk without obtaining the bytes. Missing
or malformed hashes and incomplete or surplus paths reject as `WIST4-E08`.
Scoring separately verifies that the available served bytes hash to the
declared leaf. Inclusion authenticates the commitment, not a server's reply.

An accepted reveal permanently reserves its Delta IDs within its Log.
Deduplicate identical Update IDs, then reject otherwise-valid simultaneous
reveals sharing a commitment or Delta. Rejected candidates reserve nothing.
Expired scoring windows cannot be renewed by recommitting the same Delta.

### Timing and availability

The defaults are 24 Blocks of commitment lead, 24 Blocks per epoch,
1,024 budgeted suffixes per epoch, a 168-Block base reveal minimum,
1,440 Blocks of commitment lifetime, 1,024 leaves per commitment and
eight commitments per planter suffix per epoch. WIST-4 §9 specifies
their bounds and combinations; the reveal minimum also accounts for
checkpoint rotation, adding no negative allowance for an empty roster.

The numeric minimum is insufficient under churn. Every bound Delta's
coverage sealing allowance must finish below the reveal. Every originally
represented suffix that remains represented must receive a budgeted epoch
ending after the last coverage deadline, with its fetch and sealing allowance
finished below the reveal. Use actual epochs, rosters and anchored counts.
Churn may prevent readiness before expiry; an expired commitment scores
nothing rather than bypassing these obligations.

The domain serves revealed bytes and the relevant Reference Payloads for
the scoring window. The window reads `payload_window_days` at the reveal:
it includes the reveal's Block and closes when that many whole days have
elapsed. Availability lapses; raw page bytes never enter the immutable Log.
Self-signed registry acts are served at `/.well-known/wist/registry.json`;
WIST-2 §3 supplies the pull and publication duties.

### Credit and admission evidence

Every measured Record carries an HMAC-SHA256 credit commitment under its
Reference Payload's salt over raw response bytes followed by the signer's
`auditor_id` in UTF-8. The signer binding prevents copying another party's
published commitment. It does not prevent identities sharing fetched bytes.

Credit requires possession authenticated before reveal. A miss carries no
automatic penalty: a planter can cloak a page for an honest fetcher, and
consistent captures need not be retained for later self-defense. A hard hit
requires both demonstrated possession and a verdict two bands from the band
derived over revealed bytes: `consistent` below the variance floor, or
`inconsistent` at or above the consistency threshold. Intermediate bands
and inputs for which WIST-4 §5 derives no band produce no hard hit.
Extraction and band parameters read the audited Delta's Block, as described
in [ADR-0016](0016-audit-reference-follows-the-chain.md).

Count each Audit Record ID once, even when multiple checkpoints cover it.
An admission of a former Observer carries `track_record`: its checkpoint
and a scoreboard for the three reputation tiers. Presence and checkpoint
identity are replay conditions; the scoreboard's accuracy is falsifiable
while its evidence is available, then trusted on historical replay. Replaying
after Payload expiry must not derive a different admitted roster.

Admission and score-based removal remain judgements; coverage failures
retain their separate derivable consequences. There is no automatic
promotion, scoreboard retention floor or mandatory decentralization schedule. Contradiction
escalates sampling of the audited domain for 30 days from the extension's
establishing Block; it does not itself establish Auditor divergence or
removal. Coverage accounting is described in
[ADR-0019](0019-audit-duty-accounting.md).

## Consequences and limits

The roster's admission evidence becomes inspectable without making Observer
verdicts canonical. Canary evidence demonstrates timely byte possession;
it does not prove independent network retrieval, honest administration or
universal full-page verification.

- Byte-stable pages can carry creditable leaves; per-request content is
  distinguishable and may evade this evidence supply. Range probes can
  retrieve only nonces, lowering the cost of credit. Refusing ranges or
  scattering nonces raises that cost without proving a full re-verification.
- Colluding identities can share one fetch. Planter diversity matters:
  a ring can credit its own members through its own canaries, while the
  domain and suffix budgets bound visible activity rather than ownership.
- Cloaking can fill an honest party's miss column. No automatic penalty
  follows, but admission or removal judgement can still be influenced.
- Fraud canaries incur sanctions and are needed to expose false
  `consistent` verdicts over fraudulent content. Watermark credit alone
  cannot establish that a party would detect fraud.
- The Aggregator can decline admission despite strong evidence. Public
  histories and the ability to follow another Log make that choice legible;
  they do not compel it to admit anyone.
- Fraud-canary volume cannot be classified before reveal. Visible
  commitment budgets bound unrevealed Log growth; ordinary extension rations
  also apply to fraud-canary traffic. A separate pre-reveal fraud ration
  would depend on information the Log does not have.

## Alternatives considered

- **Automatic promotion or retention thresholds:** require calibrated
  tier floors, windows and canary supply, while giving cloaking and colluding
  planters a mechanical admission or removal channel. Public scoring leaves
  the judgement accountable without making those thresholds canonical.
- **Punishing every missed canary:** an honest cloaked fetch and fabrication
  can leave the same commitment. Defending every miss would require retaining
  captures beyond the evidence policy. Positive credit and possession-backed
  hard hits avoid that automatic punishment.
- **Aggregator-only canaries:** exempt its own collaborators from the hidden
  challenge. Permissionless planting permits independent challenges.
- **Fraud-only canaries:** require continuously sacrificing established
  reputation. Watermarks provide recurring evidence; fraud canaries supply
  the separate verdict-discipline test.
- **Response commitments without signer binding:** are identical across
  fetchers and publicly copyable. Raw served bytes in the reveal would also
  defeat the content-retention design.
- **Purely Consumer-relative reputation:** cannot supply one canonical
  sampling and ingestion state for a Log. Separate Logs may make separate
  admission judgements.
- **Commit-reveal for confirmations:** the trigger is already public when
  peers are summoned. Hiding it would not establish fetch-work; canary credit
  addresses the possession question directly.
- **Stake or bonds:** impose a cost without establishing honesty and can
  exclude independent participants. TLS-derived or hardware-attested evidence
  would introduce verifier or vendor trust; neither is a protocol foundation.
- **Public Suffix List independence:** imports a mutable external registry
  and can make different accounts of one hosting provider appear independent.
  The two-label test is deliberately conservative and replayable.
- **Cluster-based eviction:** hosting and administrative correlations are
  not authenticated Log facts. Such analysis may inform judgement, but does
  not become a derived removal predicate.

## Verification

`vectors/wist4/canary.json`, `observer-checkpoints.json` and `roster.json`
exercise commitment proofs, scoring, timing, budget ordering and simultaneous
claims. WIST-4's role checklists additionally require live publication,
fetching and admission validation; vector agreement alone does not exercise
those obligations.
