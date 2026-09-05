# ADR-0012: Auditor track record becomes derivable

**Status:** accepted; amended by ADR-0028 (2026-09-05: escalation predicates have no numeric amendment); amended by ADR-0027 (2026-09-05: anchor parameter reads for in-flight windows); amended by ADR-0026 (2026-09-05: parameter combinations validate all scheduled future states); amended by ADR-0025 (2026-09-05: simultaneous registrations and key claims reject as a batch); amended by ADR-0024 (2026-09-05: attested chain contradictions require pair attribution); amended by ADR-0023 (2026-09-05: late-sealed discharge clears the current coverage count); amended by ADR-0022 (2026-09-05: appeal and ruling identity and conflict rules); amended by ADR-0021 (2026-09-05: latched rungs and ordered same-Block reversals); amended by ADR-0020 (2026-09-05: extension triggers spend ration in canonical Entry order); amended by ADR-0019 (2026-09-05: contradiction uses the amended confirmation quorum); amended by ADR-0018 (2026-09-05: reveals seal their proof starting hash) (revision landed 2026-09-05; parameters and readings in the addendum below) · **Amends:** ADR-0016 · **Date:** 2026-08-13

> The suite was frozen on 2026-08-05 (ERRATA.md). This ADR records the
> decision; the WIST-4 changes it entails are neither errata nor a
> defect-scoped revision, and landed as the revision ERRATA.md records
> under 2026-09-05, before the first tag rather than after the freeze's
> stated exit, so that the version tagged carries the text an
> implementation of the Auditor is built against.

## Context

WIST-4 made Auditor *removal* derivable: coverage failure and divergence
are computed from the Log, and the `auditor_remove` "records the
consequence and does not create it." Admission is the suite's last
discretionary act — `auditor_admit` is signed by the Aggregator alone,
and §11 names the consequence honestly: auditor independence is an
admission-time trust assumption, and a deployment that needs more "MUST
obtain it outside this protocol." This ADR does not remove that
discretion. It removes the discretion's darkness: the decision stays a
judgement, and everything the judgement weighs becomes a fact anyone can
recompute.

Two facts shape the design. First, the bootstrap problem is the
protocol's hardest: recruiting the first independent Auditors is harder
than the Publisher/Consumer chicken-and-egg, because it demands trust
negotiation with strangers before the system has anything to show. A
survey of deployed transparency ecosystems (CT monitors, Rekor, Sigsum
witnesses, key-transparency auditors, oracle systems) found no deployed
scheme in which permissionless parties' *verdicts count*: every survivor
either lets anyone watch while counting nobody (CT monitoring), curates
a roster (witness networks, root programs), or retreated to a whitelist
after capture (UMA). The empirical failure mode everywhere was too few
honest watchers, not sybils — recruitment arrives before the sybil
problem. Second, WIST cannot copy CT's edge-trust answer wholesale:
reputation feeds the Log's own control loop (`reputation_u` sets
`p_1e7`, quotas, and ingestion suspension), so one canonical answer to
"which Records count" must exist for the machine regardless of what any
Consumer believes. A canonical roster is structurally unavoidable, and
joining it stays a signature. What changes is what the signature has
behind it: a track record nobody can fabricate.

The naive track record is fabricable for free. An observer holding a
Reference Payload can emit `consistent` Records with perfect similarity
without ever fetching — for unchanged pages, the majority case, the
Payload *is* the answer. Any admission evidence built on coverage and
non-contradiction alone therefore measures publishing discipline, not
auditing. What was missing is a proof of fetch-work, and TLS cannot
supply one (non-repudiation is absent by design; every zkTLS variant is
designated-verifier, and TEE attestation reduces to vendor trust and is
practically forgeable). The proof has to come from the Log's own side:
content whose served bytes are unknowable without fetching.

## Decision

Three mechanisms and one obligation, adopted together:

**1. The observer tier.** Anyone may register as an **Observer** by a
self-signed `observer_register` Registry Update (the third
non-Aggregator-signed class, after `appeal` and
`coverage_attestation`), under the same domain-anchored identity,
self-audit bar, and Log-independence bar §3 sets for Auditors; the
Aggregator MUST verify the registrant's Declaration before sealing,
exactly as §3 has it do for `auditor_admit`, and the check is
falsifiable the same way. An Observer performs an Auditor's duties
voluntarily and identically: VRF selection with its own key, the same
Record schema, the same `prev_record` chain, records served at the
same well-known path. Its
Records carry no weight anywhere — no reputation, no confirmation, no
extension trigger, no sanction. They are public from the day they are
made, which is watch-value on the CT-monitor pattern before it is
admission evidence: anyone can read an Observer's `inconsistent`
verdict on a Publisher whether or not the Log ever counts it. The
Aggregator's transport duty does
not extend to Observers; instead each Observer periodically submits an
`observer_checkpoint` — a signed digest of its record-chain head — and
the Aggregator MUST seal one per Observer per epoch, under a
per-epoch sealing budget (an open parameter below) — subdomain
identities cost a registrant nothing, so an unbounded per-registrant
duty is a flooding surface aimed at the Log. The budget's allocation
is mechanism, not discretion: slots are keyed by the §3 two-label
suffix — a crowd of identities under one suffix consumes one
suffix's slot — and filled in an epoch-rotating derivable priority
(order suffixes by a hash over epoch number and suffix), never a
static order: a fixed queue such as registration height starves
every suffix past the budget permanently, and credit validity hangs
on checkpoint timing, so a discretionary or starvable queue is a
lever — aimable by the Aggregator or by a third party renting a
crowd — that erases a candidate's creditable history before it can
form. Rotation converts permanent zero into a bounded checkpoint
delay that the reveal window must be sized to absorb, and which
checkpoints seal in an over-budget epoch stays derivable by anyone
rather than chosen. A
Record credits toward track record only if covered by a checkpoint
sealed before the outcome it speaks to was knowable; a history cannot
be fabricated retroactively because its chain heads were sealed first.

**2. Canary Domains.** Any party may operate a **Canary Domain**: a
Publisher whose served bytes are pre-committed and later revealed, so
that a party who verdicts without fetching can be caught against
them. Planting is permissionless, and that is load-bearing: canaries
known to their planter discipline everyone except the planter's own
creatures, so Aggregator-only canaries would exempt exactly the party
§11 refuses to trust. The shared machinery: a **canary
pre-commitment** (a Merkle root over the per-Delta served-byte
strings, each embedding a planter nonce) sealed at least K Blocks
before the first Delta it covers, and attributable to no domain until
its reveal — a commitment that named its domain would hand a
fabricator the list of exactly the pages to fetch. Served bytes are
fixed per pre-committed leaf — changeable at Delta boundaries, never
adaptively — which is what makes the embedded nonce verifiable at
reveal rather than a claimed property. The nonce MUST be fresh per
Delta, so that leaves are pairwise distinct: a reused nonce on an
unchanged page makes adjacent leaves byte-identical, and one fetch
then earns credit on every subsequent Delta without contact — the
fetched-once party is exactly who the evidence exists to exclude.
The nonce carries all unguessability: the HMAC salt travels with the
Reference Payload and contributes none. Canaries come in two
classes, and the split is what makes the mechanism affordable.

A **watermark canary** serves its truthful content with the nonce
embedded where §5's extraction normalization discards it — an HTML
comment, an attribute — so its extract, its similarity, and the
honest verdict (`consistent`) are untouched: it commits no fraud,
triggers no extension, eats no sanction, and is indistinguishable
from the dynamic bytes §5's tolerance bands already accept. What
changes is only the raw response body, which is exactly what the
credit commitment covers — one unguessable character, and a
non-fetcher's best guess (the Payload's own bytes) reproduces
nothing. This is the unpredictability property of a
challenge-response retrievability proof, with the page as its own
challenge. Because nothing burns, an established Publisher can
watermark its ordinary Deltas, in its actual tier, indefinitely: the
mature stratum's canary supply is its ordinary population, not a
sacrifice. A watermark canary is a live domain, so its reveal is
availability-windowed rather than permanent — the served-byte strings
are served for a bounded window in which scoring is derivable, then
lapse as a Reference Payload does (WIST-3 §6.1) — because a Log that
kept raw page bytes forever would repeal WIST-1 §3.6's
unconfirmability by side door.

A **fraud canary** deliberately serves content mismatching its
committed Payloads: the full simulation, distinguished from ordinary
fraud by premeditation alone. The K-gap anchors that premeditation to
the affected audits, not the domain's birth, so an established honest
domain can turn fraud canary and the cost is opportunity cost rather
than dedicated farming. The reveal is deadline-bounded, and **a
reveal never voids sanctions**: fraud canaries are sacrificial by
definition and eat their ladder like anyone, so a caught fraudster's
retroactive "it was a test" buys nothing. A reveal's only effects are
Observer/Auditor scoring and statistical reclassification. The class
is the only detector of a party that fetches and then lies, and the
only measure of the roster's true catch rate — a discipline
instrument whose volume is a choice (a domain leaving the system can
die usefully as one), while the recurring supply admission evidence
consumes rides on watermarks.

**3. Credit-positive scoring.** A revealed canary scores fetch-work in
one direction only. **Credit**: a sealed **credit commitment** — the
§5 construction under the same salt, over the served bytes with the
signer's `auditor_id` appended to the message (exact encoding is the
revision's) — that reproduces over the revealed served bytes proves
its signer held those bytes before the reveal: they were unknowable
before it, and the commitment was sealed first. The check is byte
possession, never the verdict, so it reads identically over both
canary classes. The plain `response_commitment` MUST NOT carry
credit, because it says nothing about its signer: keyed by the
Reference Payload's salt alone, every fetcher of a fixed leaf seals
the identical value, and that value is public long before any reveal
— Observer records are served at well-known paths as they are made,
Auditors' Records are sealed by the ordinary pull, and the extension
a fraud canary's first `inconsistent` triggers multiplies the sealed
copies. A proof of fetch-work that can be copied is no proof; binding
the signer into the message makes every
credit value distinct and worthless secondhand. What binding cannot
buy is named in the exposure list. **No demerit for a miss**: a
`consistent` verdict on a revealed canary proves nothing by itself,
because a malicious planter can cloak — serve the matching content to
a targeted party and reveal,
framing an honest fetch as fabrication — and §5 lets
consistent-verdict captures be discarded, so the frame would be
undefendable. Punishing misses would also oblige every party to retain
every capture in self-defense, exploding §5's deliberately scoped
preservation duty. A miss is still not weightless: an encountered
canary with no credit sits on the scoreboard anyone computes, and
that residue is the frame surface the exposure list names. The one
derivable demerit is the **hard hit**, and only a
fraud canary can produce it: a credit commitment matching the
revealed bytes AND a `consistent` verdict where the revealed bytes
mismatch the Payload — proven possession plus proven lie. On a
watermark canary `consistent` is the true verdict, so the combination
does not exist there. It is mechanically checkable end-to-end: with
the served bytes public, anyone recomputes §5's similarity, and a
lying `consistent` must have carried a fabricated in-band value to
survive §3's malformed-evidence rejection; an honest party
structurally cannot produce the combination.

**4. Admission cites the scoreboard.** `auditor_admit` remains what §3
makes it: signed by the Aggregator alone, a judgement — §11 keeps
naming that honestly. What changes is its obligation: an
`auditor_admit` whose subject has an Observer history MUST name its
evidence — the checkpointed record chain and its credit history over
encountered revealed canaries, per reputation tier. That scoreboard
is derivable by anyone while the reveal's served bytes and the
Reference Payload's salt are both live — the revision MUST pin the
reveal and its scoring window inside the Payload availability window
(WIST-3 §6.1), or the credit and hard-hit checks die before the
reveal does — and after they lapse, the sealed `auditor_admit`
naming its evidence is the durable fact: §3's Declaration pattern,
falsifiable when made, trusted on replay. There is deliberately no
promotion predicate — no per-tier floor, no probation window, no
promotion rate limit, and consequently no minority cap on derived
admissions, because no admission can be compelled by satisfying a
formula. The roster's composition stays a curated judgement made in
public against evidence made in public, which is the one
configuration the surveyed ecosystems have ever survived on; the
mechanized promotion predicate is retired to the alternatives below,
with the arguments that would have to be answered to bring it back. The scoreboard does not stop at
admission. Canaries are as unidentifiable to an admitted Auditor as
to a candidate, its Records stay in the Log, and its credit history
keeps accruing — so going dark is not silence but a visible
collapse: a commitment sealed over the Payload's bytes reproduces on
no watermark canary, because the nonce is exactly what a non-fetcher
lacks, while a party that fetches and then lies walks into the hard
hit on every fraud canary it meets. Keeping the rate healthy *is*
doing the duty, at minimum per-Delta contact with every domain that
might be watching. Sustained collapse is therefore evidence for
`auditor_remove` in the same pattern admission uses — read by the
judgement, never by a floor: a mechanized retention predicate fails
on the promotion predicate's grounds at higher stakes, since a
cloaking planter would then farm a removal rather than an admission
denial. The residue that leaves is named in the exposure list.

## What this does not claim

Exposure statements, in §11's spirit — named plainly rather than
narrowed:

- **Camouflage is an arms race.** A fabricator only fails canaries it
  cannot identify without fetching. Canary domains must be
  statistically unremarkable on Log-visible metadata; the defense is
  imperfect, and its value is that even partial camouflage moves
  fabrication cost from zero to "fetch everything that might be one."
  The watermark class moves the equilibrium — at near-zero planting
  cost, prevalence can climb toward the whole byte-stable stratum —
  but only that stratum: a creditable leaf is fixed per Delta, so a
  page serving per-request bytes cannot carry one, and byte
  instability is a durable infrastructure signature a fabricator can
  classify cheaply and mostly ignore thereafter (a page can turn
  stable at a Delta boundary, so the classifier is cheap rather than
  permanent). "Everything" is bounded to the stratum that can hold
  still. The cost side erodes too: after one full fetch of a
  byte-stable page, later unchanged Deltas differ from the cache only
  at the nonce, and HTTP range probes can retrieve it for kilobytes —
  credit at a fraction of a refetch, on a page the prober never
  re-verifies. Planters SHOULD refuse range requests or scatter
  several nonces; even the probe is per-Delta contact with the real
  domain, but what the arms race prices is the cost of credit, not
  its possibility.
- **Fraud canaries still burn, and hard hits reach only where they
  are.** The watermark class removes the recurring burn from
  evidence supply: certifying the mature stratum no longer costs
  mature standing, only the entry aging no ring can skip. What still
  burns is the fraud canary, and it remains the only detector of a
  party that fetches and then lies — the sleeper — and the only
  measure of the roster's true catch rate. Its volume is a choice
  rather than a floor the evidence needs, and a stratum fraud
  canaries never visit is one where rubber-stamping is caught by
  nothing: contradiction attaches only to `inconsistent` filings
  (§4), and an always-`consistent` stamper never files one.
- **Planter diversity is a security parameter.** A scoreboard is only
  as honest as the fraction of encountered canaries the candidate's
  colluders did not plant. A ring inflating a credit rate must supply
  a large share of the Log's canary volume in the relevant tier —
  Log-visible in aggregate even when unattributable per planter.
  Ingestion budgets price the flood; per-planter canary rationing is
  thereby a security parameter, not merely a cost bound; and the
  judgement in mechanism 4 is what absorbs the residue — an
  Aggregator weighing a scoreboard is entitled to weigh who fed it,
  which no formula could without importing the attribution the next
  bullet concedes is absent. Layered, not solved.
- **Fetch-work is provable only at ring granularity.** The
  signer-bound credit commitment stops a party from crediting
  another's published value; nothing stops N identities from sharing
  one fetching backend, each sealing an honest, distinct commitment
  over bytes one fetch obtained. The evidence certifies that a
  signer held the served bytes in time, so fetch cost scales with
  rings, not identities. No scoring rule touches this; the curated
  judgement is the backstop, exactly as it is in every surveyed
  survivor.
- **Post-admission scoring is read by judgement, and the smear rides
  along.** An admitted Auditor's credit rate stays derivable
  (mechanism 4), so shirking and stamping are visible rather than
  free — but the number reaches removal only through the judgement,
  never a floor, so what bounds a sleeper is the operator's will to
  act on a collapsed scoreboard, and what threatens an honest
  Auditor is the cloak-frame smear now operating at removal stakes:
  a planter cloaking one Auditor's fetches can manufacture the same
  collapse. Long windows and planter diversity thin the frame; the
  judgement is what has to tell the framed from the lazy, and the
  smear bullet below concedes per-planter attribution is absent.
  Bounded, not removed.
- **The scoreboard's miss column is a smear channel.** A planter that
  cloaks its canaries for one party's fetches — a candidate's, or an
  admitted Auditor's, per the bullet above — fills that
  party's encountered set with canaries no honest act can credit:
  the cloaked fetch commits to Payload-matching bytes, exactly what a
  fabricator commits to, so no definition of "encountered" filters
  the frame without also letting fabricators discard their misses.
  Because admission is a judgement rather than a formula, the smear
  denies nothing mechanically — but it degrades the very evidence
  this ADR exists to create, an Aggregator reading the scoreboard
  cannot distinguish the framed from the lazy, and the per-planter
  ration bounding the attack is only as enforceable as planting is
  attributable — which the ring bullet concedes it is not, per
  planter. Thinner than the rest of this list.
- **The bootstrap majority persists until a human loosens it in public.**
  Admission is discretionary, so decentralization of the roster is a
  practice, never a mechanism, and it never completes on its own.
  What this ADR adds is legibility, not compulsion: a strong
  scoreboard left unadmitted is a fact anyone can compute and weigh
  against the operator. This is also CT's true history — root
  programs never mechanized away either.
- **The Aggregator retains the admission lever entire.** It can
  ignore a registration, starve nothing (the checkpoint budget is
  derivable), and still decline to admit anyone, forever. The
  remedy is the one §8 invariant 4 already names: the Log is public,
  the scoreboards are recomputable, the data is ODbL, and a
  community that reads curation as capture takes the commons and
  leaves. Exit, not vote.

## Consequences

- The bootstrap problem shrinks rather than dissolves: strangers need
  no trust negotiation to start — an Observer registers
  permissionlessly on day one, its records have watch-value
  immediately, and its track record accrues against evidence nobody
  can fabricate — but admission still ends in a judgement, and the
  supply of watchers is still recruited by the mission rather than
  paid or promised, which the survey says is how every deployed
  watcher ecosystem was actually staffed. The bootstrapping operator
  runs Aggregator and Auditors on day one (§11 already permits and
  states it), and is realistically the mature stratum's first planter
  too — its domains
  mature first, and planting rewards nobody in-protocol — so early on
  the party holding the judgement also supplies most of every
  candidate's encountered set: planter diversity is a growth target,
  not a day-one fact.
- WIST-4 gains: an Observers section alongside §3; Registry Update
  actions `observer_register`, `observer_checkpoint`,
  `canary_commitment`, `canary_reveal`; a
  signer-bound credit commitment field on the Audit Record; the two
  canary classes, with the watermark's extraction-neutrality rule and
  the availability-windowed reveal; the evidence-citation obligation
  on `auditor_admit`; §11 bullets per the exposure list. WIST-1
  through WIST-3 are untouched.
- Open parameters for the spec revision: K (pre-commitment lead),
  epoch length (in Blocks — the suite keeps no other clock),
  per-planter canary ration, canary volume bounds (sized
  against roster ration capacity — N × `extension_triggers_max` per
  30 days — not Log share: every fraud-canary detection consumes its
  first filer's ration, and only the first `inconsistent` for a Delta
  can summon, so a cheap Provisional flood can drain the roster's
  summons before real fraud arrives), the reveal availability window,
  the per-epoch observer checkpoint budget with its suffix-keyed,
  epoch-rotating allocation.
- Divergence handling (adopted alongside, scoped narrowly): what changes is the consequence of *contradiction* — a
  contradicted filer's standing stops feeding a removal predicate,
  and the Delta's sampling escalates with no fault assigned, because
  the Log cannot tell a liar from an honest party at a cloaked
  vantage. The hard hit remains the removal path; it is the one
  demerit that distinguishes the two. This composes with the level-1
  sanction's existing "pressure without penalty" pattern rather than
  absolving cloaking.

## Alternatives considered

- **A derivable promotion predicate, with a minority cap and Trust
  Policy objects** (the rejected design: qualification by
  credit rate over encountered revealed canaries clearing per-tier
  floors across a probation window; derived admissions bounded to a
  roster minority; "which Records count" factored into versioned,
  height-anchored policy objects so a veto is a public policy edit):
  rejected as premature, on four grounds. No deployed transparency
  ecosystem has ever counted a permissionless party's verdicts — the
  survey's own finding — while CT's monitors show watchers arrive on
  mission without an admission promise, so the predicate's
  recruitment payoff is the one leg with no evidence behind it.
  Second, a gameable predicate plus public qualification turns
  accountability into pressure aimed at the honest operator: a ring
  that farms qualification forces a public veto per candidate, and
  the veto's legitimacy, not the ring's, is what erodes. Third, the
  predicate is what forced the heaviest machinery — per-tier floors
  (whose empty case has no good answer), probation windows, promotion
  rate limits, the cap, the policy objects — parameters nobody can
  size before observed Observer and canary data exists. Fourth, the
  mechanisms adopted above generate exactly that data, so the
  predicate loses nothing by waiting: it can return as its own
  revision, arguing against this entry, floors sized against a Log
  that has actually run. The policy-object factoring has value
  independent of admission (leaving a default policy as an edit
  rather than a fork) and may likewise return on its own merits.
- **Miss-punishment scoring** (demerit for `consistent` on a revealed
  canary): rejected; the cloaking-planter frame is undefendable under
  §5's capture-discard rule, and defending would require universal
  capture retention. Credit-positive scoring needs no defense because
  no demerit lands without a matching sealed commitment.
- **PSL-based independence test**: rejected twice over. The 2-label
  rule's false-dependence direction is §3's stated, deliberate
  conservatism; the claimed false-independence direction cannot be
  constructed. PSL would *weaken* the test — free-subdomain providers
  sit in its private section, making `a.github.io`/`b.github.io`
  independent registrable domains — and imports a mutable, curated,
  out-of-Log artifact into a pure-replay function.
- **Commit-reveal on confirmations**: rejected as marginal. The
  extension rule seals the triggering Record before summoning peers,
  so the verdict under confirmation is public by construction; hiding
  it fails cheaply because triggers are base-rate `inconsistent` and a
  parrot invents an in-band similarity. Canaries, carrying the
  signer-bound credit commitment, are the anti-parroting defense.
- **Fraud-only canaries** (every canary a sacrificial mismatch):
  rejected as the evidence supply. Credit checks raw-byte possession,
  not the lie, so the burn bought nothing the watermark does not buy,
  and it priced the mature floor as a continuously unfunded public
  good — mature standing grown for months and killed per cohort,
  forever. Retained as the low-volume discipline class, which is the
  one thing the watermark cannot do.
- **Bonds or stake as admission cost**: rejected; prices out the
  honest independent operator, does not deter a funded adversary, and
  "capital predicts honesty" contradicts the suite's premises.
- **zkTLS / TEE attestation as proof of fetch**: rejected as
  foundation; designated-verifier by construction (TLS non-repudiation
  is absent by design), and hardware attestation relocates trust to a
  vendor and is practically forgeable. Admissible someday as optional
  evidence-strengthening, never load-bearing.
- **Purely consumer-relative reputation** (no canonical roster):
  rejected; `reputation_u` feeds selection, quotas, and ingestion, so
  the Aggregator must seal Blocks against one answer. The control loop
  is why one roster exists.
- **Cluster eviction as mechanism**: rejected; the discriminating
  correlations (hosting, timing infrastructure) are not in the Log,
  and a clustering judgement sealed as a removal violates §1. Salvage:
  fully specified verdict-correlation derivations MAY be published as
  evidence for Consumers and for the admission judgement, never as a
  derived removal.

The question this ADR settles reopens only against its arguments: a
scheme that counts a permissionless verdict must first show a deployed
precedent or this Log's own Observer data, then answer the control
loop; a cheaper proof of fetch-work must first answer the frame and
the collusion bounds above.

## Addendum (2026-09-05) — what the revision pinned

The decision above left parameters open and encodings to the revision.
This records what WIST-4 now says, and where the revision read the
decision in one of several possible ways, so that the choice is a fact of
record rather than of code.

**Parameters.** K, the pre-commitment lead, is `canary_lead_blocks` = 24:
one day at the default cadence, the smallest span the suite already
treats as a unit, so that a commitment sealed the Block before its Delta
cannot pass for premeditation at cadence granularity. The epoch is
`epoch_blocks` = 24, the same day; the checkpoint budget is
`observer_checkpoint_budget` = 1024 suffixes per epoch — a thousand tiny
Entries a day costs an Aggregator nothing, and a registrant must buy
apex domains, not subdomains, to consume slots. The reveal minimum is
`canary_reveal_min_blocks` = 168 after the newest bound Delta, plus one
rotation of the checkpoint budget derived from the suffixes registered
at that Delta's Block — the composition §9 states, 144 hours at the
defaults against the 168 the minimum gives — and the lifetime
`canary_lifetime_blocks` = 1440 from the commitment. Leaves per
commitment are `canary_leaves_max` = 1024. The reveal's scoring window is
`payload_window_days`, reused rather than added: the served bytes lapse
as a Reference Payload does, and the planter serves the leaves' Reference
Payloads itself for the same span, which is what pins the window inside
salt availability without touching WIST-3 §6.1's duties.

**Canary volume.** The decision asked for canary volume bounds sized
against the roster's ration capacity, because every fraud-canary
detection consumes its first filer's summons. No such bound is
enforceable: a commitment does not say which class it is, and a fraud
canary is indistinguishable from fraud until its reveal. What §5.1
rations is what the Log can see — `canary_commitments_max` = 8
commitments per planter suffix per epoch — which bounds Log growth from
planters that never reveal. The ration-drain a fraud-canary flood could
cause is the ration-drain any fraud flood causes, and §4's per-triggerer
ration is the answer to both; §11 states it.

**Encodings.** The credit commitment is HMAC-SHA256 under the Reference
Payload's salt over the raw response body with the signer's `auditor_id`
appended as UTF-8 — the reference Delta's salt, per ADR-0016, so that the
check and the Record's other commitments share one lifecycle. A leaf is
`SHA-256(0x00 ‖ served bytes)` in WIST-3 §4's tree, the nonce embedded in
the bytes rather than keyed separately: one secret plays both roles, the
unguessability a fetcher must prove and the hiding that keeps a leaf from
being a bare digest of content, and §9.1 says so where it forbids bare
digests. The leaf-to-Delta binding is declared at the reveal and checked
against the Log then — inclusion under the committed root, the canary
domain's own Delta, sealed past the lead — rather than committed, because
a commitment cannot name Deltas that do not yet exist; a false binding
can only cost the planter's own canary its credits, since every credit
check keys by the Record's own Reference Payload.

**Who signs what.** A `canary_commitment` is signed by the planter, a
domain holding a Declaration, and names it as `subject`: attributable to
a planter, never to a canary domain. A `canary_reveal` is signed by the
canary domain's Key Set and names it as `subject`: only a domain's own
keys can declare it a canary, which is what stops a third party from
"revealing" a byte-stable public page it merely fetched and crediting
itself against it. The decision's "attributable to no domain until its
reveal" is met for the canary domain and deliberately not for the
planter; what a ring can do with many planter identities is priced per
suffix and conceded in §11.

**The hard hit reads both classes.** The decision named the hard hit as
`consistent` on a fraud canary with possession proved. The revision
defines it symmetrically: possession proved and a verdict two bands from
the bytes — `consistent` where the bytes derive below
`similarity_variance_floor`, or `inconsistent` where they derive at or
above `similarity_consistent`. The mirror catches a party that fetches a
watermark and files `inconsistent`, which is the false-`inconsistent`
griefer the retired divergence predicate used to police; the
`dynamic_variance` band between the two keeps a boundary computation
from ever being a demerit. An honest party structurally produces
neither, for the reason the decision gives for the first form.

**Transport.** Self-signed acts — `observer_register`,
`observer_checkpoint`, `canary_commitment`, `canary_reveal` — are served
at `/.well-known/wist/registry.json` and pulled with the Feed, at the
baseline interval, and per epoch for a budgeted Observer; the Aggregator
seals what verifies within `record_seal_blocks`. The decision expected
WIST-1 through WIST-3 untouched; WIST-2 §3's layout gained the path and
the leaf-serving path, and WIST-3 §7's state artifact gained the
`observer` and `canary_commitment` kinds (and, with the divergence
rework, `escalation`), because a resuming Consumer must reject the same
acts a replaying one does. Nothing else in those documents changed.

**Admission evidence.** `track_record` on an `auditor_admit` carries the
newest sealed checkpoint's ID and a three-tier scoreboard — tiers read
from the Provisional gate and `latency_threshold_u`, adding no
parameter. Its presence is a replay condition (`WIST4-E04` either way);
its content is not, because two replayers at different heights hold
different reveals and must not derive different rosters. It is the
Declaration pattern the decision named: falsifiable when made, trusted
on replay.

**Divergence.** The contradiction consequence landed as decided, as its
own revision: contradiction escalates the audited domain's sampling for
30 days from the Block at which the extension closes, and feeds no
removal; `contradictions_max` is retired. The closing instant — the
first Block sealed more than `confirm_window_hours` after *B₁* — is the
instant the frozen text never named, and the extension pull that lets a
summoned Record seal inside that window at all was found missing by the
same audit and added beside it.


**Checkpoint order (2026-09-05).** The allocation stays suffix-keyed and
epoch-rotating, but the rotation is a walk rather than a fresh draw:
suffixes sit in a fixed order by `SHA-256(suffix)` and each epoch budgets
the window of one budget starting at position epoch × budget mod S. The
order drawn afresh per epoch that the revision first shipped bounded
nothing — two suffixes under a budget of one could see the same winner
three epochs running — while §5.1's reveal minimum relies on the
`⌈S / observer_checkpoint_budget⌉` bound the walk actually delivers.
