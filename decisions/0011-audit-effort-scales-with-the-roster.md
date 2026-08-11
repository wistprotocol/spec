# ADR-0011: Audit effort scales with the roster, by design

**Status:** accepted · **Date:** 2026-08-11

## Context

WIST-4 §4 selection is per-Auditor over every Delta: each admitted
Auditor draws its own share of the whole Log, so a roster of N costs N
times one Auditor's fetch volume and buys coverage rather than division
of labour. §11 states the property; this record states why the two
obvious remedies were rejected, so that the question is not reopened
without meeting the arguments.

Both remedies are real designs, not strawmen. **Sharding** partitions
the Deltas of a Block among the roster, so total effort is the
redundancy factor rather than N. A **fixed budget** has each Auditor
audit the K Deltas in a Block with the smallest draws, so one Auditor's
bill never grows with the web. Either would let a small operator audit
an arbitrarily large corpus.

## Decision

Selection stays independent per-Auditor sampling. The scaling lever is
the pair the registry already carries: `sampling_floor` and roster
size. Coverage goes as N × p at the rates in question, so halving the
floor while doubling the roster holds detection constant and halves
each Auditor's bill — a `parameter_change` and an admission policy,
no protocol change.

**Sharding is rejected because it turns blind grinding into sighted
grinding.** Block membership is the Aggregator's one remaining
grinding dimension (§11). Under sampling that grind is blind: the
Aggregator holds no Auditor key, so for a candidate Block hash it
cannot compute anyone's selection — it can rerandomize, never choose.
A shard assignment, to be verifiable, must be derivable from public
inputs; then the Aggregator evaluates each candidate membership,
sees exactly which one lands a target Delta in a captured Auditor's
shard, and grinds with feedback until one does. Hiding the assignment
instead requires a secret shared across the roster — distributed key
generation, a liveness dependency for every Block, and a secret that
capturing the same Auditors reveals anyway. The cost argument then
closes the case: sharding at redundancy r and sampling at N × p = r
fetch the same total volume. Same bill, and the assignment goes from
unknowable to computable.

**A fixed budget is rejected because it hands the sampling rate to the
attacker.** Under top-K, per-Delta scrutiny is K / M where M is the
Block's Delta volume — and M is purchasable. A single Provisional
domain may seal Deltas up to `domain_block_entries_max` per Block
inside `ingest_budget_bytes_day` (WIST-3 §3.2, WIST-2 §5) — thousands
a day — so M scales with domain registrations, at commodity prices,
and a Delta stream of self-consistent junk pages is fully conforming:
it dilutes every honest Publisher's scrutiny while accruing reputation
for the domains serving it, and no replay distinguishes it from
adoption. No parameter restores detection while the flood persists
except raising K, which is abandoning the budget. Under the rate, the
same flood cannot touch detection — per-Delta probability is p
regardless of M — and what it attacks instead is Auditor cost, which
is the governable currency: `audit_domain_budget_bytes_day` (ADR-0010)
caps what any one flooding domain can oblige, and the floor-and-roster
lever re-tunes the rest. The two designs fail under the same attack in
different currencies, and the budget fails in the one no parameter can
restore.

The honest cost of this decision: a budget self-adjusts as the web
grows, while the floor moves only by governance. Keeping detection
affordable is a stewardship duty, not an automatic property.

## Consequences

- One Auditor's steady-state bill is proportional to corpus churn times
  the reputation-weighted rate, derivable entirely from published
  parameters — and it is the same bill whether the roster is one or
  one hundred.
- Roster growth is the honest way to spread cost: N operators each pay
  a floor that governance can lower as N rises, holding N × p — the
  detection the network buys — where the roster wants it.
- The question reopens only if corpus growth makes the floor rate
  unaffordable for a modest independent operator faster than the
  roster grows. The first response is the lever above. A budget-shaped
  scheme is admissible only with an anti-dilution rule that makes
  per-Delta scrutiny independent of Block volume — which is the
  property the rate already has.
- The bound is per-Log, not per-web. The suite already follows the
  Certificate Transparency model (ADR-0004), where no monitor watches
  every log: Publishers partition across Logs by their own public,
  domain-level choice, each Log carries its own roster, and a Consumer
  weighs a roster before following its Log (§11, WIST-3 §8). That
  partition is safe where an in-Log shard is not, because it is coarse,
  visible, and disciplined by Consumers declining a weakly-audited Log
  — so at any scale, the unit an Auditor must afford is one Log, and
  the web is several.
