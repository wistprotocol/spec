# ADR-0010: Bounded Auditor fetches

**Status:** draft · **Date:** 2026-08-11

## Context

An Auditor owes a Record for each selected Delta within its coverage
deadline. Without explicit fetch limits, a hostile Publisher can choose
the Auditor's bandwidth and waiting cost. Different client defaults can
also produce different verdicts over the same page, undermining the
suite's otherwise pinned selection and measurement rules.

WIST-4 §5 specifies fetch outcomes and §9 defines their resource parameters.

## Decision

`audit_fetch_cap_bytes`, default 8 MiB, caps a single audited response.
`audit_domain_budget_bytes_day`, default 1 GiB, bounds an Auditor's fetch
bytes per domain per UTC day, including Reference Payload traffic.
`audit_redirect_max`, default 5, and `audit_fetch_timeout_seconds`,
default 30, bound redirects and elapsed fetch time.

With a usable Reference Payload, an observed-side byte-limit failure is
`not_auditable`, `unmeasured = observed`, and blocking. Transport-limit
failure for the audited URL is `unreachable`. When the reference itself
cannot be obtained and verified with a nonempty normalized extract, the
result is `not_auditable`, `unmeasured = reference`, nonblocking, including
budget, timeout and redirect exhaustion. A previously obtained usable
reference remains available after the budget expires. No fetch order is
implied. [ADR-0016](0016-audit-reference-follows-the-chain.md) explains
the reference's identity and interpretation.

Unmeasured outcomes omit measurement commitments and similarity: a failed
or truncated retrieval is not an authenticated measurement of the page.
The sealed outcome records which side was unavailable, not a replayable
network transcript of the Auditor's budget. Independence and confirmation
address false reports; the bounds alone do not authenticate a fetch claim.

## Consequences

Published limits bound exposure and align client behavior at resource
boundaries. Ordinary oversized pages can become unavailable in derived
materialization without being accused of fabrication. Missing reference
evidence does not make the page itself blocking.

The cost still scales with the number of Auditors; these are per-Auditor
bounds, not a shared fetch cache or a sharded duty. Live-network validation
must exercise oversized bodies, daily budget exhaustion, redirects,
timeouts and the observed/reference distinction.

The fetch-cap floor and its relation to `extract_cap_bytes` prevent a
parameter change from making full-cap extracts systematically unmeasurable.
Failure verdicts still discharge their applicable coverage duties; refusing
an oversized response does not itself turn a completed audit into shirking.

## Alternatives considered

**Implementation-defined limits:** let ordinary client choices change
verdicts at the same input boundary.

**Unlimited reads with voluntary abandonment:** leave a selected Auditor
choosing between unbounded work and an undischarged protocol duty.

**One failure outcome for either side:** confuses unavailable evidence with
an unmeasurable observed page and can wrongly exclude that page.
