# ADR-0010: Bounded Auditor fetches

**Status:** accepted · **Date:** 2026-08-11

## Context

Every fetch magnitude in the suite is bounded except the one that matters
most to the party least able to refuse it.

An Aggregator's pulls are bounded twice: `ingest_budget_bytes_day`
(default 1 GiB per domain per day) exists precisely because "a single Ping
would otherwise oblige terabytes of pulls, an amplification no quota
reaches" (WIST-2 §5), and its redirect rule pins which hops it follows at
all (WIST-2 §8). Blocks are bounded by `block_decompressed_cap_bytes`.
Payload content is bounded four times over, by `extract_cap_bytes`,
`links_cap_bytes`, `link_url_cap_bytes` and `summary_cap_bytes`. The
Auditor's fetch of the audited URL — a request to a server the Auditor does
not control, chosen for it by a VRF draw it cannot decline — carries no
size cap, no redirect ceiling, and no timeout.

Two things follow, and only one of them is about cost.

The **recomputability** failure is the graver one. WIST-4 §4 spends its
argument on making selection recomputable to the last digit, on the
grounds that "two honest Auditors using two correct `libm`s could have
disagreed about whether a given Delta was theirs to audit — and, under the
coverage duty, one of them would be provably in breach for a Delta the
other never owed." The fetch layer reproduces that defect one section
later: two honest Auditors with different implicit limits reach different
verdicts on the same URL, one recording a measurement and the other
recording nothing, and §5's confirmation machinery reads the disagreement
as evidence rather than as the artifact of an unpinned boundary. A
similarity computed in pinned integers over a representation obtained
under unpinned limits is not recomputable, whatever the arithmetic does.

The **cost** failure follows from the coverage duty. An Auditor owes a
Record for every selected Delta within `coverage_deadline_hours` or accrues
a coverage failure, so it cannot walk away from a hostile response: it must
fetch, and no verdict is defined for the case where it declines to read
further. A Publisher may therefore serve arbitrarily large responses to
every Auditor that draws it, at a cost the Publisher chooses and the
Auditors pay, with no per-domain ceiling of the kind the Aggregator was
given for the identical amplification.

## Decision

Four parameters bound an Auditor's fetch of an audited URL, and the two
kinds of limit resolve to the two verdicts that already exist.

**Bounds on what is read.** `audit_fetch_cap_bytes` (default 8 MiB) caps
the response body an Auditor is obliged to read for one audited URL, and
`audit_domain_budget_bytes_day` (default 1 GiB) caps what one Auditor is
obliged to fetch for one domain in one UTC day. A Delta whose audit cannot
be completed inside either bound is recorded `not_auditable`, and such a
Record is a **blocking Record** in the sense §5 already defines — the same
disposition the non-HTML rule and the mass guard carry, for the same
reason: the page cannot be measured, the Publisher is not accused of
anything, and two independent such Records exclude the URL from
materialization until one measurable page restores it.

**Bounds on the transport.** `audit_redirect_max` (default 5) and
`audit_fetch_timeout_seconds` (default 30) pin when an Auditor stops
following hops and stops waiting. Exceeding either yields `unreachable`,
which is where transport failure already lands; the parameters add no
verdict, only a boundary two Auditors share.

Neither bound alters what a Record carries. `unreachable` and
`not_auditable` already omit `response_commitment`,
`ref_extract_commitment`, `evidence_commitment` and `similarity`, on the
stated grounds that "whatever bytes the failure produced are not the page
and are not committed to" — which describes a truncated read exactly. The
Record schema is unchanged, the verdict set is unchanged, and no error code
is added: a replayer can no more verify a fetch-limit claim than it can
verify a timeout, and §5's independence requirements, not a new code, are
what make a false one costly.

## Consequences

- An Auditor's exposure per audited URL is bounded by a published number
  instead of by its own undocumented client configuration, and the
  disagreement §4 eliminated for selection is eliminated for the fetch.
- Flooding is self-limiting and self-contained. The budget is per-domain,
  so a Publisher serving oversized responses spends its own egress to
  exclude its own URLs from materialization, and reaches no other
  Publisher's. It also cannot induce a coverage failure in the Auditors it
  targets, because `not_auditable` discharges the coverage duty like any
  other verdict.
- The floors matter more than the defaults. `audit_fetch_cap_bytes` bounded
  below by 65 536 octets keeps the cap above twice the largest `extract` a
  Publisher may commit to, so no `parameter_change` can shrink it into a
  state where honest pages carrying a full-cap extract are unmeasurable —
  which, through the blocking-Record path, would be a governance route to
  excluding the whole web from materialization without sanctioning anyone.
- An honest Publisher of genuinely enormous pages loses materialization for
  those URLs rather than reputation, and has the same remedy the non-HTML
  boundary offers: serve a representation the audit mechanism can read.
- The suite gains a stated position it lacked: an audit fetches one HTML
  document and one Payload, both bounded, and an Auditor's operating cost
  is therefore derivable from published parameters rather than from
  assumptions about the pages it will meet.
