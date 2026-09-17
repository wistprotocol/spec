# ADR-0042: Quota and capacity are accounted per registrable domain

**Status:** draft · **Date:** 2026-09-17

## Context

WIST-1 §3.8 makes every Canonical Host a separate Publisher identity,
and every bound the suite places on how much one party may publish was
keyed on that identity: the Ping quota (WIST-2 §4, `quota_base` per UTC
day), the ingest budget (WIST-2 §5, `ingest_budget_bytes_day`) and the
per-domain Block capacity (WIST-3 §3.2, `domain_block_entries_max`).
Every one of them is defeated for free. A first-year domain costs cents
at some registries; a hostname under a domain one already holds costs
nothing; a subdomain on a shared host — `pages.dev`, `github.io`,
`vercel.app` — costs nothing and needs no registrar. Under per-hostname
accounting, a thousand hostnames are a thousand quotas, a thousand
budgets and a thousand capacities, and the flat, equal bounds Invariant
2 rests on bind only the party that declines to create names.

Systems that ration or block by domain solved this the same way: email
blocklists, Let's Encrypt's rate limits and Mastodon's domain blocks all
key on the registrable domain under the Public Suffix List, whose
private section records that a hosting provider's customers under one
suffix are different parties. The list changes over time, so the
revision read has to be fixed for a decision to replay.

Identity granularity cannot be retrofitted after deployment: a Log that
sealed Blocks under per-hostname capacity and switches the unit changes
which sealed Blocks are valid, which is a new major version under
PUBLICATION.md. The unit has to be right before the deployment
boundary.

## Decision

- **Accounting is per Registrable Domain.** The Ping quota, the ingest
  budget and the per-domain Block capacity are keyed on the Canonical
  Host's Registrable Domain under the Public Suffix List algorithm, both
  sections included: `a.example.com` and `b.example.com` share one
  unit; `alice.github.io` and `bob.github.io` are separate because the
  private section lists `github.io`. A host the list leaves no
  registrable domain for — a listed suffix, a single label, a host a
  wildcard rule swallows whole — is its own unit (WIST-4 §3.1).
- **The snapshot is pinned in the Log.** A `suffix_list_update`
  Registry Update names a Public Suffix List snapshot by the SHA-256 of
  its octets and their count; the Aggregator serves the octets beside
  the Log and Mirrors retain them without expiry. An accepted act is in
  force from the Block after its sealing Block. Before the first
  accepted act, every Canonical Host is its own unit, and an Aggregator
  is advised to pin its first snapshot in Block 0. A Snapshot's
  `suffix_list` tuple carries the snapshot in force so a resuming
  Consumer accounts the next Block as a replaying one does.
- **Identity, signing and scope stay per Canonical Host.** A Publisher
  is still its hostname with its own Declaration, chain, scope and
  status endpoint; hosts sharing a unit share nothing else.
- **Ranking guidance.** WIST-4 §6 recommends that trust and distrust
  propagation collapse the hosts of one Registrable Domain into one node
  under the snapshot in force, keeping private-section hosts separate,
  and read a domain's age from the height of its first sealed Entry,
  never from WHOIS or registration data.

## Alternatives considered

- **Per-hostname accounting (the status quo).** Simplest; makes every
  bound a bound on the unimaginative only.
- **A built-in suffix list, or the list at a URL read live.** A built-in
  list freezes the revision at the edition and a live read gives two
  Consumers two answers for one Block; neither replays identically.
  Pinning by digest with the file served beside the Log keeps the Log
  self-describing at the cost of one small immutable artifact per act.
- **Registrable domain without the private section.** Treats every
  customer of a hosting provider as one party, which makes a provider's
  suffix one quota for thousands of unrelated sites and hands the first
  customer to exhaust it a veto over the rest.
- **A grace period on snapshot changes, as parameter amendments have.**
  A snapshot change merges or splits accounting units; the exposure is
  one Block's capacity and one day's quota, and the act is public the
  moment it seals. Immediate effect from the next Block was chosen for
  simplicity; a grace period can be added as a refinement if operators
  need notice.
- **Keying the ingest budget per hostname while keying quota and
  capacity per registrable domain.** Leaves the budget, the one bound
  that protects the Aggregator's own fetch costs, open to the same free
  hostnames; the three bounds are keyed alike.

## Consequences

- A hostname farm under one registrable name holds one quota, one
  budget and one capacity. What remains unbounded is registration: a
  thousand cheap domains are a thousand units, priced by the registries
  and visible in the Log as a thousand fresh identities.
- Every Consumer that checks per-domain capacity fetches the snapshot
  in force; the file is a few hundred kilobytes and immutable.
- The vector `vectors/wist4/registrable-domain.json` transcribes the
  Public Suffix List project's own test cases over a fixture snapshot
  and replays acts, a snapshot advance, capacity and quota; the
  reference tools implement the algorithm twice and check both against
  those cases.
- Implementations key their quota, budget and capacity accounting on
  the Registrable Domain, seal and serve snapshots, and adopt the
  `suffix_list` tuple.
