# ADR-0004: Append-only hash-chained log with signed checkpoints (CT model)

**Status:** draft, amended by [ADR-0046](0046-single-tree-log.md) (2026-09-17: the Log is one RFC 6962 tree published as C2SP checkpoints and tiles, an Epoch is an interval of it, and a consistency proof replaces the hash chain between Epochs) · **Date:** 2026-08-02

## Context

The aggregator is logically central. The design must ensure it holds no
unaccountable power: it must be unable to forge, rewrite, or selectively
show history — and it must be replaceable.

## Decision

All system events (Declarations, Catalogs and Items, Labels and
disputes, governance acts) are sequenced into an
append-only, hash-chained, signed log with per-Epoch Merkle roots and
signed checkpoints, following the Certificate Transparency model.

## Consequences

- The aggregator cannot forge content (publisher signatures), rewrite
  the past (chain), or equivocate undetected (two conflicting signed
  checkpoints are portable proof of misbehavior).
- Reputation and every derived artifact are pure functions of public
  data — anyone can recompute them, so the aggregator is substitutable
  by construction and the commons is forkable.
- Distribution reduces to immutable static files: CDN/torrent/IPFS-
  friendly, near-zero marginal cost, mirrors need no trust.
- Operating cost is trivial compared to consensus systems: one signer,
  many verifiers.

## Alternatives considered

- **Blockchain/consensus**: pays the cost of decentralized *writing* to
  get properties this design already gets from verifiable *reading*;
  heavy dependencies, no added guarantee for this trust model.
- **Plain database dumps**: no tamper-evidence, no equivocation proof,
  aggregator becomes a trusted party — exactly what the design forbids.
