# WIST Protocol Suite

An open, verifiable, push-based web index protocol for local AI agents.

Sites publish signed **deltas** about their own URLs; an **aggregator**
sequences them into a public, hash-chained, append-only log (the
Certificate Transparency model); **consumers** download a compact snapshot
once, then follow an hourly delta stream — and query everything locally.
No crawling for freshness, no trust in any operator: consumers verify
signatures and hashes, never sources.

```
Publisher                 Aggregator                    Mirrors / Consumers
   │ writes delta to          │                               │
   │ /.well-known/      ──►   │ pulls, validates signature,   │
   │ and sends ping           │ dedups, queues                │
   │                          │ seals hourly Block,     ──►   │ sync blocks,
   │                          │ signs, chains                 │ verify chain,
   │                          │                               │ apply to local index
Auditor ◄── samples deltas from sealed blocks ──┘             │
   │ re-fetches URL, emits signed audit record ──► enters the log like any delta
```

## Documents

| Doc | Title | Status |
|-----|-------|--------|
| [WIST-1](specs/WIST-1-delta-format.md) | Delta Format & Identity — the signed delta object, JCS canonicalization, domain-anchored Ed25519 keys | v1.0.0-draft |
| [WIST-2](specs/WIST-2-site-publication.md) | Site Publication — `.well-known` layout, feed, ping + pull, unsigned-hint compatibility | v1.0.0-draft |
| [WIST-3](specs/WIST-3-logbook-distribution.md) | Logbook & Distribution — blocks, Merkle proofs, checkpoints, snapshots and tiers, sync | v1.0.0-draft |
| [WIST-4](specs/WIST-4-audit-reputation-governance.md) | Audit, Reputation & Governance — sampling, verdicts, the reputation function, sanctions, constitutional invariants | v1.0.0-draft |

The suite was frozen on 2026-08-05. Changes made to a document since then are
recorded in [ERRATA.md](ERRATA.md), which also states the bar a change must
clear to qualify as errata rather than as a revision.

## Repository layout

```
specs/       the four protocol documents
schemas/     JSON Schema (draft 2020-12) for every normative object
examples/    one validated example per object type
vectors/     deterministic test vectors (WIST-1 signature, WIST-2 link
             extraction, WIST-3 Merkle and snapshot records, WIST-4 sampling,
             reputation, decay table, audit commitments, link agreement)
tools/       vector generator and validation harness
decisions/   ADRs recording the load-bearing design decisions
```

## Verifying the suite

```bash
python -m venv tools/.venv
tools/.venv/bin/pip install -r tools/requirements.txt
tools/.venv/bin/python tools/validate_examples.py   # validates examples + vectors
tools/.venv/bin/python tools/gen_vectors.py         # regenerates (byte-identical)
```

The harness validates every example against its schema, recomputes the
WIST-1 delta ID and Ed25519 signature, recomputes the payload commitment
that binds a delta to content the log does not carry, and recomputes the
WIST-3 Merkle root and inclusion proof. Vector generation is fully
deterministic: fixed test seed, fixed timestamps, no wall-clock.

## Design decisions

- [ADR-0001](decisions/0001-jcs-canonicalization.md) — JCS (RFC 8785) for canonicalization
- [ADR-0002](decisions/0002-ed25519-domain-anchored-identity.md) — Ed25519 keys anchored to the domain
- [ADR-0003](decisions/0003-ping-plus-pull.md) — publication is ping + pull, never content push
- [ADR-0004](decisions/0004-log-centric-ct-model.md) — append-only log with signed checkpoints (CT model)
- [ADR-0005](decisions/0005-odbl-for-tier-data.md) — ODbL for public tier data
- [ADR-0006](decisions/0006-no-self-declared-importance.md) — no self-declared importance anywhere in the protocol
- [ADR-0007](decisions/0007-content-payloads-outside-the-log.md) — content payloads live outside the immutable log
- [ADR-0008](decisions/0008-raw-citation-graph-never-a-score.md) — the protocol transports the raw citation graph, never a score
- [ADR-0009](decisions/0009-embeddings-outside-the-trust-boundary.md) — embeddings live outside the trust boundary, as companion packs

## Licenses

- Specification text: [CC-BY 4.0](LICENSE)
- Public tier data (snapshots produced by conforming aggregators): ODbL 1.0
