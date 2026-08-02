# DeltaCommons Protocol Suite

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
| [DC-1](specs/DC-1-delta-format.md) | Delta Format & Identity — the signed delta object, JCS canonicalization, domain-anchored Ed25519 keys | v1.0.0-draft |
| [DC-2](specs/DC-2-site-publication.md) | Site Publication — `.well-known` layout, feed, ping + pull, unsigned-hint compatibility | v1.0.0-draft |
| [DC-3](specs/DC-3-commons-log-distribution.md) | Commons Log & Distribution — blocks, Merkle proofs, checkpoints, snapshots and tiers, sync | v1.0.0-draft |
| [DC-4](specs/DC-4-audit-reputation-governance.md) | Audit, Reputation & Governance — sampling, verdicts, the reputation function, sanctions, constitutional invariants | v1.0.0-draft |

## Repository layout

```
specs/       the four protocol documents
schemas/     JSON Schema (draft 2020-12) for every normative object
examples/    one validated example per object type
vectors/     deterministic test vectors (DC-1 signature, DC-3 Merkle)
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
DC-1 delta ID and Ed25519 signature, and recomputes the DC-3 Merkle root
and inclusion proof. Vector generation is fully deterministic: fixed test
seed, fixed timestamps, no wall-clock.

## Design decisions

- [ADR-0001](decisions/0001-jcs-canonicalization.md) — JCS (RFC 8785) for canonicalization
- [ADR-0002](decisions/0002-ed25519-domain-anchored-identity.md) — Ed25519 keys anchored to the domain
- [ADR-0003](decisions/0003-ping-plus-pull.md) — publication is ping + pull, never content push
- [ADR-0004](decisions/0004-log-centric-ct-model.md) — append-only log with signed checkpoints (CT model)
- [ADR-0005](decisions/0005-odbl-for-tier-data.md) — ODbL for public tier data
- [ADR-0006](decisions/0006-no-self-declared-importance.md) — no self-declared importance anywhere in the protocol

## Licenses

- Specification text: [CC-BY 4.0](LICENSE)
- Public tier data (snapshots produced by conforming aggregators): ODbL 1.0
