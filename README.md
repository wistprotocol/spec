# WIST Protocol Suite

**Status: editable draft under implementation and validation.**
Development and publication rules: [PUBLICATION.md](PUBLICATION.md).

An open, verifiable, push-based web index protocol for local AI agents.

Sites publish signed **deltas** about their own URLs; an **aggregator**
sequences them into a public, hash-chained, append-only log (the
Certificate Transparency model); **consumers** download a compact snapshot
once, then follow an hourly delta stream — and query everything locally.
Consumers verify signatures and hashes locally.

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

## Repository layout

```
specs/       the four protocol documents
schemas/     JSON Schema (draft 2020-12) for every normative object
examples/    one validated example per object type
vectors/     deterministic test vectors (WIST-1 signature and Declaration
             sequencing, WIST-2 link extraction, WIST-3 Merkle and snapshot
             records, WIST-4 sampling, reputation, decay table, audit
             commitments, link agreement, replay derivations, the audit
             reference Delta, canary scoring, observer checkpoints)
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

`tools/unicode_tables.py` is generated from the Unicode Character
Database for the release [ADR-0017](decisions/0017-one-pinned-unicode-version.md)
pins, by `tools/gen_unicode_tables.py`; it is committed, so validation and
generation stay offline, and the script is re-run only when that release
moves.

The harness validates every example against its schema, recomputes the
WIST-1 delta ID and Ed25519 signature, recomputes the payload commitment
that binds a delta to content the log does not carry, and recomputes the
WIST-3 Merkle root and inclusion proof. Vector generation is fully
deterministic: fixed test seed, fixed timestamps, no wall-clock.
[tools/VERIFICATION.md](tools/VERIFICATION.md) inventories, per vector
family, the independent anchor its verification rests on.

## Design decisions

- [ADR-0001](decisions/0001-jcs-canonicalization.md) — JCS (RFC 8785) for canonicalization
- [ADR-0002](decisions/0002-ed25519-domain-anchored-identity.md) — Ed25519 keys anchored to the domain
- [ADR-0003](decisions/0003-ping-plus-pull.md) — Publication is ping + pull, never content push
- [ADR-0004](decisions/0004-log-centric-ct-model.md) — Append-only hash-chained log with signed checkpoints (CT model)
- [ADR-0005](decisions/0005-odbl-for-tier-data.md) — ODbL for public tier data
- [ADR-0006](decisions/0006-no-self-declared-importance.md) — No self-declared importance anywhere in the protocol
- [ADR-0007](decisions/0007-content-payloads-outside-the-log.md) — Content payloads outside the immutable log
- [ADR-0008](decisions/0008-raw-citation-graph-never-a-score.md) — The protocol transports the raw citation graph, never a score
- [ADR-0009](decisions/0009-embeddings-outside-the-trust-boundary.md) — Embeddings live outside the trust boundary, as companion packs
- [ADR-0010](decisions/0010-auditor-fetch-limits.md) — Bounded Auditor fetches
- [ADR-0011](decisions/0011-audit-effort-scales-with-the-roster.md) — Audit effort scales with the roster, by design
- [ADR-0012](decisions/0012-auditor-track-record-becomes-derivable.md) — Auditor track record becomes derivable
- [ADR-0013](decisions/0013-strict-ed25519-verification.md) — Ed25519 verification is strict, and the profile is pinned
- [ADR-0014](decisions/0014-canonical-host-flag-profile.md) — The Canonical Host flag profile, and no lowercasing before it
- [ADR-0015](decisions/0015-recovery-window-settlement.md) — What a recovery window admits, supersedes and settles
- [ADR-0016](decisions/0016-audit-reference-follows-the-chain.md) — The audit reference is the chain tip at fetch
- [ADR-0017](decisions/0017-one-pinned-unicode-version.md) — One pinned Unicode version for the whole suite
- [ADR-0018](decisions/0018-confirmation-and-sanctions.md) — Confirmation, sanction activations and due process
- [ADR-0019](decisions/0019-audit-duty-accounting.md) — Audit duty accounting from authenticated Log prefixes
- [ADR-0020](decisions/0020-parameter-schedules.md) — Parameter schedules preserve historical obligations
- [ADR-0021](decisions/0021-block-frame-composition.md) — One Zstandard frame per Block file
- [ADR-0022](decisions/0022-log-timestamp-seconds.md) — Leap-free Log timestamps
- [ADR-0023](decisions/0023-declaration-key-binding.md) — Unambiguous Declaration key binding and identity continuity
- [ADR-0025](decisions/0025-canonical-base64url.md) — Canonical base64url at validation
- [ADR-0026](decisions/0026-publisher-timestamp-profile.md) — Deterministic Publisher timestamps

- [ADR-0028](decisions/0028-unreleased-object-version.md) — One unreleased signed-object version
- [ADR-0029](decisions/0029-signed-delta-publisher.md) — Publisher identity bound into Delta signatures and IDs
- [ADR-0030](decisions/0030-delta-version-eligibility.md) — Delta and Payload version eligibility and diagnostics

- [ADR-0034](decisions/0034-payload-field-diagnostics.md) — Payload field diagnostics and size-bound interpretation
- [ADR-0036](decisions/0036-registry-update-eligibility.md) — Registry Update field, version and authenticity dispositions
- [ADR-0037](decisions/0037-roster-replay-inputs.md) — Roster replay reads sealed strings and post-batch tenures

## Licenses

- Specification text: [CC-BY 4.0](LICENSE)
- Public tier data (snapshots produced by conforming aggregators): ODbL 1.0

Known reference divergences and outstanding validation are listed in
[CONFORMANCE.md](CONFORMANCE.md).
