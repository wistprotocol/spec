# WIST Protocol Suite

**Status: editable draft under implementation and validation.**
Development and publication rules: [PUBLICATION.md](PUBLICATION.md).

An open, verifiable, push-based web index protocol for local AI agents.

Sites publish **Items**, their current statements about their own URLs,
committed by one signed **Catalog** per Collection, and signed **labels**
about other sites; an **aggregator** sequences them into a public,
append-only log (the Certificate Transparency model); **consumers**
download a compact snapshot once, then follow an hourly Epoch stream — and
query everything locally, ranking under a policy of their own choosing.
Consumers verify signatures, proofs and hashes locally.

```
Publisher                 Aggregator                    Mirrors / Consumers
   │ serves Catalog, tree     │                               │
   │ files and Payloads ──►   │ pulls, validates signature,   │
   │ under /.well-known/      │ recomputes the root, queues   │
   │ and sends ping           │ seals hourly Epoch,     ──►   │ sync Epochs,
   │                          │ signs, chains                 │ verify chain,
   │ signs labels about   ──►  │ seals them beside Items ──►   │ apply to local index,
   │ other sites              │                               │ rank by own policy
```

## Documents

| Doc | Title | Status |
|-----|-------|--------|
| [WIST-1](specs/WIST-1-item-format.md) | Item Format & Identity — Items, the signed Catalog of each Collection, JCS canonicalization, domain-anchored Ed25519 keys, Collections and their Scopes | v1.0.0-draft |
| [WIST-2](specs/WIST-2-site-publication.md) | Site Publication — `.well-known` layout, Collection files and change lists, the Label Feed, ping + pull, unsigned-hint compatibility | v1.0.0-draft |
| [WIST-3](specs/WIST-3-logbook-distribution.md) | Logbook & Distribution — Epochs, Merkle proofs, checkpoints, snapshots and tiers, sync | v1.0.0-draft |
| [WIST-4](specs/WIST-4-governance.md) | Governance & Parameters — governance acts, constitutional invariants, the Parameter Registry, the Label Registry | v1.0.0-draft |
| [WIST-5](specs/WIST-5-emissions.md) | Emissions — the stream a content system writes, the publication each Emission yields, how a Publisher derives and signs its Catalogs, the marked-page profile | v1.0.0-draft |

## Repository layout

```
specs/       the five protocol documents
schemas/     JSON Schema (draft 2020-12) for every normative object
examples/    one validated example per object type
vectors/     deterministic test vectors (WIST-1 Items, Catalogs,
             Collections, signatures and Declaration sequencing, WIST-2
             Catalog order, tree walks, change lists, served files,
             pulls, fetch bounds, link extraction, Labels, disputes and
             label definitions, WIST-3 Merkle, snapshot records and label
             tables, WIST-4 parameter schedules, withdrawals and
             registrable domains, WIST-5 Emission streams, derivation
             and marked pages)
tools/       vector generator and validation harness
decisions/   ADRs recording the load-bearing design decisions
```

## Verifying the suite

```bash
python -m venv tools/.venv
tools/.venv/bin/pip install -r tools/requirements.txt
tools/.venv/bin/python tools/validate_examples.py   # validates examples + vectors
tools/.venv/bin/python tools/gen_vectors.py         # regenerates (byte-identical)
tools/.venv/bin/python tools/gen_emission_vectors.py      # regenerates vectors/wist5
tools/.venv/bin/python tools/verify_emission_vectors.py   # verifies them from the prose
tools/.venv/bin/python tools/gen_collection_vectors.py    # regenerates the Collection vectors
tools/.venv/bin/python tools/verify_collection_vectors.py # verifies them from the prose
tools/.venv/bin/python tools/gen_catalog_vectors.py       # regenerates the Item and Catalog vectors
tools/.venv/bin/python tools/verify_catalog_vectors.py    # verifies them from the prose
tools/.venv/bin/python tools/gen_change_list_vectors.py   # regenerates the change list vectors
tools/.venv/bin/python tools/verify_change_list_vectors.py # verifies them from the prose
tools/.venv/bin/python tools/gen_sealing_vectors.py       # regenerates the sealing, Several Logs and served-file vectors
tools/.venv/bin/python tools/verify_sealing_vectors.py    # verifies them from the prose
tools/.venv/bin/python tools/gen_waiting_vectors.py       # regenerates the waiting, recovery and pull vectors
tools/.venv/bin/python tools/verify_waiting_vectors.py    # verifies them from the prose
tools/.venv/bin/python tools/measure_catalog_costs.py     # reports Catalog and Item Entry octets and pull transfers per update round
tools/.venv/bin/python tools/measure_change_list_costs.py # reports pull transfers by tree walk and by change list per update round
```

The harness validates every example against its schema, recomputes the
WIST-1 Catalog ID and Ed25519 signature and the Item ID, key, leaf and
root, recomputes the payload commitment that binds an Item to content the
log does not carry, and recomputes the WIST-3 Merkle root and inclusion
proof. Vector generation is fully
deterministic: fixed test seed, fixed timestamps, no wall-clock.
[tools/VERIFICATION.md](tools/VERIFICATION.md) inventories, per vector
family, the independent anchor its verification rests on.

## Design decisions

- [ADR-0001](decisions/0001-jcs-canonicalization.md) — JCS (RFC 8785) for canonicalization
- [ADR-0002](decisions/0002-ed25519-domain-anchored-identity.md) — Ed25519 keys anchored to the domain
- [ADR-0003](decisions/0003-ping-plus-pull.md) — Publication is ping + pull, never content push
- [ADR-0004](decisions/0004-log-centric-ct-model.md) — Append-only hash-chained log with signed checkpoints (CT model) (amended by ADR-0046)
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
- [ADR-0021](decisions/0021-block-frame-composition.md) — One Zstandard frame per Block file, a removed object's former name (superseded by ADR-0046)
- [ADR-0022](decisions/0022-log-timestamp-seconds.md) — Leap-free Log timestamps
- [ADR-0023](decisions/0023-declaration-key-binding.md) — Unambiguous Declaration key binding and identity continuity
- [ADR-0025](decisions/0025-canonical-base64url.md) — Canonical base64url at validation
- [ADR-0026](decisions/0026-publisher-timestamp-profile.md) — Deterministic Publisher timestamps

- [ADR-0028](decisions/0028-unreleased-object-version.md) — One unreleased signed-object version
- [ADR-0029](decisions/0029-signed-delta-publisher.md) — Publisher identity bound into Catalog signatures and IDs
- [ADR-0030](decisions/0030-delta-version-eligibility.md) — Catalog and Payload version eligibility and diagnostics

- [ADR-0034](decisions/0034-payload-field-diagnostics.md) — Payload field diagnostics and size-bound interpretation
- [ADR-0036](decisions/0036-registry-update-eligibility.md) — Registry Update field, version and authenticity dispositions
- [ADR-0037](decisions/0037-roster-replay-inputs.md) — Roster replay reads sealed strings and post-batch tenures
- [ADR-0038](decisions/0038-feed-next-target.md) — Label Feed and Page `next` targets
- [ADR-0039](decisions/0039-scoped-host-materialization.md) — Scoped-host materialization preference
- [ADR-0040](decisions/0040-snapshot-recovery-state.md) — Snapshot recovery state carries the floor and the chain head
- [ADR-0041](decisions/0041-signed-publications.md) — The Payload is the publication, no Auditor role, Labelers as Publishers, ranking at consumption (supersedes ADR-0010, 0011, 0012, 0016, 0018, 0019, 0035, 0037)
- [ADR-0042](decisions/0042-registrable-domain-accounting.md) — Quota and capacity are accounted per registrable domain
- [ADR-0043](decisions/0043-label-accountability.md) — Labels expire, bind, are defined, are disputed and are bounded
- [ADR-0044](decisions/0044-fetch-bounds.md) — A fetch is bounded in destination, size and work
- [ADR-0045](decisions/0045-key-directory.md) — The Key Set is a key directory with thumbprint identifiers, validity windows, a rotation commitment and an activation delay
- [ADR-0046](decisions/0046-single-tree-log.md) — The Log is one RFC 6962 tree published as C2SP checkpoints and tiles (amends ADR-0004, supersedes ADR-0021)
- [ADR-0047](decisions/0047-key-act-authentication-height.md) — Key acts authenticate under the previous height's keys
- [ADR-0048](decisions/0048-epoch-terminology.md) — The interval between two Checkpoints is an Epoch, and wire names describe their values
- [ADR-0049](decisions/0049-snapshot-key-authentication.md) — A Snapshot carries its key acts, and unsealed Aggregator documents verify at the adopted head
- [ADR-0050](decisions/0050-emitted-publications.md) — A publication is emitted from the content's source, and `links` declares the links of the published content
- [ADR-0051](decisions/0051-collections-scope-and-keys.md) — A Publisher's publications are divided into Collections, each with an enforced Scope and its own keys
- [ADR-0052](decisions/0052-items-and-catalogs.md) — Publications are Items, and one signed Catalog per Collection commits to all of them
- [ADR-0053](decisions/0053-change-lists.md) — A change list carries the Items by which a Catalog differs from the one it replaced

## Licenses

- Specification text: [CC-BY 4.0](LICENSE)
- Public tier data (snapshots produced by conforming aggregators): ODbL 1.0

Known reference divergences and outstanding validation are listed in
[CONFORMANCE.md](CONFORMANCE.md).
