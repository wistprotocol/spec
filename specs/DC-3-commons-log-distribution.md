# DC-3: Commons Log & Distribution

**Status:** v1.0.0-draft · **Date:** 2026-08-02 · **License:** CC-BY 4.0

## 1. Introduction

The Commons Log is the single source of everything in DeltaCommons: an
append-only sequence of signed, hash-chained Blocks containing every
accepted Delta (DC-1), every audit record, and every governance action
(DC-4). Its design descends from Certificate Transparency [RFC 6962]: the
Aggregator that operates the log gains no authority from doing so, because
anyone can verify the chain, recompute every derived artifact, and detect
any attempt to rewrite or fork history. Consumers never trust the
Aggregator — they trust signatures and hashes.

This document defines the Block format, the Merkle tree and inclusion
proofs, checkpoints and anti-equivocation, the static distribution layout,
snapshots and tiers, and the consumer synchronization procedure.

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as
shown here.

- **Block**: one sealed batch of log Entries with a signed header.
- **Entry**: one typed item in a Block (`publisher_delta`, `audit_record`,
  or `registry_update`).
- **Checkpoint**: the Aggregator's signed statement of the latest Block.
- **Mirror**: any party re-serving the log's static files.
- **Snapshot**: a signed, derived materialization of log state at a Block.
- **Tier**: a size/completeness layer of a Snapshot (Tier 0 compact,
  Tier 1 full extracts).
- **Inclusion Proof**: a Merkle path proving an Entry is in a Block.

Terms from DC-1 (Envelope, Delta, Canonical Bytes) and DC-2 (Feed) keep
their defined meanings.

## 3. Block Format

Everything that happens in the system happens inside the log.

A Block is an Envelope-like object with `header`, `entries`, and `sig`
(schema: [`schemas/block.schema.json`](../schemas/block.schema.json)).

### 3.1. Header

| Field | Rule |
|-------------------|------------------------------------------------------|
| `block_number` | Sequential from 0, no gaps. |
| `prev_block_hash` | Block Hash of block N−1; the literal `sha256:genesis` for block 0. |
| `sealed_at` | RFC 3339 UTC; strictly increasing across blocks. |
| `merkle_root` | Root over `entries` (§4). |
| `entry_count` | MUST equal `entries.length`. |

The **Block Hash** is `"sha256:" + hex(SHA-256(JCS({"header": ...,
"entries": ...})))` — header and entries, excluding `sig`. The Aggregator
signs those same canonical bytes; `sig.key_id` names an Aggregator key
published in the log via `registry_update`.

### 3.2. Sealing

Blocks are sealed at a fixed cadence (Parameter Registry, DC-4 §9;
default: hourly). A Block MAY be empty (`entry_count: 0`); empty blocks
keep the chain's heartbeat observable. Once sealed, a Block is immutable
forever.

### 3.3. Entries

Each Entry is `{"type": <t>, "body": <envelope>}` with exactly three
types:

- `publisher_delta` — body is a Delta Envelope (DC-1).
- `audit_record` — body is an Audit Record Envelope (DC-4 §5).
- `registry_update` — body is a Registry Update Envelope (DC-4 §3, §7, §9).

DC-3 defines only this envelope; the `body` formats of the latter two are
normative in DC-4. Validators MUST reject Blocks containing unknown Entry
types under the current major version.

## 4. Merkle Tree and Inclusion Proofs

The tree over a Block's Entries uses the RFC 6962 hashing discipline:

```
leaf  = SHA-256(0x00 || JCS(entry))
node  = SHA-256(0x01 || left || right)
```

Leaves are the Entries in Block order. Levels are built pairwise,
left-to-right; **an unpaired final node is promoted unchanged to the next
level**. The root of a single-entry Block is that Entry's leaf hash. The
`merkle_root` of an empty Block is `"sha256:" + hex(SHA-256(0x00))` (the
leaf hash of zero bytes).

An Inclusion Proof for Entry *i* is `{"index": i, "path": [{"side":
"left"|"right", "hash": <hex>}, ...]}`, listing sibling hashes from leaf
level upward. Verification:

```
h = leaf(JCS(entry[i]))
for step in path:
    h = node(step.hash, h)  if step.side == "left"
    h = node(h, step.hash)  if step.side == "right"
accept iff "sha256:" + hex(h) == header.merkle_root
```

Inclusion Proofs let a light client verify "this Delta is in the log"
against nothing but a Block header and a Checkpoint.

## 5. Checkpoints and Anti-Equivocation

The Aggregator publishes a signed Checkpoint (schema:
[`schemas/checkpoint.schema.json`](../schemas/checkpoint.schema.json)) at
the fixed URL `/log/checkpoint.json` after sealing each Block: the
`block_number`, that Block's `block_hash`, and its `sealed_at`.

- Mirrors MUST retain every Checkpoint they have ever served.
- Consumers SHOULD fetch Checkpoints from more than one Mirror and
  SHOULD retain the Checkpoints they act on.

**Equivocation** is two Checkpoints, both validly signed by the
Aggregator, with the same `block_number` and different `block_hash`. The
evidence bundle is exactly those two Checkpoint files — self-contained,
portable, verifiable by anyone with the Aggregator's public key. A party
holding such a bundle SHOULD publish it widely; consumers verifying it
MUST stop applying new data from that Aggregator (§9, `DC3-E02`).

## 6. Static Layout

The log is distributed as static files. Transport is out of scope: any
HTTP server, CDN, torrent, or IPFS gateway works, because every file
except `checkpoint.json` is immutable and integrity is verified by hash
and signature, never by source.

```
/log/checkpoint.json                    (mutable, small, signed)
/log/blocks/000000000.json.zst          (immutable; zero-padded 9-digit block number)
/log/blocks/000000001.json.zst
...
/snapshots/2026-08-02/manifest.json     (signed; declares log position)
/snapshots/2026-08-02/tier0/index.sqlite
/snapshots/2026-08-02/tier0/embeddings.parquet
/snapshots/2026-08-02/tier1/extracts.parquet
```

Blocks are zstandard-compressed JSON. The decompressed size of a Block
MUST NOT exceed 256 MiB (Parameter Registry); consumers MUST enforce this
cap while decompressing (§10).

## 7. Snapshots and Tiers

A Snapshot is a derived artifact: the materialized state of the log up to
Block N. Its `manifest.json` (schema:
[`schemas/snapshot-manifest.schema.json`](../schemas/snapshot-manifest.schema.json))
is signed by the Aggregator and declares `log_position` (= N), the
`embedding_model`, and every file with its SHA-256 and byte size.

- **Tier 0** — summaries and quantized embeddings of every live record:
  SQLite (FTS5) + Parquet. Sized for any laptop; answers most agent
  queries alone.
- **Tier 1** — full extracts of live records, as Parquet.

**Embedding model declaration.** Embeddings are meaningful only within
one model's vector space. The manifest MUST declare the model `name`,
`version`, `dim`, and `quantization`. A Consumer using a different model
MUST NOT mix vector spaces; it re-embeds from Tier 1 extracts instead.

**Materialization rule.** A `delete` Delta (DC-1 §3.3) excludes that
URL's content from all subsequent Snapshots. The log itself retains full
history — deletion shapes the materialized present, never the recorded
past.

Anyone can rebuild a bit-identical Tier 0/Tier 1 from the raw log plus
the manifest's declared parameters; Snapshots are a convenience, not an
authority.

## 8. Consumer Synchronization

**Cold start:**

1. Fetch the latest Snapshot `manifest.json`; verify its signature.
2. Download the listed files; verify each SHA-256 and byte size.
3. Fetch `/log/checkpoint.json`; verify signature.
4. Download Blocks `log_position + 1 .. checkpoint.block_number`.
5. Verify each Block: chain (`prev_block_hash`), signature, `merkle_root`
   recomputation, `entry_count`.
6. Apply Entries in order to the local index.

**Continuous operation:**

1. Fetch `checkpoint.json` (SHOULD: from ≥ 2 Mirrors).
2. Download missing Blocks; verify as above.
3. Apply.

**Catch-up decision.** A Consumer offline for a long period compares the
Block distance from its position to the newest Checkpoint against the
distance covered by the newest Snapshot, and chooses whichever costs less
to process. Both paths converge to identical state; the choice is purely
economic.

## 9. Error Registry

| Code | Meaning and required behavior |
|---------|--------------------------------------------------------------|
| DC3-E01 | Block missing at a Mirror. Fetch from another Mirror; integrity never depends on the source. |
| DC3-E02 | Chain divergence (hash mismatch or conflicting Checkpoints). Hard failure: preserve both Checkpoints as an evidence bundle (§5), MUST NOT apply the data. |
| DC3-E03 | Corrupted Block (hash or signature failure on one file). Re-download, from another Mirror if needed, before concluding misbehavior. |
| DC3-E04 | Manifest file hash or size mismatch. Reject the entire Snapshot. |

## 10. Security Considerations

- **Equivocation** is the Aggregator's only meaningful attack, and §5
  makes it self-incriminating at the cost of two small signed files.
- **Rollback.** A Mirror serving stale data cannot regress a Consumer:
  block numbers are monotonic and Consumers never accept a Checkpoint
  older than one they hold.
- **Mirror tampering.** Mirrors are trustless byte servers; any
  modification fails hash or signature verification (`DC3-E03`).
- **Compression bombs.** The 256 MiB decompressed cap MUST be enforced
  streaming-side, aborting decompression at the limit rather than after.

## 11. Privacy Considerations

The log is public and permanent; DC-1 §9's constraints on personal data
apply to everything in it. On the read side, a Consumer's sync pattern
(timing, IP) is visible to the Mirrors it uses. Mitigations: Mirrors are
dumb file servers requiring no accounts; bulk sync reveals only "this IP
follows the log", not queries (all querying is local by design); privacy-
sensitive Consumers can sync over Tor or from a Mirror they operate.

## 12. Conformance Checklist

**Aggregator:**

- [ ] Seals Blocks per §3 (sequential numbering, strict `sealed_at`
      monotonicity, correct Block Hash and Merkle root)
- [ ] Publishes a Checkpoint per sealed Block at the fixed URL (§5)
- [ ] Serves the static layout of §6 with immutable Block files
- [ ] Produces Snapshots whose manifests satisfy §7, including the
      embedding model declaration and the materialization rule
- [ ] Never emits a Block exceeding the decompressed cap (§6)

**Mirror:**

- [ ] Serves files byte-identical to origin (verifiable by consumers)
- [ ] Retains all Checkpoints ever served (§5)

**Consumer:**

- [ ] Verifies chain, signatures, Merkle roots, and entry counts on every
      Block before applying (§8)
- [ ] Verifies manifest hashes/sizes before using a Snapshot (§8)
- [ ] Implements all four Error Registry behaviors, including evidence
      preservation on divergence (§9)
- [ ] Enforces the streaming decompression cap (§10)
- [ ] Honors the materialization rule for deletions (§7)

## Appendix A. Test Vectors

Generated by `tools/gen_vectors.py`; verified by
`tools/validate_examples.py`. Full files:
[`vectors/dc3/block.json`](../vectors/dc3/block.json),
[`vectors/dc3/inclusion-proof.json`](../vectors/dc3/inclusion-proof.json).

Block 0 contains 4 `publisher_delta` Entries: the DC-1 vector Delta
(entry 0) and three `attest` Deltas for `post-2..4`.

**Leaf hashes (hex):**

```
leaf0 = e5566aed73171ef1c162955b0d3e73660276b1fe7d3cc63becf1406b7b854758
leaf1 = 0c74934dd9c665a7f78c6d3b8f692c72e04e7740c5b675f9c488bcde41445260
leaf2 = 220054dcb66d9ba11a870cc8df9de8b45f81d9906d898779dfbc98a5458e6958
leaf3 = a09515d719b184df17752e6adf84f32a99add1f11bf6348d12278c0e9cf03376
```

**Interior nodes:**

```
n01 = node(leaf0, leaf1) = d1142719a9b0f9525ff18f1e8876d3ee529eb039acaa2ee6d9fc84cbdcfde97b
n23 = node(leaf2, leaf3) = 71d4bc08c95e21599e144e3b0b70ab1e9d804a6ce149feaaec882077495a760b
```

**Merkle root:**

```
sha256:ad59dd329d0b87f9f07f3576232f05531990847dbf75acbc6841ac44cb322f0d
```

**Block Hash (over JCS of header+entries):**

```
sha256:1e0eb04676c1f4de91a5a1ace6252a0d9baf4c1a78992e13ff845dcdb13edc7f
```

**Inclusion proof for entry 0** — path `[right: leaf1, right: n23]`:

```
h = leaf0
h = node(h, leaf1)   → d1142719...  (= n01)
h = node(h, n23)     → ad59dd32...  (= root)  ✓
```

The corresponding Checkpoint is
[`examples/checkpoint.json`](../examples/checkpoint.json). The example
manifest ([`examples/snapshot-manifest.json`](../examples/snapshot-manifest.json))
uses synthetic file hashes — the SHA-256 of the literal strings
`tier0-placeholder` / `tier1-placeholder` — so the vector is verifiable
without shipping binary artifacts.

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- [RFC 6962] Certificate Transparency — Merkle hashing discipline,
  checkpoint/equivocation model
- [RFC 8785] JSON Canonicalization Scheme (JCS)
- DC-1: Delta Format & Identity · DC-2: Site Publication ·
  DC-4: Audit, Reputation & Governance
