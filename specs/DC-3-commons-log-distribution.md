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
their defined meanings. Every signed object in this document carries
`dc_version` (DC-1 §3.1) and the DC-1 §4 signature block (`key_id`,
`alg`, `value`).

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

The **Block Hash** is `"sha256:" + hex(SHA-256(JCS(header)))` — the header
alone. The Aggregator signs those same canonical bytes; `sig.key_id` names
an Aggregator key admitted per §3.4.

The header commits to the Block's contents through `merkle_root` and
`entry_count`, so a verifier holding only a header and a Checkpoint can
authenticate the header, and then authenticate any Entry against it with an
Inclusion Proof (§4). Entries are transported inside the Block file but are
not covered by the signature directly; a verifier that downloads them MUST
recompute `merkle_root` and check `entry_count` before use.

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

### 3.4. Aggregator Keys and the Log Anchor

A Log is identified by its **Log Anchor**, a self-signed document served at
`/log/anchor.json` (schema: `schemas/log-anchor.schema.json`) declaring the
`log_id` and the **genesis key**. The Anchor is the Log's out-of-band trust
root: a Consumer MUST obtain it through a channel it trusts (bundled with
the client, pinned by the operator, or verified against an out-of-band
fingerprint) and MUST NOT accept an Anchor fetched from the Log itself
without such verification. Anchors are content-addressed by
`"sha256:" + hex(SHA-256(JCS(anchor)))`, so a fingerprint is short enough to
publish in documentation or a package manifest.

All subsequent Aggregator keys are admitted in-band: an
`aggregator_key_add` Registry Update, signed by a key already valid at that
Block, adds a key; `aggregator_key_remove`, signed the same way, retires
one. A Block sealed at height N MUST be signed by a key that was valid at
height N, where a `key_id` is **valid at height N** if it is the genesis
key, or a validly-signed `aggregator_key_add` naming that `key_id` was
sealed at a height ≤ N and no validly-signed `aggregator_key_remove`
naming that `key_id` was sealed at any height ≤ N.

Removal is permanent, not a toggle: once a validly-signed
`aggregator_key_remove` for a `key_id` is sealed, that `key_id` is invalid
at every later height, full stop — an `aggregator_key_add` sealed at a
later height naming the same, previously removed `key_id` MUST be
rejected and MUST NOT be treated as restoring validity. An operator that
needs that key's role again admits a fresh `key_id` instead; generating a
new key costs nothing, and permanent retirement avoids any ambiguity
about which of several add/remove events for the same `key_id` governs. A
Consumer replaying the Log from the Anchor can therefore compute the set
of valid keys at every height without external input.

Key rotation does not repudiate the past. A signature made by a key that
was valid when the signed object was sealed remains binding evidence
forever — including for the equivocation proof of §5. An Aggregator MUST
NOT be treated as exonerated by removing a key after the fact.

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

> **Deviation from RFC 6962.** For the empty tree, RFC 6962 defines
> MTH({}) = SHA-256(""), while this specification uses the leaf hash of
> zero bytes: SHA-256(0x00) =
> `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d`.
> Non-empty trees are identical to RFC 6962. Implementers wiring in an
> existing Certificate Transparency library MUST special-case empty Blocks.

An Inclusion Proof for Entry *i* of a Block with *n* Entries is
`{"index": i, "entry_count": n, "path": [<hex sibling hash>, ...]}`.
Sibling **sides are not carried in the proof**: they are derived from
`index` and `entry_count`, exactly as in RFC 6962, so that a proof
authenticates the Entry's *position* as well as its membership.

Verification MUST reconstruct the audit path exactly as RFC 6962 §2.1.1
defines it (the `PATH(m, D[n])` function, with `entry_count` as the tree
size *n* and `index` as *m*), applying this specification's leaf and
node hashing (above). Concretely: start with `h = leaf(JCS(entry))` and
walk from leaf to root, tracking the current node's own index within its
level, `fn` (initially `index`), and the index of the last node at that
level, `sn` (initially `entry_count - 1`). While `sn > 0`:

```
if fn is odd:               # fn is a right child
    consume the next path element as its LEFT sibling
elif fn < sn:                # fn is a left child with a real sibling
    consume the next path element as its RIGHT sibling
else:                        # fn == sn, fn even: the lone, unpaired
    consume nothing           # trailing node at this level, promoted
                              # unchanged (matching the promotion rule above)
fn = fn div 2; sn = sn div 2
```

The walk terminates when `sn == 0`; the resulting hash is accepted iff
`"sha256:" + hex(h) == merkle_root`.

A verifier MUST reject a proof when:

- `index >= entry_count` or `index < 0`;
- the proof's `entry_count` differs from the Block header's
  `entry_count`, so that a forged tree size cannot reshape the
  derivation;
- the walk needs a `path` element beyond the ones supplied (it runs out
  of siblings before `sn == 0`), or terminates with `path` elements left
  unconsumed.

Because the sides are derived from `index` and `entry_count` rather than
read from the proof, a proof authenticates the Entry's position as well
as its membership.

Inclusion Proofs let a light client verify "this Delta is in the log"
holding only a Block header, a Checkpoint, and the proof — the header is
authenticated by the Aggregator signature over its canonical bytes (§3.1)
and by the Checkpoint's `block_hash`.

## 5. Checkpoints and Anti-Equivocation

The Aggregator publishes a signed Checkpoint (schema:
[`schemas/checkpoint.schema.json`](../schemas/checkpoint.schema.json)) at
the fixed URL `/log/checkpoint.json` after sealing each Block: the
`block_number`, that Block's `block_hash`, and its `sealed_at`.

- Mirrors MUST retain every Checkpoint they have ever served.
- Consumers SHOULD fetch Checkpoints from more than one Mirror and
  SHOULD retain the Checkpoints they act on.
- A Consumer MUST verify that the Block Hash of the Block it treats as the
  chain head equals the `block_hash` of the Checkpoint it is syncing to,
  and MUST verify the chain backward from that head via `prev_block_hash`.
  A Block that is not reachable by this backward walk MUST NOT be applied.
- A Consumer MUST reject a Checkpoint whose `block_number` is lower than
  the highest it has already verified (rollback protection).
- A Consumer SHOULD treat the log as stale, and SHOULD warn, when
  `sealed_at` of the newest Checkpoint lags the current time by more than
  three times the sealing cadence (§3.2); empty Blocks make this signal
  reliable.

**Equivocation** is two Checkpoints, both validly signed by the
Aggregator, with the same `block_number` and different `block_hash`. The
evidence bundle is exactly those two Checkpoint files — self-contained,
portable, verifiable by anyone with the Aggregator's public key. A party
holding such a bundle SHOULD publish it widely; consumers verifying it
MUST stop applying new data from that Aggregator (§9, `DC3-E02`). Checkpoints
signed by *any* key valid at their `block_number` count; an Aggregator
cannot escape an equivocation proof by removing the signing key afterward
(§3.4).

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
is signed by the Aggregator and declares `snapshot_date`, `log_position`
(= N), the `embedding_model`, and every file with its SHA-256 and byte
size.

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
6. Verify that the head Block's Block Hash equals `checkpoint.block_hash`,
   and that each Block's `prev_block_hash` matches the Block Hash of its
   predecessor, walking backward from the head to `log_position`.
7. Apply Entries in order to the local index.

**Continuous operation:**

1. Fetch `checkpoint.json` (SHOULD: from ≥ 2 Mirrors).
2. Download missing Blocks; verify as above.
3. Verify that the head Block's Block Hash equals `checkpoint.block_hash`,
   and that each Block's `prev_block_hash` matches the Block Hash of its
   predecessor, walking backward from the head to `log_position`.
4. Apply.

**Catch-up decision.** A Consumer offline for a long period compares the
Block distance from its position to the newest Checkpoint against the
distance covered by the newest Snapshot, and chooses whichever costs less
to process. Both paths converge to identical state; the choice is purely
economic.

## 9. Error Registry

| Code | Meaning and required behavior |
|---------|--------------------------------------------------------------|
| DC3-E01 | Block missing at a Mirror. Fetch from another Mirror; integrity never depends on the source. |
| DC3-E02 | Chain divergence (hash mismatch or conflicting Checkpoints, or head Block Hash does not match the Checkpoint's `block_hash`). Hard failure: preserve both Checkpoints as an evidence bundle (§5), MUST NOT apply the data. |
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
- **Key rotation repudiation.** Without an in-band, height-scoped notion
  of key validity, an Aggregator caught equivocating could retire the
  signing key and claim the proof no longer identifies a currently
  trusted key, laundering the misbehavior. §3.4 closes this: key validity
  is evaluated at the signed object's own height, computed by replaying
  the log from the Log Anchor, so a signature valid at sealing time
  remains binding evidence regardless of later rotation.

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
- [ ] Publishes a Log Anchor and admits all later keys in-band (§3.4)

**Mirror:**

- [ ] Serves files byte-identical to origin (verifiable by consumers)
- [ ] Retains all Checkpoints ever served (§5)

**Consumer:**

- [ ] Verifies chain, signatures, Merkle roots, and entry counts on every
      Block before applying (§8)
- [ ] When verifying an Inclusion Proof, derives sibling sides from
      `index` and `entry_count` rather than trusting side labels in the
      proof, and rejects a shape-mismatched `path`, an `index` out of
      range, or a proof `entry_count` that disagrees with the Block
      header's (§4)
- [ ] Binds the head Block to the Checkpoint and walks the chain backward
      from it (§5, §8)
- [ ] Rejects Checkpoints older than the highest already verified (§5)
- [ ] Verifies manifest hashes/sizes before using a Snapshot (§8)
- [ ] Implements all four Error Registry behaviors, including evidence
      preservation on divergence (§9)
- [ ] Enforces the streaming decompression cap (§10)
- [ ] Honors the materialization rule for deletions (§7)
- [ ] Obtains the Anchor out-of-band and resolves signing keys by height
      (§3.4)

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

**Block Hash (over JCS of the header):**

```
sha256:d5eb92e066b027b78d8e872730bfc7e13667bc316856267ce211760b2f8f2c95
```

**Inclusion proof for entry 0** — `index 0, entry_count 4 → siblings
leaf1 then n23, both right-hand` (derived, not carried in the proof):

```
h = leaf0
h = node(h, leaf1)   → d1142719...  (= n01)   # fn=0 < sn=3: sibling on the right
h = node(h, n23)     → ad59dd32...  (= root)  # fn=0 < sn=1: sibling on the right  ✓
```

This worked example only exercises `index` 0, which — being a uniform
left-child at every level — cannot by itself distinguish a correct
verifier from one that only handles the uniform-left/uniform-right cases.
`tools/validate_examples.py`'s `merkle-exhaustive` check is the actual
correctness evidence: it verifies every `index` for every tree size 1..64
against a freshly generated audit path.

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
