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
- **Entry**: one typed item in a Block (`publisher_delta`,
  `publisher_declaration`, `audit_record`, or `registry_update`).
- **Checkpoint**: the Aggregator's signed statement of the latest Block.
- **Mirror**: any party re-serving the log's static files.
- **Snapshot**: a signed, derived materialization of log state at a Block.
- **Tier**: a size/completeness layer of a Snapshot (Tier 0 compact,
  Tier 1 full extracts).
- **Inclusion Proof**: a Merkle path proving an Entry is in a Block.
- **Payload**: the content a Delta commits to (DC-1 §3.6), distributed
  alongside the Block that seals that Delta and not inside it (§6.1).
- **Withdrawal**: the logged removal of a Payload from distribution,
  under §6.2.

Terms from DC-1 (Envelope, Delta, Canonical Bytes, Payload) and DC-2
(Feed) keep their defined meanings. Every signed object in this document carries
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
| `sealed_at` | RFC 3339 UTC at **whole-second precision with a literal trailing `Z`**; strictly increasing across blocks. |
| `merkle_root` | Root over `entries` (§4). |
| `entry_count` | MUST equal `entries.length`. |

`sealed_at` MUST match `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`
(`schemas/block.schema.json`): no fractional seconds, and no numeric offset
even one equal to zero. A Block whose `sealed_at` carries either MUST be
rejected. RFC 3339 permits both, but DC-4 §6.1 derives every reputation day
count from these values by converting them to integer seconds, and a
fractional or offset form would make that conversion a rounding decision
that two implementations could take differently — one rounded half-second
can move a whole-day boundary and with it a domain's age, penalty ages, and
score. Constraining the field is cheaper than specifying a rounding rule,
and it costs the Aggregator nothing: it chooses `sealed_at` itself.

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

Each Entry is `{"type": <t>, "body": <envelope>}` with exactly four
types:

- `publisher_delta` — body is a Delta Envelope (DC-1).
- `publisher_declaration` — body is a Publisher Declaration Envelope
  (DC-1 §5.1); the Aggregator MUST seal a Declaration Entry before, or in
  the same Block as, the first Delta it authorizes.
- `audit_record` — body is an Audit Record Envelope (DC-4 §5).
- `registry_update` — body is a Registry Update Envelope (DC-4 §3, §7, §9).

DC-3 defines only this envelope; the `body` formats of `audit_record` and
`registry_update` are normative in DC-4, and of `publisher_delta` and
`publisher_declaration` in DC-1. Validators MUST reject Blocks containing
unknown Entry types under the current major version.

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
except `checkpoint.json` is immutable and integrity is verified by hash,
signature, or commitment, never by source. Payload files are immutable in
the same sense — their bytes never change — but they are the one class of
file that may cease to be served, under §6.2.

```
/log/checkpoint.json                    (mutable, small, signed)
/log/blocks/000000000.json.zst          (immutable; zero-padded 9-digit block number)
/log/blocks/000000001.json.zst
...
/payloads/7bee228c….json                (one per content-bearing Delta — §6.1)
/snapshots/2026-08-02/manifest.json     (signed; declares log position)
/snapshots/2026-08-02/tier0/index.sqlite
/snapshots/2026-08-02/tier0/embeddings.parquet
/snapshots/2026-08-02/tier1/extracts.parquet
```

Blocks are zstandard-compressed JSON. The decompressed size of a Block
MUST NOT exceed 256 MiB (Parameter Registry); consumers MUST enforce this
cap while decompressing (§10).

### 6.1. Payloads

A Delta commits to its content and does not carry it (DC-1 §3.6). The
content travels as a **Payload** (schema:
[`schemas/payload.schema.json`](../schemas/payload.schema.json)) served at

```
/payloads/<delta-id-hex>.json
```

where `<delta-id-hex>` is the Delta ID's 64-character hex digest without
the `sha256:` prefix — the same naming a Publisher uses (DC-2 §3.1). A
Payload file is immutable while it is served: an Aggregator MUST serve at
that path either the exact bytes it verified at ingest (DC-2 §5) or
nothing at all.

Payloads are fetched in the same synchronisation pass as Blocks, from the
same static file servers, by the same unauthenticated GETs. They are
**not** covered by the Block signature and **not** covered by the Merkle
root; nothing in a Block's header, hash, or inclusion proofs depends on
them, which is exactly why a Block stays byte-immutable when a Payload is
withdrawn.

A Consumer MUST verify each Payload against its Delta's `commitment` and
`bytes` (DC-1 §3.6) before applying its content, and MUST NOT apply
content that fails (`DC1-E11`; the serving party is at fault under
`DC3-E03`). Verification does not depend on where the file came from, so a
Payload MAY be fetched from any Mirror, from another Consumer, or from the
Publisher's own `.well-known` path: the commitment decides, never the
source.

A Delta whose Payload a Consumer cannot obtain remains valid, sealed, and
part of its per-URL chain. The Consumer applies what the Delta itself
says — the URL, the change type, the observation time — and materializes
no content for it.

**Availability window.** An Aggregator and any Mirror serving a Block MUST
serve that Block's Payloads for at least the payload availability window
(Parameter Registry; default 180 days), except for Payloads withdrawn
under §6.2. A Payload that is absent without a withdrawal entry is a
`DC3-E05` fault against that Mirror; this is what distinguishes a lawful
withdrawal from a Mirror quietly dropping content it dislikes.

After the window elapses, retention is at each Mirror's discretion, and a
Consumer MUST NOT read absence as misbehavior. The window is therefore a
detection window rather than an archival promise: it is set long enough
that a Payload's absence inside it is evidence, and every duty that
depends on content — an Auditor's coverage duty above all, which expires
72 hours after a Block is sealed (DC-4 §4) — falls well within it.

**Anchor Payloads.** One class of Payload outlives the window at the
Aggregator. Two separate rules govern it — which Payload an audit names,
and how long that Payload must be served — and they are stated separately
because they end at different times and for different reasons.

*Resolution.* A URL's **anchor Payload as of a Delta *d*** is the Payload
of the last content-bearing Delta at or before *d* in that URL's per-URL
chain (DC-1 §3.5). It is what an `attest` or `delete` Delta is audited
against (DC-4 §5) and the key under which that audit's own commitments are
computed. The rule is relative to *d* rather than to the present, and
carries no liveness qualifier: an anchor that moved whenever a later
`update` was sealed would retroactively invalidate Records that were
honest when they were written, and an anchor that a `delete` erased would
leave a `delete` audit unable to name what it measured. Resolution never
expires — the chain is in the Log — and it says nothing about whether the
Payload can still be fetched.

*Serving.* An Aggregator MUST serve a Payload P, regardless of the
availability window, until one availability window after the sealing of
the **first** Delta for P's URL, above P's own Delta, that is either

- a content-bearing Delta, which supersedes P as the URL's anchor, or
- a `delete`, which ends the URL.

Until such a Delta is sealed the obligation has no expiry and displaces
the ordinary window; once that window elapses the obligation ends and
nothing requires P to be served any longer. **A deleted URL's anchor
Payload is therefore served for one window after the `delete` and no
longer**: withdrawal is how content is removed *before* that point, not a
precondition for removing it at all. A withdrawal under §6.2 ends the
obligation immediately, at any point in its life.

Resolution outliving serving is not a contradiction but the ordinary case:
an audit whose Reference Payload it can name but cannot fetch is
`not_auditable` (DC-4 §5), which is exactly how the suite records "there
was a thing to check and it is no longer available".

Holding current anchors costs the Aggregator nothing it was not already
holding — they are exactly the content Tier 1 materializes (§7) — and it
means a Publisher cannot make its own freshness claims unauditable by
dropping its copy: the Aggregator's copy is independent, and the
commitment makes the two interchangeable.

### 6.2. Withdrawal

A Payload is removed from distribution by a `payload_withdrawal` Registry
Update (DC-4 §9.1), signed by the Aggregator, whose `subject` is the
Publisher's domain and whose `details` name the `delta_id`, the
`legal_basis` under which the content is being erased, and the
`jurisdiction` of the party demanding it. A request covering several
Deltas is recorded as one entry per Delta, so that each withdrawal names
exactly what it removed and can be checked on its own.

A withdrawal takes effect at the height of the Block that seals it. From
that height:

- the Aggregator and every Mirror MUST stop serving that Payload, and a
  Consumer MUST NOT treat its absence as a fault;
- Consumers MUST exclude the withdrawn content from subsequent
  materializations and remove it from any local index already built from
  it, and the Aggregator **and every Mirror** MUST stop serving any
  already published Snapshot artifact that still contains it (§7);
- Auditors record `not_auditable` for that Delta (DC-4 §5) rather than a
  verdict derived from content;
- every party holding the Payload for protocol purposes MUST destroy it,
  its salt, and anything it retained of the content it carried. For an
  Auditor that means the WARC capture it preserved for its Audit Records
  on that Delta (DC-4 §5) and any copy of the Payload it fetched to
  compute them. The obligation reaches the Auditor because the Auditor is
  the one party the protocol requires to keep a copy of the page; leaving
  it out would relocate the retained content rather than erase it.

Destroying the captures costs no accountability. A Confirmed
Inconsistency's weight comes from the `verdict` and `similarity` values
already sealed (DC-4 §6.1), which are data in the Log and are unaffected;
the captures exist so that those verdicts can be checked while the content
is served. That covers confirmation always: a Confirmed Inconsistency is
fixed within 72 hours (DC-4 §5). It does not reliably cover the sanction
ladder built on top of it, whose spans bound how far apart Confirmed
Inconsistencies may lie rather than how old any of them is when a sanction
is filed — and §7 sets no deadline for filing one. A level-4 appeal can
therefore be heard on a Record whose Reference Payload lapsed months
earlier; DC-4 §5 works the case through and states what an appellant can
and cannot re-verify once that has happened.

What withdrawal does not touch is the record. The Delta stays sealed, its
commitment stays in the Log, its inclusion proofs keep verifying, and
every Audit Record ever published about it remains — including the
verdicts that establish what the Publisher was found to have declared.
Withdrawal removes content from distribution; it cannot remove history,
and it cannot recall copies already served.

**After a withdrawal the Log retains no unsalted digest of the withdrawn
content.** That is a property of the object formats, not an aspiration:
the Delta commits to its content under the Payload salt (DC-1 §3.6), and
every content-derived value in an Audit Record — the response, the
Auditor's reference extraction, the WARC capture — is committed under that
same salt (DC-4 §5). One salt keys all four, so destroying it makes all
four unlinkable at the same instant. The rule is general and binds any
object a later revision adds: **a content-derived value in this suite is
committed under the Payload salt or it is not carried at all.** No object,
and no `details` of any Registry Update, may carry a bare digest of
Payload content.

What remains in the Log and is derived from the withdrawn content is the
`similarity` integer, the `verdict`, and the Delta's `payload.bytes`
length. None is a digest. Against a party holding only a candidate text
none is confirming: `bytes` corroborates a length that unboundedly many
texts share, and `similarity` scores an audit against a reference that
party cannot reconstruct. Against a party that also holds the Auditor's
reference extraction or its capture, `similarity` is recomputable and can
be matched against the sealed integer exactly. What stands between that
party and the content is the destroy obligation above — a duty on a named
holder, not a property of the format, and this specification does not
present it as one (DC-1 §9, DC-4 §11).

The due process is the same the suite uses for sanctions (DC-4 §7):
notice in the Log, a named basis, a public and permanent record. An
operator that removes a Payload without sealing this entry has not
withdrawn it lawfully — it has dropped it, and §6.1's window makes that
observable.

Withdrawal is itself an act the Aggregator is accountable for, and it
cannot be performed quietly. Every withdrawal is signed, sealed and
enumerable, so anyone can list every Payload an operator has ever removed
together with the basis and jurisdiction it claimed, and a pattern no
legal basis explains is visible as a pattern. What the Log cannot do is
adjudicate a basis; it can only make the claim permanent and attributable
to the party that made it — the same standard this suite applies to every
other exercise of operator power.

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

Both tiers are built from Payloads (§6.1), not from the Log: the Log
carries commitments, and a Snapshot is where the content a Consumer
actually queries is materialized. A Snapshot MUST NOT include content
whose commitment it did not verify.

**Embedding model declaration.** Embeddings are meaningful only within
one model's vector space. The manifest MUST declare the model `name`,
`version`, `dim`, and `quantization`. A Consumer using a different model
MUST NOT mix vector spaces; it re-embeds from Tier 1 extracts instead.

**Materialization rule.** A `delete` Delta (DC-1 §3.3) excludes that
URL's content from all subsequent Snapshots. A `payload_withdrawal` (§6.2)
likewise excludes that Delta's content from every Snapshot produced at or
above its sealing height, in both tiers, including any embedding derived
from it. A URL that is **unauditable** at the Snapshot's `log_position`
(DC-4 §5) — one that two independent Auditors have been forbidden to fetch
by `robots.txt` inside the unauditable horizon, with no successful audit by
an Auditor independent of both since — is excluded for as long as that
holds, and returns to materialization at the first Snapshot built at or
above the height of such an audit. The log itself
retains full history in every case — deletion, withdrawal and
unauditability shape the materialized present, never the recorded past.

All three exclusions are computed from the Log, so two parties building a
Snapshot at the same `log_position` still produce byte-identical tiers: an
unauditable URL is decided by that URL's Audit Records in Log order and by
the Parameter Registry value in force, not by whether the builder's own
crawler happened to be turned away.

Withdrawal reaches backward into Snapshots as well, because a Snapshot
already published carries the content in its tier files. The Aggregator
and every Mirror MUST stop serving any Snapshot artifact containing
withdrawn content: the Aggregator either withdraws that Snapshot from
distribution or replaces it with one rebuilt under the exclusion rule
above, under a fresh signed manifest, and a Mirror re-serving `/snapshots/`
(§6) is bound identically — a Mirror that kept serving the superseded tier
files would leave the content in distribution no matter what the
Aggregator did, which is the whole of what withdrawal is supposed to stop.
Neither costs a Consumer anything it cannot recover, since any state a
Snapshot provides is reachable from the Log and the Payloads. A manifest's
per-file `sha256` is a digest of a whole tier file rather than of any one
record, so it is no handle onto an individual extract — deriving one from
it would require already holding the file, and with it the text.

Anyone can rebuild a bit-identical Tier 0/Tier 1 from the raw log, the
Payloads it references, and the manifest's declared parameters; Snapshots
are a convenience, not an authority. Withdrawal does not cost that
property: because the exclusion is triggered by a logged entry rather than
by whether a given rebuilder happens to hold the file, two parties with
different Payload collections still produce the same Snapshot. A party
missing a Payload that was never withdrawn cannot rebuild, and MUST report
that rather than emit a Snapshot silently missing a record.

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
7. Fetch `/payloads/<delta-id-hex>.json` for every content-bearing Delta
   in those Blocks whose Payload has not been withdrawn (§6.2); verify
   each against its Delta's commitment and `bytes` (§6.1).
8. Apply Entries in order to the local index, materializing content only
   from Payloads that verified.

**Continuous operation:**

1. Fetch `checkpoint.json` (SHOULD: from ≥ 2 Mirrors).
2. Download missing Blocks; verify as above.
3. Verify that the head Block's Block Hash equals `checkpoint.block_hash`,
   and that each Block's `prev_block_hash` matches the Block Hash of its
   predecessor, walking backward from the head to `log_position`.
4. Fetch and verify the corresponding Payloads (§6.1).
5. Apply.

Payload fetching never gates chain verification: a Consumer that cannot
obtain some Payloads still verifies, applies, and advances over the
Blocks, and simply materializes no content for the affected Deltas. Chain
integrity and content availability are separate failures, and only the
first is ever a reason to stop.

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
| DC3-E03 | Corrupted file (hash or signature failure on a Block, or a Payload that does not reproduce its Delta's commitment — DC-1 §3.6, `DC1-E11`). Re-download, from another Mirror if needed, before concluding misbehavior. |
| DC3-E04 | Manifest file hash or size mismatch. Reject the entire Snapshot. |
| DC3-E05 | Payload absent from a Mirror inside the availability window with no `payload_withdrawal` sealed for it (§6.1, §6.2). A fault against that Mirror, never against the Delta: fetch the Payload from another Mirror or from the Publisher (DC-2 §3.1), and keep applying the Log. A Consumer that sees `DC3-E05` from every source it tries SHOULD publish that fact, because a Payload absent everywhere with no logged basis is the signature of suppression rather than of erasure. |

## 10. Security Considerations

- **Equivocation** is the Aggregator's only meaningful attack, and §5
  makes it self-incriminating at the cost of two small signed files.
- **Rollback.** A Mirror serving stale data cannot regress a Consumer:
  block numbers are monotonic and Consumers never accept a Checkpoint
  older than one they hold.
- **Mirror tampering.** Mirrors are trustless byte servers; any
  modification fails hash or signature verification (`DC3-E03`). This
  covers Payloads too: a Mirror that alters one fails the Delta's
  commitment, which every fetcher recomputes and which was fixed by the
  Publisher's signature before any Mirror saw it.
- **Selective payload suppression.** Tampering being useless, a hostile
  Mirror's remaining move is to serve some Payloads and not others. §6.1
  makes that a typed, attributable fault: inside the availability window,
  absence with no `payload_withdrawal` in the Log is `DC3-E05` against
  that Mirror, and the Payload is still obtainable from the Aggregator,
  another Mirror, or the Publisher, so suppression by one party achieves
  nothing but its own detection. Lawful withdrawal looks different in
  every respect a Consumer can observe: it is announced in the Log before
  it takes effect, it names a legal basis and a jurisdiction, it applies
  at every Mirror rather than one, and it is permanent and public.
  Two limits are worth stating plainly. After the window elapses, absence
  is no longer evidence, so suppression of old Payloads is indistinguishable
  from ordinary expiry — which is tolerable because every content-dependent
  duty in the suite falls inside the window. And an Aggregator that
  withholds a Payload from ingest onward, never publishing it at all,
  is visible as a Delta that no party can audit rather than as a Mirror
  fault; DC-2 §5 closes the honest path by requiring the Aggregator to
  reject such a Delta instead of sealing it.
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
apply to everything in it. Content is deliberately not in it: Payloads are
distributed alongside the Log and are erasable under §6.2, so an erasure
order costs a file deletion plus a Log entry rather than a rewrite of
sealed history. Mirrors keep serving bytes and stay free of any obligation
to re-serialize or partially reconstruct what they hold.

Erasure is an obligation on operators, not a property of the network. A
withdrawal binds the Aggregator and its Mirrors; it cannot reach a copy
already downloaded, and nothing in this specification pretends otherwise.
What the design does guarantee is that after withdrawal the Log itself
stops helping: with the salt destroyed, the surviving commitment does not
let a holder of a copy establish that the copy is what was committed to
(DC-1 §3.6, §9).

On the read side, a Consumer's sync pattern
(timing, IP) is visible to the Mirrors it uses. Mitigations: Mirrors are
dumb file servers requiring no accounts; bulk sync reveals only "this IP
follows the log", not queries (all querying is local by design); privacy-
sensitive Consumers can sync over Tor or from a Mirror they operate.

## 12. Conformance Checklist

**Aggregator:**

- [ ] Seals Blocks per §3 (sequential numbering, strict `sealed_at`
      monotonicity, whole-second `sealed_at` ending in `Z`, correct Block
      Hash and Merkle root)
- [ ] Publishes a Checkpoint per sealed Block at the fixed URL (§5)
- [ ] Serves the static layout of §6 with immutable Block files
- [ ] Serves every sealed Delta's Payload at `/payloads/<delta-id-hex>.json`
      for at least the availability window, byte-identical to what it
      verified at ingest (§6.1)
- [ ] Serves a URL's anchor Payload with no expiry until a superseding
      content-bearing Delta or a `delete` is sealed for that URL, then for
      one further availability window, then no longer (§6.1)
- [ ] Withdraws a Payload only by sealing a `payload_withdrawal` naming
      the Delta, the legal basis, and the jurisdiction — and then stops
      serving it, together with any Snapshot artifact still containing its
      content (§6.2, §7)
- [ ] Produces Snapshots whose manifests satisfy §7, including the
      embedding model declaration and the materialization rule
- [ ] Never emits a Block exceeding the decompressed cap (§6)
- [ ] Publishes a Log Anchor and admits all later keys in-band (§3.4)
- [ ] Seals a `publisher_declaration` Entry for a domain before, or in
      the same Block as, the first Delta it authorizes (§3.3)

**Mirror:**

- [ ] Serves files byte-identical to origin (verifiable by consumers)
- [ ] Retains all Checkpoints ever served (§5)
- [ ] Serves the Payloads of every Block it serves for at least the
      availability window, and stops serving one only after a
      `payload_withdrawal` is sealed for it (§6.1, §6.2)
- [ ] Stops serving any Snapshot artifact containing withdrawn content,
      on the same terms as the Aggregator (§6.2, §7)

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
- [ ] Verifies every Payload against its Delta's commitment and `bytes`
      before materializing its content, and never lets a missing Payload
      stop chain verification (§6.1, §8)
- [ ] Implements all five Error Registry behaviors, including evidence
      preservation on divergence (§9)
- [ ] Enforces the streaming decompression cap (§10)
- [ ] Excludes deleted and withdrawn content from every materialization it
      produces, and removes withdrawn content from a local index it has
      already built (§6.2, §7)
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
leaf0 = f9b2ad1998bba159c08fa3b0706eef2bfe11839061955dc2172afca9f41d60a5
leaf1 = 0c74934dd9c665a7f78c6d3b8f692c72e04e7740c5b675f9c488bcde41445260
leaf2 = 220054dcb66d9ba11a870cc8df9de8b45f81d9906d898779dfbc98a5458e6958
leaf3 = a09515d719b184df17752e6adf84f32a99add1f11bf6348d12278c0e9cf03376
```

**Interior nodes:**

```
n01 = node(leaf0, leaf1) = adc5908010c74bf4b4fc295d788178e921e94436b91cebe19308e869b3faa00f
n23 = node(leaf2, leaf3) = 71d4bc08c95e21599e144e3b0b70ab1e9d804a6ce149feaaec882077495a760b
```

**Merkle root:**

```
sha256:80cf0dccbce6b385a278468fb7db80ba5c2d926c1fb8e80b9a4d64b527c8e131
```

**Block Hash (over JCS of the header):**

```
sha256:28418b34f83186c1af6014500c87baa2bd73b3aad4565d6534e9db0bbc7b493d
```

**Inclusion proof for entry 0** — `index 0, entry_count 4 → siblings
leaf1 then n23, both right-hand` (derived, not carried in the proof):

```
h = leaf0
h = node(h, leaf1)   → adc59080...  (= n01)   # fn=0 < sn=3: sibling on the right
h = node(h, n23)     → 80cf0dcc...  (= root)  # fn=0 < sn=1: sibling on the right  ✓
```

Entry 0's Payload is [`examples/payload.json`](../examples/payload.json),
served at `/payloads/7bee228c…1047.json`. It contributes to none of the
hashes above: every figure here is computed over Entries that carry the
commitment alone, which is why withdrawing that Payload leaves the leaf,
the root, the Block Hash, and this proof untouched.

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
