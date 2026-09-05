# WIST-3: Logbook & Distribution

**Status:** v1.0.0-draft · **Date:** 2026-08-02 · **License:** CC-BY 4.0

## 1. Introduction

The Logbook is the single source of everything in WIST: an
append-only sequence of signed, hash-chained Blocks containing every
accepted Delta (WIST-1), every audit record, and every governance action
(WIST-4). Its design descends from Certificate Transparency [RFC 6962]: the
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

- **Log** (the **Logbook**): the append-only sequence of Blocks this
  document defines, from the genesis Block onward. "The Log" always means
  the whole chain, never one Aggregator's current view of it.
- **Block**: one sealed batch of log Entries with a signed header.
- **Entry**: one typed item in a Block (`publisher_delta`,
  `publisher_declaration`, `audit_record`, or `registry_update`).
- **Log Anchor**: the self-signed document that identifies a Log by its
  `log_id` and declares its `genesis_key`; it is the Log's out-of-band
  trust root, obtained through a channel the Consumer trusts rather than
  from the Log itself (§3.4).
- **genesis key**: the Aggregator signing key the Log Anchor declares. It
  is the only Aggregator key not admitted in-band; every later one is
  added and retired by Registry Updates the genesis key's chain of
  successors signs (§3.4).
- **Checkpoint**: the Aggregator's signed statement of the latest Block.
- **Consumer**: any party that synchronizes the Log and materializes an
  index from it (§8). A Consumer trusts no Aggregator and no Mirror: it
  verifies signatures, hashes and commitments for itself.
- **Mirror**: any party re-serving the log's static files.
- **Snapshot**: a signed, derived materialization of log state at a Block.
- **Tier**: a size/completeness layer of a Snapshot (Tier 0 compact,
  Tier 1 full extracts and the link graph).
- **Inclusion Proof**: a Merkle path proving an Entry is in a Block.
- **Payload**: the content a Delta commits to (WIST-1 §3.6), distributed
  alongside the Block that seals that Delta and not inside it (§6.1).
- **Withdrawal**: the logged removal of a Payload from distribution,
  under §6.2.

Terms from WIST-1 (Envelope, Delta, Delta ID, Canonical Bytes, Payload,
Publisher, Aggregator) and WIST-2 (Feed) keep their defined meanings. Every
signed object in this document is constructed exactly as WIST-1 §4 requires —
inner object canonicalized with JCS, signed with Ed25519, signature
detached — and carries `wist_version` (WIST-1 §3.1) and the WIST-1 §4 signature
block (`key_id`, `alg`, `value`).

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
rejected. RFC 3339 permits both, but WIST-4 §6.1 derives every reputation day
count from these values by converting them to integer seconds, and a
fractional or offset form would make that conversion a rounding decision
that two implementations could take differently — one rounded half-second
can move a whole-day boundary and with it a domain's age, penalty ages, and
score. Constraining the field is cheaper than specifying a rounding rule,
and it costs the Aggregator nothing: it chooses when to seal.

What it does not choose is the timestamp inside that choice: `sealed_at`,
converted to integer seconds since the epoch, MUST be an integer multiple
of `block_cadence_seconds` as in force at the previous Block's
`sealed_at`, and a Consumer replaying the Log MUST reject a Block off the
grid. The Block Hash is an input to every Auditor's selection draw
(WIST-4 §4), and a freely chosen `sealed_at` was a free grinding dimension
over it — the grid leaves the Aggregator its sealing cadence and removes
its choice of digits. The first Block after a `parameter_change` to
`block_cadence_seconds` takes effect lands on the new grid; the Anchor's
own `created_at` is not a Block and is unconstrained.

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

Blocks are sealed at a fixed cadence (Parameter Registry, WIST-4 §9;
default: hourly). A Block MAY be empty (`entry_count: 0`); empty blocks
keep the chain's heartbeat observable. Once sealed, a Block is immutable
forever.

**Per-domain Block capacity.** A Block MUST NOT carry more than
`domain_block_entries_max` (Parameter Registry; default 10 000)
`publisher_delta` Entries whose Publisher is one domain, and a Consumer
replaying the Log MUST reject a Block that does. Where a domain has more
accepted Deltas eligible for a Block than the cap admits, the surplus
waits its turn in acceptance order, and WIST-4 §6.4's inclusion ceiling
runs from the Block a Delta's turn arrives in — so the cap never obliges
an Aggregator to breach the ceiling, nor the ceiling to breach the cap.
This is the one bound in
the suite on how much a domain may publish, and it is deliberately a
bound on *rate*, not on worth or on standing: reputation caps quota,
sampling and latency and nothing else (WIST-4 §6.4), judging content's
worth is outside the protocol (ADR-0006), and a ceiling that grew with
reputation would re-create the pay-for-position pressure Invariant 2
exists to forbid — so the cap is flat, high enough that a large site's
backfill crosses it in days, and low enough that filling the whole
commons with honest junk is a project of years conducted in public
rather than a weekend purchase. What the cap does not do is also stated:
content nobody wants is not a protocol violation, and which records
deserve a consumer's attention is ranking, decided at consumption
(ADR-0006, ADR-0008), not admission.

**A sealed Delta is sealed once.** A Delta ID MUST appear in at most one
`publisher_delta` Entry in the whole Log. An Aggregator that receives a
Delta it has already sealed treats the submission as the idempotent
acceptance WIST-1 §4 requires and MUST NOT seal it a second time; a Consumer
replaying the Log MUST reject a Block containing a `publisher_delta` Entry
whose Delta ID a lower Entry — in the same Block or an earlier one —
already carries. Together with immutability above, this is what makes "the
Block that sealed this Delta" a well-defined phrase: WIST-4 §5's Audit
Records name no Block and instead resolve their audited Block by finding
the one whose `publisher_delta` Entries carry `audited_delta`, which is a
function only because the answer is unique and permanent.

### 3.3. Entries

Each Entry is `{"type": <t>, "body": <envelope>}`, where `type` is one of
exactly four values and `body` is the Envelope that value names:

- `publisher_delta` — body is a Delta Envelope (WIST-1).
- `publisher_declaration` — body is a Publisher Declaration Envelope
  (WIST-1 §5.1); the Aggregator MUST seal a Declaration Entry before, or in
  the same Block as, the first Delta it authorizes.
- `audit_record` — body is an Audit Record Envelope (WIST-4 §5).
- `registry_update` — body is a Registry Update Envelope (WIST-4 §3, §7, §9).

WIST-3 defines only this envelope; the `body` formats of `audit_record` and
`registry_update` are normative in WIST-4, and of `publisher_delta` and
`publisher_declaration` in WIST-1. Validators MUST reject Blocks containing
unknown Entry types under the current major version.

**Entry order is canonical.** Within a Block, Entries MUST appear grouped
by type in the fixed order `publisher_declaration`, `registry_update`,
`publisher_delta`, `audit_record`, and within each group in ascending
octet order of each Entry's Merkle leaf hash (§4). A Consumer replaying
the Log MUST reject a Block ordered otherwise. The rule exists for the
same reason as the `sealed_at` grid (§3.1): Entry order feeds
`merkle_root`, `merkle_root` feeds the Block Hash, and the Block Hash
feeds every Auditor's selection draw (WIST-4 §4) — a free permutation of
Entries was a free grinding dimension of factorial size. Canonical order
leaves the Aggregator its one real choice, Block membership, and §3.2's
cadence already bounds how often that choice recurs.

Storage order and application order are therefore decoupled, and
**application order** is defined, not inherited: within a Block, apply
`publisher_declaration` Entries first (their own precedence is `seq`, and
WIST-1 §5.2's resolution rule is height-based, so intra-Block position
never decides between them), then `registry_update` Entries (admission
and removal read at Block granularity — "admitted at this Block's
`sealed_at`" — so position within the Block carries no meaning), then
`publisher_delta` Entries **in chain order**: a Delta whose `prev` names
a Delta in the same Block applies after it, which is well-defined because
chains are trees rooted outside the Block and cycles are impossible
(a Delta ID includes its `prev` in its preimage), and two Deltas with no
chain relation apply in leaf-hash order without observable difference.
`audit_record` Entries apply last, in ascending Entry index in the
canonical stored order. WIST-4 §4 reads that order for extension triggers
and ration allocation, and WIST-4 §6.1 and §7 read it for the earliest
confirming Record and its closed evidence prefix. No conforming behavior depends on any ordering freedom this
paragraph does not name. Because Declarations apply first, the Key Set a
`publisher_delta` Entry verifies under is the one WIST-1 §5.2 resolves at
its own Block with that Block's Declarations already applied: an
Aggregator MUST NOT seal a Delta that fails it (WIST-1 §5.2), and a
Consumer that meets one ignores the Entry as it ignores a fork — applied
to nothing, moving no chain tip (§7).

### 3.4. Aggregator Keys and the Log Anchor

A Log is identified by its **Log Anchor**, a self-signed document whose
inner object is `anchor` (schema:
[`schemas/log-anchor.schema.json`](../schemas/log-anchor.schema.json)),
served at `/log/anchor.json`. It declares `wist_version`, the `log_id` (the
Log's hostname identity), the `genesis_key` — an object carrying that key's
`key_id`, `alg` and raw base64url `public_key` — and `created_at`, the
instant the Log was established. The Anchor is self-signed: its `sig.key_id`
MUST name its own `genesis_key`, and a Consumer MUST reject an Anchor whose
signature does not verify under the very key it declares.

The Anchor is the Log's out-of-band trust
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
at every later height, full stop — the Aggregator MUST NOT seal an
`aggregator_key_add` naming a previously removed `key_id`, and a Consumer
replaying the Log MUST reject one and MUST NOT treat it as restoring
validity. An operator that
needs that key's role again admits a fresh `key_id` instead; generating a
new key costs nothing, and permanent retirement avoids any ambiguity
about which of several add/remove events for the same `key_id` governs. A
Consumer replaying the Log from the Anchor can therefore compute the set
of valid keys at every height without external input.

Key rotation does not repudiate the past. A signature made by a key that
was valid when the signed object was sealed remains binding evidence
forever — including for the equivocation proof of §5. An Aggregator MUST
NOT be treated as exonerated by removing a key after the fact.

**Succession.** A chain whose every valid key is lost can never extend —
no in-band act can admit a new key, because every admission is signed by
a valid one — and a chain whose keys are compromised may be one two
parties can extend, which §5 makes detectable and nothing here makes
recoverable. Both end the same way: the Log stops being the place where
this commons continues. The continuation is a **successor Log**: a new
Anchor whose optional `predecessor` names the ended Log's `log_id` and
the exact Block — `final_block_number`, `final_block_hash` — at which it
ended. The successor Anchor is a trust root like any Anchor: obtained
and verified out-of-band (§3.4 above), believed because Consumers,
Publishers and Auditors choose it, not because the old chain — which by
hypothesis can no longer say anything trustworthy — endorses it.

What the field changes is what a Consumer that accepts the successor
MUST do with the past: verify the predecessor chain to the named final
Block exactly as §8 verifies any chain, and carry the state at that
Block — materialized records, Declarations, reputation inputs, sanction
and exclusion states, every §7 state-artifact category — into the
successor's genesis, exactly as if the successor's Block 0 were Block
`final_block_number + 1`. Windows anchored to a `sealed_at` of the dead
chain keep their instants; Blocks of the successor discharge them. The
carry is the point: a fork is this suite's stated remedy for a captured
or colluding operator (WIST-4 §8, §11), and a remedy that reset every
domain to Provisional and erased every sanction would punish every
honest Publisher and amnesty every delisted one — a successor without
`predecessor` does exactly that, lawfully, as a new Log that inherits
nothing. **The named final Block must be the last one.** A `predecessor` MUST
name the highest Block of the ended Log for which any validly signed
Checkpoint exists, and a Consumer MUST reject a successor Anchor whose
`final_block_number` is lower than the highest Checkpoint it holds or
can obtain for that `log_id` — reject the Anchor, not merely the
carry. Without this rule succession is a laundering machine dressed as
continuity: a delisted operator, or anyone else, publishes a successor
naming a final Block from before its own sanction, and every Consumer
that pins it carries state from a height at which the sanction had not
happened. Truncation is exactly as attributable as equivocation and is
caught by the same retained artifact — Mirrors keep every Checkpoint
they ever served (§5), so a Checkpoint above the named final Block is
a complete, signed refutation of the successor's central claim, and
`mirror_retention_days` is what keeps one obtainable.

Competing successors that survive that test are resolved the way the
Anchor itself is: by which one the ecosystem verifiably pins, a choice
this specification makes falsifiable — each candidate names its final
Block, the rule above says whether that Block was the end, and §5's
evidence rules say whether the chain reaching it was honest — but
deliberately does not make. A major-version migration uses the same
field: a v2 Log naming a v1 predecessor is a continuation, and WIST-1
§1's "reject unknown major versions" governs objects, not history.

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
`block_number`, that Block's `block_hash`, and its `sealed_at`. It MUST
NOT publish the Checkpoint for Block N before Block N, and every lower
Block, is durably stored and retrievable at its §6 path. A Checkpoint
for Block N MUST be signed by a `key_id` valid at height N in the sense
§3.4 gives that phrase, and a Consumer verifies it against that same key
set: the Checkpoint is a statement about one Block, so the keys that
could have sealed the Block are exactly the keys that can speak for it.
The Consumer's order follows from that — the key set valid at N is what
the Blocks up to N establish, so a Checkpoint's signature is checked
after those Blocks are walked and verified, not before. Nothing rests on
the earlier check: each Block authenticates itself under §3.4, and the
Checkpoint's `block_hash` binds it to the one at N. A Checkpoint is
a permanent signed commitment to one Block Hash: published ahead of a
Block the Aggregator can still lose, it is honored only by re-sealing
byte-identical bytes — the same header over the same Entries — and is
otherwise contradicted by whatever Block N is sealed next, which is
equivocation against itself. A Consumer holding a Checkpoint whose Block
no source serves has a `WIST3-E01` it cannot clear, never a `WIST3-E02`:
the Checkpoint is evidence of what the Aggregator committed to, and the
Block's absence is the Aggregator's to remedy.

- Mirrors MUST retain every Checkpoint they have ever served.
- Consumers SHOULD fetch Checkpoints from more than one Mirror and
  SHOULD retain the Checkpoints they act on. The instruction is
  performable because Mirrors are discoverable in-band: the Aggregator
  SHOULD publish `/log/mirrors.json` — an Envelope whose inner object is
  `mirrors` (schema:
  [`schemas/mirrors.schema.json`](../schemas/mirrors.schema.json)),
  carrying `wist_version`, `updated_at` (descriptive: when the Aggregator
  last rewrote the list, compared to nothing) and `mirror_urls`, the
  `https` base URLs of Mirrors it knows to re-serve the Log, each ending
  in `/` —
  and a Consumer SHOULD also
  retain Mirror URLs from any other source it trusts, because a list the
  Aggregator curates is exactly the wrong sole source for the parties
  meant to catch the Aggregator equivocating: its value is bootstrap
  convenience, and independence of at least one comparison source is
  the property that matters.
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
MUST stop applying new data from that Aggregator (§9, `WIST3-E02`). Checkpoints
signed by *any* key valid at their `block_number` count; an Aggregator
cannot escape an equivocation proof by removing the signing key afterward
(§3.4).

The division of labor here is deliberate and worth stating exactly:
**detection is in-band, dissemination is not.** The proof is two small
signed files anyone can verify, but no channel this specification
defines carries it — "publish it widely" names no venue, and v1
deliberately ships no gossip or witness layer (the mechanism CT grew
for exactly this), because in-band objects cannot be added within a
major version and a half-specified witness protocol would be worse
than a recorded absence. Two consequences follow honestly. The
self-incrimination guarantee is scoped: an Aggregator that partitions
its audiences perfectly — distinct Checkpoints to distinct populations
that never compare notes — is caught only when a bundle crosses the
partition, which multi-Mirror fetching (above) makes likely but
nothing here makes certain. And the remedy runs on evidence, not
plumbing: a proof, however it traveled, justifies the fork/succession
path (§3.4) everywhere it lands. A witness layer is v2's to add.

## 6. Static Layout

The log is distributed as static files. Transport is out of scope: any
HTTP server, CDN, torrent, or IPFS gateway works, because every file
except `/log/checkpoint.json` and `/snapshots/index.json` is immutable and
integrity is verified by hash, signature, or commitment, never by source.

The paths below are rooted at the Log's **Service Origin**,
`https://<log_id>/` (§3.4) — which is how a party holding a Log Anchor
needs no second discovery channel: the Anchor's `log_id` names the host,
and everything else is a path. Mirrors re-serve the same paths at their
own origins. Two endpoints are dynamic and exist only at the Service
Origin, never on a Mirror: the Ingest Endpoint `POST
https://<log_id>/ingest` (WIST-2 §4) and the status endpoint `GET
https://<log_id>/status/<domain>` (WIST-2 §7.1).
Payload files are immutable in the same sense — their bytes never change —
but they are the one class of file that may cease to be served, under §6.2.

```
/log/anchor.json                        (immutable, signed; a copy of the §3.4 trust root)
/log/checkpoint.json                    (mutable, small, signed; the current head — §5)
/log/checkpoints/000000000.json         (immutable; every Checkpoint published — §5)
/log/blocks/000000000.json.zst          (immutable; zero-padded 9-digit block number)
/log/blocks/000000001.json.zst
...
/payloads/6cac5bdd….json                (one per content-bearing Delta — §6.1)
/snapshots/index.json                   (mutable, signed; the discovery entry point)
/snapshots/2026-08-02/manifest.json     (signed; declares log position)
/snapshots/2026-08-02/state.json        (signed; the state artifact — §7)
/snapshots/2026-08-02/tier0/index.sqlite
/snapshots/2026-08-02/tier1/extracts.parquet
/snapshots/2026-08-02/tier1/links.parquet
```

`/log/anchor.json` is served here for convenience only. It is the Log's
out-of-band trust root, and a Consumer MUST NOT accept the copy served at
this path without the verification §3.4 requires; a file an operator serves
about itself is not a trust root because of where it sits.

**Block files.** A Block file is the JCS canonical bytes of the Block
object — `header`, `entries` and `sig` — compressed with zstandard. The
compression level is unconstrained, but the frame MUST declare its
decompressed size (zstandard's `Frame_Content_Size`), and that size MUST
NOT exceed the Block decompressed cap (Parameter Registry; default
256 MiB). A Consumer MUST reject a frame declaring more than the cap
without decompressing it, and MUST still abort decompression at the cap if
the declared size proves to be a lie (§10): a declared size is a claim, not
a guarantee, and the streaming limit is what makes it safe to read one.

Because compression parameters are not constrained, Block *files* are not
byte-comparable across Mirrors. Integrity is recovered on the far side of
decompression: recompute `merkle_root` over `entries`, check `entry_count`,
recompute the Block Hash over `JCS(header)`, and verify the signature
against those same bytes (§3.1). §12's Mirror obligation is therefore to
serve content that verifies, not identical octets. The one class of file
for which the two coincide is the Snapshot tier files, whose octets a
signed manifest hashes directly (§7): those a Mirror MUST serve unchanged,
because nothing else authenticates them.

**Discovery.** `/snapshots/index.json` (schema:
[`schemas/snapshot-index.schema.json`](../schemas/snapshot-index.schema.json))
is the discovery entry point: a signed, mutable index whose inner object is
`index`, carrying `wist_version`, `updated_at` (when the Aggregator last
rewrote it), and `snapshots` — the Snapshots the Aggregator currently
serves, newest `snapshot_date` first, each with its `log_position`, its
`manifest_url`, and the `content_digest` (§7) that Snapshot's manifest
declares. Cold start begins there (§8). The index
carries the digest so that a Consumer can check a manifest it fetches
against a second, independently signed statement of what that Snapshot
contains. An Aggregator MUST remove an entry from the index when it stops
serving that Snapshot; a withdrawal (§6.2) is the case that forces it.

**Retention.** The Aggregator MUST keep every Block from genesis
retrievable at its `/log/blocks/` path. Replay from the Log Anchor is what
makes key validity (§3.4), reputation (WIST-4 §6) and historical signature
verification recomputable, so a Log missing a Block in the middle is a Log
no party can verify from the Anchor at all. The Aggregator MUST likewise
retain every Checkpoint it has published, at
`/log/checkpoints/<block_number>.json` with the block number zero-padded to
nine digits: `/log/checkpoint.json` names the current head and is
overwritten, so without the archive an equivocation proof (§5) would rest
on whoever happened to have kept the superseded copy.

A Mirror that serves a Block MUST retain it for at least the Mirror
retention floor (Parameter Registry: `mirror_retention_days`; default 90
days), so that an evidence bundle can be assembled after the fact rather
than only while an operator finds it convenient. §5's obligation on
Checkpoints is stricter and this floor does not relax it: a Mirror retains
every Checkpoint it has ever served, without expiry, because Checkpoints
are the equivocation evidence itself and are small enough that no retention
argument applies to them.

**Sizing.** The Log has a permanent volume floor that does not depend on
how much anyone publishes. An admitted Auditor whose VRF selects nothing in
a Block MUST still publish a `coverage_attestation` for that Block (WIST-4
§4), so an entirely idle Log still accrues roughly one Entry per admitted
Auditor per Block — at the default hourly cadence (§3.2), about 8 760
Entries per Auditor per year. Permanent volume therefore scales with roster
size multiplied by Blocks per year, before any Delta is ever sealed.
Governance deciding how large an Auditor roster to admit and how fast to
seal Blocks is deciding the Log's storage growth, and SHOULD treat those as
one decision rather than two.

### 6.1. Payloads

A Delta commits to its content and does not carry it (WIST-1 §3.6). The
content travels as a **Payload** (schema:
[`schemas/payload.schema.json`](../schemas/payload.schema.json)) served at

```
/payloads/<delta-id-hex>.json
```

where `<delta-id-hex>` is the Delta ID's 64-character hex digest without
the `sha256:` prefix — the same naming a Publisher uses (WIST-2 §3.1). A
Payload file is immutable while it is served: an Aggregator MUST serve at
that path either the exact bytes it verified at ingest (WIST-2 §5) or
nothing at all.

A Payload carries exactly three members. `wist_version` is the version of
this suite it conforms to (WIST-1 §3.1). `salt` is the base64url encoding,
unpadded, of the ≥ 16 octets that key the Delta's commitment (WIST-1 §3.6);
it is the one place the salt is published, and destroying it is what makes
a withdrawal effective (§6.2). `content` is the object the commitment is
computed over: a REQUIRED `extract`, the page's main text; a REQUIRED
`links` object carrying a REQUIRED `total` and REQUIRED `urls` (WIST-1 §3.6);
and a REQUIRED `summary` object carrying a REQUIRED `title` and an OPTIONAL
`abstract`. Those eight names and no others: `content` is the exact
preimage of `JCS(content)`, so a Payload carrying any further field
commits to different bytes and fails verification. WIST-1 §3.6 governs the
octet caps on `extract`, `links` and `summary` and the relationship
between them and `bytes`; a Payload is unsigned, so nothing here is
authenticated except by recomputing that commitment.

Payloads are fetched in the same synchronisation pass as Blocks, from the
same static file servers, by the same unauthenticated GETs. They are
**not** covered by the Block signature and **not** covered by the Merkle
root; nothing in a Block's header, hash, or inclusion proofs depends on
them, which is exactly why a Block stays byte-immutable when a Payload is
withdrawn.

A Consumer MUST verify each Payload against its Delta's `commitment` and
`bytes` (WIST-1 §3.6) before applying its content, and MUST NOT apply
content that fails (`WIST1-E10`; the serving party is at fault under
`WIST3-E03`). Verification does not depend on where the file came from, so a
Payload MAY be fetched from any Mirror, from another Consumer, or from the
Publisher's own `.well-known` path: the commitment decides, never the
source. That is also why §6.2 binds all three: a withdrawal reaches every
serving path or it reaches none of them, since any one of them suffices to
obtain the salt.

A Delta whose Payload a Consumer cannot obtain remains valid, sealed, and
part of its per-URL chain. The Consumer applies what the Delta itself
says — the URL, the change type, the observation time — and materializes
no content for it.

**Availability window.** An Aggregator and any Mirror serving a Block MUST
serve that Block's Payloads for at least the payload availability window
(Parameter Registry; default 180 days), except for Payloads withdrawn
under §6.2, and MUST NOT serve the Block before every Payload its
content-bearing Deltas commit to, less those withdrawn, is retrievable
at its path: Payloads replicate first, and the Block follows, the same
order §5 fixes between a Block and its Checkpoint, so a Payload is never
absent at a Mirror merely because replication has not reached it. A
Payload that is absent without a withdrawal entry is a
`WIST3-E05` fault against that Mirror; this is what distinguishes a lawful
withdrawal from a Mirror quietly dropping content it dislikes.

After the window elapses, retention is at each Mirror's discretion, and a
Consumer MUST NOT read absence as misbehavior. The window is therefore a
detection window rather than an archival promise: it is set long enough
that a Payload's absence inside it is evidence, and every duty that
depends on content — an Auditor's coverage duty above all, which expires
72 hours after a Block is sealed (WIST-4 §4) — falls well within it.

**Anchor Payloads.** One class of Payload outlives the window at the
Aggregator. Two separate rules govern it — which Payload an audit names,
and how long that Payload must be served — and they are stated separately
because they end at different times and for different reasons.

*Resolution.* A URL's **anchor Payload as of a Delta *d*** is the Payload
of the last content-bearing Delta at or before *d* in that URL's per-URL
chain (WIST-1 §3.5). An audit names the Delta it resolves from — its
`reference_delta`, the chain tip at fetch (WIST-4 §5) — and where that
Delta is an `attest` or a `delete`, the anchor as of it is the Reference
Payload and the key under which the audit's own commitments are
computed. The rule is relative to a named *d* rather than to the
present, so a sealed Record never changes meaning: an anchor that moved
whenever a later `update` was sealed would retroactively invalidate
Records that were honest when they were written, and an anchor that a
`delete` erased would leave an audit of that `delete` unable to name
what it measured. Resolution never expires — the chain is in the Log —
and it says nothing about whether the Payload can still be fetched.

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
obligation immediately, at any point in its life. What the post-supersession
window serves is verification: a fresh audit measures against the current
anchor, served with no expiry while it remains the anchor and for one
window after a `delete` ends the URL, and a Record sealed against the
superseded one is checkable for as long as its Reference Payload can
still be fetched.

Resolution outliving serving is not a contradiction but the ordinary case:
an audit whose Reference Payload it can name but cannot fetch is
`not_auditable` (WIST-4 §5), which is exactly how the suite records "there
was a thing to check and it is no longer available".

Holding current anchors costs the Aggregator nothing it was not already
holding — they are exactly the content Tier 1 materializes (§7) — and it
means a Publisher cannot make its own freshness claims unauditable by
dropping its copy: the Aggregator's copy is independent, and the
commitment makes the two interchangeable.

### 6.2. Withdrawal

A Payload is removed from distribution by a `payload_withdrawal` Registry
Update (WIST-4 §9.1), signed by the Aggregator, whose `subject` is the
Publisher's domain and whose `details` name the `delta_id`, the
`legal_basis` under which the content is being erased, and the
`jurisdiction` of the party demanding it. A request covering several
Deltas is recorded as one entry per Delta, so that each withdrawal names
exactly what it removed and can be checked on its own.

A withdrawal takes effect at the height of the Block that seals it. From
that height:

- the Aggregator, every Mirror **and the Publisher itself** MUST stop
  serving that Payload, and a Consumer MUST NOT treat its absence as a
  fault. The Publisher is bound because its `.well-known` copy is a third
  serving path (WIST-2 §3.1), the original one, and the only one this
  document does not otherwise reach: a withdrawal that bound the two
  downstream copies and left the source published would relocate the salt
  rather than destroy it, and every claim below about what stops being
  checkable would be false at one fetch. The Publisher's own retention
  duty for an anchor Payload (WIST-2 §3.1) ends at that height rather than
  competing with this one; a Publisher that still attests to the URL
  re-anchors the chain instead, exactly as it would if it had to stop
  serving the Payload for any other reason;
- Consumers MUST exclude the withdrawn content from subsequent
  materializations and remove it from any local index already built from
  it, and the Aggregator **and every Mirror** MUST stop serving any
  already published Snapshot artifact that still contains it —
  `tier1/links.parquet` no less than `tier1/extracts.parquet`, since a
  withdrawn Payload's declared links are content and leave distribution
  with it (§7);
- Auditors record `not_auditable` for that Delta (WIST-4 §5) rather than a
  verdict derived from content;
- every party holding the Payload for protocol purposes MUST destroy it,
  its salt, and anything it retained of the content it carried. For an
  Auditor that means the WARC capture it preserved for its Audit Records
  on that Delta (WIST-4 §5) and any copy of the Payload it fetched to
  compute them. The obligation reaches the Auditor because the Auditor is
  the one party the protocol requires to keep a copy of the page; leaving
  it out would relocate the retained content rather than erase it.

Destroying the captures costs no accountability. A Confirmed
Inconsistency's weight comes from the `verdict` and `similarity` values
already sealed (WIST-4 §6.1), which are data in the Log and are unaffected;
the captures exist so that those verdicts can be checked while the content
is served. That covers confirmation always: a Confirmed Inconsistency is
fixed within 72 hours (WIST-4 §5). It does not reliably cover the sanction
ladder built on top of it, whose spans bound how far apart Confirmed
Inconsistencies may lie rather than how old any of them is when a sanction
is filed — and §7 sets no deadline for filing one. A level-4 appeal can
therefore be heard on a Record whose Reference Payload lapsed months
earlier; WIST-4 §5 works the case through and states what an appellant can
and cannot re-verify once that has happened.

What withdrawal does not touch is the record. The Delta stays sealed, its
commitment stays in the Log, its inclusion proofs keep verifying, and
every Audit Record ever published about it remains — including the
verdicts that establish what the Publisher was found to have declared.
Withdrawal removes content from distribution; it cannot remove history,
and it cannot recall copies already served.

**After a withdrawal the Log retains no unsalted digest of the withdrawn
content.** That is a property of the object formats, not an aspiration:
the Delta commits to its content under the Payload salt (WIST-1 §3.6), and
every content-derived value in an Audit Record — the response, the
Auditor's reference extraction, the WARC capture — is committed under that
same salt (WIST-4 §5). One salt keys all four, so destroying it makes all
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
present it as one (WIST-1 §9, WIST-4 §12).

The due process is the same the suite uses for sanctions (WIST-4 §7):
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

**A withdrawal binds one Log.** Every obligation in this section runs on
Entries of the Log the withdrawal was sealed in: an Aggregator, its
Mirrors, and the Auditors admitted to *that* Log. A second, independent
Log that sealed the same Publisher's Deltas — nothing forbids one, and
WIST-2's publication surface is one site serving whomever pulls — is
unreached by it, and a Publisher who needs content erased from two Logs
files two withdrawals. Stated once, plainly, because the alternative is
a Publisher discovering it at the worst moment: this suite's erasure
guarantees are per-Log, and every "the Aggregator", "every Mirror" and
"the Auditor" in this section quantifies over one Log's roster.

## 7. Snapshots and Tiers

A Snapshot is a derived artifact: the materialized state of the log up to
Block N. Its `manifest.json` (schema:
[`schemas/snapshot-manifest.schema.json`](../schemas/snapshot-manifest.schema.json))
is signed by the Aggregator and declares `snapshot_date`, `log_position`
(= N), `anchor_block_hash` (the Block Hash of Block N), `content_digest`
(below), `state` (the state artifact, below), optionally `shards`
(below), and `files` — one entry per artifact, each carrying its `path`
relative to the manifest, its `sha256`, its `bytes`, the `tier` (`0` or
`1`) it belongs to, and, where the manifest declares `shards`, its
`shard` index.

- **Tier 0** — summaries of every live record: SQLite (FTS5) + Parquet.
  Sized for any laptop; answers most agent queries alone.
- **Tier 1** — full extracts of live records, and the link graph their
  Payloads declare, as Parquet.

Both tiers are built from Payloads (§6.1), not from the Log: the Log
carries commitments, and a Snapshot is where the content a Consumer
actually queries is materialized. A Snapshot MUST NOT include content
whose commitment it did not verify.

**Companion packs.** Neither tier carries embeddings, and no artifact
this specification defines does. A vector is a content-derived value no
verification in this suite can reach: `content_digest` deliberately
covers Log-derived tuples only, float inference admits no exact
equivalence criterion, and an inexact one — a tolerance — is an attack
budget, since manipulation inside the tolerance is invisible by
construction (ADR-0009). Instead, any party — the Aggregator included —
MAY publish a **companion pack**: a signed artifact of vectors computed
over a named Snapshot. A conforming pack declares the `content_digest`
and `log_position` it was computed against; declares its model — `name`,
`version`, `weights_hash`, `dim`, `quantization`, the distance `metric`,
and the record field embedded (`source`, e.g. `summary`) — precisely
enough that any holder of the named Snapshot can re-embed any record and
compare; and covers only records the bound digest covers, which excludes
records withdrawn at that height by construction. A pack's signature
binds provenance and its bound digest binds scope; the honesty of the
vectors themselves is neither, and this specification deliberately
defines no equivalence criterion for them — a Consumer's trust in a pack
is trust in its publisher, chosen the way a client is chosen, never a
property the protocol asserts. Packs published by the Aggregator are
Snapshot artifacts for the purposes of §6.2's withdrawal obligations; a
third-party pack containing a since-withdrawn record is a copy already
served, in the position WIST-1 §6 names, with a named holder. Discovery of
packs is out of scope: a Consumer verifies a pack against the digest of
a Snapshot it already holds, wherever the pack came from.

**The link graph.** `tier1/links.parquet` carries one row per declared
link of every live record: `(source_url, target_url, position)`, where
`source_url` is the record's Normalized URL, `target_url` a member of
its Payload's `links.urls`, and `position` that member's zero-based
index. The artifact is a pure function of the live records' Payloads —
any party holding them can rebuild and compare it row for row — and it
carries no digest of its own: `content_digest` deliberately covers
Log-derived tuples only, so that it remains computable after a
withdrawal, and the artifact's transport integrity is already pinned by
its `files` entry. It transports declarations, never a judgement: which
links are trustworthy, and what importance follows from being linked,
is ranking, and ranking is outside this protocol (WIST-4 §8, ADR-0006,
ADR-0008). That boundary is what makes carrying the graph admissible at
all: ADR-0006 keeps importance out of the protocol, and ADR-0008 records
that a page's own outbound links are a verifiable statement about the
Publisher's content rather than a claim about its own importance, so the
raw edges may be distributed while no rank, weight or aggregate of them
ever is.

**The materialized state.** The materialized state is a set of records
keyed by (Publisher domain, Normalized URL). Applying Entries in Log order:
a `new` or `update` Delta replaces the record's content and becomes the
record's **anchor Delta** (§6.1); an `attest` Delta updates the record's
freshness only and leaves the anchor where it was; a `delete` removes the
record's content and moves the chain tip like any other Delta — the key
keeps a tip, the `delete` itself, because a chain never restarts (WIST-1
§3.5) and the URL's next Delta names it as `prev`. A Delta whose `prev`
is not the chain tip the state carries for
its (Publisher domain, Normalized URL) — a fork of an already-materialized
chain (WIST-1 §3.5), or a `prev` that no lower Entry sealed — is ignored
and moves no tip; a chain's first Delta is the one that omits `prev` while
the state carries no tip for its key. Sanction levels apply as WIST-4 §7 derives them — from the evidence,
not from whether an Aggregator sealed a `sanction`: level 2 marks every
record of that domain reduced-weight; level 3 stops that domain's later
Deltas from being materialized at all, from the height it takes effect;
level 4 removes the domain's records entirely; and a `sanction_lift`, a
successful appeal, a lapsed ruling deadline, a lapsed appeal-sealing
deadline, or an identity reset (WIST-4 §7, §6.3) reverses the state from
the height that takes effect.
Deletion, withdrawal and unauditability
are covered by the rule below. The Log retains every Entry in every case;
materialization shapes only the present state.

**One URL, one Publisher.** A URL's host can lawfully sit inside two
authorities at once: its own domain's, and a parent domain whose
`subdomain_scope` names it (WIST-1 §3.2). The record key is (Publisher
domain, Normalized URL), so without a tiebreak the same URL could carry
two live records, one under each Publisher, and nothing below would say
which one a query should believe. The tiebreak is self-governance: from
the height at which the subdomain's own `seq`-0 Declaration Entry is
sealed, Deltas for that host's URLs materialize only under the
subdomain's Publisher domain — the parent's records for those URLs are
excluded from that height, exactly as a `delete` would exclude them,
and the parent's later Deltas for those URLs are not materialized while
the subdomain's Declaration stands. Below that height the parent's scope
governs alone. Every input to the rule — the Declaration Entry, its
height, the scope — is in the Log, so any two replayers agree; the
parent's excluded Entries remain in the Log like every other superseded
state.

**Materialization rule.** A `delete` Delta (WIST-1 §3.3) excludes that
URL's content from all subsequent Snapshots. A `payload_withdrawal` (§6.2)
likewise excludes that Delta's content from every Snapshot produced at or
above its sealing height, in both tiers, including any declared link
derived from it. A URL that is **unauditable** at the
Snapshot's `log_position` (WIST-4 §5) — one for which two independent Auditors
have sealed blocking Records inside the unauditable horizon, a
`robots.txt` prohibition or a page that could not be measured, with no
successful audit by an Auditor independent of both
since — is excluded for as long as that holds, and returns to
materialization at the first Snapshot built at or above the height of
such an audit. The log itself
retains full history in every case — deletion, withdrawal and
unauditability shape the materialized present, never the recorded past.

All three exclusions are computed from the Log, so two parties building a
Snapshot at the same `log_position` still materialize the same record set:
an unauditable URL is decided by that URL's Audit Records in Log order and
by the Parameter Registry value in force, not by whether the builder's own
crawler happened to be turned away.

Withdrawal reaches backward into Snapshots as well, because a Snapshot
already published carries the content in its tier files —
`tier1/extracts.parquet`'s text and `tier1/links.parquet`'s declared
links alike, per §6.2's rule that both are content. The Aggregator and
every Mirror MUST stop serving any Snapshot artifact containing
withdrawn content: the Aggregator either withdraws that Snapshot from
distribution or replaces it with one rebuilt under the exclusion rule
above, under a fresh signed manifest and at a `log_position` at or above
the withdrawal's sealing height — below that height the exclusion does
not apply and the rebuild would simply reproduce the content — and a
Mirror re-serving `/snapshots/` (§6) is bound identically — a Mirror
that kept serving the superseded tier files would leave the content in
distribution no matter what the Aggregator did, which is the whole of
what withdrawal is supposed to stop.
Neither costs a Consumer anything it cannot recover, since any state a
Snapshot provides is reachable from the Log and the Payloads. A manifest's
per-file `sha256` is a digest of a whole tier file rather than of any one
record, so it is no handle onto an individual extract — deriving one from
it would require already holding the file, and with it the text.

Anyone can rebuild an equivalent Tier 0/Tier 1 from the raw log, the
Payloads it references, and the manifest's declared parameters; Snapshots
are a convenience, not an authority. Withdrawal does not cost that
property: because the exclusion is triggered by a logged entry rather than
by whether a given rebuilder happens to hold the file, two parties with
different Payload collections still materialize the same record set. A
party missing a Payload that was never withdrawn cannot rebuild, and MUST
report that rather than emit a Snapshot silently missing a record.

**Verifying a rebuild.** Snapshot files are not byte-reproducible: SQLite
and Parquet outputs vary with library version, page size, insertion order,
and compression settings, and none of that is a property of the state being
described. This specification therefore does not require byte equality
between independent builds. It requires **semantic equivalence**, verified
by the manifest's `content_digest`:

```
record(r)       = {"url": r.url, "publisher": r.publisher,
                   "delta_id": r.delta_id, "observed_at": r.observed_at,
                   "weight": r.weight}
record_bytes(r) = JCS(record(r))
content_digest  = "sha256:" + hex(SHA-256(concat(
                      sorted(record_bytes(r) for r in records))))
```

where `records` is every live record materialized at `log_position`;
`r.delta_id` is the record's anchor Delta (§6.1) — the last content-bearing
Delta in its per-URL chain at that height, and therefore the Delta whose
Payload supplied the content the tiers carry; `r.observed_at` is the
`observed_at` of the newest Delta in that chain, which is the freshness the
tiers carry and is what makes an `attest` visible in the digest;
`r.weight` is `"full"` or `"reduced"` (WIST-4 §7 level 2); and `sorted` is
ascending octet order. Records are keyed by (Publisher domain, Normalized
URL) and the tuple carries both, so the ordering is total and no two
records can produce equal bytes. JCS objects are self-delimiting, so the
concatenation is unambiguous; an empty live set digests the empty octet
string.

Two parties that materialize the same Log prefix MUST obtain the same
`content_digest` regardless of their storage libraries; a mismatch — not a
differing file hash — is what indicates divergence. Per-file `sha256`
values remain in the manifest for transport integrity of the specific
artifacts the Aggregator published (§6).

**Every input is in the Log, and none of it is content.** The digest is a
function of the Log prefix from genesis through `log_position` and of
nothing else. Deletion, withdrawal, unauditability and every rung of the
sanction ladder are decided by sealed Entries and by the deadlines those
Entries start — WIST-4 §7 derives each ladder
level from the evidence rather than from an Aggregator's `sanction`, and
lifts it on a deadline the Aggregator lets lapse rather than on a
`sanction_lift` it chooses to file — and
the Parameter Registry values that decide them are read as of
`log_position`. Two consequences carry the design:

- **A rebuilder needs no Payload to compute it.** That is deliberate. A
  Payload may have been withdrawn since the Snapshot was published (§6.2),
  and a digest whose preimage included the withdrawn text could never be
  recomputed again — the guarantee would expire exactly when it is most
  contested. Because a withdrawal excludes the record only from Snapshots
  at or above its sealing height, and a replacement Snapshot is built at or
  above that height (above), every withdrawal a digest accounts for lies
  inside the prefix the digest is computed over: no second horizon is
  needed to say which ones those are.
- **Agreement still pins the content.** `delta_id` is the SHA-256 of a
  Delta's Canonical Bytes, and those carry the salted commitment to the
  Payload (WIST-1 §3.6). Two parties whose digests agree therefore hold the
  same commitment for every record, and §6.1 forbids materializing content
  that does not reproduce its commitment. The digest itself carries no
  content and confirms nothing a holder of a candidate text could not
  already confirm from the Log, since every field of the tuple is sealed
  there in the clear; the per-record commitment, not the digest, is what
  binds the text.

**What the digest does not say.** It describes a record set, not a height.
Two `log_position`s whose live sets are identical digest identically, which
is correct — they are the same state. The height is carried by
`log_position` and bound to a single chain by `anchor_block_hash`, the
Block Hash of Block `log_position`, which §8 checks against the chain the
Consumer verified. A Consumer that rebuilds to a height whose live set
differs therefore sees a `content_digest` mismatch (`WIST3-E04`) rather than
silent agreement; one that rebuilds to a different height whose live set is
the same agrees, and is right to, since the manifest's `log_position`
already says which height was meant. A manifest from a forked chain shows
an `anchor_block_hash` the Consumer's chain does not produce (`WIST3-E02`),
whatever its digest says. Nor does the digest speak for a
non-conforming builder: it proves two parties materialized the same
records, not that either verified the Payloads it indexed, which §6.1
requires of them separately.

**Sharding.** A manifest MAY declare `shards`: a `count` ≥ 1 and a
`digests` array of exactly `count` entries. When it does, every `files`
entry carries a `shard` index in `[0, count)`, a record belongs to the
shard

    first 8 octets of SHA-256(UTF-8 of the Publisher domain),
    read big-endian, mod count

— by Publisher domain, so every domain's records travel together and a
Consumer holding a shard holds whole domains, never fragments — and
`digests[i]` is the §7 construction computed over shard *i*'s records
alone. The whole-set `content_digest` is unchanged and remains REQUIRED:
the shards partition the records, so any party holding all shards
recomputes it, and any party holding some verifies each held shard
against its own digest. A **partial Consumer** MAY materialize any
subset of shards, MUST verify each held shard's digest and MUST treat
its coverage as partial — absence of a record it holds no shard for is
not evidence of anything. Sharding is what keeps two obligations
compatible at scale: a withdrawal (§6.2) invalidates the files of one
shard and the manifest, not every artifact of the Snapshot, so Mirrors
re-fetch one shard rather than terabytes; and a Consumer whose hardware
fits a fraction of the corpus verifies the fraction it holds instead of
trusting it. `shards.count` is the Aggregator's choice per Snapshot; a
manifest without `shards` is the `count` = 1 case with the bookkeeping
elided.

**Tier layout is normative.** A conforming rebuild MUST produce, per
shard where sharded: `tier0/index.sqlite` — a SQLite database whose
table `records` has columns `url`, `publisher`, `delta_id`,
`observed_at`, `weight`, `title`, `abstract`, `lang` (the record tuple's
fields plus the Payload `summary`'s members, `NULL` where the Payload
declares none), with an FTS5 index over `title` and `abstract` — and
`tier1/extracts.parquet` (`url`, `publisher`, `delta_id`, `extract`) and
`tier1/links.parquet` (above). An implementation MAY add columns and
auxiliary tables; a Consumer MUST ignore columns it does not know, and
MUST NOT require any column this paragraph does not name. The layout is
normative for the same reason the digest is: "anyone can rebuild an
equivalent Tier 0" is exercisable only if two rebuilds answer the same
query the same way, and a first implementation's private layout would
otherwise become a de facto standard nothing checks.

**The state artifact.** The record tuples are the index's content; they
are not its law. Key validity, admissions, governance states and
reputation are all defined by replay from genesis, and a Consumer that
starts from a Snapshot instead of genesis needs that state or it cannot
verify the first post-rotation signature, continue a sanction ladder,
or compute a reputation. The manifest therefore declares `state`: the
`path`, `sha256` and `bytes` of a state file, and its `state_digest`.
The state file is a signed Envelope whose inner object is `state`
(schema:
[`schemas/snapshot-state.schema.json`](../schemas/snapshot-state.schema.json)),
carrying `wist_version`, the `log_position` (= the manifest's), and
`entries`: one tuple per item of live protocol state, each a JSON array
whose first member is its kind. The kinds, their key fields and their
value fields are:

| Kind | Key fields | Value fields | Defined by |
|---|---|---|---|
| `aggregator_key` | `key_id` | `public_key`, added height, removed height or `null` | §3.4 |
| `auditor` | `auditor_id`, `key_id` | `public_key`, admitted height, removed height or `null` | WIST-4 §3 |
| `declaration` | domain | the current Declaration Envelope, its sealing height | WIST-1 §5 |
| `parameter` | identifier, `effective_at` | value | WIST-4 §9 |
| `sanction_state` | domain | level, establishing Registry Update IDs, each open deadline instant | WIST-4 §7 |
| `recovery_window` | domain | recovery Declaration height, window end | WIST-1 §5.2 |
| `exclusion` | publisher, URL | excluded-since height | WIST-4 §5 |
| `coverage_failure` | `auditor_id`, block number | — | WIST-4 §4 |
| `escalation` | domain | establishing `sealed_at` | WIST-4 §4 |
| `observer` | `observer_id`, `key_id` | `public_key`, registered height, ended height or `null` | WIST-4 §3.1 |
| `canary_commitment` | Registry Update ID | planter domain, `root`, `leaves`, sealing height | WIST-4 §5.1 |
| `reputation_inputs` | domain | first-accepted-Delta `sealed_at`, reset height or `null`, `C`, the counted-URL digest set (below), penalties as (confirming `sealed_at`, severity) pairs | WIST-4 §6 |
| `record` | publisher, URL | chain-tip Delta ID | §6.1, §7 |

A `parameter` tuple exists only for a parameter amended since genesis:
Registry defaults are constants of this suite and are not restated. One
tuple exists per amendment rather than per identifier, which is why
`effective_at` is a key field: a `parameter_change` sealed before
`log_position` but effective after it is live state a resuming Consumer
cannot re-derive — it will never see that Entry again — and a single tuple
per identifier would force the artifact to choose between the value in
force and the one about to be. Both appear, and a Consumer applies each at
its own instant — `effective_at` inclusive, the greatest `effective_at`
at or before an instant prevailing (WIST-4 §9). An amendment that another
amendment with the same `effective_at`, sealed later in Log order,
supersedes is never in force and is not state: no tuple exists for it,
which is what keeps the key unambiguous. A
`record` tuple carries the chain tip — the newest Delta of the chain,
which the content tuple does not name (its `delta_id` is the anchor) —
because a resuming Consumer must reject a fork of the live chain
exactly as a replaying one would (WIST-1 §3.5). One `record` tuple
exists per (Publisher domain, Normalized URL) the state carries a tip
for, a deleted URL included: a `delete` removes the content tuple and
leaves the tip, which is the `delete` itself, so the `record` tuples'
keys are a superset of the content tuples' and not the same set. A
resuming Consumer therefore holds the tip the URL's next Delta will name
and applies that Delta exactly as a replaying one does; a state that
omitted the tuple would have it ignore that Delta as a fork of nothing
while full replay applied it, and the two would never agree again on
that URL. `state_digest` is the §7
construction verbatim — `sha256:` over the concatenation of the sorted
JCS bytes of every tuple — and every field above is Log-derived, so the
digest is computable after any withdrawal, for the §7 reasons. A
Consumer that replays from genesis MAY recompute it and MUST obtain the
manifest's value; recomputability from public inputs, not the
Aggregator's signature, is what makes the artifact state rather than
testimony.

A tuple's encoding is normative: it is the JSON array `[kind, key
fields…, value fields…]` with the members in exactly the order the table
gives, none omitted and none added. Heights and block numbers are JSON
integers; a "removed height or `null`" member is an integer or JSON
`null`; instants (a window end, a deadline, a first-accepted
`sealed_at`, a penalty's confirming `sealed_at`, an escalation's
establishing `sealed_at`, a parameter's
`effective_at`) are the whole-second literal-`Z` RFC 3339 strings the
sealing Blocks and the Entries they seal carry (WIST-4 §2, §9.1);
domains, URLs, `key_id`s, `auditor_id`s and parameter identifiers are
the strings the sealed Entries carry; keys are raw base64url public
keys; IDs are `sha256:`-prefixed. Three kinds need more than that:
`declaration`'s value members are the current Declaration Envelope as
sealed, verbatim as one JSON object member, then its sealing height;
`sanction_state`'s establishing Registry Update IDs are an
ascending-octet-ordered array, and its open deadlines an array of
two-member `[label, instant]` arrays with `label` one of `"appeal"`,
`"appeal_sealing"`, `"ruling"` (WIST-4 §7's three open-deadline kinds),
in ascending octet order of their JCS bytes; `reputation_inputs`'
penalties are an array of two-member `[confirming sealed_at, severity]`
arrays in Log order of the confirming Records, and its counted-URL
digest set is the ascending-octet-ordered array fixed below. The
schema pins each kind's arity and member types
([`schemas/snapshot-state.schema.json`](../schemas/snapshot-state.schema.json));
the table remains the normative inventory, and a state file omitting a
kind with live instances at `log_position`, or carrying one this table
does not name, does not verify.

**The counted-URL digest set, and why the artifact stays small.** `C`
counts distinct URLs (WIST-4 §6), so continuing the count requires
membership, not just a total — and a naive artifact would carry up to
`c_cap` Normalized URLs per domain, which at a million domains is tens
of gigabytes: a mandatory artifact larger than the laptop-sized Tier 0
this section exists to keep laptop-sized. A `reputation_inputs` tuple
therefore carries, in place of the URLs, the ascending-octet-ordered
list of their **counted-URL digests**: for each counted URL, the first
16 octets of `SHA-256(JCS(publisher domain) ‖ JCS(Normalized URL))`,
lowercase hex. Membership is all the count needs, the domain is inside
the preimage so digests never collide usefully across domains, and the
inputs are Log-derived like every other field, so the tuple stays
recomputable and the digest stays withdrawal-proof. The bound is then
`c_cap` × 32 hex octets per domain — under 16 KiB at the default 500,
two orders below the URLs themselves — and a Consumer continuing the
count digests each newly-audited URL the same way. Truncation to 16
octets is deliberate and sufficient: the set is a private
bookkeeping aid whose only adversarial use would be inflating one's own
`C`, which requires forging a `consistent` Audit Record from an
independent Auditor and not a digest collision.

Sharding applies to this artifact as to the tiers: when the manifest
declares `shards`, the state file MAY be split on the same
Publisher-domain rule, one part per shard for the domain-keyed kinds
(`declaration`, `sanction_state`, `recovery_window`, `exclusion`,
`escalation`, `reputation_inputs`, `record`), with the Log-wide kinds
(`aggregator_key`, `auditor`, `parameter`, `coverage_failure`,
`observer`, `canary_commitment`) carried in every part, since no Consumer
can validate an Entry without them. A `canary_commitment` tuple exists
while the commitment is live — unrevealed and inside its lifetime
(WIST-4 §5.1) — and an `observer` tuple while the registration holds, so
that a resuming Consumer rejects the same reveals and checkpoints a
replaying one does.
The tuple set is a set: a Log-wide tuple appears exactly once in the
digest preimage, however many parts carry a copy.
`state_digest` remains the digest over the whole tuple set: a partial
Consumer verifies its parts against the per-shard digests and, as
above, treats its coverage as partial.

**Cold start:**

1. Fetch `/snapshots/index.json`; verify its signature; choose an entry
   (normally the newest).
2. Fetch that entry's `manifest_url`; verify its signature; verify that its
   `snapshot_date`, `log_position` and `content_digest` are the ones the
   index entry named (`WIST3-E04` on disagreement — the two are independently
   signed statements about the same Snapshot).
3. Download the listed files — all of them, or, under a manifest that
   declares `shards` (§7), the state file and any subset of shards —
   and verify each SHA-256 and byte size.
4. Fetch `/log/checkpoint.json`; verify signature.
5. Download Blocks `log_position + 1 .. checkpoint.block_number`. A Block
   a Mirror does not hold is `WIST3-E01`: fetch it from another Mirror,
   since integrity never depends on the source.
6. Verify each Block: chain (`prev_block_hash`), signature, `merkle_root`
   recomputation, `entry_count`.
7. Verify that the head Block's Block Hash equals `checkpoint.block_hash`,
   and that each Block's `prev_block_hash` matches the Block Hash of its
   predecessor, walking backward from the head to `log_position`.
8. Verify that the manifest's `anchor_block_hash` is the Block Hash of
   Block `log_position` on that same chain: against the `prev_block_hash`
   of Block `log_position + 1` when one was downloaded, or against the
   Checkpoint's `block_hash` when the Snapshot is already at the head. A
   mismatch is chain divergence (`WIST3-E02`), not a corrupt file: it means
   the Snapshot describes a different chain from the one just verified.
9. Fetch `/payloads/<delta-id-hex>.json` for every content-bearing Delta
   in those Blocks whose Payload has not been withdrawn (§6.2); verify
   each against its Delta's commitment and `bytes` (§6.1).
10. Load the state artifact (§7): verify its signature and its
    `log_position`, and adopt its tuples as the protocol state at
    `log_position` — key registries, Declarations, governance states,
    reputation inputs, chain tips. Every Entry applied in the next step
    is validated against this state exactly as a replaying Consumer
    validates against state it derived itself: a signature under a key
    the state does not admit, a Delta whose `prev` is not the chain tip
    the state carries, a Record from an Auditor the state shows removed, all fail
    as they would on full replay.
11. Apply Entries in order to the local index, materializing content only
    from Payloads that verified.

A Consumer that also replays the Log from genesis MAY recompute the
Snapshot's `content_digest` and `state_digest` (§7) and compare them with
the manifest's. Doing so needs no Payload and no tier file, so it is
available to any party holding the Blocks — including one checking an
Aggregator it does not otherwise sync from — and it is what keeps the
state artifact an assertion anyone can falsify rather than testimony a
cold-starting Consumer must take on trust.

**Continuous operation:**

1. Fetch `checkpoint.json` (SHOULD: from ≥ 2 Mirrors). A Checkpoint whose
   `block_number` is lower than the highest already verified MUST be
   rejected (§5's rollback rule) before any Block is downloaded against it,
   and the Consumer SHOULD warn if the newest Checkpoint's `sealed_at` lags
   the current time by more than three sealing cadences (§5) — a stale head
   and a rolled-back head are the two ways a Mirror can leave a Consumer
   verifying correctly against the wrong end of the chain.
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
to process. Both paths converge to identical state — the record tuples by
`content_digest`, the protocol state by `state_digest`, each recomputable
from the Blocks alone (§7) — so the choice is purely economic. Without
the state artifact the sentence before this one would be false: record
tuples alone carry no key registry, no governance state and no chain
tips, and the two paths would converge only on content while disagreeing
on law.

**Following more than one Log.** Nothing in this suite binds a Publisher
to one Log: WIST-2's publication surface is one site serving whomever
pulls, so any number of Aggregators MAY ingest the same Feed and a
Consumer MAY follow any number of Logs. Merging them needs no protocol.
A Delta ID is the SHA-256 of the Delta's Canonical Bytes (WIST-1 §4),
which carry nothing about the Log that sealed them, and `prev` chains a
URL's Deltas on the Publisher's side rather than the Aggregator's — so
one Delta has one identity and one predecessor in every Log that sealed
it, and a Consumer holding two Logs deduplicates by Delta ID exactly.
What does not merge is everything a Log derives rather than transports.
Which Deltas an Aggregator ingested, its Auditor roster (WIST-4 §3),
every reputation, sanction, exclusion and quota computed from that
roster's Records (WIST-4 §6), and the reach of a withdrawal (§6.2) are
state of one Log, defined by replay of that Log's history. A Consumer
MUST NOT carry any of them into another Log: each is a function of a
single chain, and a value mixed across chains is recomputable by nobody.
Coverage across Logs is partial in exactly the sense §7 gives a sharded
Snapshot — absence of a record from a Log a Consumer does not follow is
not evidence of anything, and neither is absence from a Log that never
ingested that Publisher. The one place state does cross chains is
succession (§3.4), where a successor Anchor names its predecessor and
the Block it ended at; that is one Log continued under new keys, not two
Logs reconciled, and nothing here extends it to concurrent Logs.

## 9. Error Registry

| Code | Meaning and required behavior |
|---------|--------------------------------------------------------------|
| WIST3-E01 | Block missing at a Mirror. Fetch from another Mirror; integrity never depends on the source. |
| WIST3-E02 | Chain divergence (hash mismatch or conflicting Checkpoints, head Block Hash does not match the Checkpoint's `block_hash`, or a Snapshot manifest whose `anchor_block_hash` is not the Block Hash of Block `log_position` on the verified chain — §8). Hard failure: preserve both Checkpoints as an evidence bundle (§5), MUST NOT apply the data. |
| WIST3-E03 | Corrupted file (hash or signature failure on a Block, or a Payload that does not reproduce its Delta's commitment — WIST-1 §3.6, `WIST1-E10`). Re-download, from another Mirror if needed, before concluding misbehavior. |
| WIST3-E04 | Snapshot manifest mismatch. Three cases, one code, different responses. A file hash or byte size that disagrees with the manifest, or a manifest that disagrees with the `/snapshots/index.json` entry that pointed to it (§8): reject the entire Snapshot and re-fetch, from another Mirror if needed. A `content_digest`, `state_digest` or per-shard digest (§7) that disagrees with the Consumer's own rebuild at `log_position`: not a transport fault and not fixable by re-downloading — the Consumer MUST NOT treat that Snapshot as authoritative, MUST fall back to materializing from the Log and the Payloads, and SHOULD publish both digests with the `log_position`, since a Snapshot that does not match the Log is a claim the Aggregator cannot support and anyone replaying the Log can check the report. |
| WIST3-E05 | Payload absent from a Mirror inside the availability window with no `payload_withdrawal` sealed for it (§6.1, §6.2). A fault against that Mirror, never against the Delta: fetch the Payload from another Mirror or from the Publisher (WIST-2 §3.1), and keep applying the Log. A Consumer that sees `WIST3-E05` from every source it tries SHOULD publish that fact, because a Payload absent everywhere with no logged basis is the signature of suppression rather than of erasure. |

## 10. Security Considerations

- **Equivocation** is the Aggregator's only meaningful attack, and §5
  makes it self-incriminating at the cost of two small signed files.
- **Rollback.** A Mirror serving stale data cannot regress a Consumer:
  block numbers are monotonic and Consumers never accept a Checkpoint
  older than one they hold.
- **Mirror tampering.** Mirrors are trustless byte servers; any
  modification fails hash or signature verification (`WIST3-E03`). This
  covers Payloads too: a Mirror that alters one fails the Delta's
  commitment, which every fetcher recomputes and which was fixed by the
  Publisher's signature before any Mirror saw it.
- **Selective payload suppression.** Tampering being useless, a hostile
  Mirror's remaining move is to serve some Payloads and not others. §6.1
  makes that a typed, attributable fault: inside the availability window,
  absence with no `payload_withdrawal` in the Log is `WIST3-E05` against
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
  fault; WIST-2 §5 closes the honest path by requiring the Aggregator to
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

The log is public and permanent; WIST-1 §9's constraints on personal data
apply to everything in it. Content is deliberately not in it: Payloads are
distributed alongside the Log and are erasable under §6.2, so an erasure
order costs a file deletion plus a Log entry rather than a rewrite of
sealed history. Mirrors keep serving bytes and stay free of any obligation
to re-serialize or partially reconstruct what they hold.

Erasure is an obligation on operators, not a property of the network. A
withdrawal binds the Aggregator, its Mirrors and the Publisher that first
served the Payload; it cannot reach a copy
already downloaded, and nothing in this specification pretends otherwise.
What the design does guarantee is that after withdrawal the Log itself
stops helping: with the salt destroyed, the surviving commitment does not
let a holder of a copy establish that the copy is what was committed to
(WIST-1 §3.6, §9).

On the read side, a Consumer's sync pattern
(timing, IP) is visible to the Mirrors it uses. Mitigations: Mirrors are
dumb file servers requiring no accounts; bulk sync reveals only "this IP
follows the log", not queries (all querying is local by design); privacy-
sensitive Consumers can sync over Tor or from a Mirror they operate.

## 12. Conformance Checklist

**Aggregator:**

- [ ] Seals Blocks per §3 (sequential numbering, strict `sealed_at`
      monotonicity on the cadence grid, whole-second `sealed_at` ending
      in `Z`, canonical Entry order, the per-domain Entry capacity,
      correct Block Hash and Merkle root)
- [ ] Publishes a Checkpoint per sealed Block at the fixed URL, never
      before the Block it names and every lower Block are durably stored
      and served (§5)
- [ ] Serves the static layout of §6 with immutable Block files
- [ ] Serves every sealed Delta's Payload at `/payloads/<delta-id-hex>.json`
      from no later than the Block that seals it, for at least the
      availability window, byte-identical to what it verified at ingest
      (§6.1)
- [ ] Serves a URL's anchor Payload with no expiry until a superseding
      content-bearing Delta or a `delete` is sealed for that URL, then for
      one further availability window, then no longer (§6.1)
- [ ] Withdraws a Payload only by sealing a `payload_withdrawal` naming
      the Delta, the legal basis, and the jurisdiction — and then stops
      serving it, together with any Snapshot artifact still containing its
      content (§6.2, §7)
- [ ] Produces Snapshots whose manifests satisfy §7, including the
      materialization rule, the `content_digest`, the state artifact and
      its `state_digest`, per-shard digests where sharded, and an
      `anchor_block_hash` equal to the Block Hash of Block `log_position`
- [ ] Treats any companion pack it publishes itself as a Snapshot
      artifact for §6.2's withdrawal obligations (§7)
- [ ] Publishes `/snapshots/index.json`, signed, newest first, agreeing
      with each manifest it points to, and removes an entry when it stops
      serving that Snapshot (§6)
- [ ] Retains every Block from genesis and every Checkpoint it has
      published, the latter at `/log/checkpoints/<block_number>.json` (§6)
- [ ] Rebuilds a Snapshot superseded by a withdrawal at a `log_position`
      at or above the withdrawal's height, or withdraws it (§6.2, §7)
- [ ] Never emits a Block exceeding the decompressed cap, and declares each
      Block frame's decompressed size (§6)
- [ ] Publishes a Log Anchor and admits all later keys in-band (§3.4)
- [ ] Seals a `publisher_declaration` Entry for a domain before, or in
      the same Block as, the first Delta it authorizes, and never seals a
      Delta the Key Set resolved at its own Block no longer verifies
      (§3.3, WIST-1 §5.2)

**Mirror:**

- [ ] Serves content that verifies: a Block file that decompresses to a
      Block reproducing its Block Hash, `merkle_root` and `entry_count`,
      and a signed object whose canonical bytes reproduce its signature —
      not necessarily the origin's octets, which compression settings make
      Mirror-specific (§6)
- [ ] Serves Snapshot tier files byte-identical to origin, since only the
      manifest's per-file `sha256` authenticates them (§6, §7)
- [ ] Retains every Block it serves for at least `mirror_retention_days`
      (§6)
- [ ] Retains all Checkpoints ever served, without expiry (§5, §6)
- [ ] Serves the Payloads of every Block it serves for at least the
      availability window, never serves a Block before its Payloads, and
      stops serving one only after a `payload_withdrawal` is sealed for
      it (§6.1, §6.2)
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
- [ ] Rejects Checkpoints older than the highest already verified, before
      downloading Blocks against them (§5, §8)
- [ ] Warns when the newest Checkpoint's `sealed_at` lags the current time
      by more than three sealing cadences (§5, §8)
- [ ] Verifies manifest hashes/sizes before using a Snapshot, checks the
      manifest against the `/snapshots/index.json` entry that named it, and
      binds `anchor_block_hash` to the chain it verified (§8)
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
- [ ] Rejects Blocks off the `sealed_at` grid, out of canonical Entry
      order, or over the per-domain Entry capacity (§3.1–§3.3)
- [ ] On cold start from a Snapshot, loads the state artifact and
      validates subsequent Entries against it; on a sharded Snapshot,
      verifies each held shard's digest and treats coverage as partial
      (§7, §8)
- [ ] On accepting a successor Anchor, verifies the predecessor chain to
      its declared final Block and carries state forward (§3.4)
- [ ] When following more than one Log, deduplicates by Delta ID, keeps
      each Log's derived state to that Log, and treats coverage as partial
      (§8)

## Appendix A. Test Vectors

Generated by `tools/gen_vectors.py`; verified by
`tools/validate_examples.py`. Full files:
[`vectors/wist3/block.json`](../vectors/wist3/block.json),
[`vectors/wist3/inclusion-proof.json`](../vectors/wist3/inclusion-proof.json).

Block 0 contains 4 `publisher_delta` Entries: the WIST-1 vector Delta and
three `attest` Deltas for `post-2..4`. Their positions follow §3.3's
canonical order — one type group, ascending leaf-hash order — which puts
the WIST-1 vector Delta at entry 0 and the `attest` Deltas at entries 1, 2
and 3; no Entry's position is chosen.

**Leaf hashes (hex):**

```
leaf0 = 003466c49d154d4a1a727db31832343d95a12895c745e42694f20219d91e8e3b
leaf1 = 21a0706098e48aef88915327ccf69ef4b531494974cc426035ec14a39afdf6ca
leaf2 = bd9f265d4ef744b3660f2ce2a7cdf4776f36489ca12a3dfc6d0aac1fd0c27191
leaf3 = f3080af7283905717b0b7a0c01f2575f25e47dc5e59f60bb0e238ab1f5885fce
```

**Interior nodes:**

```
n01 = node(leaf0, leaf1) = a1c0239ab92c6b8b73004c3bc733eb0525010d98671df022cf9026ff62158986
n23 = node(leaf2, leaf3) = c16e1115f918661cf1627f7792052f273c4b4b5e34c008082b6b20d5df81af53
```

**Merkle root:**

```
sha256:263c5109e9a0684970ab4af502fadca90685e8b59f2f8aa1a21c22c5fe228876
```

**Block Hash (over JCS of the header):**

```
sha256:f6a352a23522bbce2ae827d9c4c4941dbca3a8a9a7be37d99d4f620e4d0d5487
```

**Inclusion proof for entry 0** — `index 0, entry_count 4 → siblings
leaf1 then n23, both right-hand` (derived, not carried in the proof):

```
h = leaf0
h = node(h, leaf1)   → 8f76270c...  (= n01)   # fn=0 < sn=3: sibling on the right
h = node(h, n23)     → 2665ae59...  (= root)  # fn=0 < sn=1: sibling on the right  ✓
```

Entry 2's Payload is [`examples/payload.json`](../examples/payload.json),
served at `/payloads/6cac5bdd…5120.json`. It contributes to none of the
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
without shipping binary artifacts. Its `anchor_block_hash` is the Block
Hash above, Block 0 being its `log_position`.

Its `content_digest` is computed over the two records in
[`vectors/wist3/snapshot-records.json`](../vectors/wist3/snapshot-records.json),
which publishes the record tuples themselves so that §7's formula is
reproducible from the file: one full-weight record for the Delta above, and
one reduced-weight record for a domain under a WIST-4 §7 level-2 mark, so
that both `weight` values and the ordering rule are exercised. That second
domain's Delta is not an Entry of the example Block; the vector demonstrates
the record encoding, not a materialization of Block 0.
[`examples/snapshot-index.json`](../examples/snapshot-index.json) is the
corresponding discovery index, carrying the same `snapshot_date`,
`log_position` and `content_digest` the manifest declares.

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- [RFC 6962] Certificate Transparency — Merkle hashing discipline,
  checkpoint/equivocation model
- [RFC 8785] JSON Canonicalization Scheme (JCS)
- WIST-1: Delta Format & Identity · WIST-2: Site Publication ·
  WIST-4: Audit, Reputation & Governance
