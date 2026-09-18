# WIST-3: Logbook & Distribution

**Status:** v1.0.0-draft · **Date:** 2026-08-02 · **License:** CC-BY 4.0

## 1. Introduction

The Logbook is one append-only RFC 6962 Merkle tree whose leaves are
accepted Deltas and Declarations (WIST-1), Labels and disputes (WIST-2
§3.3) and governance actions (WIST-4), published as C2SP checkpoints and
tiles so that generic transparency-log clients and Witnesses read it
with no knowledge of this suite. Consumers verify the tree and recompute
derived artifacts. The Certificate Transparency [RFC 6962] design
rationale is recorded in
[ADR-0004](../decisions/0004-log-centric-ct-model.md) and the adoption
of the C2SP formats in
[ADR-0046](../decisions/0046-single-tree-log.md).

This document defines Blocks as intervals of the tree, the Entry format,
the tree and its proofs, Checkpoints, Witnesses and anti-equivocation,
the static distribution layout, snapshots and tiers, and the consumer
synchronization procedure.

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as
shown here.

- **Log** (the **Logbook**): the append-only RFC 6962 Merkle tree this
  document defines, whose leaves are the Entries in the order they were
  appended. "The Log" always means the whole tree, never one
  Aggregator's current view of it.
- **Block**: the Entries between two consecutive Checkpoints — the
  leaves from the previous Checkpoint's tree size up to, excluding, its
  own — sealed together under one `sealed_at` (§3).
- **Entry**: one typed item in a Block (`publisher_delta`,
  `publisher_declaration`, `label`, `dispute` or `registry_update`), and
  one leaf of the tree.
- **Log Anchor**: the self-signed document that identifies a Log by its
  `log_id` and declares its `genesis_key`; it is the Log's out-of-band
  trust root, obtained through a channel the Consumer trusts rather than
  from the Log itself (§3.4).
- **genesis key**: the Aggregator signing key the Log Anchor declares. It
  is the only Aggregator key not admitted in-band; every later one is
  added and retired by Registry Updates the genesis key's chain of
  successors signs (§3.4).
- **Checkpoint**: the Aggregator's signed statement of the tree at one
  size — a signed note in the C2SP checkpoint format, carrying the
  Block's number and `sealed_at` (§5). Checkpoint N ends Block N.
- **Witness**: a party that cosigns a Checkpoint after verifying it
  consistent with every Checkpoint of the same Log it cosigned before,
  under the C2SP witness protocol; a **Cosignature** is the signature
  line it adds (§5).
- **Consumer**: any party that synchronizes the Log and materializes an
  index from it (§8). A Consumer trusts no Aggregator and no Mirror: it
  verifies signatures, hashes and commitments for itself.
- **Mirror**: any party re-serving the log's static files.
- **Snapshot**: a signed, derived materialization of log state at a Block.
- **Tier**: a size/completeness layer of a Snapshot (Tier 0 compact,
  Tier 1 full extracts and the link graph).
- **Inclusion Proof**: a Merkle audit path proving an Entry is a leaf of
  the tree a Checkpoint states (§4).
- **Consistency Proof**: the RFC 6962 proof that the tree one Checkpoint
  states extends the tree an earlier one states (§4).
- **Payload**: the content a Delta commits to (WIST-1 §3.6), distributed
  alongside the Block that seals that Delta and not inside it (§6.1).
- **Withdrawal**: the logged removal of a Payload from distribution,
  under §6.2.

Terms from WIST-1 (Envelope, Delta, Delta ID, Canonical Bytes, Payload,
Publisher, Aggregator) and WIST-2 (Feed) keep their defined meanings. Every
signed object in this document except the Checkpoint is constructed exactly as WIST-1 §4 requires —
inner object canonicalized with JCS, signed with Ed25519, signature
detached — and carries `wist_version` (WIST-1 §3.1) and the WIST-1 §4 signature
block (`key_id`, `alg`, `value`). The Checkpoint is a signed note under
the C2SP formats §5 names, signed by the same Aggregator keys (§3.4).

In the vocabulary of RFC 9943 (SCITT), the Aggregator is the
Transparency Service, a Publisher an Issuer, the URL a Delta is about
(WIST-1 §3.2) the Subject, the admission rules (WIST-1 §7, WIST-2 §5,
§3 of this document) the Registration Policy, and an Inclusion Proof
against a cosigned Checkpoint the Receipt. The mapping places the suite
for a reader arriving from SCITT and adds no object: a COSE-encoded
Receipt is OPTIONAL and undefined in this edition, because it would be
a second encoding of the proof §4 already defines.

## 3. Block Format

A Block is the interval of the Log between two consecutive Checkpoints.
Write `size(N)` for the tree size Checkpoint N states (§5), with
`size(-1)` = 0: Block N's Entries are the leaves with indexes from
`size(N-1)` up to, excluding, `size(N)`, and its `entry_count` is
`size(N) - size(N-1)`, derived and never carried. No object represents a
Block: Checkpoint N is its signed statement, and its Entries are served
as §6 describes.

### 3.1. Identity and `sealed_at`

Checkpoint N states, for Block N:

| Value | Rule |
|-------------------|------------------------------------------------------|
| `block_number` | Sequential from 0, no gaps. |
| tree size | `size(N)` ≥ `size(N-1)`; equality is an empty Block. |
| root hash | Root of the tree at `size(N)` (§4); the tree at `size(N-1)` is its prefix, which a Consistency Proof verifies (§5). |
| `sealed_at` | RFC 3339 UTC at **whole-second precision with a literal trailing `Z`**; strictly increasing across blocks. |

`sealed_at` MUST match `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9]Z$`:
no fractional seconds, and no numeric offset
even one equal to zero. A Block whose `sealed_at` carries either MUST be
rejected. RFC 3339 permits both, but every day count in the suite — a
recovery window (WIST-1 §5.2), the availability window (§6.1), a parameter's
grace period (WIST-4 §5) — is derived from these values by converting them
to integer seconds, and a fractional or offset form would make that
conversion a rounding decision that two implementations could take
differently — one rounded half-second can move a whole-day boundary and
with it a window's end. Constraining the field is cheaper than specifying a rounding rule,
and it costs the Aggregator nothing: it chooses when to seal.

The date and time MUST be valid in the Gregorian calendar. Seconds are
`00` through `59`: a leap-second spelling with `:60` MUST be rejected,
never normalized to another instant. Integer epoch seconds count exactly
86,400 seconds per calendar day from 1970-01-01T00:00:00Z, without leap
seconds; 2016-12-31T23:59:59Z and 2017-01-01T00:00:00Z are one second
apart. The same profile applies wherever the suite requires this
whole-second, literal-`Z` form, including the Snapshot state timestamps
in §7. Other RFC 3339 fields retain their specified formats.

What it does not choose is the timestamp inside that choice: `sealed_at`,
converted to integer seconds since the epoch, MUST be an integer multiple
of `block_cadence_seconds` as in force at the previous Block's
`sealed_at`, and a Consumer replaying the Log MUST reject a Block off the
grid. The grid leaves the Aggregator its sealing cadence and removes
its choice of digits, so a Block's instant is a fact of the schedule
rather than an operator's choice. The first Block after a `parameter_change` to
`block_cadence_seconds` takes effect lands on the new grid; the Anchor's
own `created_at` is not a Block and is unconstrained.

A Block is identified by its number; what its Checkpoint states about
the tree is the pair (tree size, root hash), which an empty Block shares
with the Block before it (§3.2), and there is no Block hash apart from
the root. Where this suite
carries a Block's root hash in a JSON member — `anchor_block_hash` (§7),
`final_block_hash` (§3.4) — it is `"sha256:" + hex(root hash)`, the
same 32 octets the Checkpoint's root hash line carries in base64 (§5).

Checkpoint N commits to the Block's Entries through the tree: a verifier
holding Checkpoints N−1 and N knows the Block's leaf range and
authenticates any Entry against Checkpoint N with an Inclusion Proof
(§4). Entries are transported unsigned (§6); a verifier that downloads a
Block's Entries MUST verify, before use, that their leaf hashes occupy
that range in the tree whose root Checkpoint N states — an Inclusion
Proof per Entry, or the recomputation of that root from the tree hashes
it holds, which is the same check made once.

### 3.2. Sealing

Blocks are sealed at a fixed cadence (Parameter Registry, WIST-4 §5;
default: hourly): at a grid instant of §3.1 the Aggregator appends the
Block's Entries to the tree in the order §3.3 fixes and issues its
Checkpoint (§5). The Aggregator MUST issue a Checkpoint at every grid
instant, an empty Block — a Checkpoint restating the previous tree size
— where nothing is eligible; empty blocks keep the Log's heartbeat
observable, and a replaying Consumer, which sees only the Checkpoints
issued, checks each against the grid and does not reject a missed
instant (§5 gives the staleness signal). Once sealed, a Block is
immutable forever: its Entries' leaf indexes never change and no later
Checkpoint omits them.

**Per-domain Block capacity.** A Block MUST NOT carry more than
`domain_block_entries_max` (Parameter Registry; default 10 000)
`publisher_delta` and `label` Entries, counted together, whose
Publisher's or Labeler's Canonical Host has one Registrable Domain under
the Public Suffix List snapshot in force at the Block (WIST-4 §3.1), and
a Consumer replaying the Log MUST reject a Block that does. The unit is
the Registrable Domain, not the hostname, because a hostname under a
name one holds is free; before the first accepted `suffix_list_update`
every Canonical Host is its own unit. `dispute` Entries count with the
Deltas and Labels of the disputant's unit. **Per-Labeler cap.** Inside
that capacity, a Block MUST NOT carry more than
`labeler_block_entries_max` (Parameter Registry; default 1 000) `label`
and `dispute` Entries, counted together, of one Registrable Domain, and a
Consumer replaying the Log MUST reject a Block that does; the surplus
waits its turn in acceptance order like any other. The cap never
exceeds the per-domain capacity (WIST-4 §5), so a Labeler's Labels are
bounded twice and its Deltas once: labeling is an opinion about other
parties' publications, and a party that could fill a Block with
opinions as freely as with publications would make every Consumer's
subscription list the only bound on it. Where a Registrable Domain has
more accepted Deltas and Labels eligible for a Block than the cap
admits, the surplus waits its turn in acceptance order across its
hosts, and WIST-4 §5's inclusion ceiling runs from the Block an Entry's
turn arrives in — so the cap never obliges an Aggregator to breach the
ceiling, nor the ceiling to breach the cap. This is the one bound in
the suite on how much a domain may publish, and it is deliberately a
bound on *rate*, not on worth or on standing: every Registrable Domain
has the same quota and every domain the same eligibility (WIST-4 §5), judging
content's worth is outside the protocol (ADR-0006), and a ceiling that
grew with any standing would re-create the pay-for-position pressure
Invariant 2 exists to forbid — so the cap is flat, high enough that a large site's
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
Block that sealed this Delta" a well-defined phrase, a function only
because the answer is unique and permanent. A Label ID (WIST-2 §3.3) is
sealed once on the same terms, in at most one `label` Entry.

### 3.3. Entries

Each Entry is `{"type": <t>, "body": <envelope>}`, where `type` is one of
exactly five values and `body` is the Envelope that value names:

- `publisher_delta` — body is a Delta Envelope (WIST-1).
- `publisher_declaration` — body is a Publisher Declaration Envelope
  (WIST-1 §5.1); the Aggregator MUST seal a Declaration Entry before, or in
  the same Block as, the first Delta it authorizes.
- `label` — body is a Label Envelope (WIST-2 §3.3).
- `dispute` — body is a Dispute Envelope (WIST-2 §3.3).
- `registry_update` — body is a Registry Update Envelope (WIST-4 §3).

WIST-3 defines only this envelope; the `body` format of `registry_update`
is normative in WIST-4, of `label` and `dispute` in WIST-2, and of
`publisher_delta` and `publisher_declaration` in WIST-1. Validators MUST reject Blocks containing
unknown Entry types under the current major version.

**An Entry fits one leaf.** An Entry's JCS serialization — its leaf
data (§4) — MUST NOT exceed 65 535 octets, the largest length the
16-bit prefix of an entry bundle can carry ([tlog-tiles], §6). The
Aggregator MUST NOT seal a larger Entry, and a Consumer replaying the
Log MUST reject a Block that contains one (`WIST3-E03`).

**Entry order is canonical.** Within a Block, Entries MUST appear grouped
by type in the fixed order `publisher_declaration`, `registry_update`,
`publisher_delta`, `label`, `dispute`, and within each group in ascending octet
order of each Entry's Merkle leaf hash (§4). A Consumer replaying the Log
MUST reject a Block ordered otherwise. The rule exists for the same
reason as the `sealed_at` grid (§3.1): Entry order fixes each leaf's
index, and with it the root hash every Checkpoint from N on states, and
a free permutation of Entries would let one set of Entries seal under
many roots. Canonical order leaves the Aggregator its one real choice,
Block membership. An Entry's leaf index (§4) is `size(N-1)` plus its
position in this order, so Log order — ascending Block height, then
Entry index — is ascending leaf index.

Storage order and application order are therefore decoupled, and
**application order** is defined, not inherited: within a Block, apply
`publisher_declaration` Entries first (for each domain, validate and apply
them in ascending `seq`, after settling any recovery window whose end is
at or before this Block's `sealed_at` and activating any pending head
whose activation height is this Block's; WIST-1 §5.2 retains the highest
accepted sequence through settlement and selects a recovery window's owner in
ascending `(Block height, seq)` order, so intra-Block storage position
never decides between them; a fresh Declaration applied before that owner
becomes pending, while an in-window fresh competitor does not),
with equal-sequence groups handled by WIST-1 §5.2: conflicting first-install
Envelopes invalidate the entire Block under `WIST1-E08`; current-Declaration
re-serves and exact duplicates install no additional state or signature.
Every Declaration must pass its acceptance checks; on failure reject the
whole Block with the applicable error, preserving the previously accepted
prefix and all its state, including recovery windows due to settle in the
rejected Block. Then apply `registry_update` Entries (key acts read at
Block granularity — "valid at this Block's `sealed_at`" — under §3.4;
`parameter_change` validation and equal-effective-time precedence read
canonical Entry index under WIST-4 §5; a `payload_withdrawal` naming a
Delta this Block seals takes effect on that Delta as the Delta applies
below, WIST-4 §5.1), then
`publisher_delta` Entries **in chain order**: a Delta whose `prev` names
a Delta in the same Block applies after it, which is well-defined because
chains are trees rooted outside the Block and cycles are impossible
(a Delta ID includes its `prev` in its preimage), and two Deltas with no
chain relation apply in leaf-hash order without observable difference.
`label` Entries apply next, in ascending Entry index in the canonical
stored order, which WIST-2 §3.3 reads to order two Labels of one Labeler
sealed in one Block, and `dispute` Entries last, in the same order, which
orders two disputes of one Label by one disputant; a dispute applies
nothing to the Label it names. No conforming behavior depends on any ordering freedom this
paragraph does not name. Because Declarations apply first, the Key Set a
`publisher_delta` Entry verifies under is the one WIST-1 §5.2 resolves at
its own Block with that Block's Declarations already applied: an
Aggregator MUST NOT seal a Delta that fails it (WIST-1 §5.2), and a
Consumer that meets one ignores the Entry as it ignores a fork — applied
to nothing, moving no chain tip (§7). The same disposition covers every
other WIST-1 §7 Delta check a sealed Entry can fail — field validation,
§3.1 major support, the caps and clock allowance in force at its Block
(WIST-1 §3.4, WIST-4 §5) and Normalized URL or authority — none of which
an Aggregator may seal: the Entry is ignored, the Block stays accepted,
and a later Delta naming the ignored one as `prev` is ignored with it.

### 3.4. Aggregator Keys and the Log Anchor

A Log is identified by its **Log Anchor**, a self-signed document whose
inner object is `anchor` (schema:
[`schemas/log-anchor.schema.json`](../schemas/log-anchor.schema.json)),
served at `/log/anchor.json`. It declares `wist_version`, the `log_id` (the
Log's hostname identity, and the origin line of its Checkpoints, §5), the `genesis_key` — an object carrying that key's
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
one. Checkpoint N (§5) MUST be signed by a key that was valid at
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

**An Aggregator key as a note signer.** A Checkpoint is a signed note
(§5), and an Aggregator key signs it under the Ed25519 signature type of
[signed-note]: the key name is the Log's origin, its `log_id` (§5), for
every Aggregator key, as [tlog-checkpoint] recommends; the note key ID
is `SHA-256(key name || 0x0A || 0x01 || 32-byte public key)[:4]`, the
derivation [signed-note] gives that type; and the signature line's
value is `base64(key ID || Ed25519 signature over the note text)`. The
verifier-key string [signed-note] defines,
`<log_id>+<hex key ID>+base64(0x01 || public key)`, is the form in which
a key is configured at a Witness. A `key_id` never appears in the note:
a Consumer maps a signature line to a `key_id` by computing the note
key ID of every key valid at the Checkpoint's height. The Aggregator
therefore MUST NOT seal an `aggregator_key_add` whose key's note key ID
equals that of any key previously admitted to the Log, the genesis key
included, and a Consumer replaying the Log MUST reject one: a collision
is the one case in which a signature line would name two keys.

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
the exact Block — `final_block_number`, and `final_block_hash`, the root
hash Checkpoint `final_block_number` states in the `sha256:` form of
§3.1 — at which it ended. The successor's `log_id` MUST differ from its
predecessor's: the origin names one tree at every Witness and Consumer
(§5), and the successor's tree begins empty. The successor Anchor is a
trust root like any Anchor: obtained
and verified out-of-band (§3.4 above), believed because Consumers and
Publishers choose it, not because the old chain — which by
hypothesis can no longer say anything trustworthy — endorses it.

What the field changes is what a Consumer that accepts the successor
MUST do with the past: verify the predecessor chain to the named final
Block exactly as §8 verifies any chain, and carry the state at that
Block — materialized records, Declarations, parameters, withdrawals,
Labels, every §7 state-artifact category — into the
successor's genesis, exactly as if the successor's Block 0 were Block
`final_block_number + 1`. Windows anchored to a `sealed_at` of the dead
chain keep their instants; Blocks of the successor discharge them. The
carry is the point: a fork is this suite's stated remedy for a captured
or colluding operator (WIST-4 §4, §8), and a remedy that erased every
domain's history and every withdrawal would punish every honest
Publisher — a successor without `predecessor` does exactly that,
lawfully, as a new Log that inherits nothing. **The named final Block must be the last one.** A `predecessor` MUST
name the highest Block of the ended Log for which any validly signed
Checkpoint exists, and a Consumer MUST reject a successor Anchor whose
`final_block_number` is lower than the highest Checkpoint it holds or
can obtain for that `log_id` — reject the Anchor, not merely the
carry. Without this rule succession is a laundering machine dressed as
continuity: an operator, or anyone else, publishes a successor naming a
final Block from before a withdrawal or key removal it dislikes, and
every Consumer that pins it carries state from a height at which that
Entry had not happened. Truncation is exactly as attributable as equivocation and is
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

## 4. Merkle Tree, Inclusion and Consistency Proofs

The Log is one RFC 6962 Merkle tree over SHA-256, with that RFC's
hashing discipline:

```
leaf  = SHA-256(0x00 || JCS(entry))
node  = SHA-256(0x01 || left || right)
```

A leaf's data is the Entry object's JCS serialization (RFC 8785), so an
Entry's leaf hash is a function of the Entry alone. Leaves are the
Entries in Log order (§3.3), indexed from 0. Levels are built pairwise,
left-to-right; **an unpaired final node is promoted unchanged to the
next level**, which yields RFC 6962 §2.1's `MTH` at every tree size.
The root of a single-leaf tree is that leaf's hash, and the root of the
empty tree — the Log before its first Entry, tree size 0 — is
`SHA-256("")`, as RFC 6962 §2.1 defines:
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Every tree size, the empty one included, is exactly RFC 6962's, so an
existing RFC 6962 or C2SP implementation verifies this Log unmodified.

An Inclusion Proof for the Entry at leaf index *i* in the tree of size
*n* is `{"index": i, "tree_size": n, "path": [<hex sibling hash>, ...]}`:
`index` is the leaf index in the Log, never the Entry's position in its
Block, and `tree_size` is the size a Checkpoint states. Sibling **sides
are not carried in the proof**: they are derived from `index` and
`tree_size`, exactly as in RFC 6962, so that a proof authenticates the
Entry's *position* as well as its membership.

Verification MUST reconstruct the audit path exactly as RFC 6962 §2.1.1
defines it (the `PATH(m, D[n])` function, with `tree_size` as the tree
size *n* and `index` as *m*), applying the leaf and node hashing above.
Concretely: start with `h = leaf(JCS(entry))` and walk from leaf to
root, tracking the current node's own index within its level, `fn`
(initially `index`), and the index of the last node at that level, `sn`
(initially `tree_size - 1`). While `sn > 0`:

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
`h` equals the root hash the Checkpoint states.

A verifier MUST reject a proof when:

- `index >= tree_size` or `index < 0`;
- the proof's `tree_size` differs from the tree size of the Checkpoint
  it is verified against, so that a forged tree size cannot reshape the
  derivation;
- the walk needs a `path` element beyond the ones supplied (it runs out
  of siblings before `sn == 0`), or terminates with `path` elements left
  unconsumed.

Because the sides are derived from `index` and `tree_size` rather than
read from the proof, a proof authenticates the Entry's position as well
as its membership.

A **Consistency Proof** from tree size *m* to tree size *n*, 0 ≤ *m* ≤ *n*,
is RFC 6962 §2.1.2's `PROOF(m, D[n])`. It is verified by reconstructing
the root at *m* and the root at *n* from it as RFC 9162 §2.1.4.2
defines, and accepted iff each equals the root hash the corresponding
Checkpoint states. The proof is empty when *m* = 0 — the empty tree is a
prefix of every tree — and when *m* = *n*, where the two roots MUST be
equal; no proof exists from a larger size to a smaller one. The Log
serves no proof objects: a Consumer holding the tree hashes §6 serves
computes either proof itself, and a proof it receives from another
party is verified the same way.

Inclusion Proofs let a light client verify "this Delta is in the log"
holding only a Checkpoint and the proof: the Checkpoint is authenticated
by the Aggregator's signature and the Cosignatures it carries (§5), and
the proof binds the Entry to the root it states.

## 5. Checkpoints and Anti-Equivocation

After sealing each Block the Aggregator publishes its **Checkpoint**: a
signed note [signed-note] in the C2SP checkpoint format
[tlog-checkpoint], served at the current-head URL and archived per
Block at the paths §6 assigns. Its note text is exactly five lines:

```
<origin>
<tree size>
<root hash>
block_number <block_number>
sealed_at <sealed_at>
```

The first three are the lines [tlog-checkpoint] defines. The origin is
the Log's `log_id` (§3.4) verbatim, which is the schema-less URL form
that format recommends; the tree size is `size(N)`; the root hash is
the root of the tree at that size (§4) in the base64 encoding that
format specifies. The last two are that format's extension lines, which
it leaves opaque and this document fixes: line 4 is the string
`block_number`, one space (U+0020) and the Block's number as an ASCII
decimal with no leading zeroes (`0` for Block 0); line 5 is the string
`sealed_at`, one space and the Block's `sealed_at` in the §3.1 profile.
They are extension lines rather than members of a signed object so that
a checkpoint-format client parses the Checkpoint unchanged and a Witness
cosigns it unchanged; the cosignature formats make no statement about
extension lines [tlog-cosignature], which is why what the Log attests
and what a Witness attests are stated separately below.

A Consumer parses a Checkpoint as [signed-note] and [tlog-checkpoint]
define and then reads the extension lines by the rules above. A
Checkpoint whose note text has more or fewer than five lines, whose
origin is not the Anchor's `log_id`, whose line 4 or 5 differs from the
form above in any octet — a leading zero, a second space, a `sealed_at`
outside the §3.1 profile — or whose text or signature lines do not
parse under those formats is not this Log's Checkpoint: it is rejected
as `WIST3-E03`, and nothing in it is evidence.

**The Log's signature.** A Checkpoint MUST carry at least one signature
line under an Aggregator key valid at height N in the sense §3.4 gives
that phrase, N being the `block_number` line, in the signer form §3.4
defines; it MAY carry more than one, as during a rotation. A Consumer
treats as known exactly the Aggregator keys valid at N and the Witness
keys it trusts, ignores every other signature line as [signed-note]
requires, and MUST reject the Checkpoint (`WIST3-E03`) when a line
naming a known key fails to verify; the number of signature lines it
accepts follows [signed-note]. The signature is checked after the
Blocks up to N are walked, because the keys that can speak for Block N
are the ones the Log establishes at N: the Consumer parses the note,
fetches the Entries below `size(N)` it does not hold (§6), verifies
them against the tree the note states (§3.1) and that tree's
consistency with its verified head (below), applies Block N's Registry
Updates, computes the key set valid at N and verifies the signature
under it. Nothing rests on the order — the Entries establish the key
set only once a signature under that set closes the loop, and a
Checkpoint the loop does not close is applied by nobody. Cosignatures
change none of this: a Checkpoint's identity is its note text, whatever
signature lines it carries, and the Aggregator republishes the same
Checkpoint with each Cosignature it obtains.

The Aggregator MUST NOT publish Checkpoint N before every Entry with a
leaf index below `size(N)` is durably stored and retrievable at its §6
path. A Checkpoint is a permanent signed commitment to one root at one
size: published ahead of Entries the Aggregator can still lose, it is
honored only by serving byte-identical Entries and is otherwise
contradicted by whatever the Log serves next, which is equivocation
against itself. A Consumer holding a Checkpoint whose Entries no source
serves has a `WIST3-E01` it cannot clear, never a `WIST3-E02`: the
Checkpoint is evidence of what the Aggregator committed to, and the
Entries' absence is the Aggregator's to remedy.

- Mirrors MUST retain every Checkpoint they have ever served, with every
  signature line it carried.
- Consumers SHOULD fetch Checkpoints from more than one source — Mirrors,
  and the monitoring endpoint each trusted Witness serves under
  [tlog-witness] — and
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
- A Consumer MUST verify every Checkpoint from its verified head to the
  one it adopts, in `block_number` order: each extends the tree of the
  previous one — a Consistency Proof between the two sizes (§4) — and
  each Block's Entries are the leaves `size(N-1)` through `size(N) - 1`
  of that tree (§3.1). A Checkpoint that fails the Consistency Proof is
  chain divergence (`WIST3-E02`), evidenced below. An Entry not covered
  by a Checkpoint the Consumer has verified MUST NOT be applied.
- A Consumer MUST reject a Checkpoint whose `block_number` is lower than
  the highest it has already verified (rollback protection): it keeps
  its verified head, adopts nothing from the offered Checkpoint and
  fetches the head from another source. The rejection has no error
  code and the Checkpoint is not evidence, because the Log signs a
  Checkpoint at every Block and a source serving an old one has shown
  only that it is behind. A Checkpoint whose `block_number` the
  Consumer has already verified, the head's or a lower one it retains,
  MUST have note text identical to the verified one, or the two
  equivocate (below).
- A Consumer SHOULD treat the log as stale, and SHOULD warn, when
  `sealed_at` of the newest Checkpoint it can accept lags the current
  time by more than three times the sealing cadence (§3.2); empty Blocks
  make this signal reliable.

**Witnesses.** A Checkpoint MAY carry Cosignatures: signature lines a
Witness adds under [tlog-cosignature] after verifying, through
[tlog-witness], that the Checkpoint is consistent with every Checkpoint
of this origin it cosigned before. A Cosignature attests the first three
lines of the note and nothing about the extension lines
[tlog-cosignature]; what it adds is that the tree the Aggregator signed
is the one the Witness saw, so a Consumer holding a cosigned Checkpoint
knows that no Consumer sharing that Witness was served a different tree
at that size. Which Witnesses a Consumer trusts is its configuration —
the tuples of Witness name, public key and cosignature version
[tlog-cosignature] describes, obtained as the Anchor is (§3.4) — and how
many it requires is the Parameter Registry's `checkpoint_witness_quorum`
(WIST-4 §5; default 0), read as in force at the Checkpoint's
`sealed_at`: a Consumer MUST NOT act on a Checkpoint carrying verified
Cosignatures from fewer than that many distinct trusted Witness names.
A Checkpoint short of the quorum is neither evidence nor an error: the
Consumer keeps its verified head and retries, and the staleness rule
above applies while it stays short. The quorum applies to the
Checkpoint a Consumer adopts as its head; the Checkpoints between its
previous head and that one are verified by the Log's signature and by
recomputation against the head's tree (above), which the head's
Cosignatures cover. The Aggregator submits each Checkpoint to the
Witnesses it uses through [tlog-witness]'s `add-checkpoint` call and
republishes it with the Cosignatures returned; which Witnesses it uses
is its choice and no Consumer's trust source, for the reason the Mirror
list is not (above).

While `checkpoint_witness_quorum` is 0 — the value this edition starts
at, before any Witness cosigns the Log — a Consumer that accepts a
Checkpoint carrying no Cosignature from a Witness it trusts MUST record
that acceptance as unwitnessed with the Checkpoint it retains and
SHOULD report it as it reports a stale Log. The interim is stated here
rather than left implicit because an unwitnessed Checkpoint is exactly
the split view the quorum exists to exclude.

**Equivocation** is two Checkpoints of one Log, each validly signed
under an Aggregator key valid at the height its `block_number` line
states (§3.4), that state the same tree size and different root
hashes, or the same `block_number` and a different tree size, root hash
or `sealed_at`. The first form is the one [tlog-checkpoint] forbids a
log to sign and a Witness refuses to cosign; the second is this suite's
own, because a Block's bounds and instant decide capacity, application
order and every day count (§3), and two partitions of one tree are two
states. The evidence bundle is exactly those two Checkpoint files —
self-contained, portable, verifiable by anyone with the Anchor and the
Log's key acts. A third form needs more: two Checkpoints of different
sizes between which no Consistency Proof exists — the smaller's root is
not the root of the larger tree's prefix at that size, a tree size
below the previous Checkpoint's included — where the evidence is both
Checkpoints and the tree hashes (§6) that reproduce the larger root,
from which anyone recomputes the prefix root the smaller contradicts.
A party holding a bundle SHOULD publish it widely; consumers verifying
it MUST stop applying new data from that Aggregator (§9, `WIST3-E02`).
Checkpoints signed by *any* key valid at their `block_number` count; an
Aggregator cannot escape an equivocation proof by removing the signing
key afterward (§3.4).

**Detection is in-band; dissemination is partly so.** The proof is two
small signed files anyone can verify, and "publish it widely" still
names no venue. What a Witness quorum adds is prevention rather than a
channel: a Witness cosigns nothing inconsistent with what it cosigned
before, so a split view reaches a Consumer applying the quorum only if
that many trusted Witnesses saw it — which is why a quorum of one
operator's Witnesses is not a quorum, and why the roster is the
Consumer's. Two limits remain. Below the quorum, and for every
Checkpoint accepted unwitnessed, an Aggregator that partitions its
audiences perfectly — distinct Checkpoints to distinct populations that
never compare notes — is caught only when a bundle crosses the
partition, which multi-source fetching (above) makes likely but nothing
here makes certain. And the remedy runs on evidence, not plumbing: a
proof, however it traveled, justifies the fork/succession path (§3.4)
everywhere it lands.

## 6. Static Layout

The log is distributed as static files. Transport is out of scope: any
HTTP server, CDN, torrent, or IPFS gateway works, because every file
except `/checkpoint` and `/snapshots/index.json` is immutable and
integrity is verified by hash, signature, or commitment, never by source.

The paths below are rooted at the Log's **Service Origin**,
`https://<log_id>/` (§3.4) — which is how a party holding a Log Anchor
needs no second discovery channel: the Anchor's `log_id` names the host,
and everything else is a path. The Service Origin is also the tiled-log
*prefix* of [tlog-tiles], so that the Checkpoint's origin line,
`<log_id>`, is the scheme-less prefix that format recommends and a
client of that format reads the Log from the Anchor alone: the head
Checkpoint at `/checkpoint`, the tree's hashes at
`/tile/<L>/<N>[.p/<W>]` and its Entries at `/tile/entries/<N>[.p/<W>]`,
each exactly as [tlog-tiles] defines the path, the content and the
`Content-Type`. The suite's own files sit under `/log/`, `/payloads/`
and `/snapshots/`. Mirrors re-serve the same paths at their
own origins. Two endpoints are dynamic and exist only at the Service
Origin, never on a Mirror: the Ingest Endpoint `POST
https://<log_id>/ingest` (WIST-2 §4) and the status endpoint `GET
https://<log_id>/status/<domain>` (WIST-2 §7.1).
Payload files are immutable in the same sense — their bytes never change —
but they are the one class of file that may cease to be served, under §6.2.

```
/checkpoint                             (mutable, small, signed note; the current head — §5, [tlog-tiles])
/tile/0/000                             (immutable; a full level-0 tile: 256 leaf hashes — [tlog-tiles])
/tile/0/001.p/44                        (a partial tile, here for tree size 300; deletable once the full tile exists)
/tile/1/000.p/1
/tile/entries/000                       (immutable; an entry bundle: the leaf data of 256 Entries — [tlog-tiles])
/tile/entries/001.p/44
/log/anchor.json                        (immutable, signed; a copy of the §3.4 trust root)
/log/checkpoints/000000000              (note text immutable; every Checkpoint published, zero-padded 9-digit block number — §5)
/log/checkpoints/000000001
...
/log/suffix-lists/7d33b504….dat         (immutable; a pinned Public Suffix List snapshot, WIST-4 §3.1)
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

**Checkpoints.** `/checkpoint` is the head Checkpoint, served with
`Content-Type: text/plain; charset=utf-8` and headers that prevent
caching beyond a few seconds [tlog-tiles].
`/log/checkpoints/<block_number>`, the number zero-padded to nine
digits, is the archive: Checkpoint N as a signed note, served with the
same `Content-Type`, carrying every signature line the Aggregator has
obtained for it. The Aggregator MAY rewrite an archive file to add
Cosignatures (§5) and MUST NOT alter its note text. A file at that path
whose `block_number` line is not the path's number is `WIST3-E03`.

**Tiles and entry bundles.** The tree is served as [tlog-tiles] tiles —
256 hashes of 32 octets per full tile, a partial tile of the width the
tree size requires at its right edge — and the Entries as that format's
entry bundles: each leaf's data, the JCS serialization of the Entry
(§4), prefixed by its length as a big-endian uint16, so that each entry
hashes to the corresponding hash of the level-0 tile. Both are octets
the tree fixes, byte-identical at every source, and compressed, if at
all, at the HTTP layer as [tlog-tiles] provides. A Consumer verifies a
tile or bundle only by recomputation against the root a verified
Checkpoint states (§3.1, §4); one that does not reproduce it is
`WIST3-E03`. The Log serves no proof objects (§4). The Aggregator MUST
serve, for the tree size its head Checkpoint states, the partial tiles
and the partial entry bundle that size requires, and MAY delete a
partial tile or bundle once the full one exists [tlog-tiles]; a
Consumer MUST NOT fetch a partial tile or bundle without a verified
Checkpoint whose size requires it, and falls back to the full one
[tlog-tiles].

**Block size.** The size of Block N is the number of octets its Entries
occupy in entry bundles: the sum, over Block N's Entries, of the length
of each JCS serialization plus two. It MUST NOT exceed the applicable
`block_decompressed_cap_bytes` (WIST-4 §5; Registry default 256 MiB):
the Aggregator seals under the caps that section names, and a Consumer
MUST reject a Block that exceeds them (`WIST3-E03`). The cap counts
octets after any HTTP content-coding is removed, which is the sense in
which the identifier says *decompressed*, and it bounds what a Consumer
fetches to apply a Block: the Block's own octets, the remainder of the
at most two bundles it shares with its neighbours — each bundle at most
256 leaves of 65 537 octets (§3.3) — and 32 octets of level-0 tile per
leaf with the tiles above them. Before fetching a Block, a Consumer
derives a transport bound from its already verified prefix: the greatest
`block_decompressed_cap_bytes` in the map at that prefix's last
`sealed_at` and at every accepted future `effective_at`. With no verified
Block, use the Registry default. Accepted pending amendments participate;
rejected candidates and the Block being fetched do not. This bound also
covers historical Block fetches because each accepted cap covers the
entire sealed prefix (WIST-4 §5). A Consumer restoring from a Snapshot uses
its authenticated parameter tuples, including pending amendments (§7),
and its manifest's Block `block_number` as its prefix. This
bootstrap bound cannot be raised by unauthenticated state. The size
guarantee itself still requires the reconstruction WIST-4 §5 specifies.

A Consumer MUST stop reading a response before buffering bytes beyond
the limit (§10) when a tile exceeds 8 192 octets, an entry bundle
exceeds 16 777 472 octets — 256 leaves of 65 537 — or the entries
attributable to the Block being fetched, those whose leaf indexes lie
in its range, exceed the transport bound. These failures are
`WIST3-E03`. Equality with a bound is permitted. A Mirror's claim or
the local wall clock MUST NOT raise a bound.

After authentication, replay the Block's parameter candidates and check
its size against WIST-4 §5's current and prospective bounds before
applying it. The transport bound alone does
not authorize use of a scheduled increase before its effective instant,
and cannot excuse exceeding an already accepted pending reduction.

Every file is verified rather than trusted, and §12's Mirror obligation
is to serve octets that verify: a tile or bundle by recomputation
against the Checkpoint's root, a Checkpoint by its signature lines
(§5), a signed object by its signature, a Payload by its commitment
(§6.1). Only the Snapshot tier files carry no verification of their
own: a signed manifest hashes their octets directly (§7), so those a
Mirror MUST serve unchanged.

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

**Retention.** The Log is never pruned: its minimum index under
[tlog-tiles] is 0, and the Aggregator MUST keep every entry bundle and
every full tile from genesis retrievable at its path. Replay from the Log Anchor is what
makes key validity (§3.4), the parameter schedule (WIST-4 §5) and
historical signature verification recomputable, so a Log missing an Entry in the middle is a Log
no party can verify from the Anchor at all. The Aggregator MUST likewise
retain every Checkpoint it has published, at
`/log/checkpoints/<block_number>` (above): `/checkpoint` names the
current head and is overwritten, so without the archive an equivocation
proof (§5) would rest on whoever happened to have kept the superseded
copy, and a Consumer, which verifies every Checkpoint between its head
and the one it adopts (§5), would have nothing to verify.

A Mirror **serves Block N** when it serves Checkpoint N and every entry
bundle and tile whose leaf range meets Block N's. A Mirror that serves
a Block MUST retain it for at least the Mirror
retention floor (Parameter Registry: `mirror_retention_days`; default 90
days), measured from its first service of that Block with the value in
force at that instant, and while it serves the Log's head it serves the
partial tiles and bundle that head requires (above). Later amendments
do not shorten that obligation.
This lets an evidence bundle be assembled after the fact rather
than only while an operator finds it convenient. §5's obligation on
Checkpoints is stricter and this floor does not relax it: a Mirror retains
every Checkpoint it has ever served, without expiry, because Checkpoints
are the equivocation evidence itself and are small enough that no retention
argument applies to them.

**Suffix-list files.** Every Public Suffix List snapshot a sealed
`suffix_list_update` names is served at `/log/suffix-lists/<hex>.dat`,
where `<hex>` is the identifier's 64-character digest (WIST-4 §3.1), as
the exact octets that hash to it, from the Block that seals the act and
without expiry; a Mirror that serves a Block MUST serve the snapshot in
force at it and every snapshot an act in that Block names, and retains
them as it retains Checkpoints, without expiry. A file whose octets do
not hash to its name is `WIST3-E03`, and one no source holds is
`WIST3-E01`: the Consumer cannot check the per-domain capacity of any
Block that snapshot governs until it obtains the file.

**Sizing.** The Log's permanent volume is the Entries it seals —
Declarations, governance acts, Deltas, Labels and disputes — plus the
tiles above them, under 33 octets per leaf across every level, and one
Checkpoint per Block. An idle Log accrues one
Checkpoint per cadence and nothing else, so storage growth is a function
of what Publishers and Labelers publish and of the cadence alone.

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
this suite it conforms to (WIST-1 §3.1); WIST-1 §7 defines complete Payload
field/version validation and diagnostic precedence. `salt` is the base64url encoding,
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

Payloads are fetched in the same synchronisation pass as entry bundles,
from the same static file servers, by the same unauthenticated GETs. They
are **not** covered by the tree: no leaf hash, root or Inclusion Proof
depends on them, which is exactly why the tree is untouched when a
Payload is withdrawn.

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

**Availability window.** An Aggregator and any Mirror serving a Block (§6) MUST
serve that Block's Payloads for at least the payload availability window
(Parameter Registry; default 180 days), except for Payloads withdrawn
under §6.2, and MUST NOT serve Checkpoint N before every Payload Block
N's content-bearing Deltas commit to, less those withdrawn, is
retrievable at its path: Payloads replicate first, then the Entries,
then the Checkpoint, extending the order §5 fixes between the Entries
and their Checkpoint, so a Payload is never
absent at a Mirror merely because replication has not reached it. A
Payload that is absent without a withdrawal entry is a
`WIST3-E05` fault against that Mirror; this is what distinguishes a lawful
withdrawal from a Mirror quietly dropping content it dislikes.

After the window elapses, retention is at each Mirror's discretion, and a
Consumer MUST NOT read absence as misbehavior. The window is therefore a
detection window rather than an archival promise: it is set long enough
that a Payload's absence inside it is evidence, and every duty that
depends on content — a Consumer's materialization above all — falls well
within it.

**Anchor Payloads.** One class of Payload outlives the window at the
Aggregator. Two separate rules govern it — which Payload a chain resolves to,
and how long that Payload must be served — and they are stated separately
because they end at different times and for different reasons.

*Resolution.* A URL's **anchor Payload as of a Delta *d*** is the Payload
of the last content-bearing Delta at or before *d* in that URL's per-URL
chain (WIST-1 §3.5). Where *d* is an `attest` or a `delete`, the anchor
as of it is the content the chain still stands on or has just ended.
The rule is relative to a named *d* rather than to the present, so a
statement about the chain at *d* never changes meaning when a later
`update` is sealed. Resolution never expires — the chain is in the Log —
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
window serves is verification: a Consumer materializing at a height
inside it still finds the content the chain stood on, and a superseded
Payload stays checkable against its commitment for as long as it can be
fetched.

Resolution outliving serving is not a contradiction but the ordinary case:
a Consumer that can name the anchor but cannot fetch it materializes no
content for the URL (above), which is exactly how the suite records
"there was a thing to show and it is no longer available".

Holding current anchors costs the Aggregator nothing it was not already
holding — they are exactly the content Tier 1 materializes (§7) — and it
means a Publisher cannot make its own freshness claims unverifiable by
dropping its copy: the Aggregator's copy is independent, and the
commitment makes the two interchangeable.

### 6.2. Withdrawal

A Payload is removed from distribution by a `payload_withdrawal` Registry
Update (WIST-4 §5.1), signed by the Aggregator, whose `subject` is the
Publisher's domain and whose `details` name the `delta_id`, the
`legal_basis` under which the content is being erased, and the
`jurisdiction` of the party demanding it. A request covering several
Deltas is recorded as one entry per Delta, so that each withdrawal names
exactly what it removed and can be checked on its own.

A withdrawal takes effect at the height of the Block that seals it, for a
Delta sealed in that same Block included: the Delta applies (§3.3) and
moves its chain tip, and its content is never materialized. From that
height:

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
- every party holding the Payload for protocol purposes MUST destroy it,
  its salt, and anything it retained of the content it carried.

What withdrawal does not touch is the record. The Delta stays sealed, its
commitment stays in the Log, its inclusion proofs keep verifying, and
every Label ever sealed about it remains.
Withdrawal removes content from distribution; it cannot remove history,
and it cannot recall copies already served.

**After a withdrawal the Log retains no unsalted digest of the withdrawn
content.** That is a property of the object formats, not an aspiration:
the Delta commits to its content under the Payload salt (WIST-1 §3.6), and
destroying the salt makes the commitment unlinkable. The rule is general and binds any
object a later revision adds: **a content-derived value in this suite is
committed under the Payload salt or it is not carried at all.** No object,
and no `details` of any Registry Update, may carry a bare digest of
Payload content.

What remains in the Log and is derived from the withdrawn content is the
Delta's `payload.bytes` length and any Label a Labeler sealed about the
URL. Neither is a digest: `bytes` corroborates a length that unboundedly
many texts share, and a Label is a registry name and an integer. What
stands between a party holding a copy and a confirmation is the destroy
obligation above — a duty on a named holder, not a property of the
format, and this specification does not present it as one (WIST-1 §9,
WIST-4 §9).

The due process is notice in the Log, a named basis, a public and
permanent record. An
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
Entries of the Log the withdrawal was sealed in: an Aggregator and its
Mirrors. A second, independent
Log that sealed the same Publisher's Deltas — nothing forbids one, and
WIST-2's publication surface is one site serving whomever pulls — is
unreached by it, and a Publisher who needs content erased from two Logs
files two withdrawals. Stated once, plainly, because the alternative is
a Publisher discovering it at the worst moment: this suite's erasure
guarantees are per-Log, and every "the Aggregator" and "every Mirror" in
this section quantifies over one Log.

## 7. Snapshots and Tiers

A Snapshot is a derived artifact: the materialized state of the log up to
Block N. Its `manifest.json` (schema:
[`schemas/snapshot-manifest.schema.json`](../schemas/snapshot-manifest.schema.json))
is signed by the Aggregator and declares `snapshot_date`, `block_number`
(= N), `log_position` (= `size(N)`, the tree size Checkpoint N states,
§3), `anchor_block_hash` (the root hash of the tree at `log_position`,
in the `sha256:` form of §3.1), `content_digest`
(below), `state` (the state artifact, below), optionally `shards`
(below), and `files` — one entry per artifact, each carrying its `path`
relative to the manifest, its `sha256`, its `bytes`, the `tier` (`0` or
`1`) it belongs to, and, where the manifest declares `shards`, its
`shard` index. `block_number` is carried because a tree size names no
Block on its own: an empty Block restates the size before it (§3.2),
and the state at two such Blocks can differ by whatever their
`sealed_at` instants settle, expire or bring into force. Throughout
this section "at `log_position`" means at Block N — over the Entries
whose leaf index is below `log_position`, with Block N's `sealed_at` as
the instant — and "above" or "below" `log_position` means above or
below Block N. Every height a Snapshot carries, in this section's
tuples and tables, is a Block number, never a tree size.

- **Tier 0** — summaries of every live record: SQLite (FTS5) + Parquet.
  Sized for any laptop; answers most agent queries alone.
- **Tier 1** — full extracts of live records, the link graph their
  Payloads declare, and the Labels sealed about them, as Parquet.

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
is ranking, and ranking is outside this protocol (WIST-4 §4, ADR-0006,
ADR-0008). That boundary is what makes carrying the graph admissible at
all: ADR-0006 keeps importance out of the protocol, and ADR-0008 records
that a page's own outbound links are a verifiable statement about the
Publisher's content rather than a claim about its own importance, so the
raw edges may be distributed while no rank, weight or aggregate of them
ever is.

**The label table.** `tier1/labels.parquet` carries one row per Label
current at `log_position` from any Labeler the Log sealed: `(labeler,
subject, name, value, asserted_at, expires_at, delta)`, where `value` is
the Label's integer or `NULL` where absent, `expires_at` and `delta` the
Label's members or `NULL`, and a retracted Label or one expired at Block
`log_position`'s `sealed_at` has no row (WIST-2 §3.3). Like the link
graph it is a pure function of the Log — every field is sealed in a
`label` Entry — and transports statements, never a judgement: which
Labelers a Consumer believes is the Consumer's subscription (WIST-4
§6), and no Snapshot builder applies a Label to a record.

**The dispute table.** `tier1/disputes.parquet` carries one row per
current dispute at `log_position`: `(label_id, disputant, reason,
asserted_at)`, `reason` `NULL` where absent (WIST-2 §3.3). A dispute
alters nothing in the label table: the two tables sit beside each
other so that a Consumer weighing a Labeler can read what the labeled
parties answered, and no builder decides between them.

**The labeler table.** `tier1/labelers.parquet` carries one row per
Labeler with any sealed `label` Entry at or below `log_position`:
`(labeler, label_count, retraction_count, distinct_subjects,
first_seen_height)` — every sealed `label` Entry of the Labeler counted,
retractions included, the number of those with `retracted` `true`, the
number of distinct `subject` values across them, and the height of its
first sealed `label` Entry. The table reads no Label's `name` or
`value` and applies no Label: it is arithmetic over Entry counts a
Consumer could redo from the Log, materialized so that a subscription
decision can start from how a Labeler behaves rather than from
nothing. The table is tier-1 data, not state: no tuple carries its
counts, a Consumer resumed from a Snapshot MAY read it for the figures
at `log_position`, and one that does not holds counts only for the
Entries it walked and MUST NOT present them as the Labeler's whole
history.

**The materialized state.** The materialized state is a set of records
keyed by (Publisher domain, Normalized URL). The Publisher domain is the
Delta's signed `publisher`, authenticated under WIST-1 §3.8/§5; it is never
derived from key ownership or the URL host. Rotation, recovery and identity
reset do not reassign these keys or erase their chain tips. Apply chain
validation to this domain before materialization filters; an excluded
record does not transfer its chain to a preferred Publisher. Applying Entries in Log order:
a `new` or `update` Delta replaces the record's content and becomes the
record's **anchor Delta** (§6.1); an `attest` Delta updates the record's
freshness only and leaves the anchor where it was; a `delete` removes the
record's content and moves the chain tip like any other Delta — the key
keeps a tip, the `delete` itself, because a chain never restarts (WIST-1
§3.5) and the URL's next Delta names it as `prev`. A Delta whose `prev`
is not the chain tip the state carries for
its (Publisher domain, Normalized URL) — a fork of an already-materialized
chain (WIST-1 §3.5), or a `prev` that no lower Entry sealed — is ignored
and moves no tip, and so is a sealed Delta that fails a WIST-1 §7 check
at its Block (§3.3); a chain's first Delta is the one that omits `prev` while
the state carries no tip for its key.
Deletion and withdrawal are covered by the rule below. The Log retains every Entry in every case;
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
governs alone — and where the host never declares, more than one scoped
Publisher can hold a live record for the URL, a record no `delete` or
withdrawal above excludes. The record
materialized is then the **nearest ancestor**'s: the Publisher whose domain
is the longest the host descends from, the host being `<label>.D` or a
deeper descendant of that domain `D`. A Publisher that is no ancestor of
the host materializes the URL only while no ancestor holds a live record,
and among such Publishers the least domain in ascending octet order does.
The other records are excluded at that height exactly as a parent's are
under self-declaration, and return when the preferred record leaves.
Every input to the rule — the Declaration Entry, its
height, the scope, the domains — is in the Log, so any two replayers agree; the
parent's excluded Entries remain in the Log like every other superseded
state.

**Materialization rule.** A `delete` Delta (WIST-1 §3.3) excludes that
URL's content from all subsequent Snapshots. A `payload_withdrawal` (§6.2)
likewise excludes that Delta's content from every Snapshot produced at or
above its sealing height, in both tiers, including any declared link
derived from it. The log itself retains full history in every case —
deletion and withdrawal shape the materialized present, never the
recorded past.

Both exclusions are computed from the Log, so two parties building a
Snapshot at the same `log_position` still materialize the same record set.

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
                   "delta_id": r.delta_id, "observed_at": r.observed_at}
record_bytes(r) = JCS(record(r))
content_digest  = "sha256:" + hex(SHA-256(concat(
                      sorted(record_bytes(r) for r in records))))
```

where `records` is every live record materialized at `log_position`;
`r.delta_id` is the record's anchor Delta (§6.1) — the last content-bearing
Delta in its per-URL chain at that height, and therefore the Delta whose
Payload supplied the content the tiers carry; `r.observed_at` is the
`observed_at` of the newest Delta in that chain, which is the freshness the
tiers carry and is what makes an `attest` visible in the digest; and
`sorted` is ascending octet order. Records are keyed by (Publisher domain, Normalized
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
nothing else. Deletion and withdrawal are decided by sealed Entries, and
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
`block_number` and `log_position` and bound to a single tree by
`anchor_block_hash`, the root hash at `log_position`, which §8 checks
against the Checkpoint the Consumer verified. A Consumer that rebuilds to a height whose live set
differs therefore sees a `content_digest` mismatch (`WIST3-E04`) rather than
silent agreement; one that rebuilds to a different height whose live set is
the same agrees, and is right to, since the manifest's `log_position`
already says which height was meant. A manifest from a forked Log shows
an `anchor_block_hash` the Consumer's tree does not produce (`WIST3-E02`),
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
`observed_at`, `title`, `abstract`, `lang` (the record tuple's fields
plus the Payload `summary`'s members, `NULL` where the Payload declares
none), with an FTS5 index over `title` and `abstract` — and
`tier1/extracts.parquet` (`url`, `publisher`, `delta_id`, `extract`),
`tier1/links.parquet`, `tier1/labels.parquet`, `tier1/disputes.parquet`
and `tier1/labelers.parquet` (above). An implementation MAY add columns and
auxiliary tables; a Consumer MUST ignore columns it does not know, and
MUST NOT require any column this paragraph does not name. The layout is
normative for the same reason the digest is: "anyone can rebuild an
equivalent Tier 0" is exercisable only if two rebuilds answer the same
query the same way, and a first implementation's private layout would
otherwise become a de facto standard nothing checks.

**The state artifact.** The record tuples are the index's content; they
are not its law. Key validity, the parameter schedule, withdrawals and
Labels are all defined by replay from genesis, and a Consumer that
starts from a Snapshot instead of genesis needs that state or it cannot
verify the first post-rotation signature, apply a pending amendment, or
hold the Label a Labeler retracts next. The manifest therefore declares `state`: the
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
| `declaration` | domain | the current Declaration Envelope, its sealing height, the highest accepted `seq` | WIST-1 §5 |
| `pending_declaration` | domain | the pending head Envelope, its sealing height, the activation height | WIST-1 §5.2 |
| `parameter` | identifier, `effective_at` | value | WIST-4 §5 |
| `recovery_window` | domain | owner Declaration height, window end, the recovery-chain head Envelope, its sealing height | WIST-1 §5.2 |
| `suffix_list` | snapshot identifier | sealing height of the act that put it in force | WIST-4 §3.1 |
| `withdrawal` | Delta ID | the Publisher's domain, sealing height | §6.2 |
| `label` | labeler, subject, name | value or `null`, `asserted_at`, `expires_at` or `null`, `delta` or `null`, Label ID, sealing height | WIST-2 §3.3 |
| `dispute` | Label ID, disputant | `reason` or `null`, `asserted_at`, sealing height | WIST-2 §3.3 |
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
at or before an instant prevailing (WIST-4 §5). An amendment that another
amendment with the same `effective_at`, sealed later in Log order,
supersedes is never in force and is not state: no tuple exists for it,
which is what keeps the key unambiguous. A `suffix_list` tuple exists
for the one snapshot in force at the first Block above `log_position`
— the most recent accepted `suffix_list_update` sealed at or below it
(WIST-4 §3.1) — and for no earlier one, so that a resuming Consumer
accounts the next Block's capacity under the snapshot a replaying one
reads; no tuple exists while no act has been accepted. A
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
`null`; instants (a window end, a parameter's `effective_at`) are the
whole-second literal-`Z` RFC 3339 strings the sealing Blocks and the
Entries they seal carry (WIST-4 §3); a Label's `asserted_at` is the
Publisher timestamp its Entry carries (WIST-2 §3.3); domains, URLs,
`key_id`s, names and parameter identifiers are the strings the sealed
Entries carry; keys are raw base64url public keys; IDs and snapshot
identifiers are `sha256:`-prefixed. Five kinds need more than that:
`declaration`'s value members are the current Declaration Envelope as
sealed, verbatim as one JSON object member, then its sealing height, then
the highest accepted `seq` — WIST-1 §5.2's sequence floor, which a
settlement that restores a lower-sequence head leaves above the current
`seq`; `recovery_window`'s are the owner Declaration's sealing height, the
window end, then the recovery-chain head's Declaration Envelope verbatim
and its sealing height — the owner itself until a legitimate follower
advances the head (WIST-1 §5.2), carried in full because a resuming
Consumer verifies later followers against the head's Key Set and holds no
Block to fetch it from; `pending_declaration`'s are the pending head's
Declaration Envelope verbatim, its sealing height and the activation
height frozen at the first pending Declaration (WIST-1 §5.2), carried in
full for the same reason, and present only while a pending head exists;
a `label` tuple exists for each (labeler,
subject, name) whose current Label at `log_position` is not retracted
and not expired at Block `log_position`'s `sealed_at` (WIST-2 §3.3),
carrying that Label's value or `null`, its `asserted_at`, its
`expires_at` or `null`, its `delta` or `null`, its Label ID and its
sealing height, so that a resuming Consumer orders a later Label of the
same triple, drops the Label at its expiry, reads its binding and
checks a later dispute naming the Label (WIST-2 §3.3) exactly as a
replaying one does; a `dispute` tuple exists for each (Label ID, disputant) with
a sealed dispute, carrying the current dispute's `reason` or `null`, its
`asserted_at` and its sealing height; a `withdrawal` tuple
exists for every withdrawn Delta, since a Consumer resuming above the
withdrawal's Block never sees its Entry and must still exclude the
content (§6.2) — and, since no tuple names the Deltas sealed at or
below `log_position`, a resuming Consumer accepts a later act naming
one of them as consistent and checks WIST-4 §5.1's contract only for
an act naming a Delta it walked. The schema pins each kind's arity and member types
([`schemas/snapshot-state.schema.json`](../schemas/snapshot-state.schema.json));
the table remains the normative inventory, and a state file omitting a
kind with live instances at `log_position`, or carrying one this table
does not name, does not verify.

Sharding applies to this artifact as to the tiers: when the manifest
declares `shards`, the state file MAY be split on the same
Publisher-domain rule, one part per shard for the domain-keyed kinds
(`declaration`, `pending_declaration`, `recovery_window`, `record`,
`withdrawal` by the withdrawn Delta's Publisher, `label` by its Labeler, `dispute` by its
disputant), with the Log-wide
kinds (`aggregator_key`, `parameter`, `suffix_list`) carried in every
part, since no Consumer can validate an Entry without them.
The tuple set is a set: a Log-wide tuple appears exactly once in the
digest preimage, however many parts carry a copy.
`state_digest` remains the digest over the whole tuple set: a partial
Consumer verifies its parts against the per-shard digests and, as
above, treats its coverage as partial.

## 8. Cold Start and Continuous Operation

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
4. Load the state artifact (§7): verify its signature and its
   `log_position`, and adopt its tuples as the protocol state at Block
   `block_number` — key registries, Declarations, parameters, the
   Public Suffix List snapshot in force (whose octets the Consumer
   fetches from `/log/suffix-lists/` and verifies by their identifier
   before it checks the next Block's per-domain capacity, WIST-4
   §3.1), withdrawals, Labels, chain tips. Every Entry applied below
   is validated against this state exactly as a replaying Consumer
   validates against state it derived itself: a signature under a key
   the state does not admit, a Delta whose `prev` is not the chain tip
   the state carries, a Label older than the one the state holds for its
   triple, all fail as they would on full replay. A `recovery_window` tuple makes its head an
   eligible predecessor beside the current Declaration, and the Consumer
   settles it before applying the first Block at or after its end exactly
   as WIST-1 §5.2 directs: the head becomes current and the `declaration`
   tuple's sequence floor stays. A `pending_declaration` tuple makes its
   head an eligible predecessor beside the current Declaration, supplies
   no Delta authority, and activates or is reversed at the heights
   WIST-1 §5.2 fixes.
5. Fetch `/log/checkpoints/<block_number>` (§6) and verify it as §5
   requires under the `aggregator_key` tuples just loaded; verify that
   it states tree size `log_position` and the root hash
   `anchor_block_hash` carries (§3.1). A mismatch is chain divergence
   (`WIST3-E02`), not a corrupt file: it means the Snapshot describes a
   different tree from the one the Log signs. This Checkpoint is the
   Consumer's verified head.
6. Fetch `/checkpoint` (SHOULD: from ≥ 2 sources, the monitoring
   endpoint of each trusted Witness among them, §5) and every archived
   Checkpoint between the head and it. A Checkpoint, tile or entry
   bundle a source does not hold is `WIST3-E01`: fetch it from another,
   since integrity never depends on the source.
7. Verify each Checkpoint above the head, in `block_number` order, as
   §5 requires: parse it; fetch the entry bundles covering its Block's
   leaves and the tiles the two proofs need (§6); verify the Consistency
   Proof from the previous Checkpoint's tree size and the Block's leaves
   against its root (§3.1, §4); apply the Block's Registry Updates; then
   verify the Log's signature under the key set valid at its height.
8. Choose the Checkpoint to adopt: the newest verified one, the head of
   step 5 included, carrying the Witness quorum §5 requires, recorded as
   unwitnessed where §5's interim applies. Entries above its tree size
   are not applied. If none carries the quorum the Consumer has no state
   to act on and retries (§5).
9. Fetch `/payloads/<delta-id-hex>.json` for every content-bearing Delta
   in the Blocks up to it whose Payload has not been withdrawn (§6.2);
   verify each against its Delta's commitment and `bytes` (§6.1).
10. Apply Entries in order to the local index, Block by Block,
    materializing content only from Payloads that verified.

A Consumer that also replays the Log from genesis MAY recompute the
Snapshot's `content_digest` and `state_digest` (§7) and compare them with
the manifest's. Doing so needs no Payload and no tier file, so it is
available to any party holding the Entries — including one checking an
Aggregator it does not otherwise sync from — and it is what keeps the
state artifact an assertion anyone can falsify rather than testimony a
cold-starting Consumer must take on trust.

**Continuous operation:**

1. Fetch `/checkpoint` (SHOULD: from ≥ 2 sources, §5). A Checkpoint whose
   `block_number` is lower than the highest already verified MUST be
   rejected (§5's rollback rule) before any tile or bundle is fetched
   against it, and the Consumer SHOULD warn if the newest Checkpoint's
   `sealed_at` lags the current time by more than three sealing cadences
   (§5) — a stale head and a rolled-back head are the two ways a Mirror
   can leave a Consumer verifying correctly against the wrong end of the
   tree.
2. Fetch the archived Checkpoints between the verified head and it, and
   verify each as cold start's step 7 does.
3. Choose the Checkpoint to adopt as cold start's step 8 does; short of
   the quorum, keep the verified head and retry (§5).
4. Fetch and verify the corresponding Payloads (§6.1).
5. Apply.

Payload fetching never gates tree verification: a Consumer that cannot
obtain some Payloads still verifies, applies, and advances over the
Blocks, and simply materializes no content for the affected Deltas. Tree
integrity and content availability are separate failures, and only the
first is ever a reason to stop.

**Catch-up decision.** A Consumer offline for a long period compares the
Block distance from its position to the newest Checkpoint against the
distance covered by the newest Snapshot, and chooses whichever costs less
to process. Both paths converge to identical state — the record tuples by
`content_digest`, the protocol state by `state_digest`, each recomputable
from the Entries alone (§7) — so the choice is purely economic. Without
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
A Label likewise has one identity in every Log that sealed it (WIST-2
§3.3) and deduplicates the same way. What does not merge is everything a
Log derives rather than transports. Which Deltas and Labels an Aggregator
ingested, its parameter schedule (WIST-4 §5), its quota accounting and
the reach of a withdrawal (§6.2) are state of one Log, defined by replay
of that Log's history. A Consumer
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
| WIST3-E01 | A Checkpoint, tile, entry bundle or Public Suffix List snapshot missing at a source (§5, §6). Fetch it from another — a Mirror, the Aggregator or, for a head Checkpoint, a trusted Witness's monitoring endpoint; integrity never depends on the source. A Consumer holding a Checkpoint whose Entries no source serves keeps this code and applies nothing above its verified head (§5). |
| WIST3-E02 | Chain divergence: a Consistency Proof that fails between two Checkpoints of the Log, two Checkpoints that equivocate under §5, or a Snapshot manifest whose `log_position` or `anchor_block_hash` is not what Checkpoint `block_number` states (§7, §8). Hard failure: preserve the Checkpoints — and, for a failed Consistency Proof, the tiles that reproduce the larger root — as an evidence bundle (§5), MUST NOT apply the data. |
| WIST3-E03 | Invalid object: a Checkpoint that fails §5's parsing or signature rules or sits at an archive path not its own (§6); a tile or entry bundle over its format size or not reproducing the tree its Checkpoint states (§3.1, §6); a Block over the size cap (§6, WIST-4 §5) or carrying an Entry over 65 535 octets (§3.3); a suffix-list file whose octets do not hash to its name (§6); or a Payload that does not reproduce its Delta's commitment (WIST-1 §3.6, `WIST1-E10`). Re-download, from another source if needed, before concluding misbehavior; a Block the Aggregator sealed over a bound is misbehavior no source repairs. |
| WIST3-E04 | Snapshot manifest mismatch. Three cases, one code, different responses. A file hash or byte size that disagrees with the manifest, or a manifest that disagrees with the `/snapshots/index.json` entry that pointed to it (§8): reject the entire Snapshot and re-fetch, from another Mirror if needed. A `content_digest`, `state_digest` or per-shard digest (§7) that disagrees with the Consumer's own rebuild at `log_position`: not a transport fault and not fixable by re-downloading — the Consumer MUST NOT treat that Snapshot as authoritative, MUST fall back to materializing from the Log and the Payloads, and SHOULD publish both digests with the `log_position`, since a Snapshot that does not match the Log is a claim the Aggregator cannot support and anyone replaying the Log can check the report. |
| WIST3-E05 | Payload absent from a Mirror inside the availability window with no `payload_withdrawal` sealed for it (§6.1, §6.2). A fault against that Mirror, never against the Delta: fetch the Payload from another Mirror or from the Publisher (WIST-2 §3.1), and keep applying the Log. A Consumer that sees `WIST3-E05` from every source it tries SHOULD publish that fact, because a Payload absent everywhere with no logged basis is the signature of suppression rather than of erasure. |

A Checkpoint short of the Witness quorum has no code: §5 makes it a
wait, not a fault — the Consumer keeps its verified head, retries and
reports staleness as §5 directs — and an implementation MUST NOT report
it under `WIST3-E02` or `WIST3-E03`.

A Checkpoint below the verified head has no code either: §5's rollback
rule rejects it as a stale source, and an implementation MUST NOT
report it under `WIST3-E02` or `WIST3-E03` unless its note text differs
from the Checkpoint the Consumer verified at that `block_number`, which
is equivocation (`WIST3-E02`).

## 10. Security Considerations

- **Equivocation** is the Aggregator's only meaningful attack. §5
  makes it self-incriminating at the cost of two small signed files,
  and a Witness quorum makes it unreachable: a Consumer requiring
  `checkpoint_witness_quorum` Cosignatures adopts a split view only if
  that many of its trusted Witnesses cosigned both sides, which the
  Witness protocol forbids each of them to do. Below the quorum, and at
  the quorum of 0 this edition starts at, the defence is the evidence
  bundle alone (§5).
- **What a Cosignature does not cover.** A Witness attests the origin,
  tree size and root hash and makes no statement about the extension
  lines [tlog-cosignature], so two Checkpoints agreeing on the tree and
  differing in `block_number` or `sealed_at` — §5's second form of
  equivocation, which moves Block bounds and day counts — pass every
  Witness and are caught by the evidence bundle alone. Only the Log's
  own signature binds those lines, which is why it is a [signed-note]
  Ed25519 signature over the whole note text (§3.4) rather than a
  cosignature type. A Witness roster the Log distributed would let the
  Aggregator choose its own auditors, which is why the roster is the
  Consumer's configuration (§5).
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
  is visible as a Delta whose content no party can verify rather than as a Mirror
  fault; WIST-2 §5 closes the honest path by requiring the Aggregator to
  reject such a Delta instead of sealing it.
- **Compression bombs.** The tile and entry-bundle format sizes and the
  verified-prefix transport bound (§6) MUST be enforced while a response
  is read, before buffering bytes beyond the limit and whatever
  content-coding the transport applied.
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
      in `Z`, canonical Entry order, the per-domain Entry capacity, no
      Entry over 65 535 octets, and a Checkpoint stating the tree's true
      size and root)
- [ ] Publishes a Checkpoint per sealed Block at `/checkpoint` and in
      the archive, as the five-line signed note of §5 under a key valid
      at its height, never before every Entry below its tree size is
      durably stored and served (§5, §6)
- [ ] Serves the static layout of §6: the [tlog-tiles] tiles and entry
      bundles at the Service Origin's root, the partial ones its head
      requires, never pruned
- [ ] Submits each Checkpoint to the Witnesses it uses and republishes
      it, at `/checkpoint` and in the archive, with the Cosignatures
      returned and its note text unchanged (§5, §6)
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
- [ ] Materializes one record per URL under §7's one-URL, one-Publisher
      rule: the self-declared host's own, else the nearest ancestor
      Publisher's, else the least non-ancestor domain in octet order
- [ ] Produces Snapshots whose manifests satisfy §7, including the
      materialization rule, the `content_digest`, the state artifact and
      its `state_digest`, per-shard digests where sharded, and a
      `block_number`, `log_position` and `anchor_block_hash` that
      Checkpoint `block_number` states
- [ ] Treats any companion pack it publishes itself as a Snapshot
      artifact for §6.2's withdrawal obligations (§7)
- [ ] Publishes `/snapshots/index.json`, signed, newest first, agreeing
      with each manifest it points to, and removes an entry when it stops
      serving that Snapshot (§6)
- [ ] Retains every entry bundle and full tile from genesis and every
      Checkpoint it has published, the latter at
      `/log/checkpoints/<block_number>` (§6)
- [ ] Serves every Public Suffix List snapshot a sealed
      `suffix_list_update` names at `/log/suffix-lists/<hex>.dat`, from
      the sealing Block and without expiry, and counts the per-domain
      capacity per Registrable Domain under the snapshot in force
      (§3.2, §6, WIST-4 §3.1)
- [ ] Rebuilds a Snapshot superseded by a withdrawal at a `log_position`
      at or above the withdrawal's height, or withdraws it (§6.2, §7)
- [ ] Seals no Block whose size (§6) exceeds the smallest cap WIST-4 §5
      puts in force for it
- [ ] Publishes a Log Anchor and admits all later keys in-band (§3.4)
- [ ] Seals a `publisher_declaration` Entry for a domain before, or in
      the same Block as, the first Delta it authorizes, and never seals a
      Delta the Key Set resolved at its own Block no longer verifies
      (§3.3, WIST-1 §5.2)
- [ ] Seals each pulled Label that verifies as a `label` Entry and each
      dispute as a `dispute` Entry, at most once per ID and within the
      per-Labeler cap, and materializes `tier1/labels.parquet`,
      `tier1/disputes.parquet` and `tier1/labelers.parquet` from the
      Labels and disputes current at `log_position` and every sealed
      `label` Entry (§3.2, §3.3, §7, WIST-2 §3.3)

**Mirror:**

- [ ] Serves tiles, entry bundles and Checkpoints byte-identical to the
      origin's, and signed objects whose canonical bytes reproduce their
      signatures (§6)
- [ ] Serves Snapshot tier files byte-identical to origin, since only the
      manifest's per-file `sha256` authenticates them (§6, §7)
- [ ] Retains every Block it serves — its Checkpoint and the bundles and
      tiles meeting its leaves — for at least `mirror_retention_days`
      (§6)
- [ ] Retains all Checkpoints ever served, with every signature line
      they carried, without expiry (§5, §6)
- [ ] Serves the Public Suffix List snapshots the Blocks it serves read
      and name, without expiry (§6)
- [ ] Serves the Payloads of every Block it serves for at least the
      availability window, never serves a Checkpoint before its Block's
      Payloads, and
      stops serving one only after a `payload_withdrawal` is sealed for
      it (§6.1, §6.2)
- [ ] Stops serving any Snapshot artifact containing withdrawn content,
      on the same terms as the Aggregator (§6.2, §7)

**Consumer:**

- [ ] Applies the tile and entry-bundle format sizes, the transport
      bound and the accepted-schedule size checks (§6); rejects leap
      seconds in Log-comparable timestamps (§3.1, §7)
- [ ] Verifies every Checkpoint between its head and the one it adopts —
      parse, Consistency Proof, the Block's leaves against the root, the
      Log's signature under the keys valid at its height — before
      applying its Block (§5, §8)
- [ ] When verifying an Inclusion Proof, derives sibling sides from
      `index` and `tree_size` rather than trusting side labels in the
      proof, and rejects a shape-mismatched `path`, an `index` out of
      range, or a proof `tree_size` that disagrees with the Checkpoint's
      (§4)
- [ ] Adopts as head only a Checkpoint carrying the Witness quorum in
      force, counted over a roster it configured out-of-band, and records
      an acceptance under quorum 0 as unwitnessed (§5)
- [ ] Rejects Checkpoints older than the highest already verified, before
      fetching tiles or bundles against them (§5, §8)
- [ ] Warns when the newest Checkpoint's `sealed_at` lags the current time
      by more than three sealing cadences (§5, §8)
- [ ] Verifies manifest hashes/sizes before using a Snapshot, checks the
      manifest against the `/snapshots/index.json` entry that named it, and
      binds `block_number`, `log_position` and `anchor_block_hash` to the
      Checkpoint it verified (§8)
- [ ] Verifies every Payload against its Delta's commitment and `bytes`
      before materializing its content, and never lets a missing Payload
      stop chain verification (§6.1, §8)
- [ ] Implements all five Error Registry behaviors, including evidence
      preservation on divergence (§9)
- [ ] Enforces the format sizes and the transport bound while reading
      (§6, §10)
- [ ] Excludes deleted and withdrawn content from every materialization it
      produces, and removes withdrawn content from a local index it has
      already built (§6.2, §7)
- [ ] Obtains the Anchor out-of-band and resolves signing keys by height
      (§3.4)
- [ ] Rejects Blocks off the `sealed_at` grid, out of canonical Entry
      order, over the per-domain Entry capacity counted per
      Registrable Domain under the snapshot in force, obtained and
      verified by its identifier, over the per-Labeler cap, or carrying
      an Entry over 65 535 octets (§3.1–§3.3, §6, WIST-4 §3.1)
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
three `attest` Deltas for `post-2..4`, at leaf indexes 0 through 3 of a
tree of size 4. Their positions follow §3.3's
canonical order — one type group, ascending leaf-hash order — which puts
the WIST-1 vector Delta at leaf 3; the other positions contain the
`attest` Deltas. No Entry’s position is chosen.

**Leaf hashes (hex):**

```
leaf0 = 75c6c8c2cb19db1247c531f326f1eb73f1be9c2f3275cf82792c194b3f259498
leaf1 = 836dc0b3e22bded85b29840c757502128eaae0b1375ee99fe2c78bf794bc1d9a
leaf2 = bea0c768bc2e63130a903adcc65f248d0da56f5ab5bf4abe628a2c2b140007ca
leaf3 = ca3a0886a09c7664edeb1adafaf8542b60dcf12f728d62868a462cf82cf585ef
```

**Interior nodes:**

```
n01 = node(leaf0, leaf1) = 6c77758a2c40c6247022f51bbc43b3bb515ea01c783abd0861b4fe8e43d5d7ff
n23 = node(leaf2, leaf3) = a99ad975eda3a87b3956b765d2333052d0f355836e87c2d5b5976647c492200c
```

**Root hash of the tree at size 4**, as `anchor_block_hash` carries it
(§3.1) and as the Checkpoint's third line carries it (§5):

```
sha256:405940d7902a70ecd62a01c438ec95e5250c0ad580d8b88903358530c120dbbe
QFlA15AqcOzWKgHEOOyV5SUMCtWA2LiJAzWFMMEg274=
```

**Inclusion proof for leaf 0** — `index 0, tree_size 4 → siblings
leaf1 then n23, both right-hand` (derived, not carried in the proof):

```
h = leaf0
h = node(h, leaf1)   → 6c77758a...  (= n01)   # fn=0 < sn=3: sibling on the right
h = node(h, n23)     → 405940d7...  (= root)  # fn=0 < sn=1: sibling on the right  ✓
```

Entry 3's Payload is [`examples/payload.json`](../examples/payload.json),
served at `/payloads/37e4e7246e5bcb20781adf26611128bb3b7b8d9b9ceff02f2630cdb645266860.json`. It contributes to none of the
hashes above: every figure here is computed over Entries that carry the
commitment alone, which is why withdrawing that Payload leaves the leaf,
the root, the Checkpoint, and this proof untouched.

This worked example only exercises `index` 0, which — being a uniform
left-child at every level — cannot by itself distinguish a correct
verifier from one that only handles the uniform-left/uniform-right cases.
`tools/validate_examples.py`'s `merkle-exhaustive` check is the actual
correctness evidence: it verifies every `index` for every tree size 1..64
against a freshly generated audit path.

The vector also fixes the Log's static surface for this tree (§6): the
level-0 partial tile `/tile/0/000.p/4`, the 128 octets `leaf0 || leaf1
|| leaf2 || leaf3`; the entry bundle `/tile/entries/000.p/4`, the four
Entries' JCS serializations each prefixed by its big-endian uint16
length; and the Consistency Proof from size 0 to size 4, which is empty
(§4). Block 1 is empty: Checkpoint 1 restates size 4 and the root above
one cadence later, and the Consistency Proof from 4 to 4 is the
equality of the two roots. The empty tree — the Log before Block 0 —
has size 0 and the root §4 gives.

The corresponding Checkpoint is
[`examples/checkpoint.txt`](../examples/checkpoint.txt): the five-line
note of §5 — the `log_id` of
[`examples/log-anchor.json`](../examples/log-anchor.json), `4`, the
base64 root above, `block_number 0` and `sealed_at
2026-08-02T13:00:00Z` — followed by the Log's signature line under the
example Aggregator key in the signer form §3.4 fixes. The example
manifest ([`examples/snapshot-manifest.json`](../examples/snapshot-manifest.json))
uses synthetic file hashes — the SHA-256 of the literal strings
`tier0-placeholder` / `tier1-placeholder` — so the vector is verifiable
without shipping binary artifacts. Its `block_number` is 0, its
`log_position` 4 and its `anchor_block_hash` the root above.

Its `content_digest` is computed over the two records in
[`vectors/wist3/snapshot-records.json`](../vectors/wist3/snapshot-records.json),
which publishes the record tuples themselves so that §7's formula is
reproducible from the file: one record for the Delta above and one for a
second domain, so that the ordering rule is exercised. That second
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
- [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) Certificate
  Transparency Version 2.0 — consistency proof verification (§4)
- [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html) SCITT
  architecture — vocabulary mapping (§2)
- [signed-note](https://c2sp.org/signed-note@v1.0.0) ·
  [tlog-checkpoint](https://c2sp.org/tlog-checkpoint@v1.0.0) ·
  [tlog-cosignature](https://c2sp.org/tlog-cosignature) ·
  [tlog-witness](https://c2sp.org/tlog-witness) ·
  [tlog-tiles](https://c2sp.org/tlog-tiles) — the C2SP Checkpoint,
  signature, Cosignature, Witness and tiled-log formats (§3.3, §3.4,
  §5, §6)
- WIST-1: Delta Format & Identity · WIST-2: Site Publication ·
  WIST-4: Governance & Parameters
