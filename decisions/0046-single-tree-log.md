# ADR-0046: The Log is one RFC 6962 tree published as C2SP checkpoints and tiles

**Status:** draft · **Date:** 2026-09-17

## Context

WIST-3 seals one Merkle tree per Epoch and chains the Epochs through
the header hash formerly named `prev_block_hash`. Nothing outside this
suite verifies that structure: a
Consumer walks every Epoch backward from a Checkpoint, and §5 records that
the first edition ships no witness layer, so an Aggregator's only check is
that someone holds two contradicting Checkpoints and publishes them.

Every comparable log has converged on a different shape. Certificate
Transparency's static-ct-api, Sigstore's Rekor v2, the Go checksum database
and Pixel binary transparency each publish one growing RFC 6962 tree as
C2SP `tlog-checkpoint` signed notes over `tlog-tiles` static files,
cosigned under `tlog-witness` and `tlog-cosignature` and checked against a
verifier-side `tlog-policy` quorum, with `tlog-mirror` for re-serving.
witness-network.org already cosigns third-party logs, and SCITT (RFC 9943)
gives the surrounding vocabulary. Adopting that shape gives the Log
existing clients, existing witnesses and a split-view defence the suite
currently names as future work; keeping the present shape means writing
and operating all of it alone.

The suite's own guarantees do not depend on the per-Epoch tree. They
depend on: an Entry's position being fixed once published, a Consumer
being able to prove inclusion, an interval of the Log carrying a
`sealed_at` a Consumer can anchor day counts to, the per-domain and
per-Labeler capacity of that interval, the canonical order of the Entries
inside it, and the height a Snapshot is taken at.

## Decision

- **One append-only tree, and an Epoch becomes an interval of it.** The
  Log is a single RFC 6962 tree whose leaves are the suite's Entries in
  append order. An Epoch is redefined as the entries between two
  consecutive checkpoints, identified by the tree size the checkpoint
  states. `epoch_number` becomes the index of that interval, and every
  rule written over an Epoch keeps its meaning over the interval:
  per-domain and per-Labeler capacity (WIST-3 §3.2, WIST-4 §5), the
  inclusion ceiling and the discovery sealing deadline counted in Epochs,
  canonical Entry order within the interval (which now fixes the order
  leaves are appended in), the `sealed_at` grid, Snapshot heights, and
  §3.4's fork and succession path. `prev_block_hash` is replaced by an
  RFC 6962 consistency proof between the two tree sizes, which is the
  same statement — this interval extends that one — proved rather than
  asserted. The empty-tree deviation §4 records disappears with the
  per-Epoch tree: a Log with no Entries is a tree of size zero.
- **Checkpoints are C2SP signed notes.** The checkpoint is a
  `tlog-checkpoint` note with the origin line, the tree size and the root
  hash, signed with Ed25519 under the `signed-note` signature format,
  carrying the interval's `sealed_at` as an extension line so the
  suite's day counts keep their anchor. It is issued at least hourly, so
  an idle Log still produces the heartbeat empty Epochs give today.
  Equivocation becomes two notes for one tree size with different roots,
  and the evidence bundle stays the two files.
- **Tiles are the static layout.** The Log publishes `tlog-tiles`
  paths, and the hourly stream is new entry bundles and the partial tiles
  above them. Snapshots and tier files are unchanged in purpose and
  shape: a materialized index over the Log up to a checkpoint's tree
  size, with `tree_size` reading as that size and `root_hash`
  as the root it anchors to. The manifest states the Epoch number beside
  them, because a tree size names no Epoch on its own: an empty Epoch
  restates the size before it, and the state at two such Epochs differs
  by whatever their instants settle, expire or bring into force.
- **Witness cosignatures, with a quorum the Registry distributes.** A
  checkpoint may carry witness cosignatures under `tlog-witness` and
  `tlog-cosignature`. The verifier-side quorum policy is distributed
  through the Parameter Registry (WIST-4 §5), and once witnesses exist a
  Consumer accepts a checkpoint only with the policy's quorum. Until
  they do, the interim is stated in the specification rather than left
  implicit: a Consumer records that it accepted an unwitnessed
  checkpoint. The project operates the first witness and applies to
  witness-network.org, because a quorum of one operator's witnesses is
  not a quorum.
- **The C2SP surface sits at the origin's root.** `tlog-tiles` recommends
  that the origin line be the schema-less URL prefix the tiles are served
  under, so the checkpoint, the tiles and the entry bundles are served at
  the root of the Log's `log_id` and the origin is that `log_id`. The
  suite's own endpoints keep their existing prefixes; a generic C2SP
  client needs none of them. The Log's own signature on a checkpoint is a
  `signed-note` Ed25519 signature (type `0x01`), which covers the
  extension lines the suite's day counts depend on; the cosignature type
  is the Witnesses'.
- **An Entry fits an entry bundle.** `tlog-tiles` length-prefixes a
  leaf's data with a uint16, so an Entry's serialization is bounded at
  65 535 octets and an Aggregator MUST NOT seal a larger one. The bound
  is the format's, not a policy choice, and no Entry the suite defines
  approaches it.
- **The Witness roster is the Consumer's, the threshold is the Log's
  floor.** Which Witnesses a Consumer trusts is its own configuration,
  obtained as the Log Anchor is, never from the Log: an Aggregator that
  named its own Witnesses would be choosing the parties meant to catch it
  equivocating, which is why the Mirror list is already advisory. The
  Parameter Registry carries the quorum threshold alone, and it is a
  minimum: a Consumer MAY require more Cosignatures, or specific
  Witnesses, under a verifier-side policy of its own.
- **SCITT vocabulary, receipts deferred.** The specification maps its
  terms to RFC 9943's — the Aggregator is the Transparency Service, a
  Publisher the Issuer, the URL an Item is about the Subject, the
  admission rules the Registration Policy, and an inclusion proof
  against a cosigned checkpoint the Receipt — so that a reader arriving
  from SCITT can place the suite. COSE-encoded receipts are optional and
  deferred: nothing in the suite needs them, and adding a second encoding
  of a proof the tiles already serve would be two formats to keep
  agreeing.

## Alternatives considered

- **Keep the per-Epoch trees and add witnesses on top.** A witness would
  have to learn this suite's chaining rule to check that two Checkpoints
  are consistent, which is exactly the work the existing witness network
  will not do; the point of adopting the format is that a witness needs
  to know nothing about WIST.
- **One tree, but keep `prev_block_hash` beside the consistency proof.**
  Two statements of the same fact, one proved and one asserted, with a
  rule needed for the case where they disagree.
- **Make the checkpoint interval the only notion and drop Epochs.** Every
  count in the suite — capacity, the inclusion ceiling, the recovery
  window's opening, Snapshot heights — is written in Epochs, and the
  interval is what an Epoch already is.
- **Adopt COSE receipts now.** They would be a second, independently
  verifiable form of the same proof, and the first disagreement between
  the two encodings is a bug no Consumer can adjudicate.

## Consequences

- WIST-3 is revised throughout, and with it the affected WIST-4
  parameters, the schemas — the per-Epoch file's schema, formerly the Block
  schema, is removed — the examples and
  every Log vector. Existing sealed Logs do not carry forward: the change
  is made before the first deployment, under PUBLICATION.md.
- Every verifying role gains tree, checkpoint, tile and cosignature
  verification; the Aggregator seals into the single tree, publishes
  tiles and submits to witnesses after sealing; the Consumer syncs over
  tiles, checks the quorum and adopts a Snapshot at a checkpoint's tree
  size.
- An existing C2SP client — Tessera or `golang.org/x/mod/sumdb/tlog` —
  reads the published Log, which is the check that the adoption is real
  rather than a paraphrase of the format in this suite's own words.
