# ADR-0048: The interval between two Checkpoints is an Epoch, and wire names describe their values

**Status:** draft · **Date:** 2026-09-18

## Context

Since the single-tree Log ([ADR-0046](0046-single-tree-log.md)) the unit
the suite called a Block is no object and has no hash: it is the interval
of the Log between two consecutive Checkpoints (WIST-3 §3). The word named
nothing concrete and carried a blockchain connotation the design rejects
([ADR-0004](0004-log-centric-ct-model.md)). Key-transparency logs — CONIKS,
Google Key Transparency — call the period between two published signed
tree heads an epoch.

Four members misdescribed their values:

- `log_position` is a tree size, not a unique position: an empty interval
  restates the previous size, so sorting Snapshots by it is wrong.
- `anchor_block_hash` and `final_block_hash` carry the tree's root hash;
  the interval has no hash apart from the root, and "anchor" collided with
  the Log Anchor.
- `block_decompressed_cap_bytes` bounds entry-bundle octets in a format
  that compresses nothing.

"Epoch" already appeared in the suite for the origin of Unix time, which
would have left the new term with two meanings.

## Decision

The interval is an **Epoch**, plural Epochs, in every phrase the former
term formed: Epoch N, empty Epoch, sealing Epoch, per-domain Epoch
capacity. **height** remains the synonym for an Epoch's number — height N,
activation height, sealed at a height ≤ N — and wire members and tuple
fields named `height` are unchanged. The former compound "Block height"
becomes "Epoch number".

| Former identifier | Identifier | Carried by |
|---|---|---|
| `block_number` | `epoch_number` | Checkpoint note text (WIST-3 §5), Snapshot manifest, index and state |
| `final_block_number` | `final_epoch_number` | Log Anchor `predecessor` |
| `final_block_hash` | `final_root_hash` | Log Anchor `predecessor` |
| `anchor_block_hash` | `root_hash` | Snapshot manifest |
| `log_position` | `tree_size` | Snapshot manifest, index and state |
| `block_decompressed_cap_bytes` | `epoch_cap_bytes` | Parameter Registry |
| `block_cadence_seconds` | `epoch_cadence_seconds` | Parameter Registry |
| `domain_block_entries_max` | `domain_epoch_entries_max` | Parameter Registry |
| `labeler_block_entries_max` | `labeler_epoch_entries_max` | Parameter Registry |
| `declaration_activation_blocks` | `declaration_activation_epochs` | Parameter Registry |
| `max_inclusion_blocks` | `max_inclusion_epochs` | Parameter Registry |
| `record_seal_blocks` | `record_seal_epochs` | Parameter Registry |

Value forms, defaults, bounds and every rule reading these members are
unchanged. The manifest's `epoch_number`, `tree_size` and `root_hash`
mirror the Checkpoint's lines. Vector files and case names carrying the
former term for the interval are renamed the same way.

Unix time is "Unix seconds" wherever the suite converts a timestamp to an
integer (WIST-3 §3.1), so "epoch" has no second sense.

Names of objects that no longer exist are not re-coined. Where a decision
record recounts a removed design, "Block file", "Block frame", "Block
header", "Block hash" and `prev_block_hash` stay as written, marked as
former names.

## Alternatives considered

- **Keep "Block".** Costs nothing now, and keeps a name for an object the
  suite removed, which every new reader then looks for.
- **"Interval".** Accurate and unclaimed, but it is the common noun every
  definition of the term needs — "the interval between two Checkpoints" —
  and it names no established concept in transparency logs.
- **No noun, only "the checkpoint interval".** ADR-0046 weighed and
  rejected this: every count in the suite — capacity, the inclusion
  ceiling, the recovery window's opening, Snapshot heights — needs a named
  unit.
- **`anchor_root_hash` instead of `root_hash`.** Rejected: the plain name
  mirrors the Checkpoint's root hash line beside `epoch_number` and
  `tree_size`, and the prefix would keep the collision with the Log Anchor.
- **Replace "height" with "Epoch N" everywhere.** Rejected: height is the
  established word for a log's sequence number, and it appears in wire
  members the rename has no reason to touch.

## Consequences

- The Checkpoint note's fourth line changes, so every Checkpoint signature
  changes and every vector carrying one is re-signed. Snapshot manifests,
  indexes, state files and Log Anchors with a `predecessor` change members,
  so their signatures and digests change with them.
- The change is possible only because the draft is undeployed
  (PUBLICATION.md); after deployment it would be a new major version.
- "Epoch" has exactly one meaning in the suite, and Unix time is always
  "Unix seconds".
- `tree_size` no longer reads as an ordering key: Snapshots at distinct
  Epochs can share a tree size, and `epoch_number` distinguishes them
  (WIST-3 §7).
