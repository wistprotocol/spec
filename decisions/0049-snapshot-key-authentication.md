# ADR-0049: A Snapshot carries its key acts, and unsealed Aggregator documents verify at the adopted head

**Status:** draft · **Date:** 2026-09-19

## Context

WIST-3 §3.4 roots a Log's trust in the Anchor's genesis key and admits every
later key by a sealed key act, so a Consumer replaying from the Anchor
computes the key set at every height. A Consumer resuming from a Snapshot
does not replay. §8 had it verify the state file's signature, adopt the
file's `aggregator_key` tuples and verify the Snapshot's Checkpoint under
them. After any rotation the tuples naming the valid keys were thus
authenticated by a signature under one of those keys: a state file, manifest,
index and Checkpoint all signed by one arbitrary key, with a tuple naming that
key, verified against each other, and nothing chained to the Anchor.
Verifying the documents under the genesis key alone is sound and makes every
Snapshot unusable once the genesis key is removed.

§3.4 fixes the authenticating height of Registry Updates and Checkpoints
([ADR-0047](0047-key-act-authentication-height.md)). No text fixed one for
the Aggregator-signed documents that are never sealed: the Snapshot index,
manifest and state file (§6, §7) and `/log/mirrors.json` (§5). The index is
mutable and signed at the head while listing older Snapshots, and the Mirror
list names no height at all.

## Decision

**Key acts travel in the tuples.** An `aggregator_key` tuple carries, after
its heights, the accepted `aggregator_key_add` Envelope that admitted the key
(`null` for the genesis key) and the accepted `aggregator_key_remove`
Envelope that retired it (`null` while it is valid), each verbatim as
sealed. Of two removals of one key accepted in one Epoch, the tuple carries
the one at the lower Entry index. Both members are Log-derived, so
`state_digest` stays recomputable by replay.

**The tuples authenticate from the Anchor.** Before using any tuple, a
Consumer checks that exactly one tuple has no adding act and names the
Anchor's genesis key at added height 0; that every other tuple's acts are
well-formed key acts naming its `key_id` and `public_key`; that heights are
ordered (a removal above its addition, the genesis key's at or above 0, none
above the Snapshot's Epoch); that no two tuples share a note key ID; and
that each act at height *h* verifies under a tuple's key valid at *h* − 1.
A signer valid at *h* − 1 was added below *h*, so by induction on height
every act chains to the genesis key. A failure rejects the Snapshot
(`WIST3-E04`).

**Unsealed documents verify at the adopted head.** The Snapshot index,
manifest and state file, and the Mirror list, verify under a key valid at
the height of the Checkpoint the Consumer adopts: cold start's step 8, or
its adopted head in continuous operation. A cold-starting Consumer therefore
parses the three Snapshot documents, authenticates the key tuples, verifies
the Snapshot's Checkpoint under the tuples' key set at the Snapshot's Epoch,
walks to the Checkpoint it will adopt — key acts above the Snapshot
authenticate under §3.4 from the tuples — and only then checks the three
signatures; until they verify it persists and acts on nothing derived from
the Snapshot. An Aggregator that removes a key re-signs every such document
that key signed and it still serves, under a key valid at the new head. A
Mirror list that does not verify is not an error: its entries remain the
untrusted location hints §6.1 already permits.

## Alternatives and consequences

*Verify under the genesis key alone.* Sound, and ends Snapshot resume at the
genesis key's removal, which §3.4 permits and a compromise can force.

*Resume only after fetching the key acts from the Log by Inclusion Proof.*
The proofs bind the acts to the tree the Snapshot's Checkpoint signs, and
that Checkpoint's signer is the key being authenticated, so the proofs add
fetches and no assurance the carried Envelopes lack. The sealing heights
remain assertions of the state file's signer either way, falsifiable by
replay like every other tuple.

*Re-issue the Anchor with the current key set.* The Anchor is the Log's
content-addressed identity and is obtained out-of-band; re-issuing it turns
every rotation into an out-of-band distribution problem.

*Verify the Snapshot documents under the keys valid at the Snapshot's
Epoch.* A key stays valid at every height below its removal, so a removed
key — removal being the response to compromise — could sign false state for
old Epochs forever and attach it to the genuine tree, genuine Checkpoints
and genuine Cosignatures. A replaying Consumer is not exposed to that: a
removed key can only sign a fork of the tree, which comparison across
sources and the Witness quorum catch. Verifying at the adopted head gives
the removed key nothing once the Consumer reaches a Checkpoint at or above
the removal, and also settles the index, whose signer may be newer than the
Snapshots it lists.

Residual exposure, stated in WIST-3 §10: the holder of a removed key that
also serves a Consumer a head below the removal can still pass a false
Snapshot, where a replaying Consumer would only see old truth; the defences
are §5's staleness warning and heads fetched from more than one source,
Witness monitoring endpoints among them. A holder of a once-valid key can
present tuples omitting its removal, exactly as it can serve a replaying
Consumer a fork from before the removal, with the same defences. A key valid
at the head can assert false state, as before; `state_digest` recomputation
by any replaying party is what falsifies it.

Costs: the state artifact grows by up to two Envelopes per key, and every
Snapshot's `state_digest` changes. Removing a key obliges the Aggregator to
re-sign the state files that key signed, then their manifests (a manifest
hashes the state file's octets), then the index; `content_digest` and
`state_digest` are unaffected. Mirrors holding the old documents are
rejected with `WIST3-E04` until they refresh. No key is valid on both sides
of an Epoch that adds the only replacement and removes the only predecessor,
so documents fail for Consumers on one side of it until re-signed; adding
the replacement at a lower height than the removal avoids the gap. The
signature check moves to the end of cold start, so a hostile source can make
a Consumer walk Epochs before a bad signature is found; a signature naming a
tuple's key that fails under that key can never verify later and may be
rejected at once.
