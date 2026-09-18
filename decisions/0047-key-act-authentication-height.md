# ADR-0047: Key acts authenticate under the previous height's keys

**Status:** draft · **Date:** 2026-09-18

## Context

WIST-3 §3.4 defined a Log key as valid at height N from its addition at a
height ≤ N until a removal at a height ≤ N, and WIST-4 §5.1 authenticated
every Registry Update under a key "valid at the act's Block". For the two
key acts that definition refers to itself. An `aggregator_key_remove` of a
key, signed by that key, makes its signer invalid at N, so it authenticates
iff it does not. An `aggregator_key_add` signed by a key that a removal in
the same Block retires authenticates or not according to which act an
implementation evaluates first, so two replayers could derive different key
sets from one Log. The text also left "reject" open between the act and the
Block for a repeated `key_id` or note key ID, named no code, gave no
disposition to a removal of a key that is not valid, and did not say whether
a Snapshot's state carries removed keys, which the collision rule and §5's
equivocation rule both read.

## Decision

A key act sealed in Block N is authenticated under the keys valid at height
N−1, the genesis key alone for Block 0. Every other Registry Update of Block
N, and Checkpoint N, is authenticated under the keys valid at N, the set
after all of Block N's accepted key acts.

Authenticated key acts are evaluated in canonical Entry index order against
every key ever admitted, removed keys and lower Entry indexes of the same
Block included. An addition whose `key_id` or note key ID was ever admitted,
and a removal of a `key_id` not valid at N−1, are key-act failures: the
Aggregator MUST NOT seal one, and a replayer ignores it as `WIST4-E04`,
changing no key state and keeping the Block valid. Authentication failures
stay `WIST4-E11` and take precedence.

The state artifact carries an `aggregator_key` tuple for every key ever
admitted at or below the Snapshot's Block, a removed key with its removal
height. A Checkpoint at or below a Consumer's head is judged under the keys
valid at that Checkpoint's own height.

## Alternatives and consequences

Authenticating key acts under the set valid at N keeps the paradox and makes
the result depend on evaluation order. Authenticating them sequentially, each
under the set the previous Entry index left, is deterministic but lets a
key's position in leaf-hash order, which no operator chooses by intent,
decide whether a rotation succeeds. Authenticating every act of Block N
under N−1 would let a key removed in Block N, which the removal declares
untrusted, still sign a withdrawal or parameter change sealed beside it, and
would bar a key added in Block N from those acts while §5 lets it sign
Checkpoint N. Reading key acts at N−1 and everything else at N makes the key
set at N a function of the set at N−1 and the Block's set of key acts; Entry
index enters only to choose between two additions of one `key_id` or note
key ID, where some tie-break is unavoidable.

`WIST4-E04` is the code because WIST-4 §5.1 already assigns it to the other
contract failures that read Log state: a `payload_withdrawal` naming no
sealed Delta of its subject and a `suffix_list_update` with a wrong octet
count. `WIST4-E03` is scoped to `parameter_change` rules under WIST-4 §5.
Voiding the Block instead would give any key holder a veto over every Entry
sealed beside a bad act, which WIST-4 §9 rules out for the whole registry.

A key may sign its own removal, the genesis key is removable, and a Block
whose removals empty the key set has no valid Checkpoint and is never
applied; WIST-3 §3.4's succession path covers a Log that loses every key.
Carrying removed keys grows the state artifact by one tuple per retired key
and changes the `state_digest` of any Snapshot taken after a removal.
