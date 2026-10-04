# ADR-0036: Registry Update field, version and authenticity dispositions

**Status:** draft · **Date:** 2026-09-14

## Context

The Registry Update schema constrains every Envelope, but the error registry
named codes only for `details` contract failures and parameter rules. An
Envelope carrying unknown members, a malformed signature field, an
unsupported major version, a timestamp denoting no instant, or a signature
that fails under the Log key had no diagnostic and no stated precedence, and
nothing said whether such an act still changes replay state. The decision
first covered roster, canary and process acts as well;
[ADR-0041](0041-signed-publications.md) removed those acts, and the gate
governs the five acts WIST-4 §3 lists.

## Decision

WIST-4 §5.1 defines the eligibility gate every Registry Update passes before
any semantic rule: WIST-1 §4 JSON/JCS eligibility (`WIST1-E05`), then the
complete schema, partitioned into the action's `details` and `subject`
contract (`WIST4-E04`) and every other field failure (`WIST4-E11`), then the
act's own version support (`WIST4-E11`), then authenticity under a Log key
valid at the height WIST-3 §3.4 fixes for the act (`WIST4-E11`). E11 precedes
E04; field failures precede authenticity; authenticity precedes semantics, a
key-act failure's `WIST4-E04` included. An act rejected at the gate changes
no key registry, schedule or withdrawal state; the containing Epoch stays
valid. The schema's version, timestamp and identifier patterns are exact
whole-string patterns. Two schema failures of a `parameter_change` are
not the gate's: a string `details.parameter` that names no WIST-4 §5
identifier, with a `subject` that is the same string, and an integer
`details.value` outside its WIST-4 §5 bound. Such an act passes to
authentication and is rejected under WIST-4 §5 as `WIST4-E03`, the code
WIST-4 §7 gives both and a value that breaks a combination rule also
takes, so a value past a bound has one code whether the schema can
express that bound or not; a non-string `parameter` stays `WIST4-E04`.

A `payload_withdrawal` is authenticated under the Log key (WIST4-E11
otherwise). Its `delta_id` names the Item ID of the Item whose Payload
it withdraws (WIST-3 §6.2): an Item of kind `page` that a valid
`publisher_item` Entry sealed at or below the act's Epoch, that Epoch
included whatever the order of its Entries, against a Catalog whose
`publisher` is the `subject` ([ADR-0052](0052-items-and-catalogs.md)),
or the act fails its `details` contract (WIST4-E04). Repeated withdrawals of one Item are accepted, the
earliest Epoch governing. Rejecting a withdrawal of an unsealed or
foreign Item keeps the act's `subject` truthful and gives every replayer
one withdrawal height per Item.

Every Registry Update is identified by its ID, which hashes `update` alone.
An occurrence that fails eligibility or field validation is rejected with
that failure's code whether or not its ID was accepted earlier: the Envelope
around an accepted `update` can itself be malformed, and one order of the
two checks gives every validator one diagnostic. An occurrence that passes
them and carries an ID already accepted at a lower Epoch, or earlier in the
same Epoch, is idempotent, so a re-sealed Entry never re-applies or
conflicts with itself. A Snapshot carries one `registry_update` tuple
per accepted ID, of every action, with the height of the Epoch whose
occurrence was accepted (WIST-3 §7), and a Consumer resumed from it holds
those IDs as accepted.

## Alternatives and consequences

Ignoring such acts without a code leaves implementations no shared
diagnostic and no precedence, so two validators could report one malformed
act as E04 or as nothing. Assigning field failures to E04 would make one code
cover both an action's contract and unrelated Envelope defects. Letting a
malformed or unauthenticated act reach the semantic rules would let bytes no
Log key signed admit or retire a key, amend a parameter or withdraw a
Payload.

Reusing `WIST1-E01` for every failing signature would mislabel an act signed
under the wrong key, whose signature may verify under a key the rule does not
admit.

Leaving a resumed Consumer to judge a repeat as a first occurrence changes
state, not only a diagnostic. Two `parameter_change` acts A and B with one
`effective_at`, B sealed later and so prevailing (WIST-4 §5), are followed
by A sealed again while its `effective_at` is still `param_grace_days`
ahead: on replay the repeat is idempotent and B stays in force, while a
Consumer resumed from a Snapshot between B and the repeat, without A's
ID, would accept the repeat as later in Log order and put A in force. The tuple adds one ID
and one height per accepted act: of the other kinds only `aggregator_key`
carries the act that produced it, and a superseded amendment has no
`parameter` tuple.

`vectors/wist4/withdrawal.json` and `vectors/wist4/registrable-domain.json`
carry unknown-member, unsupported-major, foreign-key and contract cases for
`payload_withdrawal` and `suffix_list_update`;
`vectors/wist3/aggregator-keys.json` carries the authentication height of key
acts and of acts signed by a key admitted or removed in the same Epoch.

The undeployed draft changes under [PUBLICATION.md](../PUBLICATION.md).
