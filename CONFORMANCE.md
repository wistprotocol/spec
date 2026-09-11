# Conformance validation

The specification is authoritative. Passing the reference harness does not
establish conformance for behavior it does not exercise. Known reference
divergences below must be resolved with discriminating vectors before a
stable edition can be published under [PUBLICATION.md](PUBLICATION.md).

## URL resolution

WIST-2 §11 step 5 specifies RFC 3986 §5. The `normalize_url` function in
`tools/link_extraction.py` delegates relative resolution to `urljoin`, which
does not implement that procedure for these inputs:

| Candidate | Base | Required result | Reference result |
|---|---|---|---|
| `https:///x` | `https://example.com/blog/post-1` | Reject the empty host | `https://example.com/x` |
| `a//b` | `https://example.com/blog/post-1` | `https://example.com/blog/a//b` | `https://example.com/blog/a/b` |
| `x//` | `https://example.com/blog/post-1` | `https://example.com/blog/x//` | `https://example.com/blog/x/` |

An explicitly empty authority cannot inherit the base host. Empty path
segments survive merging and removal of dot segments. The link-extraction
vectors do not exercise these cases. Correct the reference resolver and
add positive and negative cases without changing the specified algorithm.

## Recovery history resolution

Before authenticated recovery and identity-scoped finding replay can be
validated, resolve these WIST-1 §5.2 and WIST-3 §3.3 ambiguities with signed
Declaration histories carrying sequence numbers and predecessor hashes:

- WIST-4 §7 authenticates an appeal against the Key Set current at its
  notice's Block. An open recovery window can have distinct accepted and
  recovery-chain heads, while WIST-1 §5.2's historical key rule addresses
  Deltas. Define notice-era appeal authority across open and settled
  prefixes with signed appeals under competing and recovery-chain keys.
  WIST-4 §6.3's identity continuity does not determine signature eligibility.
- Distinct same-domain, same-sequence Declaration candidates can each name
  the pre-Block head. WIST-1 requires rejection of an invalid Declaration,
  but does not define whether this conflicting batch invalidates its Block
  or has another disposition. Define the result without choosing a winner
  by storage index, with signed conflicting-candidate vectors.

WIST-1 §5.2 and WIST-3 §3.3 select recovery ownership in ascending
`(Block height, seq)` order. `vectors/wist1/recovery-order.json` exercises
signed Declarations and predecessor links in authenticated Block chains,
including reversed leaf-hash order. WIST-1 §5.2 separately retains the highest
accepted sequence through settlement and defines eligible predecessor heads.
`vectors/wist1/recovery-heads.json` authenticates a complete hourly Block chain
and probes ordinary/recovery followers across competitors, stale predecessor
rejection, named-predecessor classification, the deadline transition and
idempotent re-serving of the restored lower-sequence head. Its reference
validates Declaration authorship separately from Block inclusion. It asserts
no identity-reset or conflicting-batch result.

WIST-4 §6.3 preserves the recovery owner's identity from its application
onward. In-window fresh competitors cause no reset or sanction lift in any
prefix; settlement does not restore opening values or reverse ordinary
process effects. A fresh predecessor earlier in the owner's Block resets
normally, as does a valid fresh replacement after settlement unless a new
window has opened. `vectors/wist4/recovery-identity.json` authenticates two
hourly Declaration histories with reversed owner/competitor storage order
and deadline probes. Its separate abstract projections exercise identity
scope for age, credit, penalties, findings, rungs and notice targets with
already-eligible inputs. They do not authenticate or establish eligibility
of Audit Records, notices, lifts or appeals, or Snapshot resume conformance.

`vectors/wist1/recovery-settlement.json` exercises abstract signer membership
but omits authenticated sequence and predecessor transitions. Passing it
cannot establish agreement on these unresolved history cases. Its two
abstract thief-rotation cases restore `recovery_keys` from `r2` to `r1`
without the replaced recovery key's authority, contrary to WIST-1 §5.2.
Replace these inadmissible projections with signed admissible competitors
and rejection twins before claiming authenticated settlement conformance.

WIST-3 §7's Snapshot `declaration` tuple carries only the current Envelope
and sealing height, and `recovery_window` carries only owner height and end.
These do not supply the retained accepted sequence floor after restoration
of a lower-sequence head, or both open-window heads. Define sufficient
Snapshot state or required authenticated history reconstruction, with
Snapshot-versus-full-history vectors, before Snapshot recovery replay can
establish conformance. The full-history head vectors do not resolve this
Snapshot representation question.

## Validation still required

The vector-family inventory in `tools/VERIFICATION.md` distinguishes
independent anchors from self-consistency. The following acceptance evidence
must also be supplied before stable publication; isolated signature or
arithmetic checks do not establish live-service behavior.

| Surface | Required evidence |
|---|---|
| WIST-1 §4 canonicalization | Correctly rounded binary64 edge cases, fractional JSON values in signed objects and rejection outside the finite range |
| WIST-1 §5.2 Declaration key binding | Initial admission, replacement and historical replay consume `declaration-binding.json`; duplicate identifiers reject and reused identifiers or aliases preserve the authenticated public key's correct identity/recovery class |
| WIST-1 §5.2 recovery ownership and heads | Replay consumes `recovery-order.json` and `recovery-heads.json`, authenticating each Declaration against its eligible named predecessor, retaining the accepted sequence floor and settling before deadline-Block Declarations. Canonical storage order and a later recovery inside the window cannot replace its owner. Snapshot state, appeal authority and conflicting-candidate disposition require the resolutions listed above. |
| WIST-4 §6.3 recovery identity | Consume `recovery-identity.json`; integrate its reset boundaries with authenticated Delta/Audit Record history, candidate-Block parameter profiles, notice evidence and due process. Recovery preserves identity without freezing state or retroactively altering earlier prefixes. Abstract projection inputs do not establish these integrated obligations. |
| WIST-2 §§3–5, 7 Feed pulls | Domain mismatch and unusable-Feed classification; Declaration refresh before counting signature failure; seen-ID bookkeeping; Page creation/sealing timestamps |
| WIST-2 §7 and WIST-4 §6.4 quotas | Error-code accounting, `WIST2-E05` exclusion, UTC-day parameter/reputation anchor and live quota application |
| WIST-2 §§6, 8 scheduling and redirects | Hints change audit timing without creating a selection duty; redirect termination and authority restrictions under live pulls |
| WIST-3 §§5–6 publication | Durable Block publication before its Checkpoint; Payload replication before the Block; acquisition of cited evidence before serving a notice |
| WIST-3 §§3.1, 6 transport parsing | Independent decoding of the Block-frame vectors and general compressed/checksummed frames; rejection of extra frames, skippable data and trailing bytes; leap-second rejection in all Log-comparable timestamp fields and Snapshot tuples. The raw-frame reference in `tools/block_frames.py` does not implement entropy decoding or checksum verification. |
| WIST-3 §§3.4, 5 Log key succession | A rotated Aggregator key authenticates Blocks and Checkpoints at the correct height, including rejected keys |
| WIST-4 §§4–5 audit execution | Small-order VRF key rejection; actual fetch byte, time and redirect limits; reference/observed failures; WARC capture and required evidence retention |
| WIST-4 §6.4 inclusion | Acceptance and per-domain turn accounting under backlog, overload and recovery; the Log alone does not reveal acceptance time |
| WIST-4 §§3.1, 5.1–5.2, 7 integration | Observer and canary publication, authenticated admission evidence, accepted notice service and complete appeal processes across the four roles |

These are validation requirements, not assertions that every boundary lacks
unit coverage. Current vectors already exercise, among other cases,
normalization, key-set selection, late appeals and notice activation targets.
Provide an exact specification commit and the exercised obligations when
claiming that any row is satisfied.

## Object-version policy

WIST-1 §3.1 prohibits new fields in a minor object version. Draft changes
include required Audit Record fields and additional Registry Update actions
while objects still carry `wist_version = 1.0.0`. Before final consolidation
or an adopted wire-format change, determine explicitly whether successive
drafts define one unreleased object version or require a new major object
version. Align document labels and signed objects with that decision and
add discriminating vectors. The draft publication policy itself changes
neither object acceptance nor version semantics.
