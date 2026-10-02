# Draft development and publication

The WIST suite is an editable draft until its protocol roles have been
implemented and validated together. A draft label identifies work under
validation; it promises no stable edition or compatibility between draft
revisions. Cite an exact specification commit when reporting conformance.
Before either stable publication or the deployment boundary below, successive
revisions define the same unreleased signed-object version, currently
`wist_version = 1.0.0`. Incompatible changes, including required fields, MAY
retain that version under WIST-1 §3.1. This exception applies across the
suite, not only to one object type. A validator implements an exact draft
revision and MUST enforce that revision's complete rules; the shared version
string does not authorize accepting objects from other draft revisions.
Compatibility claims and validation evidence MUST identify the specification
commit. There is no implicit legacy-object acceptance or field normalization.

The exception ends at the earlier of stable publication and the deployment
boundary. After that boundary, a substantive change requires a new major
version, even when the deployed edition is labelled draft.

## Developing the draft

Edit the documents, schemas and vectors together. Record technical changes
and their reasons in Git. Keep design decisions provisional, updating the
relevant ADR in place as its mechanism is refined; retain the rationale,
alternatives, assumptions and consequences needed to evaluate that design.
Use a separate ADR for a distinct architectural decision, rather than for
each refinement of a provisional one.

The specification determines behavior. An implementation or reference tool
does not settle an ambiguity by choosing a library default. Record unresolved
questions and reference divergences explicitly; resolve each behavioral gap
in the text with a discriminating conformance vector in the same change.
Verification evidence distinguishes exercised behavior from obligations not
covered by the harness. Agreement between a generator and its verifier alone
does not establish correctness.

An unreleased draft needs no errata ledger for ordinary development.
Commit history preserves the changes; the current documents state the
current rules. Keep known conformance failures visible until resolved.

## Stable-edition criteria

Final consolidation requires all of the following:

- Implemented Publisher, Aggregator and Consumer roles validated end to end
  against the applicable WIST-1 through WIST-4 conformance checklists,
  including a Publisher acting as a Labeler: live pulls of Catalogs, with
  their lists, change lists and Payloads, and of Label Feeds, admission,
  sealing, Snapshot production and Consumer verification and ranking.
- Two independent implementations passing the full vector suite, including
  the pure-Python conformance reference in `tools/`. Passing vectors does not
  waive a known failure or an unexercised role obligation.
- Resolution of known specification gaps and conformance failures. Each
  resolved behavioral gap carries a discriminating vector. Validation
  evidence identifies the specification commit and obligations exercised.
- An edition label and signed-object version consistent with WIST-1 §3.1.
  Identify the exact validated draft revision being frozen; older incompatible
  draft objects do not gain acceptance merely by sharing its version string.
  A document tag alone cannot authorize a wire-format change.

Until these conditions hold, publications remain drafts. Publish the
validated edition with its conformance evidence and accept its consolidated
design decisions. Subsequent substantive changes to an accepted ADR use a
new ADR with an `Amends` header naming every affected decision; additive
clarifications use dated addenda. Annotate each affected decision's status
with the reference, date and effect of the change.

Publishing a stable edition also activates the immutability and change rules
under [Deployment boundary](#deployment-boundary) for that edition.

## Deployment boundary

From the first Log sealing Epochs consumed by a third party, the deployed
edition's normative text is fixed, even if its label still says draft.
Record corrections in that edition's errata ledger. An erratum cannot break
an implementation conforming to the existing text and must express a rule
already implied by it or correct an error without changing behavior.
A substantive change requires a new major version and explicit adoption.
