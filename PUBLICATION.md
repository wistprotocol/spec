# Draft development and publication

The WIST suite is an editable draft until its protocol roles have been
implemented and validated together. A draft label identifies work under
validation; it promises no stable edition or compatibility between draft
revisions. Cite an exact specification commit when reporting conformance.
Draft status does not waive the signed objects' version rules.

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

- An implemented Auditor validated end to end with a Publisher, Aggregator
  and Consumer against the applicable WIST-1 through WIST-4 conformance
  checklists, including live fetches, evidence capture, Record publication,
  admission, sealing and Consumer verification.
- Two independent implementations passing the full vector suite, including
  the pure-Python conformance reference in `tools/`. Passing vectors does not
  waive a known failure or an unexercised role obligation.
- Resolution of known specification gaps and conformance failures. Each
  resolved behavioral gap carries a discriminating vector. Validation
  evidence identifies the specification commit and obligations exercised.
- An explicit reconciliation of the edition label with WIST-1 §3.1's signed
  object version rules. A document tag alone cannot authorize a wire-format
  change. This policy assigns no new `wist_version`.

Until these conditions hold, publications remain drafts. Publish the
validated edition with its conformance evidence and accept its consolidated
design decisions. Subsequent substantive changes to an accepted ADR use a
new ADR with an `Amends` header naming every affected decision; additive
clarifications use dated addenda. Annotate each affected decision's status
with the reference, date and effect of the change.

## Deployment boundary

From the first Log sealing Blocks consumed by a third party, the deployed
edition's normative text is fixed, even if its label still says draft.
Record corrections in that edition's errata ledger. An erratum cannot break
an implementation conforming to the existing text and must express a rule
already implied by it or correct an error without changing behavior.
A substantive change requires a new major version and explicit adoption.
