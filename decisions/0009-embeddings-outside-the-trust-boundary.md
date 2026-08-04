# ADR-0009: Embeddings live outside the trust boundary, as companion packs

**Status:** accepted · **Date:** 2026-08-03

## Context

Tier 0 carried quantized embeddings of every live record, and the
manifest declared the model that produced them. Nothing verified them.
`content_digest` deliberately covers Log-derived tuples only, so a
perturbed vector passes every check the suite defines; float inference
is nondeterministic across hardware and BLAS libraries, so no exact
equivalence criterion can exist; and the only possible inexact one — a
tolerance — is an attack budget, since any manipulation inside the
tolerance is invisible by construction. A suite that declares an
implementation non-conforming for computing reputation in floating
point *even when the results agree* (WIST-4 §6) cannot carry a
tolerance-verified artifact inside the same trust boundary without
breaking its own category. The model choice was also ungoverned: one
operator's model defined "similar" for every Tier-0 consumer, against
the README's "no trust in any operator."

Semantic retrieval still matters — for agent consumers it is the
primary retrieval mode, and re-embedding a full Tier 1 is a multi-day
GPU job, so "rebuild it yourself" is theoretical for exactly the
laptop-class consumer Tier 0 serves.

## Decision

The protocol carries no embeddings. Any party — the Aggregator
included — MAY publish a signed **companion pack** (WIST-3 §7): vectors
computed over a named Snapshot, binding the Snapshot's `content_digest`
and `log_position`, self-describing its model (name, version, weights
hash, dim, quantization, metric, source field), and covering only
records the bound digest covers — which excludes withdrawn records at
publish time by construction.

The signature binds **provenance**; the digest binds **scope**; vector
honesty is neither — it is chosen trust in the pack publisher,
deliberately outside the protocol's verification claims. The
specification defines no equivalence criterion for vectors on purpose:
the tolerance question does not leave WIST-3, it leaves the protocol.

## Consequences

- Tier 0 sheds its dominant per-record cost; the laptop-sized claim is
  arithmetic again rather than aspiration.
- "No trust in any operator" stays exact everywhere the protocol makes
  the claim, because the protocol no longer transports an artifact the
  claim cannot cover.
- Model choice decentralizes: consumers pick packs the way they pick
  clients, models can improve without protocol change, and pack
  publishing is an open ecosystem role rather than an operator power.
- An embedding is an unsalted content-derived value — embedding a
  candidate text and comparing vectors partially confirms withdrawn
  content, the confirmability the Payload salt exists to destroy. Packs
  are no worse than the Tier 1 extracts they derive from, but they sit
  inside the same withdrawal obligations: the Aggregator's own packs
  are bound like any Snapshot artifact, and a third-party pack holder
  is in the position WIST-1 §6 already names — a copy already served,
  with a named holder, rather than a structural inevitability.
