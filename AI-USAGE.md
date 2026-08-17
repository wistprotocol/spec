# AI Usage

This file records the generative-AI involvement in this repository's
history from before per-commit provenance marking existed — every commit
up to and including the one introducing this file. From that point on,
commits with substantially AI-generated content name the model used in
an `Assisted-by:` git trailer.

## Record

Development in the covered period used Claude Fable 5
(`claude-fable-5`, Anthropic) via Claude Code, under human direction:
maintainers directed the work and reviewed and accepted every change
before it entered history. Delegated subagent tasks may have executed
on other Claude-family models (Claude Opus, Claude Sonnet) under
Fable 5's direction and final review, so provenance is recorded at the
orchestrator level.

AI-drafted: the four specification documents, the JSON Schemas and
examples, the conformance tooling in `tools/`, and the test vectors it
generates.

Human: the protocol's design — roles, trust model, mechanisms,
parameters; every normative decision, recorded as dated ADRs in
`decisions/`; and the errata discipline in `ERRATA.md`. Vectors were
derived from the specification prose, never the reverse — when they
disagreed, the prose won and the divergence landed in `ERRATA.md` — and
where an external reference exists for a primitive, the harness
re-proves the tooling against it on every run (e.g. the RFC 9381
Appendix B.3 ECVRF vectors in `tools/ecvrf.py`).

## Copyright

The creative choices shaping this repository — the protocol's design,
the selection and arrangement of its content, and the direction and
acceptance of every AI contribution — are its human maintainers'.
Licensed under the terms in `LICENSE`.
