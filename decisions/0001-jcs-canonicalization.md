# ADR-0001: JCS (RFC 8785) for canonicalization

**Status:** accepted · **Date:** 2026-08-02

## Context

Every object in the suite is signed, and signing JSON requires a
byte-exact canonical form: the same logical object must always produce
the same octets, or signatures and content-derived IDs are meaningless.

## Decision

All signatures and content IDs are computed over JCS (RFC 8785) canonical
bytes of the inner object.

## Consequences

- Serialization ambiguity (whitespace, key order, number forms) is
  eliminated, and with it the classic canonicalization attacks.
- Objects that cannot be canonically represented are rejected, never
  repaired (DC1-E05).
- Everything stays human-readable JSON: `curl | jq` remains a first-class
  debugging tool, which matters for a protocol courting web-developer
  adoption.
- Implementations need a JCS library (widely available) or a careful
  hand-rolled serializer plus the test vectors in DC-1 Appendix A.

## Alternatives considered

- **Canonical CBOR**: binary, compact, but kills casual debuggability and
  raises the implementation bar for the audience that matters most (site
  operators).
- **Sign raw bytes as transmitted**: forces every party to store original
  octets forever and makes IDs transport-dependent; rejected.
