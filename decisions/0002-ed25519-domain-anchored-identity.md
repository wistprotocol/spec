# ADR-0002: Ed25519 keys anchored to the domain

**Status:** accepted · **Date:** 2026-08-02

## Context

The protocol needs publisher identity that is Sybil-resistant, cheap to
verify, and aligned with where reputation naturally lives.

## Decision

Publisher identity is an Ed25519 Key Set published at
`/.well-known/wist/publisher.json`, anchored to the domain over
HTTPS and nowhere else. No DIDs, no blockchain.

The `_wist.<domain>` DNS TXT fallback this decision originally
carried is not part of it. Plain DNS is unauthenticated and DNSSEC is
neither universally deployed nor universally validated, so the fallback
handed an attacker who could force the HTTPS endpoint to fail — a strictly
easier act than breaking HTTPS — a way to publish a signing key for a
domain it does not control, defeating the anchor this decision exists to
establish. Conditioning it on DNSSEC was rejected for the same reason: a
fallback that is only sometimes authenticated is one whose security depends
on a property no verifier can check at the moment it matters. WIST-1 §8
records the closed door.

## Consequences

- The domain is already the unit of web reputation and costs money to
  hold — Sybil resistance comes for free at the identity layer, and
  disposable-domain attacks are handled economically by WIST-4's Provisional
  cap and sanction ladder.
- Verification requires nothing but HTTPS and an Ed25519 library.
- Key rotation/revocation is self-service (new Key Set signed by the old
  key); domain resale without key continuity resets reputation.
- Ed25519 specifically: deterministic signatures (no nonce-reuse
  disasters), 64-byte signatures, universal library support.

## Alternatives considered

- **DID methods**: an extra identity layer with heavy dependencies that
  adds no trust here — the domain would still be the anchor underneath.
- **Reusing X.509/TLS certificates**: ties signing to CA issuance and
  short-lived certs; conflates transport identity with content authorship.
