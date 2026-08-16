# ADR-0013: Ed25519 verification is strict, and the profile is pinned

**Status:** accepted (addendum 2026-08-16: the VRF's key validation) · **Date:** 2026-08-16

## Context

Every party in this suite decides the same question about the same bytes:
does this signature verify? A Publisher's Delta, a Declaration, a Block
header, a Checkpoint, an Audit Record and a Registry Update are all one
construction (WIST-1 §4), so one answer to that question is the foundation
the whole Log rests on.

RFC 8032 does not supply one answer. §5.1.7 states the verification
equation as `[s]B = R + [k]A` and then permits a verifier to check the
cofactored form `[8][s]B = [8](R + [k]A)` instead; it recommends but does
not require rejecting a non-canonically encoded `A` or `R`; and it says
nothing about points of small order. Implementations differ accordingly.
libsodium rejects small-order keys and non-canonical encodings;
`ed25519-dalek` exposes both a permissive `verify` and a `verify_strict`;
consensus systems such as Zcash and Tendermint adopted ZIP-215, which goes
the other way and accepts everything cofactored verification accepts,
precisely so that no two nodes disagree.

Left unpinned, the divergence is not theoretical. A public key carrying a
torsion component admits signatures that satisfy the cofactored equation
and fail the cofactorless one, so two honest verifiers reading the same
Block reach opposite conclusions about the same Entry. In a Log whose
premise is that a Consumer verifies rather than trusts, that is a fork with
no attacker required — and with an attacker, a small-order `A` is a key
under which one signature verifies for many keys, in a suite that anchors
identity to keys and to nothing else.

WIST-1 §8's malleability bullet said only that Ed25519 signatures "are
deterministic; validators MUST verify against Canonical Bytes only", which
addresses what is signed and not how the signature is checked.

## Decision

WIST-1 §4 pins the profile, for every signature the suite defines:

- **Cofactorless.** The equation is `[s]B = R + [k]A`, checked without the
  cofactor. Recomputing `R` and comparing encodings is the same check and
  is permitted.
- **`s` canonically reduced**, `0 ≤ s < L`. Adding `L` leaves `[s]B`
  unchanged, so a verifier omitting this accepts a second valid signature
  for a message the key already signed.
- **`A` and `R` canonically encoded** — the encoded `y` below
  `p = 2^255 − 19` — and **not of small order**.

A signature failing any of these is `WIST1-E01`. A key in `keys` or
`recovery_keys` that is non-canonically encoded or of small order is not
admitted to the Key Set, and a Delta naming it is `WIST1-E02`: the check
belongs where the key enters, so the Key Set a Consumer replays is the set
the Aggregator ingested against.

`vectors/wist1/ed25519-strictness.json` carries the seven cases that
separate this profile from the permissive readings, the torsion-key case
that separates cofactored from cofactorless included.

## Alternatives considered

**ZIP-215 (cofactored, non-canonical encodings accepted).** It buys the
same thing this decision buys — all conformant verifiers agree on every
input — and it buys it with a wider acceptance set, which is a virtue for a
chain that must never stall. It was rejected because acceptance is not free
here: it admits small-order `A`, and a domain-anchored identity model
cannot afford a class of keys under which one signature verifies for many.
Its library support is also narrower outside the chains that authored it,
so most implementers would be writing WIST-specific verification code,
which is how pinned rules stop being followed.

**Leaving it to RFC 8032.** Rejected as the status quo whose defect this
records: the RFC's own text permits both readings, so "follow RFC 8032"
names no single behavior.

## Consequences

- An implementation inherits the profile from `libsodium`'s default or
  `ed25519-dalek`'s `verify_strict` rather than hand-rolling it. The
  residue is the canonical-encoding check on `A`, which some libraries
  perform silently and others (including `ed25519-dalek`, whose decoder
  reduces mod `p`) do not — so it is stated as its own bullet rather than
  left to the library.
- Existing valid signatures are unaffected: an honest signer produces a
  canonical `R`, a reduced `s`, and a prime-order `A`, so nothing an honest
  Publisher has ever emitted stops verifying.
- A key that no verifier will accept can no longer be published and then
  discovered one rejected Delta at a time, because the Key Set rejects it
  at discovery.
- The suite gains a property it claimed but did not have: two conforming
  verifiers reach the same verdict on every signature, including
  adversarially constructed ones.

## Addendum (2026-08-16) — the same standard for the VRF's keys

RFC 9381 makes `ECVRF_validate_key` optional and leaves the choice to the
application, exactly as RFC 8032 leaves the cofactor to the verifier. WIST-4
§4 now requires it: a `vrf_proof` under an Auditor public key that fails key
validation does not verify, and the Record is void for standing
(`WIST4-E01`).

The reasoning is this ADR's, applied to the key set one layer up.
ECVRF-EDWARDS25519-SHA512-TAI shares the RFC 8032 key format (§5.5), so the
same small-order points are reachable; and §11's argument that an Auditor
cannot steer its own selection rests on `beta` being the *unique* correct
output for a Block, which a small-order key destroys — an Auditor could then
grind selection sets until one omitted the Deltas it preferred not to audit.
Skipping the step is conforming under RFC 9381 read alone, which is why the
requirement is stated in the suite rather than inherited.

