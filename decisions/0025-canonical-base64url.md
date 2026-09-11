# ADR-0025: Canonical base64url at validation

**Status:** draft · **Date:** 2026-09-11

## Context

[RFC 4648 §3.5](https://www.rfc-editor.org/rfc/rfc4648.html#section-3.5)
requires encoders to zero unused bits but permits decoders to reject or
accept nonzero bits. Citing unpadded base64url alone therefore permits
validators to disagree. Alternate public-key strings can decode to the same
bytes, affecting key-set disjointness and continuity if compared as text.
An alternate detached signature spelling can also change an Envelope's
leaf hash without changing its verified signature bytes.

## Decision

Require canonical unpadded base64url for every protocol field using that
encoding, including public keys, signatures and Payload salts. Reject
nonzero unused bits, invalid lengths, padding, whitespace and foreign
alphabet characters. Retain each field's decoded length constraint.
Decoding and canonical re-encoding must reproduce the input exactly.

Extend `WIST1-E14` to these encoding failures. Validate encoding before
using the field for cryptographic eligibility, authentication or commitment
verification. Declaration field validation still precedes sequencing,
conflict comparison and idempotence; malformed unused keys reject the
Declaration, while canonically encoded unusable points remain governed by
§4's exclusion rule. Preserve existing object dispositions and transport
wrappers, including first-contact `WIST2-E04` and invalid-Block-file
`WIST3-E03`. No order among unrelated failures is introduced.

Compare public-key membership by decoded bytes after validation. Canonical
strings produce the same equality relation. Preserve original signed
entries for hashing, signatures and recovery protection; do not normalize
an invalid spelling into an accepted object.

## Alternatives and consequences

Permissive decoding would require every equality operation to handle
multiple textual spellings and would retain signature-Envelope aliases.
Normalizing signed fields before validation changes canonical bytes and
predecessor hashes. Restricting canonicality to public keys would leave
signature and salt validation dependent on decoder defaults. A single
encoding profile avoids these inconsistencies without changing valid
encoder output or the Ed25519 point-verification profile.

The schemas constrain unused bits as well as alphabet and length.
`vectors/wist1/base64url.json` supplies signed Declaration mutations,
signature aliases and byte-level boundaries. The reference independently
checks trailing bits, schema agreement and signature validity beneath
alias spellings. These fixtures establish encoding validation, not complete
hostname/timestamp eligibility, authenticated process acceptance or live
admission, sealing and restoration.

The undeployed draft changes under [PUBLICATION.md](../PUBLICATION.md).
