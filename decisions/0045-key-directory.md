# ADR-0045: The Key Set is a key directory with thumbprint identifiers, validity windows, a rotation commitment and an activation delay

**Status:** draft · **Date:** 2026-09-17

## Context

WIST-1 §5 discovered keys through a Declaration whose entries carried a
Publisher-chosen `key_id`, a raw public key and a `valid_from` instant.
Four weaknesses followed from that shape. A free identifier could name
several keys and a key could carry several identifiers, so signer
resolution, Page fallback and every replay rule had to preserve alias
bindings that no honest Publisher needs. A key had a start but no end,
so an overlap between an outgoing and an incoming signing key could only
be ended by another Declaration. A thief holding the current signing key
could rotate to keys of its own choosing at once, and the only answer
was the offline recovery key. And a party holding the web host alone
could publish a fresh identity that reset the domain's history in the
Epoch that sealed it, leaving the owner no window in which a still-held
signing or recovery key could reverse it. Separately, the Declaration's
key entries were a WIST-specific shape that no JWKS tooling could read
or produce.

## Decision

- **Entries are JSON Web Keys.** Each `keys` and `recovery_keys` entry
  is an RFC 8037 OKP JWK: `kty` `"OKP"`, `crv` `"Ed25519"`, `x` the raw
  public key, and `kid` equal to the RFC 7638 thumbprint of that key.
  The `keys` array is therefore the `keys` member of a JWKS document,
  and a signature block's `key_id` names an entry by thumbprint. Because
  a thumbprint names exactly one key and a key has exactly one
  thumbprint, no identifier aliases exist: a Declaration lists each
  public key once across both sets, and every rule that preserved alias
  bindings collapses to a lookup by `kid`.
- **Validity is a window.** `nbf` is REQUIRED and `exp` OPTIONAL, both
  NumericDate integers. A signing binding authorizes a Catalog whose
  `generated_at` lies in [`nbf`, `exp`)
  ([ADR-0052](0052-items-and-catalogs.md)). Listing the outgoing key with an
  `exp` beside the incoming key with a later `nbf` is the overlap
  window; omitting the outgoing key remains immediate revocation.
  Declaration signing authority stays set membership by public key and
  ignores the window, so a Publisher can always rotate under a listed
  key and a validator never needs a clock to classify a Declaration.
- **A Key Set has a fingerprint.** The fingerprint of a signing set is
  `sha256:` over the JCS array of its `kid` values in ascending byte
  order. It serves the two features below, and covers a Declaration's
  `keys` alone, never the keys of a Collection
  ([ADR-0051](0051-collections-scope-and-keys.md)).
- **A Declaration may commit to its successor's keys.** An optional
  `next_keys` member carries the fingerprint of the signing set the next
  ordinary rotation will install. While a commitment stands, an ordinary
  rotation either keeps the signing set and the commitment unchanged or
  installs exactly the committed set. A thief holding the current
  signing key can therefore rotate only to keys it does not hold.
  Recovery rotations override the commitment, because recovery keys
  outrank signing keys already.
- **A fresh identity activates after a delay.** A Declaration signed by
  neither the previous signing set nor its recovery keys, accepted
  outside a recovery window, is sealed but pending: it supplies no
  authority and does not become current until
  `declaration_activation_epochs` Epochs (Parameter Registry, default
  24) after its sealing Epoch. A Declaration signed by a key of the
  previous Key Set or its recovery keys, naming the previous current
  Declaration and sealed before that height, reverses the pending
  identity: it is discarded and never becomes current. The pending head
  and its activation height are Snapshot state. Where the Epoch at the
  activation height is rejected, the pending head activates at the
  first accepted Epoch above it, and the identity reset and the
  narrowing take that Epoch's height: a rejected Epoch applies nothing,
  and leaving the head pending for ever would let one rejected Epoch
  cancel an activation no key holder reversed. With
  `declaration_activation_epochs` at 0 the fresh identity becomes current
  when its Declaration applies, so a Declaration of higher `seq` applied
  later in the same Epoch meets it as current and cannot reverse it, and
  its activation narrows the Publisher's records (ADR-0051) before that
  Declaration applies. A Declaration signed by a key of a Collection is
  signed by neither set and is a fresh identity (ADR-0051).
- **The fingerprint may be published in DNS.** A `_wist.<domain>` TXT
  record MAY carry the current signing set's fingerprint for operators
  and monitors to compare against the served Declaration. It carries no
  key and changes no acceptance decision, so it is not a discovery
  channel and stays inside WIST-1 §8's prohibition.

## Alternatives considered

- **Keep `key_id` free and add thumbprint uniqueness as a rule.** Keeps
  human-readable identifiers but keeps every alias rule alive; the
  thumbprint is a stable name any tool can recompute, and a label for
  humans belongs in the Publisher's own records.
- **`nbf`/`exp` as Publisher timestamps.** Would keep fractional-second
  precision, but JWKS consumers expect NumericDate, and a whole-second
  start or end of a key's authority loses nothing a Publisher needs.
- **Committing to the successor's complete entries.** Would fix the
  successor's `nbf`/`exp` at commitment time; committing to the
  thumbprint set leaves the timing of the rotation to the rotation.
- **A delay measured in time.** Epochs are what a replaying Consumer
  can count without a clock; the recovery window is time-based because
  it bounds the queuing of Catalogs, whereas activation only orders
  Declarations.
- **Delaying every Declaration.** An ordinary or recovery rotation is
  authenticated by a key the domain already listed; delaying it would
  slow the honest case for no gain, and the recovery window already
  covers a stolen signing key.

## Consequences

- Publishers regenerate their Declarations in the JWK shape; a signature
  block's `key_id` becomes the thumbprint, so every signed object under
  the old identifiers is re-signed or re-declared before publication.
- Aggregators and Consumers drop alias handling and add the pending
  state: a domain may carry a current Declaration and a pending head at
  once, Catalogs verify only under the current one, and Log replay derives
  activation and reversal from heights alone.
- A `pending_declaration` Snapshot tuple carries the pending head, its
  sealing height and its activation height (WIST-3 §7).
- `vectors/wist1/key-directory.json` carries thumbprint known answers,
  entry field cases, overlap eligibility, satisfied and unsatisfied
  commitments, a delayed activation with its reversal twin and a DNS
  fingerprint record.
