# ADR-0007: Content payloads outside the immutable log

**Status:** accepted · **Date:** 2026-08-02

## Context

The Commons Log is append-only, hash-chained and replicated across mirrors
that the project does not control. Extracts and summaries are drawn from
public web pages, and public web pages routinely contain personal data — a
name in an article, an author byline, a court record. Data protection law
grants erasure rights over that data (GDPR Art. 17, LGPD Art. 18), and those
rights attach to whoever redistributes it, not only to the original
publisher.

The EDPB's Guidelines 02/2025 on processing personal data through blockchain
technologies, adopted in final form on 7 July 2026, are directly on point
for append-only replicated structures. Two findings matter here: data that
is hashed or encrypted may still be personal data, and the recommended
design keeps personal data out of the immutable structure altogether rather
than relying on erasing it afterwards. Deleting the off-chain data so that
an on-chain hash can no longer identify anyone is recognised, but as a
workaround rather than as good design.

An index is also not an archive. Archives have specific exemptions
(GDPR Art. 17(3)) that an index does not, so an index that also behaves as
a permanent archive takes on archival legal exposure without archival legal
protection.

Carrying extract bytes inside the signed object and inside sealed Blocks
would put that text permanently beyond any operator's ability to withdraw
it. It would also make the erasure path expensive: Block files would stop
being byte-immutable, and every mirror and Consumer would have to handle
re-serialisation and partially-removed entries during verification.

## Decision

Signed objects commit to content; they do not carry it.

- A Delta carries a **salted commitment** to its `extract`, `links` and
  `summary` (HMAC-SHA256 under a per-Delta random salt of at least 128
  bits), not their bytes.
- The bytes and the salt travel as **content-addressed payload files
  alongside** the Block, in the same hourly synchronisation, served as
  static files exactly as Blocks are.
- Payloads are erasable. A withdrawal is recorded in the Log as a signed
  redaction entry naming its legal basis, following the same due process
  the suite already uses for sanctions: notice, evidence, public and
  permanent record.
- Operators and mirrors MUST serve payloads for a minimum availability
  window (a Parameter Registry value), so that a payload disappearing
  quietly is distinguishable from one withdrawn for cause.
- A withdrawn payload discharges an Auditor's coverage duty for the
  affected Delta rather than counting against it.

The salt is what makes the commitment unlinkable after withdrawal: once
bytes and salt are gone, a party holding a copy of the original text cannot
demonstrate that it corresponds to the commitment in the Log.

## Consequences

- Personal data leaves the immutable structure by construction, which is
  the design the EDPB guidance recommends, rather than by a promise to
  delete later.
- Blocks stay byte-immutable and mirrors stay dumb file servers. Erasure
  costs a file deletion plus a Log entry, not a re-serialisation of
  history.
- The publisher remains cryptographically bound to what it declared for as
  long as the payload exists, which is the window in which auditing
  happens. After withdrawal, accountability rests on the Audit Records
  already sealed, which record verdicts as data.
- Reputation remains a pure function of Log history: a replaying party
  reads recorded verdicts rather than recomputing similarity, so
  withdrawal does not change any score.
- Deduplication by identical content can no longer be done from Log
  commitments, because salts differ. It moves to materialisation, where
  the Aggregator holds the plaintext — which is where it belongs.
- The constitutional invariant on immutability narrows and is restated
  accordingly: the Log's record and its commitments are permanent and
  append-only, while content payloads may be withdrawn under logged due
  process. Stating the narrower rule is preferable to keeping a broader
  one that the mechanism would contradict.
- An irreducible residue remains: URLs stay in the Log permanently, and a
  URL can itself contain a name. This is the minimum public identifier the
  function requires, it is already public on the web, and it is the same
  residue Certificate Transparency carries in domain names. The Privacy
  Considerations state it plainly rather than implying the design is
  residue-free.

## Alternatives considered

- **Redaction in place** — keep extracts in Blocks and remove bytes on
  request, preserving entry hashes. Legally this is the workaround tier
  rather than the recommended design, and operationally it is worse: it
  breaks byte-immutable Block files and pushes re-serialisation into every
  mirror and Consumer.
- **Crypto-shredding** — encrypt extracts and destroy keys on request.
  Unsuited to indefinite retention because the encryption ages, and
  meaningless for this system in any case, since the content is published
  openly and copies exist from the moment it is served.
- **Keeping nothing derived from personal data in the Log at all** — the
  EDPB's ideal tier. Incompatible with being a web index: without URLs
  there is no index.
- **Status quo, with a takedown process only** — defensible by precedent,
  since large public web corpora operate this way, but it declines a fix
  that is inexpensive while the specification is in draft and expensive
  once sealed Blocks and mirrors exist.
