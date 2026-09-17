# WIST-2: Site Publication

**Status:** v1.0.0-draft · **Date:** 2026-08-02 · **License:** CC-BY 4.0

## 1. Introduction

WIST-2 defines **ping + pull** publication: a Publisher serves Deltas
(WIST-1) and Labels (§3.3) under its `.well-known` path and notifies
Aggregators to fetch them.
These Publisher-hosted artifacts permit independent retrieval and verification
without coupling publication to one Aggregator. Design rationale:
[ADR-0003](../decisions/0003-ping-plus-pull.md).

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as
shown here.

- **Feed**: the signed list of a Publisher's recent Delta IDs.
- **Page**: an immutable, sealed slice of exactly 1000 older Delta IDs
  evicted from a Feed, reachable by walking `next` (§3.2).
- **Ping**: the unauthenticated notification a Publisher sends an
  Aggregator's Ingest Endpoint to trigger a pull.
- **Change Hint**: an unsigned, out-of-protocol signal (IndexNow ping,
  sitemap, llms.txt) that a page may have changed.
- **Ingest Endpoint**: `POST https://<log_id>/ingest` at the
  Aggregator's Service Origin (WIST-3 §6); a Publisher learns a Log's
  `log_id` from its Log Anchor, obtained out of band (WIST-3 §3.4).
- **Label**: a Publisher's signed statement about a subject outside its
  own authority, under a name from WIST-4 §6's Label Registry (§3.3).
- **Labeler**: a Publisher in its capacity as the signer of Labels.
- **Label Feed**: the signed list of a Labeler's recent Label IDs, with
  the shape and rules of the Feed (§3.3).

Terms defined in WIST-1 (Publisher, Aggregator, Delta, Delta ID, Envelope,
Key Set, Canonical Host, Normalized URL, Payload, Publisher Declaration)
are used with their WIST-1 meanings. Every
Envelope in this document carries `wist_version` (WIST-1 §3.1) and the WIST-1
§4 signature block (`key_id`, `alg`, `value`).

## 3. Well-Known Layout

A conforming Publisher serves, over HTTPS only:

```
/.well-known/wist/publisher.json     (identity — WIST-1 §5)
/.well-known/wist/deltas/<id>.json   (one file per Delta)
/.well-known/wist/payloads/<id>.json (one file per content-bearing Delta)
/.well-known/wist/feed.json          (the Feed)
/.well-known/wist/feed/<n>.json      (sealed Feed Pages — §3.2)
/.well-known/wist/labels/<id>.json   (one file per Label — §3.3)
/.well-known/wist/label-feed.json    (the Label Feed — §3.3)
/.well-known/wist/label-feed/<n>.json (sealed Label Feed Pages — §3.3)
```

The Label paths exist only for a Publisher that labels; a Publisher
serving none of them is a Publisher with no Labels.

### 3.1. Delta and Payload Files

`deltas/<id>.json` contains exactly one Delta Envelope, where `<id>` is
the Delta ID (including the `sha256:` prefix is NOT used in the filename;
the filename is the 64-char hex digest, e.g.
`deltas/6cac5bdd...5120.json`). Delta files are immutable: once published
under an ID, the bytes MUST NOT change. Publishers SHOULD serve them with
long-lived cache headers (`Cache-Control: public, max-age=31536000,
immutable`).

`payloads/<id>.json` contains the Payload (schema:
[`schemas/payload.schema.json`](../schemas/payload.schema.json)) of the
Delta with that ID, and MUST be served for every content-bearing Delta
(WIST-1 §3.3). The filename uses the same 64-char hex digest, so the two
files of one Delta share a name and differ only in directory. A Payload
is unsigned; its integrity comes from the Delta's commitment (WIST-1 §3.6),
which every fetcher recomputes. Payload files are immutable while served,
under the same caching advice as Delta files — but unlike Delta files they
are erasable: a Publisher MAY stop serving a Payload, and MUST stop when
the content must be erased.

**Payload retention.** A Publisher MUST keep retrievable its URL's
**current anchor Payload** — the Payload of the last content-bearing Delta
in that URL's chain (WIST-3 §6.1) — for as long as it continues to emit
`attest` Deltas for that URL, because that Payload is the content an
`attest` still stands on (WIST-3 §6.1). A Publisher that must stop serving
it re-anchors the chain instead, by publishing an `update` with a fresh
Payload or a `delete`; what it MUST NOT do is keep attesting to content
nobody can obtain. Payloads of superseded Deltas carry no such obligation
on the Publisher; the Aggregator's own retention of them is WIST-3
§6.1's.

**Withdrawal ends that duty and every other reason to serve.** From the
height a `payload_withdrawal` for a Delta is sealed (WIST-3 §6.2), the
Publisher MUST stop serving that Delta's Payload at
`payloads/<id>.json`, and the retention duty above does not survive it —
the two do not compete, and where a Publisher would otherwise still be
attesting to the withdrawn anchor it re-anchors the chain as above.
Withdrawal reaching the Aggregator and the Mirrors but not the site that
first published the content would leave the salt on the open web at a
well-known path, and with it the commitment the salt keys (WIST-1 §3.6).
One serving
path left open is the whole of the guarantee gone, which is why WIST-3 §6.2
binds all three.

### 3.2. The Feed and its Pages

`feed.json` is an Envelope whose inner object is `feed` (schema:
[`schemas/feed.schema.json`](../schemas/feed.schema.json)): `domain`,
`generated_at`, `deltas` — Delta IDs in publication order, newest last —
and `next`. `generated_at` MUST be monotonically non-decreasing across
successive versions of `feed.json`; an Aggregator MUST discard a pull whose
`generated_at` has regressed, under `WIST2-E05`.

For each requested Canonical Host, the Aggregator MUST durably retain the
greatest `generated_at` of a live `feed.json` that passed §5's complete
field, domain and signature checks, including any required Declaration
retry. After those checks and before following `next` or admitting Deltas,
it MUST atomically compare and retain that timestamp. A smaller value is
`WIST2-E05`; equality passes. Failed field, domain or signature checks take
precedence and MUST NOT change the retained value. Failure to persist the
comparison result MUST stop the pull before Page or Delta work.

Later Page, Delta or Payload failures, budget suspension and an empty or
already-ingested Feed MUST NOT undo this observation. Sealed Pages neither
compare against nor advance this live-Feed value. The value survives restart
and all Declaration changes, including recovery settlement and identity
reset; it is scoped to the requested host, not a signing key or identity
interval. A host without a retained observation starts with its first
authenticated live Feed. The validator clock imposes no additional bound on
`generated_at`. See [ADR-0033](../decisions/0033-feed-regression-state.md).

**Publication order** is the order in which the Publisher first added each
Delta to the Feed. A Delta MUST NOT appear before the Delta named by its
`prev`.

**Page sealing.** When appending a Delta would make `deltas` exceed 1000
entries, the Publisher MUST first seal the current 1000 entries into an
immutable Page at `/.well-known/wist/feed/<n>.json`. `<n>` is a
zero-based counter assigned in sealing order — `0` for the first Page a
domain ever seals (its oldest content), incrementing by exactly one each
time a further Page is sealed, and never reused or reassigned once
published, so a Page's URL and bytes never change. The Publisher MUST
publish the new Page's file at its URL *before* removing the newly-sealed
entries from the live `feed.json` and updating its `next` — so at every
instant, each Delta being sealed is retrievable either from the live
`feed.json` (not yet cut over) or from the new Page (already published),
never from neither. Once cutover completes, `feed.json`'s `next` names the
highest-numbered (most recently sealed) Page's absolute URL. Each Page
carries the same schema and the same `domain`, and its own `next` names
the next-*older* Page — Page `<n-1>`'s absolute URL, or `null` for Page 0,
which has no older Page before it. Pages MUST partition the Publisher's
history: every Delta ID the Publisher has ever sealed MUST appear on
exactly one Page, never on two and never on none.

**Verification of sealed pages.** Verify a Page under WIST-1 §4 using the
signing entry named by its `sig.key_id` in the Declaration current at
`generated_at`. If no usable named entry verifies, try the Declaration
selected from the first following Block by the bridge below. An absent
current Declaration also permits this fallback. Each attempt MUST use that
Declaration's own named entry and public bytes; another alias of those bytes
does not supply the named entry or suppress fallback. Finding `sig.key_id`
in current does not suppress fallback when its entry fails verification.
No other Declaration supplies authority, and the Delta-only
`valid_from` comparison does not apply to Pages. A Page that verifies under
neither source is `WIST2-E04`.

Pages are immutable and never re-signed on rotation. A validator MUST NOT
reject a Page solely because its signing key has since been retired or its
authorizing Declaration had not sealed when the Page was cut.

A Page's `generated_at` is the instant of the cutover that sealed it — the
same value the `feed.json` published at that cutover carries — and not the
instant the entries on it were first added to the Feed. The Page is signed
at cutover, by whichever key the Publisher holds then, and the rule above
resolves its Key Set through this field; stamping it with an earlier
instant would resolve a Key Set that need not contain the key that signed
the Page, so a Page honestly sealed after a rotation would fail
verification under its own signature. Sealing order and page numbering
therefore agree with `generated_at` order, which is the same
non-decreasing sequence §3.2 already requires of successive `feed.json`
versions.

WIST-1 §5.2's historical-verification procedure cannot be applied directly
here: it resolves a Key Set by **Block height**, and Pages are never sealed
into the Log, so a Page has no height. The bridge is stated once, and it is
the only conversion permitted: the Key Set current at a `generated_at` is
the one declared by the domain's `publisher_declaration` Entry (WIST-3 §3.3)
with the greatest `sealed_at` not later than that `generated_at` — the
highest `seq` among them where one Block seals several, which is the Key
Set WIST-1 §5.2 resolves at that Block's height — with
WIST-1 §5.2's recovery exception applied to that comparison exactly as it is
applied to the by-height one, so a Declaration superseded by a recovery
rotation is excluded here too. `sealed_at` is strictly increasing across
Blocks (WIST-3 §3.1), so the ordering by `sealed_at` and the ordering by
height are the same ordering; what changes is only the key the Consumer
looks the Declaration up by, because a Page carries a timestamp and not a
height. Every input is in the Log, so two validators resolve the same Page
to the same Key Set. Because that comparison is against a Block's
`sealed_at`, `generated_at` carries the same whole-second, literal-`Z` form
`sealed_at` does (`schemas/feed.schema.json`, WIST-3 §3.1): the two values
compare directly, with no normalization step for two implementations to
perform differently.

A Page can be cut under a key no sealed Declaration yet holds. The
Publisher rotates and seals a Page in one act, and the Declaration
recording the rotation seals only when an Aggregator next pulls it — or,
before first contact, when an Aggregator first learns the domain exists,
which can be a thousand Deltas and several Pages after the Publisher
started. A Delta has no such gap, because an Aggregator seals a
Declaration before or beside the first Delta it authorizes (WIST-3 §3.3)
and seals a Delta only where the Key Set at its height verifies it
(WIST-1 §5.2); a Page is never sealed, so nothing holds it. The second
resolution above closes the gap: fallback selects the Key Set of the
**first** Block sealed after `generated_at` that seals an
applicable Declaration of the domain — the same recovery exception
applied — the Publisher's own act attested one seal late. Where that
Block seals several Declarations of the domain, the Key Set is the
highest `seq`'s, exactly as at a height: the lower one was the Key Set
at no instant — WIST-1 §5.2 resolves the higher `seq` at that Block —
and a Page accepted under it would be one no Delta could ever have been
sealed under. It is the first such Block and not any later one, so a
Page cannot claim a key from a rotation two seals ahead; and both
lookups read Blocks every validator holds, so two validators still
resolve one Page to one answer. A Page cut before the domain's first
Declaration sealed resolves, by the same rule, to that Declaration's
Key Set.

**Aggregator obligation.** On each pull, an Aggregator MUST follow `next`
until it reaches a page whose newest Delta ID it has already ingested, or
until `next` is `null`, applying the same diff-fetch-validate-queue
procedure (§5 steps 2–4) to every page's `deltas` as to the live
`feed.json`'s. Diffing only the live `feed.json` is non-conforming and
loses Deltas whenever more than one window's worth is published between
pulls.

**Target rule.** An Aggregator reads `next` only when the walk continues
past the object carrying it: after that Feed or Page passed §5's field,
domain and signature checks — and, for the live `feed.json`, the
`generated_at` comparison — and only if it lists a Delta ID not yet seen.
An unread `next` is checked against nothing. A `next` the Feed schema
rejects — not a string, not `https`, carrying a fragment — is a field
failure of its whole Feed or Page under §5 and never reaches this rule. A
read `next` MUST be byte-identical to its own Normalized URL (WIST-1 §2)
and MUST begin with `https://`, the requested Canonical Host and
`/.well-known/wist/`, in those octets: no userinfo, no port, no
`subdomain_scope` host, and a query fetched as written. No Declaration
supplies this rule's inputs, so a retry, rotation or recovery settlement
cannot change a target's disposition; §8 still governs redirects from an
accepted target. A `next` failing the rule is `WIST2-E01`: the walk stops
there with no usable Page, exactly as it stops at a Page it cannot fetch,
an Aggregator MUST NOT fetch it, and the Deltas of the Feed and Pages
already fetched proceed under §5. Byte-identity decides encoded
spellings: `%2E%2E`, `%7e` and `:443` normalize away, so no URL spelling
them is identical to its normalization, while `%2F` stays encoded and a
path beginning `/.well-known/wist%2F` does not begin with the prefix.

**Caching.** Publishers SHOULD serve `feed.json` with `Cache-Control:
no-cache` and an `ETag`; Aggregators SHOULD use conditional requests. A
pull that returns `304` is not `WIST2-E02` and MUST NOT count as noise.
Sealed Pages are immutable and SHOULD instead be served with long-lived
cache headers, as in §3.1.

### 3.3. Labels

A Publisher MAY publish **Labels**: signed statements about subjects
outside its own authority, each under a name from the Label Registry
(WIST-4 §6). A Label is an Envelope whose inner object is `label`
(schema: [`schemas/label.schema.json`](../schemas/label.schema.json)),
carrying:

- `wist_version` (WIST-1 §3.1);
- `labeler` — the Labeler's Canonical Host, in the form and with the
  binding a Delta's `publisher` carries (WIST-1 §3.8): the Label's
  identity and its signature authority;
- `subject` — a Normalized URL (WIST-1 §2), byte-identical to its own
  normalization, or a Canonical Host; in JCS octets it MUST NOT exceed
  `url_cap_bytes` (WIST-4 §5);
- `name` — a Label Registry name (WIST-4 §6);
- `value` — OPTIONAL, an integer in micro-units, 0 … 1 000 000;
- `asserted_at` — the instant the Labeler asserts the statement for, a
  Publisher timestamp under WIST-1 §3.4's profile and clock rule, read
  exactly as a Delta's `observed_at`;
- `retracted` — OPTIONAL, `true` where the Label withdraws the Labeler's
  earlier Label of the same `name` on the same `subject`;
- `expires_at` — OPTIONAL, the instant from which the Label applies
  nothing, a Publisher timestamp under the same profile as
  `asserted_at`; it MUST be later than `asserted_at`, and one that is
  not is `WIST2-E06`;
- `delta` — OPTIONAL, only with a Normalized URL `subject`, a Delta ID
  that binds the Label to one publication: the Label applies only while
  the subject URL's record stands on that anchor Delta (WIST-3 §7) and
  covers no later publication of the URL. A `delta` beside a Canonical
  Host `subject`, or one that is not a Delta ID, is `WIST2-E06`; whether
  the Delta is sealed in any Log is not checked, since a Labeler may
  bind to a publication another Log sealed.

Those nine members and no others. The **Label ID** is `"sha256:" +
hex(SHA-256(JCS(label)))`, the construction WIST-1 §4 uses for a Delta
ID. A Label is signed under the Labeler's Key Set by the rule a Delta is
signed under (WIST-1 §5.2), with `asserted_at` in the place of
`observed_at` for key validity, and WIST-1 §4's profile; `labeler` MUST
equal the Declaration's `domain` (WIST-1 §3.8).

**Self-labeling is rejected.** A Label whose `subject` is a Normalized
URL under the Labeler's own authority — its `domain` or a host its
`subdomain_scope` names (WIST-1 §3.2) — or a Canonical Host equal to that
domain or to a scoped host, is a statement about the Labeler itself,
which WIST-4 §4 forbids: it is rejected under `WIST2-E06` and never
sealed. Everything else is outside the scope rule by design: a Label is
an opinion about another party, and the Log records who signed it.

**Files and the Label Feed.** `labels/<id>.json` contains exactly one
Label Envelope, named and served exactly as `deltas/<id>.json` is (§3.1):
immutable once published, the filename the 64-character hex digest of
the Label ID. `label-feed.json` is an Envelope whose inner object is
`feed` with §3.2's schema, `domain`, `generated_at`, `next` and rules —
the Feed's sealing, page numbering at `label-feed/<n>.json`,
`generated_at` monotonicity, `feed_window`, retained-observation and Page
verification rules apply unchanged — except that its `deltas` member
lists Label IDs in publication order. A Labeler's Label Feed is its own
sequence, separate from its Feed; the two share a Declaration and a Key
Set.

**Which Label is current.** For each (labeler, subject, name), the
Labeler's current Label at a height is the sealed Label with the
greatest `asserted_at`, and among equal instants the one later in Log
order (WIST-3 §3.3: ascending Block height, then Entry index). A current
Label with `retracted` `true` means the Labeler asserts nothing about
that subject under that name; every earlier Label stays sealed. A Label
whose `asserted_at` is earlier than the current Label's is sealed and
applies nothing. A current Label with an `expires_at` applies nothing
at a Block whose `sealed_at` is at or after that instant — compared as
instants, the Publisher timestamp converted exactly — and it stays the
current Label, so an earlier unexpired Label does not return; a Labeler
that wants the subject labeled again asserts anew. Consumers read
Labels through their Snapshot tuples and `tier1/labels.parquet` (WIST-3
§7), which carry the current, unretracted, unexpired Labels with their
`expires_at` and `delta`, and apply only the Labelers they subscribe to
(WIST-4 §6).

**Label definitions.** A Labeler SHOULD publish, for every `name` it
uses, a **label definition**: an Envelope whose inner object is
`definition` (schema:
[`schemas/label-definition.schema.json`](../schemas/label-definition.schema.json)),
carrying `wist_version`, `labeler` (bound as a Label's is), the `name`,
a `description` — a Normalized URL where the Labeler describes what the
name means and how it applies it — a `treatment`, one of `hide`, `warn`
and `inform`, the treatment a Consumer applies to the name's subjects
when its own profile names none (WIST-4 §6), and `asserted_at`, read
as a Label's. It is served at `labels/definitions/<hex>.json`, where
`<hex>` is the lowercase hex SHA-256 of the name's UTF-8 octets, and is
signed under the Labeler's Key Set as a Label is. A definition is not
sealed and not pulled by an Aggregator: a Consumer fetches it for each
name of a Labeler it subscribes to, keeps the newest `asserted_at` that
verifies, and treats a name with no verifiable definition as `inform`.
A definition for a `wist` term describes the Labeler's own application
of the registry's meaning, which it cannot change.

**Disputes.** The domain a Label is about MAY publish a **dispute**: an
Envelope whose inner object is `dispute` (schema:
[`schemas/dispute.schema.json`](../schemas/dispute.schema.json)),
carrying `wist_version`, `disputant` — the disputing Publisher's
Canonical Host, bound as a Label's `labeler` is — `label`, the disputed
Label's ID, `log` and `height`, the `log_id` and Block height at which
the disputant saw the Label sealed, an OPTIONAL `reason`, a Normalized
URL where the disputant states its grounds, and `asserted_at`, read as
a Label's. Those seven members and no others; the **Dispute ID** is the
Label ID construction over `dispute`. A dispute is published at
`labels/<id>.json` beside the Labels — the directory holds Label and
Dispute Envelopes alike, told apart by their inner member — and listed
in the Label Feed like a Label. It is signed under the disputant's Key
Set by the rule a Label is signed under. The self-labeling rule does not
apply: a dispute references a Label rather than asserting anything
about its signer, and the opposite constraint holds instead — the
disputed Label's `subject` MUST lie under the disputant's authority
(its `domain` or a scoped host, or a URL under either, WIST-1 §3.2), and
the Label MUST already be sealed in the Log the Aggregator seals; a
dispute failing either, or a field check, is `WIST2-E06` and never
sealed. `log` and `height` are the disputant's citation: an Aggregator
MUST NOT reject a dispute for naming another Log or a height at which
its own Log did not seal the Label. For each (label, disputant) the
current dispute is chosen as a Label is, by `asserted_at` and then Log
order. A dispute is never applied by the Aggregator or a Snapshot
builder: it alters no Label, tuple or record. It is sealed as a
`dispute` Entry (WIST-3 §3.3), carried as a `dispute` tuple and
materialized in `tier1/disputes.parquet` beside the labels (WIST-3 §7),
so that a Consumer weighing a Labeler sees what the labeled parties
answered, without any party in the suite deciding who is right.

**Pull.** Whenever an Aggregator pulls a domain's Feed — on a Ping and at
the baseline interval alike (§5) — it MUST also fetch `label-feed.json`
where the domain serves one, walk it under §3.2's rules and §5's ingest
budget, fetch each ID it has not sealed, validate the Label or dispute
under this section and WIST-1 §4, and queue it for sealing as a `label`
or `dispute` Entry (WIST-3 §3.3) under the eligibility and ceiling
WIST-4 §5 gives a Delta and the per-Labeler cap of WIST-3 §3.2. A Label
or dispute that fails is `WIST2-E06`, reported at the status endpoint
(§7.1) with its ID, and pulled again on the next pull like a rejected
Delta (§5). A Label ID or Dispute ID an Aggregator has sealed is seen,
exactly as a Delta ID is.

## 4. The Ping

To notify an Aggregator, a Publisher sends:

```
POST https://<log_id>/ingest
Content-Type: application/json

{"host": "example.com"}
```

`host` MUST be a Canonical Host (WIST-1 §2). An Aggregator MUST reject a
ping whose `host` is not canonical, and MUST reject a Feed whose
`feed.domain` differs from the host it was fetched from, with
`WIST2-E04` (§7): a Feed naming another domain does not authenticate as
this domain's Feed, whatever its signature verifies against.
The field-validation precedence in §5 applies before this comparison.

The Ping carries no content and no signature; authenticity comes from the
subsequent HTTPS pull of the signed Feed and Deltas. Responses:

| Status | Meaning |
|--------|---------------------------------------------------|
| 202 | Accepted; a pull will follow |
| 429 | Rate-limited; MUST include `Retry-After` |
| 403 | The Aggregator does not ingest this domain, for a reason outside this suite — an operator's legal obligation is the case foreseen. The refusal MUST be visible as the `refused` state at the status endpoint (§7.1), and WIST-4 §4's invariants still bind: a refusal is not for sale and never a treatment of one Publisher's content against another's. |

On a 5xx, timeout, or connection failure a Publisher SHOULD retry at most
three times with exponential backoff (1 min, 4 min, 16 min) and then rely
on the Aggregator's baseline polling; it MUST NOT retry a 4xx other than
429.

The Ping quota Q is `quota_base` Pings per UTC day per Registrable
Domain (WIST-4 §5), the same for every Registrable Domain: a Ping for a
Canonical Host counts against the Registrable Domain of that host under
the Public Suffix List snapshot in force at the Ping (WIST-4 §3.1), so
hosts under one registrable name share one quota while hosts under a
private-section suffix hold their own. Counts are kept per Registrable
Domain as named under the snapshot in force at each Ping: when an
accepted `suffix_list_update` changes a host's Registrable Domain
inside a day, the Pings already counted stay under the unit they were
counted against, and from its next Ping the host counts against the
unit it now belongs to, starting from whatever that unit already
carries. Only pings resolving to
`WIST2-E02` or `WIST2-E04` count against it; productive pings do not.
Once Q is reached, every Ping for a host of that Registrable Domain
yields `429` until the UTC-day window resets.

## 5. Aggregator Pull Behavior

On receiving a Ping for a known-or-new domain, the Aggregator:

0. **First contact.** If the domain is unknown, the Aggregator MUST fetch
   and verify `publisher.json` (WIST-1 §5.1) before any Feed pull, seal it
   as a `publisher_declaration` Entry (WIST-3 §3.3), and apply the Ping
   quota of WIST-4 §5. A missing or invalid Declaration is a
   `WIST2-E04` rejection.

   **Ingest budget.** §3.2's obligation to walk sealed Pages has no page
   cap, so a first contact — or a long-dormant domain's return — can
   demand a domain's entire history, and a hostile domain can make that
   history arbitrarily deep: a single Ping would otherwise oblige
   terabytes of pulls, an amplification no quota reaches because
   productive pings are unmetered (§4). The Aggregator therefore
   applies a per-domain budget, accounted per Registrable Domain
   (WIST-4 §3.1) so that a free hostname is not a free budget, keyed at
   each fetch as §4 keys the quota at each Ping: it MUST
   fetch no more than
   `ingest_budget_bytes_day` (Parameter Registry; default 1 GiB) of
   Feed pages, Deltas and Payloads for the hosts of one Registrable
   Domain per UTC day, MAY
   suspend the walk when the budget is spent, and MUST resume it —
   from where it stopped, which §3.2's "until already-ingested" rule
   makes well-defined — on a later day rather than treat the suspension
   as completion. The budget bounds the walk without breaking it: an
   honest large site backfills across days; a hostile deep feed costs
   its own hosting bill, not the Aggregator's month. An Aggregator MAY
   suspend a walk below the budget under a per-pull limit of its own, in
   octets or in objects, so that one Ping cannot hold a pull for a whole
   day's budget; it resumes such a walk as it resumes a budget
   suspension, and a walk suspended below the budget and resumed on a
   later pull satisfies §3.2's until-already-ingested rule the same way.
   An object that would cross the remaining budget or the per-pull limit
   is not read past the bound: the octets read are debited and the walk
   suspends there. An object above its own §8 response bound is a failed
   fetch, not a suspension, and debits nothing.

   Declaration discovery is outside this byte budget: initial, periodic and
   failure-triggered `publisher.json` requests MUST NOT debit it. Exhaustion
   MUST NOT defer a required Declaration retry for an already-fetched object
   or turn a failed retry into suspension. Content fetching still suspends
   at the budget boundary; discovery alone neither completes the walk nor
   makes an unusable Feed usable. Discovery remains subject to WIST-1 §5.1
   and §8's transport rules. See [ADR-0031](../decisions/0031-declaration-refresh.md).
1. Fetches `feed.json`. Before domain comparison or signature verification,
   the Aggregator MUST validate the complete Feed Envelope against its schema,
   including formats and WIST-1 §4 canonicalizability. This gate applies to
   sealed Pages too. A failure is `WIST2-E01`, including when a malformed
   domain also differs from the requested host or a malformed signature would
   fail verification. Do not normalize signed fields or trigger the
   failure-driven Declaration retry for a field failure. Feed/Page
   `wist_version` MUST contain exactly three dot-separated ASCII decimal
   components with no leading zeros except `0`, no suffix and no numeric upper
   bound. `generated_at` uses WIST-3 §3.1's exact Log-comparable timestamp
   profile, including Gregorian calendar validation. After this gate, a
   `feed.domain` differing from the requested host is `WIST2-E04` without a
   Declaration retry, even if the signature also fails. The existing §7 noise
   and backoff dispositions apply. See
   [ADR-0032](../decisions/0032-feed-field-diagnostics.md).

   Verifies its signature against the domain's Key
   Set (WIST-1 §5). A Feed the Aggregator cannot use is `WIST2-E01` and is
   retried on the backoff schedule of §7 — one that cannot be fetched at
   all, and one fetched but unusable: not well-formed JSON, failing the
   Feed schema, or naming a `next` that fails §3.2's target rule
   (§3.2). The two share a code because they share a remedy and a
   remedier: the Aggregator holds no Feed either way, nothing about the
   domain's state has changed, and only the Publisher can fix it. A Feed whose signature does
   not verify against the Key Set the Aggregator holds MUST trigger one
   re-fetch of `publisher.json`, evaluated under WIST-1 §5.2, and a
   second verification of the same Feed bytes against the Key Set that
   results, before the pull is `WIST2-E04`: a Publisher that rotates
   signs its next Feed under a key the Aggregator's cached Key Set (WIST-1
   §5.1) does not yet hold, and without the re-fetch every pull until the
   cache expired would be noise against its quota and its Deltas would
   wait a day. The re-fetch is one per failing pull, so a Feed that
   fails under the current Declaration too costs the same one rejection
   it did before.

   The live Feed and all sealed Pages share this one failure-triggered
   Declaration attempt per pull. A sealed Page whose signature fails both
   §3.2 sources MUST trigger it if unused; initial/periodic discovery does
   not consume it. A failed, invalid or unchanged response consumes the
   attempt. Reverify the same Page Envelope using §3.2's authenticated Log
   sources, never the fetched Declaration merely because it was accepted
   for admission. Without an applicable sealed source, the Page remains
   `WIST2-E04`; a later pull can succeed after inclusion. A failure after
   the shared attempt was used is `WIST2-E04` without another request.
   Declaration retry traffic creates no separate noise event, and the
   content-budget exclusion above applies to this attempt too.

   **Delta Declaration retry.** When live ingestion checks a fetched Delta's
   binding under WIST-1 §5.1 and obtains `WIST1-E01` or `WIST1-E02`, it MUST
   re-fetch `publisher.json` once before rejecting for that binding failure.
   This includes absent, excluded and not-yet-valid named bindings, as well
   as eligible bindings whose signatures fail. Apply the retry separately
   to each distinct requested Delta ID within the domain's pull, including
   retrieved predecessors. Repeated occurrences or revalidation of that ID
   during the same pull, including after predecessor retrieval or recovery
   settlement, share the attempt; they MUST NOT trigger another. A later
   pull starts new attempts. Initial/periodic discovery and the shared
   Feed/Page retry do not consume any Delta's attempt; neither does another
   Delta's retry. A pull here includes its live Feed, Page walk and
   all predecessor, Delta and Payload processing until completion or
   suspension; resumption is a later pull.

   Evaluate the fetched Declaration under WIST-1 §§5.1–5.2, retaining only
   accepted authority. A failed request or invalid/unchanged response still
   consumes the attempt. Then reverify the same Delta Envelope bytes under
   the resulting admission sources, applying any recovery settlement due
   before admission. Retry success does not waive scope, fields, version,
   clock, predecessor, Payload or other admission checks. A malformed field
   or foreign-Publisher association alone MUST NOT trigger this retry;
   other semantic failures alone do not trigger it either. WIST-1 §7 still
   permits rejection for another established semantic failure without
   performing a binding check. Record a remaining binding failure using
   its post-retry E02/E01 result. Declaration retry traffic adds no noise
   event of its own; the enclosing Feed or Delta retains §7's disposition.
   These live Delta rules do not change §3.2's sealed-Page source selection.
2. Diffs `feed.deltas` against the IDs it has already seen for the
   domain, following `next` through sealed Pages as required by §3.2.
   An ID is seen when the Aggregator has sealed it or holds it accepted
   for sealing — queued, or held under a recovery window — and not
   otherwise (WIST-1 §3.5). An ID rejected on an earlier pull, for a
   transient cause (`WIST2-E03` on a momentary `404`, `WIST1-E06` on
   skew) or a lasting one, is therefore pulled again on the next pull
   and, failing again, rejected again, the rejection recorded afresh
   (§7.1) and the pull disposed of against the quota as §4 says for its
   code. Republishing byte-identical files yields the same ID, so a
   Publisher that has fixed what was wrong is pulled once more and one
   that changed nothing is refused once more.
3. Fetches each new `deltas/<id>.json`; validates each per WIST-1 (§4, §7),
   retrieving and validating first, in chain order, any `prev` it has not
   sealed (WIST-1 §3.5).
   After WIST-1's mandatory Delta field checks, its signed `publisher` MUST
   equal the authenticated Feed or Page's `domain`; otherwise reject that
   Delta with `WIST2-E03`. The same association check applies to fetched
   predecessors and precedes idempotent acceptance: an ID accepted for
   another domain is not a seen ID for this domain. Compare the logical
   Publisher being pulled, not a redirect destination (§8) or Mirror host.
   This rejection neither attributes the foreign Delta to the Feed's domain
   nor invalidates it under its actual Publisher; it does not count as Ping
   noise (§4). Scope failure against the signed Publisher remains WIST1-E03.
   A fetched JSON Delta Envelope's field failures retain WIST1-E14 under
   WIST-1 §7, even if its signature fails, its ID differs from the requested
   ID, or its Publisher differs from the Feed domain. WIST2-E03 covers
   unavailable or non-JSON Delta responses and, after mandatory field
   checks, mismatched Delta IDs; it does not wrap WIST-1 field diagnostics.
   For every content-bearing Delta it also fetches the corresponding
   `payloads/<id>.json` in the same pass and verifies it against the
   Delta's commitment and `bytes` (WIST-1 §3.6). A Delta whose Payload is
   unavailable, malformed, or fails that verification at pull time MUST be
   rejected with `WIST2-E03` and MUST NOT be sealed: the Aggregator cannot
   undertake to serve (WIST-3 §6.1) content it never received, and a Delta
   sealed without its Payload would have nothing to materialize.
4. Queues accepted Deltas for the next log block (WIST-3 §3), and the
   Payloads it verified for publication alongside the Block that seals
   them (WIST-3 §6.1). A queued Delta is sealed only where it verifies
   under the Key Set WIST-1 §5.2 resolves at the sealing Block: one whose
   signing key a Declaration accepted since the pull has retired is
   `WIST1-E02` at sealing, reported (§7.1) and not sealed, and its ID is
   pulled again once the Publisher re-signs it (step 2).
5. **Labels.** Fetches `label-feed.json` where the domain serves one,
   under the same walk, budget and seen rules as the Feed, fetches each
   unseen Label, validates it under §3.3 and queues it for sealing like a
   Delta; a rejected Label is reported (§7.1) and pulled again on the
   next pull.

Aggregators MUST also poll known feeds at a low baseline frequency
(default: every 24 hours, a Parameter Registry value — WIST-4 §5) regardless
of Pings. A lost Ping therefore delays ingestion but never loses data.

The `/.well-known/wist/` path is published *for* automated consumption
by Aggregators; `robots.txt` directives do not apply to fetches under
this path. This suite obliges no fetch of any other path: nothing in it
compares a page with its publication, so a Publisher's `robots.txt`
governs whatever a Labeler or a Consumer chooses to fetch on its own
account and nothing the protocol requires.

## 6. Unsigned Change Hints (Compatibility)

Aggregators MAY consume existing ecosystems as Change Hints: IndexNow
pings, sitemap `<lastmod>` changes, and llms.txt updates.

An unsigned hint MUST NOT produce content attributed to the domain.

For every URL, with signed Deltas or without, hints only inform the
Aggregator's pull scheduling — they produce no log entries.

The signed path always has higher weight and lower latency: signed Deltas
enter the log directly on the publisher's authority, while hints are
second-class — unattributed, scheduled at the system's convenience. This
asymmetry is the adoption incentive for WIST-1/WIST-2.

## 7. Error Registry

| Code | Meaning and required behavior |
|---------|--------------------------------------------------------------|
| WIST2-E01 | Feed unusable after Ping: unreachable, or fetched and unusable — not well-formed JSON, failing the Feed schema, or naming a `next` that fails §3.2's target rule (§3.2, §5). Aggregator retries with exponential backoff at 1 min, 4 min, 16 min, 64 min; a fresh ping cancels a pending backoff and starts a new attempt, subject to quota. The pull is not noise (§4): the backoff, not the quota, is what bounds a domain that keeps serving one. |
| WIST2-E02 | Ping produced no new feed content. Counts as noise against the domain's Ping quota. |
| WIST2-E03 | Delta whose signed `publisher` differs from the authenticated Feed/Page domain (§5), or a Delta referenced in Feed but missing or corrupted at `deltas/<id>.json`, or a content-bearing Delta whose `payloads/<id>.json` is missing, corrupted, or does not reproduce its commitment (WIST-1 §3.6). Typed rejection, visible to the Publisher via the status endpoint (§7.1). |
| WIST2-E04 | First contact or Feed authentication failure. Three cases, one code, each one of the Feed failing to authenticate as this domain's: a Feed whose signature does not verify against the domain's Key Set even after the one Declaration re-fetch §5 step 1 requires; a Feed whose `feed.domain` differs from the host it was fetched from (§4), which authenticates as some other domain's Feed or as none, whatever key signed it; and a first-contact pull (§5 step 0) whose `publisher.json` is missing, unreachable, malformed, or fails WIST-1 §5.1 verification — the last being the case where no Key Set exists to check the first against. The pull is discarded; counts as noise against the quota. The status endpoint (§7.1) MUST distinguish them in its `detail` field, since a Publisher whose Declaration never loaded, one whose Feed signature is wrong, and one serving a misaddressed Feed take entirely different remedies. |
| WIST2-E05 | Feed `generated_at` regression. The pull is discarded; it does not count against the quota — §4's noise set is closed at `WIST2-E02`/`WIST2-E04`. |
| WIST2-E06 | Label rejected (§3.3): a Label referenced in the Label Feed but missing or corrupted at `labels/<id>.json`; a field, version or JSON eligibility failure under WIST-1 §4 and §7's rules read over the `label` object; a `subject` that is not its own Normalized URL or Canonical Host, or exceeds `url_cap_bytes`; a `name` outside the Label Registry's form; an `asserted_at` beyond the clock allowance; a `labeler` other than the Feed's authenticated domain; or a self-labeling Label. A signature or key-binding failure keeps `WIST1-E01`/`WIST1-E02`. Typed rejection, visible to the Labeler via the status endpoint (§7.1) with the Label ID as `delta_id`; not noise. |

### 7.1. Publisher Status Endpoint

Aggregators MUST expose `GET https://<log_id>/status/<domain>` at the
Service Origin (WIST-3 §6), returning the
`status` object (schema:
[`schemas/status.schema.json`](../schemas/status.schema.json)) as JSON. It
carries `wist_version`, the `domain` it describes, and:

- `last_pull_at` — the time of the last successful pull, or `null` if the
  Aggregator has never completed one;
- `quota_remaining` — Pings still available to the domain's Registrable
  Domain in the current UTC-day window, against the `Q` of WIST-4 §5,
  shared with every other host of that Registrable Domain (§4);
- `state` — the domain's **ingestion** state: one of `new` (known, not yet
  successfully pulled), `active`, or `refused` (the Aggregator does not
  ingest the domain — the one state §4 answers a Ping with `403` for);
- `rejections` — the pending typed rejections, each with its `code` (a
  WIST-1 or WIST-2 error code, §7 and WIST-1 §7), the `at` it was recorded, the
  `delta_id` it concerns where one applies, and a free-text `detail`.

The status document is a plain JSON object, not a signed Envelope — it is
the Publisher's debugging surface, not an artifact other parties verify.

## 8. Security Considerations

- **Ping flooding.** Pings are the cheapest object in the system by
  design: no content, no crypto, one small POST. Amplification is
  bounded, not minimal by nature: in steady state a Ping triggers one
  conditional Feed fetch, but a first contact obliges the §3.2 page
  walk, whose depth the pinging domain controls — which is why §5's
  per-domain ingest budget, not the Ping's own cheapness, is the
  content-walk bound; Declaration discovery is excluded (§5). Quotas
  (WIST-4 §5) throttle abusive domains, and both the quota and the
  budget are keyed per Registrable Domain (WIST-4 §3.1), so a flood
  from a thousand free hostnames under one name is one domain's flood;
  Ingest Endpoints SHOULD additionally apply source-IP rate limits below the
  per-domain quotas.
- **Feed replay.** An attacker replaying an old `feed.json` cannot
  regress state: signatures bind content, `generated_at` monotonicity
  detects rollback, and Deltas already seen are idempotent (WIST-1 §4).
- **Cache poisoning of `.well-known`.** All discovery and pulls are
  HTTPS-only; Aggregators MUST NOT accept any `wist` resource
  over plain HTTP. An Aggregator MUST follow a redirect only when the
  target is `https` and its Canonical Host equals the Canonical Host of
  the request, or is listed in the Publisher's `subdomain_scope`.
  Apex-to-`www` redirects are therefore conforming when `www` is in
  scope. The target rule bounds *where* a chain can go and not how long
  it runs, and two in-scope hosts pointing at each other satisfy it for
  ever, so two bounds close the chain: an Aggregator MUST NOT follow a
  redirect to a URL already fetched in the same chain, and MUST NOT
  follow more than five in one. A resource whose chain exceeds either is
  not retrieved, which is `WIST2-E01` for a Feed like any other failure
  to fetch. Five is chosen rather than derived: a publication path
  needing a sixth hop to reach its own well-known file is misconfigured
  rather than unlucky.
- **Redirect authority per request.** The `subdomain_scope` a redirect
  target is checked against is the one in the Declaration accepted at
  the instant the request is issued: a replacement accepted earlier in
  the same pull governs the requests after it, and a host the
  replacement dropped no longer authorizes a redirect. Before the first
  accepted Declaration — during first contact (§5) — a redirect MUST
  stay on the requested Canonical Host.
- **Fetch destinations.** A Publisher chooses where every fetch goes —
  its Canonical Host, each redirect target and the addresses its names
  resolve to — so an Aggregator's fetcher is a request an outside party
  aims from inside the Aggregator's network. An Aggregator MUST connect
  only to a public unicast address: it checks a literal host, every
  redirect hop and every address a name resolves to at connection time,
  and refuses a name whole when any address it resolves to is refused.
  The refused classes are, for IPv4, loopback (127.0.0.0/8), unspecified
  (0.0.0.0), private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
  link-local (169.254.0.0/16, where cloud metadata services live),
  shared address space (100.64.0.0/10), broadcast (255.255.255.255),
  multicast (224.0.0.0/4), documentation (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24), benchmarking (198.18.0.0/15) and reserved
  (240.0.0.0/4); for IPv6, loopback (::1), unspecified (::), unique
  local (fc00::/7), link-local (fe80::/10), multicast (ff00::/8) and
  documentation (2001:db8::/32); an IPv4-mapped (::ffff:0:0/96), 6to4
  (2002::/16) or NAT64 (64:ff9b::/96) address takes the class of the
  IPv4 address it embeds. A deployment that runs the whole stack on one
  machine MAY admit loopback alone, under the same explicit opt-in that
  admits plain HTTP to it. A refused destination is a failed fetch:
  `WIST2-E01` for a Feed or Page, and for a Delta or Payload the
  disposition §5 gives an object it cannot retrieve.
- **Response bounds.** No field check applies before an object has been
  read, so the octets an Aggregator reads are bounded before the fields
  are. An Aggregator MUST NOT read more than 1 048 576 octets of a
  Declaration, Feed, Page or Mirror list (WIST-3 §5); 16 384 + 2 ×
  `url_cap_bytes` octets of a Delta file; or `extract_cap_bytes` +
  `links_cap_bytes` + `summary_cap_bytes` + 4 096 octets of a Payload,
  each parameter read from the map in force at the request (WIST-4 §5).
  The fixed terms cover what the caps do not reach — signatures,
  identifiers, timestamps, framing and the Payload salt — and the flat
  bound covers objects whose fields the schema bounds by count and
  length rather than by a parameter. An object above its bound is a
  failed fetch with the dispositions above. The vector
  `vectors/wist2/fetch-bounds.json` exercises this rule and the two
  before it. See [ADR-0044](../decisions/0044-fetch-bounds.md).

## 9. Privacy Considerations

Pings reveal publication timing to the Aggregator, and Feeds are public
by construction — a Publisher's activity pattern is observable by anyone.
No reader or consumer data is involved at this layer: WIST-2 concerns only
the Publisher→Aggregator direction, and Publishers learn nothing about
who consumes their Deltas.

## 10. Conformance Checklist

This checklist is not the document's last section: §11 defines the link
extraction procedure the Publisher row below is stated over, and it
follows here rather than preceding it so that the pull sequence stays
adjacent to the layout it walks.

**Publisher:**

- [ ] Serves the well-known paths over HTTPS with the layout of §3
- [ ] Delta files are immutable and named by hex digest (§3.1)
- [ ] Serves a Payload for every content-bearing Delta, at the matching
      hex-digest name, and keeps the anchor Payload of every URL it
      attests retrievable (§3.1)
- [ ] Declares `content.links` by §11's extraction procedure exactly,
      truncated to the longest prefix that fits `links_cap_bytes` (§11,
      WIST-1 §3.6)
- [ ] Stops serving a Payload from the height a `payload_withdrawal`
      naming its Delta is sealed — the retention duty above does not
      survive it — and re-anchors the chain rather than keeping the
      withdrawn Payload published in order to go on attesting
      (§3.1, WIST-3 §6.2)
- [ ] Where it labels, serves each Label at `labels/<id>.json` and lists
      it in a Label Feed under §3.2's rules, signs it under its Key Set,
      names a registry `name`, places `expires_at` after `asserted_at`,
      binds `delta` only to a URL subject, and never labels a subject
      under its own authority (§3.3)
- [ ] Where it labels, serves a signed definition of each name it uses
      at `labels/definitions/<hex>.json` with a description URL and a
      treatment (§3.3)
- [ ] Where it disputes, serves each dispute at `labels/<id>.json`,
      lists it in a Label Feed, names a sealed Label whose subject lies
      under its own authority, and signs it under its Key Set (§3.3)
- [ ] Seals Pages when `deltas` would exceed 1000 entries — file
      published before cutover, sealing-order numbering, no Delta
      omitted or duplicated across Pages, monotonic `generated_at` (§3.2)
- [ ] Pings with the exact one-field body of §4, honors `Retry-After`, and
      follows the retry/backoff rule of §4

**Aggregator (ingest side):**

- [ ] Implements the pull sequence of §5 with signature validation at
      every step
- [ ] Pulls each content-bearing Delta's Payload in the same pass, checks
      it against the Delta's commitment, and rejects with `WIST2-E03` rather
      than sealing a Delta whose Payload it does not hold (§5, §7)
- [ ] Performs First Contact (verifies `publisher.json` before any Feed
      pull for an unknown domain) (§5)
- [ ] Re-fetches `publisher.json` once, and re-verifies the Feed against
      the resulting Key Set, before a Feed signature failure is
      `WIST2-E04` (§5, §7)
- [ ] Follows `next` through sealed Pages until reaching already-ingested
      content or `null`; never diffs only the live `feed.json` (§3.2)
- [ ] Reads `next` only when the walk continues; fetches a target only
      when byte-identical to its Normalized URL and beginning with
      `https://`, the requested Canonical Host and `/.well-known/wist/`;
      otherwise records `WIST2-E01`, fetches nothing there and keeps the
      Deltas already fetched (§3.2)
- [ ] Treats an ID as seen only once sealed or held accepted for sealing,
      and pulls a rejected ID again on the next pull (§5, WIST-1 §3.5)
- [ ] Verifies a sealed Page against the Key Set current at its
      `generated_at`, or that of the first Block after it sealing an
      applicable Declaration — the highest `seq`'s where a Block seals
      several (§3.2)
- [ ] Applies the per-domain ingest budget to that walk, accounted per
      Registrable Domain, suspending and resuming across days rather
      than truncating it (§5, WIST-4 §3.1)
- [ ] Runs baseline polling independent of Pings (§5)
- [ ] Pulls a domain's Label Feed with its Feed under the same budget,
      validates each Label and dispute under §3.3 — a dispute only of a
      Label it has sealed whose subject lies under the disputant's
      authority — seals what verifies under the per-Labeler cap and
      reports `WIST2-E06` for the rest (§3.3, §5, §7, WIST-3 §3.2)
- [ ] Never attributes unsigned-hint content to a domain (§6)
- [ ] Implements the Error Registry behaviors and the status endpoint (§7)
- [ ] Accounts pings correctly against the Registrable Domain's quota
      under the snapshot in force — only `WIST2-E02`/`WIST2-E04` count
      as noise (§4, WIST-4 §3.1)
- [ ] HTTPS-only, same-authority-only fetching, per the Canonical Host /
      `subdomain_scope` redirect rule (§8)

## 11. Link Extraction

A Publisher declares its page's external links in the Payload's `links`
member (WIST-1 §3.6) by the procedure below. The procedure is
deterministic so that two tools deriving a publication from the same
page declare the same links, and so that a Labeler or Consumer that
chooses to compare a page with its publication can apply it too; nothing
in this suite obliges that comparison.

The procedure operates on the **raw HTML response octets** — never on a
DOM after script execution, so a link inserted by JavaScript does not
exist for it, and the scan below is specified precisely enough that two
conforming implementations cannot disagree about anything else. In order
of appearance in the octet stream:

1. Strip every HTML comment: the octet run from `<!--` through the next
   `-->`, or through the end of input if unterminated.
2. Skip raw-text element content: everything between a case-insensitive
   `<script`, `<style`, or `<textarea` start tag and its matching
   case-insensitive end tag — or through the end of input if
   unterminated — is not scanned for `<a>` elements or comments.
3. An `<a>` element opens at a case-insensitive `<a` immediately followed
   by whitespace (tab, LF, FF, CR, or space), `/`, or `>` — `<article>`
   and `<aside>` MUST NOT match. Parse its attributes quote-aware: an
   attribute name is a run of octets excluding whitespace, `=`, `>`, and
   `/`; an optional `=` is followed by a `"`- or `'`-quoted value (a `>`
   inside the quotes does not end the tag) or by an unquoted run up to
   the next whitespace or `>`. The tag ends at the first `>` that is not
   inside a quoted value. The candidate is the value of the first
   attribute named exactly `href` (case-insensitive) — `data-href` is a
   different attribute and MUST NOT be treated as `href`.
4. Decode character references in the candidate before resolution:
   `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`, `&#NNN;` (decimal, ASCII
   digits `0`-`9` only), and `&#xHH;` (hexadecimal, ASCII `0`-`9`,
   `A`-`F` and `a`-`f` only). The repertoires are pinned because a
   language whose "digit" class spans Unicode — and whose integer parser
   silently folds those digits to their ASCII values — decodes
   `&#٦٥;` to `A`, while an implementation reading this step as written
   leaves it untouched; the two then extract different links from one
   page. An `&` that forms none of these is left as written, digits
   outside the repertoire included. A numeric character reference whose
   code point is not a Unicode scalar value — above `0x10FFFF`, or a
   surrogate `0xD800`-`0xDFFF` — makes the value have no link: it is
   discarded, the same fail-closed posture WIST-1 §2 takes toward an
   unresolvable escape.
5. Resolve the decoded candidate against the final response URL per RFC
   3986 §5.
6. Normalize per WIST-1 §2. A value with no Normalized URL is discarded —
   it is not a link, the fail-closed rule of WIST-1 §2.
7. Discard every link whose Canonical Host is the Publisher's domain or
   a subdomain of it.
8. Deduplicate: the first occurrence of a Normalized URL holds its
   position; later occurrences are discarded.

The count of survivors is `total`. `urls` is the longest prefix of the
survivors, in order, whose serialized `links` object fits
`links_cap_bytes` (WIST-1 §3.6).

**Which representations are HTML.** A representation is **HTML** for this
procedure when the media type of its `Content-Type` response header —
compared case-insensitively, with any parameters such as `charset`
ignored — is `text/html` or `application/xhtml+xml`. Every other media
type is not, and neither is a representation served with no
`Content-Type` at all. A representation that is not HTML has no links
under this procedure: its Payload MUST declare `{"total": 0, "urls":
[]}`. A Publisher MUST decide the question from that header alone and
MUST NOT sniff the body, because any party repeating the procedure on
its own fetch can read only the header the same way. The predicate is
enumerated rather than left to "whatever a browser would parse" for the
reason the whole procedure is: two tools that read
`application/xhtml+xml` differently would declare different sets from
one page.

`vectors/wist2/link-extraction.json` carries the conformance fixtures: the
exact input octets and the exact member a conforming implementation
produces, including one fixture whose full set exceeds the budget so
that the prefix rule is exercised, not merely stated, and one fixture
exercising the scan itself — a comment-wrapped link, a script-embedded
link, a `data-href` decoy, a quoted attribute value containing `>`, a
character reference, an uppercase tag, and an unquoted `href`.

## 12. Text Extraction

A Publisher's `extract` is an editorial choice about what the page's
content *is* (WIST-1 §3.6). This section gives the RECOMMENDED procedure
for deriving an **observed text** from a fetched HTML page — for
Publisher tooling that derives its publication from the page it serves,
and for any Labeler or Consumer that chooses to compare a page with a
publication — pinned for the reason §11 pins link extraction: two
conforming implementations produce the same text from the same octets.
The procedure is deliberately **whole-document**: any rule that tried to
isolate "main content" would be a boilerplate heuristic, and heuristics
are the disagreement this section exists to remove. A comparison over
its output should read containment — how much of the published text the
page carries — since the whole document carries every navigation link
and footer the page serves.

The procedure operates on the raw HTML response octets — never a DOM,
the same posture as §11, and shares §11's scan:

1. Strip every HTML comment and skip every raw-text element
   (`script`, `style`, `textarea`), exactly as §11 steps 1–2; each
   stripped construct contributes a single space (0x20).
2. Replace each remaining tag with a single space. A tag opens at `<`
   immediately followed by an ASCII letter, `/`, `!` or `?`, and ends
   at the first `>` not inside a `"`- or `'`-quoted attribute value
   (§11's quote-aware rule); a `<` followed by anything else is
   literal text. Everything outside tags is literal text.
3. Decode the resulting octet stream as UTF-8, replacing every invalid
   sequence with U+FFFD. The declared charset is never consulted:
   charset sniffing is implementation-divergent, and a non-UTF-8 page
   degrades identically for every implementation rather than differently per
   library.
4. Decode character references in the text, with exactly §11 step 4's
   repertoire; a reference that is malformed, over-long, or names a
   non-scalar code point is left exactly as written — text is not a
   link candidate, so there is nothing to fail closed on.
5. Collapse every run of ASCII whitespace (tab, LF, FF, CR, space) to
   a single space and trim the ends.

The output is the observed text. Two
conforming implementations given the same response octets produce
identical output; every choice above that deviates from rendering
fidelity — inline tags becoming word boundaries, undeclared charsets
ignored — deviates identically for everyone, which is the property that
matters. `vectors/wist2/text-extraction.json` carries the conformance
fixtures for this procedure.

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- WIST-1: Delta Format & Identity — Envelope, Delta ID, Key Set, scope rule
- WIST-3: Logbook & Distribution — block queueing
- WIST-4: Governance & Parameters — quotas, parameters, the Label Registry
