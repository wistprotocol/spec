# WIST-2: Site Publication

**Status:** v1.0.0-draft · **Date:** 2026-08-02 · **License:** CC-BY 4.0

## 1. Introduction

WIST-2 defines how a Publisher makes its Deltas (WIST-1) available and how
Aggregators learn about them. The design principle is **ping + pull**: the
site never sends content to anyone. It publishes Deltas on itself, under
its own `.well-known` path, and merely rings a doorbell when something is
new. The site's `.well-known` is the canonical source of truth; publishers
are not coupled to any aggregator. Any aggregator, auditor, or researcher
pulling the same paths sees the same data, which is what makes the system
third-party verifiable and the aggregator substitutable (WIST-3, WIST-4).

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
/.well-known/wist/appeals/<id>.json  (one file per appeal — §3.3)
```

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
`attest` Deltas for that URL, because that Payload is the reference an
`attest` is audited against (WIST-4 §5). A Publisher that must stop serving
it re-anchors the chain instead, by publishing an `update` with a fresh
Payload or a `delete`; what it MUST NOT do is keep attesting to content
nobody can obtain. Payloads of superseded Deltas carry no such obligation
on the Publisher; the Aggregator's own retention of them, which is what
keeps an already-sealed Audit Record verifiable, is WIST-3 §6.1's.

**Withdrawal ends that duty and every other reason to serve.** From the
height a `payload_withdrawal` for a Delta is sealed (WIST-3 §6.2), the
Publisher MUST stop serving that Delta's Payload at
`payloads/<id>.json`, and the retention duty above does not survive it —
the two do not compete, and where a Publisher would otherwise still be
attesting to the withdrawn anchor it re-anchors the chain as above.
Withdrawal reaching the Aggregator and the Mirrors but not the site that
first published the content would leave the salt on the open web at a
well-known path, and with it every commitment the salt keys: the Delta's
own and the three an Audit Record seals (WIST-1 §3.6, WIST-4 §5). One serving
path left open is the whole of the guarantee gone, which is why WIST-3 §6.2
binds all three.

### 3.2. The Feed and its Pages

`feed.json` is an Envelope whose inner object is `feed` (schema:
[`schemas/feed.schema.json`](../schemas/feed.schema.json)): `domain`,
`generated_at`, `deltas` — Delta IDs in publication order, newest last —
and `next`. `generated_at` MUST be monotonically non-decreasing across
successive versions of `feed.json`; an Aggregator MUST discard a pull whose
`generated_at` has regressed, under `WIST2-E05`.

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

**Verification of sealed pages.** A page is verified against the Key Set
current at the page's `generated_at` or, where that Key Set does not
hold the key that signed it, against the Key Set of the first Block
after `generated_at` sealing an applicable Declaration of the domain
(the bridge below);
because pages are immutable they are
never re-signed on rotation, and a validator MUST NOT reject a page solely
because its signing key has since been retired, or because the
Declaration admitting it had not been sealed when the page was cut. A
page that verifies under neither Key Set is `WIST2-E04`.

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
resolution above closes the gap: a Page whose signing key the Key Set
current at `generated_at` does not hold verifies if that key is in the
Key Set of the **first** Block sealed after `generated_at` that seals an
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

`next` MUST be an absolute `https` URL whose Canonical Host is within the
Publisher's authority and whose path is under
`/.well-known/wist/`. A `next` that is not is `WIST2-E01`: the walk stops
there with no usable Page, exactly as it stops at a Page it cannot
fetch, and an Aggregator MUST NOT follow it.

**Caching.** Publishers SHOULD serve `feed.json` with `Cache-Control:
no-cache` and an `ETag`; Aggregators SHOULD use conditional requests. A
pull that returns `304` is not `WIST2-E02` and MUST NOT count as noise.
Sealed Pages are immutable and SHOULD instead be served with long-lived
cache headers, as in §3.1.

### 3.3. Appeals

`appeals/<id>.json` contains exactly one `appeal` Registry Update Envelope
(WIST-4 §7, schema:
[`schemas/registry-update.schema.json`](../schemas/registry-update.schema.json)),
where `<id>` is the 64-character hex digest of the Registry Update ID
(WIST-4 §7) of the `notice` being appealed — the same
digest-without-the-`sha256:`-prefix naming §3.1 uses for Deltas, and the
same value the Envelope's own `details.notice` carries. A Publisher that
appeals a sanction notice publishes the file at that path; the Aggregator
pulls it, seals it as a `registry_update` Entry (WIST-3 §3.3), and WIST-4 §7
fixes the deadline by which it MUST.

**The pull is the Aggregator's duty and needs no Ping.** For every
`"sanction"` `notice` it seals, an Aggregator MUST fetch that notice's
appeal path from the sanctioned domain at least once after the appeal
window closes and before WIST-4 §7's sealing deadline, and SHOULD poll it at
the baseline interval (§5) throughout the window. It MUST NOT make that
fetch conditional on a Ping: a domain in Sanctioned Quarantine has its
Pings answered `403` (§4), so an appeal path polled only on notification
would be unreachable in exactly the case it exists for. The Publisher MAY
ping as well, and MUST NOT read a `403` as the appeal having failed to
arrive — the appeal is served, and what the Log does with it is WIST-4 §7's
subject.

The path exists because an appeal is the one Publisher artifact whose
delivery a level-3 sanction would otherwise block: Sanctioned Quarantine
rejects that domain's Pings and Feed pulls (§4), and an appeal carried in
no other way would depend on the goodwill of the party being appealed
against. Publishing it at a well-known path over HTTPS makes the appeal a
signed, dated, fetchable artifact from the instant it is served — before
any Aggregator acts on it, and whether or not one ever does — so a party
checking whether an appeal was suppressed fetches it and checks the Log,
rather than taking either party's word. Appeal files are immutable under
the same rule as Delta files: once published under an `<id>`, the bytes
MUST NOT change, and a Publisher that wants to say more files nothing here
— it says it in the appeal it publishes, once.

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

The Ping carries no content and no signature; authenticity comes from the
subsequent HTTPS pull of the signed Feed and Deltas. Responses:

| Status | Meaning |
|--------|---------------------------------------------------|
| 202 | Accepted; a pull will follow |
| 429 | Rate-limited; MUST include `Retry-After` |
| 403 | Domain in Sanctioned Quarantine or delisted (WIST-4 §7). New and Provisional domains MUST NOT receive 403. It suspends ingestion of that domain's content and nothing else: the Aggregator's duty to fetch the domain's appeal path (§3.3) is independent of any Ping and survives the `403`. |

On a 5xx, timeout, or connection failure a Publisher SHOULD retry at most
three times with exponential backoff (1 min, 4 min, 16 min) and then rely
on the Aggregator's baseline polling; it MUST NOT retry a 4xx other than
429.

Per-domain Ping quotas are a function of the domain's reputation; the
quota formula is normative in WIST-4 §6. WIST-2 only fixes the dependency:
higher reputation ⇒ higher quota. Only pings resolving to `WIST2-E02` or
`WIST2-E04` count against the domain's daily quota Q (WIST-4 §6); productive
pings do not. Exceeding Q yields `429` until the UTC-day window resets.

## 5. Aggregator Pull Behavior

On receiving a Ping for a known-or-new domain, the Aggregator:

0. **First contact.** If the domain is unknown, the Aggregator MUST fetch
   and verify `publisher.json` (WIST-1 §5.1) before any Feed pull, seal it
   as a `publisher_declaration` Entry (WIST-3 §3.3), and apply the
   new-domain quota of WIST-4 §6. A missing or invalid Declaration is a
   `WIST2-E04` rejection.

   **Ingest budget.** §3.2's obligation to walk sealed Pages has no page
   cap, so a first contact — or a long-dormant domain's return — can
   demand a domain's entire history, and a hostile domain can make that
   history arbitrarily deep: a single Ping would otherwise oblige
   terabytes of pulls, an amplification no quota reaches because
   productive pings are unmetered (§4). The Aggregator therefore
   applies a per-domain budget: it MUST fetch no more than
   `ingest_budget_bytes_day` (Parameter Registry; default 1 GiB) of
   Feed pages, Deltas and Payloads for one domain per UTC day, MAY
   suspend the walk when the budget is spent, and MUST resume it —
   from where it stopped, which §3.2's "until already-ingested" rule
   makes well-defined — on a later day rather than treat the suspension
   as completion. The budget bounds the walk without breaking it: an
   honest large site backfills across days; a hostile deep feed costs
   its own hosting bill, not the Aggregator's month.
1. Fetches `feed.json`; verifies its signature against the domain's Key
   Set (WIST-1 §5). A Feed the Aggregator cannot use is `WIST2-E01` and is
   retried on the backoff schedule of §7 — one that cannot be fetched at
   all, and one fetched but unusable: not well-formed JSON, failing the
   Feed schema, or naming a `next` outside the Publisher's authority
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
   For every content-bearing Delta it also fetches the corresponding
   `payloads/<id>.json` in the same pass and verifies it against the
   Delta's commitment and `bytes` (WIST-1 §3.6). A Delta whose Payload is
   unavailable, malformed, or fails that verification at pull time MUST be
   rejected with `WIST2-E03` and MUST NOT be sealed: the Aggregator cannot
   undertake to serve (WIST-3 §6.1) content it never received, and a Delta
   sealed without its Payload would be permanently unauditable.
4. Queues accepted Deltas for the next log block (WIST-3 §3), and the
   Payloads it verified for publication alongside the Block that seals
   them (WIST-3 §6.1). A queued Delta is sealed only where it verifies
   under the Key Set WIST-1 §5.2 resolves at the sealing Block: one whose
   signing key a Declaration accepted since the pull has retired is
   `WIST1-E02` at sealing, reported (§7.1) and not sealed, and its ID is
   pulled again once the Publisher re-signs it (step 2).

Aggregators MUST also poll known feeds at a low baseline frequency
(default: every 24 hours, a Parameter Registry value — WIST-4 §9) regardless
of Pings. A lost Ping therefore delays ingestion but never loses data.

The `/.well-known/wist/` path is published *for* automated
consumption by aggregators and auditors; `robots.txt` directives do not
apply to fetches under this path. Fetches of any other path (e.g. auditor
re-fetches of content URLs, WIST-4 §5) remain subject to `robots.txt`.

An Auditor's re-fetches MUST carry the product token
`WIST-Auditor` in `User-Agent`, and it evaluates `robots.txt`
([RFC 9309]) under that token; the Auditor's `auditor_id` MAY appear
elsewhere in the header for operator contact, but MUST NOT be the token
the file is matched on. One token for every Auditor is what keeps the
choice a Publisher makes a choice about auditing rather than about
auditors.

A `robots.txt` in force that would grant access to some admitted Auditors
(WIST-4 §3) and deny it to others — by naming individual Auditors, or by any
other discrimination between them — MUST be treated by **every** Auditor
as a prohibition, recorded `unreachable` with `robots_excluded` (WIST-4 §5),
whatever access it purports to grant that Auditor itself. Selective
permission is the more dangerous case, not the lesser one: a Publisher
that admits exactly one Auditor keeps its URL audited on paper while
ensuring no second independent Auditor can ever see the page, and a
Confirmed Inconsistency needs two.

A Publisher that forbids those re-fetches keeps that right and pays a
stated price: a URL that two Auditors independent of one another have been
turned away from, both exclusions sealed inside the unauditable horizon, is
excluded from materialization until an Auditor independent of both records
a successful audit, or until those exclusions age out of the horizon with
none replacing them. It is not a sanction and touches no reputation —
declining audits and being materialized are simply not available at the
same time. WIST-4 §5 owns that rule and states it normatively, including why
one Auditor's exclusion is not enough and why the clearing audit must come
from a third: this paragraph is a pointer, and where the two differ WIST-4 §5
governs (WIST-4 §5, WIST-3 §7).

## 6. Unsigned Change Hints (Compatibility)

Aggregators MAY consume existing ecosystems as Change Hints: IndexNow
pings, sitemap `<lastmod>` changes, and llms.txt updates.

An unsigned hint MUST NOT produce content attributed to the domain.

A hint MAY advance an Auditor's fetch of a Delta already in its
selection set (WIST-4 §4) — the hinted URL's Delta, where the Auditor's
own draw or the extension rule names it — and nothing more. A Record
for a Delta outside the Auditor's selection set is void (WIST-4 §10,
`WIST4-E01`) whatever prompted the fetch, so a hint never creates an
Audit Record; it only times one the Auditor owed. For every other URL,
with signed Deltas or without, hints only inform the Aggregator's pull
and audit scheduling — they produce no log entries.

The signed path always has higher weight and lower latency: signed Deltas
enter the log directly on the publisher's authority, while hints are
second-class — at most auditor-attributed, scheduled at the system's
convenience. This asymmetry is the adoption incentive for WIST-1/WIST-2.

## 7. Error Registry

| Code | Meaning and required behavior |
|---------|--------------------------------------------------------------|
| WIST2-E01 | Feed unusable after Ping: unreachable, or fetched and unusable — not well-formed JSON, failing the Feed schema, or naming a `next` outside the Publisher's authority (§3.2, §5). Aggregator retries with exponential backoff at 1 min, 4 min, 16 min, 64 min; a fresh ping cancels a pending backoff and starts a new attempt, subject to quota. The pull is not noise (§4): the backoff, not the quota, is what bounds a domain that keeps serving one. |
| WIST2-E02 | Ping produced no new feed content. Counts as noise against the domain's Ping quota. |
| WIST2-E03 | Delta referenced in Feed but missing or corrupted at `deltas/<id>.json`, or a content-bearing Delta whose `payloads/<id>.json` is missing, corrupted, or does not reproduce its commitment (WIST-1 §3.6). Typed rejection, visible to the Publisher via the status endpoint (§7.1). |
| WIST2-E04 | First contact or Feed authentication failure. Three cases, one code, each one of the Feed failing to authenticate as this domain's: a Feed whose signature does not verify against the domain's Key Set even after the one Declaration re-fetch §5 step 1 requires; a Feed whose `feed.domain` differs from the host it was fetched from (§4), which authenticates as some other domain's Feed or as none, whatever key signed it; and a first-contact pull (§5 step 0) whose `publisher.json` is missing, unreachable, malformed, or fails WIST-1 §5.1 verification — the last being the case where no Key Set exists to check the first against. The pull is discarded; counts as noise against the quota. The status endpoint (§7.1) MUST distinguish them in its `detail` field, since a Publisher whose Declaration never loaded, one whose Feed signature is wrong, and one serving a misaddressed Feed take entirely different remedies. |
| WIST2-E05 | Feed `generated_at` regression. The pull is discarded; it does not count against the quota — §4's noise set is closed at `WIST2-E02`/`WIST2-E04`. |

### 7.1. Publisher Status Endpoint

Aggregators MUST expose `GET https://<log_id>/status/<domain>` at the
Service Origin (WIST-3 §6), returning the
`status` object (schema:
[`schemas/status.schema.json`](../schemas/status.schema.json)) as JSON. It
carries `wist_version`, the `domain` it describes, and:

- `last_pull_at` — the time of the last successful pull, or `null` if the
  Aggregator has never completed one;
- `quota_remaining` — Pings still available to the domain in the current
  UTC-day window, against the `Q` of WIST-4 §6;
- `state` — the domain's **ingestion** state: one of `new` (known, not yet
  successfully pulled), `active`, `sanctioned_quarantine` (WIST-4 §7 level 3)
  or `delisted` (level 4). The last two are exactly the states §4 answers a
  Ping with `403` for. Provisional (WIST-4 §6.3) is deliberately absent: it
  bounds a domain's reputation and never its ingestion, so a Provisional
  domain reports `active` like any other, and an implementation that
  reported it here would be advertising a restriction WIST-4 §6.3 forbids it
  to apply;
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
  actual bound. Quotas (WIST-4 §6) throttle abusive domains; Ingest
  Endpoints SHOULD additionally apply source-IP rate limits below the
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
  to fetch. Five is chosen rather than derived: it is the same allowance
  WIST-4 §9's `audit_redirect_max` gives an Auditor, and a
  publication path needing a sixth hop to reach its own well-known file
  is misconfigured rather than unlucky.

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
- [ ] Appeals a sanction notice by publishing a signed `appeal` at
      `appeals/<notice-id>.json`, immutable once published, naming that
      notice in `details.notice` (§3.3, WIST-4 §7)
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
- [ ] Treats an ID as seen only once sealed or held accepted for sealing,
      and pulls a rejected ID again on the next pull (§5, WIST-1 §3.5)
- [ ] Verifies a sealed Page against the Key Set current at its
      `generated_at`, or that of the first Block after it sealing an
      applicable Declaration — the highest `seq`'s where a Block seals
      several (§3.2)
- [ ] Applies the per-domain ingest budget to that walk, suspending and
      resuming across days rather than truncating it (§5)
- [ ] Runs baseline polling independent of Pings (§5)
- [ ] Fetches every `"sanction"` notice's appeal path from the sanctioned
      domain before WIST-4 §7's sealing deadline, independent of any Ping
      and notwithstanding the `403` that domain's Pings receive (§3.3, §4)
- [ ] Never attributes unsigned-hint content to a domain (§6)
- [ ] Implements the Error Registry behaviors and the status endpoint (§7)
- [ ] Accounts pings correctly against the domain's quota — only
      `WIST2-E02`/`WIST2-E04` count as noise (§4)
- [ ] HTTPS-only, same-authority-only fetching, per the Canonical Host /
      `subdomain_scope` redirect rule (§8)

## 11. Link Extraction

A Publisher declares its page's external links in the Payload's `links`
member (WIST-1 §3.6) by one procedure, and an Auditor checking the
declaration (WIST-4 §5) MUST apply the same procedure to its own fetch —
the rule is deterministic precisely so that the two runs can disagree
only when the page did.

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
[]}`. Publisher and Auditor MUST decide the question from that header
alone and MUST NOT sniff the body, because they decide it on two
separate fetches of the same page and only the header is a declaration
both can read the same way. The predicate is enumerated rather than left
to "whatever a browser would parse" for the reason the whole procedure
is: a Publisher that reads `application/xhtml+xml` as non-HTML declares
`{"total": 0, "urls": []}` while an Auditor that reads it as HTML
extracts a set, and the disagreement surfaces as a `link_agreement` of 0
(WIST-4 §5) with neither party having misdeclared anything.

`vectors/wist2/link-extraction.json` carries the conformance fixtures: the
exact input octets and the exact member a conforming implementation
produces, including one fixture whose full set exceeds the budget so
that the prefix rule is exercised, not merely stated, and one fixture
exercising the scan itself — a comment-wrapped link, a script-embedded
link, a `data-href` decoy, a quoted attribute value containing `>`, a
character reference, an uppercase tag, and an unquoted `href`.

## 12. Text Extraction

WIST-4 §5's similarity metric compares the Publisher's committed `extract`
against an **observed text** an Auditor produces from its own fetch, and
this section pins how that text is produced, for the reason §11 pins
link extraction: a metric two conforming implementations can compute
differently is not recomputable, and every verdict, sanction and
reputation value replays through this one. The Publisher's side is not
touched — `extract` remains an editorial choice about what the page's
content *is* — the pinned procedure governs only the observed side, and
it is deliberately **whole-document**: any rule that tried to isolate
"main content" would be a boilerplate heuristic, and heuristics are the
disagreement this section exists to remove. What makes whole-document
extraction safe for honest Publishers is WIST-4 §5's containment reading,
not anything here.

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
   degrades identically for every Auditor rather than differently per
   library.
4. Decode character references in the text, with exactly §11 step 4's
   repertoire; a reference that is malformed, over-long, or names a
   non-scalar code point is left exactly as written — text is not a
   link candidate, so there is nothing to fail closed on.
5. Collapse every run of ASCII whitespace (tab, LF, FF, CR, space) to
   a single space and trim the ends.

The output is the observed text WIST-4 §5 normalizes and measures. Two
conforming implementations given the same response octets produce
identical output; every choice above that deviates from rendering
fidelity — inline tags becoming word boundaries, undeclared charsets
ignored — deviates identically for everyone, which is the property that
matters. `vectors/wist2/text-extraction.json` carries the conformance
fixtures for this procedure and for WIST-4 §5's metric over its output.

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- [RFC 9309] Robots Exclusion Protocol — the product-token matching §5's
  Auditor rule is stated over
- WIST-1: Delta Format & Identity — Envelope, Delta ID, Key Set, scope rule
- WIST-3: Logbook & Distribution — block queueing
- WIST-4: Audit, Reputation & Governance — quotas, sanctions, auditor observations
