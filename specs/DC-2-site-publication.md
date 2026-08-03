# DC-2: Site Publication

**Status:** v1.0.0-draft · **Date:** 2026-08-02 · **License:** CC-BY 4.0

## 1. Introduction

DC-2 defines how a Publisher makes its Deltas (DC-1) available and how
Aggregators learn about them. The design principle is **ping + pull**: the
site never sends content to anyone. It publishes Deltas on itself, under
its own `.well-known` path, and merely rings a doorbell when something is
new. The site's `.well-known` is the canonical source of truth; publishers
are not coupled to any aggregator. Any aggregator, auditor, or researcher
pulling the same paths sees the same data, which is what makes the system
third-party verifiable and the aggregator substitutable (DC-3, DC-4).

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
- **Ingest Endpoint**: the Aggregator URL that receives Pings.

Terms defined in DC-1 (Publisher, Aggregator, Delta, Delta ID, Envelope,
Key Set, Canonical Host, Normalized URL, Payload, Publisher Declaration)
are used with their DC-1 meanings. Every
Envelope in this document carries `dc_version` (DC-1 §3.1) and the DC-1
§4 signature block (`key_id`, `alg`, `value`).

## 3. Well-Known Layout

A conforming Publisher serves, over HTTPS only:

```
/.well-known/deltacommons/publisher.json     (identity — DC-1 §5)
/.well-known/deltacommons/deltas/<id>.json   (one file per Delta)
/.well-known/deltacommons/payloads/<id>.json (one file per content-bearing Delta)
/.well-known/deltacommons/feed.json          (the Feed)
/.well-known/deltacommons/feed/<n>.json      (sealed Feed Pages — §3.2)
/.well-known/deltacommons/appeals/<id>.json  (one file per appeal — §3.3)
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
(DC-1 §3.3). The filename uses the same 64-char hex digest, so the two
files of one Delta share a name and differ only in directory. A Payload
is unsigned; its integrity comes from the Delta's commitment (DC-1 §3.6),
which every fetcher recomputes. Payload files are immutable while served,
under the same caching advice as Delta files — but unlike Delta files they
are erasable: a Publisher MAY stop serving a Payload, and MUST stop when
the content must be erased.

**Payload retention.** A Publisher MUST keep retrievable its URL's
**current anchor Payload** — the Payload of the last content-bearing Delta
in that URL's chain (DC-3 §6.1) — for as long as it continues to emit
`attest` Deltas for that URL, because that Payload is the reference an
`attest` is audited against (DC-4 §5). A Publisher that must stop serving
it re-anchors the chain instead, by publishing an `update` with a fresh
Payload or a `delete`; what it MUST NOT do is keep attesting to content
nobody can obtain. Payloads of superseded Deltas carry no such obligation
on the Publisher; the Aggregator's own retention of them, which is what
keeps an already-sealed Delta auditable, is DC-3 §6.1's.

**Withdrawal ends that duty and every other reason to serve.** From the
height a `payload_withdrawal` for a Delta is sealed (DC-3 §6.2), the
Publisher MUST stop serving that Delta's Payload at
`payloads/<id>.json`, and the retention duty above does not survive it —
the two do not compete, and where a Publisher would otherwise still be
attesting to the withdrawn anchor it re-anchors the chain as above.
Withdrawal reaching the Aggregator and the Mirrors but not the site that
first published the content would leave the salt on the open web at a
well-known path, and with it every commitment the salt keys: the Delta's
own and the three an Audit Record seals (DC-1 §3.6, DC-4 §5). One serving
path left open is the whole of the guarantee gone, which is why DC-3 §6.2
binds all three.

### 3.2. The Feed and its Pages

`feed.json` is an Envelope whose inner object is `feed` (schema:
[`schemas/feed.schema.json`](../schemas/feed.schema.json)): `domain`,
`generated_at`, `deltas` — Delta IDs in publication order, newest last —
and `next`. `generated_at` MUST be monotonically non-decreasing across
successive versions of `feed.json`; an Aggregator MUST discard a pull whose
`generated_at` has regressed, under `DC2-E05`.

**Publication order** is the order in which the Publisher first added each
Delta to the Feed. A Delta MUST NOT appear before the Delta named by its
`prev`.

**Page sealing.** When appending a Delta would make `deltas` exceed 1000
entries, the Publisher MUST first seal the current 1000 entries into an
immutable Page at `/.well-known/deltacommons/feed/<n>.json`. `<n>` is a
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
current at the page's `generated_at`; because pages are immutable they are
never re-signed on rotation, and a validator MUST NOT reject a page solely
because its signing key has since been retired.

DC-1 §5.2's historical-verification procedure cannot be applied directly
here: it resolves a Key Set by **Block height**, and Pages are never sealed
into the Log, so a Page has no height. The bridge is stated once, and it is
the only conversion permitted: the Key Set current at a `generated_at` is
the one declared by the domain's `publisher_declaration` Entry (DC-3 §3.3)
with the greatest `sealed_at` not later than that `generated_at` — with
DC-1 §5.2's recovery exception applied to that comparison exactly as it is
applied to the by-height one, so a Declaration superseded by a recovery
rotation is excluded here too. `sealed_at` is strictly increasing across
Blocks (DC-3 §3.1), so the ordering by `sealed_at` and the ordering by
height are the same ordering; what changes is only the key the Consumer
looks the Declaration up by, because a Page carries a timestamp and not a
height. Every input is in the Log, so two validators resolve the same Page
to the same Key Set. Because that comparison is against a Block's
`sealed_at`, `generated_at` carries the same whole-second, literal-`Z` form
`sealed_at` does (`schemas/feed.schema.json`, DC-3 §3.1): the two values
compare directly, with no normalization step for two implementations to
perform differently.

**Aggregator obligation.** On each pull, an Aggregator MUST follow `next`
until it reaches a page whose newest Delta ID it has already ingested, or
until `next` is `null`, applying the same diff-fetch-validate-queue
procedure (§5 steps 2–4) to every page's `deltas` as to the live
`feed.json`'s. Diffing only the live `feed.json` is non-conforming and
loses Deltas whenever more than one window's worth is published between
pulls.

`next` MUST be an absolute `https` URL whose Canonical Host is within the
Publisher's authority and whose path is under
`/.well-known/deltacommons/`.

**Caching.** Publishers SHOULD serve `feed.json` with `Cache-Control:
no-cache` and an `ETag`; Aggregators SHOULD use conditional requests. A
pull that returns `304` is not `DC2-E02` and MUST NOT count as noise.
Sealed Pages are immutable and SHOULD instead be served with long-lived
cache headers, as in §3.1.

### 3.3. Appeals

`appeals/<id>.json` contains exactly one `appeal` Registry Update Envelope
(DC-4 §7, schema:
[`schemas/registry-update.schema.json`](../schemas/registry-update.schema.json)),
where `<id>` is the 64-character hex digest of the Registry Update ID
(DC-4 §7) of the `notice` being appealed — the same
digest-without-the-`sha256:`-prefix naming §3.1 uses for Deltas, and the
same value the Envelope's own `details.notice` carries. A Publisher that
appeals a sanction notice publishes the file at that path; the Aggregator
pulls it, seals it as a `registry_update` Entry (DC-3 §3.3), and DC-4 §7
fixes the deadline by which it MUST.

**The pull is the Aggregator's duty and needs no Ping.** For every
`"sanction"` `notice` it seals, an Aggregator MUST fetch that notice's
appeal path from the sanctioned domain at least once after the appeal
window closes and before DC-4 §7's sealing deadline, and SHOULD poll it at
the baseline interval (§5) throughout the window. It MUST NOT make that
fetch conditional on a Ping: a domain in Sanctioned Quarantine has its
Pings answered `403` (§4), so an appeal path polled only on notification
would be unreachable in exactly the case it exists for. The Publisher MAY
ping as well, and MUST NOT read a `403` as the appeal having failed to
arrive — the appeal is served, and what the Log does with it is DC-4 §7's
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
POST <ingest endpoint>
Content-Type: application/json

{"host": "example.com"}
```

`host` MUST be a Canonical Host (DC-1 §2). An Aggregator MUST reject a
ping whose `host` is not canonical, and MUST reject a Feed whose
`feed.domain` differs from the host it was fetched from.

The Ping carries no content and no signature; authenticity comes from the
subsequent HTTPS pull of the signed Feed and Deltas. Responses:

| Status | Meaning |
|--------|---------------------------------------------------|
| 202 | Accepted; a pull will follow |
| 429 | Rate-limited; MUST include `Retry-After` |
| 403 | Domain in Sanctioned Quarantine or delisted (DC-4 §7). New and Provisional domains MUST NOT receive 403. It suspends ingestion of that domain's content and nothing else: the Aggregator's duty to fetch the domain's appeal path (§3.3) is independent of any Ping and survives the `403`. |

On a 5xx, timeout, or connection failure a Publisher SHOULD retry at most
three times with exponential backoff (1 min, 4 min, 16 min) and then rely
on the Aggregator's baseline polling; it MUST NOT retry a 4xx other than
429.

Per-domain Ping quotas are a function of the domain's reputation; the
quota formula is normative in DC-4 §6. DC-2 only fixes the dependency:
higher reputation ⇒ higher quota. Only pings resolving to `DC2-E02` or
`DC2-E04` count against the domain's daily quota Q (DC-4 §6); productive
pings do not. Exceeding Q yields `429` until the UTC-day window resets.

## 5. Aggregator Pull Behavior

On receiving a Ping for a known-or-new domain, the Aggregator:

0. **First contact.** If the domain is unknown, the Aggregator MUST fetch
   and verify `publisher.json` (DC-1 §5.1) before any Feed pull, seal it
   as a `publisher_declaration` Entry (DC-3 §3.3), and apply the
   new-domain quota of DC-4 §6. A missing or invalid Declaration is a
   `DC2-E04` rejection.

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
   Set (DC-1 §5). A Feed that cannot be fetched at all is `DC2-E01` and is
   retried on the backoff schedule of §7.
2. Diffs `feed.deltas` against the IDs it has already seen for the
   domain, following `next` through sealed Pages as required by §3.2.
3. Fetches each new `deltas/<id>.json`; validates each per DC-1 (§4, §7).
   For every content-bearing Delta it also fetches the corresponding
   `payloads/<id>.json` in the same pass and verifies it against the
   Delta's commitment and `bytes` (DC-1 §3.6). A Delta whose Payload is
   unavailable, malformed, or fails that verification at pull time MUST be
   rejected with `DC2-E03` and MUST NOT be sealed: the Aggregator cannot
   undertake to serve (DC-3 §6.1) content it never received, and a Delta
   sealed without its Payload would be permanently unauditable.
4. Queues accepted Deltas for the next log block (DC-3 §3), and the
   Payloads it verified for publication alongside the Block that seals
   them (DC-3 §6.1).

Aggregators MUST also poll known feeds at a low baseline frequency
(default: every 24 hours, a Parameter Registry value — DC-4 §9) regardless
of Pings. A lost Ping therefore delays ingestion but never loses data.

The `/.well-known/deltacommons/` path is published *for* automated
consumption by aggregators and auditors; `robots.txt` directives do not
apply to fetches under this path. Fetches of any other path (e.g. auditor
re-fetches of content URLs, DC-4 §5) remain subject to `robots.txt`.

An Auditor's re-fetches MUST carry the product token
`DeltaCommons-Auditor` in `User-Agent`, and it evaluates `robots.txt`
([RFC 9309]) under that token; the Auditor's `auditor_id` MAY appear
elsewhere in the header for operator contact, but MUST NOT be the token
the file is matched on. One token for every Auditor is what keeps the
choice a Publisher makes a choice about auditing rather than about
auditors.

A `robots.txt` in force that would grant access to some admitted Auditors
(DC-4 §3) and deny it to others — by naming individual Auditors, or by any
other discrimination between them — MUST be treated by **every** Auditor
as a prohibition, recorded `unreachable` with `robots_excluded` (DC-4 §5),
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
same time. DC-4 §5 owns that rule and states it normatively, including why
one Auditor's exclusion is not enough and why the clearing audit must come
from a third: this paragraph is a pointer, and where the two differ DC-4 §5
governs (DC-4 §5, DC-3 §7).

## 6. Unsigned Change Hints (Compatibility)

Aggregators MAY consume existing ecosystems as Change Hints: IndexNow
pings, sitemap `<lastmod>` changes, and llms.txt updates.

An unsigned hint MUST NOT produce content attributed to the domain.

A hint MAY trigger an auditor re-fetch of the hinted URL. If the domain
has signed Deltas for that URL, the result enters the log as an Audit
Record (DC-4 §5), signed by the auditor. For URLs with no signed Deltas,
hints only inform the Aggregator's pull and audit scheduling — they
produce no log entries.

The signed path always has higher weight and lower latency: signed Deltas
enter the log directly on the publisher's authority, while hints are
second-class — at most auditor-attributed, scheduled at the system's
convenience. This asymmetry is the adoption incentive for DC-1/DC-2.

## 7. Error Registry

| Code | Meaning and required behavior |
|---------|--------------------------------------------------------------|
| DC2-E01 | Feed unreachable after Ping. Aggregator retries with exponential backoff at 1 min, 4 min, 16 min, 64 min; a fresh ping cancels a pending backoff and starts a new attempt, subject to quota. |
| DC2-E02 | Ping produced no new feed content. Counts as noise against the domain's Ping quota. |
| DC2-E03 | Delta referenced in Feed but missing or corrupted at `deltas/<id>.json`, or a content-bearing Delta whose `payloads/<id>.json` is missing, corrupted, or does not reproduce its commitment (DC-1 §3.6). Typed rejection, visible to the Publisher via the status endpoint (§7.1). |
| DC2-E04 | First contact or Feed authentication failure. Two cases, one code: a Feed whose signature does not verify against the domain's Key Set, and a first-contact pull (§5 step 0) whose `publisher.json` is missing, unreachable, malformed, or fails DC-1 §5.1 verification — the second being the case where no Key Set exists to check the first against. The pull is discarded; counts as noise against the quota. The status endpoint (§7.1) MUST distinguish the two in its `detail` field, since a Publisher whose Declaration never loaded and one whose Feed signature is wrong take entirely different remedies. |
| DC2-E05 | Feed `generated_at` regression. The pull is discarded and counts against the quota as noise. |

### 7.1. Publisher Status Endpoint

Aggregators MUST expose `GET <aggregator>/status/<domain>` returning the
`status` object (schema:
[`schemas/status.schema.json`](../schemas/status.schema.json)) as JSON. It
carries `dc_version`, the `domain` it describes, and:

- `last_pull_at` — the time of the last successful pull, or `null` if the
  Aggregator has never completed one;
- `quota_remaining` — Pings still available to the domain in the current
  UTC-day window, against the `Q` of DC-4 §6;
- `state` — the domain's **ingestion** state: one of `new` (known, not yet
  successfully pulled), `active`, `sanctioned_quarantine` (DC-4 §7 level 3)
  or `delisted` (level 4). The last two are exactly the states §4 answers a
  Ping with `403` for. Provisional (DC-4 §6.3) is deliberately absent: it
  bounds a domain's reputation and never its ingestion, so a Provisional
  domain reports `active` like any other, and an implementation that
  reported it here would be advertising a restriction DC-4 §6.3 forbids it
  to apply;
- `rejections` — the pending typed rejections, each with its `code` (a
  DC-1 or DC-2 error code, §7 and DC-1 §7), the `at` it was recorded, the
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
  actual bound. Quotas (DC-4 §6) throttle abusive domains; Ingest
  Endpoints SHOULD additionally apply source-IP rate limits below the
  per-domain quotas.
- **Feed replay.** An attacker replaying an old `feed.json` cannot
  regress state: signatures bind content, `generated_at` monotonicity
  detects rollback, and Deltas already seen are idempotent (DC-1 §4).
- **Cache poisoning of `.well-known`.** All discovery and pulls are
  HTTPS-only; Aggregators MUST NOT accept any `deltacommons` resource
  over plain HTTP. An Aggregator MUST follow a redirect only when the
  target is `https` and its Canonical Host equals the Canonical Host of
  the request, or is listed in the Publisher's `subdomain_scope`.
  Apex-to-`www` redirects are therefore conforming when `www` is in
  scope.

## 9. Privacy Considerations

Pings reveal publication timing to the Aggregator, and Feeds are public
by construction — a Publisher's activity pattern is observable by anyone.
No reader or consumer data is involved at this layer: DC-2 concerns only
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
      DC-1 §3.6)
- [ ] Stops serving a Payload from the height a `payload_withdrawal`
      naming its Delta is sealed — the retention duty above does not
      survive it — and re-anchors the chain rather than keeping the
      withdrawn Payload published in order to go on attesting
      (§3.1, DC-3 §6.2)
- [ ] Appeals a sanction notice by publishing a signed `appeal` at
      `appeals/<notice-id>.json`, immutable once published, naming that
      notice in `details.notice` (§3.3, DC-4 §7)
- [ ] Seals Pages when `deltas` would exceed 1000 entries — file
      published before cutover, sealing-order numbering, no Delta
      omitted or duplicated across Pages, monotonic `generated_at` (§3.2)
- [ ] Pings with the exact one-field body of §4, honors `Retry-After`, and
      follows the retry/backoff rule of §4

**Aggregator (ingest side):**

- [ ] Implements the pull sequence of §5 with signature validation at
      every step
- [ ] Pulls each content-bearing Delta's Payload in the same pass, checks
      it against the Delta's commitment, and rejects with `DC2-E03` rather
      than sealing a Delta whose Payload it does not hold (§5, §7)
- [ ] Performs First Contact (verifies `publisher.json` before any Feed
      pull for an unknown domain) (§5)
- [ ] Follows `next` through sealed Pages until reaching already-ingested
      content or `null`; never diffs only the live `feed.json` (§3.2)
- [ ] Applies the per-domain ingest budget to that walk, suspending and
      resuming across days rather than truncating it (§5)
- [ ] Runs baseline polling independent of Pings (§5)
- [ ] Fetches every `"sanction"` notice's appeal path from the sanctioned
      domain before DC-4 §7's sealing deadline, independent of any Ping
      and notwithstanding the `403` that domain's Pings receive (§3.3, §4)
- [ ] Never attributes unsigned-hint content to a domain (§6)
- [ ] Implements the Error Registry behaviors and the status endpoint (§7)
- [ ] Accounts pings correctly against the domain's quota — only
      `DC2-E02`/`DC2-E04` count as noise (§4)
- [ ] HTTPS-only, same-authority-only fetching, per the Canonical Host /
      `subdomain_scope` redirect rule (§8)

## 11. Link Extraction

A Publisher declares its page's external links in the Payload's `links`
member (DC-1 §3.6) by one procedure, and an Auditor checking the
declaration (DC-4 §5) MUST apply the same procedure to its own fetch —
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
   discarded, the same fail-closed posture DC-1 §2 takes toward an
   unresolvable escape.
5. Resolve the decoded candidate against the final response URL per RFC
   3986 §5.
6. Normalize per DC-1 §2. A value with no Normalized URL is discarded —
   it is not a link, the fail-closed rule of DC-1 §2.
7. Discard every link whose Canonical Host is the Publisher's domain or
   a subdomain of it.
8. Deduplicate: the first occurrence of a Normalized URL holds its
   position; later occurrences are discarded.

The count of survivors is `total`. `urls` is the longest prefix of the
survivors, in order, whose serialized `links` object fits
`links_cap_bytes` (DC-1 §3.6).

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
(DC-4 §5) with neither party having misdeclared anything.

`vectors/dc2/link-extraction.json` carries the conformance fixtures: the
exact input octets and the exact member a conforming implementation
produces, including one fixture whose full set exceeds the budget so
that the prefix rule is exercised, not merely stated, and one fixture
exercising the scan itself — a comment-wrapped link, a script-embedded
link, a `data-href` decoy, a quoted attribute value containing `>`, a
character reference, an uppercase tag, and an unquoted `href`.

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- [RFC 9309] Robots Exclusion Protocol — the product-token matching §5's
  Auditor rule is stated over
- DC-1: Delta Format & Identity — Envelope, Delta ID, Key Set, scope rule
- DC-3: Commons Log & Distribution — block queueing
- DC-4: Audit, Reputation & Governance — quotas, sanctions, auditor observations
