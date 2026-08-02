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
- **Ping**: the unauthenticated notification a Publisher sends an
  Aggregator's Ingest Endpoint to trigger a pull.
- **Change Hint**: an unsigned, out-of-protocol signal (IndexNow ping,
  sitemap, llms.txt) that a page may have changed.
- **Ingest Endpoint**: the Aggregator URL that receives Pings.

Terms defined in DC-1 (Publisher, Delta, Delta ID, Envelope, Key Set) are
used with their DC-1 meanings.

## 3. Well-Known Layout

A conforming Publisher serves, over HTTPS only:

```
/.well-known/deltacommons/publisher.json     (identity — DC-1 §5)
/.well-known/deltacommons/deltas/<id>.json   (one file per Delta)
/.well-known/deltacommons/feed.json          (the Feed)
```

### 3.1. Delta Files

`deltas/<id>.json` contains exactly one Delta Envelope, where `<id>` is
the Delta ID (including the `sha256:` prefix is NOT used in the filename;
the filename is the 64-char hex digest, e.g.
`deltas/e3ba905f...87b1.json`). Delta files are immutable: once published
under an ID, the bytes MUST NOT change. Publishers SHOULD serve them with
long-lived cache headers (`Cache-Control: public, max-age=31536000,
immutable`).

### 3.2. The Feed

`feed.json` is an Envelope whose inner object is `feed` (schema:
[`schemas/feed.schema.json`](../schemas/feed.schema.json)): `domain`,
`generated_at`, `deltas` — a rolling window of at most 1000 Delta IDs in
publication order, newest last — and `next`, a URI pointing to the
previous (older) immutable feed page, or `null` if none. Feed pages
referenced by `next` MUST be immutable; only the top `feed.json` changes.
`generated_at` MUST be monotonically non-decreasing across successive
versions of `feed.json`.

## 4. The Ping

To notify an Aggregator, a Publisher sends:

```
POST <ingest endpoint>
Content-Type: application/json

{"host": "example.com"}
```

The Ping carries no content and no signature; authenticity comes from the
subsequent HTTPS pull of the signed Feed and Deltas. Responses:

| Status | Meaning |
|--------|---------------------------------------------------|
| 202 | Accepted; a pull will follow |
| 429 | Rate-limited; MUST include `Retry-After` |
| 403 | Domain quarantined or delisted (see DC-4 §7) |

Per-domain Ping quotas are a function of the domain's reputation; the
quota formula is normative in DC-4 §6. DC-2 only fixes the dependency:
higher reputation ⇒ higher quota.

## 5. Aggregator Pull Behavior

On receiving a Ping for a known-or-new domain, the Aggregator:

1. Fetches `feed.json`; verifies its signature against the domain's Key
   Set (DC-1 §5).
2. Diffs `feed.deltas` against the IDs it has already seen for the domain.
3. Fetches each new `deltas/<id>.json`; validates each per DC-1 (§4, §7).
4. Queues accepted Deltas for the next log block (DC-3 §3).

Aggregators MUST also poll known feeds at a low baseline frequency
(default: every 24 hours, a Parameter Registry value — DC-4 §9) regardless
of Pings. A lost Ping therefore delays ingestion but never loses data.

The `/.well-known/deltacommons/` path is published *for* automated
consumption by aggregators and auditors; `robots.txt` directives do not
apply to fetches under this path. Fetches of any other path (e.g. auditor
re-fetches of content URLs, DC-4 §5) remain subject to `robots.txt`.

## 6. Unsigned Change Hints (Compatibility)

Aggregators MAY consume existing ecosystems as Change Hints: IndexNow
pings, sitemap `<lastmod>` changes, and llms.txt updates.

An unsigned hint MUST NOT produce content attributed to the domain. A
hint MAY trigger an auditor observation, which enters the log signed by
the auditor.

The signed path always has higher weight and lower latency: signed Deltas
enter the log directly on the publisher's authority, while hint-triggered
auditor observations are second-class — attributed to the auditor, and
scheduled at the auditor's convenience. This asymmetry is the adoption
incentive for DC-1/DC-2.

## 7. Error Registry

| Code | Meaning and required behavior |
|---------|--------------------------------------------------------------|
| DC2-E01 | Feed unreachable after Ping. Aggregator retries with exponential backoff at 1 min, 4 min, 16 min, 1 h, then abandons the Ping and relies on baseline polling. |
| DC2-E02 | Ping produced no new feed content. Counts as noise against the domain's Ping quota. |
| DC2-E03 | Delta referenced in Feed but missing or corrupted at `deltas/<id>.json`. Typed rejection, visible to the Publisher via the status endpoint (§7.1). |
| DC2-E04 | Feed signature invalid. The pull is discarded; counts as noise against the quota. |

### 7.1. Publisher Status Endpoint

Aggregators MUST expose `GET <aggregator>/status/<domain>` returning, as
JSON, the domain's last successful pull time, pending rejections with
their DC-1/DC-2 error codes, current quota, and quarantine state. This is
the Publisher's debugging surface.

## 8. Security Considerations

- **Ping flooding.** Pings are the cheapest object in the system by
  design: no content, no crypto, one small POST. Amplification is
  minimal — a Ping triggers at most one conditional Feed fetch — and
  quotas (DC-4 §6) throttle abusive domains. Ingest Endpoints SHOULD
  additionally apply source-IP rate limits below the per-domain quotas.
- **Feed replay.** An attacker replaying an old `feed.json` cannot
  regress state: signatures bind content, `generated_at` monotonicity
  detects rollback, and Deltas already seen are idempotent (DC-1 §4).
- **Cache poisoning of `.well-known`.** All discovery and pulls are
  HTTPS-only; Aggregators MUST NOT accept any `deltacommons` resource
  over plain HTTP, and MUST NOT follow redirects that leave the domain's
  authority (a redirect from `example.com` to another host invalidates
  the pull).

## 9. Privacy Considerations

Pings reveal publication timing to the Aggregator, and Feeds are public
by construction — a Publisher's activity pattern is observable by anyone.
No reader or consumer data is involved at this layer: DC-2 concerns only
the Publisher→Aggregator direction, and Publishers learn nothing about
who consumes their Deltas.

## 10. Conformance Checklist

**Publisher:**

- [ ] Serves the three well-known paths over HTTPS with the layout of §3
- [ ] Delta files are immutable and named by hex digest (§3.1)
- [ ] Feed window ≤ 1000 IDs, publication order, immutable `next` pages,
      monotonic `generated_at` (§3.2)
- [ ] Pings with the exact one-field body of §4 and honors `Retry-After`

**Aggregator (ingest side):**

- [ ] Implements the pull sequence of §5 with signature validation at
      every step
- [ ] Runs baseline polling independent of Pings (§5)
- [ ] Never attributes unsigned-hint content to a domain (§6)
- [ ] Implements the Error Registry behaviors and the status endpoint (§7)
- [ ] HTTPS-only, same-authority-only fetching (§8)

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- DC-1: Delta Format & Identity — Envelope, Delta ID, Key Set, scope rule
- DC-3: Commons Log & Distribution — block queueing
- DC-4: Audit, Reputation & Governance — quotas, quarantine, auditor observations
