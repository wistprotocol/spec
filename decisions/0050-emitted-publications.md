# ADR-0050: A publication is emitted from the content's source, and `links` declares the links of the published content

**Status:** draft · **Date:** 2026-09-27

## Context

ADR-0041 made the Payload the publication: whether the resource at the
URL carries the same text "is not a protocol property". Two rules still
tie a Publisher to the page it serves. WIST-2 §10 requires declaring
`content.links` "by §11's extraction procedure exactly", §11 runs on
"the raw HTML response octets", and WIST-1 §3.6 requires an empty
`links` "for any non-HTML representation". WIST-2 §12 recommends
deriving `extract` from the whole document.

Read literally, those rules give three results nobody intends. A
Publisher whose page is assembled in the browser declares no link,
whatever its published text cites. A Publisher that holds its content
in a store must fetch its own page to fill `links`. And the declared
set carries the navigation and footer links an editorial `extract`
omits, which then enter the link graph Consumers build (WIST-3 §7).
WIST-1 §3.6 concedes that the rule is "checkable only against the page,
which no party in this suite is obliged to fetch".

A Publisher that derives its publications from served pages has two
further choices to make that a page cannot settle: which pages are
published, and which part of a page is its content. A listing of URLs
does not say which ones the owner wants indexed, and the text of a
whole document includes what surrounds the content. A wrong choice
lasts, because a sealed URL never leaves the Log (WIST-1 §9).

The machine-readable formats in widest use are written by the system
that stores the content, from the fields it stores: Open Graph tags on
72.2 % of websites and JSON-LD on 55.7 % (W3Techs, 2026-09-27), and
syndication feeds discoverable on 35.9 % of 196 598 sampled sites
(M. Nottingham, feed survey, 2026-05-11). Markup kept by hand in page
templates did not spread: microformats are on 0.5 % of websites.
Conversion of served HTML by an intermediary reads element names or
heuristics and does not see content rendered by script.

## Decision

### Emissions

A Publisher's content system states what it publishes as **Emissions**:
unsigned objects, one per URL, carrying the URL, the language, the
instant of the last change, the title, an optional abstract, and the
content as text or as an HTML fragment. A suite document, WIST-5,
defines the Emission, the header that opens a stream of them, and two
modes. A complete stream lists every publication of its Collection
(ADR-0051), so that absence is removal. An incremental stream lists
changes and removals.

The part of a Publisher that turns Emissions into signed objects reads
no page and makes no choice about content. It validates each Emission,
derives the Payload, and publishes nothing when an Emission names a URL
outside its Collection's Scope, a URL with no Normalized URL, or
content above a cap.

An Emission never reaches an Aggregator. WIST-5 binds the two parts of
a Publisher to each other, so that a content system written for one
signing tool works with another, and changes nothing an Aggregator or a
Consumer does.

### `links`

`links` declares the external links of the published content. Where
the content is emitted as an HTML fragment, they are extracted from
that fragment by WIST-2 §11's procedure; where it is emitted as text,
the Emission lists them in content order. Normalization, the exclusion
of the Publisher's own hosts, deduplication, `total` and truncation to
the longest prefix within `links_cap_bytes` are unchanged (WIST-1
§3.6). `extract` is derived from an HTML fragment by WIST-2 §12's
procedure.

WIST-2 §11 and §12 remain the suite's deterministic procedures. They
apply to the content a Publisher emits, and to a served page only for a
party that chooses to compare the page with the publication.

### Pages that declare themselves

WIST-5 carries an optional profile for a Publisher whose only store of
content is its pages. A page opts in with a marker and delimits its
content with a second one. An Emitter following the profile emits only
from pages that carry the first marker, and only the region the second
delimits. A page without the marker is never emitted, whatever listing
names it.

## Alternatives considered

- **Keep `links` a function of the served page.** Leaves the three
  results above in place, and nothing in the suite checks the rule.
- **The marked page as the protocol's source, read by the
  Aggregator.** Obliges an Aggregator to fetch pages, which ADR-0003
  and ADR-0041 removed, and excludes every page rendered by script.
- **A representation of each URL obtained by content negotiation.**
  Serves script-rendered sites, but detecting a change takes a request
  per URL and removal stays inferred.
- **Leave the format between the content system and the signing part
  to each tool.** Binds every content system to the one tool it was
  written for.

## Consequences

- WIST-2 §10's Publisher row on `links`, the opening paragraphs of §11
  and §12 and WIST-1 §3.6's paragraph on the `links` member are
  restated, and the Payload schema's description of `links` follows.
- ADR-0008 has the declared subset be "the first N links in raw-HTML
  document order" and calls the rule "an auditable function of the
  page". The order is now the emitted fragment's, and what the rule
  removes is the gap between the published content and its
  declaration.
- A page and its publication can differ more easily than when one was
  derived from the other. ADR-0041 leaves that comparison to Labelers
  and Consumers. A party that compares the raw HTML of a
  script-rendered page with its publication finds none of the
  published text in it.
- A Publisher with neither a content system nor marked pages writes
  its Emissions by hand.
- WIST-5 can gain a profile without a new version of any signed
  object, since no sealed object depends on it.

## Verification

Vectors carry: an Emission whose HTML fragment holds links the page
around it does not; an Emission of text with declared links; declared
links truncated at `links_cap_bytes`; a complete stream and an
incremental one that reach the same publications; an Emission refused
for a URL outside its Scope; a marked page, the same page without its
marker, and a marked page whose region is empty.
