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

### Streams

A stream is UTF-8 octets with no byte order mark, divided into lines
by LF (0x0A); the LF of the last line may be absent. The division
precedes the reading of a line's octets as UTF-8, so a fault of
encoding belongs to its line. A stream of no octets differs from the
form. Each line is one JSON object, which JSON whitespace may
surround, with no repeated member name, whose strings are sequences of
Unicode scalar values and in which no array or object lies inside a
member's array or object. Member names are compared after their
escapes are decoded. The first line is the header, the last is the
trailer, and each line between them is an Emission or a removal. An
object carries exactly the members listed for its kind. A line with a
`removed` member is read as a removal. A last line is the trailer when
it carries exactly the trailer's member set; any other last line is
read as a line before a missing trailer. The line of a stream of one
line is its first, so that stream lacks its trailer. A first line with another
member set than the header's, a line between the first and the last
that carries the header's member set or the trailer's, and a trailer
whose `end` is not `true` differ from the form. `count` is written in
decimal digits alone, without sign, fraction, exponent or leading
zero, and is at most 9007199254740991.

| Line | Members |
|---|---|
| Header | `wist_emission`, the string `1`; `publisher`, the Publisher's `domain`; `collection`, the Collection's name; `mode`, `complete` or `incremental` |
| Emission | `url`; `lang`, in the profile of WIST-1 §3.7; `modified`, a Publisher timestamp (WIST-1 §3.4); `title`; optionally `abstract`; and either `html`, or `text` with an optional array `links` of strings |
| Removal | `url`; `removed`, the value `true`. In an incremental stream only |
| Trailer | `end`, the value `true`; `count`, the number of lines between header and trailer |

The trailer exists because a complete stream cut short would
otherwise remove every publication it no longer lists.

The URL of a line is the Normalized URL (WIST-1 §2) of its `url`,
which is absolute and need not be spelled normalized; a relative
reference has no Normalized URL. The header's `publisher` is compared
with `domain` octet by octet.

The part that reads a stream refuses it whole, and publishes nothing
from it, on the first of these it meets, reading the lines in order
and, within a line, the conditions in the order of the table; a
missing trailer and a wrong `count` are met after the last line.
WIST-5 assigns the codes.

| Refusal | Condition |
|---|---|
| `stream-form` | The octets, a line, the header's or the trailer's place, or `count` differ from the form above |
| `header` | A header member of another value or type, a `publisher` or `collection` that is not the one the stream is read for, or a `collection` the Publisher's current Declaration does not name |
| `emission-form` | An Emission or a removal with another member set, a member of another type or profile, or a removal in a complete stream |
| `url` | A `url` with no Normalized URL |
| `duplicate` | Two lines with the same URL |
| `scope` | An Emission whose URL the Collection's Scope (ADR-0051) does not cover under the Publisher's current Declaration |
| `cap` | An Emission with the `JCS` serialization of its URL above `url_cap_bytes`, a derived `extract` above `extract_cap_bytes`, a `title` above 256 or an `abstract` above 1500 Unicode scalar values, or `JCS(summary)` above `summary_cap_bytes` (WIST-1 §3.6) |

A removal's URL is read for `url` and `duplicate` alone.

Each Emission yields one publication: its URL, `lang`, `modified` and
the Payload's `content` (WIST-1 §3.6), whose `summary` carries `title`
and, where present, `abstract`, unchanged.

A stream is applied to the Collection's published publications, from
which those the Scope no longer covers are first taken out. A complete
stream leaves exactly its own publications. An incremental stream
replaces or adds the publication of each Emission and takes out the
one each removal names; a removal that names no published URL has no
effect. A publication whose `lang` and `JCS(content)` equal the
published one's is unchanged and keeps the published `modified`.

The application states its plan in four lists of URLs. `added`,
`changed` and `unchanged` hold the URL of each Emission, by whether
the published publications, after those outside the Scope were taken
out, lack it, hold it with another `lang` or `content`, or hold it
unchanged. `removed` holds each published URL the result lacks. A
publication an incremental stream does not name is in no list.

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

Both procedures read the UTF-8 octets of `html`. §11 step 5 resolves
against the Emission's URL, and step 7 reads the header's `publisher`.
An `extract` derived from `text` is `text`, unchanged. Each member of
an Emission's `links` passes §11 steps 5 to 8, without the character
references of step 4; an Emission of `text` without `links` declares
`{"total": 0, "urls": []}`.

A link whose `JCS` serialization exceeds `link_url_cap_bytes` (WIST-1
§3.6) is discarded at step 6 with the links that have no Normalized
URL, and `total` does not count it. §11 did not state what becomes of
such a link, and a Payload that declares one is rejected.

### Pages that declare themselves

WIST-5 carries an optional profile for a Publisher whose only store of
content is its pages. A page opts in with a marker and delimits its
content with a second one. An Emitter following the profile emits only
from pages that carry the first marker, and only the region the second
delimits. A page without the marker is never emitted, whatever listing
names it.

The profile reads a page's URL and its octets, where the page is HTML
under WIST-2 §11 or a file its owner names as HTML. It scans as §11
steps 1 to 3 do, outside comments and raw-text elements, reading a
start tag's attributes by step 3 with the element's name in the place
of `a`. The start tags it reads so are those of `a`, `meta`, `title`
and `html`; a comment opens inside any other tag as §11 step 1 has it
open anywhere. Attribute values are compared and taken as octets,
before any character reference is decoded, and an attribute without a
value has the empty value.

| Part | Source in the page |
|---|---|
| Marker | A `meta` start tag whose first `name` attribute is `wist` and whose first `content` attribute is `publish` |
| Region | The octets between the first comment `<!--wist:content-->` and the first comment `<!--/wist:content-->` after it, both found outside raw-text elements |
| `html` | The region, decoded as UTF-8 with each invalid sequence replaced by U+FFFD |
| `title` | §12 applied to the octets between the first `title` start tag and the next `</title` in the octets after it, inside a comment or not, compared without case; the empty string where the page has no such start tag or no `</title` after it |
| `abstract` | §12 applied to the first `content` attribute of the first `meta` start tag whose first `name` attribute is `description`; absent where the page has no such tag or that tag has no `content` |
| `lang` | The first `lang` attribute of the first `html` start tag, with the letters before its first `-` in lowercase, where the result is in the profile of WIST-1 §3.7; `und` otherwise |
| `modified` | The instant the Emitter's source gives for the page's last change, or the instant of reading; never the page |

A page with the marker and without a whole region is not emitted. A
page whose region is empty is emitted with an empty `html`, as an
Emission of any source may carry empty content. The profile shortens
nothing: a page above a cap reaches the refusal of the stream that
carries it.

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
- **Refuse the one Emission that fails and publish the rest.** In a
  complete stream the refused URL would be absent and therefore
  removed, and the fault would reach the Log before its owner saw it.
- **A region delimited by an attribute on an element.** Finding the
  element's end takes a tree of elements, which two readers build
  differently from malformed markup; a pair of comments is found by
  the scan §11 already fixes.
- **An Emitter that shortens content above a cap.** The tool would
  choose what part of a page is published.

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

They are `vectors/wist5/emission-streams.json`,
`emission-derivation.json` and `marked-pages.json`, generated by
`tools/gen_emission_vectors.py` from the reference in
`tools/emissions.py` and `tools/marked_page.py`, and recomputed by
`tools/verify_emission_vectors.py`, which was written from this text
without the other three.
