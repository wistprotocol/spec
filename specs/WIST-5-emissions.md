# WIST-5: Emissions

**Status:** v1.0.0-draft · **Date:** 2026-10-02 · **License:** CC-BY 4.0

## 1. Introduction

A Publisher's content system states what it publishes as **Emissions**:
unsigned objects, one per URL, written by the system that stores the
content. A second part of the Publisher reads them, derives each
publication and signs the Catalogs that commit to it
([WIST-1](WIST-1-item-format.md) §3.5).

This document defines:

- the **stream** that carries Emissions, and the refusals of the part
  that reads it (§3);
- the **publication** an Emission yields (§4);
- the **application** of a stream to a Collection's publications, and
  its plan (§5);
- how the part of a Publisher that signs derives a Catalog's list,
  chooses its `generated_at` and decides that a Catalog is due (§6);
- an optional **marked-page profile** for a Publisher whose only store
  of content is its pages (§7).

An Emission never reaches an Aggregator. This document binds the two
parts of a Publisher to each other, so that a content system written for
one signing tool works with another, and changes nothing an Aggregator or
a Consumer does. No sealed object depends on it.

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as
shown here.

Terms of WIST-1 §2 keep their meaning. This document adds:

- **Emission**: an unsigned object stating what the Publisher publishes
  at one URL (§3.2).
- **Stream**: a sequence of lines that opens with a header, carries
  Emissions and removals, and closes with a trailer (§3).
- **The part that reads a stream**: the part of a Publisher that
  validates a stream, derives its publications and applies it (§3 to §5).
  It reads no page and makes no choice about content.
- **The part that signs**: the part of a Publisher that derives the list
  of a Catalog and signs it (§6).
- **Publication**: what one Emission yields — a URL, a `lang`, a
  `modified` and the Payload's `content` (§4).
- **Published publications** of a Collection: the result of the last
  stream applied to it (§5), whether or not a Catalog was signed since;
  none before the first application.
- **Served Catalog** of a Collection:
  [WIST-2](WIST-2-site-publication.md) §3.1's.
- **Served Declaration**: the Publisher Declaration (WIST-1 §5.1) the
  Publisher serves when the stream is read or the Catalog is signed.
- **Suite value** of a parameter: its default in
  [WIST-4](WIST-4-governance.md) §5; for `removal_retention_days`, the
  180 days WIST-3 §7 fixes for every Log.

**Parameters.** The part that reads a stream and the part that signs
read every parameter at its suite value, whatever a Log has amended,
since a Publisher reads no Log's parameters: `url_cap_bytes` (2048),
`extract_cap_bytes` (32 768), `summary_cap_bytes` (2048),
`links_cap_bytes` (4096), `link_url_cap_bytes` (2048),
`catalog_items_max`, `clock_skew_seconds`, `removal_retention_days` and
`catalog_refresh_seconds` included. WIST-4 §5 keeps every Log at or
above the five caps and `catalog_items_max`. It does not so bound
`clock_skew_seconds`: a Log that lowered it can refuse a Catalog §6.1
places ahead of the clock (`WIST1-E06`).

## 3. Streams

### 3.1. Form

A stream is UTF-8 octets with no byte order mark, divided into lines by
LF (0x0A); the LF of the last line MAY be absent. The division precedes
the reading of a line's octets as UTF-8, so a fault of encoding belongs
to its line. A stream of no octets differs from the form.

Each line is one JSON object [RFC 8259], which JSON whitespace MAY
surround:

- no member name is repeated, names being compared after their escapes
  are decoded;
- every string, member names included, is a sequence of Unicode scalar
  values after its escapes are decoded;
- no array or object lies inside a member's array or object;
- every number, rounded to the nearest IEEE 754 binary64 value with
  ties to even, is finite: a number beyond that range, such as `1e999`
  or 2^1024 − 2^970, differs from the form wherever it appears, while a
  finite number in a member of another type is a fault of that member
  (§3.3).

The first line is the header, the last is the trailer, and each line
between them is an Emission or a removal. An object carries exactly the
members listed for its kind (§3.2).

- A first line with another member set than the header's differs from
  the form.
- A line with a `removed` member is read as a removal.
- A last line is the trailer when it carries exactly the trailer's
  member set. Any other last line is read as a line before a missing
  trailer, one with the header's member set included: that line is
  refused with `emission-form`, met before the missing trailer.
- The line of a stream of one line is its first, so that stream lacks
  its trailer.
- A line between the first and the last that carries the header's
  member set or the trailer's differs from the form.
- A trailer whose `end` is not `true`, or whose `count` is not a number
  written in decimal digits alone — without sign, fraction, exponent or
  leading zero — and at most 9007199254740991, differs from the form.

The trailer exists because a complete stream cut short would otherwise
remove every publication it no longer lists.

### 3.2. Lines

| Line | Members |
|---|---|
| Header | `wist_emission`, the string `1`; `publisher`, the Publisher's `domain` (WIST-1 §3.8); `collection`, the Collection's name (WIST-1 §5.1); `mode`, `complete` or `incremental` |
| Emission | `url`; `lang`, in the profile of WIST-1 §3.7; `modified`, a Publisher timestamp (WIST-1 §3.4); `title`; optionally `abstract`; and either `html`, or `text` with an optional array `links` of strings. Every member but `links` is a string |
| Removal | `url`, a string; `removed`, the value `true`. In an incremental stream only |
| Trailer | `end`, the value `true`; `count`, the number of lines between header and trailer |

A **complete** stream lists every publication of its Collection, so that
absence is removal. An **incremental** stream lists changes and
removals.

The **URL of a line** is the Normalized URL (WIST-1 §2) of its `url`,
which is absolute and need not be spelled normalized; a relative
reference has no Normalized URL. The header's `publisher` is compared
with `domain` octet by octet. `html` and `text` MAY be empty. An
Emission of `text` lists in `links` the links of that text, in content
order.

```
{"wist_emission":"1","publisher":"example.com","collection":"default","mode":"complete"}
{"url":"https://example.com/blog/coffee","lang":"en","modified":"2026-09-27T14:00:00Z","title":"Brewing coffee","abstract":"Step by step.","html":"<p>Boil the water.</p>"}
{"end":true,"count":1}
```

Schema of one line:
[`schemas/emission.schema.json`](../schemas/emission.schema.json). The
schema states member sets and types; this section's rules on octets,
lines and order hold beside it.

### 3.3. Refusals

A stream is read for one Publisher and one Collection. The part that
reads it MUST refuse it whole, and publish nothing from it, on the first
of these conditions it meets, reading the lines in order and, within a
line, the conditions in the order of the table. A missing trailer and a
wrong `count` are met after the last line.

| Code | Condition |
|---|---|
| `stream-form` | The octets, a line, the header's or the trailer's place, or `count` differ from the form of §3.1; or `count` is not the number of lines between header and trailer |
| `header` | A header member of another value or type, a `publisher` or `collection` that is not the one the stream is read for, or a `collection` the served Declaration does not name |
| `emission-form` | An Emission or a removal with another member set, a member of another type or profile, or a removal in a complete stream |
| `url` | A `url` with no Normalized URL |
| `duplicate` | Two lines with the same URL; the later line is the one refused |
| `scope` | An Emission whose URL the Collection's Scope (WIST-1 §5.1) does not cover under the served Declaration |
| `cap` | An Emission or a removal with the JCS serialization of its URL above `url_cap_bytes`; or an Emission whose new Item of kind `page` (§6.2, second row) would have a JCS serialization above 16 384 + `url_cap_bytes` octets, whether or not its content is unchanged, which bounds `lang` and `modified`; a derived `extract` above `extract_cap_bytes`; a `title` above 256 or an `abstract` above 1500 Unicode scalar values; or `JCS(summary)` above `summary_cap_bytes` (WIST-1 §3.6) |

A removal's URL is read for `url`, `duplicate` and `cap` alone: a
removal MAY name a URL the Scope does not cover. A served Declaration
without `collections` names the Collection `default` alone (WIST-1
§5.1).

A refused stream changes no publication. A refusal reports its code and,
for a condition met in a line, the number of that line, the header being
line 1. A byte order mark is met in line 1 and a `count` that differs
from the form in the trailer's line; a missing trailer, a `count` that
is not the number of lines and a stream of no octets are reported with
no line.

**Rationale.** Refusing the one Emission that fails and publishing the
rest would, in a complete stream, leave the refused URL absent and
therefore removed, and the fault would reach the Log before its owner
saw it.

## 4. The Publication of an Emission

Each Emission yields one publication: the URL of its line, its `lang`,
its `modified` and the `content` of a Payload (WIST-1 §3.6).

| Member of `content` | Value |
|---|---|
| `extract` | For `html`, the result of WIST-2 §12 over the UTF-8 octets of `html`; for `text`, `text` unchanged |
| `links` | For `html`, the result of WIST-2 §11 over the UTF-8 octets of `html`; for `text`, the result of WIST-2 §11's steps for declared links over the members of `links` in their order, or `{"total": 0, "urls": []}` where the Emission has no `links` |
| `summary` | `title` and, where present, `abstract`, unchanged |

WIST-2 §11 resolves each candidate against the URL of the line, and
its step 7 reads the header's `publisher` as the Publisher's domain. Normalization,
deduplication, `total`, the discard of a link above `link_url_cap_bytes`
and truncation to the longest prefix within `links_cap_bytes` are WIST-1
§3.6's and WIST-2 §11's, unchanged. The part that reads a stream
shortens no `extract`, `title` or `abstract`: a value above its cap is
the refusal `cap` (§3.3).

`links` therefore declares the external links of the published content,
and of no page around it.

## 5. Application and the Plan

A stream that meets no refusal is **applied** to the published
publications of its Collection:

1. Every published publication whose URL the Collection's Scope does
   not cover under the served Declaration is taken out.
2. A complete stream leaves exactly the publications of its Emissions.
   An incremental stream replaces or adds the publication of each
   Emission and takes out the publication each removal names; a removal
   that names no published URL changes no publication.
3. A publication whose `lang` and `JCS(content)` equal those of the
   published publication of its URL is **unchanged**: the published
   one stays, with its `modified`, whatever the Emission's `modified`
   says.

The application states its **plan** in four sets of URLs:

| Set | URLs |
|---|---|
| `added` | The URL of each Emission for which the published publications, after step 1, hold none |
| `changed` | The URL of each Emission for which they hold a publication with another `lang` or `content` |
| `unchanged` | The URL of each Emission whose publication is unchanged |
| `removed` | Each published URL the result lacks, those taken out at step 1 included |

A publication an incremental stream does not name and the result holds
is in no set, and so is the URL of a removal that names no published
URL. The result is the Collection's published publications from then on:
a second stream applied before a Catalog is signed is applied to the
result of the first.

## 6. Signing Catalogs

### 6.1. The Instant and the Due Catalog

A Catalog of a Collection is **due**, whether or not its list changed,
once the clock of the part that signs, cut to the whole second, is at or
after the served Catalog's `generated_at` plus `catalog_refresh_seconds`
(604 800 seconds), and at any clock for a Collection with no served
Catalog. The part that signs MUST sign every due Catalog when it runs,
and MAY sign a Catalog that is not due; the result of an application
(§5) is published by the next Catalog signed for its Collection. A
Publisher MUST run it at least once in every `catalog_refresh_seconds`,
so that each Catalog is signed less than twice that interval after the
one before (WIST-3 §3.2).

No Catalog is due or signed for a Collection the served Declaration
does not name, whatever files the Publisher still serves for it: the
part that signs refuses with `collection` (§6.3). Every Log in which
that Declaration is in force refuses such a Catalog with `WIST1-E03`
(WIST-3 §3.3), and the files served for the Collection end by WIST-2
§3.1.

The `generated_at` of a Catalog is the later of the clock of the part
that signs, cut to the whole second, and the served Catalog's
`generated_at` plus one second; for a Collection with no served Catalog
it is the clock, cut to the whole second. When that instant is more than
`clock_skew_seconds` beyond the clock, cut to the whole second, the part
that signs MUST refuse with `catalog-instant` and sign nothing for the
Collection: its clock is wrong, or no Aggregator accepted the served
Catalog (WIST-1 §3.4).

### 6.2. From Publications to Items

The part that signs derives the list of a Catalog from the list of the
served Catalog, the published publications, the URLs named by the
removals of every incremental stream applied since the served Catalog
was signed, and the Catalog's `generated_at` (§6.1).

It first takes out of the published publications, for good, those whose
URL the Collection's Scope does not cover under the served Declaration,
so a Catalog signed with no stream lists their served Items as removed. The first condition
below that an Item, a publication or a URL meets decides.

| Condition | In the new list |
|---|---|
| A publication whose URL has a served Item of kind `page` with the publication's `lang` as `meta.lang` and a Payload, held by the part that signs and passing WIST-1 §7's Payload checks against the Item's `payload`, whose `JCS(content)` equals the publication's | The served Item and its Payload, unchanged, with its salt and its `observed_at` |
| Any other publication | A new Item of kind `page`: `url`, the publication's URL; `observed_at`, its `modified`; `meta`, its `lang` alone; `payload`, the commitment to its `content` under a fresh salt (WIST-1 §3.6) |
| A served Item of kind `page` whose URL has no publication | An Item of kind `removed` whose `observed_at` is the Catalog's `generated_at` |
| A served Item of kind `removed` whose URL has no publication | The served Item, unchanged, while `generated_at` is earlier than its `observed_at` plus `removal_retention_days` (180) of 86 400 seconds each; nothing from that instant on |
| A URL a removal of the stream names, with no publication and no served Item, whether or not the Collection's Scope covers it | An Item of kind `removed` whose `observed_at` is the Catalog's `generated_at` |

A new Item's `publisher` is the Publisher's `domain`, and the Payload of
a new Item of kind `page` carries the `wist_version` of the Catalog. A
served Item whose `publisher` is not the Publisher's `domain` is read as
an Item of kind `page` whose Payload is not held, so a new Item takes
its place.

The Catalog's `size`, `root` and `tree`, the tree files and the order of
the list are WIST-1 §3.5 and §4's. The change list that leads to the new
Catalog is WIST-2 §3.1's.

### 6.3. Refusals of the Part that Signs

The part that signs MUST refuse, and sign no Catalog of the Collection,
on the first of these it meets, in the order of the table.

| Code | Condition |
|---|---|
| `collection` | The served Declaration does not name the Collection |
| `catalog-instant` | The `generated_at` of §6.1 is more than `clock_skew_seconds` (600) beyond the clock, cut to the whole second |
| `served-list` | The list of the served Catalog holds two Items of one URL |
| `item-instant` | The new list holds an Item whose `observed_at` is later than the Catalog's `generated_at` |
| `catalog-size` | The new list holds more than `catalog_items_max` (16 777 216) Items |

`collection` is first because no Catalog of that Collection can be
accepted, and `catalog-instant` precedes the rest because the instant is
an input of the derivation. Each refusal stops the Catalog of its Collection alone: the
served Catalog stays served, the published publications stay as they
were, and the Catalogs of the Publisher's other Collections proceed.

## 7. The Marked-Page Profile

This profile is OPTIONAL. It serves a Publisher whose only store of
content is its pages. A page opts in with a marker and delimits its
content with a pair of comments. A content system following the profile
MUST emit only from pages that carry the marker, and only the region the
comments delimit. A page without the marker is never emitted, whatever
listing names it.

The profile reads a page's URL and its octets, where the page is HTML
under WIST-2 §11 or a file its owner names as HTML. It scans as WIST-2
§11 steps 1 to 3 do, outside comments and raw-text elements, reading a
start tag's attributes by step 3 with the element's name in the place of
`a`. The start tags it reads so are those of `a`, `meta`, `title` and
`html`; a comment opens inside any other tag as §11 step 1 has it open
anywhere. Attribute values are compared and taken as octets, before any
character reference is decoded, and an attribute without a value has the
empty value.

| Part | Source in the page |
|---|---|
| Marker | A `meta` start tag whose first `name` attribute is `wist` and whose first `content` attribute is `publish` |
| Region | The octets between the first comment `<!--wist:content-->` and the first comment `<!--/wist:content-->` after it, both found outside raw-text elements and compared octet by octet, so another case or inner spacing delimits nothing |
| `url` | The page's URL, as the content system holds it |
| `html` | The region, decoded as UTF-8 |
| `title` | WIST-2 §12 applied to the octets between the first `title` start tag and the next `</title` in the octets after it, inside a comment or not, compared without case; the empty string where the page has no such start tag or no `</title` after it |
| `abstract` | WIST-2 §12 applied to the first `content` attribute of the first `meta` start tag whose first `name` attribute is `description`; absent where the page has no such tag or that tag has no `content` |
| `lang` | The first `lang` attribute of the first `html` start tag, with each of the letters A to Z (0x41 to 0x5A) before its first `-`, or in the whole value where it has none, mapped to a to z and no other character mapped, where the result is in the profile of WIST-1 §3.7; `und` otherwise |
| `modified` | The instant the content system's source gives for the page's last change, or the instant of reading; never a value read from the page |

Where the profile decodes octets as UTF-8, in the `html` row and at
WIST-2 §12 step 3 for `title` and `abstract`, each maximal subpart of an
ill-formed subsequence (Unicode 16.0 §3.9, "U+FFFD Substitution of
Maximal Subparts") is replaced by one U+FFFD.

A page with the marker and without a whole region is not emitted. A page
whose region is empty is emitted with an empty `html`. The profile
shortens nothing: a page above a cap reaches the refusal of the stream
that carries it (§3.3).

**Rationale.** A region delimited by an attribute on an element would
take a tree of elements to find the element's end, which two readers
build differently from malformed markup; a pair of comments is found by
the scan WIST-2 §11 already fixes.

## 8. Error Registry

The codes of §3.3 and §6.3 are this document's registry. They are
reported by one part of a Publisher to its operator: none appears in a
sealed object, on a status endpoint (WIST-2 §7.1) or in any exchange
with an Aggregator, so they carry no `WISTn-Enn` form.

| Code | Raised by | Effect |
|---|---|---|
| `stream-form`, `header`, `emission-form`, `url`, `duplicate`, `scope`, `cap` | The part that reads a stream (§3.3) | The stream is refused whole; no publication changes |
| `collection`, `catalog-instant`, `served-list`, `item-instant`, `catalog-size` | The part that signs (§6.3) | No Catalog of the Collection is signed |

## 9. Security Considerations

- **A sealed URL never leaves the Log.** An Item sealed for a URL stays
  in every Log that sealed it (WIST-1 §9). The plan (§5) names every URL
  a stream adds, changes or removes before any signature exists; a
  Publisher that reads it before signing sees a wrong visibility rule in
  its content system while the fault is still private.
- **Whole-stream refusal.** A complete stream cut short, or one with a
  single faulty line, removes or publishes nothing (§3.3): absence is
  removal only in a stream whose trailer and `count` were read.
- **No key in the content system.** An Emission is unsigned, so the
  system that knows the content holds no signing key, and the part that
  signs needs no access to the content's store.
- **Trust between the parts.** The part that reads a stream publishes
  what the stream states. Whoever can write a stream the Publisher
  reads can publish and remove under the Publisher's name, within the
  Collection's Scope; the channel between the two parts is the
  Publisher's to protect.
- **Scope.** A stream publishes nothing outside its Collection's Scope
  (§3.3), so a content system given one Collection cannot publish under
  another's URLs.
- **A page and its publication can differ.** `extract` and `links` are
  those of the emitted content (§4). Whether the resource at the URL
  carries the same content is not a protocol property (WIST-1 §3.6); a
  party that compares the raw HTML of a script-rendered page with its
  publication finds none of the published text in it.

## 10. Privacy Considerations

- A marked page publishes only its region (§7), and an unmarked page
  nothing: the marker is the owner's statement, per page, that the
  region is public.
- `modified` discloses when content changed. An unchanged publication
  keeps its published `modified` (§5), so a stream regenerated without
  a change of content discloses no new instant.
- Removal takes a URL's Item out of the Catalog and leaves what Logs
  sealed (WIST-1 §9); erasure of a sealed Payload is WIST-3 §6.2's.

## 11. Conformance Checklist

**Content system (writes streams):**

- [ ] Writes streams in the form of §3.1 with the lines of §3.2, the
      trailer's `count` included
- [ ] Lists every publication of the Collection in a complete stream,
      and writes removals in incremental streams alone (§3.2)
- [ ] Where it follows the marked-page profile, emits only from pages
      with the marker and only the delimited region, and takes
      `modified` from no page (§7)

**The part that reads a stream:**

- [ ] Refuses a stream whole on the first condition of §3.3 in line and
      table order, reports the code and line, and changes no publication
- [ ] Derives `extract`, `links` and `summary` by §4 and shortens no
      value above a cap
- [ ] Applies a stream by §5, keeps an unchanged publication with its
      published `modified`, and states the plan in the four sets
- [ ] Reads every parameter at its suite value (§2)

**The part that signs:**

- [ ] Signs every due Catalog when it runs, with the `generated_at` of
      §6.1
- [ ] Derives each list by §6.2, keeping a served Item, its salt and
      its `observed_at` for unchanged content, and an Item of kind
      `removed` for `removal_retention_days`
- [ ] Refuses by §6.3 in the order of its table, for the Collection
      alone
- [ ] Writes the change list WIST-2 §3.1 requires before the Catalog is
      served

## Appendix A. Test Vectors

| File | Content |
|---|---|
| `vectors/wist5/emission-streams.json` | Streams with each refusal of §3.3, its line and the order among refusals; caps with twins at the bound; application of complete and incremental streams and the plan (§5) |
| `vectors/wist5/emission-derivation.json` | `extract` and `links` of `html` and of `text` (§4) |
| `vectors/wist5/marked-pages.json` | The marker, the region, `title`, `abstract` and `lang` of §7, and the publication each emitted page yields |
| `vectors/wist2/item-lists.json` | The list derivation of §6.2 with `collection`, `served-list`, `item-instant` and `catalog-size`, and the order of §6.3 |
| `vectors/wist2/catalog-order.json` | The `generated_at`, the due Catalog and `catalog-instant` (§6.1) |

## References

- [RFC 2119] / [RFC 8174] BCP 14 key words
- [RFC 8259] The JavaScript Object Notation (JSON) Data Interchange
  Format
- [RFC 8785] JSON Canonicalization Scheme (JCS)
- The Unicode Standard, Version 16.0, §3.9
- WIST-1: Item Format & Identity — Items, Catalogs, the Payload, the
  Declaration and its Collections
- WIST-2: Site Publication — Collection files, change lists, §11 link
  extraction, §12 text extraction
- WIST-3: Logbook & Distribution — the refresh rule (§3.2)
- WIST-4: Governance & Parameters — the suite values of §5
