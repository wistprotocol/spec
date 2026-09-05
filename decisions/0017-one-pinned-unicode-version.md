# ADR-0017: One pinned Unicode version for the whole suite

**Status:** accepted · **Date:** 2026-09-04
**Amends:** ADR-0014

## Context

Two of this suite's identity surfaces are Unicode algorithms. WIST-1 §2's
Canonical Host is UTS #46 processing, which is the Publisher's name, the
authority a Delta's `url` is scoped against, a key of the Record tuple and
therefore an input to `content_digest`. WIST-4 §5's similarity metric is
NFC, default full case-folding, untailored UAX #29 word segmentation and a
General Category filter, and it decides whether a Delta is `consistent`,
which decides penalties, sanctions and exclusion from materialization.

ADR-0014 pinned the UTS #46 flag profile after finding that two
implementations reaching for different defaults produced different
A-labels for the same host. It pinned the flags and stopped there. Every
one of these algorithms also reads the Unicode Character Database, and the
UCD changes at every release:

- A character unassigned in one release has General Category `Cn`. A §5
  segment containing only such characters is discarded at step 4. The
  release that assigns it as a letter keeps the same segment, so the two
  releases derive different word sequences — a different `similarity`, a
  different verdict, a different Confirmed Inconsistency.
- `Word_Break` and `Grapheme_Cluster_Break` gain entries the same way, so
  the same text segments differently, and the short-text branch counts a
  different number of clusters.
- The case-folding table gains entries, so two texts equal under one
  release differ under another.
- UTS #46's own mapping table is derived from the UCD, so the same host
  maps to different A-labels under two releases — the failure ADR-0014
  exists to close, reached by a route ADR-0014 left open.

§5 claims that "no two conforming Auditors can disagree about a boundary
case from rounding alone" and that selection is "recomputable rather than
merely reproducible-in-practice". Neither claim survives an unpinned
Unicode version: the arithmetic is exact and the inputs to it are not.

## Decision

Pin one Unicode version for the whole suite — **Unicode 16.0** — and read
every Unicode property from it: NFC, default full case-folding, UAX #29
word boundaries and extended grapheme clusters, General Category, and the
UTS #46 mapping and validity tables.

Moving the version is a change to the documents, not an implementation's
choice. Before a deployment exists it is a revision recorded in the errata;
after one it is a new major version, on the same footing as WIST-4 §8's
constitutional invariants, because the move changes identities and verdicts
the Log has already sealed.

An implementation whose platform offers only a later release is not
conforming. It does not approximate: the characters its platform assigned
are exactly the ones the two implementations will disagree about.

## Consequences

A character assigned after Unicode 16.0 is invisible to the metric until
the suite moves. Its segment is discarded by §5's filter, and a host using
it has no Canonical Host and cannot be a Publisher. That is the price of
recomputability, and it is paid in the same currency the rest of the suite
pays: a rule every party can apply identically, at the cost of a rule that
tracks the world.

The suite now names a version in two documents. `tools/` reads that
version's properties, and an implementation that must read them from a
platform library states which release that library carries.

## Alternatives considered

**The latest release at the time of evaluation.** Tracks the world at the
cost of the property the metric exists to have: two Auditors auditing the
same Delta on the same day, on platforms updated a month apart, derive
different verdicts, and a party replaying the Log years later reproduces
neither. It would leave §5's recomputability claim false in the ordinary
case rather than the exotic one.

**The version in force at the Block's `sealed_at`, as a Parameter Registry
value.** Recomputable, and it lets the suite move forward without a major
version. Rejected for what it costs every replaying party: correct replay
would require carrying every historical UCD release and selecting among
them per Block, so the cheapest conforming Consumer stops being one that
reads a platform library and starts being one that ships a Unicode
archive. The Registry's other values are integers a party compares; this
one would be a data set a party must possess.

**Pinning only the properties §5 reads, leaving §2 on the flag profile
alone.** Rejected because the two surfaces meet: WIST-2 §11 normalizes
every link target through §2's Canonical Host, and §5's link dimension
compares the sets that produces. Splitting the pin would leave the
citation graph and the metric over it on different releases.
