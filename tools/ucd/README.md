# Unicode Character Database conformance tests

`WordBreakTest.txt` and `GraphemeBreakTest.txt` as published by the Unicode
Consortium for the release ADR-0017 pins, vendored unchanged.

They are the known-answer test for `tools/segmentation.py`, which
implements UAX #29's default word boundaries and extended grapheme
clusters — the segmentation WIST-4 §5 measures similarity over. The
harness runs every case on each invocation (`unicode:uax29-conformance`),
so an implementation of the annex written from its text is checked against
the Consortium's own expectations rather than against a second reading of
the same text.

Source: `https://www.unicode.org/Public/16.0.0/ucd/auxiliary/`
