# ADR-0021: One Zstandard frame per Block file

**Status:** draft · **Date:** 2026-09-10

## Context

WIST-3 §6 binds a Block file's declared decompressed size to its canonical
Block bytes. Zstandard also permits concatenated and skippable frames.
A trailing empty frame or skippable metadata can leave the decompressed
bytes unchanged, so length equality alone does not determine file validity.

## Decision

A Block file contains exactly one standard Zstandard frame, from its magic
number through its final compressed block and optional checksum. The frame
ends at the end of the file. Reject concatenated frames, skippable frames
at any position and trailing bytes as `WIST3-E03`, even when they add no
decompressed bytes. That one frame declares the complete Block size;
existing transport, actual-length and accepted-schedule checks still apply.

Compression level, standard frame header variants and optional checksums
remain available. This decision introduces no dictionary distribution
mechanism and no compressed-input byte budget.

## Consequences and alternatives

Checking the decoder's output length is insufficient: validators must also
check frame composition and complete consumption of the file. One frame
gives the declared size a single meaning independent of decoder defaults.

Allowing concatenation would require aggregate size declarations and rules
for empty frames; allowing skippable frames would add unauthenticated
metadata with no protocol use. Both alternatives complicate a file that
carries one signed Block. Rejecting them does not bound compressed input
size, decompression work or network buffering; those need separate limits.

## Verification

`vectors/wist3/block-frames.json` carries exact raw-frame encodings of a
signed canonical Block, concatenated empty and nonempty frames, skippable
frames, trailing bytes, truncations, size mismatches and cap boundaries.
An undersized-window case exercises RFC 8878's raw-block size limit even
when a general-purpose decoder accepts the frame permissively.
`tools/validate_examples.py` independently decodes the fixture's raw blocks;
it does not implement general Zstandard entropy decoding. Valid compressed
and checksummed frames additionally require independent decoder checks.
