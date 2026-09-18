#!/usr/bin/env python3
"""Shared Merkle tree primitives for WIST WIST-3 (RFC 6962 discipline).

Hashing (WIST-3 §4):
    leaf = SHA-256(0x00 || data)
    node = SHA-256(0x01 || left || right)

`merkle_root` is RFC 6962's Merkle Tree Hash MTH(D[n]), built iteratively
(pairwise levels, an unpaired trailing node promoted unchanged) rather than
via the recursive definition — the two are equivalent (the recursive split
point k = largest power of two < n always lands on an even boundary of the
iterative construction, by induction on n), and the iterative form is what
WIST-3 §4 documents.

`audit_path` is RFC 6962 §2.1.1's PATH(m, D[n]) function, used to *generate*
an Inclusion Proof's `path`. It is deliberately a different algorithm from
`verify_inclusion`'s fn/sn walk (in tools/validate_examples.py), which
*verifies* one: keeping generation and verification independently
implemented is what lets the exhaustive property test in
tools/validate_examples.py catch a bug in either without both sides sharing
the same mistake.
"""
import hashlib


def leaf_hash(b: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + b).digest()


def node_hash(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()


def merkle_root(leaves: list) -> bytes:
    """RFC 6962 MTH(D[n]) for a non-empty list of leaf hashes."""
    if not leaves:
        raise ValueError("merkle_root requires at least one leaf")
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0]


def audit_path(index: int, leaves: list) -> list:
    """RFC 6962 §2.1.1 PATH(m, D[n]): the audit path for leaf `index`.

        PATH(0, {d(0)}) = {}
        for n > 1, k = largest power of two < n:
            PATH(m, D[n]) = PATH(m, D[0:k])     : MTH(D[k:n])   if m <  k
            PATH(m, D[n]) = PATH(m - k, D[k:n]) : MTH(D[0:k])   if m >= k

    Returns sibling hashes leaf-level first, root-level last — the order
    WIST-3 §4's `path` lists them in.
    """
    if not (0 <= index < len(leaves)):
        raise ValueError("index out of range")

    def rec(m: int, d: list) -> list:
        n = len(d)
        if n <= 1:
            return []
        k = 1
        while k * 2 < n:
            k *= 2
        if m < k:
            return rec(m, d[:k]) + [merkle_root(d[k:])]
        else:
            return rec(m - k, d[k:]) + [merkle_root(d[:k])]

    return rec(index, list(leaves))


def _perfect_root(leaves: list, start: int, count: int) -> bytes:
    """MTH over leaves[start:start+count] where count is a power of two."""
    level = leaves[start:start + count]
    while len(level) > 1:
        level = [node_hash(level[i], level[i + 1])
                 for i in range(0, len(level), 2)]
    return level[0]


def consistency_proof(m: int, n: int, leaves: list) -> list:
    """RFC 6962 §2.1.2 PROOF(m, D[n]) over a list of leaf hashes.

    Empty when m == 0 (the empty tree is a prefix of every tree) and when
    m == n, where the two roots are equal instead (WIST-3 §4).
    """
    if not (0 <= m <= n <= len(leaves)):
        raise ValueError("require 0 <= m <= n <= len(leaves)")
    if m == 0 or m == n:
        return []

    def sub(m: int, d: list, b: bool) -> list:
        if m == len(d):
            return [] if b else [merkle_root(d)]
        k = 1
        while k * 2 < len(d):
            k *= 2
        if m <= k:
            return sub(m, d[:k], b) + [merkle_root(d[k:])]
        return sub(m - k, d[k:], False) + [merkle_root(d[:k])]

    return sub(m, list(leaves), True)


def tile_hashes(leaves: list, level: int) -> list:
    """The [tlog-tiles] hashes at tree level `level`: the roots of the
    complete 2**level-leaf subtrees, left to right. An incomplete trailing
    subtree contributes no hash at this level."""
    width = 1 << level
    return [_perfect_root(leaves, i, width)
            for i in range(0, len(leaves) - len(leaves) % width, width)]


def tile_bytes(hashes: list) -> bytes:
    """A [tlog-tiles] tile: its hashes concatenated, 32 octets each."""
    return b"".join(hashes)


def entry_bundle_bytes(entries_jcs: list) -> bytes:
    """A [tlog-tiles] entry bundle (WIST-3 §6): each Entry's JCS
    serialization prefixed by its length as a big-endian uint16."""
    out = bytearray()
    for data in entries_jcs:
        if len(data) > 0xFFFF:
            raise ValueError("Entry exceeds the 65 535-octet bound (WIST-3 §3.3)")
        out += len(data).to_bytes(2, "big") + data
    return bytes(out)


def tile_path_index(n: int) -> str:
    """[tlog-tiles]'s path encoding of a tile index: three-digit groups,
    every group but the last prefixed with `x`."""
    groups = []
    while True:
        groups.append("%03d" % (n % 1000))
        n //= 1000
        if not n:
            break
    groups.reverse()
    return "/".join(["x" + g for g in groups[:-1]] + [groups[-1]])


def tile_path(level: int, index: int, width: int = 0) -> str:
    """`/tile/<L>/<N>` or `/tile/entries/<N>`, with `.p/<W>` for a partial
    tile. `level` is the tile level, or the string `entries`."""
    path = "/tile/%s/%s" % (level, tile_path_index(index))
    return path + (".p/%d" % width if width else "")
