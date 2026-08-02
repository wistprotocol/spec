#!/usr/bin/env python3
"""Shared Merkle tree primitives for DeltaCommons DC-3 (RFC 6962 discipline).

Hashing (DC-3 §4):
    leaf = SHA-256(0x00 || data)
    node = SHA-256(0x01 || left || right)

`merkle_root` is RFC 6962's Merkle Tree Hash MTH(D[n]), built iteratively
(pairwise levels, an unpaired trailing node promoted unchanged) rather than
via the recursive definition — the two are equivalent (the recursive split
point k = largest power of two < n always lands on an even boundary of the
iterative construction, by induction on n), and the iterative form is what
DC-3 §4 documents.

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
    DC-3 §4's `path` lists them in.
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
