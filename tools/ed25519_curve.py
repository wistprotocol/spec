#!/usr/bin/env python3
"""edwards25519 group arithmetic and point encoding (RFC 8032 Section 5.1).

`cryptography` does not expose edwards25519 group operations, so the field
and group arithmetic the Ed25519 verification-profile vectors need — to
construct non-canonical encodings, small-order and mixed-order points and
unreduced scalars — is implemented here. It is written for clarity and
testability, NOT for constant-time execution: this module is a
specification aid and test-vector generator, not production key-handling
code.
"""
import hashlib

# --------------------------------------------------------------------------
# edwards25519 parameters — RFC 8032 Section 5.1, Table 1
# --------------------------------------------------------------------------
P = 2**255 - 19                                   # field prime
D = -121665 * pow(121666, P - 2, P) % P           # curve constant d
Q = 2**252 + 27742317777372353535851937790883648493   # group order L
COFACTOR = 8
BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960

class InvalidProof(Exception):
    """Raised where the RFC says an algorithm outputs "INVALID"."""


def _sha512(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for part in parts:
        h.update(part)
    return h.digest()


# --------------------------------------------------------------------------
# Group arithmetic, extended homogeneous coordinates (X, Y, Z, T),
# x = X/Z, y = Y/Z, x*y = T/Z — RFC 8032 Section 5.1.4
# --------------------------------------------------------------------------
IDENTITY = (0, 1, 1, 0)
BASE = (BX % P, BY % P, 1, BX * BY % P)


def _add(pt1, pt2):
    """RFC 8032 Section 5.1.4 addition (complete for a = -1)."""
    x1, y1, z1, t1 = pt1
    x2, y2, z2, t2 = pt2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _double(pt):
    """RFC 8032 Section 5.1.4 doubling."""
    x1, y1, z1, _ = pt
    a = x1 * x1 % P
    b = y1 * y1 % P
    c = 2 * z1 * z1 % P
    h = a + b
    e = h - (x1 + y1) ** 2
    g = a - b
    f = c + g
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _negate(pt):
    x, y, z, t = pt
    return (-x % P, y, z, -t % P)


def _mul(scalar: int, pt):
    """Scalar multiplication by double-and-add. `scalar` MUST be >= 0."""
    result = IDENTITY
    addend = pt
    while scalar > 0:
        if scalar & 1:
            result = _add(result, addend)
        addend = _double(addend)
        scalar >>= 1
    return result


def _equal(pt1, pt2) -> bool:
    x1, y1, z1, _ = pt1
    x2, y2, z2, _ = pt2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _is_identity(pt) -> bool:
    return _equal(pt, IDENTITY)


def _affine(pt):
    x, y, z, _ = pt
    zinv = pow(z, P - 2, P)
    return (x * zinv % P, y * zinv % P)


# --------------------------------------------------------------------------
# Type conversions — RFC 9381 Section 5.5 (little-endian) and RFC 8032
# --------------------------------------------------------------------------
def int_to_string(value: int, length: int) -> bytes:
    """RFC 8032 Section 5.1.2 — little-endian, fixed length."""
    return value.to_bytes(length, "little")


def string_to_int(data: bytes) -> int:
    """Little-endian interpretation (RFC 9381 Section 5.5)."""
    return int.from_bytes(data, "little")


def point_to_string(pt) -> bytes:
    """RFC 8032 Section 5.1.2 point encoding (32 octets)."""
    x, y = _affine(pt)
    return int_to_string(y | ((x & 1) << 255), 32)


def string_to_point(data: bytes):
    """RFC 8032 Section 5.1.3 point decoding. Raises InvalidProof on failure."""
    if len(data) != 32:
        raise InvalidProof("point string must be 32 octets")
    value = string_to_int(data)
    x_0 = (value >> 255) & 1              # step 1: bit 255 is lsb of x
    y = value & ((1 << 255) - 1)
    if y >= P:                            # step 1: y >= p -> decoding fails
        raise InvalidProof("y coordinate not in field")
    # step 2: x^2 = (y^2 - 1) / (d*y^2 + 1); x = u*v^3 * (u*v^7)^((p-5)/8)
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    v3 = v * v % P * v % P
    v7 = v3 * v3 % P * v % P
    x = u * v3 % P * pow(u * v7 % P, (P - 5) // 8, P) % P
    # step 3: pick the branch that actually squares to u/v
    if (v * x * x - u) % P != 0:
        if (v * x * x + u) % P == 0:
            x = x * pow(2, (P - 1) // 4, P) % P
        else:
            raise InvalidProof("no square root: not a curve point")
    # step 4: select the root matching x_0
    if x == 0 and x_0 == 1:
        raise InvalidProof("x = 0 with sign bit set")
    if x % 2 != x_0:
        x = P - x
    return (x, y, 1, x * y % P)
