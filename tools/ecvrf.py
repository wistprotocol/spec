#!/usr/bin/env python3
"""ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) in pure Python.

Implements the ciphersuite defined in RFC 9381 Section 5.5:

    suite_string = 0x03
    G            = edwards25519 (RFC 8032 Section 5.1, Table 1)
    fLen = qLen = ptLen = 32, cLen = 16, hLen = 64, cofactor = 8
    Hash                    = SHA-512
    secret scalar / pub key = RFC 8032 Section 5.1.5 (SHA-512 + pruning)
    encode_to_curve_salt    = PK_string
    encode_to_curve         = try_and_increment (RFC 9381 Section 5.4.1.1)
                              with interpret_hash_value_as_a_point(s)
                                   = string_to_point(s[0]...s[31])
    nonce_generation        = RFC 8032 style (RFC 9381 Section 5.4.2.2)
    int_to_string           = little-endian (RFC 8032 Section 5.1.2)
    string_to_int           = little-endian
    point_to_string         = RFC 8032 Section 5.1.2 encoding
    string_to_point         = RFC 8032 Section 5.1.3 decoding

Every constant and every step below is transcribed from the RFC text, not
recalled: see the inline `RFC 9381 Section x.y step n` citations. The
module is proved correct by `self_test()`, which replays RFC 9381
Appendix B.3 (Examples 16, 17 and 18 — the vectors for *this* ciphersuite;
Appendix B.1 is the P-256 suite) including every published intermediate
value (x, H, k_string, k, U = k*B, V = k*H, pi, beta), not merely the
final outputs.

`cryptography` does not expose edwards25519 group operations, so the field
and group arithmetic is implemented here. It is written for clarity and
testability, NOT for constant-time execution: this module is a
specification aid and test-vector generator, not production key-handling
code (RFC 9381 Section 7.5 discusses side channels).

Public API:
    prove(sk_seed: bytes, alpha: bytes) -> bytes   # 80-octet pi_string
    proof_to_hash(pi: bytes) -> bytes              # 64-octet beta_string
    verify(pk: bytes, alpha: bytes, pi: bytes) -> bool
    public_key(sk_seed: bytes) -> bytes            # 32-octet PK_string
"""
import hashlib

# --------------------------------------------------------------------------
# edwards25519 parameters — RFC 8032 Section 5.1, Table 1
# --------------------------------------------------------------------------
P = 2**255 - 19                                   # field prime
D = -121665 * pow(121666, P - 2, P) % P           # curve constant d
Q = 2**252 + 27742317777372353535851937790883648493   # group order L
COFACTOR = 8                                      # RFC 9381 Section 5.5
BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960

# --------------------------------------------------------------------------
# Ciphersuite constants — RFC 9381 Section 5.5 (ECVRF-EDWARDS25519-SHA512-TAI)
# --------------------------------------------------------------------------
SUITE_STRING = b"\x03"
CLEN = 16
QLEN = 32
PTLEN = 32
HLEN = 64
PI_LEN = PTLEN + CLEN + QLEN                      # 80

# Domain separators, quoted verbatim from the RFC steps that define them.
_ENCODE_TO_CURVE_DS_FRONT = b"\x01"   # Section 5.4.1.1 step 2
_ENCODE_TO_CURVE_DS_BACK = b"\x00"    # Section 5.4.1.1 step 3
_CHALLENGE_DS_FRONT = b"\x02"         # Section 5.4.3 step 1
_CHALLENGE_DS_BACK = b"\x00"          # Section 5.4.3 step 4
_PROOF_TO_HASH_DS_FRONT = b"\x03"     # Section 5.2 step 4
_PROOF_TO_HASH_DS_BACK = b"\x00"      # Section 5.2 step 5


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


# --------------------------------------------------------------------------
# Key derivation — RFC 8032 Section 5.1.5, referenced by RFC 9381 Section 5.5
# --------------------------------------------------------------------------
def _secret_scalar_and_public_key(sk_seed: bytes):
    """Return (x, Y, PK_string) for a 32-octet Ed25519 secret key."""
    if len(sk_seed) != 32:
        raise ValueError("secret key must be 32 octets")
    h = _sha512(sk_seed)
    buf = bytearray(h[:32])
    buf[0] &= 0xF8          # clear lowest three bits of the first octet
    buf[31] &= 0x7F         # clear highest bit of the last octet
    buf[31] |= 0x40         # set second-highest bit of the last octet
    x = string_to_int(bytes(buf))
    y_point = _mul(x, BASE)
    return x, y_point, point_to_string(y_point)


def public_key(sk_seed: bytes) -> bytes:
    """PK_string for a 32-octet Ed25519 secret key (equals the Ed25519 pubkey)."""
    return _secret_scalar_and_public_key(sk_seed)[2]


# --------------------------------------------------------------------------
# Auxiliary functions — RFC 9381 Section 5.4
# --------------------------------------------------------------------------
def _encode_to_curve_tai(encode_to_curve_salt: bytes, alpha_string: bytes):
    """ECVRF_encode_to_curve_try_and_increment — RFC 9381 Section 5.4.1.1.

    interpret_hash_value_as_a_point(s) = string_to_point(s[0]...s[31])
    (RFC 9381 Section 5.5, EDWARDS25519-SHA512-TAI).
    """
    for ctr in range(256):                                        # step 1, 5.e
        hash_string = _sha512(
            SUITE_STRING,
            _ENCODE_TO_CURVE_DS_FRONT,
            encode_to_curve_salt,
            alpha_string,
            int_to_string(ctr, 1),                                # step 5.a
            _ENCODE_TO_CURVE_DS_BACK,
        )                                                         # step 5.b
        try:
            h_point = string_to_point(hash_string[:32])           # step 5.c
        except InvalidProof:
            continue
        h_point = _mul(COFACTOR, h_point)                         # step 5.d
        if not _is_identity(h_point):                             # step 5 loop
            return h_point
    raise InvalidProof("encode_to_curve failed for all 256 counters")


def _nonce_generation(sk_seed: bytes, h_string: bytes) -> int:
    """ECVRF_nonce_generation_RFC8032 — RFC 9381 Section 5.4.2.2."""
    hashed_sk_string = _sha512(sk_seed)                           # step 1
    truncated = hashed_sk_string[32:64]                           # step 2
    k_string = _sha512(truncated, h_string)                       # step 3
    return string_to_int(k_string) % Q                            # step 4


def _challenge_generation(p1, p2, p3, p4, p5) -> int:
    """ECVRF_challenge_generation — RFC 9381 Section 5.4.3."""
    buf = [SUITE_STRING, _CHALLENGE_DS_FRONT]                     # steps 1-2
    for point in (p1, p2, p3, p4, p5):                            # step 3
        buf.append(point_to_string(point))
    buf.append(_CHALLENGE_DS_BACK)                                # steps 4-5
    c_string = _sha512(*buf)                                      # step 6
    return string_to_int(c_string[:CLEN])                         # steps 7-8


def _decode_proof(pi_string: bytes):
    """ECVRF_decode_proof — RFC 9381 Section 5.4.4."""
    if len(pi_string) != PI_LEN:
        raise InvalidProof(f"pi must be {PI_LEN} octets, got {len(pi_string)}")
    gamma = string_to_point(pi_string[:PTLEN])                    # steps 1, 4-5
    c = string_to_int(pi_string[PTLEN:PTLEN + CLEN])              # steps 2, 6
    s = string_to_int(pi_string[PTLEN + CLEN:])                   # steps 3, 7
    if s >= Q:                                                    # step 8
        raise InvalidProof("s out of range")
    return gamma, c, s


def _validate_key(y_point) -> None:
    """ECVRF_validate_key — RFC 9381 Section 5.4.5 (cofactor form)."""
    if _is_identity(_mul(COFACTOR, y_point)):
        raise InvalidProof("public key has small order")


# --------------------------------------------------------------------------
# Public algorithms — RFC 9381 Sections 5.1, 5.2, 5.3
# --------------------------------------------------------------------------
def prove(sk_seed: bytes, alpha: bytes) -> bytes:
    """ECVRF_prove — RFC 9381 Section 5.1. Returns the 80-octet pi_string.

    `sk_seed` is the 32-octet Ed25519 secret key (RFC 8032 Section 5.1.5);
    the same key that signs Ed25519 signatures. Deterministic: identical
    (sk_seed, alpha) always yields identical pi.
    """
    x, y_point, pk_string = _secret_scalar_and_public_key(sk_seed)  # step 1
    h_point = _encode_to_curve_tai(pk_string, alpha)                # step 2
    h_string = point_to_string(h_point)                             # step 3
    gamma = _mul(x, h_point)                                        # step 4
    k = _nonce_generation(sk_seed, h_string)                        # step 5
    c = _challenge_generation(y_point, h_point, gamma,
                              _mul(k, BASE), _mul(k, h_point))      # step 6
    s = (k + c * x) % Q                                             # step 7
    return (point_to_string(gamma)                                  # step 8
            + int_to_string(c, CLEN)
            + int_to_string(s, QLEN))


def proof_to_hash(pi: bytes) -> bytes:
    """ECVRF_proof_to_hash — RFC 9381 Section 5.2. Returns 64-octet beta.

    Per the RFC's own note, run this only on a pi known to come from
    `prove`, or from inside `verify`.
    """
    gamma, _c, _s = _decode_proof(pi)                               # steps 1-3
    return _sha512(SUITE_STRING,                                    # step 6
                   _PROOF_TO_HASH_DS_FRONT,
                   point_to_string(_mul(COFACTOR, gamma)),
                   _PROOF_TO_HASH_DS_BACK)


def verify(pk: bytes, alpha: bytes, pi: bytes, validate_key: bool = True) -> bool:
    """ECVRF_verify — RFC 9381 Section 5.3. True iff pi is valid for (pk, alpha).

    `validate_key` defaults to TRUE, which buys "full collision resistance"
    and "unpredictability under malicious key generation" (RFC 9381 Section 5
    and Section 7.1) — the relevant setting when the key owner may itself be
    adversarial, as an Auditor may be.
    """
    try:
        y_point = string_to_point(pk)                               # steps 1-2
        if validate_key:
            _validate_key(y_point)                                  # step 3
        gamma, c, s = _decode_proof(pi)                              # steps 4-6
        h_point = _encode_to_curve_tai(pk, alpha)                    # step 7
        u = _add(_mul(s, BASE), _negate(_mul(c, y_point)))           # step 8
        v = _add(_mul(s, h_point), _negate(_mul(c, gamma)))          # step 9
        c_prime = _challenge_generation(y_point, h_point, gamma, u, v)  # step 10
        return c == c_prime                                          # step 11
    except (InvalidProof, ValueError):
        return False


def verify_and_hash(pk: bytes, alpha: bytes, pi: bytes,
                    validate_key: bool = True):
    """("VALID", beta) form of RFC 9381 Section 5.3 — returns beta or None."""
    if not verify(pk, alpha, pi, validate_key):
        return None
    return proof_to_hash(pi)


# --------------------------------------------------------------------------
# RFC 9381 Appendix B.3 test vectors for ECVRF-EDWARDS25519-SHA512-TAI
# --------------------------------------------------------------------------
# Transcribed verbatim from RFC 9381 Appendix B.3 (Examples 16, 17, 18).
# All hex strings below are OCTET STRINGS as printed in the RFC (x, k and
# the point values are little-endian encodings, per Section 5.5).
RFC9381_B3_VECTORS = (
    {   # Example 16
        "sk": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "pk": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "alpha": "",
        "x": "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f",
        "ctr": 0,
        "h": "91bbed02a99461df1ad4c6564a5f5d829d0b90cfc7903e7a5797bd658abf3318",
        "k_string": ("7100f3d9eadb6dc4743b029736ff283f5be494128df128df2817106f345b8594"
                     "b6d6da2d6fb0b4c0257eb337675d96eab49cf39e66cc2c9547c2bf8b2a6afae4"),
        "k": "8a49edbd1492a8ee09766befe50a7d563051bf3406cbffc20a88def030730f0f",
        "u": "aef27c725be964c6a9bf4c45ca8e35df258c1878b838f37d9975523f09034071",
        "v": "5016572f71466c646c119443455d6cb9b952f07d060ec8286d678615d55f954f",
        "pi": ("8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f"
               "26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab126"
               "8a1b0db10836d9826a528ca76567805"),
        "beta": ("90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff"
                 "66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"),
    },
    {   # Example 17
        "sk": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "pk": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "alpha": "72",
        "x": "68bd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e51",
        "ctr": 1,
        "h": "5b659fc3d4e9263fd9a4ed1d022d75eaacc20df5e09f9ea937502396598dc551",
        "k_string": ("42589bbf0c485c3c91c1621bb4bfe04aed7be76ee48f9b00793b2342acb9c167"
                     "cab856f9f9d4febc311330c20b0a8afd3743d05433e8be8d32522ecdc16cc5ce"),
        "k": "d8c3a66921444cb3427d5d989f9b315aa8ca3375e9ec4d52207711a1fdb44107",
        "u": "1dcb0a4821a2c48bf53548228b7f170962988f6d12f5439f31987ef41f034ab3",
        "v": "fd03c0bf498c752161bae4719105a074630a2aa5f200ff7b3995f7bfb1513423",
        "pi": ("f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593"
               "3bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da"
               "3ef39226bbc355bdc9850112c8f4b02"),
        "beta": ("eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb"
                 "5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"),
    },
    {   # Example 18
        "sk": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "pk": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "alpha": "af82",
        "x": "909a8b755ed902849023a55b15c23d11ba4d7f4ec5c2f51b1325a181991ea95c",
        "ctr": 0,
        "h": "bf4339376f5542811de615e3313d2b36f6f53c0acfebb482159711201192576a",
        "k_string": ("38b868c335ccda94a088428cbf3ec8bc7955bfaffe1f3bd2aa2c59fc31a0febc"
                     "59d0e1af3715773ce11b3bbdd7aba8e3505d4b9de6f7e4a96e67e0d6bb6d6c3a"),
        "k": "5ffdbc72135d936014e8ab708585fda379405542b07e3bd2c0bd48437fbac60a",
        "u": "2bae73e15a64042fcebf062abe7e432b2eca6744f3e8265bc38e009cd577ecd5",
        "v": "88cba1cb0d4f9b649d9a86026b69de076724a93a65c349c988954f0961c5d506",
        "pi": ("9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf809"
               "6bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d"
               "41b00b05081ed0f58ee5e31b3a970e"),
        "beta": ("645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c45"
                 "2118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"),
    },
)


def self_test(verbose: bool = False) -> None:
    """Replay RFC 9381 Appendix B.3 end to end. Raises AssertionError on drift.

    Checks every published intermediate (secret scalar, try_and_increment
    counter, H, k_string, k, U = k*B, V = k*H) as well as pi and beta, so a
    coincidentally-correct output cannot hide a wrong construction. Also
    exercises the negative paths: tampered proof, wrong alpha, wrong key.
    """
    # Curve constants must match RFC 8032 Table 1 exactly.
    assert D == 37095705934669439343138083508754565189542113879843219016388785533085940283555, \
        "curve constant d drifted"
    assert Q == 7237005577332262213973186563042994240857116359379907606001950938285454250989, \
        "group order L drifted"
    assert (BY * BY - BX * BX - 1 - D * BX * BX % P * BY * BY) % P == 0, \
        "base point is not on the curve"
    assert _is_identity(_mul(Q, BASE)), "base point does not have order L"
    assert SUITE_STRING == b"\x03", "suite_string must be 0x03 (RFC 9381 Section 5.5)"

    for i, vec in enumerate(RFC9381_B3_VECTORS, start=16):
        sk = bytes.fromhex(vec["sk"])
        alpha = bytes.fromhex(vec["alpha"])
        x, y_point, pk_string = _secret_scalar_and_public_key(sk)

        assert pk_string.hex() == vec["pk"], f"Example {i}: PK mismatch"
        assert int_to_string(x, 32).hex() == vec["x"], f"Example {i}: secret scalar mismatch"

        # try_and_increment must succeed on the counter the RFC reports.
        for ctr in range(256):
            hash_string = _sha512(SUITE_STRING, _ENCODE_TO_CURVE_DS_FRONT,
                                  pk_string, alpha, int_to_string(ctr, 1),
                                  _ENCODE_TO_CURVE_DS_BACK)
            try:
                cand = _mul(COFACTOR, string_to_point(hash_string[:32]))
            except InvalidProof:
                continue
            if not _is_identity(cand):
                break
        assert ctr == vec["ctr"], f"Example {i}: try_and_increment ctr {ctr} != {vec['ctr']}"

        h_point = _encode_to_curve_tai(pk_string, alpha)
        assert point_to_string(h_point).hex() == vec["h"], f"Example {i}: H mismatch"

        k_string = _sha512(_sha512(sk)[32:64], point_to_string(h_point))
        assert k_string.hex() == vec["k_string"], f"Example {i}: k_string mismatch"
        k = _nonce_generation(sk, point_to_string(h_point))
        assert int_to_string(k, 32).hex() == vec["k"], f"Example {i}: k mismatch"

        assert point_to_string(_mul(k, BASE)).hex() == vec["u"], f"Example {i}: U mismatch"
        assert point_to_string(_mul(k, h_point)).hex() == vec["v"], f"Example {i}: V mismatch"

        pi = prove(sk, alpha)
        assert pi.hex() == vec["pi"], f"Example {i}: pi mismatch"
        assert len(pi) == PI_LEN, f"Example {i}: pi length"

        beta = proof_to_hash(pi)
        assert beta.hex() == vec["beta"], f"Example {i}: beta mismatch"
        assert len(beta) == HLEN, f"Example {i}: beta length"

        pk = bytes.fromhex(vec["pk"])
        assert verify(pk, alpha, pi), f"Example {i}: valid proof rejected"
        assert verify_and_hash(pk, alpha, pi) == beta, f"Example {i}: verify_and_hash mismatch"

        # Determinism: proving twice must yield the identical proof.
        assert prove(sk, alpha) == pi, f"Example {i}: prove is not deterministic"

        # Negative paths.
        for pos in (0, PTLEN, PI_LEN - 1):
            bad = bytearray(pi)
            bad[pos] ^= 0x01
            assert not verify(pk, alpha, bytes(bad)), \
                f"Example {i}: tampered proof accepted (octet {pos})"
        assert not verify(pk, alpha + b"\x00", pi), f"Example {i}: wrong alpha accepted"
        assert not verify(pk, alpha, pi[:-1]), f"Example {i}: short proof accepted"
        other_pk = bytes.fromhex(RFC9381_B3_VECTORS[(i - 16 + 1) % 3]["pk"])
        assert not verify(other_pk, alpha, pi), f"Example {i}: wrong key accepted"

        if verbose:
            print(f"Example {i}: OK (ctr={ctr}, pi={pi.hex()[:16]}..., "
                  f"beta={beta.hex()[:16]}...)")

    # Small-order public keys MUST be rejected when validate_key is TRUE
    # (RFC 9381 Section 5.4.5). The identity point is the y = 1 encoding.
    small_order = int_to_string(1, 32)
    assert not verify(small_order, b"", bytes(PI_LEN)), "small-order key accepted"


if __name__ == "__main__":
    self_test(verbose=True)
    print("RFC 9381 vectors OK")
