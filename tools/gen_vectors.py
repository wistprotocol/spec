#!/usr/bin/env python3
"""Generate deterministic WIST-1/WIST-3 test vectors and signed examples.

Never uses wall-clock or randomness: fixed seed, fixed timestamps.
Re-running always produces byte-identical output.
"""
import base64, calendar, hashlib, hmac, json, pathlib, time
from decimal import Decimal, localcontext

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ecvrf
import link_extraction
from merkle import audit_path, leaf_hash, node_hash

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIST1 = ROOT / "vectors" / "wist1"
EXAMPLES = ROOT / "examples"
WIST1.mkdir(parents=True, exist_ok=True)
EXAMPLES.mkdir(parents=True, exist_ok=True)

SEED = bytes(range(32))  # TEST ONLY — never use in production

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

priv = Ed25519PrivateKey.from_private_bytes(SEED)
pub_raw = priv.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def sign_envelope(inner_name: str, inner: dict, key_id: str) -> dict:
    canonical = rfc8785.dumps(inner)
    sig = priv.sign(canonical)
    return {inner_name: inner,
            "sig": {"key_id": key_id, "alg": "Ed25519", "value": b64u(sig)}}

def write_json(path: pathlib.Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n")

# -------------------------------------------------- WIST-1/WIST-3: payload + delta
# A Delta commits to its content and does not carry it (WIST-1 §3.6). The content
# travels as a Payload (WIST-3 §6.1) whose salt never reaches the Log.
#
# A production salt is drawn from a CSPRNG, fresh per Delta. This generator has
# no random source by construction — it must stay byte-reproducible — so the
# vector's salt is derived from a fixed domain-separated string and the Delta's
# URL. That is a property of the vector, never of a conforming Publisher.
DELTA_URL = "https://example.com/blog/post-1"
EXTRACT = "WIST is an open, verifiable, push-based web index protocol."

# The example Delta's own page, in raw HTML octets — link_extraction.py's
# "example-delta-page" vector fixture below runs its extraction procedure
# over this exact byte string, so the Payload's links member is derived from
# a page rather than asserted, and the vector, the example and the audit
# story below all agree by construction.
LINKS_CAP_BYTES = 4096
FIXTURE_HTML = b"""<!doctype html><html><body>
<p>Reference: <a href="https://example.org/reference">ref</a></p>
<a href="https://spec.example.net/wist-1">the spec</a>
<a href="/blog/post-2">internal relative</a>
<a href="https://www.example.com/about">internal subdomain</a>
<a href="http://insecure.example.io/x">non-https, dropped</a>
<a href="mailto:someone@example.org">not a URL scheme, dropped</a>
<a href="https://EXAMPLE.ORG/reference">duplicate after normalization</a>
<a href="https://example.org/%7euser">escape renormalized, distinct URL</a>
</body></html>"""
LINKS = link_extraction.links_member(
    *link_extraction.extract_links(FIXTURE_HTML, DELTA_URL, "example.com"),
    LINKS_CAP_BYTES)

CONTENT = {
    "extract": EXTRACT,
    "links": LINKS,
    "summary": {"title": "Post 1", "abstract": "An introduction to WIST."},
}
content_canonical = rfc8785.dumps(CONTENT)
salt = hashlib.sha256(b"wist-test-salt|" + DELTA_URL.encode()).digest()[:16]
assert len(salt) >= 16, "salt must be at least 128 bits (WIST-1 §3.6)"
commitment = "hmac-sha256:" + hmac.new(salt, content_canonical, hashlib.sha256).hexdigest()

payload = {"wist_version": "1.0.0", "salt": b64u(salt), "content": CONTENT}

delta = {
    "wist_version": "1.0.0",
    "url": DELTA_URL,
    "change_type": "new",
    "observed_at": "2026-08-02T12:00:00Z",
    "payload": {"commitment": commitment, "alg": "HMAC-SHA256",
                "bytes": len(content_canonical)},
    "meta": {"lang": "en", "topics": ["software"], "license": "CC-BY-4.0"},
}

delta_canonical = rfc8785.dumps(delta)
delta_id = "sha256:" + sha256_hex(delta_canonical)
delta_envelope = sign_envelope("delta", delta, "test-k1")

write_json(WIST1 / "keypair.json",
           {"seed_hex": SEED.hex(), "public_key": b64u(pub_raw),
            "warning": "test vector key — NEVER use in production"})
(WIST1 / "delta.canonical").write_bytes(delta_canonical)
write_json(WIST1 / "envelope.json", delta_envelope)
(WIST1 / "id.txt").write_text(delta_id + "\n")
write_json(EXAMPLES / "delta.json", delta_envelope)
write_json(EXAMPLES / "payload.json", payload)
print("wist1 delta id:", delta_id)
print("wist1 payload salt:", payload["salt"], "commitment:", commitment,
      "bytes:", len(content_canonical))
print("wist1 payload path: /payloads/%s.json" % delta_id.split(":")[1])

# The suite's second test keypair: the recovery key of the publisher example
# below, and the fresh identity of the §5.2 sequencing vector. WIST-1 §5.2
# forbids one key from serving as both a signing and a recovery key.
SEED2 = bytes(range(32, 64))    # TEST ONLY — never use in production
SEED3 = bytes(range(64, 96))    # TEST ONLY — never use in production
SEED4 = bytes(range(96, 128))   # TEST ONLY — never use in production
priv2 = Ed25519PrivateKey.from_private_bytes(SEED2)
priv3 = Ed25519PrivateKey.from_private_bytes(SEED3)
priv4 = Ed25519PrivateKey.from_private_bytes(SEED4)

def raw_public(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

pub2_raw, pub3_raw, pub4_raw = raw_public(priv2), raw_public(priv3), raw_public(priv4)

def sign_envelope_with(key, inner_name: str, inner: dict, key_id: str) -> dict:
    return {inner_name: inner,
            "sig": {"key_id": key_id, "alg": "Ed25519",
                    "value": b64u(key.sign(rfc8785.dumps(inner)))}}

# ------------------------------------------------------------ WIST-1: publisher
publisher = {
    "wist_version": "1.0.0",
    "seq": 0,
    "domain": "example.com",
    "subdomain_scope": ["www.example.com", "blog.example.com"],
    "keys": [
        {"key_id": "test-k1", "alg": "Ed25519", "public_key": b64u(pub_raw),
         "valid_from": "2026-08-02T12:00:00Z"}
    ],
    # A distinct keypair, as WIST-1 §5.2 requires: the two sets share neither
    # a key_id nor a public_key, because a recovery key that is also a signing
    # key is not held offline and is stolen with the key it duplicates.
    "recovery_keys": [
        {"key_id": "test-r1", "alg": "Ed25519", "public_key": b64u(pub2_raw),
         "valid_from": "2026-08-02T12:00:00Z"}
    ],
    "contact": "mailto:webmaster@example.com",
}
write_json(EXAMPLES / "publisher.json", sign_envelope("publisher", publisher, "test-k1"))
print("wist1 publisher example written")

# ------------------------------------------- WIST-1 §5.2: Declaration sequencing
# One stored Declaration, a fetched one per case, and the outcome §5.2 fixes.
# The vector exists because the sequencing rules are the point at which an
# implementation decides whether a Publisher whose keys never change can be
# re-polled at all: §5.1 caps a cached Key Set at 24 hours, so the re-serve of
# an unchanged Declaration is the most common event in the whole mechanism.
#
# A second test keypair is needed for the rotation targets and for the fresh
# identity — a Declaration signed by neither the stored signing keys nor the
# stored recovery keys. Test-only, like the first.
def decl_hash(inner: dict) -> str:
    """WIST-1 §5.2: prev_declaration = sha256 over JCS of the inner object."""
    return "sha256:" + sha256_hex(rfc8785.dumps(inner))

K2 = {"key_id": "test-k2", "alg": "Ed25519", "public_key": b64u(pub3_raw),
      "valid_from": "2026-08-03T12:00:00Z"}
R2 = {"key_id": "test-r2", "alg": "Ed25519", "public_key": b64u(pub4_raw),
      "valid_from": "2026-08-03T12:00:00Z"}

stored_decl = publisher
stored_hash = decl_hash(stored_decl)

def variant(**over):
    out = json.loads(json.dumps(stored_decl))
    out.update(over)
    return out

mutated_same_seq = variant(contact="mailto:security@example.com")
rotated = variant(seq=1, prev_declaration=stored_hash, keys=[K2])
recovery_rotated = variant(seq=1, prev_declaration=stored_hash, keys=[K2],
                           recovery_keys=[R2])
recovery_dropped_by_signing_key = variant(seq=1, prev_declaration=stored_hash,
                                          recovery_keys=[R2])
missing_prev = variant(seq=1, keys=[K2])
wrong_prev = variant(seq=1, prev_declaration=decl_hash(mutated_same_seq), keys=[K2])
fresh_identity = variant(seq=1, prev_declaration=stored_hash, keys=[K2])
overlapping_sets = variant(
    seq=1, prev_declaration=stored_hash,
    recovery_keys=[{"key_id": "test-r1", "alg": "Ed25519",
                    "public_key": b64u(pub_raw),
                    "valid_from": "2026-08-02T12:00:00Z"}])

declaration_cases = [
    {"name": "identical re-serve",
     "stored": sign_envelope("publisher", stored_decl, "test-k1"),
     "fetched": sign_envelope("publisher", stored_decl, "test-k1"),
     "expected": "idempotent",
     "why": "§5.2: the fetched publisher object is byte-identical to the "
            "accepted one, so the re-poll §5.1's 24-hour cache TTL obliges is "
            "an idempotent acceptance, not WIST1-E08."},
    {"name": "same seq, different bytes",
     "stored": sign_envelope("publisher", stored_decl, "test-k1"),
     "fetched": sign_envelope("publisher", mutated_same_seq, "test-k1"),
     "expected": "WIST1-E08",
     "why": "§5.2: seq is not greater than the highest accepted and the object "
            "differs — the superseded-replay case the rule catches."},
    {"name": "stale lower seq",
     "stored": sign_envelope("publisher", rotated, "test-k1"),
     "fetched": sign_envelope("publisher", stored_decl, "test-k1"),
     "expected": "WIST1-E08",
     "why": "§5.2: seq 0 below the accepted seq 1."},
    {"name": "missing prev_declaration",
     "stored": sign_envelope("publisher", stored_decl, "test-k1"),
     "fetched": sign_envelope("publisher", missing_prev, "test-k1"),
     "expected": "WIST1-E08",
     "why": "§5.2: seq > 0 with prev_declaration absent."},
    {"name": "mismatched prev_declaration",
     "stored": sign_envelope("publisher", stored_decl, "test-k1"),
     "fetched": sign_envelope("publisher", wrong_prev, "test-k1"),
     "expected": "WIST1-E08",
     "why": "§5.2: prev_declaration does not equal the hash of the previously "
            "accepted Declaration's publisher object."},
    {"name": "ordinary rotation",
     "stored": sign_envelope("publisher", stored_decl, "test-k1"),
     "fetched": sign_envelope("publisher", rotated, "test-k1"),
     "expected": "ordinary_rotation",
     "why": "§5.2: higher seq, correct prev_declaration, signed by a key of "
            "the previous Key Set; recovery_keys carried byte-identical."},
    {"name": "recovery rotation",
     "stored": sign_envelope("publisher", stored_decl, "test-k1"),
     "fetched": sign_envelope_with(priv2, "publisher", recovery_rotated, "test-r1"),
     "expected": "recovery_rotation",
     "why": "§5.2: signed by a key in the previous Declaration's "
            "recovery_keys, which is what lets it replace them."},
    {"name": "recovery keys altered by a signing key",
     "stored": sign_envelope("publisher", stored_decl, "test-k1"),
     "fetched": sign_envelope("publisher", recovery_dropped_by_signing_key, "test-k1"),
     "expected": "WIST1-E08",
     "why": "§5.2: recovery keys protect themselves — a Declaration altering "
            "them MUST be signed by one of the recovery keys it replaces."},
    {"name": "fresh identity",
     "stored": sign_envelope("publisher", stored_decl, "test-k1"),
     "fetched": sign_envelope_with(priv3, "publisher", fresh_identity, "test-k2"),
     "expected": "fresh_identity",
     "why": "§5.2: signed by neither the previous signing keys nor the "
            "previous recovery_keys, which it carries byte-identical — "
            "accepted, with A and C reset to zero (WIST-4 §6)."},
    {"name": "fresh identity inside an open recovery window",
     "stored": sign_envelope("publisher", stored_decl, "test-k1"),
     "fetched": sign_envelope_with(priv3, "publisher", fresh_identity, "test-k2"),
     "recovery_window_open": True,
     "expected": "fresh_identity",
     "why": "§5.2: an open window changes nothing about acceptance — the "
            "Declaration is sealed and superseded at the window's end, "
            "because rejecting it at ingest would leave a thief's attempt "
            "invisible to a party replaying the Log."},
    {"name": "key named in both key sets",
     "stored": sign_envelope("publisher", stored_decl, "test-k1"),
     "fetched": sign_envelope("publisher", overlapping_sets, "test-k1"),
     "expected": "WIST1-E08",
     "why": "§5.2: the same public_key in keys and recovery_keys. A recovery "
            "key that is also a signing key is stolen with it, and a signer "
            "in both sets leaves the recovery-window classification without "
            "an answer every replaying party derives identically."},
]

write_json(WIST1 / "declaration-sequence.json", {
    "note": ("WIST-1 §5.2 Declaration sequencing and classification. Each case "
             "evaluates `fetched` against the already-accepted `stored` for the "
             "same domain; a case's own `recovery_window_open` overrides the "
             "file-level default. `expected` is one of "
             "`idempotent` (accepted, replaces nothing), `ordinary_rotation`, "
             "`recovery_rotation`, `fresh_identity` (accepted, A and C reset), "
             "or the error code the evaluation rejects with."),
    "recovery_window_open": False,
    "cases": declaration_cases,
})
print("wist1 declaration-sequence vector written")

# ------------------------------ WIST-1 §5.2: recovery-window settlement
# The window's two derivations, over key_ids alone: which served Deltas are
# admitted to the queue (the union of the pre-recovery Key Set and the
# recovery Declaration's own), and what the window's end does with them
# (revalidation against the recovery chain's newest Declaration). Every
# Declaration sealed inside the window that does not legitimately follow the
# recovery Declaration is superseded, whatever its classification.
def settle_case(name, recovery, window, served, why):
    chain = [recovery]
    superseded = []
    for decl in window:
        head = chain[-1]
        if decl["signer"] in head["keys"] + head.get("recovery_keys", []):
            chain.append(decl)
        else:
            superseded.append(decl["label"])
    effective = chain[-1]["keys"]
    admitted = [d for d in served
                if d["signer"] in PRE_RECOVERY_KEYS + recovery["keys"]]
    return {
        "name": name,
        "pre_recovery_keys": PRE_RECOVERY_KEYS,
        "recovery_declaration": recovery,
        "window_declarations": window,
        "served": served,
        "expected": {
            "queued": [d["delta_id"] for d in admitted],
            "not_queued": [d["delta_id"] for d in served if d not in admitted],
            "effective_keys": effective,
            "superseded": superseded,
            "sealed": [d["delta_id"] for d in admitted if d["signer"] in effective],
            "rejected": [d["delta_id"] for d in admitted
                         if d["signer"] not in effective],
        },
        "why": why,
    }

PRE_RECOVERY_KEYS = ["k1"]
RECOVERY_DECL = {"label": "recovery", "signer": "r1", "keys": ["k2"],
                 "recovery_keys": ["r2"]}

settlement_cases = [
    settle_case(
        "no competing declaration", RECOVERY_DECL, [],
        [{"delta_id": "d-old", "signer": "k1"},
         {"delta_id": "d-new", "signer": "k2"},
         {"delta_id": "d-alien", "signer": "kX"}],
        "§5.2: the union admits the compromised key's Delta and the "
        "recovered Publisher's alike, and the settlement keeps only what "
        "verifies under the recovery Declaration's own keys. A Delta signed "
        "by a key in neither set never reaches the queue (WIST1-E02)."),
    settle_case(
        "thief rotates inside the window", RECOVERY_DECL,
        [{"label": "thief rotation", "signer": "k1", "keys": ["kT"],
          "recovery_keys": ["r1"]}],
        [{"delta_id": "d-thief", "signer": "k1"},
         {"delta_id": "d-owner", "signer": "k2"}],
        "§5.2: an ordinary rotation signed by the compromised key does not "
        "follow the recovery Declaration, so it is superseded and its "
        "Deltas are WIST1-E13."),
    settle_case(
        "fresh identity inside the window", RECOVERY_DECL,
        [{"label": "fresh identity", "signer": "kF", "keys": ["kF"],
          "recovery_keys": ["r2"]}],
        [{"delta_id": "d-owner", "signer": "k2"}],
        "§5.2: a fresh identity is accepted when served and superseded at "
        "the window's end like any other non-following Declaration — "
        "otherwise a thief answers a recovery by starting over under the "
        "same domain."),
    settle_case(
        "recovered Publisher rotates again", RECOVERY_DECL,
        [{"label": "post-recovery rotation", "signer": "k2", "keys": ["k3"],
          "recovery_keys": ["r2"]}],
        [{"delta_id": "d-k2", "signer": "k2"},
         {"delta_id": "d-old", "signer": "k1"}],
        "§5.2: signed by a key of the recovery Declaration's own Key Set, so "
        "it legitimately follows and its Key Set is the one settlement "
        "revalidates against — d-k2 no longer verifies under it."),
    settle_case(
        "recovery key rotates again", RECOVERY_DECL,
        [{"label": "second recovery rotation", "signer": "r2",
          "keys": ["k4"], "recovery_keys": ["r3"]},
         {"label": "thief rotation after it", "signer": "k1",
          "keys": ["kT"], "recovery_keys": ["r1"]}],
        [{"delta_id": "d-k4", "signer": "k2"}],
        "§5.2: the chain may extend through a recovery key too, and a "
        "rotation signed by the compromised key is superseded wherever in "
        "the window it lands."),
]

write_json(WIST1 / "recovery-settlement.json", {
    "note": ("WIST-1 §5.2 recovery-window admission and settlement, over "
             "key_ids alone — no signatures, because both derivations read "
             "key membership and Log order and nothing else. `served` is in "
             "acceptance order; `expected.queued` are the Deltas the union "
             "rule admits, `expected.sealed` those the settlement keeps in "
             "that order, and `expected.rejected` those it drops with "
             "WIST1-E13 (the queued copy only — the Delta ID is not barred)."),
    "cases": settlement_cases,
})
print("wist1 recovery-settlement vector written")

# --------------------------------------- WIST-1 §4: the verification profile
# RFC 8032 §5.1.7 leaves the cofactor, the reduction of `s` and the treatment
# of small-order and non-canonically-encoded points to the verifier. §4 pins
# all of them, and these cases are the ones that separate the pinned profile
# from the permissive readings: each rejected case verifies under at least one
# conforming-with-RFC-8032 implementation that skipped one of §4's checks.
def ed25519_sign(seed: bytes, msg: bytes, published_a: bytes | None = None):
    h = ecvrf._sha512(seed)
    buf = bytearray(h[:32])
    buf[0] &= 0xF8
    buf[31] &= 0x7F
    buf[31] |= 0x40
    a = ecvrf.string_to_int(bytes(buf))
    prefix = h[32:]
    a_bytes = published_a or ecvrf.point_to_string(ecvrf._mul(a, ecvrf.BASE))
    r = ecvrf.string_to_int(ecvrf._sha512(prefix, msg)) % ecvrf.Q
    r_bytes = ecvrf.point_to_string(ecvrf._mul(r, ecvrf.BASE))
    k = ecvrf.string_to_int(ecvrf._sha512(r_bytes, a_bytes, msg)) % ecvrf.Q
    s = (r + k * a) % ecvrf.Q
    return a_bytes, r_bytes + ecvrf.int_to_string(s, 32)

def ed25519_check(a_bytes: bytes, msg: bytes, sig: bytes, cofactored: bool) -> bool:
    """The RFC 8032 §5.1.7 equation, with and without the cofactor."""
    r_bytes, s_bytes = sig[:32], sig[32:]
    s = ecvrf.string_to_int(s_bytes)
    if s >= ecvrf.Q and not cofactored:
        return False
    try:
        a_pt = ecvrf.string_to_point(a_bytes)
        r_pt = ecvrf.string_to_point(r_bytes)
    except ecvrf.InvalidProof:
        return False
    k = ecvrf.string_to_int(ecvrf._sha512(r_bytes, a_bytes, msg)) % ecvrf.Q
    lhs = ecvrf._mul(s % ecvrf.Q if cofactored else s, ecvrf.BASE)
    rhs = ecvrf._add(r_pt, ecvrf._mul(k, a_pt))
    if cofactored:
        lhs, rhs = ecvrf._mul(8, lhs), ecvrf._mul(8, rhs)
    return ecvrf._equal(lhs, rhs)

def order_eight_point():
    """A point of order exactly 8: [L]P for a P outside the prime-order group."""
    for y in range(2, 500):
        try:
            pt = ecvrf.string_to_point(ecvrf.int_to_string(y, 32))
        except ecvrf.InvalidProof:
            continue
        t = ecvrf._mul(ecvrf.Q, pt)
        if ecvrf._is_identity(t) or ecvrf._is_identity(ecvrf._mul(4, t)):
            continue
        if ecvrf._is_identity(ecvrf._mul(8, t)):
            return t
    raise AssertionError("no order-8 point found")

ED_MSG = b"WIST-1 verification profile vector"
T8 = order_eight_point()
T8_BYTES = ecvrf.point_to_string(T8)
NONCANONICAL_ONE = ecvrf.int_to_string(ecvrf.P + 1, 32)   # decodes to y = 1
BASE_A, BASE_SIG = ed25519_sign(SEED, ED_MSG)

# A published key carrying a torsion component: the signature below satisfies
# the cofactored equation and fails the cofactorless one, which is the single
# case that separates the two readings on otherwise well-formed inputs.
TORSION_A = ecvrf.point_to_string(
    ecvrf._add(ecvrf.string_to_point(BASE_A), T8))
_, TORSION_SIG = ed25519_sign(SEED, ED_MSG, published_a=TORSION_A)

unreduced_sig = BASE_SIG[:32] + ecvrf.int_to_string(
    ecvrf.string_to_int(BASE_SIG[32:]) + ecvrf.Q, 32)

ed_cases = [
    {"name": "valid signature", "public_key": BASE_A, "signature": BASE_SIG,
     "expected": "accept",
     "why": "§4: canonical A and R, s < L, neither point of small order."},
    {"name": "s not reduced", "public_key": BASE_A, "signature": unreduced_sig,
     "expected": "reject",
     "why": "§4: s + L leaves [s]B unchanged, so a verifier omitting the "
            "canonical-s check accepts a second signature for a message the "
            "same key already signed."},
    {"name": "public key non-canonically encoded", "public_key": NONCANONICAL_ONE,
     "signature": BASE_SIG, "expected": "reject",
     "why": "§4: the encoded y is p + 1, which is not less than p; a decoder "
            "that reduces mod p silently reads it as the identity."},
    {"name": "public key of small order", "public_key": T8_BYTES,
     "signature": BASE_SIG, "expected": "reject",
     "why": "§4: an order-8 A is a key under which one signature verifies for "
            "many keys, which a domain-anchored identity cannot admit."},
    {"name": "R non-canonically encoded", "public_key": BASE_A,
     "signature": NONCANONICAL_ONE + BASE_SIG[32:], "expected": "reject",
     "why": "§4: same encoding rule applied to R."},
    {"name": "R of small order", "public_key": BASE_A,
     "signature": T8_BYTES + BASE_SIG[32:], "expected": "reject",
     "why": "§4: an order-8 R is killed by the cofactor, so a cofactored "
            "verifier cannot see what it changes."},
    {"name": "torsion in the public key", "public_key": TORSION_A,
     "signature": TORSION_SIG, "expected": "reject",
     "cofactored_would_accept": True,
     "why": "§4: [8][s]B = [8](R + kA) holds while [s]B = R + kA does not — "
            "the case that separates cofactored verification from the "
            "cofactorless equation §4 pins."},
]

assert ed25519_check(BASE_A, ED_MSG, BASE_SIG, cofactored=False)
assert not ed25519_check(TORSION_A, ED_MSG, TORSION_SIG, cofactored=False)
assert ed25519_check(TORSION_A, ED_MSG, TORSION_SIG, cofactored=True)
assert ed25519_check(BASE_A, ED_MSG, unreduced_sig, cofactored=True)

write_json(WIST1 / "ed25519-strictness.json", {
    "note": ("WIST-1 §4's verification profile: cofactorless equation, s "
             "canonically reduced, A and R canonically encoded and not of "
             "small order. `message_hex` is the signed octet string — these "
             "cases exercise the profile itself, not Canonical Bytes. Every "
             "`reject` case is one some RFC 8032 verifier accepts."),
    "message_hex": ED_MSG.hex(),
    "cases": [{"name": c["name"],
               "public_key_hex": c["public_key"].hex(),
               "signature_hex": c["signature"].hex(),
               "expected": c["expected"],
               **({"cofactored_would_accept": True}
                  if c.get("cofactored_would_accept") else {}),
               "why": c["why"]} for c in ed_cases],
})
print("wist1 ed25519-strictness vector written")

# ------------------------------------------- WIST-1 §2: Canonical Host cases
# The flags §2 pins are only observable where they disagree with the strict
# defaults, so every case below is either a discriminator for one flag or a
# rejection the definition owes an implementer. Expected A-labels are the
# Punycode of the label after UTS #46's mapping step, computed here rather
# than pasted; the mapping itself is quoted per case in `why`.
def alabel(mapped: str) -> str:
    return "xn--" + mapped.encode("punycode").decode("ascii")

host_cases = [
    {"name": "ASCII case and trailing dot", "input": "EXAMPLE.org.",
     "expected": "example.org",
     "why": "§2: UTS #46 mapping folds case; the trailing dot is removed."},
    {"name": "hyphens in the third and fourth position",
     "input": "r2---sn-x.example", "expected": "r2---sn-x.example",
     "why": "§2: CheckHyphens=false. Under CheckHyphens=true this host — the "
            "shape CDN nodes actually use — has no canonicalization at all."},
    {"name": "leading hyphen", "input": "-foo.example",
     "expected": "-foo.example",
     "why": "§2: CheckHyphens=false places no positional restriction."},
    {"name": "IDN label", "input": "bücher.example",
     "expected": alabel("bücher") + ".example",
     "why": "§2: mapping leaves ü, Punycode encodes it."},
    {"name": "nontransitional sharp s", "input": "faß.de",
     "expected": alabel("faß") + ".de",
     "why": "§2: Transitional_Processing=false keeps ß rather than mapping it "
            "to ss."},
    {"name": "uppercase sigma", "input": "example.ΑΣ",
     "expected": "example." + alabel("ασ"),
     "why": "§2: UTS #46 maps Σ to σ context-free. An implementation that "
            "lowercases first with a context-sensitive full lowercase gets ς "
            "and therefore " + alabel("ας") + " — a different Canonical Host "
            "for the same input, which is why §2 forbids the extra step."},
    {"name": "A-label passthrough", "input": "xn--bcher-kva.example",
     "expected": "xn--bcher-kva.example",
     "why": "§2: an already-encoded A-label canonicalizes to itself."},
    {"name": "IPv4 literal", "input": "127.0.0.1", "expected": "127.0.0.1",
     "why": "§2: digits and dots pass UseSTD3ASCIIRules."},
    {"name": "STD3 violation", "input": "under_score.example", "expected": None,
     "why": "§2: UseSTD3ASCIIRules=true rejects ASCII outside letters, digits "
            "and hyphen."},
    {"name": "label too long", "input": "a" * 64 + ".example", "expected": None,
     "why": "§2: VerifyDnsLength=true bounds a label at 63 octets."},
    {"name": "empty host", "input": "", "expected": None,
     "why": "§2: VerifyDnsLength=true rejects an empty domain."},
    {"name": "zero-width non-joiner out of context", "input": "a‌b.example",
     "expected": None,
     "why": "§2: CheckJoiners=true — U+200C is admissible only after a virama "
            "or in a joining context, and 'a' is neither."},
    {"name": "bidi violation", "input": "אa.example", "expected": None,
     "why": "§2: CheckBidi=true — an RTL label may not carry a strong LTR "
            "character."},
]

write_json(WIST1 / "host-canonicalization.json", {
    "note": ("WIST-1 §2 Canonical Host. `expected` is the Canonical Host, or "
             "null where the input has no canonicalization and a validator "
             "MUST reject the `url` carrying it with WIST1-E03."),
    "flags": {"UseSTD3ASCIIRules": True, "CheckHyphens": False,
              "CheckBidi": True, "CheckJoiners": True,
              "Transitional_Processing": False, "VerifyDnsLength": True},
    "cases": host_cases,
})
print("wist1 host-canonicalization vector written")

# ----------------------------------------------------------------- WIST-2: feed
feed = {
    "wist_version": "1.0.0",
    "domain": "example.com",
    "generated_at": "2026-08-02T12:00:00Z",
    "deltas": [delta_id],
    "next": None,
}
write_json(EXAMPLES / "feed.json", sign_envelope("feed", feed, "test-k1"))
print("wist2 feed example written")

# --------------------------------------------------------------- WIST-2: status
# Not a signed Envelope (WIST-2 §7.1) — a plain JSON debugging surface.
write_json(EXAMPLES / "status.json", {
    "wist_version": "1.0.0", "domain": "example.com",
    "last_pull_at": "2026-08-02T12:05:00Z", "quota_remaining": 1098,
    "state": "new",
    "rejections": [{"code": "WIST1-E07", "at": "2026-08-02T12:05:00Z",
                    "delta_id": "sha256:" + "0" * 64,
                    "detail": "prev chain violation"}],
})
print("wist2 status example written")

# ------------------------------------------------- WIST-2: link extraction
WIST2V = ROOT / "vectors" / "wist2"
WIST2V.mkdir(parents=True, exist_ok=True)

expected_urls = ["https://example.org/reference", "https://spec.example.net/wist-1",
                 "https://example.org/~user"]

# Fixture 2: truncation. Each link serializes to 54 JCS octets, so 100 of
# them (5400+ octets) overflow the 4096-octet budget while 74 do not,
# ensuring the declared prefix comes out strictly shorter than total.
OVERFLOW_LINK_COUNT = 100
overflow_html = b"".join(
    b'<a href="https://links.example.io/item-%03d?section=references">x</a>' % n
    for n in range(OVERFLOW_LINK_COUNT))

# Fixture 3: scan-hardening. Exercises WIST-2 §11 steps 1-4 (comment/raw-text
# skipping, quote-aware attribute parsing, `data-href` vs `href`, character
# reference decoding), not just the resolve/normalize/dedupe steps fixtures
# 1-2 already cover.
scan_html = b"""<!doctype html><html><body>
<!-- <a href="https://commented.example.io/x">hidden in comment</a> -->
<script>var link = "<a href=\\"https://scripted.example.io/x\\">";</script>
<a data-href="https://decoy.example.io/x">decoy, not href</a>
<a title="a>b" href="https://quoted.example.io/x">quoted value holds a bare &gt;</a>
<a href="https://query.example.io/x?y=1&amp;z=2">entity reference in the query</a>
<A HREF="https://upper.example.io/x">uppercase tag and attribute name</A>
<a href=https://unquoted.example.io/x>unquoted href value</a>
</body></html>"""
scan_expected_urls = ["https://quoted.example.io/x", "https://query.example.io/x?y=1&z=2",
                      "https://upper.example.io/x", "https://unquoted.example.io/x"]
scan_excluded_hosts = ("commented.example.io", "scripted.example.io", "decoy.example.io")

cases = []
for label, html, base, dom in (
        ("example-delta-page", FIXTURE_HTML, DELTA_URL, "example.com"),
        ("budget-truncation", overflow_html, DELTA_URL, "example.com"),
        ("scan-hardening", scan_html, DELTA_URL, "example.com")):
    urls, total = link_extraction.extract_links(html, base, dom)
    member = link_extraction.links_member(urls, total, LINKS_CAP_BYTES)
    cases.append({"label": label, "html_hex": html.hex(), "base_url": base,
                  "publisher_domain": dom, "expected": member})

assert cases[0]["expected"] == {"total": 3, "urls": expected_urls}, \
    "fixture extraction drifted"
assert cases[1]["expected"]["total"] == OVERFLOW_LINK_COUNT and \
    0 < len(cases[1]["expected"]["urls"]) < OVERFLOW_LINK_COUNT, \
    "truncation not exercised"
assert cases[2]["expected"] == {"total": 4, "urls": scan_expected_urls}, \
    "scan-hardening fixture drifted"
assert not any(host in u for u in cases[2]["expected"]["urls"]
              for host in scan_excluded_hosts), \
    "a comment-, script-, or data-href-only link leaked into the declared set"

write_json(WIST2V / "link-extraction.json",
           {"note": ("WIST-2's extraction procedure over raw HTML bytes. "
                     "html_hex decodes to the exact input; expected is the "
                     "links member a conforming Publisher declares for it "
                     "under links_cap_bytes."),
            "links_cap_bytes": LINKS_CAP_BYTES, "cases": cases})
print("wist2 link-extraction vector:", [c["label"] for c in cases])

# ------------------------------------- WIST-2 §12 / WIST-4 §5: text + similarity
# Extraction fixtures exercise the scan (comments, raw-text elements, tags
# as boundaries, quote-aware `>`, bare `<`, character references, whitespace
# collapse); similarity fixtures exercise the containment quotient, the
# short-reference grapheme branch, and the mass guard. Texts stay in the
# ASCII letters-and-spaces domain, where the test implementation's
# normalization coincides exactly with WIST-4 §5's (see similarity()'s note).
TEXT_FIXTURES = []
for label, html in (
    ("scan-hardening",
     b"<html><head><title>Title words</title>"
     b"<script>var x = \"<p>not text</p>\";</script>"
     b"<style>p { color: red }</style></head>"
     b"<body><!-- a comment --><p>alpha <b>beta</b>\n\n gamma</p>"
     b"<a href=\"/x\" title=\"y>z\">delta</a>"
     b"<textarea>not text either</textarea>"
     b"1 < 2 but &lt;tag&gt; is text &amp; so is &#65;</body></html>"),
    ("utf8-replacement",
     b"one \xff two"),
):
    TEXT_FIXTURES.append({"label": label, "html_hex": html.hex(),
                          "expected": link_extraction.extract_text(html)})

PAD = "pad " * 40                     # 40 words: exactly at the default guard
REF9 = "one two three four five six seven eight nine"
SIM_FIXTURES = []
for label, ref, obs in (
    # Whole-document containment: the committed text embedded in template
    # furniture scores full marks — the case the quotient exists for.
    ("containment-full", REF9, "home about " + REF9 + " contact " + PAD),
    # 9 words -> two 8-word shingles; the observed drops the last word, so
    # exactly one shingle survives: 500000, exercising the denominator |A|.
    ("containment-half", REF9,
     PAD + "one two three four five six seven eight ten"),
    # Below the guard: a bot-interstitial-sized page is not_auditable,
    # never similarity 0.
    ("mass-guard", REF9, "please enable javascript to view this site"),
    # Short reference (2 words): the grapheme branch, contained verbatim.
    ("short-reference-graphemes", "hello world", PAD + "hello world"),
):
    sim = link_extraction.similarity(ref, obs)
    SIM_FIXTURES.append({"label": label, "reference": ref, "observed": obs,
                         "similarity": sim,
                         "verdict_input": "not_auditable" if sim is None else sim})
assert [f["verdict_input"] for f in SIM_FIXTURES] == \
    [1_000_000, 500_000, "not_auditable", 1_000_000], "similarity fixtures drifted"

write_json(WIST2V / "text-extraction.json", {
    "note": ("WIST-2 §12's whole-document text extraction over raw HTML "
             "octets, and WIST-4 §5's reference-containment similarity over "
             "its output. html_hex decodes to the exact input; expected is "
             "the observed text a conforming Auditor produces. similarity "
             "cases carry min_observed_words = 40 (the Registry default); "
             "a null similarity is the mass guard ruling not_auditable."),
    "min_observed_words": 40,
    "extraction": TEXT_FIXTURES,
    "similarity": SIM_FIXTURES,
})
print("wist2 text-extraction vector:",
      [c["label"] for c in TEXT_FIXTURES + SIM_FIXTURES])

# ------------------------------------------------------------ WIST-3: log anchor
anchor = {
    "wist_version": "1.0.0",
    "log_id": "log.example.org",
    "genesis_key": {"key_id": "test-agg-k1", "alg": "Ed25519",
                    "public_key": b64u(pub_raw)},
    "created_at": "2026-08-02T00:00:00Z",
}
write_json(EXAMPLES / "log-anchor.json", sign_envelope("anchor", anchor, "test-agg-k1"))
print("wist3 log anchor example written")

# ---------------------------------------------------------------- WIST-3: block
WIST3 = ROOT / "vectors" / "wist3"
WIST3.mkdir(parents=True, exist_ok=True)

def attest_delta(n: int, prev_id: str) -> dict:
    inner = {
        "wist_version": "1.0.0",
        "url": f"https://example.com/blog/post-{n}",
        "change_type": "attest",
        "observed_at": "2026-08-02T12:00:00Z",
        "prev": prev_id,
        "meta": {"lang": "en"},
    }
    return sign_envelope("delta", inner, "test-k1")

# prev IDs for the attest deltas: synthetic prior deltas ("new" for each URL)
def synthetic_prior_id(n: int) -> str:
    inner = {
        "wist_version": "1.0.0",
        "url": f"https://example.com/blog/post-{n}",
        "change_type": "new",
        "observed_at": "2026-08-01T12:00:00Z",
        "meta": {"lang": "en"},
    }
    return "sha256:" + sha256_hex(rfc8785.dumps(inner))

entries = [{"type": "publisher_delta", "body": delta_envelope}]
for n in (2, 3, 4):
    entries.append({"type": "publisher_delta",
                    "body": attest_delta(n, synthetic_prior_id(n))})

# WIST-3 §3.3: Entry order is canonical — grouped by type (all four here are
# publisher_delta), ascending leaf-hash order within the group. None of the
# attest chains reference each other inside the Block, so leaf-hash order
# and chain order impose no conflicting demand on this vector.
entries.sort(key=lambda e: leaf_hash(rfc8785.dumps(e)))

leaves = [leaf_hash(rfc8785.dumps(e)) for e in entries]
n01 = node_hash(leaves[0], leaves[1])
n23 = node_hash(leaves[2], leaves[3])
merkle_root = "sha256:" + node_hash(n01, n23).hex()

header = {
    "wist_version": "1.0.0",
    "block_number": 0,
    "prev_block_hash": "sha256:genesis",
    "sealed_at": "2026-08-02T13:00:00Z",
    "merkle_root": merkle_root,
    "entry_count": 4,
}
block_inner = header                      # header only — WIST-3 §3.1
block_canonical = rfc8785.dumps(block_inner)
block_hash = "sha256:" + sha256_hex(block_canonical)
block_sig = priv.sign(block_canonical)
block = {"header": header, "entries": entries,
         "sig": {"key_id": "test-agg-k1", "alg": "Ed25519", "value": b64u(block_sig)}}

inclusion_proof = {"index": 0, "entry_count": len(entries),
                   "path": [h.hex() for h in audit_path(0, leaves)]}

write_json(WIST3 / "block.json", block)
write_json(WIST3 / "inclusion-proof.json", inclusion_proof)
write_json(EXAMPLES / "block.json", block)

# ------------------------------------------- WIST-3 §4: the empty Block
# A heartbeat Block carries no Entries, and §3.2 requires the Log to keep
# sealing on cadence when nothing arrives. The empty tree is this suite's
# one deviation from RFC 6962 — SHA-256(0x00) rather than SHA-256 of the
# empty string — and an implementation wiring in a CT library inherits the
# other constant silently, so the vector exists to catch exactly that.
empty_header = {
    "wist_version": "1.0.0",
    "block_number": 1,
    "prev_block_hash": block_hash,
    "sealed_at": "2026-08-02T14:00:00Z",
    "merkle_root": "sha256:" + hashlib.sha256(b"\x00").hexdigest(),
    "entry_count": 0,
}
empty_canonical = rfc8785.dumps(empty_header)
empty_block = {"header": empty_header, "entries": [],
               "sig": {"key_id": "test-agg-k1", "alg": "Ed25519",
                       "value": b64u(priv.sign(empty_canonical))}}
write_json(WIST3 / "empty-block.json", {
    "note": "WIST-3 §4: a Block with no Entries, hashed per §3.1. `rfc6962_empty_root` is RFC 6962's own empty-tree constant, for contrast.",
    "block": empty_block,
    "block_hash": "sha256:" + sha256_hex(empty_canonical),
    "rfc6962_empty_root": "sha256:" + hashlib.sha256(b"").hexdigest(),
})
print("wist3 empty block hash:", "sha256:" + sha256_hex(empty_canonical))

checkpoint = {
    "wist_version": "1.0.0",
    "block_number": 0,
    "block_hash": block_hash,
    "sealed_at": "2026-08-02T13:00:00Z",
}
write_json(EXAMPLES / "checkpoint.json", sign_envelope("checkpoint", checkpoint, "test-agg-k1"))

# ---------------------------------------- WIST-3 §7: snapshot content digest
# The record tuple carries Log-derived identifiers only — no page content — so
# the digest stays computable after a Payload is withdrawn, while `delta_id`
# still pins the salted commitment that binds the content itself.
#
# Two records, so that both `weight` values and the ordering rule are
# exercised. The second domain's Delta is not an Entry of the example Block:
# this vector demonstrates §7's record encoding, not a materialization of
# Block 0.
REDUCED_URL = "https://reduced.example.org/notice"
REDUCED_CONTENT = {
    "extract": "A second domain, materialized under a level-2 weight mark.",
    "links": {"total": 0, "urls": []},
    "summary": {"title": "Notice", "abstract": "A reduced-weight record."},
}
reduced_canonical = rfc8785.dumps(REDUCED_CONTENT)
reduced_salt = hashlib.sha256(
    b"wist-test-salt|" + REDUCED_URL.encode()).digest()[:16]
reduced_delta = {
    "wist_version": "1.0.0",
    "url": REDUCED_URL,
    "change_type": "new",
    "observed_at": "2026-08-02T11:30:00Z",
    "payload": {"commitment": "hmac-sha256:" + hmac.new(
                    reduced_salt, reduced_canonical, hashlib.sha256).hexdigest(),
                "alg": "HMAC-SHA256", "bytes": len(reduced_canonical)},
    "meta": {"lang": "en"},
}
reduced_delta_id = "sha256:" + sha256_hex(rfc8785.dumps(reduced_delta))

RECORD_FIELDS = ["url", "publisher", "delta_id", "observed_at", "weight"]

snapshot_records = [
    {"url": DELTA_URL, "publisher": "example.com", "delta_id": delta_id,
     "observed_at": delta["observed_at"], "weight": "full"},
    {"url": REDUCED_URL, "publisher": "reduced.example.org",
     "delta_id": reduced_delta_id,
     "observed_at": reduced_delta["observed_at"], "weight": "reduced"},
]
assert all(sorted(r) == sorted(RECORD_FIELDS) for r in snapshot_records), \
    "a record carries a field §7's tuple does not name"


def content_digest(records) -> str:
    """WIST-3 §7: SHA-256 over the ascending-octet-order concatenation of JCS."""
    return "sha256:" + sha256_hex(b"".join(sorted(rfc8785.dumps(r) for r in records)))


snapshot_digest = content_digest(snapshot_records)
assert content_digest(list(reversed(snapshot_records))) == snapshot_digest, \
    "the digest depends on input order"

# tier1/links.parquet materialization (WIST-3 §7): one row per declared link of
# every live record, (source_url, target_url, position). source_url is the
# record's Normalized URL; target_url and position come from that record's
# Payload content.links.urls, in declared order. This is a function of
# Payload content, not of the Log, so — unlike the record tuple above — a
# link row leaves distribution together with its Payload on a withdrawal
# (WIST-3 §6.2) rather than surviving in content_digest. The reduced.example.org
# record contributes no rows: its Payload declares no links.
snapshot_links = [
    {"source_url": DELTA_URL, "target_url": u, "position": i}
    for i, u in enumerate(CONTENT["links"]["urls"])
]

write_json(WIST3 / "snapshot-records.json", {
    "note": ("The live record set WIST-3 §7's content_digest is computed over. "
             "Each record carries Log-derived identifiers only: no page "
             "content reaches the digest, so it remains computable after a "
             "Payload is withdrawn (WIST-3 §6.2), while delta_id still names "
             "the Delta whose salted commitment binds the content. The "
             "reduced.example.org Delta is not an Entry of the example "
             "Block; this vector publishes the record encoding, not a "
             "materialization of Block 0. `links` is the tier1/links.parquet "
             "materialization: one (source_url, target_url, position) row "
             "per declared link of every live record, source_url the "
             "record's Normalized URL and target_url/position drawn in "
             "order from that record's Payload content.links.urls. Unlike "
             "the record tuple above, a link row derives from Payload "
             "content, not from the Log, and therefore leaves distribution "
             "with the Payload on a withdrawal (WIST-3 §6.2) rather than "
             "surviving in content_digest; the reduced.example.org record "
             "contributes no rows because its Payload declares no links."),
    "snapshot_date": "2026-08-02",
    "log_position": 0,
    "record_fields": RECORD_FIELDS,
    "records": snapshot_records,
    "content_digest": snapshot_digest,
    "links": snapshot_links,
})

# ------------------------------------------- WIST-3 §7: the state artifact
# The protocol state at log_position, one tuple per live item, kinds and
# fields per WIST-3 §7's table. Aligned with snapshot-records above: the same
# two records (chain tips = their only Deltas), their two domains'
# reputation inputs, and the genesis Aggregator key. No `parameter` tuples:
# nothing is amended at height 0, and Registry defaults are not restated.
def counted_url_digest(domain: str, url: str) -> str:
    """WIST-3 §7: first 16 octets of SHA-256(JCS(domain) ‖ JCS(url)), hex.

    Membership is all `C` needs, so the set carries digests rather than the
    URLs themselves — the difference between a state artifact that stays
    under 16 KiB per domain and one that outgrows the tier it ships beside.
    """
    return sha256_hex(rfc8785.dumps(domain) + rfc8785.dumps(url))[:32]


state_entries = [
    ["aggregator_key", "test-agg-k1", b64u(pub_raw), 0, None],
    ["record", "example.com", DELTA_URL, delta_id],
    ["record", "reduced.example.org", REDUCED_URL, reduced_delta_id],
    # C = 1 for example.com: the audit-record example seals a `consistent`
    # verdict for the vector Delta's URL, so the counted-URL digest set has
    # exactly one member and exercises the encoding rather than asserting an
    # empty list. reduced.example.org has no audit and stays at zero.
    ["reputation_inputs", "example.com", "2026-08-02T13:00:00Z", None, 1,
     [counted_url_digest("example.com", DELTA_URL)], []],
    ["reputation_inputs", "reduced.example.org", "2026-08-02T13:00:00Z", None, 0, [], []],
]


def state_digest_of(entries) -> str:
    """WIST-3 §7: the content_digest construction verbatim, over state tuples."""
    return "sha256:" + sha256_hex(b"".join(sorted(rfc8785.dumps(e) for e in entries)))


state_inner = {"wist_version": "1.0.0", "log_position": 0, "entries": state_entries}
state_envelope = sign_envelope("state", state_inner, "test-agg-k1")
write_json(EXAMPLES / "snapshot-state.json", state_envelope)
state_bytes = rfc8785.dumps(state_envelope)

tier0_content = b"tier0-placeholder"
tier1_content = b"tier1-placeholder"
links_parquet_content = b"links-placeholder"
manifest = {
    "wist_version": "1.0.0",
    "snapshot_date": "2026-08-02",
    "log_position": 0,
    "anchor_block_hash": block_hash,
    "content_digest": snapshot_digest,
    "state": {"path": "state.json", "sha256": sha256_hex(state_bytes),
              "bytes": len(state_bytes),
              "state_digest": state_digest_of(state_entries)},
    "files": [
        {"path": "tier0/index.sqlite", "sha256": sha256_hex(tier0_content),
         "bytes": len(tier0_content), "tier": 0},
        {"path": "tier1/extracts.parquet", "sha256": sha256_hex(tier1_content),
         "bytes": len(tier1_content), "tier": 1},
        {"path": "tier1/links.parquet", "sha256": sha256_hex(links_parquet_content),
         "bytes": len(links_parquet_content), "tier": 1},
    ],
}
write_json(EXAMPLES / "snapshot-manifest.json",
           sign_envelope("manifest", manifest, "test-agg-k1"))

# ------------------------------------------------------- WIST-3 §5: mirrors
mirrors = {
    "wist_version": "1.0.0",
    "updated_at": "2026-08-02T13:05:00Z",
    "mirror_urls": ["https://mirror-1.example/", "https://mirror-2.example/"],
}
write_json(EXAMPLES / "mirrors.json", sign_envelope("mirrors", mirrors, "test-agg-k1"))
print("wist3 mirrors example written")

# ------------------------------------------------------ WIST-3 §6: discovery
snapshot_index = {
    "wist_version": "1.0.0",
    "updated_at": "2026-08-02T13:05:00Z",
    "snapshots": [
        {"snapshot_date": manifest["snapshot_date"],
         "log_position": manifest["log_position"],
         "manifest_url": "/snapshots/%s/manifest.json" % manifest["snapshot_date"],
         "content_digest": manifest["content_digest"]},
    ],
}
write_json(EXAMPLES / "snapshot-index.json",
           sign_envelope("index", snapshot_index, "test-agg-k1"))
print("wist3 snapshot content digest:", snapshot_digest)
print("wist3 block hash:", block_hash)
print("wist3 merkle root:", merkle_root)
print("wist3 leaves:", [l.hex() for l in leaves])
print("wist3 nodes: n01=%s n23=%s" % (n01.hex(), n23.hex()))

# ------------------------------------------------- WIST-4: audit + registry
# The Auditor's VRF proof over the Block Hash (WIST-4 §4). alpha is the 32 raw
# octets of the Block Hash — the hex digest decoded, WITHOUT the "sha256:"
# prefix. The VRF key is the Auditor's Ed25519 key (RFC 9381
# ECVRF-EDWARDS25519-SHA512-TAI reuses the RFC 8032 key format).
alpha = bytes.fromhex(block_hash.split(":")[1])
pi = ecvrf.prove(SEED, alpha)
beta = ecvrf.proof_to_hash(pi)

# Every content-derived value an Audit Record seals is committed under the
# Payload salt of the Payload the audit measured against (WIST-4 §5), so one
# salt lifecycle governs the Delta's commitment and the Auditor's alike.
# The audited Delta here is the WIST-1 vector Delta, so that salt is `salt`.
def audit_commit(message: bytes) -> str:
    return "hmac-sha256:" + hmac.new(salt, message, hashlib.sha256).hexdigest()


RESPONSE_BODY = b"response-placeholder"
REF_EXTRACTION = EXTRACT.encode()      # a `consistent` audit: the Auditor's own
                                       # extraction reproduces the Payload extract
WARC_CAPTURE = b"warc-placeholder"

audit_record = {
    "wist_version": "1.0.0",
    "audited_delta": delta_id,
    # The example chain holds one Delta, so the chain tip at fetch is the
    # audited Delta itself (WIST-4 §5).
    "reference_delta": delta_id,
    "auditor_id": "audit.example.net",
    "fetched_at": "2026-08-02T14:00:00Z",
    "response_commitment": audit_commit(RESPONSE_BODY),
    "ref_extract_commitment": audit_commit(REF_EXTRACTION),
    "similarity": 940000,
    # The vector page's observed links reproduce the declared ones exactly
    # (fixture 1 *is* the audited page), so this is link_agreement's own
    # exact-match case (WIST-4 §5) rather than a bare 1_000_000 literal.
    "link_agreement": link_extraction.link_agreement(
        CONTENT["links"]["urls"], CONTENT["links"]["total"],
        CONTENT["links"]["urls"], CONTENT["links"]["total"]),
    "verdict": "consistent",
    "evidence_commitment": audit_commit(WARC_CAPTURE),
    "vrf_proof": pi.hex(),
    # The example Auditor's first-ever publication (WIST-4 §4's per-auditor
    # chain starts at null); a later Record would carry the previous
    # Record-or-attestation ID here.
    "prev_record": None,
}
write_json(EXAMPLES / "audit-record.json",
           sign_envelope("record", audit_record, "test-aud-k1"))

WIST4 = ROOT / "vectors" / "wist4"
WIST4.mkdir(parents=True, exist_ok=True)
write_json(WIST4 / "audit-commitments.json", {
    "note": ("Preimages of the example Audit Record's commitments. Each is "
             "HMAC-SHA256 keyed by the salt of the Payload the audit measured "
             "against — here examples/payload.json, the Payload of the "
             "reference Delta, which in the example chain is the audited "
             "Delta itself (WIST-4 §5). Once that Payload is withdrawn the "
             "salt is gone and none of these commitments can be checked "
             "again."),
    "audited_delta": delta_id,
    "reference_delta": delta_id,
    "salt_source": "examples/payload.json",
    "commitments": {
        "response_commitment": {
            "message_hex": RESPONSE_BODY.hex(),
            "value": audit_record["response_commitment"]},
        "ref_extract_commitment": {
            "message_hex": REF_EXTRACTION.hex(),
            "value": audit_record["ref_extract_commitment"]},
        "evidence_commitment": {
            "message_hex": WARC_CAPTURE.hex(),
            "value": audit_record["evidence_commitment"]},
    },
})

# ------------------------------------------------ WIST-4: link agreement
AGREE_D = CONTENT["links"]["urls"]          # the example Payload's declaration
AGREE_TOTAL = CONTENT["links"]["total"]     # ditto, its total (WIST-1 §3.6 links.total)
write_json(WIST4 / "link-agreement.json", {
    "note": "Worked link_agreement cases (WIST-4 §5), integer micro-units.",
    "cases": [
        {"label": "exact-match", "declared_urls": AGREE_D, "declared_total": AGREE_TOTAL,
         "observed_urls": AGREE_D, "observed_total": AGREE_TOTAL,
         "link_agreement": link_extraction.link_agreement(
             AGREE_D, AGREE_TOTAL, AGREE_D, AGREE_TOTAL)},
        {"label": "one-dropped", "declared_urls": AGREE_D, "declared_total": AGREE_TOTAL,
         "observed_urls": AGREE_D[:-1], "observed_total": AGREE_TOTAL - 1,
         "link_agreement": link_extraction.link_agreement(
             AGREE_D, AGREE_TOTAL, AGREE_D[:-1], AGREE_TOTAL - 1)},
        {"label": "disjoint", "declared_urls": AGREE_D, "declared_total": AGREE_TOTAL,
         "observed_urls": ["https://unrelated.example.io/a"], "observed_total": 1,
         "link_agreement": link_extraction.link_agreement(
             AGREE_D, AGREE_TOTAL, ["https://unrelated.example.io/a"], 1)},
        {"label": "count-fraud", "declared_urls": AGREE_D, "declared_total": AGREE_TOTAL,
         "observed_urls": AGREE_D, "observed_total": 40,
         "link_agreement": link_extraction.link_agreement(AGREE_D, AGREE_TOTAL, AGREE_D, 40)},
        {"label": "both-empty", "declared_urls": [], "declared_total": 0,
         "observed_urls": [], "observed_total": 0,
         "link_agreement": link_extraction.link_agreement([], 0, [], 0)},
    ],
})
assert [c["link_agreement"] for c in
        json.loads((WIST4 / "link-agreement.json").read_text())["cases"]] == \
    [1_000_000, 666_666, 0, 75_000, 1_000_000], "agreement worked values drifted"
print("wist4 link-agreement vector written")

registry_update = {
    "wist_version": "1.0.0",
    "action": "auditor_admit",
    "subject": "audit.example.net",
    "details": {"key_id": "test-aud-k1", "alg": "Ed25519", "public_key": b64u(pub_raw)},
    "effective_at": "2026-08-02T12:00:00Z",
}
write_json(EXAMPLES / "registry-update.json",
           sign_envelope("update", registry_update, "test-agg-k1"))
print("wist4 audit-record and registry-update examples written")

# ------------------------------------------------------ WIST-4: audit sampling
# Worked VRF sampling vector (WIST-4 §4), computed the way §4 mandates: in
# integers, with no float anywhere in the selection test.
#   D(d)  = first 8 octets of SHA-256(beta || UTF-8 of the full Delta ID
#           string, "sha256:" prefix included), big-endian
#   p_1e7 = clamp(200000 + 3 x (1e6 - reputation_u), 200000, 5000000)
#   select <=> D x 10^7 < p_1e7 x 2^64
SAMPLING_FLOOR_1E7 = 200_000
SAMPLING_CEILING_1E7 = 5_000_000
SAMPLING_SLOPE = 3
TWO_64 = 2**64


def draw_D(beta_bytes: bytes, did: str) -> tuple[bytes, int]:
    first8 = hashlib.sha256(beta_bytes + did.encode()).digest()[:8]
    return first8, int.from_bytes(first8, "big")


def sampling_p_1e7(reputation_u: int) -> int:
    """WIST-4 §4's sampling rate, scaled by 1e7. Exact: no rounding occurs."""
    return min(max(SAMPLING_FLOOR_1E7 + SAMPLING_SLOPE * (10**6 - reputation_u),
                   SAMPLING_FLOOR_1E7), SAMPLING_CEILING_1E7)


def selected(D: int, p_1e7: int) -> bool:
    return D * 10**7 < p_1e7 * TWO_64


def approx4(n: int) -> str:
    """Exact integer -> 4-significant-digit rendering, e.g. 5.350e25.

    WIST-4's Appendix A shows these products rounded for reading; computing the
    rendering here (in Decimal, not float) keeps the published figure honest
    and lets the harness pin it.
    """
    with localcontext() as ctx:
        ctx.prec = 40
        d = Decimal(n)
        exp = len(str(n)) - 1
        mant = (d / Decimal(10) ** exp).quantize(Decimal("1.000"))
        return f"{mant}e{exp}"


# Guard against the published figures drifting from the Parameter Registry:
# 0.10 and 0.90 reputation read as p = 0.29 and 0.05.
assert sampling_p_1e7(100_000) == 2_900_000 and sampling_p_1e7(900_000) == 500_000, \
    "sampling p_1e7 drifted"
assert sampling_p_1e7(10**6) == SAMPLING_FLOOR_1E7, "floor not reached at full reputation"
assert sampling_p_1e7(0) == 3_200_000, "slope drifted"

# Two real Deltas of the same example Block, drawn against the same beta: entry
# 0 is selected by nobody, and one further Entry is selected at a Provisional
# domain's rate but not at an established domain's. One selected and one
# not-selected case is what exercises the strict inequality in both directions.
# Which Entry plays the second role follows from beta, so it is located here
# rather than pinned: any change to the Block moves every draw at once.
draw_bytes, D_primary = draw_D(beta, delta_id)
# WIST-3 §3.3's canonical order decides where each Entry sits, so the primary
# Delta's index is located, not assumed.
primary_index = next(
    i for i, e in enumerate(entries)
    if "sha256:" + sha256_hex(rfc8785.dumps(e["body"]["delta"])) == delta_id)
selected_index = next(
    i for i in range(len(entries))
    if i != primary_index
    and selected(draw_D(beta, "sha256:" + sha256_hex(
        rfc8785.dumps(entries[i]["body"]["delta"])))[1], sampling_p_1e7(100_000))
    and not selected(draw_D(beta, "sha256:" + sha256_hex(
        rfc8785.dumps(entries[i]["body"]["delta"])))[1], sampling_p_1e7(900_000)))
selected_delta_id = "sha256:" + sha256_hex(
    rfc8785.dumps(entries[selected_index]["body"]["delta"]))
sel_bytes, D_selected = draw_D(beta, selected_delta_id)

selection_cases = []
for idx, did, dbytes, D in (
        (primary_index, delta_id, draw_bytes, D_primary),
        (selected_index, selected_delta_id, sel_bytes, D_selected)):
    for rep_label, rep_u in (("provisional", 100_000), ("established", 900_000)):
        p1e7 = sampling_p_1e7(rep_u)
        selection_cases.append({
            "label": f"entry-{idx}-{rep_label}",
            "delta_id": did,
            "entry_index": idx,
            "draw_first8_hex": dbytes.hex(),
            "D": D,
            "reputation_u": rep_u,
            "p_1e7": p1e7,
            "lhs": D * 10**7,
            "rhs": p1e7 * TWO_64,
            "lhs_approx": approx4(D * 10**7),
            "rhs_approx": approx4(p1e7 * TWO_64),
            "selected": selected(D, p1e7),
        })
assert any(c["selected"] for c in selection_cases), "no selected case in the vector"
assert not all(c["selected"] for c in selection_cases), "no rejected case in the vector"

write_json(WIST4 / "sampling.json", {
    "auditor_public_key": b64u(pub_raw),
    "ciphersuite": "ECVRF-EDWARDS25519-SHA512-TAI",
    "block_hash": block_hash,
    "alpha_hex": alpha.hex(), "vrf_proof_hex": pi.hex(), "beta_hex": beta.hex(),
    "delta_id": delta_id, "draw_first8_hex": draw_bytes.hex(), "D": D_primary,
    "test": "select <=> D x 10^7 < p_1e7 x 2^64  (integers only, WIST-4 §4)",
    "note": ("D, lhs and rhs exceed 2^53; a consumer whose JSON parser uses "
             "IEEE-754 doubles MUST read D from draw_first8_hex and recompute "
             "lhs/rhs as big integers."),
    "parameters": {"floor_1e7": SAMPLING_FLOOR_1E7, "ceiling_1e7": SAMPLING_CEILING_1E7,
                   "slope_per_micro": SAMPLING_SLOPE},
    "selection": selection_cases,
})
print("wist4 sampling alpha:", alpha.hex())
print("wist4 sampling pi:", pi.hex())
print("wist4 sampling beta:", beta.hex())
print("wist4 sampling draw[:8] hex:", draw_bytes.hex(), "D:", D_primary)
for c in selection_cases:
    print("wist4 sampling %-22s D=%-20d rep_u=%-7d p_1e7=%-8d -> %s" % (
        c["label"], c["D"], c["reputation_u"], c["p_1e7"],
        "AUDIT" if c["selected"] else "no audit"))

# --------------------------------------------------------- WIST-4: decay table
# WIST-4 §6.1: decay(t) = floor(exp(-t/180) * 1e9) for whole days 0..1825.
# The published table is normative; nothing at runtime evaluates exp(). It is
# generated here in exact decimal arithmetic (never IEEE-754 doubles, whose
# exp() differs in the last ulp between libms) via the Taylor series for
# exp(x), which converges for every x and whose terms are exact decimals.
DECAY_SCALE = 10**9
DECAY_MAX_DAYS = 1825
DECAY_TAU = 180


def decay_scaled(t: int, prec: int) -> int:
    """floor(exp(-t/180) * 1e9), computed at `prec` significant decimal digits."""
    with localcontext() as ctx:
        ctx.prec = prec
        x = Decimal(-t) / Decimal(DECAY_TAU)
        term = total = Decimal(1)
        k = 1
        # Stop once the last term added is below the working epsilon; the tail
        # of an alternating series is bounded by its first omitted term.
        eps = Decimal(10) ** -(prec - 10)
        while abs(term) > eps:
            term = term * x / k
            total += term
            k += 1
        return int((total * Decimal(DECAY_SCALE)).to_integral_value(rounding="ROUND_FLOOR"))


decay_table = [decay_scaled(t, 60) for t in range(DECAY_MAX_DAYS + 1)]
# The floor() is only well defined if it is stable under more precision: recompute
# the whole table at double the working precision and require byte equality. If any
# entry sat within 1e-50 of an integer boundary this would catch it.
assert decay_table == [decay_scaled(t, 120) for t in range(DECAY_MAX_DAYS + 1)], \
    "decay table is not stable under increased precision"
assert decay_table[0] == DECAY_SCALE, "decay(0) must be exactly 1e9"
assert all(decay_table[i] > decay_table[i + 1] for i in range(DECAY_MAX_DAYS)), \
    "decay table must be strictly decreasing"

write_json(WIST4 / "decay-table.json", {
    "scale": DECAY_SCALE,
    "max_days": DECAY_MAX_DAYS,
    "values": decay_table,
})
print("wist4 decay table: decay(0)=%d decay(30)=%d decay(1825)=%d" % (
    decay_table[0], decay_table[30], decay_table[DECAY_MAX_DAYS]))

# ------------------------------------------------------- WIST-4: reputation
# WIST-4 §6, in the integers the spec mandates. Nothing here is a float.
MICRO = 10**6
BASE_AT_AGE_0 = 100_000          # = the Provisional cap (§6.2)
AGE_NORM_DAYS = 730
C_CAP = 500
PENALTY_WEIGHT = 5
GATE_AGE_DAYS = 30
GATE_C = 10
PROVISIONAL_CAP = 100_000


def epoch_seconds(ts: str) -> int:
    """RFC 3339 UTC -> integer POSIX seconds (86400 s/day, no leap seconds)."""
    return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))


def whole_days(earlier: str, later: str) -> int:
    delta = epoch_seconds(later) - epoch_seconds(earlier)
    assert delta >= 0, "sealed_at is strictly increasing (WIST-3 §3.1)"
    return delta // 86400


def base_u(age_days: int) -> int:
    return BASE_AT_AGE_0 + (
        (MICRO - BASE_AT_AGE_0) * min(age_days, AGE_NORM_DAYS)) // AGE_NORM_DAYS


def decay(t: int) -> int:
    return decay_table[t] if t <= DECAY_MAX_DAYS else 0


def reputation_case(label, age_days, distinct_urls, incidents, note=""):
    """One fully worked §6 evaluation. `incidents` = [(severity, t_days), ...]."""
    c = min(distinct_urls, C_CAP)
    # Ascending t_i (ties: Delta ID byte order) — integer addition, so the order
    # cannot change the total; it only makes published intermediates agree.
    ordered = sorted(incidents, key=lambda i: (i[1], i[0]))
    penalty_n = sum(s * decay(t) for s, t in ordered)
    b = base_u(age_days)
    numerator = b * (c + 1) * DECAY_SCALE
    denominator = (c + 1) * DECAY_SCALE + PENALTY_WEIGHT * penalty_n
    formula_u = numerator // denominator
    formula_u = max(0, min(MICRO, formula_u))
    provisional = age_days < GATE_AGE_DAYS or c < GATE_C
    reputation_u = min(formula_u, PROVISIONAL_CAP) if provisional else formula_u
    quota = 100 + 10_000 * reputation_u // MICRO
    # §4's sampling rate for this reputation, in §4's own integer scale.
    p_1e7 = sampling_p_1e7(reputation_u)
    return {
        "label": label,
        "note": note,
        "A": age_days,
        "distinct_audited_urls": distinct_urls,
        "C": c,
        "inconsistencies": [
            {"severity": s, "t_days": t, "decay": decay(t)} for s, t in ordered],
        "base_u": b,
        "penalty_n": penalty_n,
        "numerator": numerator,
        "denominator": denominator,
        "formula_u": formula_u,
        "provisional": provisional,
        "reputation_u": reputation_u,
        "Q": quota,
        "p_1e7": p_1e7,
        "p_readable": "0.%07d" % p_1e7,
    }


# The primary worked example, with A and t_i derived from real Block sealed_at
# values rather than asserted: the first Delta is the one sealed in the WIST-3
# example Block, and Block N is sealed 400 days and 5 hours later, so the
# partial day truncates away and A = 400.
FIRST_DELTA_BLOCK_SEALED_AT = header["sealed_at"]        # 2026-08-02T13:00:00Z
BLOCK_N_SEALED_AT = "2027-09-06T18:00:00Z"               # +400d 5h
CONFIRMING_BLOCK_SEALED_AT = "2027-08-07T17:00:00Z"      # 30d 1h before Block N

A_primary = whole_days(FIRST_DELTA_BLOCK_SEALED_AT, BLOCK_N_SEALED_AT)
t_primary = whole_days(CONFIRMING_BLOCK_SEALED_AT, BLOCK_N_SEALED_AT)
assert (A_primary, t_primary) == (400, 30), "worked-example day counts drifted"

primary = reputation_case(
    "worked-example", A_primary, 12, [(2, t_primary)],
    "A = 400 days, C = 12 distinct audited URLs, one severity-2 Confirmed "
    "Inconsistency confirmed 30 days before Block N.")
primary["sealed_at"] = {
    "first_delta_block": FIRST_DELTA_BLOCK_SEALED_AT,
    "confirming_block": CONFIRMING_BLOCK_SEALED_AT,
    "block_n": BLOCK_N_SEALED_AT,
}

# The Provisional boundary. Requirement: reputation MUST NOT fall because a
# gate lifted. Rows 1-3 walk A across the age gate at C = 10 with a clean
# record; rows 4-6 walk the same boundary with a severity-2 penalty in force
# (where the cap is not even binding); rows 7-8 walk the C gate for an aged
# domain, the only place the cap actually binds.
boundary = [
    reputation_case("gate-age-below", 29, 10, [], "A one day short of the age gate"),
    reputation_case("gate-age-at", 30, 10, [], "exactly at both gates"),
    reputation_case("gate-age-above", 31, 10, [], "one day past the age gate"),
    reputation_case("gate-age-below-penalized", 29, 10, [(2, 30)],
                    "same, with a severity-2 Confirmed Inconsistency at t = 30"),
    reputation_case("gate-age-at-penalized", 30, 10, [(2, 30)],
                    "same, exactly at both gates"),
    reputation_case("gate-c-below", 800, 9, [], "aged but under-audited: the cap binds"),
    reputation_case("gate-c-at", 800, 10, [], "the same domain one audited URL later"),
    reputation_case("new-domain", 0, 0, [], "a brand-new domain"),
]

write_json(WIST4 / "reputation.json", {
    "micro_scale": MICRO,
    "decay_scale": DECAY_SCALE,
    "constants": {
        "base_at_age_0": BASE_AT_AGE_0,
        "age_normalization_days": AGE_NORM_DAYS,
        "c_cap": C_CAP,
        "penalty_weight": PENALTY_WEIGHT,
        "gate_age_days": GATE_AGE_DAYS,
        "gate_c": GATE_C,
        "provisional_cap_u": PROVISIONAL_CAP,
        "decay_tau_days": DECAY_TAU,
        "decay_max_days": DECAY_MAX_DAYS,
        "quota_base": 100,
        "quota_slope": 10_000,
        "inclusion_latency_threshold_u": 500_000,
    },
    "worked_example": primary,
    "boundary": boundary,
})
for case in [primary] + boundary:
    print("wist4 reputation %-24s A=%-4d C=%-3d penalty=%-12d formula=%-7d rep_u=%-7d Q=%-6d p=%s"
          % (case["label"], case["A"], case["C"], case["penalty_n"],
             case["formula_u"], case["reputation_u"], case["Q"], case["p_readable"]))
assert all(
    boundary[i]["reputation_u"] <= boundary[i + 1]["reputation_u"]
    for i in (0, 1, 3, 5)), "reputation fell when a gate lifted"

# --------------------------------------- WIST-4: replay-derivation vectors
# §3 independence, §5/§7 confirming-block selection and severity, §6.1/§6.3
# A/C/penalty inputs, §4 coverage counting and extension rationing, §7 ladder
# state. Pure integer functions over abstract Log positions: `sealed_at`
# appears as integer POSIX seconds (`*_s`), heights and Entry indexes as
# integers, Auditors and Publishers as hostnames. Every expected value below
# is computed by the reference functions here, never written by hand.

HOUR_S = 3600
DAY_S = 86400
CONFIRM_WINDOW_HOURS = 72
INCONSISTENT_EFFECTIVE_BELOW = 300_000
SEVERITY_MINOR_FLOOR = 150_000
SEVERITY_MISLEADING_FLOOR = 50_000
EXTENSION_TRIGGERS_MAX = 3
CONTRADICTIONS_MAX = 2
RATION_WINDOW_DAYS = 30
COVERAGE_FAILURES_MAX = 24
ESCALATIONS = {"l2": (3, 90, 0), "l3_count": (10, 90, 0), "l4_sev3": (3, 180, 3)}
APPEAL_WINDOW_DAYS = 14
APPEAL_SEAL_DAYS = 7
RULING_DEADLINE_DAYS = 30


def spaced_labels(node):
    """Labels are prose, not identifiers: spaces keep them outside the token
    shapes the repo-wide digest sweep in validate_examples.py flags."""
    if isinstance(node, dict):
        return {k: (v.replace("-", " ") if k == "label" and isinstance(v, str)
                    else spaced_labels(v)) for k, v in node.items()}
    if isinstance(node, list):
        return [spaced_labels(v) for v in node]
    return node


def independent(a: str, b: str) -> bool:
    """WIST-4 §3: no shared suffix of two or more labels."""
    sa, sb = a.split(".")[-2:], b.split(".")[-2:]
    if len(sa) < 2 or len(sb) < 2:
        return True
    return sa != sb


def confirming_index(records, window_hours):
    """WIST-4 §5/§7: earliest Record, in Log order, sealed within the pairwise
    window of an earlier Record from an independent Auditor."""
    for prev, nxt in zip(records, records[1:]):
        assert (nxt["block_height"], nxt["entry_index"]) > \
               (prev["block_height"], prev["entry_index"]), "not in Log order"
        assert nxt["sealed_at_s"] >= prev["sealed_at_s"], "sealed_at decreased"
    window_s = window_hours * HOUR_S
    for i, record in enumerate(records):
        for earlier in records[:i]:
            if independent(earlier["auditor"], record["auditor"]) and \
               record["sealed_at_s"] - earlier["sealed_at_s"] <= window_s:
                return i
    return None


def ci_severity(records, confirming):
    """WIST-4 §7: highest effective similarity over the closed confirming set."""
    sim = max(r["effective_similarity"] for r in records[:confirming + 1])
    assert sim < INCONSISTENT_EFFECTIVE_BELOW, "not an inconsistent-band similarity"
    if sim >= SEVERITY_MINOR_FLOOR:
        return 1
    if sim >= SEVERITY_MISLEADING_FLOOR:
        return 2
    return 3


def rec(height, entry, sealed_at_s, auditor, effective_similarity=0):
    return {"block_height": height, "entry_index": entry, "sealed_at_s": sealed_at_s,
            "auditor": auditor, "effective_similarity": effective_similarity}


AUD_A, AUD_B, AUD_C = "audit.example.net", "checker.example.org", "watch.sample.net"
AUD_A2 = "peer.example.net"

independence_cases = [
    {"a": a, "b": b, "independent": independent(a, b)}
    for a, b in [
        (AUD_A, AUD_B),
        ("a.example.org", "b.example.org"),
        ("a.com.br", "b.com.br"),
        ("audit.example.org", "audit.example.org"),
        ("a.example.org", "b.sample.org"),
        ("example.org", "a.example.org"),
    ]
]

confirmation_scenarios = [
    ("pair-inside-window", [rec(1, 0, 0, AUD_A, 40_000), rec(2, 0, 10 * HOUR_S, AUD_B, 10_000)]),
    ("same-auditor-never", [rec(1, 0, 0, AUD_A), rec(2, 0, 10 * HOUR_S, AUD_A)]),
    ("dependent-never", [rec(1, 0, 0, AUD_A), rec(2, 0, 10 * HOUR_S, AUD_A2)]),
    ("boundary-inclusive", [rec(1, 0, 0, AUD_A, 200_000), rec(2, 0, 72 * HOUR_S, AUD_B, 100_000)]),
    ("boundary-exceeded", [rec(1, 0, 0, AUD_A), rec(2, 0, 72 * HOUR_S + 1, AUD_B)]),
    ("stale-first-later-pair", [rec(1, 0, 0, AUD_A, 10_000),
                                rec(2, 0, 100 * HOUR_S, AUD_B, 160_000),
                                rec(3, 0, 110 * HOUR_S, AUD_C, 20_000)]),
    ("pair-skips-dependent", [rec(1, 0, 0, AUD_A, 40_000),
                              rec(2, 0, 10 * HOUR_S, AUD_A2, 60_000),
                              rec(3, 0, 20 * HOUR_S, AUD_B, 10_000)]),
    ("earliest-wins", [rec(1, 0, 0, AUD_A, 40_000),
                       rec(2, 0, 10 * HOUR_S, AUD_B, 10_000),
                       rec(3, 0, 20 * HOUR_S, AUD_C, 10_000)]),
    ("late-record-outside-closed-set", [rec(1, 0, 0, AUD_A, 40_000),
                                        rec(2, 0, 10 * HOUR_S, AUD_B, 10_000),
                                        rec(3, 0, 20 * HOUR_S, AUD_C, 250_000)]),
    ("shared-block-zero-gap", [rec(5, 0, 100, AUD_A, 100_000), rec(5, 1, 100, AUD_B, 60_000)]),
]

confirmation_cases = []
for label, records in confirmation_scenarios:
    idx = confirming_index(records, CONFIRM_WINDOW_HOURS)
    confirmation_cases.append({
        "label": label,
        "records": records,
        "confirming_index": idx,
        "severity": None if idx is None else ci_severity(records, idx),
    })

write_json(WIST4 / "confirmation.json", spaced_labels({
    "note": "WIST-4 §5/§7 confirming-block selection and severity over one Delta's inconsistent Records in Log order.",
    "confirm_window_hours": CONFIRM_WINDOW_HOURS,
    "severity_bands": {"minor_floor": SEVERITY_MINOR_FLOOR,
                       "misleading_floor": SEVERITY_MISLEADING_FLOOR,
                       "inconsistent_below": INCONSISTENT_EFFECTIVE_BELOW},
    "independence": independence_cases,
    "cases": confirmation_cases,
}))


def most_recent_reset(resets, n):
    below = [r for r in resets if r <= n]
    return max(below) if below else None


def in_scope(height, reset, n):
    return height <= n and (reset is None or height > reset)


def derive_inputs(case):
    reset = most_recent_reset(case["resets"], case["n"]["height"])
    n_h, n_s = case["n"]["height"], case["n"]["sealed_at_s"]
    accepted = [d for d in case["accepted"] if in_scope(d["height"], reset, n_h)]
    a_days = 0
    if accepted:
        first = min(accepted, key=lambda d: d["height"])
        a_days = (n_s - first["sealed_at_s"]) // DAY_S
    urls = {a["url"] for a in case["consistent_audits"]
            if in_scope(a["height"], reset, n_h) and a["change"] in ("new", "update")}
    c = min(len(urls), C_CAP)
    entries = []
    for finding in case["confirmed"]:
        if not in_scope(finding["height"], reset, n_h):
            continue
        t = (n_s - finding["sealed_at_s"]) // DAY_S
        entries.append((t, finding["delta_id"], finding["severity"]))
    entries.sort(key=lambda e: (e[0], e[1].encode()))
    return {"reset": reset, "a_days": a_days, "c": c,
            "penalty_inputs": [[s, t] for t, _, s in entries]}


derivation_scenarios = [
    {"label": "no-reset-full-history",
     "resets": [], "n": {"height": 100, "sealed_at_s": 130 * DAY_S},
     "accepted": [{"height": 10, "sealed_at_s": 100 * DAY_S},
                  {"height": 20, "sealed_at_s": 110 * DAY_S}],
     "consistent_audits": [
         {"height": 30, "url": "https://site.example/a", "change": "new"},
         {"height": 40, "url": "https://site.example/a", "change": "update"},
         {"height": 50, "url": "https://site.example/b", "change": "update"},
         {"height": 60, "url": "https://site.example/c", "change": "attest"},
         {"height": 70, "url": "https://site.example/d", "change": "delete"}],
     "confirmed": [
         {"height": 80, "sealed_at_s": 100 * DAY_S, "delta_id": "sha256:bb", "severity": 2},
         {"height": 81, "sealed_at_s": 100 * DAY_S, "delta_id": "sha256:aa", "severity": 3},
         {"height": 90, "sealed_at_s": 120 * DAY_S, "delta_id": "sha256:cc", "severity": 1}]},
    {"label": "reset-rescopes-everything",
     "resets": [55], "n": {"height": 100, "sealed_at_s": 130 * DAY_S},
     "accepted": [{"height": 10, "sealed_at_s": 100 * DAY_S},
                  {"height": 60, "sealed_at_s": 120 * DAY_S}],
     "consistent_audits": [
         {"height": 50, "url": "https://site.example/a", "change": "new"},
         {"height": 70, "url": "https://site.example/b", "change": "new"}],
     "confirmed": [
         {"height": 55, "sealed_at_s": 110 * DAY_S, "delta_id": "sha256:aa", "severity": 3},
         {"height": 90, "sealed_at_s": 125 * DAY_S, "delta_id": "sha256:bb", "severity": 1}]},
    {"label": "reset-with-nothing-after",
     "resets": [90], "n": {"height": 100, "sealed_at_s": 130 * DAY_S},
     "accepted": [{"height": 10, "sealed_at_s": 100 * DAY_S}],
     "consistent_audits": [
         {"height": 30, "url": "https://site.example/a", "change": "new"}],
     "confirmed": [
         {"height": 80, "sealed_at_s": 100 * DAY_S, "delta_id": "sha256:aa", "severity": 3}]},
]
for case in derivation_scenarios:
    case["expected"] = derive_inputs(case)

write_json(WIST4 / "derivation.json", spaced_labels({
    "note": "WIST-4 §6.1/§6.3 inputs derived from one domain's Log events. penalty_inputs rows are [severity, t_days].",
    "c_cap": C_CAP,
    "cases": derivation_scenarios,
}))


def within_days_ending_at(t_s, end_s, days):
    return t_s <= end_s and end_s - t_s < days * DAY_S


def pair_status(selected, recorded, attested):
    if not selected:
        return "discharged" if attested else "failed"
    return "discharged" if all(d in recorded for d in selected) else "failed"


def pair_counts(attestation, chain_proof_in_window):
    if attestation == "unmet":
        return True
    if attestation == "unmet-chain-contradicted":
        return False
    assert attestation == "missing"
    return not chain_proof_in_window


def in_coverage_failure(times_s, n_s, failures_max):
    return sum(1 for t in times_s
               if within_days_ending_at(t, n_s, RATION_WINDOW_DAYS)) > failures_max


DID1, DID2 = "sha256:d1", "sha256:d2"
coverage_pair_cases = [
    {"label": label, "selected": sel, "recorded": recd, "attested": att,
     "status": pair_status(sel, recd, att)}
    for label, sel, recd, att in [
        ("full-coverage", [DID1, DID2], [DID2, DID1], False),
        ("partial-is-failure", [DID1, DID2], [DID1], False),
        ("empty-selection-unattested", [], [], False),
        ("empty-selection-attested", [], [], True),
        ("extra-records-harmless", [DID1], [DID1, DID2], False),
    ]
]
coverage_counting_cases = [
    {"label": label, "attestation": att, "chain_proof_in_window": chain,
     "counts": pair_counts(att, chain)}
    for label, att, chain in [
        ("attested-unmet-counts", "unmet", False),
        ("chain-contradiction-stops-count", "unmet-chain-contradicted", False),
        ("unattested-counts", "missing", False),
        ("chain-proof-excludes-unattested", "missing", True),
        ("chain-proof-does-not-shield-attested", "unmet", True),
    ]
]
coverage_state_scenarios = [
    ("at-the-maximum", [90 * DAY_S + i for i in range(COVERAGE_FAILURES_MAX)], 100 * DAY_S),
    ("past-the-maximum", [90 * DAY_S + i for i in range(COVERAGE_FAILURES_MAX + 1)], 100 * DAY_S),
    ("aged-out", [10 * DAY_S + i for i in range(30)], 100 * DAY_S),
]
coverage_state_cases = [
    {"label": label, "counting_failure_times_s": times, "n_sealed_at_s": n_s,
     "in_coverage_failure": in_coverage_failure(times, n_s, COVERAGE_FAILURES_MAX)}
    for label, times, n_s in coverage_state_scenarios
]

write_json(WIST4 / "coverage.json", spaced_labels({
    "note": "WIST-4 §4 coverage-failure counting: pair status, the count at Block N, and the coverage-failure state.",
    "coverage_deadline_hours": 72,
    "coverage_failures_max": COVERAGE_FAILURES_MAX,
    "record_seal_blocks": 24,
    "window_days": RATION_WINDOW_DAYS,
    "pair_cases": coverage_pair_cases,
    "counting_cases": coverage_counting_cases,
    "state_cases": coverage_state_cases,
}))


def trigger_indices(records, window_hours):
    window_s = window_hours * HOUR_S
    return [i for i, record in enumerate(records)
            if not any(record["sealed_at_s"] - earlier["sealed_at_s"] <= window_s
                       for earlier in records[:i])]


def extension_deadline_s(b1_s, window_hours):
    return b1_s + (window_hours // 2) * HOUR_S


def rationed_summons(triggers, window_days, triggers_max):
    summons = []
    for i, (auditor, at_s) in enumerate(triggers):
        prior = sum(1 for (ea, es), s in zip(triggers[:i], summons)
                    if s and ea == auditor and within_days_ending_at(es, at_s, window_days))
        summons.append(prior < triggers_max)
    return summons


def summoned(roster, already_sealed, publisher_domain):
    return [i for i, candidate in enumerate(roster)
            if independent(candidate, publisher_domain)
            and all(independent(candidate, filer) for filer in already_sealed)]


def in_divergence(times_s, n_s, contradictions_max):
    return sum(1 for t in times_s
               if within_days_ending_at(t, n_s, RATION_WINDOW_DAYS)) > contradictions_max


extension_trigger_scenarios = [
    ("lone-first-triggers", [rec(1, 0, 0, AUD_A)]),
    ("inside-window-no-trigger", [rec(1, 0, 0, AUD_A), rec(2, 0, 72 * HOUR_S, AUD_B)]),
    ("past-window-triggers-again", [rec(1, 0, 0, AUD_A), rec(2, 0, 72 * HOUR_S + 1, AUD_B)]),
    ("any-earlier-record-suppresses", [rec(1, 0, 0, AUD_A),
                                       rec(2, 0, 50 * HOUR_S, AUD_B),
                                       rec(3, 0, 100 * HOUR_S, AUD_C)]),
]
extension_trigger_cases = [
    {"label": label, "records": records,
     "trigger_indices": trigger_indices(records, CONFIRM_WINDOW_HOURS)}
    for label, records in extension_trigger_scenarios
]
extension_ration_scenarios = [
    ("fourth-in-window-rationed",
     [[AUD_A, 0], [AUD_A, DAY_S], [AUD_A, 2 * DAY_S], [AUD_A, 3 * DAY_S]]),
    ("ration-resets-as-summons-age-out",
     [[AUD_A, 0], [AUD_A, DAY_S], [AUD_A, 2 * DAY_S], [AUD_A, 32 * DAY_S]]),
    ("rationed-out-trigger-consumes-nothing",
     [[AUD_A, 0], [AUD_A, HOUR_S], [AUD_A, 2 * HOUR_S], [AUD_A, 3 * HOUR_S],
      [AUD_A, 30 * DAY_S + HOUR_S]]),
    ("ration-is-per-auditor",
     [[AUD_A, 0], [AUD_A, HOUR_S], [AUD_A, 2 * HOUR_S], [AUD_B, 3 * HOUR_S]]),
]
extension_ration_cases = [
    {"label": label, "triggers": triggers,
     "summons": rationed_summons([tuple(t) for t in triggers],
                                 RATION_WINDOW_DAYS, EXTENSION_TRIGGERS_MAX)}
    for label, triggers in extension_ration_scenarios
]
extension_summons_cases = [
    {"label": "dependents-of-filers-and-publisher-excluded",
     "roster": [AUD_A, AUD_A2, AUD_B, "watch.publisher.example"],
     "already_sealed": [AUD_A], "publisher_domain": "www.publisher.example",
     "summoned_indices": summoned([AUD_A, AUD_A2, AUD_B, "watch.publisher.example"],
                                  [AUD_A], "www.publisher.example")},
    {"label": "independence-from-every-filer",
     "roster": [AUD_C, AUD_A2],
     "already_sealed": [AUD_A, "eye.sample.net"],
     "publisher_domain": "www.publisher.example",
     "summoned_indices": summoned([AUD_C, AUD_A2],
                                  [AUD_A, "eye.sample.net"], "www.publisher.example")},
]
divergence_scenarios = [
    ("at-the-maximum", [99 * DAY_S, 98 * DAY_S], 100 * DAY_S),
    ("past-the-maximum", [99 * DAY_S, 98 * DAY_S, 97 * DAY_S], 100 * DAY_S),
    ("aged-out", [60 * DAY_S, 98 * DAY_S, 97 * DAY_S], 100 * DAY_S),
]
divergence_cases = [
    {"label": label, "contradiction_times_s": times, "n_sealed_at_s": n_s,
     "in_divergence": in_divergence(times, n_s, CONTRADICTIONS_MAX)}
    for label, times, n_s in divergence_scenarios
]

write_json(WIST4 / "extension.json", spaced_labels({
    "note": "WIST-4 §4 extension rule: trigger, ration, summoned set and divergence.",
    "confirm_window_hours": CONFIRM_WINDOW_HOURS,
    "extension_triggers_max": EXTENSION_TRIGGERS_MAX,
    "contradictions_max": CONTRADICTIONS_MAX,
    "ration_window_days": RATION_WINDOW_DAYS,
    "deadline_cases": [
        {"b1_sealed_at_s": 1000, "confirm_window_hours": 72,
         "deadline_s": extension_deadline_s(1000, 72)},
        {"b1_sealed_at_s": 0, "confirm_window_hours": 73,
         "deadline_s": extension_deadline_s(0, 73)},
    ],
    "trigger_cases": extension_trigger_cases,
    "ration_cases": extension_ration_cases,
    "summons_cases": extension_summons_cases,
    "divergence_cases": divergence_cases,
}))

# ------------------------------------ WIST-4 §4: the extension Record's proof
# A Record the extension rule names carries the proof for B₁, the Block that
# sealed the triggering Record: the draw over the audited Block did not select
# the Delta, and the Record's standing is B₁'s selection set. B₁ here is the
# empty Block; a third alpha stands for a Block that names the Delta for
# nobody, and the audited Block's own proof shows the draw that did not select.
EXTENSION_REPUTATION_U = 900_000
assert not selected(D_primary, sampling_p_1e7(EXTENSION_REPUTATION_U)), \
    "the extension-proof vector needs a Delta the audited Block's draw does not select"
trigger_alpha = bytes.fromhex(sha256_hex(empty_canonical))
trigger_pi = ecvrf.prove(SEED, trigger_alpha)
neither_alpha = hashlib.sha256(b"wist-test-block|neither").digest()
neither_pi = ecvrf.prove(SEED, neither_alpha)
write_json(WIST4 / "extension-proof.json", spaced_labels({
    "note": ("WIST-4 §3, §4: the Block an Audit Record's vrf_proof is over. "
             "audited_block carries audited_delta; trigger_block is B₁, the Block "
             "sealing the triggering Record. Each case gives the proof, the Block it "
             "verifies over and the standing it earns."),
    "auditor_public_key": b64u(pub_raw),
    "audited_delta": delta_id,
    "audited_block": {"block_hash": block_hash, "alpha_hex": alpha.hex()},
    "trigger_block": {"block_hash": "sha256:" + sha256_hex(empty_canonical),
                      "alpha_hex": trigger_alpha.hex()},
    "reputation_u": EXTENSION_REPUTATION_U,
    "cases": [
        {"label": "extension-proof-over-trigger-block", "vrf_proof_hex": trigger_pi.hex(),
         "named_by_extension": True, "proof_block": "trigger", "standing": "extension"},
        {"label": "audited-block-proof-unselected", "vrf_proof_hex": pi.hex(),
         "named_by_extension": True, "proof_block": "audited", "standing": "WIST4-E01"},
        {"label": "proof-over-neither-block", "vrf_proof_hex": neither_pi.hex(),
         "named_by_extension": True, "proof_block": None, "standing": "WIST4-E01"},
        {"label": "trigger-proof-but-not-summoned", "vrf_proof_hex": trigger_pi.hex(),
         "named_by_extension": False, "proof_block": "trigger", "standing": "WIST4-E01"},
    ],
}))
print("wist4 extension-proof vector written")


def criterion_times(findings, count, span_days, min_severity):
    qualifying = [f["sealed_at_s"] for f in findings if f["severity"] >= min_severity]
    met = []
    for k, at in enumerate(qualifying):
        in_span = sum(1 for earlier in qualifying[:k + 1]
                      if span_days is None
                      or within_days_ending_at(earlier, at, span_days))
        if in_span >= count:
            met.append(at)
    return met


def in_force_strictly_before(met, clear, t_s):
    last_met = max((m for m in met if m < t_s), default=None)
    last_clear = max((c for c in clear if c < t_s), default=None)
    return last_met is not None and (last_clear is None or last_clear < last_met)


def l4_accrual_times(findings, l3_met, l3_clear):
    return [f["sealed_at_s"] for f in findings
            if in_force_strictly_before(l3_met, l3_clear, f["sealed_at_s"])]


def state_void_at(notice_s, appeal_s, ruling):
    if notice_s is None:
        return None
    window_close = notice_s + APPEAL_WINDOW_DAYS * DAY_S
    t = window_close + APPEAL_SEAL_DAYS * DAY_S
    appeal_by_t = appeal_s if appeal_s is not None and appeal_s <= t else None
    valid_unappealed = (ruling is not None and ruling[0] == "unappealed"
                        and window_close <= ruling[1] <= t)
    if appeal_by_t is None and not valid_unappealed:
        return t
    if appeal_by_t is None:
        return None
    due = appeal_by_t + RULING_DEADLINE_DAYS * DAY_S
    if ruling is not None and ruling[1] <= due:
        if ruling[0] == "overturned":
            return ruling[1]
        if ruling[0] == "upheld":
            return None
    return due


def in_force(met, clear, n_s):
    last_met = max((m for m in met if m <= n_s), default=None)
    last_clear = max((c for c in clear if c <= n_s), default=None)
    return last_met is not None and (last_clear is None or last_clear < last_met)


def finding(day, severity):
    return {"sealed_at_s": day * DAY_S, "severity": severity}


sanction_criterion_scenarios = [
    ("every-finding-meets-l1", [finding(10, 1), finding(20, 2)], 1, None, 0),
    ("three-in-ninety-meet-l2",
     [finding(0, 1), finding(30, 1), finding(89, 1), finding(200, 1)],
     ESCALATIONS["l2"][0], ESCALATIONS["l2"][1], ESCALATIONS["l2"][2]),
    ("spread-past-span-never-meets",
     [finding(0, 1), finding(91, 1), finding(182, 1)],
     ESCALATIONS["l2"][0], ESCALATIONS["l2"][1], ESCALATIONS["l2"][2]),
    # The boundary itself: the window is end-inclusive and start-exclusive
    # (§7, §6.1), so a finding exactly `span` whole days before the one that
    # would complete the count sits outside it.
    ("exactly-ninety-days-apart-is-outside",
     [finding(0, 1), finding(45, 1), finding(90, 1)],
     ESCALATIONS["l2"][0], ESCALATIONS["l2"][1], ESCALATIONS["l2"][2]),
    ("one-day-inside-ninety-meets",
     [finding(0, 1), finding(45, 1), finding(89, 1)],
     ESCALATIONS["l2"][0], ESCALATIONS["l2"][1], ESCALATIONS["l2"][2]),
    ("exactly-one-eighty-days-apart-is-outside",
     [finding(0, 3), finding(90, 3), finding(180, 3)],
     ESCALATIONS["l4_sev3"][0], ESCALATIONS["l4_sev3"][1], ESCALATIONS["l4_sev3"][2]),
    ("one-day-inside-one-eighty-meets",
     [finding(0, 3), finding(90, 3), finding(179, 3)],
     ESCALATIONS["l4_sev3"][0], ESCALATIONS["l4_sev3"][1], ESCALATIONS["l4_sev3"][2]),
    ("three-severity-3-in-180-meet-l4",
     [finding(0, 3), finding(10, 1), finding(20, 3), finding(30, 3)],
     ESCALATIONS["l4_sev3"][0], ESCALATIONS["l4_sev3"][1], ESCALATIONS["l4_sev3"][2]),
    ("any-severity-3-meets-l3",
     [finding(0, 3), finding(10, 1), finding(20, 3), finding(30, 3)], 1, None, 3),
]
sanction_criterion_cases = [
    {"label": label, "findings": findings, "count": count, "span_days": span,
     "min_severity": sev, "met_times_s": criterion_times(findings, count, span, sev)}
    for label, findings, count, span, sev in sanction_criterion_scenarios
]
sanction_accrual_scenarios = [
    ("accrual-while-l3-in-force", [finding(10, 3), finding(20, 1), finding(30, 1)],
     [10 * DAY_S], []),
    ("the-creating-finding-is-not-accrual", [finding(10, 3)], [10 * DAY_S], []),
    ("accrual-stops-at-clear", [finding(10, 3), finding(20, 1), finding(40, 1)],
     [10 * DAY_S], [30 * DAY_S]),
]
sanction_accrual_cases = [
    {"label": label, "findings": findings, "l3_met_times_s": met, "l3_clear_times_s": clear,
     "accrual_times_s": l4_accrual_times(findings, met, clear)}
    for label, findings, met, clear in sanction_accrual_scenarios
]
sanction_void_scenarios = [
    ("no-notice-never-voids", None, None, None),
    ("nothing-by-t-voids-at-t", 0, None, None),
    ("valid-unappealed-discharges", 0, None, ["unappealed", 15 * DAY_S]),
    ("early-unappealed-is-absent", 0, None, ["unappealed", 13 * DAY_S]),
    ("appeal-without-ruling-voids-at-deadline", 0, 10 * DAY_S, None),
    ("upheld-in-time-keeps-state", 0, 10 * DAY_S, ["upheld", 20 * DAY_S]),
    ("late-ruling-does-not-cure", 0, 10 * DAY_S, ["upheld", 45 * DAY_S]),
    ("overturned-voids-when-sealed", 0, 10 * DAY_S, ["overturned", 20 * DAY_S]),
    ("appeal-after-t-does-not-discharge", 0, (14 + 7 + 1) * DAY_S, None),
]
sanction_void_cases = [
    {"label": label, "notice_sealed_at_s": notice, "appeal_sealed_at_s": appeal,
     "ruling": ruling,
     "void_at_s": state_void_at(notice, appeal,
                                None if ruling is None else (ruling[0], ruling[1]))}
    for label, notice, appeal, ruling in sanction_void_scenarios
]
sanction_in_force_scenarios = [
    ("never-met", [], [], 100),
    ("met-uncleared", [50], [], 100),
    ("cleared", [50], [60], 100),
    ("re-met-after-clear", [50, 70], [60], 100),
    ("met-in-the-future", [150], [], 100),
    ("clear-at-the-met-instant", [50], [50], 100),
]
sanction_in_force_cases = [
    {"label": label, "met_times_s": met, "clear_times_s": clear, "n_s": n,
     "in_force": in_force(met, clear, n)}
    for label, met, clear, n in sanction_in_force_scenarios
]

write_json(WIST4 / "sanctions.json", spaced_labels({
    "note": "WIST-4 §7 ladder state derivation: escalation criteria, accrual, void instants and rungs in force at N.",
    "escalation": {"l2": {"count": 3, "days": 90},
                   "l3_count": {"count": 10, "days": 90},
                   "l3_severity": 3,
                   "l4_sev3": {"count": 3, "days": 180}},
    "appeal_window_days": APPEAL_WINDOW_DAYS,
    "appeal_seal_days": APPEAL_SEAL_DAYS,
    "ruling_deadline_days": RULING_DEADLINE_DAYS,
    "criterion_cases": sanction_criterion_cases,
    "accrual_cases": sanction_accrual_cases,
    "void_cases": sanction_void_cases,
    "in_force_cases": sanction_in_force_cases,
}))

# ------------------------------------- WIST-4 §5: the reference Delta
# A Record names `reference_delta`: the newest Delta of the audited Delta's
# per-URL chain sealed at or before `fetched_at`. The Reference Payload is
# the anchor as of that Delta, the change type read for the `delete` mirror
# and the link dimension is that Delta's, and §3 rejects a reference outside
# the chain, before the audited Delta, or sealed after `fetched_at`. The
# expectations below are computed from the chain and asserted against a
# hand-written table so the generator cannot drift from the prose silently.
REF_CHAIN = [
    {"id": "d1", "height": 1, "sealed_at_s": 0,      "change": "update", "payload": "P1"},
    {"id": "d2", "height": 3, "sealed_at_s": 7_200,  "change": "update", "payload": "P2"},
    {"id": "d3", "height": 5, "sealed_at_s": 14_400, "change": "attest", "payload": None},
    {"id": "d3b", "height": 5, "sealed_at_s": 14_400, "change": "attest", "payload": None},
    {"id": "d4", "height": 7, "sealed_at_s": 21_600, "change": "delete", "payload": None},
    {"id": "d5", "height": 9, "sealed_at_s": 28_800, "change": "new",    "payload": "P3"},
]
REF_OTHER_CHAIN = [
    {"id": "x1", "height": 2, "sealed_at_s": 3_600, "change": "update", "payload": "PX"},
]
CONTENT_BEARING = {"new", "update"}


def ref_index(chain, delta_id):
    for i, d in enumerate(chain):
        if d["id"] == delta_id:
            return i
    return None


def newest_at_or_before(chain, fetched_at_s):
    """WIST-4 §5: the newest chain Delta whose Block sealed_at ≤ fetched_at."""
    tip = None
    for d in chain:
        if d["sealed_at_s"] <= fetched_at_s:
            tip = d["id"]
    return tip


def resolve_anchor(chain, delta_id):
    """WIST-3 §6.1: the last content-bearing Delta at or before delta_id."""
    for d in reversed(chain[: ref_index(chain, delta_id) + 1]):
        if d["change"] in CONTENT_BEARING:
            return d["payload"]
    return None


def reference_valid(chain, audited, reference, fetched_at_s):
    """WIST-4 §3: the three recomputable rejections, in the order §3 lists them."""
    ri, ai = ref_index(chain, reference), ref_index(chain, audited)
    if ri is None:
        return "WIST4-E02"
    if ri < ai:
        return "WIST4-E02"
    if chain[ri]["sealed_at_s"] > fetched_at_s:
        return "WIST4-E02"
    return True


def effective_similarity(similarity, change):
    return MICRO - similarity if change == "delete" else similarity


def verdict_from_effective(effective):
    if effective >= SIMILARITY_CONSISTENT:
        return "consistent"
    if effective >= INCONSISTENT_EFFECTIVE_BELOW:
        return "dynamic_variance"
    return "inconsistent"


SIMILARITY_CONSISTENT = 600_000


def reference_case(label, audited, fetched_at_s, reference, record_height,
                   record_sealed_at_s, similarity=None):
    assert record_sealed_at_s >= fetched_at_s, "a Record seals after its fetch"
    assert fetched_at_s >= REF_CHAIN[ref_index(REF_CHAIN, audited)]["sealed_at_s"], \
        "a fetch precedes its audited Block"
    valid = reference_valid(REF_CHAIN, audited, reference, fetched_at_s)
    case = {
        "label": label, "audited": audited, "fetched_at_s": fetched_at_s,
        "reference": reference, "record_height": record_height,
        "record_sealed_at_s": record_sealed_at_s, "valid": valid,
        "expected_reference": newest_at_or_before(REF_CHAIN, fetched_at_s),
        "resolved_payload": None, "reading_change": None,
    }
    if valid is True:
        change = REF_CHAIN[ref_index(REF_CHAIN, reference)]["change"]
        case["resolved_payload"] = resolve_anchor(REF_CHAIN, reference)
        case["reading_change"] = change
        if similarity is not None:
            eff = effective_similarity(similarity, change)
            verdict = verdict_from_effective(eff)
            case.update({"similarity": similarity, "effective_similarity": eff,
                         "verdict": verdict,
                         "counts_toward_c": verdict == "consistent" and change in CONTENT_BEARING})
    return case


reference_cases = [
    reference_case("tip-unchanged", "d1", 3_600, "d1", 2, 3_600, 950_000),
    reference_case("honest-rewrite", "d1", 10_800, "d2", 4, 10_800, 980_000),
    reference_case("stale-reference-not-decidable", "d1", 10_800, "d1", 4, 10_800, 20_000),
    reference_case("attest-after-rewrite", "d3", 18_000, "d3b", 6, 18_000, 900_000),
    reference_case("audited-attest-tip-delete", "d3", 25_200, "d4", 8, 25_200, 0),
    reference_case("delete-then-recreated", "d4", 32_400, "d5", 10, 32_400, 990_000),
    reference_case("reactive-truth-after-fetch", "d1", 3_600, "d2", 4, 10_800),
    reference_case("reference-before-audited", "d2", 10_800, "d1", 4, 10_800),
    reference_case("reference-from-another-chain", "d1", 10_800, "x1", 4, 10_800),
    reference_case("boundary-sealed-at-equals-fetched-at", "d1", 7_200, "d2", 4, 10_800, 980_000),
]

REFERENCE_EXPECTED = {
    "tip-unchanged":                        (True,        "d1",  "P1", "update", "consistent",   True),
    "honest-rewrite":                       (True,        "d2",  "P2", "update", "consistent",   True),
    "stale-reference-not-decidable":        (True,        "d2",  "P1", "update", "inconsistent", False),
    "attest-after-rewrite":                 (True,        "d3b", "P2", "attest", "consistent",   False),
    "audited-attest-tip-delete":            (True,        "d4",  "P2", "delete", "consistent",   False),
    "delete-then-recreated":                (True,        "d5",  "P3", "new",    "consistent",   True),
    "reactive-truth-after-fetch":           ("WIST4-E02", "d1",  None, None,     None,           None),
    "reference-before-audited":             ("WIST4-E02", "d2",  None, None,     None,           None),
    "reference-from-another-chain":         ("WIST4-E02", "d2",  None, None,     None,           None),
    "boundary-sealed-at-equals-fetched-at": (True,        "d2",  "P2", "update", "consistent",   True),
}
for c in reference_cases:
    exp = REFERENCE_EXPECTED[c["label"]]
    got = (c["valid"], c["expected_reference"], c["resolved_payload"],
           c["reading_change"], c.get("verdict"), c.get("counts_toward_c"))
    assert got == exp, f"reference vector drifted: {c['label']}: {got} != {exp}"
assert {c["valid"] for c in reference_cases} == {True, "WIST4-E02"}

write_json(WIST4 / "superseded-audit.json", {
    "note": "WIST-4 §5 reference_delta and what is read as of it (WIST-3 §6.1), plus the WIST4-E02 rejections over it. expected_reference is what an honest Auditor names.",
    "similarity_consistent": SIMILARITY_CONSISTENT,
    "similarity_variance_floor": INCONSISTENT_EFFECTIVE_BELOW,
    "chain": REF_CHAIN,
    "other_chain": REF_OTHER_CHAIN,
    "cases": reference_cases,
})
print("wist4 reference-delta vector: %d cases" % len(reference_cases))

print("wist4 replay-derivation vectors: confirmation=%d derivation=%d coverage=%d+%d+%d extension=%d+%d+%d+%d sanctions=%d+%d+%d+%d cases" % (
    len(confirmation_cases), len(derivation_scenarios),
    len(coverage_pair_cases), len(coverage_counting_cases), len(coverage_state_cases),
    len(extension_trigger_cases), len(extension_ration_cases),
    len(extension_summons_cases), len(divergence_cases),
    len(sanction_criterion_cases), len(sanction_accrual_cases),
    len(sanction_void_cases), len(sanction_in_force_cases)))
