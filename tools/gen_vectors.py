#!/usr/bin/env python3
"""Generate deterministic WIST-1/WIST-3 test vectors and signed examples.

Never uses wall-clock or randomness: fixed seed, fixed timestamps.
Re-running always produces byte-identical output.
"""
import base64, calendar, datetime, hashlib, hmac, itertools, json, pathlib, re, time
from decimal import Decimal, localcontext
from fractions import Fraction

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ed25519_curve
import link_extraction
from merkle import audit_path, consistency_proof, leaf_hash, node_hash
from merkle import merkle_root as merkle_tree_root
from merkle import entry_bundle_bytes, tile_bytes, tile_hashes, tile_path

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

def kid_of_x(x: str) -> str:
    """WIST-1 §5.1: the RFC 7638 thumbprint of an Ed25519 OKP JWK, computed over
    the entry's `x` string as written."""
    return b64u(hashlib.sha256(rfc8785.dumps({"crv": "Ed25519", "kty": "OKP", "x": x})).digest())

def kid_of(raw: bytes) -> str:
    return kid_of_x(b64u(raw))

def nbf_at(instant: str) -> int:
    """A whole-second UTC instant as the NumericDate integer WIST-1 §5.1 uses."""
    return calendar.timegm(time.strptime(instant, "%Y-%m-%dT%H:%M:%SZ"))

def jwk_x(x: str, nbf, exp=None) -> dict:
    entry = {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid_of_x(x),
             "nbf": nbf_at(nbf) if isinstance(nbf, str) else nbf}
    if exp is not None:
        entry["exp"] = nbf_at(exp) if isinstance(exp, str) else exp
    return entry

def jwk(raw: bytes, nbf, exp=None) -> dict:
    return jwk_x(b64u(raw), nbf, exp)

KID1 = kid_of(pub_raw)

def write_json(path: pathlib.Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n")

def spaced_labels(node):
    """Labels are prose, not identifiers: spaces keep them outside the token
    shapes the repo-wide digest sweep in validate_examples.py flags."""
    if isinstance(node, dict):
        return {k: (v.replace("-", " ") if k == "label" and isinstance(v, str)
                    else spaced_labels(v)) for k, v in node.items()}
    if isinstance(node, list):
        return [spaced_labels(v) for v in node]
    return node


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
# a page rather than asserted, and the vector and the example agree by
# construction.
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
    "publisher": "example.com",
    "url": DELTA_URL,
    "change_type": "new",
    "observed_at": "2026-08-02T12:00:00Z",
    "payload": {"commitment": commitment, "alg": "HMAC-SHA256",
                "bytes": len(content_canonical)},
    "meta": {"lang": "en", "topics": ["software"], "license": "CC-BY-4.0"},
}

delta_canonical = rfc8785.dumps(delta)
delta_id = "sha256:" + sha256_hex(delta_canonical)
delta_envelope = sign_envelope("delta", delta, KID1)

write_json(WIST1 / "keypair.json",
           {"seed_hex": SEED.hex(), "public_key": b64u(pub_raw), "kid": KID1,
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
SEED5 = bytes(range(128, 160))  # TEST ONLY — never use in production
priv2 = Ed25519PrivateKey.from_private_bytes(SEED2)
priv3 = Ed25519PrivateKey.from_private_bytes(SEED3)
priv4 = Ed25519PrivateKey.from_private_bytes(SEED4)
priv5 = Ed25519PrivateKey.from_private_bytes(SEED5)

def raw_public(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

pub2_raw, pub3_raw, pub4_raw = raw_public(priv2), raw_public(priv3), raw_public(priv4)
KID2, KID3, KID4 = kid_of(pub2_raw), kid_of(pub3_raw), kid_of(pub4_raw)
# The fifth keypair is listed by no Declaration: its thumbprint names an unknown signer.
KID5 = kid_of(raw_public(priv5))

def sign_envelope_with(key, inner_name: str, inner: dict, key_id: str) -> dict:
    return {inner_name: inner,
            "sig": {"key_id": key_id, "alg": "Ed25519",
                    "value": b64u(key.sign(rfc8785.dumps(inner)))}}

# ---------------------------------------------------- WIST-3 §5: Checkpoints
EMPTY_ROOT = hashlib.sha256(b"").digest()

def note_key_id(name: str, raw_pub: bytes) -> bytes:
    """WIST-3 §3.4: the [signed-note] note key ID for an Aggregator key."""
    return hashlib.sha256(name.encode() + b"\x0a\x01" + raw_pub).digest()[:4]

def checkpoint_note(log_id: str, key, tree_size: int, root: bytes,
                    epoch_number: int, sealed_at: str) -> str:
    """WIST-3 §5: a signed Checkpoint note — the five-line text, a blank
    line, then the Log's signature line under `key` (signer name `log_id`,
    as §3.4 requires of every Aggregator key)."""
    text = "%s\n%d\n%s\nepoch_number %d\nsealed_at %s\n" % (
        log_id, tree_size, base64.b64encode(root).decode(), epoch_number, sealed_at)
    kid = note_key_id(log_id, raw_public(key))
    sig = key.sign(text.encode())
    return text + "\n— %s %s\n" % (log_id, base64.b64encode(kid + sig).decode())

def note_field(text: str, name: str):
    """Read one field back out of a Checkpoint note this generator just
    signed (a convenience for building `expected` fixtures — never used to
    validate an untrusted note; see tools/validate_examples.py for that)."""
    lines = text.split("\n\n", 1)[0].split("\n")
    return {"origin": lines[0], "tree_size": int(lines[1]), "root": base64.b64decode(lines[2]),
            "epoch_number": int(lines[3].split(" ", 1)[1]),
            "sealed_at": lines[4].split(" ", 1)[1]}[name]

def note_text_only(checkpoint_text: str) -> str:
    """The bare five-line note text a signed Checkpoint carries (WIST-3 §5),
    with the blank line and every signature line stripped — what a Witness
    cosignature signs (see `cosignature_line`)."""
    return checkpoint_text.split("\n\n", 1)[0] + "\n"

def with_signature_lines(checkpoint_text: str, *lines: str) -> str:
    """Append extra newline-terminated `— name base64` signature lines to a
    signed Checkpoint note (WIST-3 §5 / [signed-note]: any number of
    signature lines, no blank line between them)."""
    return checkpoint_text + "".join(lines)

def witness_key_id(name: str, raw_pub: bytes) -> bytes:
    """[tlog-cosignature]'s note key ID for a Witness key: the [signed-note]
    formula (WIST-3 §3.4) with type byte 0x04, not the Aggregator's 0x01."""
    return hashlib.sha256(name.encode() + b"\x0a\x04" + raw_pub).digest()[:4]

def cosignature_line(name: str, key, checkpoint_text: str, timestamp: int) -> str:
    """[tlog-cosignature] cosignature/v1: one Witness's signature line over
    a Checkpoint's bare note text — the `cosignature/v1\\ntime <T>\\n`
    preamble plus all five lines, no signature block (WIST-3 §5: a
    Cosignature attests only that the Aggregator's tree is the one the
    Witness saw, nothing about the extension lines it does not repeat)."""
    kid = witness_key_id(name, raw_public(key))
    message = "cosignature/v1\ntime %d\n%s" % (timestamp, note_text_only(checkpoint_text))
    sig = key.sign(message.encode())
    payload = kid + timestamp.to_bytes(8, "big") + sig
    return "— %s %s\n" % (name, base64.b64encode(payload).decode())

def root_token(leaves: list) -> str:
    """WIST-3 §3.1: an Epoch's root hash where this suite carries it in a
    JSON member (`root_hash`, `final_root_hash`) — `"sha256:" +
    hex(root)` — reused here for `pinned_head`-style fixture pins, since a
    Epoch has no hash apart from its root."""
    root = merkle_tree_root(leaves) if leaves else EMPTY_ROOT
    return "sha256:" + root.hex()

def seal(log_id: str, key, leaves: list, entries: list, epoch_number: int,
        sealed_at: str) -> tuple:
    """WIST-3 §§3-5: extend the cumulative Log tree `leaves` (leaf hashes of
    every Entry sealed so far) with one Epoch's `entries` and seal it.
    Returns (epoch, new_leaves), where `epoch` is `{"checkpoint": ...,
    "entries": entries}`."""
    new_leaves = leaves + [leaf_hash(rfc8785.dumps(e)) for e in entries]
    root = merkle_tree_root(new_leaves) if new_leaves else EMPTY_ROOT
    note = checkpoint_note(log_id, key, len(new_leaves), root, epoch_number, sealed_at)
    return {"checkpoint": note, "entries": entries}, new_leaves

def prefix_leaves(history: list) -> list:
    """The cumulative Log tree's leaf hashes through a `epochs` prefix loaded
    back from a previously written vector (WIST-3 §3.1: an Epoch is just the
    Entries between two Checkpoints, replayed here in Entry order)."""
    return [leaf_hash(rfc8785.dumps(e)) for blk in history for e in blk["entries"]]

# ------------------------------------------------------------ WIST-1: publisher
publisher = {
    "wist_version": "1.0.0",
    "seq": 0,
    "domain": "example.com",
    "subdomain_scope": ["www.example.com", "blog.example.com"],
    "keys": [jwk(pub_raw, "2026-08-02T12:00:00Z")],
    # A distinct keypair, as WIST-1 §5.2 requires: the two sets share no
    # public key, because a recovery key that is also a signing key is not
    # held offline and is stolen with the key it duplicates.
    "recovery_keys": [jwk(pub2_raw, "2026-08-02T12:00:00Z")],
    "contact": "mailto:webmaster@example.com",
}
write_json(EXAMPLES / "publisher.json", sign_envelope("publisher", publisher, KID1))
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

K2 = jwk(pub3_raw, "2026-08-03T12:00:00Z")
R2 = jwk(pub4_raw, "2026-08-03T12:00:00Z")

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
fresh_identity_dropping_recovery = variant(seq=1, prev_declaration=stored_hash, keys=[K2])
del fresh_identity_dropping_recovery["recovery_keys"]
overlapping_sets = variant(
    seq=1, prev_declaration=stored_hash,
    recovery_keys=[jwk(pub_raw, "2026-08-02T12:00:00Z")])

declaration_cases = [
    {"name": "identical re-serve",
     "stored": sign_envelope("publisher", stored_decl, KID1),
     "fetched": sign_envelope("publisher", stored_decl, KID1),
     "expected": "idempotent",
     "why": "§5.2: the fetched publisher object is byte-identical to the "
            "accepted one, so the re-poll §5.1's 24-hour cache TTL obliges is "
            "an idempotent acceptance, not WIST1-E08."},
    {"name": "same seq, different bytes",
     "stored": sign_envelope("publisher", stored_decl, KID1),
     "fetched": sign_envelope("publisher", mutated_same_seq, KID1),
     "expected": "WIST1-E08",
     "why": "§5.2: seq is not greater than the highest accepted and the object "
            "differs — the superseded-replay case the rule catches."},
    {"name": "stale lower seq",
     "stored": sign_envelope("publisher", rotated, KID1),
     "fetched": sign_envelope("publisher", stored_decl, KID1),
     "expected": "WIST1-E08",
     "why": "§5.2: seq 0 below the accepted seq 1."},
    {"name": "missing prev_declaration",
     "stored": sign_envelope("publisher", stored_decl, KID1),
     "fetched": sign_envelope("publisher", missing_prev, KID1),
     "expected": "WIST1-E08",
     "why": "§5.2: seq > 0 with prev_declaration absent."},
    {"name": "mismatched prev_declaration",
     "stored": sign_envelope("publisher", stored_decl, KID1),
     "fetched": sign_envelope("publisher", wrong_prev, KID1),
     "expected": "WIST1-E08",
     "why": "§5.2: prev_declaration does not equal the hash of the previously "
            "accepted Declaration's publisher object."},
    {"name": "ordinary rotation",
     "stored": sign_envelope("publisher", stored_decl, KID1),
     "fetched": sign_envelope("publisher", rotated, KID1),
     "expected": "ordinary_rotation",
     "why": "§5.2: higher seq, correct prev_declaration, signed by a key of "
            "the previous Key Set; recovery_keys carried byte-identical."},
    {"name": "recovery rotation",
     "stored": sign_envelope("publisher", stored_decl, KID1),
     "fetched": sign_envelope_with(priv2, "publisher", recovery_rotated, KID2),
     "expected": "recovery_rotation",
     "why": "§5.2: signed by a key in the previous Declaration's "
            "recovery_keys, which is what lets it replace them."},
    {"name": "recovery keys altered by a signing key",
     "stored": sign_envelope("publisher", stored_decl, KID1),
     "fetched": sign_envelope("publisher", recovery_dropped_by_signing_key, KID1),
     "expected": "WIST1-E08",
     "why": "§5.2: recovery keys protect themselves — a Declaration altering "
            "them MUST be signed by one of the recovery keys it replaces."},
    {"name": "fresh identity",
     "stored": sign_envelope("publisher", stored_decl, KID1),
     "fetched": sign_envelope_with(priv3, "publisher", fresh_identity, KID3),
     "expected": "fresh_identity",
     "why": "§5.2: signed by neither the previous signing keys nor the "
            "previous recovery_keys, which it carries byte-identical — "
            "accepted as a fresh identity whose history starts here (WIST-3 §7)."},
    {"name": "fresh identity inside an open recovery window",
     "stored": sign_envelope("publisher", stored_decl, KID1),
     "fetched": sign_envelope_with(priv3, "publisher", fresh_identity, KID3),
     "recovery_window_open": True,
     "expected": "fresh_identity",
     "why": "§5.2: an open window changes nothing about acceptance — the "
            "Declaration is sealed and superseded at the window's end, "
            "because rejecting it at ingest would leave a thief's attempt "
            "invisible to a party replaying the Log."},
    {"name": "fresh identity dropping the recovery keys",
     "stored": sign_envelope("publisher", stored_decl, KID1),
     "fetched": sign_envelope_with(priv3, "publisher", fresh_identity_dropping_recovery, KID3),
     "expected": "WIST1-E08",
     "why": "§5.2: recovery keys protect themselves against every Declaration "
            "not signed by one of them — a fresh identity included, or a "
            "party holding only the web server could shed them and sever "
            "the owner's path back."},
    {"name": "key named in both key sets",
     "stored": sign_envelope("publisher", stored_decl, KID1),
     "fetched": sign_envelope("publisher", overlapping_sets, KID1),
     "expected": "WIST1-E08",
     "why": "§5.2: the same public key in keys and recovery_keys. A recovery "
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
             "`recovery_rotation`, `fresh_identity` (accepted; resets only outside an open recovery window), "
             "or the error code the evaluation rejects with."),
    "recovery_window_open": False,
    "cases": declaration_cases,
})
print("wist1 declaration-sequence vector written")


def binding_case(name, incoming, signer, key_id, expected, stored=stored_decl):
    return {"name": name,
            "stored": sign_envelope("publisher", stored, KID1) if stored else None,
            "fetched": sign_envelope_with(signer, "publisher", incoming, key_id),
            "expected": expected}

binding_cases = []
for array, original in (("keys", stored_decl["keys"][0]),
                        ("recovery_keys", stored_decl["recovery_keys"][0])):
    for duplicate in (dict(original), dict(original, nbf=original["nbf"] + 3600)):
        for reverse in (False, True):
            entries = [original, duplicate]
            if reverse:
                entries.reverse()
            incoming = variant(seq=1, prev_declaration=stored_hash, **{array: entries})
            binding_cases.append(binding_case(
                f"duplicate {array} key {'reversed' if reverse else 'forward'} "
                f"{'identical' if duplicate == original else 'different window'}",
                incoming, priv, KID1, "WIST1-E08"))
            initial = variant(**{array: entries})
            binding_cases.append(binding_case(
                f"initial duplicate {array} {'reversed' if reverse else 'forward'} "
                f"{'identical' if duplicate == original else 'different window'}",
                initial, priv, KID1, "WIST1-E08", stored=None))

mismatched = variant(seq=1, prev_declaration=stored_hash, keys=[dict(K2, kid=KID1)])
binding_cases.extend([
    binding_case("ordinary rotation to a new key", rotated, priv, KID1, "ordinary_rotation"),
    binding_case("recovery rotation", recovery_rotated, priv2, KID2, "recovery_rotation"),
    binding_case("fresh identity under the incoming key", rotated, priv3, KID3, "fresh_identity"),
    binding_case("fresh identity cannot alter recovery", dict(rotated, recovery_keys=[R2]),
                 priv3, KID3, "WIST1-E08"),
    binding_case("kid not the thumbprint of x", mismatched, priv3, KID1, "WIST1-E14"),
    binding_case("kid mismatch precedes recovery protection", dict(mismatched, recovery_keys=[R2]),
                 priv3, KID1, "WIST1-E14"),
    binding_case("initial kid not the thumbprint of x", variant(keys=[dict(stored_decl["keys"][0], kid=KID3)]),
                 priv, KID3, "WIST1-E14", stored=None),
    binding_case("expiry not after start", variant(seq=1, prev_declaration=stored_hash,
                 keys=[dict(K2, exp=K2["nbf"])]), priv, KID1, "WIST1-E14"),
    binding_case("unrelated signature under known identifier", rotated, priv4, KID3, "WIST1-E01"),
    binding_case("unknown signer identifier", rotated, priv3, KID5, "WIST1-E02"),
    binding_case("incoming recovery key cannot self authorize", recovery_rotated,
                 priv4, KID4, "WIST1-E02"),
    binding_case("initial self signature", stored_decl, priv, KID1, "initial", stored=None),
    binding_case("initial signature names second signing key",
                 variant(keys=[K2, stored_decl["keys"][0]]), priv, KID1, "initial", stored=None),
])
write_json(WIST1 / "declaration-binding.json", {
    "note": "WIST-1 sections 5.1 and 5.2: check each entry's kid against its thumbprint and its "
            "window, authenticate sig.key_id against previous signing/recovery and incoming signing "
            "entries, and classify the verified public key by previous set membership. "
            "A null stored value tests the initial self-signed Declaration. A public key listed twice "
            "is WIST1-E08; a kid that is not its entry's thumbprint is WIST1-E14.",
    "cases": binding_cases,
})

def recovery_order_entry(envelope):
    return {"type": "publisher_declaration", "body": envelope}


def recovery_order_leaf(envelope):
    return leaf_hash(rfc8785.dumps(recovery_order_entry(envelope)))


def recovery_order_case(name, reverse_leaves, split_epochs=False, ordinary_first=False):
    initial = sign_envelope("publisher", publisher, KID1)
    prefix = [initial]
    if ordinary_first:
        ordinary = variant(seq=1, prev_declaration=decl_hash(publisher),
                           contact="mailto:rotation@example.com")
        prefix.append(sign_envelope("publisher", ordinary, KID1))
    first_inner = variant(seq=len(prefix),
                          prev_declaration=decl_hash(prefix[-1]["publisher"]),
                          keys=[K2], recovery_keys=[R2])
    first = sign_envelope_with(priv2, "publisher", first_inner, KID2)
    for nonce in range(1000):
        second_inner = dict(first_inner, seq=first_inner["seq"] + 1,
                            prev_declaration=decl_hash(first_inner),
                            contact=f"mailto:recovery{nonce}@example.com")
        second = sign_envelope_with(priv4, "publisher", second_inner, KID4)
        if (recovery_order_leaf(second) < recovery_order_leaf(first)) == reverse_leaves:
            break
    else:
        raise AssertionError("no discriminating recovery leaf order")
    batches = [[initial], prefix[1:] + [first, second]]
    if split_epochs:
        batches = [[initial], [first], [second]]
    epochs, tree_leaves = [], []
    for height, batch in enumerate(batches):
        entries = sorted(map(recovery_order_entry, batch),
                         key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
        epoch, tree_leaves = seal("test-log-k1", priv, tree_leaves, entries, height,
                                  f"2026-08-04T{height:02d}:00:00Z")
        epochs.append(epoch)
    return {"name": name, "epochs": epochs, "pinned_head": root_token(tree_leaves),
            "expected": {"application_sequences": list(range(len(prefix) + 2)),
                         "owner_sequence": first_inner["seq"], "owner_height": 1,
                         "owner_declaration": decl_hash(first_inner),
                         "opened_at": note_field(epochs[1]["checkpoint"], "sealed_at"),
                         "windows_opened": 1},
            "recovery_leaves_reversed": reverse_leaves}


write_json(WIST1 / "recovery-order.json", {
    "note": "WIST-1 section 5.2 and WIST-3 section 3.3 recovery ownership over "
            "valid serial Declaration histories. The supplied Log key and pinned head "
            "are trusted fixture inputs. All queries are at the final Epoch, strictly "
            "inside the default seven-day recovery window; no settlement, conflicting "
            "candidate disposition or identity-reset result is asserted. The second "
            "recovery is signed by the recovery key installed by the first.",
    "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
    "recovery_window_days": 7,
    "declaration_activation_epochs": 0,
    "cases": [
        recovery_order_case("same Epoch reversed recovery leaves", True),
        recovery_order_case("same Epoch ascending recovery leaves", False),
        recovery_order_case("later Epoch does not reopen recovery", True, split_epochs=True),
        recovery_order_case("ordinary predecessor before two recoveries", True, ordinary_first=True),
    ],
})

def recovery_settlement_vectors():
    extra = {name: Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        ("wist settlement " + name).encode()).digest()) for name in ("third", "fourth", "alien")}
    key_entries = {name: jwk(raw_public(key), "2026-08-03T12:00:00Z")
                   for name, key in extra.items()}
    kids = {name: entry["kid"] for name, entry in key_entries.items()}
    initial = sign_envelope("publisher", publisher, KID1)

    def signed(previous, seq, signer, key_id, **changes):
        inner = dict(previous["publisher"], seq=seq,
                     prev_declaration=decl_hash(previous["publisher"]), **changes)
        return sign_envelope_with(signer, "publisher", inner, key_id)

    owner = signed(initial, 1, priv2, KID2, keys=[K2], recovery_keys=[R2])
    fresh = signed(owner, 2, priv, KID1, keys=publisher["keys"])
    descendant = signed(fresh, 3, priv, KID1, keys=[key_entries["third"]])
    alien = signed(owner, 2, extra["alien"], kids["alien"], keys=[key_entries["alien"]])
    ordinary = signed(owner, 2, priv3, KID3, keys=[key_entries["third"]])
    second = signed(owner, 2, priv4, KID4, keys=[key_entries["fourth"]],
                    recovery_keys=publisher["recovery_keys"])
    after_second = signed(second, 3, priv, KID1, keys=publisher["keys"])
    shared = signed(owner, 2, priv, KID1, keys=publisher["keys"] + [K2])
    wrong_branch = signed(shared, 3, priv3, KID3, keys=[key_entries["third"]])
    right_branch = signed(owner, 3, priv3, KID3, keys=[key_entries["third"]])
    scenarios = [
        ("no competitor", [], owner, []),
        ("fresh competitor and ordinary descendant", [fresh, descendant], owner, [fresh, descendant]),
        ("unrelated fresh identity", [alien], owner, [alien]),
        ("ordinary recovery chain follower", [ordinary], ordinary, []),
        ("recovery follower and fresh competitor", [second, after_second], second, [after_second]),
        ("shared signing key names competitor", [shared, wrong_branch], owner, [shared, wrong_branch]),
        ("shared signing key names recovery head", [shared, right_branch], right_branch, [shared]),
    ]
    start = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc)
    def timestamp(hour):
        return (start + datetime.timedelta(hours=hour)).strftime("%Y-%m-%dT%H:%M:%SZ")
    def projection(env):
        inner = env["publisher"]
        return {"label": decl_hash(inner), "predecessor": inner.get("prev_declaration"),
                "signer": env["sig"]["key_id"],
                "keys": [key["kid"] for key in inner["keys"]],
                "recovery_keys": [key["kid"] for key in inner.get("recovery_keys", [])],
                "envelope": env}
    cases = []
    for name, window, effective, superseded in scenarios:
        events = [initial, owner] + window
        epochs, tree_leaves = [], []
        for height in range(170):
            entries = [recovery_order_entry(events[height])] if height < len(events) else []
            epoch, tree_leaves = seal("test-log-k1", priv, tree_leaves, entries, height,
                                      timestamp(height))
            epochs.append(epoch)
        served = []
        for index, (signer, key_id) in enumerate([
                (priv, KID1), (priv3, KID3),
                (extra["third"], kids["third"]), (extra["fourth"], kids["fourth"]),
                (extra["alien"], kids["alien"]), (priv3, KID3)]):
            inner = dict(delta, url=f"https://example.com/settlement/{index}",
                         observed_at=timestamp(10))
            env = sign_envelope_with(signer, "delta", inner, key_id)
            served.append({"delta_id": decl_hash(inner), "signer": key_id, "envelope": env})
        queued = [d for d in served if d["signer"] in {KID1, KID3}]
        effective_ids = [key["kid"] for key in effective["publisher"]["keys"]]
        probes = []
        for height, env in enumerate(events[2:], 2):
            predecessor = next(e for e in events[:height]
                               if decl_hash(e["publisher"]) == env["publisher"]["prev_declaration"])
            altered = publisher["recovery_keys"] if predecessor["publisher"]["recovery_keys"] == [R2] else [R2]
            signer_id = env["sig"]["key_id"]
            if signer_id in [key["kid"] for key in predecessor["publisher"]["recovery_keys"]]:
                continue
            signer = {KID1: priv, KID3: priv3, kids["alien"]: extra["alien"]}[signer_id]
            twin = signed(predecessor, env["publisher"]["seq"], signer, signer_id,
                          keys=env["publisher"]["keys"], recovery_keys=altered)
            probes.append({"name": "unauthorized recovery set replacement",
                           "prefix_height": height - 1, "candidate": twin,
                           "expected_result": "WIST1-E08"})
        stale = signed(initial, len(events), priv, KID1)
        probes.append({"name": "pre recovery predecessor cannot return",
                       "prefix_height": len(events) - 1, "candidate": stale,
                       "expected_result": "WIST1-E08"})
        bad = json.loads(json.dumps(owner))
        raw = bytearray(base64.urlsafe_b64decode(bad["sig"]["value"] + "=="))
        raw[0] ^= 1
        bad["sig"]["value"] = b64u(raw)
        probes.append({"name": "invalid Declaration author signature",
                       "prefix_height": 0, "candidate": bad, "expected_result": "WIST1-E01"})
        cases.append({"name": name, "epochs": epochs, "pinned_head": root_token(tree_leaves),
                      "initial_declaration": projection(initial),
                      "pre_recovery_keys": [KID1], "recovery_declaration": projection(owner),
                      "window_declarations": [projection(env) for env in window], "served": served,
                      "probes": probes,
                      "expected": {"queued": [d["delta_id"] for d in queued],
                                   "not_queued": [d["delta_id"] for d in served if d not in queued],
                                   "effective_keys": effective_ids,
                                   "effective_declaration": decl_hash(effective["publisher"]),
                                   "superseded": [decl_hash(env["publisher"]) for env in superseded],
                                   "eligible": [d["delta_id"] for d in queued if d["signer"] in effective_ids],
                                   "rejected": [d["delta_id"] for d in queued if d["signer"] not in effective_ids]}})
    binding_cases = []
    sample = dict(delta, observed_at=timestamp(10), url="https://example.com/settlement/bindings")
    old_delta = sign_envelope_with(priv, "delta", sample, KID1)
    new_delta = sign_envelope_with(priv3, "delta", sample, KID3)
    bad_delta = json.loads(json.dumps(new_delta))
    bad_delta["sig"]["value"] = old_delta["sig"]["value"]
    full_scope = {"domain": publisher["domain"], "subdomain_scope": publisher["subdomain_scope"]}
    bare_scope = {"domain": publisher["domain"], "subdomain_scope": []}

    def binding(name, before, opening, final, env, queued, eligible,
                scopes=(full_scope, full_scope, full_scope)):
        binding_cases.append({"name": name, "pre_recovery_keys": before,
                              "recovery_keys": opening, "settlement_keys": final,
                              "pre_recovery_scope": scopes[0], "recovery_scope": scopes[1],
                              "settlement_scope": scopes[2],
                              "envelope": env, "delta_id": decl_hash(env["delta"]),
                              "expected_queued": queued, "expected_eligible": eligible})
    binding("old binding queues but fails settlement", publisher["keys"], [K2],
            [K2], old_delta, True, False)
    binding("settlement start excludes previously queued Delta", publisher["keys"], [K2],
            [dict(K2, nbf=nbf_at(timestamp(11)))], new_delta, True, False)
    binding("settlement expiry excludes previously queued Delta", publisher["keys"], [K2],
            [dict(K2, exp=nbf_at(timestamp(10)))], new_delta, True, False)
    binding("start equality is eligible", publisher["keys"], [dict(K2, nbf=nbf_at(timestamp(10)))],
            [dict(K2, nbf=nbf_at(timestamp(10)))], new_delta, True, True)
    binding("expiry after the observation is eligible", publisher["keys"],
            [dict(K2, exp=nbf_at(timestamp(11)))], [dict(K2, exp=nbf_at(timestamp(11)))],
            new_delta, True, True)
    binding("future start prevents queue admission", publisher["keys"], [dict(K2, nbf=nbf_at(timestamp(11)))],
            [K2], new_delta, False, False)
    binding("expired admission entry prevents queue admission", publisher["keys"],
            [dict(K2, exp=nbf_at(timestamp(10)))], [K2], new_delta, False, False)
    binding("known identifier with invalid signature is not queued", publisher["keys"], [K2],
            [K2], bad_delta, False, False)
    binding("unknown identifier is not queued", publisher["keys"], [K2], [K2],
            sign_envelope_with(priv3, "delta", sample, KID5), False, False)
    binding("later re serve of rejected Delta ID under a restored key", publisher["keys"], [K2],
            publisher["keys"], old_delta, True, True)
    binding_cases[-1]["re_serve_of"] = 0
    scoped = dict(delta, observed_at=timestamp(10), url="https://blog.example.com/settlement/bindings")
    scoped_delta = sign_envelope_with(priv3, "delta", scoped, KID3)
    binding("scope withdrawn at settlement rejects a queued Delta", publisher["keys"], [K2], [K2],
            scoped_delta, True, False, (full_scope, full_scope, bare_scope))
    binding("scope granted only at settlement prevents queue admission", publisher["keys"], [K2], [K2],
            scoped_delta, False, False, (bare_scope, bare_scope, full_scope))
    write_json(WIST1 / "recovery-settlement.json", {
        "note": "WIST-1 section 5.2. Each case supplies 170 authenticated hourly Epochs, "
                "opening recovery at height 1 and settling at height 169. Declaration projections "
                "must match their signed Envelopes and Epoch Entries. Every key in each history "
                "has a fixed window; separate binding_cases vary the windows and the frozen "
                "admission and settlement scopes, each given as a domain and its subdomain_scope. "
                "Every timestamp probe uses whole-second literal-Z values; this family does not "
                "establish the broader RFC 3339 profile of observed_at. Signed served Deltas are "
                "distinct new URLs received in array order at hour 10; their shape and signature "
                "eligibility are exercised, not Payload availability, quotas or actual Epoch packing. "
                "expected.eligible denotes signature-eligible survivors in acceptance order, not proof "
                "of their eventual inclusion. Each probe independently replaces the next Epoch's "
                "Declaration as an unsealed candidate and must reject without changing its prefix. "
                "Snapshot recovery is not established by these histories.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "declaration_activation_epochs": 0,
        "cases": cases, "binding_cases": binding_cases})


recovery_settlement_vectors()

def recovery_binding_vectors():
    signers = {name: Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        ("wist recovery binding " + name).encode()).digest()) for name in ("a", "b", "c")}
    start = nbf_at("2026-08-04T10:00:00Z")
    instant = "2026-08-04T10:00:00.0000000001Z"
    equivalent = "2026-08-04t11:00:00.000000000100+01:00"
    excluded = b64u((1).to_bytes(32, "little"))
    kids = {name: kid_of(raw_public(key)) for name, key in signers.items()}

    def key(name, nbf=start, public=None, exp=None):
        return jwk_x(public or b64u(raw_public(signers[name])), nbf, exp)

    def eligible(entry, at=start):
        return entry["x"] != excluded and entry["nbf"] <= at and entry.get("exp", at + 1) > at

    # Each scenario lists the pre-recovery entry of signer a and the owner's
    # entry, which may belong to a or b. A probe's outcome follows WIST-1 §5.1
    # over both frozen sources: no eligible named binding is WIST1-E02, an
    # eligible binding with a failing signature is WIST1-E01.
    scenarios = [
        ("both eligible", key("a"), key("b")),
        ("old future", key("a", start + 1), key("b")),
        ("owner future", key("a"), key("b", start + 1)),
        ("both future", key("a", start + 1), key("b", start + 1)),
        ("old expired", key("a", start - 3600, exp=start), key("b")),
        ("owner expired", key("a"), key("b", start - 3600, exp=start)),
        ("same public old future", key("a", start + 1), key("a")),
        ("same public owner future", key("a"), key("a", start + 1)),
        ("same public owner expired", key("a"), key("a", start - 3600, exp=start)),
        ("old excluded", key("a", public=excluded), key("b")),
        ("owner excluded", key("a"), key("b", public=excluded)),
        ("both excluded", key("a", public=excluded), key("b", public=excluded)),
        ("excluded and future", key("a", public=excluded), key("b", start + 1)),
        ("future and excluded", key("a", start + 1), key("b", public=excluded)),
    ]
    histories, cases = {}, []
    for name, before, opening in scenarios:
        def outcome(signer, named, at=start):
            candidates = [entry for entry in (before, opening) if entry["kid"] == kids[named]]
            if not any(eligible(entry, at) for entry in candidates):
                return "WIST1-E02"
            return "accepted" if signer == named else "WIST1-E01"
        outcomes = (outcome("a", "a"), outcome("b", "b"))
        for reverse in (False, True):
            history_name = name + (" reversed arrays" if reverse else "")
            old_keys = publisher["keys"] + [before]
            new_keys = [K2, opening]
            if reverse:
                old_keys.reverse()
                new_keys.reverse()
            initial = sign_envelope("publisher", dict(publisher, keys=old_keys), KID1)
            owner = sign_envelope_with(priv2, "publisher", dict(publisher, seq=1,
                prev_declaration=decl_hash(initial["publisher"]), keys=new_keys,
                recovery_keys=[R2]), KID2)
            follower = sign_envelope_with(priv3, "publisher", dict(owner["publisher"], seq=2,
                prev_declaration=decl_hash(owner["publisher"]), keys=[key("c")]), KID3)
            epochs, tree_leaves = [], []
            for height, env in enumerate((initial, owner, follower)):
                epoch, tree_leaves = seal("test-log-k1", priv, tree_leaves,
                                          [recovery_order_entry(env)], height,
                                          f"2026-08-04T{height:02d}:00:00Z")
                epochs.append(epoch)
            histories[history_name] = {"epochs": epochs, "pinned_head": root_token(tree_leaves)}

            def add(label, signer, identifier, expected, observed_at=instant, damage=None):
                inner = dict(delta, url="https://example.com/recovery/bindings", observed_at=observed_at)
                env = sign_envelope_with(signer, "delta", inner, identifier)
                if damage == "signature":
                    env["sig"]["value"] = b64u(bytes(64))
                elif damage == "encoding":
                    env["sig"]["value"] += "="
                for height in (1, 2):
                    cases.append({"name": history_name + " " + label + f" at height {height}",
                                  "history": history_name, "prefix_height": height,
                                  "envelope": env, "expected": expected})

            for signer_name, result in zip(("a", "b"), outcomes):
                add("signature " + signer_name, signers[signer_name], kids[signer_name], result)
            add("forged signature under the first identifier", signers["b"], kids["a"], outcome("b", "a"))
            add("forged signature under the second identifier", signers["a"], kids["b"], outcome("a", "b"))
            add("invalid signature", signers["a"], kids["a"],
                "WIST1-E02" if outcomes[0] == "WIST1-E02" else "WIST1-E01", damage="signature")
            add("unknown identifier", signers["a"], KID5, "WIST1-E02")
            add("pre recovery only recovery key", priv2, KID2, "WIST1-E02")
            add("owner only recovery key", priv4, KID4, "WIST1-E02")
            add("follower only signing key", signers["c"], kids["c"], "WIST1-E02")
            add("retired owner signing key", priv3, KID3, "accepted")
            add("malformed signature before missing authority", signers["a"], KID5,
                "WIST1-E14", damage="encoding")
            add("leap label before missing authority", signers["a"], KID5, "WIST1-E14",
                observed_at="2016-12-31T23:59:60Z")
            add("fraction beyond nanoseconds", signers["a"], kids["a"], outcomes[0],
                observed_at="2026-08-04T10:00:00.00000000010000000000000000001Z")
            add("whole second start equality", signers["a"], kids["a"], outcomes[0],
                observed_at="2026-08-04T10:00:00Z")
            add("fraction before the start", signers["a"], kids["a"],
                outcome("a", "a", start - Fraction(1, 10 ** 30)),
                observed_at="2026-08-04T09:59:59.999999999999999999999999999999Z")
            add("offset equality", signers["b"], kids["b"], outcomes[1], observed_at=equivalent)
    write_json(WIST1 / "recovery-bindings.json", {
        "note": "WIST-1 sections 4, 5.1 and 5.2. Each history authenticates an initial Declaration, "
                "a recovery owner and an ordinary recovery-chain follower in three hourly Epochs. "
                "The supplied Log key and pinned head are trusted fixture inputs. Every independent Delta "
                "probe uses the prefix through prefix_height; the open window freezes the initial and "
                "owner signing bindings even after the follower. accepted denotes only successful Delta "
                "key verification, not queue mutation, complete Delta/chain eligibility, Payload availability, "
                "quotas, clock skew, actual sealing, settlement or Snapshot restoration. Timestamp probes "
                "exercise exact window ordering against integer nbf and exp values and field rejection; "
                "accepted probes supply no live clock. "
                "Reversed-array histories re-sign Declarations and rebuild authenticated hashes.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "declaration_activation_epochs": 0,
        "histories": histories, "cases": cases})


recovery_binding_vectors()

def recovery_heads_vectors():
    def signed(previous, seq, signer, key_id, **changes):
        inner = dict(previous["publisher"], seq=seq,
                     prev_declaration=decl_hash(previous["publisher"]), **changes)
        return sign_envelope_with(signer, "publisher", inner, key_id)

    initial = sign_envelope("publisher", publisher, KID1)
    owner = signed(initial, 1, priv2, KID2, keys=[K2], recovery_keys=[R2])
    fresh = signed(owner, 10, priv, KID1, keys=publisher["keys"])
    follower = signed(owner, 11, priv3, KID3, contact="mailto:owner@example.com")
    fresh_again = signed(follower, 20, priv, KID1, keys=publisher["keys"])
    recovered = signed(follower, 21, priv4, KID4, recovery_keys=publisher["recovery_keys"])
    competitor = signed(recovered, 30, priv, KID1, keys=publisher["keys"])
    after = signed(recovered, 31, priv3, KID3, contact="mailto:after@example.com")
    events = {0: initial, 1: owner, 2: fresh, 3: follower, 4: fresh_again,
              5: recovered, 6: competitor, 169: after}
    epochs, tree_leaves = [], []
    leaves_before = []
    start = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc)
    def timestamp(hour):
        return (start + datetime.timedelta(hours=hour)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for height in range(171):
        leaves_before.append(list(tree_leaves))
        entries = [recovery_order_entry(events[height])] if height in events else []
        epoch, tree_leaves = seal("test-log-k1", priv, tree_leaves, entries, height, timestamp(height))
        epochs.append(epoch)
    def state(current, head, floor, opened_at=1, windows=1):
        return {"current_declaration": decl_hash(current["publisher"]),
                "recovery_head": decl_hash(head["publisher"]) if head else None,
                "highest_accepted_seq": floor,
                "window_end": timestamp(opened_at + 168) if head else None,
                "windows_opened": windows}
    heights = {decl_hash(envelope["publisher"]): height for height, envelope in events.items()}

    def tuples(current, head, floor, opened_at=1):
        declaration = ["declaration", "example.com", current, heights[decl_hash(current["publisher"])], floor]
        window = None if head is None else [
            "recovery_window", "example.com", opened_at, timestamp(opened_at + 168), head,
            heights[decl_hash(head["publisher"])]]
        return {"declaration": declaration, "recovery_window": window}
    trace_args = [
        (0, (initial, None, 0, 1, 0)), (1, (owner, owner, 1, 1, 1)), (2, (fresh, owner, 10, 1, 1)),
        (3, (follower, follower, 11, 1, 1)), (4, (fresh_again, follower, 20, 1, 1)),
        (5, (recovered, recovered, 21, 1, 1)), (6, (competitor, recovered, 30, 1, 1)),
        (168, (competitor, recovered, 30, 1, 1)), (169, (after, None, 31, 1, 1)),
        (170, (after, None, 31, 1, 1)),
    ]
    traces = [(height, state(*args)) for height, args in trace_args]
    snapshot_tuples = [dict(height=height, **tuples(*args[:4])) for height, args in trace_args]
    probes = []
    def probe(name, prefix, hour, envelope, outcome, expected, branch=None):
        probes.append({"name": name, "prefix_height": prefix,
                       "candidate_sealed_at": timestamp(hour), "candidate": envelope,
                       "expected_result": outcome, "expected_state": expected})
        if branch is not None:
            probes[-1]["branch"] = branch
    probe("ordinary follower bypasses fresh competitor", 2, 3, follower,
          "ordinary_rotation", state(follower, follower, 11))
    via_fresh = signed(fresh, 11, priv3, KID3, keys=[K2])
    probe("same key naming competitor is fresh", 2, 3, via_fresh,
          "fresh_identity", state(via_fresh, owner, 11))
    for seq in (2, 10):
        candidate = signed(owner, seq, priv3, KID3)
        probe(f"sequence {seq} cannot ignore accepted competitor", 2, 3,
              candidate, "WIST1-E08", state(fresh, owner, 10))
    stale = signed(owner, 12, priv3, KID3)
    probe("old recovery ancestor cannot fork advanced chain", 3, 4, stale,
          "WIST1-E08", state(follower, follower, 11))
    probe("current Declaration is idempotent", 3, 4, follower,
          "idempotent", state(follower, follower, 11))
    sibling = signed(owner, 11, priv3, KID3, contact="mailto:sibling@example.com")
    probe("same predecessor is not identical publisher bytes", 3, 4, sibling,
          "WIST1-E08", state(follower, follower, 11))
    probe("recovery follower uses named head recovery protection", 4, 5, recovered,
          "recovery_rotation", state(recovered, recovered, 21))
    off_chain = signed(fresh_again, 21, priv4, KID4,
                       recovery_keys=publisher["recovery_keys"])
    probe("recovery of competitor cannot take window ownership", 4, 5, off_chain,
          "recovery_rotation", state(off_chain, follower, 21))
    stolen = signed(owner, 11, priv, KID1, keys=publisher["keys"],
                     recovery_keys=publisher["recovery_keys"])
    probe("fresh competitor cannot restore old recovery keys", 2, 3, stolen,
          "WIST1-E08", state(fresh, owner, 10))
    bad_signature = json.loads(json.dumps(follower))
    raw = bytearray(base64.urlsafe_b64decode(bad_signature["sig"]["value"] + "=="))
    raw[0] ^= 1
    bad_signature["sig"]["value"] = b64u(raw)
    probe("Epoch inclusion cannot replace author verification", 2, 3, bad_signature,
          "WIST1-E01", state(fresh, owner, 10))
    probe("noncurrent recovery head re serve before settlement rejects", 6, 168,
          recovered, "WIST1-E08", state(competitor, recovered, 30))
    probe("current competitor re serve before settlement is idempotent", 6, 168,
          competitor, "idempotent", state(competitor, recovered, 30))
    probe("legitimate follower just before settlement", 6, 168, after,
          "ordinary_rotation", state(after, after, 31))
    probe("restored lower sequence head re serve at settlement", 168, 169,
          recovered, "idempotent", state(recovered, None, 30))
    probe("superseded competitor re serve at settlement rejects", 168, 169,
          competitor, "WIST1-E08", state(recovered, None, 30))
    probe("legitimate follower in deadline Epoch", 168, 169, after,
          "ordinary_rotation", state(after, None, 31))
    obsolete = signed(competitor, 31, priv, KID1)
    probe("superseded predecessor in deadline Epoch rejects", 168, 169, obsolete,
          "WIST1-E08", state(recovered, None, 30))
    low_seq = signed(recovered, 22, priv3, KID3)
    probe("settlement retains competing sequence floor", 168, 169, low_seq,
          "WIST1-E08", state(recovered, None, 30))
    new_recovery = signed(recovered, 31, priv2, KID2)
    probe("recovery at deadline opens a new window", 168, 169, new_recovery,
          "recovery_rotation", state(new_recovery, new_recovery, 31, opened_at=169, windows=2))
    probe("superseded predecessor remains rejected after settlement", 170, 171,
          signed(competitor, 32, priv, KID1), "WIST1-E08", state(after, None, 31))
    competitor_recovery = signed(fresh, 11, priv4, KID4,
                                 recovery_keys=publisher["recovery_keys"])
    branch_epoch, branch_leaves = seal("test-log-k1", priv, leaves_before[3],
                                       [recovery_order_entry(competitor_recovery)], 3, timestamp(3))
    branch = {"epochs": epochs[:3] + [branch_epoch], "pinned_head": root_token(branch_leaves),
              "expected_state": state(competitor_recovery, owner, 11)}
    follows_named = signed(owner, 12, priv3, KID3)
    probe("ordinary follower preserves named head recovery set", 3, 4, follows_named,
          "ordinary_rotation", state(follows_named, follows_named, 12), branch=0)
    follows_competitor_set = signed(owner, 12, priv3, KID3,
                                    recovery_keys=publisher["recovery_keys"])
    probe("current competitor recovery set cannot replace named head set", 3, 4,
          follows_competitor_set, "WIST1-E08", state(competitor_recovery, owner, 11), branch=0)
    low_seq_after_restore = signed(recovered, 22, priv3, KID3)
    resume_cases = [
        {"label": "floor survives a restored lower sequence head",
         "declaration": ["declaration", "example.com", recovered, 5, 30], "recovery_window": None,
         "candidate": low_seq_after_restore, "candidate_sealed_at": timestamp(170), "height": 170,
         "expected_result": "WIST1-E08", "without": "floor", "degraded_result": "ordinary_rotation"},
        {"label": "chain head authenticates a follower before settlement",
         "declaration": ["declaration", "example.com", competitor, 6, 30],
         "recovery_window": ["recovery_window", "example.com", 1, timestamp(169), recovered, 5],
         "candidate": after, "candidate_sealed_at": timestamp(168), "height": 168,
         "expected_result": "ordinary_rotation", "without": "head", "degraded_result": "WIST1-E08"},
    ]
    write_json(WIST1 / "recovery-heads.json", {
        "note": "WIST-1 section 5.2 accepted sequence and recovery heads. The supplied "
                "Log key and final pinned head authenticate one complete hourly Epoch chain. "
                "An optional branch index selects an independently pinned alternate history. "
                "Queries replay through prefix_height, settle at candidate_sealed_at, then "
                "evaluate one independent unsealed candidate. Rejection preserves the "
                "post-settlement state. No invalid candidate is asserted to be a valid "
                "sealed Entry. No identity or conflicting-batch result is asserted.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "declaration_activation_epochs": 0,
        "epochs": epochs, "pinned_head": root_token(tree_leaves),
        "branches": [branch],
        "expected_prefix_states": [{"height": height, "state": expected}
                                   for height, expected in traces],
        "snapshot_tuples": snapshot_tuples,
        "resume_cases": resume_cases,
        "probes": probes,
    })


recovery_heads_vectors()

def recovery_admission_vectors():
    def signed(previous, seq, signer, key_id, **changes):
        inner = dict(previous["publisher"], seq=seq,
                     prev_declaration=decl_hash(previous["publisher"]), **changes)
        return sign_envelope_with(signer, "publisher", inner, key_id)

    initial = sign_envelope("publisher", publisher, KID1)
    owner = signed(initial, 1, priv2, KID2, keys=[K2], recovery_keys=[R2])
    fresh = signed(owner, 2, priv, KID1, keys=publisher["keys"])
    branch = signed(fresh, 3, priv, KID1, contact="mailto:branch@example.com")
    branch_recovery = signed(branch, 4, priv4, KID4, keys=[K2])
    follower = signed(owner, 5, priv3, KID3, contact="mailto:follower@example.com")
    competitor = signed(follower, 6, priv, KID1, keys=publisher["keys"])
    newest = signed(follower, 7, priv3, KID3, contact="mailto:newest@example.com")
    recovered = signed(owner, 3, priv4, KID4, keys=publisher["keys"])
    recovered_again = signed(recovered, 4, priv4, KID4, contact="mailto:again@example.com")
    fresh_after_recovery = signed(recovered, 4, priv3, KID3, keys=[K2], contact="mailto:after-recovery@example.com")
    after = signed(newest, 8, priv, KID1, keys=publisher["keys"])
    late = signed(owner, 3, priv, KID1, keys=publisher["keys"], contact="mailto:late@example.com")
    declarations = dict(initial=initial, owner=owner, fresh=fresh, branch=branch,
                        branch_recovery=branch_recovery, follower=follower,
                        competitor=competitor, newest=newest, recovered=recovered,
                        recovered_again=recovered_again, fresh_after_recovery=fresh_after_recovery,
                        after=after, late=late)
    start = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc)
    def timestamp(hour, seconds=0):
        return (start + datetime.timedelta(hours=hour, seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    def epoch(height, leaves, names):
        entries = sorted((recovery_order_entry(declarations[name]) for name in names),
                         key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
        return seal("test-log-k1", priv, leaves, entries, height, timestamp(height))
    epochs, tree_leaves = [], []
    for height in range(168):
        result, tree_leaves = epoch(height, tree_leaves,
                                    ["initial"] if height == 0 else ["owner"] if height == 1 else [])
        epochs.append(result)
    leaves168 = tree_leaves

    cases = []
    def case(name, accepted, sealed, retained, discarded, current, floor,
             post=None, log_current=None, log_floor=None, new_window=False, boundary=None,
             new_window_owner=None, log_reset=False, overdue=False):
        before, leaves_before_169 = epoch(168, leaves168, sealed)
        post = post or []
        deadline, leaves_after_deadline = epoch(169, leaves_before_169,
                                                retained + [item[0] for item in post if item[1] != "WIST1-E08"])
        probes = [{"declaration": item, "expected": result} for item, result in post]
        cases.append({
            "name": name,
            "admitted_at": boundary or timestamp(167, 1),
            "admitted": accepted,
            "last_inside_epoch": before,
            "last_inside_pin": root_token(leaves_before_169),
            "expected_settlement": {"current": current, "floor": floor,
                                    "queue_source": "owner", "retained": retained,
                                    "removed": discarded},
            "removed_recovery_sealing_violation": overdue,
            "at_deadline": probes,
            "expected_after_repeat": {"current": post[-1][0] if post and post[-1][1] != "WIST1-E08" else current,
                                      "floor": declarations[post[-1][0]]["publisher"]["seq"]
                                      if post and post[-1][1] != "WIST1-E08" else floor},
            "deadline_epoch": deadline,
            "deadline_pin": root_token(leaves_after_deadline),
            "expected_log": {"current": log_current or (post[-1][0] if post and post[-1][1] != "WIST1-E08" else current),
                             "floor": log_floor if log_floor is not None else (declarations[post[-1][0]]["publisher"]["seq"]
                                       if post and post[-1][1] != "WIST1-E08" else floor),
                             "window_end": timestamp(337) if new_window else None,
                             "reset_height": 169 if log_reset else None},
        })
        if new_window:
            cases[-1]["expected_window_owner"] = new_window_owner or "recovered"
        if discarded == ["fresh"]:
            revival, leaves_revival = epoch(169, leaves_before_169, ["fresh"])
            cases[-1]["forbidden_revival"] = {"epoch": revival, "pin": root_token(leaves_revival),
                                             "log_current": "fresh", "log_reset_height": 169}
    case("pending fresh competitor is removed", ["fresh"], [], [], ["fresh"], "owner", 2,
         post=[("fresh", "WIST1-E08")], log_floor=1)
    case("ordinary and recovery descendants are removed", ["fresh", "branch", "branch_recovery"], [], [],
         ["fresh", "branch", "branch_recovery"], "owner", 4, log_floor=1)
    case("legitimate followers survive competing branches",
         ["fresh", "branch", "branch_recovery", "follower", "competitor", "newest"], [],
         ["follower", "newest"], ["fresh", "branch", "branch_recovery", "competitor"], "newest", 7)
    case("pending recovery follower opens its own sealing window", ["fresh", "recovered"], [],
         ["recovered"], ["fresh"], "recovered", 3, new_window=True)
    case("repeated settlement preserves a new accepted identity",
         ["follower", "competitor", "newest"], [], ["follower", "newest"], ["competitor"], "newest", 7,
         post=[("after", "fresh_identity")], log_reset=True)
    case("last second competitor is superseded", ["fresh"], [], [], ["fresh"], "owner", 2,
         log_floor=1, boundary=timestamp(169, -1))
    case("exact deadline fresh candidate is a new identity", ["fresh"], [], [], ["fresh"], "owner", 2,
         post=[("late", "fresh_identity")], log_reset=True)
    case("sealed competitor remains visible with its sequence floor", ["fresh"], ["fresh"], [], [],
         "owner", 2)
    case("first pending recovery owns the new window", ["fresh", "recovered", "recovered_again"], [],
         ["recovered", "recovered_again"], ["fresh"], "recovered_again", 4, new_window=True)
    case("newly admitted fresh successor seals inside the next window", ["fresh", "recovered"], [],
         ["recovered"], ["fresh"], "recovered", 3, post=[("fresh_after_recovery", "fresh_identity")],
         new_window=True)
    case("supersession does not erase an overdue recovery sealing duty", ["fresh", "branch", "branch_recovery"], [], [],
         ["fresh", "branch", "branch_recovery"], "owner", 4, log_floor=1,
         boundary=timestamp(2, 1), overdue=True)
    write_json(WIST1 / "recovery-admission.json", {
        "note": "WIST-1 section 5.2. Shared signed hourly prefix plus each case's last inside Epoch "
                "and deadline Epoch authenticate sealed Declaration state. Named signed admission "
                "candidates are separate supplied local events, not claims of inclusion. Admission "
                "happens at admitted_at, including when later than last_inside_epoch. Settle at "
                "deadline, evaluate at_deadline candidates in order, then repeat admission settlement "
                "before evaluating the deadline Epoch. No Delta, Payload, quota, Snapshot, durable "
                "storage or authenticated Audit Record eligibility is asserted.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "declaration_activation_epochs": 0,
        "deadline": timestamp(169),
        "epochs": epochs, "pinned_head": root_token(tree_leaves),
        "declarations": declarations, "cases": cases,
    })


recovery_admission_vectors()

def declaration_conflict_vectors():
    def signed(previous, seq, signer=priv, key_id=KID1, **changes):
        inner = dict(previous["publisher"], seq=seq,
                     prev_declaration=decl_hash(previous["publisher"]), **changes)
        return sign_envelope_with(signer, "publisher", inner, key_id)

    def epoch(leaves, height, batch):
        entries = sorted(map(recovery_order_entry, batch),
                         key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
        instant = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc) + datetime.timedelta(hours=height)
        return seal("test-log-k1", priv, leaves, entries, height,
                   instant.isoformat().replace("+00:00", "Z"))

    def state(current, chain=None, floor=None, windows=0, reset=None):
        return {"current_envelope": decl_hash(current),
                "recovery_envelope": decl_hash(chain) if chain else None,
                "highest_accepted_seq": current["publisher"]["seq"] if floor is None else floor,
                "window_end": "2026-08-11T01:00:00Z" if chain else None,
                "windows_opened": windows, "reset_height": reset}

    initial = sign_envelope("publisher", publisher, KID1)
    owner = signed(initial, 1, priv2, KID2, keys=[K2], recovery_keys=[R2])
    fresh = signed(owner, 2, keys=publisher["keys"])
    epochs, tree_leaves = [], []
    leaves_before = [[]]
    for height in range(169):
        batch = [initial] if height == 0 else [owner] if height == 1 else [fresh] if height == 2 else []
        result, tree_leaves = epoch(tree_leaves, height, batch)
        epochs.append(result)
        leaves_before.append(tree_leaves)
    prefixes = {"empty": [], "initial": epochs[:1], "open": epochs[:3], "deadline": epochs}
    prefix_leaves = {"empty": leaves_before[0], "initial": leaves_before[1],
                     "open": leaves_before[3], "deadline": leaves_before[169]}
    initial_state = {"example.com": state(initial)}
    open_state = {"example.com": state(fresh, owner, windows=1)}
    cases = []

    def add(name, prefix, batch, expected, result="accepted", isolated=(), invalid=(), **fields):
        history = prefixes[prefix]
        leaves = prefix_leaves[prefix]
        candidate, candidate_leaves = epoch(leaves, len(history), batch)
        cases.append({"name": name, "prefix": prefix, "epoch": candidate,
                      "pinned_head": root_token(candidate_leaves),
                      "expected_results": [result], "expected_state": expected,
                      "signature_valid": [entry["body"] not in invalid for entry in candidate["entries"]],
                      "expected_accepted_head": root_token(candidate_leaves) if result == "accepted" else root_token(leaves),
                      "isolated_candidates": [{"previous": p, "incoming": e, "expected_result": r}
                                              for p, e, r in isolated], **fields})

    ordinary = signed(initial, 1, keys=[K2])
    recovery_same = sign_envelope_with(priv2, "publisher", ordinary["publisher"], KID2)
    for reverse in (False, True):
        for nonce in range(1000):
            sibling = signed(initial, 1, contact=f"mailto:sibling{nonce}@example.com")
            if (recovery_order_leaf(sibling) < recovery_order_leaf(ordinary)) == reverse:
                break
        else:
            raise AssertionError("no discriminating sibling order")
        add("distinct siblings " + ("reversed" if reverse else "ascending"), "initial",
            [ordinary, sibling], initial_state, "WIST1-E08",
            [(initial, ordinary, "ordinary_rotation"), (initial, sibling, "ordinary_rotation")],
            first_candidate=decl_hash(ordinary), sibling_leaves_reversed=reverse)
    add("same publisher ordinary and recovery signatures", "initial", [ordinary, recovery_same],
        initial_state, "WIST1-E08",
        [(initial, ordinary, "ordinary_rotation"), (initial, recovery_same, "recovery_rotation")])
    add("ordinary signature alone", "initial", [ordinary], {"example.com": state(ordinary)})
    add("recovery signature alone", "initial", [recovery_same],
        {"example.com": state(recovery_same, recovery_same, windows=1)})
    add("identical recovery Envelopes apply once", "initial", [owner, owner],
        {"example.com": state(owner, owner, windows=1)})
    add("current publisher alternate signatures install nothing", "initial",
        [initial, sign_envelope_with(priv2, "publisher", publisher, KID2)], initial_state)
    alternate_initial = sign_envelope("publisher", dict(publisher, contact="mailto:other@example.com"), KID1)
    add("distinct initial Declarations", "empty", [initial, alternate_initial], {}, "WIST1-E08",
        [(None, initial, "initial"), (None, alternate_initial, "initial")])
    add("identical initial Envelopes", "empty", [initial, initial], initial_state)
    other = sign_envelope("publisher", dict(publisher, domain="aaa.example.net", subdomain_scope=[],
                                           contact="mailto:keys@aaa.example.net"), KID1)
    add("equal sequences across domains", "empty", [initial, other],
        {"example.com": state(initial), "aaa.example.net": state(other)})
    lower = signed(initial, 1, contact="mailto:lower@example.com")
    left = signed(lower, 2, contact="mailto:left@example.com")
    right = signed(lower, 2, contact="mailto:right@example.com")
    add("reject lower sequence and other domain effects", "initial", [other, lower, left, right],
        initial_state, "WIST1-E08",
        [(None, other, "initial"), (initial, lower, "ordinary_rotation"),
         (lower, left, "ordinary_rotation"), (lower, right, "ordinary_rotation")])
    follower = signed(owner, 3, priv3, KID3, contact="mailto:follower@example.com")
    competitor = signed(fresh, 3, contact="mailto:competitor@example.com")
    add("distinct eligible recovery heads", "open", [follower, competitor], open_state, "WIST1-E08",
        [(owner, follower, "ordinary_rotation"), (fresh, competitor, "ordinary_rotation")])
    restored_alternate = sign_envelope_with(priv3, "publisher", owner["publisher"], KID3)
    add("settlement precedes restored current re serves", "deadline", [owner, restored_alternate],
        {"example.com": state(owner, floor=2, windows=1)})
    after_left = signed(owner, 3, priv3, KID3, contact="mailto:afterleft@example.com")
    after_right = signed(owner, 3, priv3, KID3, contact="mailto:afterright@example.com")
    add("rejected deadline Epoch does not settle", "deadline", [after_left, after_right],
        open_state, "WIST1-E08",
        [(owner, after_left, "ordinary_rotation"), (owner, after_right, "ordinary_rotation")])
    invalid_author = sign_envelope_with(priv4, "publisher", ordinary["publisher"], KID1)
    add("conflict does not filter invalid signatures", "initial", [ordinary, invalid_author],
        initial_state, "WIST1-E08",
        [(initial, ordinary, "ordinary_rotation"), (initial, invalid_author, "WIST1-E01")],
        invalid=[invalid_author])
    add("duplicate does not waive first signature check", "initial", [invalid_author, invalid_author],
        initial_state, "WIST1-E01", [(initial, invalid_author, "WIST1-E01")], invalid=[invalid_author])
    add("current object and changed sibling conflict", "initial", [initial, alternate_initial],
        initial_state, "WIST1-E08")
    add("initial and duplicate replacement in one Epoch", "empty", [initial, ordinary, ordinary],
        {"example.com": state(ordinary)})
    invalid_other = sign_envelope_with(priv4, "publisher", other["publisher"], KID1)
    add("different domains may report either failure", "initial", [invalid_other, ordinary, recovery_same],
        initial_state, "WIST1-E08", [(None, invalid_other, "WIST1-E01")], invalid=[invalid_other],
        expected_results=["WIST1-E01", "WIST1-E08"])
    fresh_outside = signed(initial, 1, priv3, KID3, keys=[K2])
    add("fresh identity outside a window resets", "initial", [fresh_outside],
        {"example.com": state(fresh_outside, reset=1)},
        isolated=[(initial, fresh_outside, "fresh_identity")])
    fresh_settled = signed(owner, 3, keys=publisher["keys"])
    add("fresh identity after settlement resets", "deadline", [fresh_settled],
        {"example.com": state(fresh_settled, windows=1, reset=169)},
        isolated=[(owner, fresh_settled, "fresh_identity")])
    write_json(WIST1 / "declaration-conflicts.json", {
        "note": "WIST-1 section 5.2 and WIST-3 section 3.3 equal-sequence Declaration groups. "
                "Each case appends its Epoch to the named authenticated prefix; trusted fixture "
                "inputs are the supplied Log key, pinned head and default seven-day window. "
                "Expected state hashes commit to whole installed Envelopes, including signatures. "
                "The deadline prefix ends one hour before settlement. Candidate classification "
                "probes are independent of batch acceptance; signature_valid checks only cryptographic "
                "authorship against fixture key bindings, not eligibility or idempotent installation. "
                "No Snapshot eligibility is asserted. Domain iteration order is immaterial to accepted state.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "declaration_activation_epochs": 0,
        "prefixes": prefixes, "cases": cases})


declaration_conflict_vectors()

def declaration_field_vectors():
    conflicts = json.loads((WIST1 / "declaration-conflicts.json").read_text())
    initial = sign_envelope("publisher", publisher, KID1)
    ordinary = variant(seq=1, prev_declaration=stored_hash, keys=[K2])
    cases = []

    def add(name, path, value=None, remove=False, expected="WIST1-E14", base=ordinary):
        inner = json.loads(json.dumps(base))
        target = inner
        for part in path[:-1]:
            target = target[part]
        if remove:
            del target[path[-1]]
        else:
            target[path[-1]] = value
        cases.append({"name": name, "envelope": sign_envelope("publisher", inner, KID1),
                      "expected": expected, "author_signature_valid": True})

    for path, value in (
        (["seq"], None), (["seq"], True), (["seq"], 1.5), (["seq"], -1),
        (["seq"], float(2**53)), (["prev_declaration"], None),
        (["prev_declaration"], "sha256:bad"), (["keys"], []),
        (["recovery_keys"], None), (["subdomain_scope"], None),
        (["contact"], None), (["contact"], "x" * 257),
        (["domain"], "bad host.example"), (["subdomain_scope"], ["bad host.example"]),
        (["keys", 0, "kid"], "x" * 43), (["keys", 0, "kid"], KID1),
        (["keys", 0, "kid"], "x" * 65), (["keys", 0, "kty"], "EC"),
        (["keys", 0, "crv"], "X25519"), (["keys", 0, "alg"], "Ed25519"),
        (["keys", 0, "x"], "!" * 43), (["keys", 0, "x"], K2["x"][:42]),
        (["keys", 0, "exp"], None), (["keys", 0, "exp"], "later"),
        (["keys", 0, "exp"], K2["nbf"]), (["keys", 0, "exp"], K2["nbf"] - 1),
        (["recovery_keys", 0, "kid"], KID3),
        (["wist_version"], "1.0"), (["unknown"], True),
    ):
        add("invalid " + " ".join(map(str, path)) + " " + str(value)[:12], path, value)
    for path in (["seq"], ["domain"], ["keys"], ["keys", 0, "nbf"], ["keys", 0, "kid"],
                 ["keys", 0, "x"], ["keys", 0, "kty"], ["keys", 0, "crv"]):
        add("missing " + " ".join(map(str, path)), path, remove=True)
    add("expiry after start", ["keys", 0, "exp"], K2["nbf"] + 1, expected="ordinary_rotation")
    add("recovery expiry after start", ["recovery_keys", 0, "exp"],
        publisher["recovery_keys"][0]["nbf"] + 1, expected="WIST1-E08")
    add("missing semantic predecessor", ["prev_declaration"], remove=True, expected="WIST1-E08")
    add("well shaped wrong predecessor", ["prev_declaration"], "sha256:" + "00" * 32,
        expected="WIST1-E08")
    add("later minor version", ["wist_version"], "1.1.0", expected="ordinary_rotation")
    add("unimplemented major version", ["wist_version"], "2.0.0", expected="WIST1-E15")
    add("safe integer maximum", ["seq"], 2**53 - 1, expected="ordinary_rotation")
    add("contact at bound", ["contact"], "x" * 256, expected="ordinary_rotation")
    times = [("2026-02-30T12:00:00Z", False), ("2026-08-04T24:00:00Z", False),
             ("2026-08-04T12:00:00", False), ("2026-08-04T12:00:00.Z", False),
             ("2026-08-04T12:00:00+24:00", False), ("2026-08-04T12:00:00+00:60", False),
             ("２０２６-08-04T12:00:00Z", False), (None, False),
             ("2026-08-04T12:00:00Z", True), ("2026-08-04t12:00:00.0000000001z", True),
             ("2026-08-04T09:00:00-03:00", True), ("0000-02-29T00:00:00Z", True)]
    times.extend([
        ("2026-08-04T10:00:00." + "0" * 4400 + "1Z", True),
        ("2016-12-31T23:59:60Z", False),
        ("2016-12-31T15:59:60-08:00", False),
        ("2017-01-01T00:59:60+01:00", False),
        ("2016-12-31t23:59:60.1234567890123456789z", False),
        ("2016-12-30T23:59:60Z", False),
        ("2016-12-31T23:58:60Z", False),
        ("1972-06-30T23:59:60Z", False),
        ("1990-12-31T23:59:60Z", False),
        ("1990-12-31T15:59:60-08:00", False),
        ("2030-06-30T23:59:60Z", False),
        ("9999-12-31T23:59:60Z", False),
        ("2016-12-31T23:59:59.999999999999999999999999999999Z", True),
        ("2017-01-01T00:00:00Z", True),
        ("2030-06-30T23:59:58Z", True),
        ("2030-06-30T23:59:59Z", True),
        ("2030-06-30T23:59:59.99999999999999999999Z", True),
        ("2030-07-01T00:00:00Z", True),
        ("2030-07-01T00:59:59+01:00", True),
        ("2030-06-30T15:59:59-08:00", True),
        ("0000-01-01T00:00:00+23:59", True),
        ("9999-12-31T23:59:59.99999999999999999999-23:59", True),
        ("0000-02-29t00:00:00.0-00:00", True),
        ("2000-02-29T00:00:00+00:00", True),
        ("1900-02-29T00:00:00Z", False),
        ("0001-02-29T00:00:00Z", False),
        ("0000-02-30T00:00:00Z", False),
        ("-0001-12-31T23:59:59Z", False),
        ("10000-01-01T00:00:00Z", False),
        ("2026-08-04T12:00:61Z", False),
        ("2026-08-04T12:60:00Z", False),
        ("2026-08-04T12:00:00-24:00", False),
        ("2026-08-04T12:00:00-00:60", False),
        ("2026-08-04T12:00:00,5Z", False),
        ("2026-08-04T12:00:00.٥Z", False),
        ("2026-08-04T12:00:00Z\n", False),
        ("2026-08-04 12:00:00Z", False),
        ("2026-08-04T12:00:00+01", False),
        ("2026-08-04T12:00:00+00:00[UTC]", False),
    ])
    starts = [(0, True), (253402300799, True), (1754308800, True), (-1, False),
              (253402300800, False), (1.5, False), ("1754308800", False), (None, False),
              (True, False), ([1754308800], False)]
    for position, (value, valid) in enumerate(starts):
        add(f"signing start {position}", ["keys", 0, "nbf"], value,
            expected="ordinary_rotation" if valid else "WIST1-E14")
        add(f"recovery start {position}", ["recovery_keys", 0, "nbf"], value,
            expected="WIST1-E08" if valid else "WIST1-E14")
    for field, value in (("sig", None), ("unknown", True)):
        env = sign_envelope("publisher", ordinary, KID1)
        env[field] = value
        cases.append({"name": "Envelope " + field, "envelope": env,
                      "expected": "WIST1-E14", "author_signature_valid": field != "sig"})
    for field, value in (("value", "bad"), ("key_id", None), ("alg", "other"), ("unknown", True)):
        env = sign_envelope("publisher", ordinary, KID1)
        env["sig"][field] = value
        cases.append({"name": "signature " + field, "envelope": env,
                      "expected": "WIST1-E14", "author_signature_valid": field != "value"})
    bad_signature = sign_envelope_with(priv4, "publisher", ordinary, KID1)
    cases.append({"name": "valid fields invalid signature", "envelope": bad_signature,
                  "expected": "WIST1-E01", "author_signature_valid": False})
    cases.append({"name": "invalid fields and invalid signature",
                  "envelope": sign_envelope_with(priv4, "publisher", dict(ordinary, contact=None), KID1),
                  "expected": "WIST1-E14", "author_signature_valid": False})
    delta_cases = []
    for position, (value, valid) in enumerate(times):
        inner = {key: value for key, value in delta.items() if key != "payload"}
        inner.update(change_type="delete", observed_at=value, prev=decl_hash(delta))
        delta_cases.append({"name": f"observed at {position}",
                            "envelope": sign_envelope("delta", inner, KID1),
                            "expected": "well_formed" if valid else "WIST1-E14"})
    absent = {key: value for key, value in delta.items() if key not in ("payload", "observed_at")}
    absent.update(change_type="delete", prev=decl_hash(delta))
    delta_cases.append({"name": "missing observed at", "envelope": sign_envelope("delta", absent, KID1),
                        "expected": "WIST1-E14"})

    key_time_cases = []
    ten = nbf_at("2026-08-04T10:00:00Z")
    for name, window, observed_at, expected in [
        ("fraction follows whole second", (ten, None), "2026-08-04T10:00:00.5Z", "key_bound_satisfied"),
        ("inclusive start", (ten, None), "2026-08-04T10:00:00Z", "key_bound_satisfied"),
        ("fraction before the start", (ten, None), "2026-08-04T09:59:59.999999999999999999999999999999Z", "WIST1-E02"),
        ("no fractional rounding", (ten, None), "2026-08-04T09:59:59." + "9" * 4400 + "Z", "WIST1-E02"),
        ("unknown local offset equality", (ten, None), "2026-08-04t10:00:00.000-00:00", "key_bound_satisfied"),
        ("numeric offset equality", (ten, None), "2026-08-04T11:30:00+01:30", "key_bound_satisfied"),
        ("numeric offset before the start", (ten, None), "2026-08-04T11:29:59.9+01:30", "WIST1-E02"),
        ("exclusive expiry", (ten, ten + 3600), "2026-08-04T11:00:00Z", "WIST1-E02"),
        ("fraction below the expiry", (ten, ten + 3600), "2026-08-04T10:59:59.99999999999999999999Z", "key_bound_satisfied"),
        ("expiry under an offset spelling", (ten, ten + 3600), "2026-08-04T08:00:00-03:00", "WIST1-E02"),
        ("inserted leap label invalid", (ten, None), "2026-08-04T10:00:60Z", "WIST1-E14"),
        ("positive leap boundary", (nbf_at("2016-12-31T23:59:59Z"), None), "2017-01-01T00:00:00Z", "key_bound_satisfied"),
        ("leap second not counted", (nbf_at("2017-01-01T00:00:00Z"), None), "2016-12-31T23:59:59.999Z", "WIST1-E02"),
        ("hypothetical deletion keeps 59", (nbf_at("2030-06-30T23:59:58Z"), None), "2030-06-30T23:59:59Z", "key_bound_satisfied"),
        ("Unix time origin", (0, None), "1970-01-01T00:00:00Z", "key_bound_satisfied"),
        ("before the Unix time origin precedes every window", (0, None), "1969-12-31T23:59:59.999Z", "WIST1-E02"),
        ("year zero precedes every window", (0, None), "0000-01-01T00:00:00+23:59", "WIST1-E02"),
        ("last representable start", (253402300799, None), "9999-12-31T23:59:59Z", "key_bound_satisfied"),
        ("offset beyond the written year range", (253402300799, None), "9999-12-31T23:59:59.5-00:01", "key_bound_satisfied"),
        ("largest expiry", (0, 253402300799), "9999-12-31T23:59:58.999Z", "key_bound_satisfied"),
    ]:
        declaration = dict(publisher, keys=[jwk(pub_raw, window[0], window[1])])
        inner = {key: value for key, value in delta.items() if key != "payload"}
        inner.update(change_type="delete", observed_at=observed_at, prev=decl_hash(delta))
        key_time_cases.append({"name": name,
                               "declaration": sign_envelope("publisher", declaration, KID1),
                               "envelope": sign_envelope("delta", inner, KID1),
                               "expected": expected})
    elapsed_cases = [
        {"start": "2016-12-31T23:59:59Z", "end": "2017-01-01T00:00:00Z", "seconds": "1"},
        {"start": "2030-06-30T23:59:58Z", "end": "2030-07-01T00:00:00Z", "seconds": "2"},
        {"start": "2030-06-30T15:59:58-08:00", "end": "2030-07-01T01:00:00+01:00", "seconds": "2"},
        {"start": "0000-02-28T00:00:00Z", "end": "0000-03-01T00:00:00Z", "seconds": "172800"},
        {"start": "2026-08-04T10:00:00Z", "end": "2026-08-04T10:10:00.00000000000000000001Z", "seconds": "600.00000000000000000001"},
    ]

    relation_cases = []
    for name, kind, reference, observed_at, expected in [
        ("skew bound inclusive", "clock", "2026-08-04T10:00:00Z", "2026-08-04T07:10:00-03:00", "relation_satisfied"),
        ("skew bound exact excess", "clock", "2026-08-04T10:00:00Z", "2026-08-04T10:10:00.00000000000000000001Z", "WIST1-E06"),
        ("skew bound tiny older", "clock", "2026-08-04T10:00:00Z", "2026-08-04T10:09:59.99999999999999999999Z", "relation_satisfied"),
        ("equal predecessor offset", "predecessor", "2026-08-04T10:00:00Z", "2026-08-04T07:00:00.000-03:00", "WIST1-E07"),
        ("strict predecessor tiny later", "predecessor", "2026-08-04T10:00:00Z", "2026-08-04T10:00:00.00000000000000000001Z", "relation_satisfied"),
        ("strict predecessor tiny earlier", "predecessor", "2026-08-04T10:00:00.00000000000000000002Z", "2026-08-04T10:00:00.00000000000000000001Z", "WIST1-E07"),
    ]:
        inner = {key: value for key, value in delta.items() if key != "payload"}
        inner.update(change_type="delete", observed_at=observed_at, prev=decl_hash(delta))
        case = {"name": name, "kind": kind, "reference": reference, "expected": expected}
        if kind == "predecessor":
            predecessor = dict(delta, observed_at=reference)
            case["predecessor"] = sign_envelope("delta", predecessor, KID1)
            inner["prev"] = decl_hash(predecessor)
        case["envelope"] = sign_envelope("delta", inner, KID1)
        relation_cases.append(case)

    def epoch(leaves, height, batch):
        entries = sorted(map(recovery_order_entry, batch),
                         key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
        instant = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc) + datetime.timedelta(hours=height)
        return seal("test-log-k1", priv, leaves, entries, height,
                   instant.isoformat().replace("+00:00", "Z"))

    batches = []
    other = sign_envelope("publisher", dict(publisher, domain="other.example"), KID1)
    for case in cases:
        batch, batch_leaves = epoch(prefix_leaves(conflicts["prefixes"]["initial"]), 1,
                                    [other, case["envelope"]])
        batches.append({"name": case["name"], "prefix": "initial", "epoch": batch,
                        "pinned_head": root_token(batch_leaves),
                        "expected": "accepted" if case["expected"] == "ordinary_rotation" else case["expected"]})
    valid = sign_envelope("publisher", ordinary, KID1)
    malformed = json.loads(json.dumps(valid))
    malformed["sig"]["unknown"] = True
    later = dict(ordinary, seq=2, prev_declaration=decl_hash(ordinary), contact=None)
    for name, members, expected in (
        ("field error precedes same sequence conflict", [valid, malformed], "WIST1-E14"),
        ("field error rolls back lower sequence", [valid, sign_envelope_with(priv3, "publisher", later, KID3)], "WIST1-E14"),
        ("repaired field accepts both sequences", [valid, sign_envelope_with(
            priv3, "publisher", dict(later, contact="mailto:security@example.com"), KID3)], "accepted"),
    ):
        batch, batch_leaves = epoch(prefix_leaves(conflicts["prefixes"]["initial"]), 1, members + [other])
        batches.append({"name": name, "prefix": "initial", "epoch": batch,
                        "pinned_head": root_token(batch_leaves), "expected": expected})
    for prefix in ("empty", "initial", "open", "deadline"):
        history = conflicts["prefixes"][prefix]
        current = initial if prefix in ("empty", "initial") else history[2]["entries"][0]["body"]
        env = json.loads(json.dumps(current))
        env["sig"]["unknown"] = True
        batch, batch_leaves = epoch(prefix_leaves(history), len(history), [other, env])
        batches.append({"name": "malformed re serve " + prefix, "prefix": prefix, "epoch": batch,
                        "pinned_head": root_token(batch_leaves), "expected": "WIST1-E14"})
    for prefix in ("empty", "initial", "open", "deadline"):
        history = conflicts["prefixes"][prefix]
        current = initial if prefix in ("empty", "initial") else history[2]["entries"][0]["body"]
        for array in ("keys", "recovery_keys"):
            inner = json.loads(json.dumps(current["publisher"]))
            inner[array][0]["nbf"] = -1
            env = sign_envelope("publisher", inner, KID1)
            batch, batch_leaves = epoch(prefix_leaves(history), len(history), [other, env])
            batches.append({"name": "negative start rolls back " + array + " " + prefix,
                            "prefix": prefix, "epoch": batch,
                            "pinned_head": root_token(batch_leaves), "expected": "WIST1-E14"})
    write_json(WIST1 / "declaration-fields.json", {
        "note": "WIST-1 sections 3.4, 5.1 and 7. Signature-valid field mutations use the supplied fixture "
                "author key independently of eligibility. Each Declaration case replaces stored; each batch "
                "appends to its named authenticated prefix. Rejection preserves the full accepted state and head, "
                "including due settlement and other domains. Delta cases assert timestamp field syntax only, "
                "not full clock, chain or Payload eligibility. Timestamp fields follow the event-independent "
                "Gregorian profile in WIST-1 section 3.4, rejecting every leap label; the 2030-06-30 "
                "deletion is hypothetical and asserts no IERS announcement. Key-time cases authenticate "
                "one supplied binding and assert only field validity and its window, inclusive at nbf "
                "and exclusive at exp. Elapsed cases "
                "use exact civil-clock seconds. Relation cases isolate the inclusive 600-second clock bound "
                "and strict predecessor ordering; predecessor authorship and ID are checked but lower Log "
                "position, chain availability and clock acquisition are supplied assumptions. Hostname coverage is limited to ASCII structural examples. No full field profile, "
                "cryptographic key admission, Snapshot restoration or live service conformance is asserted.",
        "log_key": conflicts["log_key"], "author_key": b64u(pub_raw), "stored": initial,
        "recovery_window_days": 7, "declaration_activation_epochs": 0,
        "prefixes": conflicts["prefixes"],
        "cases": cases, "delta_cases": delta_cases, "epoch_cases": batches,
        "key_time_cases": key_time_cases, "elapsed_cases": elapsed_cases, "relation_cases": relation_cases})


declaration_field_vectors()

def declaration_key_eligibility_vectors():
    excluded = {
        "noncanonical point": bytes.fromhex("ee" + "ff" * 30 + "7f"),
        "small order point": bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        "identity point": (1).to_bytes(32, "little"),
        "negative zero point": (1 + 2**255).to_bytes(32, "little"),
        "not a curve point": (2).to_bytes(32, "little"),
    }
    excluded_values = {b64u(value) for value in excluded.values()}
    cases = []

    def add(name, previous, incoming, signer, key_id, expected):
        old = sign_envelope("publisher", previous, KID1) if previous else None
        env = sign_envelope_with(signer, "publisher", incoming, key_id)
        cases.append({"name": name, "stored": old, "fetched": env, "expected": expected,
                      "author_key": b64u(raw_public(signer)),
                      "expected_usable": {field: [key for key in incoming.get(field, [])
                                                   if key["x"] not in excluded_values]
                                          for field in ("keys", "recovery_keys")}})

    for label, raw in excluded.items():
        bad = jwk(raw, "2026-08-03T12:00:00Z")
        for field in ("keys", "recovery_keys"):
            initial = variant(**{field: stored_decl[field] + [bad]})
            add("initial unused " + field + " " + label, None, initial, priv, KID1, "initial")
            ordinary = dict(initial, seq=1, prev_declaration=decl_hash(initial),
                            keys=[K2, bad] if field == "keys" else [K2])
            add("ordinary unused " + field + " " + label, initial, ordinary,
                priv, KID1, "ordinary_rotation")
        incoming = variant(seq=1, prev_declaration=stored_hash, keys=[K2, bad])
        add("recovery unused " + label, stored_decl, incoming, priv2, KID2, "recovery_rotation")
        add("excluded incoming named signer " + label, stored_decl, incoming, priv3, bad["kid"], "WIST1-E02")
        previous = variant(recovery_keys=[stored_decl["recovery_keys"][0], bad])
        incoming = dict(previous, seq=1, prev_declaration=decl_hash(previous), keys=[K2])
        add("excluded previous recovery named signer " + label, previous, incoming,
            priv3, bad["kid"], "WIST1-E02")
        add("valid recovery carries excluded entry " + label, previous, incoming,
            priv2, KID2, "recovery_rotation")
        changed = dict(incoming, recovery_keys=stored_decl["recovery_keys"])
        add("excluded recovery entry still protected " + label, previous, changed,
            priv, KID1, "WIST1-E08")
        add("valid recovery removes excluded entry " + label, previous, changed,
            priv2, KID2, "recovery_rotation")
        add("initial no usable signing keys " + label, None, variant(keys=[bad]),
            priv3, bad["kid"], "WIST1-E02")
        add("replacement no usable signing keys " + label, stored_decl,
            variant(seq=1, prev_declaration=stored_hash, keys=[bad]), priv, KID1, "ordinary_rotation")
        previous = variant(keys=stored_decl["keys"] + [bad])
        incoming = variant(seq=1, prev_declaration=decl_hash(previous), keys=[K2])
        add("excluded old entry permits incoming signer " + label, previous, incoming,
            priv3, KID3, "fresh_identity")
        incoming = variant(seq=1, prev_declaration=stored_hash, keys=[bad, K2])
        add("excluded incoming entry permits old signer " + label, stored_decl, incoming,
            priv, KID1, "ordinary_rotation")
        duplicate = variant(keys=stored_decl["keys"] + [bad, bad])
        add("excluded duplicate key " + label, None, duplicate, priv, KID1, "WIST1-E08")
        overlap = variant(keys=stored_decl["keys"] + [bad], recovery_keys=[bad])
        add("excluded cross set overlap " + label, None, overlap, priv, KID1, "WIST1-E08")
        previous = variant(recovery_keys=[bad])
        incoming = dict(previous, seq=1, prev_declaration=decl_hash(previous), recovery_keys=[])
        add("no usable recovery key does not unprotect entries " + label, previous, incoming,
            priv, KID1, "WIST1-E08")
    mixed = jwk(bytes.fromhex(
        "b502ff3d92e31d8190b4aa4ea0414005167fad089c4de9dac8a2fc850fed4f58"), "2026-08-03T12:00:00Z")
    add("non small mixed order key remains usable", None,
        variant(keys=stored_decl["keys"] + [mixed]), priv, KID1, "initial")
    add("usable named binding invalid signature", stored_decl,
        variant(seq=1, prev_declaration=stored_hash, keys=[K2]), priv4, KID3, "WIST1-E01")
    add("future start does not exclude Declaration signer", None,
        variant(keys=[jwk(pub_raw, 253402300799)]), priv, KID1, "initial")
    add("past expiry does not exclude Declaration signer", None,
        variant(keys=[jwk(pub_raw, 0, 1)]), priv, KID1, "initial")
    add("past expiry does not exclude rotation signer", stored_decl,
        variant(seq=1, prev_declaration=decl_hash(variant(keys=[jwk(pub_raw, 0, 1)])), keys=[K2]),
        priv, KID1, "WIST1-E08")
    expired = variant(keys=[jwk(pub_raw, 0, 1)])
    add("expired previous entry still rotates", expired,
        dict(expired, seq=1, prev_declaration=decl_hash(expired), keys=[K2]), priv, KID1, "ordinary_rotation")
    write_json(WIST1 / "declaration-key-eligibility.json", {
        "note": "WIST-1 sections 4 and 5.2 derive usable keys while retaining every signed entry. "
                "stored is null for initial admission; otherwise it is an authenticated initial Declaration. "
                "Each fetched signature is independently verifiable under author_key, even when that key has "
                "no eligible named binding. expected_usable describes cryptographic key exclusion only, "
                "even for rejected Envelopes, and is not installed state. Fixtures use canonical base64url "
                "and ordinary valid fields; nbf and exp never filter a Declaration signer. No temporal "
                "authority selection, full field/encoding profile, live "
                "admission, Delta replay or Snapshot result is asserted.",
        "cases": cases})


declaration_key_eligibility_vectors()

def base64url_vectors():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    fields = []
    for kind, size in (("x", 32), ("signature", 64), ("salt", 16), ("salt", 17), ("salt", 18)):
        encoded = b64u(bytes(range(size)))
        unused = (6 - (size * 8) % 6) % 6
        for index, character in enumerate(alphabet):
            fields.append({"name": f"{kind} {size} octets final sextet {index}", "kind": kind,
                           "encoded": encoded[:-1] + character,
                           "expected": "well_formed" if index % (2**unused) == 0 else "WIST1-E14"})
    for kind, size in (("x", 32), ("signature", 64), ("salt", 16)):
        canonical = b64u(bytes(range(size)))
        for name, value in (("padding", canonical + "="), ("newline", canonical + "\n"),
                            ("leading space", " " + canonical), ("foreign alphabet", "/" + canonical[1:]),
                            ("non ASCII", "é" + canonical[1:]), ("one character", "A"),
                            ("empty", ""), ("null", None), ("number", 42), ("boolean", True),
                            ("wrong byte length", b64u(bytes(size - 1)))):
            fields.append({"name": kind + " " + name, "kind": kind, "encoded": value,
                           "expected": "WIST1-E14"})
    cases = []

    def alias(encoded, bits):
        return encoded[:-1] + alphabet[alphabet.index(encoded[-1]) + bits]

    def add(name, inner, previous=None, expected="WIST1-E14", signature_bits=0):
        env = sign_envelope("publisher", inner, KID1)
        if signature_bits:
            env["sig"]["value"] = alias(env["sig"]["value"], signature_bits)
        cases.append({"name": name, "stored": previous, "envelope": env, "expected": expected})

    initial = sign_envelope("publisher", publisher, KID1)
    ordinary = variant(seq=1, prev_declaration=stored_hash, keys=[K2])
    add("canonical initial", publisher, expected="initial")
    add("canonical ordinary", ordinary, initial, "ordinary_rotation")
    add("canonical cross set overlap", variant(recovery_keys=[publisher["keys"][0]]), expected="WIST1-E08")
    for bits in range(1, 4):
        for field in ("keys", "recovery_keys"):
            mutated = json.loads(json.dumps(publisher))
            mutated[field][0]["x"] = alias(mutated[field][0]["x"], bits)
            add(f"initial {field} unused bits {bits}", mutated)
            incoming = dict(mutated, seq=1, prev_declaration=stored_hash)
            add(f"replacement {field} unused bits {bits}", incoming, initial)
            rethumbed = json.loads(json.dumps(mutated))
            rethumbed[field][0]["kid"] = kid_of_x(rethumbed[field][0]["x"])
            add(f"initial {field} unused bits {bits} under a matching thumbprint", rethumbed)
        bad = dict(K2, x=alias(K2["x"], bits))
        add(f"unused signing key unused bits {bits}", variant(keys=publisher["keys"] + [bad]))
        bad = dict(publisher["keys"][0], x=alias(publisher["keys"][0]["x"], bits))
        add(f"cross set noncanonical spelling unused bits {bits}", variant(recovery_keys=[bad]))
        excluded = dict(K2, x=alias(b64u((1).to_bytes(32, "little")), bits))
        add(f"excluded point malformed spelling {bits}", variant(keys=publisher["keys"] + [excluded]))
    for bits in range(1, 16):
        add(f"initial signature unused bits {bits}", publisher, signature_bits=bits)
        add(f"replacement signature unused bits {bits}", ordinary, initial, signature_bits=bits)
    conflicts = json.loads((WIST1 / "declaration-conflicts.json").read_text())
    epochs = []
    for prefix in ("empty", "initial", "open", "deadline"):
        history = conflicts["prefixes"][prefix]
        current = initial if prefix in {"empty", "initial"} else next(
            entry["body"] for epoch in history for entry in epoch["entries"]
            if entry["body"]["publisher"]["seq"] == (1 if prefix == "deadline" else 2))
        malformed = json.loads(json.dumps(current))
        malformed["sig"]["value"] = alias(malformed["sig"]["value"], 1)
        other = sign_envelope("publisher", dict(publisher, domain="other.example"), KID1)
        for reject in (False, True):
            members = [other, current] + ([malformed] if reject else [])
            entries = sorted(map(recovery_order_entry, members), key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
            instant = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc) + datetime.timedelta(hours=len(history))
            epoch, epoch_leaves = seal("test-log-k1", priv, prefix_leaves(history), entries, len(history),
                                       instant.isoformat().replace("+00:00", "Z"))
            epochs.append({"name": prefix + (" rejects signature alias" if reject else " accepts canonical twin"),
                           "prefix": prefix, "epoch": epoch, "pinned_head": root_token(epoch_leaves),
                           "expected": "WIST1-E14" if reject else "accepted"})
    write_json(WIST1 / "base64url.json", {
        "note": "WIST-1 section 2 canonical base64url. Field cases establish encoding/length only, not point "
                "eligibility or signatures. Declaration author signatures are valid under author_key even when "
                "permissive decoding is needed to inspect a rejected signature alias; acceptance never repairs it. "
                "Each Epoch appends to its named authenticated prefix; rejection preserves all state and the "
                "accepted head, including due settlement and other domains. Canonical twins exercise acceptance. "
                "Full field formats, live services, transport wrappers and Snapshot restoration are not established.",
        "author_key": b64u(pub_raw), "log_key": conflicts["log_key"], "recovery_window_days": 7,
        "declaration_activation_epochs": 0,
        "fields": fields, "cases": cases, "prefixes": conflicts["prefixes"], "epoch_cases": epochs})


base64url_vectors()

def declaration_host_vectors():
    longest = '.'.join(['a' * 63] * 3 + ['a' * 61])
    hosts = [
        ('canonical ASCII', 'example.com', 'example.com'),
        ('uppercase', 'EXAMPLE.com', 'example.com'),
        ('trailing dot', 'example.com.', 'example.com'),
        ('uppercase trailing dot', 'EXAMPLE.COM.', 'example.com'),
        ('third fourth hyphens', 'r2---sn-x.example', 'r2---sn-x.example'),
        ('leading hyphen', '-foo.example', '-foo.example'),
        ('trailing hyphen', 'foo-.example', 'foo-.example'),
        ('hyphen label', '-.example', '-.example'),
        ('U label', 'bücher.example', 'xn--bcher-kva.example'),
        ('A label', 'xn--bcher-kva.example', 'xn--bcher-kva.example'),
        ('uppercase A label', 'XN--BCHER-KVA.example', 'xn--bcher-kva.example'),
        ('nontransitional U label', 'faß.de', 'xn--fa-hia.de'),
        ('nontransitional A label', 'xn--fa-hia.de', 'xn--fa-hia.de'),
        ('mapped sigma', 'example.ΑΣ', 'example.xn--mxa0b'),
        ('canonical sigma', 'example.xn--mxa0b', 'example.xn--mxa0b'),
        ('Unicode separator', 'example。com', 'example.com'),
        ('single label', 'example', 'example'),
        ('numeric labels', '127.0.0.1', '127.0.0.1'),
        ('numeric final label', 'example.123', 'example.123'),
        ('label boundary', 'a' * 63 + '.example', 'a' * 63 + '.example'),
        ('host boundary', longest, longest),
        ('empty', '', None), ('root', '.', None),
        ('empty label', 'example..com', None), ('leading dot', '.example.com', None),
        ('two trailing dots', 'example.com..', None),
        ('underscore', 'under_score.example', None), ('space', 'bad host.example', None),
        ('newline', 'example.com\n', None), ('port', 'example.com:443', None),
        ('URL', 'https://example.com/', None), ('wildcard', '*.example.com', None),
        ('label overflow', 'a' * 64 + '.example', None), ('host overflow', longest + 'a', None),
        ('empty A label', 'xn--.example', None),
        ('ASCII only A label', 'xn--abc-.example', None),
        ('invalid Punycode', 'xn--0.example', None),
        ('disallowed decoded point', 'xn--a.example', None),
        ('decoded joiner violation', 'xn--ab-j1t.example', None),
        ('decoded bidi violation', 'xn--a-zhc.example', None),
        ('Unicode 16 U label', '\u1c89.example', 'xn--d4f.example'),
        ('Unicode 16 A label', 'xn--d4f.example', 'xn--d4f.example'),
        ('Unicode 17 U label excluded', '\U0001e6c0.example', None),
        ('Unicode 17 A label excluded', 'xn--uv5h.example', None),
    ]
    host_cases = [{'name': name, 'input': value, 'canonical': canonical,
                   'expected': 'well_formed' if value == canonical else 'WIST1-E14'}
                  for name, value, canonical in hosts]
    cases = []
    for host in host_cases:
        for field in ('domain', 'subdomain_scope'):
            inner = variant(**{field: host['input'] if field == 'domain' else [host['input']]})
            cases.append({'name': field + ' ' + host['name'], 'host_case': host['name'], 'field': field,
                          'envelope': sign_envelope('publisher', inner, KID1),
                          'expected': 'initial' if host['expected'] == 'well_formed' else 'WIST1-E14'})
    conflicts = json.loads((WIST1 / 'declaration-conflicts.json').read_text())
    epochs = []

    def add_epoch(name, prefix, members, expected, domains=None):
        history = conflicts['prefixes'][prefix]
        entries = sorted(map(recovery_order_entry, members), key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
        instant = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc) + datetime.timedelta(hours=len(history))
        epoch, epoch_leaves = seal('test-log-k1', priv, prefix_leaves(history), entries, len(history),
                                   instant.isoformat().replace('+00:00', 'Z'))
        epochs.append({'name': name, 'prefix': prefix, 'epoch': epoch,
                       'pinned_head': root_token(epoch_leaves), 'expected': expected,
                       'expected_domains': sorted(domains) if domains is not None else None})

    for case in cases:
        add_epoch(case['name'], 'empty', [case['envelope']],
                  'accepted' if case['expected'] == 'initial' else 'WIST1-E14',
                  [case['envelope']['publisher']['domain']] if case['expected'] == 'initial' else None)
    initial = sign_envelope('publisher', publisher, KID1)
    other = sign_envelope('publisher', variant(domain='other.example'), KID1)
    for spelling in ('EXAMPLE.com', 'example.com.'):
        alias = sign_envelope('publisher', variant(domain=spelling), KID1)
        add_epoch('canonical and alternate ' + spelling, 'empty', [initial, alias, other], 'WIST1-E14')
    upper_idn = sign_envelope('publisher', variant(domain='bücher.example'), KID1)
    canonical_idn = sign_envelope('publisher', variant(domain='xn--bcher-kva.example'), KID1)
    add_epoch('U label and A label identity', 'empty', [upper_idn, canonical_idn], 'WIST1-E14')
    add_epoch('canonical duplicate identity', 'empty', [canonical_idn, canonical_idn], 'accepted', ['xn--bcher-kva.example'])
    sibling = sign_envelope('publisher', variant(domain='xn--bcher-kva.example', contact='other'), KID1)
    add_epoch('canonical identity conflicts', 'empty', [canonical_idn, sibling], 'WIST1-E08')
    add_epoch('distinct canonical identities', 'empty', [initial, canonical_idn, other], 'accepted',
              ['example.com', 'xn--bcher-kva.example', 'other.example'])
    for prefix in ('initial', 'open', 'deadline'):
        history = conflicts['prefixes'][prefix]
        current = initial if prefix == 'initial' else next(
            entry['body'] for epoch in history for entry in epoch['entries']
            if entry['body']['publisher']['seq'] == (1 if prefix == 'deadline' else 2))
        malformed = dict(current['publisher'], subdomain_scope=['EXAMPLE.com'])
        bad = sign_envelope('publisher', malformed, KID1)
        add_epoch(prefix + ' field before conflict and settlement', prefix, [current, bad, other], 'WIST1-E14')
        add_epoch(prefix + ' canonical acceptance twin', prefix, [current, other], 'accepted',
                  ['example.com', 'other.example'])
    write_json(WIST1 / 'declaration-hosts.json', {
        'note': 'WIST-1 sections 2 and 5.1 signed Canonical Host representation. Host cases distinguish '
                'canonicalization from signed spelling eligibility. Every Declaration case has a valid '
                'author signature but only expected initial cases have valid host fields. Each candidate '
                'Epoch appends to its named authenticated prefix. Rejection preserves all state and the '
                'accepted head, including due recovery settlement. These fixtures do not establish full '
                'Unicode mapping coverage, RFC 3339 eligibility, discovery, live service validation or '
                'Snapshot recovery. Single label host acceptance asserts no suffix policy.',
        'author_key': b64u(pub_raw), 'log_key': conflicts['log_key'], 'recovery_window_days': 7,
        'declaration_activation_epochs': 0,
        'hosts': host_cases, 'cases': cases, 'prefixes': conflicts['prefixes'], 'epoch_cases': epochs})


declaration_host_vectors()

# ------------------------------ WIST-1 §5.2: the Key Set at a sealing height
# The ordinary resolution rule over key identifiers alone: a Delta sealed at height N
# verifies under the highest-seq Declaration sealed at a height <= N, the
# Epoch's own Declarations included (WIST-3 §3.3 applies them first). The
# recovery exception is exercised by recovery-settlement.json.
def keyset_at(declarations, height):
    applicable = [d for d in declarations if d["height"] <= height]
    if not applicable:
        return []
    return max(applicable, key=lambda d: d["seq"])["keys"]


def keyset_case(name, declarations, deltas, why):
    verifies = [d["delta_id"] for d in deltas
                if d["signer"] in keyset_at(declarations, d["height"])]
    rejected = [d["delta_id"] for d in deltas if d["delta_id"] not in verifies]
    heights = sorted({d["height"] for d in deltas} | {d["height"] for d in declarations})
    return {"name": name, "declarations": declarations, "deltas": deltas,
            "expected": {"key_set_at": [{"height": h, "keys": keyset_at(declarations, h)}
                                        for h in heights],
                         "verifies": verifies, "rejected": rejected},
            "why": why}


ROTATION = [{"label": "genesis", "seq": 0, "height": 1, "keys": ["k1"]},
            {"label": "rotation", "seq": 1, "height": 5, "keys": ["k2"]}]
keyset_cases = [
    keyset_case(
        "rotation retiring the old key",
        ROTATION,
        [{"delta_id": "d-below", "height": 4, "signer": "k1"},
         {"delta_id": "d-beside-old", "height": 5, "signer": "k1"},
         {"delta_id": "d-beside-new", "height": 5, "signer": "k2"},
         {"delta_id": "d-above-old", "height": 6, "signer": "k1"},
         {"delta_id": "d-above-new", "height": 6, "signer": "k2"}],
        "§5.2: the Key Set at height N is the highest-seq Declaration sealed "
        "at or below N, so a Delta signed by the retired key verifies below "
        "the rotation's Epoch and nowhere at or above it — the Epoch's own "
        "Declaration applies first (WIST-3 §3.3) — while the new key "
        "verifies from that Epoch onward."),
    keyset_case(
        "rotation keeping the old key",
        [{"label": "genesis", "seq": 0, "height": 1, "keys": ["k1"]},
         {"label": "rotation", "seq": 1, "height": 5, "keys": ["k1", "k2"]}],
        [{"delta_id": "d-beside-old", "height": 5, "signer": "k1"},
         {"delta_id": "d-above-old", "height": 9, "signer": "k1"}],
        "§5.2: a rotation that carries the old key forward retires nothing, "
        "and Deltas under it verify at every height."),
    keyset_case(
        "before the first declaration",
        ROTATION,
        [{"delta_id": "d-orphan", "height": 0, "signer": "k1"}],
        "§5.2, WIST-3 §3.3: no Declaration is sealed at or below the Delta's "
        "height, so no Key Set applies and the Delta does not verify — the "
        "Declaration must seal before or beside the first Delta it "
        "authorizes."),
]

write_json(WIST1 / "keyset-at-height.json", {
    "note": ("WIST-1 §5.2 historical verification, ordinary case, over key identifiers "
             "alone: `declarations` carry seq, sealing height and keys; each "
             "Delta carries its sealing height and signer. `expected.key_set_at` "
             "is the Key Set resolved at each height present, `verifies` and "
             "`rejected` (WIST1-E02) the Deltas by that resolution. The recovery "
             "exception is exercised by recovery-settlement.json."),
    "cases": keyset_cases,
})
print("wist1 keyset-at-height vector written")

# --------------------------------------- WIST-1 §4: the verification profile
# RFC 8032 §5.1.7 leaves the cofactor, the reduction of `s` and the treatment
# of small-order and non-canonically-encoded points to the verifier. §4 pins
# all of them, and these cases are the ones that separate the pinned profile
# from the permissive readings: each rejected case verifies under at least one
# conforming-with-RFC-8032 implementation that skipped one of §4's checks.
def ed25519_sign(seed: bytes, msg: bytes, published_a: bytes | None = None):
    h = ed25519_curve._sha512(seed)
    buf = bytearray(h[:32])
    buf[0] &= 0xF8
    buf[31] &= 0x7F
    buf[31] |= 0x40
    a = ed25519_curve.string_to_int(bytes(buf))
    prefix = h[32:]
    a_bytes = published_a or ed25519_curve.point_to_string(ed25519_curve._mul(a, ed25519_curve.BASE))
    r = ed25519_curve.string_to_int(ed25519_curve._sha512(prefix, msg)) % ed25519_curve.Q
    r_bytes = ed25519_curve.point_to_string(ed25519_curve._mul(r, ed25519_curve.BASE))
    k = ed25519_curve.string_to_int(ed25519_curve._sha512(r_bytes, a_bytes, msg)) % ed25519_curve.Q
    s = (r + k * a) % ed25519_curve.Q
    return a_bytes, r_bytes + ed25519_curve.int_to_string(s, 32)

def ed25519_check(a_bytes: bytes, msg: bytes, sig: bytes, cofactored: bool) -> bool:
    """The RFC 8032 §5.1.7 equation, with and without the cofactor."""
    r_bytes, s_bytes = sig[:32], sig[32:]
    s = ed25519_curve.string_to_int(s_bytes)
    if s >= ed25519_curve.Q and not cofactored:
        return False
    try:
        a_pt = ed25519_curve.string_to_point(a_bytes)
        r_pt = ed25519_curve.string_to_point(r_bytes)
    except ed25519_curve.InvalidProof:
        return False
    k = ed25519_curve.string_to_int(ed25519_curve._sha512(r_bytes, a_bytes, msg)) % ed25519_curve.Q
    lhs = ed25519_curve._mul(s % ed25519_curve.Q if cofactored else s, ed25519_curve.BASE)
    rhs = ed25519_curve._add(r_pt, ed25519_curve._mul(k, a_pt))
    if cofactored:
        lhs, rhs = ed25519_curve._mul(8, lhs), ed25519_curve._mul(8, rhs)
    return ed25519_curve._equal(lhs, rhs)

def order_eight_point():
    """A point of order exactly 8: [L]P for a P outside the prime-order group."""
    for y in range(2, 500):
        try:
            pt = ed25519_curve.string_to_point(ed25519_curve.int_to_string(y, 32))
        except ed25519_curve.InvalidProof:
            continue
        t = ed25519_curve._mul(ed25519_curve.Q, pt)
        if ed25519_curve._is_identity(t) or ed25519_curve._is_identity(ed25519_curve._mul(4, t)):
            continue
        if ed25519_curve._is_identity(ed25519_curve._mul(8, t)):
            return t
    raise AssertionError("no order-8 point found")

ED_MSG = b"WIST-1 verification profile vector"
T8 = order_eight_point()
T8_BYTES = ed25519_curve.point_to_string(T8)
NONCANONICAL_ONE = ed25519_curve.int_to_string(ed25519_curve.P + 1, 32)   # decodes to y = 1
BASE_A, BASE_SIG = ed25519_sign(SEED, ED_MSG)

# A published key carrying a torsion component: the signature below satisfies
# the cofactored equation and fails the cofactorless one, which is the single
# case that separates the two readings on otherwise well-formed inputs.
TORSION_A = ed25519_curve.point_to_string(
    ed25519_curve._add(ed25519_curve.string_to_point(BASE_A), T8))
_, TORSION_SIG = ed25519_sign(SEED, ED_MSG, published_a=TORSION_A)

unreduced_sig = BASE_SIG[:32] + ed25519_curve.int_to_string(
    ed25519_curve.string_to_int(BASE_SIG[32:]) + ed25519_curve.Q, 32)

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
write_json(EXAMPLES / "feed.json", sign_envelope("feed", feed, KID1))
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

# ---------------------------------------------- WIST-2 §12: text extraction
# Extraction fixtures exercise the scan (comments, raw-text elements, tags
# as boundaries, quote-aware `>`, bare `<`, character references, whitespace
# collapse) of the recommended derivation.
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

write_json(WIST2V / "text-extraction.json", {
    "note": ("WIST-2 §12's whole-document text extraction over raw HTML "
             "octets. html_hex decodes to the exact input; expected is the "
             "text the recommended derivation produces."),
    "extraction": TEXT_FIXTURES,
})
print("wist2 text-extraction vector:", [c["label"] for c in TEXT_FIXTURES])

# ------------------------------- WIST-2 §3.2: the Key Set a sealed Page verifies under
# Over key identifiers alone: a Page verifies under the Key Set current at its
# generated_at — the Declaration with the greatest sealed_at not later than
# it — or, where that Key Set lacks the signer, under the first Declaration
# sealed after generated_at. Declarations here are all applicable (the
# recovery exception is exercised by wist1/recovery-settlement.json).
def page_keyset_current(declarations, generated_at_s):
    at_or_before = [d for d in declarations if d["sealed_at_s"] <= generated_at_s]
    return max(at_or_before, key=lambda d: (d["sealed_at_s"], d["seq"]))["keys"] \
        if at_or_before else []


def page_keyset_next(declarations, generated_at_s):
    """§3.2: the Key Set of the first Epoch after generated_at sealing a
    Declaration of the domain — the highest seq's where it seals several,
    the Key Set WIST-1 §5.2 resolves at that height."""
    after = [d for d in declarations if d["sealed_at_s"] > generated_at_s]
    if not after:
        return []
    first_s = min(d["sealed_at_s"] for d in after)
    return max((d for d in after if d["sealed_at_s"] == first_s),
               key=lambda d: d["seq"])["keys"]


def page_case(name, declarations, pages, why):
    resolved = []
    for pg in pages:
        current = page_keyset_current(declarations, pg["generated_at_s"])
        nxt = page_keyset_next(declarations, pg["generated_at_s"])
        under = ("current" if pg["signer"] in current
                 else "next" if pg["signer"] in nxt else None)
        resolved.append({"page": pg["page"], "current_keys": current,
                         "next_keys": nxt, "verifies_under": under,
                         "verifies": under is not None})
    return {"name": name, "declarations": declarations, "pages": pages,
            "expected": resolved, "why": why}


PAGE_DECLS = [{"label": "genesis", "seq": 0, "sealed_at_s": 100, "keys": ["k1"]},
              {"label": "rotation", "seq": 1, "sealed_at_s": 200, "keys": ["k2"]},
              {"label": "second rotation", "seq": 2, "sealed_at_s": 300, "keys": ["k3"]}]
page_cases = [
    page_case(
        "page cut after its declaration sealed",
        PAGE_DECLS,
        [{"page": 0, "generated_at_s": 250, "signer": "k2"},
         {"page": 1, "generated_at_s": 250, "signer": "k1"}],
        "§3.2: the Key Set current at generated_at is the rotation's, so its "
        "key verifies and the retired key does not — the retired key was "
        "current at no instant at or after the rotation sealed."),
    page_case(
        "page cut between a rotation and its sealing",
        PAGE_DECLS,
        [{"page": 0, "generated_at_s": 150, "signer": "k2"},
         {"page": 1, "generated_at_s": 150, "signer": "k1"},
         {"page": 2, "generated_at_s": 150, "signer": "k3"}],
        "§3.2: the Publisher rotated to k2 and cut a Page before an Aggregator "
        "sealed the rotation; k2 is in the first Declaration sealed after "
        "generated_at, so the Page verifies; k1 was current; k3 belongs to the "
        "second Declaration after, which the rule never reaches."),
    page_case(
        "page cut before first contact",
        PAGE_DECLS,
        [{"page": 0, "generated_at_s": 50, "signer": "k1"},
         {"page": 1, "generated_at_s": 50, "signer": "k2"}],
        "§3.2: no Declaration is sealed at or before generated_at, so the first "
        "Declaration sealed after it — the domain's own seq-0 Declaration — "
        "is what a Page cut before first contact resolves to."),
    page_case(
        "generated_at equal to a sealing instant",
        PAGE_DECLS,
        [{"page": 0, "generated_at_s": 200, "signer": "k2"},
         {"page": 1, "generated_at_s": 200, "signer": "k1"},
         {"page": 2, "generated_at_s": 200, "signer": "k3"}],
        "§3.2: \"not later than\" is inclusive, so a Page whose generated_at "
        "equals the rotation's sealed_at is current under the rotation; the "
        "retired key is under neither resolution, and the next Declaration "
        "after 200 is the second rotation, whose key k3 therefore verifies."),
    page_case(
        "two rotations sealed in one epoch",
        [{"label": "genesis", "seq": 0, "sealed_at_s": 100, "keys": ["k1"]},
         {"label": "rotation", "seq": 1, "sealed_at_s": 200, "keys": ["k2"]},
         {"label": "second rotation", "seq": 2, "sealed_at_s": 200, "keys": ["k3"]}],
        [{"page": 0, "generated_at_s": 150, "signer": "k3"},
         {"page": 1, "generated_at_s": 150, "signer": "k2"},
         {"page": 2, "generated_at_s": 200, "signer": "k3"},
         {"page": 3, "generated_at_s": 200, "signer": "k2"}],
        "§3.2: one Epoch seals seq 1 and seq 2, so both resolutions read the "
        "Epoch's Key Set — the highest seq's, as WIST-1 §5.2 resolves it at "
        "that height. k3 verifies under next for a Page cut before the Epoch "
        "and under current for one cut at its instant; k2 was the Key Set at "
        "no instant and verifies under neither."),
]

write_json(WIST2V / "page-keyset.json", {
    "note": ("WIST-2 §3.2 Key Set resolution for a sealed Page, over key identifiers "
             "alone: `declarations` carry seq, sealing instant and keys, every "
             "one applicable; each Page carries generated_at and signer. Each "
             "`expected` row gives the Key Set current at generated_at, that "
             "of the first Epoch after it sealing a Declaration (the highest "
             "seq's where it seals several), and which of the two the Page "
             "verifies under (`current`, `next`, or null for WIST2-E04)."),
    "cases": page_cases,
})
print("wist2 page-keyset vector written")

def page_binding_vectors():
    def binding(key, excluded=False):
        return jwk(bytes(32) if excluded else raw_public(key), "2099-01-01T00:00:00Z")

    anchor = binding(priv)
    histories = {}
    for name, bindings in {
        "rotated": [binding(priv2), binding(priv3), binding(priv4)],
        "excluded": [binding(priv2, True), binding(priv3), binding(priv4)],
    }.items():
        sources = []
        previous = None
        for seq, key in enumerate(bindings):
            body = dict(wist_version="1.0.0", domain="example.com", seq=seq,
                        keys=[anchor, key])
            if previous:
                body["prev_declaration"] = decl_hash(previous["publisher"])
            envelope = sign_envelope_with(priv, "publisher", body, KID1)
            sources.append(dict(sealed_at=f"2026-08-09T{12 + seq:02}:00:00Z", envelope=envelope))
            previous = envelope
        histories[name] = sources

    probes = []
    def probe(name, history, identifier, key, expected, cut="2026-08-09T12:30:00Z"):
        body = dict(wist_version="1.0.0", domain="example.com", generated_at=cut,
                    deltas=[], next=None)
        probes.append(dict(name=name, history=history,
                           envelope=sign_envelope_with(key, "feed", body, identifier),
                           expected=expected))

    excluded_kid = kid_of(bytes(32))
    probe("incoming key uses first next named entry", "rotated", KID3, priv3, "next")
    probe("current key verifies current", "rotated", KID2, priv2, "current")
    probe("unlisted identifier cannot borrow a listed key", "rotated", KID5, priv2, "WIST2-E04")
    probe("key from a later Epoch cannot supply authority", "rotated", KID4, priv4, "WIST2-E04")
    probe("incoming key is current at exact seal", "rotated", KID3, priv3, "current", "2026-08-09T13:00:00Z")
    probe("retired key cannot verify at exact seal", "rotated", KID2, priv2, "WIST2-E04", "2026-08-09T13:00:00Z")
    probe("incoming key before first contact is too late", "rotated", KID3, priv3, "WIST2-E04", "2026-08-09T11:00:00Z")
    probe("first contact resolves original entry", "rotated", KID2, priv2, "next", "2026-08-09T11:00:00Z")
    probe("invalid signature under a named entry rejects", "rotated", KID3, priv4, "WIST2-E04")
    probe("anchor key verifies current", "rotated", KID1, priv, "current")
    probe("excluded current entry permits first next", "excluded", KID3, priv3, "next")
    probe("excluded current entry cannot borrow later key", "excluded", KID4, priv4, "WIST2-E04")
    probe("excluded entry supplies no authority under its own identifier", "excluded", excluded_kid, priv2, "WIST2-E04")
    probe("current succeeds without a following Declaration", "rotated", KID4, priv4, "current", "2026-08-09T15:00:00Z")
    probe("retired key fails without a following Declaration", "rotated", KID3, priv3, "WIST2-E04", "2026-08-09T15:00:00Z")
    return dict(note="WIST-2 §3.2 named-entry verification over signed ordinary Declaration chains. "
                "Sealing positions are supplied inputs, without Epoch inclusion or recovery proofs. "
                "Empty Delta lists isolate signature/source selection; these are not publication or "
                "Page-size fixtures. Future nbf values distinguish Pages from Delta filtering.",
                histories=histories, probes=probes)


write_json(WIST2V / "page-bindings.json", page_binding_vectors())

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

# ---------------------------------------------------------------- WIST-3: epoch
WIST3 = ROOT / "vectors" / "wist3"
WIST3.mkdir(parents=True, exist_ok=True)

def attest_delta(n: int, prev_id: str) -> dict:
    inner = {
        "wist_version": "1.0.0",
        "publisher": "example.com",
        "url": f"https://example.com/blog/post-{n}",
        "change_type": "attest",
        "observed_at": "2026-08-02T12:00:00Z",
        "prev": prev_id,
        "meta": {"lang": "en"},
    }
    return sign_envelope("delta", inner, KID1)

# prev IDs for the attest deltas: synthetic prior deltas ("new" for each URL)
def synthetic_prior_id(n: int) -> str:
    inner = {
        "wist_version": "1.0.0",
        "publisher": "example.com",
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
# attest chains reference each other inside the Epoch, so leaf-hash order
# and chain order impose no conflicting demand on this vector.
entries.sort(key=lambda e: leaf_hash(rfc8785.dumps(e)))

leaves = [leaf_hash(rfc8785.dumps(e)) for e in entries]
n01 = node_hash(leaves[0], leaves[1])
n23 = node_hash(leaves[2], leaves[3])
root_bytes = node_hash(n01, n23)
epoch_hash = "sha256:" + root_bytes.hex()

LOG_ID = anchor["log_id"]
checkpoint_text = checkpoint_note(LOG_ID, priv, 4, root_bytes, 0, "2026-08-02T13:00:00Z")
(EXAMPLES / "checkpoint.txt").write_text(checkpoint_text)

epoch = {"checkpoint": checkpoint_text, "entries": entries}

inclusion_proof = {"index": 0, "tree_size": len(entries),
                   "path": [h.hex() for h in audit_path(0, leaves)]}

tile_0 = tile_bytes(tile_hashes(leaves, 0))
entry_bundle = entry_bundle_bytes([rfc8785.dumps(e) for e in entries])
consistency_0_4 = consistency_proof(0, 4, leaves)
assert consistency_0_4 == []

write_json(WIST3 / "epoch.json", {
    "note": "WIST-3 Appendix A. The Log's static surface (§6) for its tree at size 4: "
            "the Checkpoint, the level-0 partial tile, the entry bundle, and the empty "
            "Consistency Proof from the empty tree (size 0) to size 4.",
    "log_id": LOG_ID,
    "checkpoint": checkpoint_text,
    "entries": entries,
    "tree_size": 4,
    "root": epoch_hash,
    "leaf_hashes": [h.hex() for h in leaves],
    "tile_0_000_p_4": tile_0.hex(),
    "tile_0_000_p_4_path": tile_path(0, 0, 4),
    "entry_bundle_000_p_4": entry_bundle.hex(),
    "entry_bundle_000_p_4_path": tile_path("entries", 0, 4),
    "consistency_proof_0_to_4": [h.hex() for h in consistency_0_4],
})
write_json(WIST3 / "inclusion-proof.json", inclusion_proof)

# ------------------------------------------- WIST-3 §3.2, §4: the empty Epoch
# A heartbeat Epoch carries no Entries, and §3.2 requires the Log to keep
# sealing on cadence when nothing arrives: Epoch 1's Checkpoint restates
# Epoch 0's tree size and root one cadence later. Every tree size in this
# suite, the empty tree (before Epoch 0) included, is exactly RFC 6962's —
# there is no deviation to contrast it with.
epoch_1_checkpoint = checkpoint_note(LOG_ID, priv, 4, root_bytes, 1, "2026-08-02T14:00:00Z")
consistency_4_4 = consistency_proof(4, 4, leaves)
assert consistency_4_4 == []
write_json(WIST3 / "empty-epoch.json", {
    "note": "WIST-3 §3.2, §4: Epoch 1 of vectors/wist3/epoch.json's example Log is empty "
            "— nothing eligible — so its Checkpoint restates the previous tree size and "
            "root, one cadence later. The empty tree before Epoch 0 has size 0 and root "
            "SHA-256(\"\") (RFC 6962 §2.1); the Consistency Proof from size 4 to size 4 is "
            "the equality of the two roots.",
    "empty_tree_size": 0,
    "empty_tree_root": "sha256:" + EMPTY_ROOT.hex(),
    "epoch_0_root": epoch_hash,
    "epoch_1": {"checkpoint": epoch_1_checkpoint, "entries": []},
    "consistency_proof_4_to_4": [h.hex() for h in consistency_4_4],
})

# ----------------------------------- WIST-3 §§4-6, 8-10: Checkpoint vectors
# One cumulative tree over the Appendix A Log: Epoch 0 (leaves 0-3, this
# file's `epoch`/`leaves`/`root_bytes`), Epoch 1 (empty, `epoch_1_checkpoint`),
# Epoch 2 (leaves 4-6, three more Entries, below). Hourly `sealed_at`.
entries2 = [{"type": "publisher_delta", "body": attest_delta(n, synthetic_prior_id(n))}
           for n in (5, 6, 7)]
entries2.sort(key=lambda e: leaf_hash(rfc8785.dumps(e)))
epoch2, leaves2 = seal(LOG_ID, priv, leaves, entries2, 2, "2026-08-02T15:00:00Z")
checkpoint2 = epoch2["checkpoint"]
consistency_4_7 = consistency_proof(4, 7, leaves2)
assert consistency_4_7, "the 4-to-7 proof must carry at least one node to be worth altering"
altered_4_7 = list(consistency_4_7)
altered_4_7[0] = bytes([altered_4_7[0][0] ^ 1]) + altered_4_7[0][1:]

def witness_keypair(name: str):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("wist witness " + name).encode()).digest())

witness_a, witness_b, witness_outsider = (
    witness_keypair("witness-a.example"), witness_keypair("witness-b.example"),
    witness_keypair("witness-outsider.example"))  # trusted by no roster below
WITNESS_T = nbf_at("2026-08-02T15:00:00Z")

def bad_cosignature_line(name: str, key, checkpoint_text: str, timestamp: int) -> str:
    """Same construction as `cosignature_line`, with the signature bytes
    flipped — a known-Witness-key line that fails to verify, for §5's
    known-key rejection rule."""
    kid = witness_key_id(name, raw_public(key))
    message = "cosignature/v1\ntime %d\n%s" % (timestamp, note_text_only(checkpoint_text))
    sig = bytearray(key.sign(message.encode()))
    sig[0] ^= 0xFF
    payload = kid + timestamp.to_bytes(8, "big") + bytes(sig)
    return "— %s %s\n" % (name, base64.b64encode(payload).decode())

# §5 note-form cases: a positive control (Epoch 0's Checkpoint) with one
# field at a time broken, plus two `valid` cases carrying a signature line
# under a signer this check's roster does not know.
_base_lines = note_text_only(epoch["checkpoint"]).rstrip("\n").split("\n")
_sig_block = epoch["checkpoint"].split("\n\n", 1)[1]

def _note(lines) -> str:
    return "\n".join(lines) + "\n\n" + _sig_block

def _with_sealed_at(value: str) -> str:
    lines = list(_base_lines); lines[4] = "sealed_at " + value
    return _note(lines)

def _with_epoch_number_line(value: str) -> str:
    lines = list(_base_lines); lines[3] = value
    return _note(lines)

def signed_note(note_text: str) -> str:
    """The Log's signature line over arbitrary note text (WIST-3 §5), for
    the root-hash-line cases below: re-signing the mutation leaves the
    parse rule under test as the only ground for rejection."""
    kid = note_key_id(LOG_ID, raw_public(priv))
    return note_text + "\n— %s %s\n" % (
        LOG_ID, base64.b64encode(kid + priv.sign(note_text.encode())).decode())

def with_root_line(value: str) -> str:
    lines = list(_base_lines); lines[2] = value
    return signed_note("\n".join(lines) + "\n")

def broken_signature(checkpoint_text: str) -> str:
    """The same Checkpoint with the last octet of its Log signature flipped:
    a signature line naming a known key that does not verify (WIST-3 §5)."""
    text, block = checkpoint_text.split("\n\n", 1)
    prefix = "— %s " % LOG_ID
    assert block.startswith(prefix), "the Log's signature is not the first line"
    blob = bytearray(base64.b64decode(block[len(prefix):].strip()))
    blob[-1] ^= 0xFF
    return text + "\n\n" + prefix + base64.b64encode(bytes(blob)).decode() + "\n"

def unknown_signature_line(name: str, checkpoint_text: str) -> str:
    """A signature line over a Checkpoint's note text under a key no roster
    in this file knows, in the [signed-note] form WIST-3 §5 fixes."""
    return "— %s %s\n" % (name, base64.b64encode(
        note_key_id(name, raw_public(priv5))
        + priv5.sign(note_text_only(checkpoint_text).encode())).decode())

_sig_fails_block = broken_signature(epoch["checkpoint"]).split("\n\n", 1)[1]

unknown_signer_line = unknown_signature_line("unknown-signer.example", checkpoint2)
outsider_cosignature_line = cosignature_line("witness-outsider.example", witness_outsider, checkpoint2, WITNESS_T)

# §5's four parse points: the root hash line is the base64 of exactly 32
# octets and re-encodes to itself, every signature line ends in a newline,
# a key name is non-empty and free of Unicode space and `+`, and a note
# carries at most 16 signature lines.
B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_root_line = _base_lines[2]
_root_tail = B64_ALPHABET.index(_root_line[42])
assert _root_tail % 4 == 0, "a 32-octet root's last base64 character carries two unused bits"
_root_trailing_bits = _root_line[:42] + B64_ALPHABET[_root_tail + 1] + "="
assert base64.b64decode(_root_trailing_bits) == root_bytes
assert base64.b64encode(root_bytes).decode() != _root_trailing_bits
_root_unpadded = _root_line.rstrip("=")
assert len(_root_unpadded) == 43

_unknown_lines = [unknown_signature_line("unknown-signer-%02d.example" % i, checkpoint2)
                  for i in range(1, 17)]

note_form_cases = [
    {"name": "six-line note text", "checkpoint": _note(_base_lines + ["extra_field 1"]),
     "expected": "WIST3-E03"},
    {"name": "four-line note text", "checkpoint": _note(_base_lines[:-1]),
     "expected": "WIST3-E03"},
    {"name": "epoch_number with a leading zero", "checkpoint": _with_epoch_number_line("epoch_number 01"),
     "expected": "WIST3-E03"},
    {"name": "epoch_number with two spaces", "checkpoint": _with_epoch_number_line("epoch_number  0"),
     "expected": "WIST3-E03"},
    {"name": "sealed_at with fractional seconds", "checkpoint": _with_sealed_at("2026-08-02T13:00:00.5Z"),
     "expected": "WIST3-E03"},
    {"name": "origin not equal to the log_id", "checkpoint": _note(["not-" + LOG_ID] + _base_lines[1:]),
     "expected": "WIST3-E03"},
    {"name": "known-key signature fails",
     "checkpoint": "\n".join(_base_lines) + "\n\n" + _sig_fails_block, "expected": "WIST3-E03"},
    {"name": "extra signature line from an unknown signer",
     "checkpoint": with_signature_lines(checkpoint2, unknown_signer_line), "expected": "valid"},
    {"name": "cosignature line from a Witness not in the roster",
     "checkpoint": with_signature_lines(checkpoint2, outsider_cosignature_line), "expected": "valid"},
    {"name": "root hash line decoding to 31 octets",
     "checkpoint": with_root_line(base64.b64encode(root_bytes[:31]).decode()),
     "expected": "WIST3-E03"},
    {"name": "root hash line decoding to 33 octets",
     "checkpoint": with_root_line(base64.b64encode(root_bytes + root_bytes[:1]).decode()),
     "expected": "WIST3-E03"},
    {"name": "root hash line with nonzero trailing bits",
     "checkpoint": with_root_line(_root_trailing_bits), "expected": "WIST3-E03"},
    {"name": "root hash line without its base64 padding",
     "checkpoint": with_root_line(_root_unpadded), "expected": "WIST3-E03"},
    {"name": "final signature line without its terminating newline",
     "checkpoint": epoch["checkpoint"][:-1], "expected": "WIST3-E03"},
    {"name": "signature line whose key name contains a plus",
     "checkpoint": with_signature_lines(
         checkpoint2, unknown_signature_line("unknown+signer.example", checkpoint2)),
     "expected": "WIST3-E03"},
    {"name": "signature line whose key name carries a no-break space",
     "checkpoint": with_signature_lines(
         checkpoint2, unknown_signature_line("unknown signer.example", checkpoint2)),
     "expected": "WIST3-E03"},
    {"name": "signature line whose key name is empty",
     "checkpoint": with_signature_lines(checkpoint2, unknown_signature_line("", checkpoint2)),
     "expected": "WIST3-E03"},
    {"name": "note carrying 16 signature lines",
     "checkpoint": with_signature_lines(checkpoint2, *_unknown_lines[:15]), "expected": "valid"},
    {"name": "note carrying 17 signature lines",
     "checkpoint": with_signature_lines(checkpoint2, *_unknown_lines), "expected": "WIST3-E03"},
]

consistency_cases = [
    {"name": "0 to 4 (empty tree)", "m": 0, "n": 4, "m_root": root_token([]), "n_root": root_token(leaves),
     "path": [h.hex() for h in consistency_0_4], "expected": "valid"},
    {"name": "4 to 4 (equal roots)", "m": 4, "n": 4, "m_root": root_token(leaves), "n_root": root_token(leaves),
     "path": [], "expected": "valid"},
    {"name": "4 to 7", "m": 4, "n": 7, "m_root": root_token(leaves), "n_root": root_token(leaves2),
     "path": [h.hex() for h in consistency_4_7], "expected": "valid"},
    {"name": "4 to 7 with one node altered", "m": 4, "n": 7, "m_root": root_token(leaves),
     "n_root": root_token(leaves2), "path": [h.hex() for h in altered_4_7], "expected": "WIST3-E02"},
    {"name": "0 to 4 with a size-0 root other than SHA-256(\"\")", "m": 0, "n": 4,
     "m_root": root_token(leaves), "n_root": root_token(leaves2), "path": [],
     "note": "WIST-3 §4: the empty proof exempts no root from comparison. The "
             "root reconstructed at size 0 is SHA-256(\"\"), so a stated size-0 "
             "root that is some other tree's root fails the Consistency Proof "
             "from size 0 as any root mismatch does.",
     "expected": "WIST3-E02"},
]

# WIST-3 §4, §5: the same rule where the size-0 root is a validly signed
# Checkpoint's own. Epoch 0 of a Log states size 0 before any Entry is
# sealed; a Checkpoint stating size 0 with another root is signed chain
# divergence, and the one Checkpoint is the whole evidence.
size_zero_cases = [
    {"name": "size-0 Checkpoint stating the empty-tree root",
     "checkpoint": checkpoint_note(LOG_ID, priv, 0, EMPTY_ROOT, 0, "2026-08-02T12:00:00Z"),
     "expected": "valid"},
    {"name": "size-0 Checkpoint stating another tree's root",
     "checkpoint": checkpoint_note(LOG_ID, priv, 0, root_bytes, 0, "2026-08-02T12:00:00Z"),
     "expected": "WIST3-E02"},
]

ROLLBACK_EQUIVOCATING = checkpoint_note(LOG_ID, priv, 4, root_bytes, 1, "2026-08-02T14:30:00Z")

rollback_cases = [
    {"name": "lower Checkpoint identical to the one verified at its epoch_number",
     "verified_head_epoch_number": 2, "verified_checkpoint": epoch_1_checkpoint,
     "offered_checkpoint": epoch_1_checkpoint, "expected": "not_adopted"},
    {"name": "lower Checkpoint never retained",
     "verified_head_epoch_number": 2, "verified_checkpoint": None,
     "offered_checkpoint": epoch_1_checkpoint, "expected": "not_adopted"},
    {"name": "lower Checkpoint whose note text differs from the one verified at its epoch_number",
     "verified_head_epoch_number": 2, "verified_checkpoint": epoch_1_checkpoint,
     "offered_checkpoint": ROLLBACK_EQUIVOCATING, "expected": "WIST3-E02"},
]

_equiv_a_entries = [{"type": "publisher_delta", "body": attest_delta(n, synthetic_prior_id(n))}
                    for n in (105, 106, 107, 108)]
_equiv_a_entries.sort(key=lambda e: leaf_hash(rfc8785.dumps(e)))
_equiv_a_leaves = [leaf_hash(rfc8785.dumps(e)) for e in _equiv_a_entries]
_equiv_a_checkpoint = checkpoint_note(LOG_ID, priv, 4, merkle_tree_root(_equiv_a_leaves), 7,
                                      "2026-08-02T16:00:00Z")
_equiv_b_checkpoint = checkpoint_note(LOG_ID, priv, 4, root_bytes, 0, "2026-08-02T13:30:00Z")
_equiv_c_entries = [{"type": "publisher_delta", "body": attest_delta(n, synthetic_prior_id(n))}
                    for n in (205, 206, 207, 208, 209, 210, 211)]
_equiv_c_entries.sort(key=lambda e: leaf_hash(rfc8785.dumps(e)))
_equiv_c_leaves = [leaf_hash(rfc8785.dumps(e)) for e in _equiv_c_entries]
_equiv_c_checkpoint = checkpoint_note(LOG_ID, priv, 7, merkle_tree_root(_equiv_c_leaves), 8,
                                      "2026-08-02T17:00:00Z")

equivocation_cases = [
    {"form": "same tree size, different root", "checkpoint_1": epoch["checkpoint"],
     "checkpoint_2": _equiv_a_checkpoint, "expected": "WIST3-E02"},
    {"form": "same epoch_number, same size and root, different sealed_at",
     "checkpoint_1": epoch["checkpoint"], "checkpoint_2": _equiv_b_checkpoint, "expected": "WIST3-E02"},
    {"form": "different sizes, no Consistency Proof between them", "checkpoint_1": epoch["checkpoint"],
     "checkpoint_2": _equiv_c_checkpoint, "leaf_hashes_2": [h.hex() for h in _equiv_c_leaves],
     "expected": "WIST3-E02"},
]

archive_cases = [
    {"name": "epoch_number 0 filed under the size-4 Epoch's own path, wrong path for the Log",
     "path": "/log/checkpoints/000000001", "checkpoint": epoch["checkpoint"], "expected": "WIST3-E03"},
    {"name": "epoch_number 2 filed under its own path", "path": "/log/checkpoints/000000002",
     "checkpoint": checkpoint2, "expected": "valid"},
]

witness_roster = {"witness-a.example": b64u(raw_public(witness_a)),
                  "witness-b.example": b64u(raw_public(witness_b))}

_line_a = cosignature_line("witness-a.example", witness_a, checkpoint2, WITNESS_T)
_line_a_again = cosignature_line("witness-a.example", witness_a, checkpoint2, WITNESS_T + 60)
_line_b = cosignature_line("witness-b.example", witness_b, checkpoint2, WITNESS_T)
_line_a_bad = bad_cosignature_line("witness-a.example", witness_a, checkpoint2, WITNESS_T)

quorum_cases = [
    {"name": "quorum 2, one trusted cosignature: short of quorum", "quorum": 2,
     "checkpoint": with_signature_lines(checkpoint2, _line_a), "expected": "not_adopted"},
    {"name": "quorum 2, two distinct trusted cosignatures: adopted", "quorum": 2,
     "checkpoint": with_signature_lines(checkpoint2, _line_a, _line_b),
     "expected": "valid", "unwitnessed": False},
    {"name": "quorum 2, two cosignatures under the same trusted name: counts once", "quorum": 2,
     "checkpoint": with_signature_lines(checkpoint2, _line_a, _line_a_again), "expected": "not_adopted"},
    {"name": "quorum 1, one cosignature that fails to verify", "quorum": 1,
     "checkpoint": with_signature_lines(checkpoint2, _line_a_bad),
     "note": "WIST-3 §5 defines a known key as the union of valid Aggregator "
             "keys and trusted Witness keys, and requires WIST3-E03 rejection "
             "of the whole Checkpoint when a line naming a known key fails to "
             "verify — read here to cover a failing trusted-Witness line too, "
             "not just a failing Aggregator line.",
     "expected": "WIST3-E03"},
    {"name": "quorum 0, no cosignature: adopted and unwitnessed", "quorum": 0,
     "checkpoint": checkpoint2, "expected": "valid", "unwitnessed": True},
]

# WIST-3 §3.1: how the table's rules fail between two consecutive
# Checkpoints. Epoch 2's Checkpoint is the verified head throughout; each
# case offers one higher Checkpoint. EPOCH_CADENCE_SECONDS is the grid
# every `sealed_at` in this file lands on (WIST-4 §5's Registry default).
EPOCH_CADENCE_SECONDS = 3600
root2_bytes = merkle_tree_root(leaves2)
assert nbf_at("2026-08-02T15:00:00Z") % EPOCH_CADENCE_SECONDS == 0

checkpoint3_empty = checkpoint_note(LOG_ID, priv, 7, root2_bytes, 3, "2026-08-02T16:00:00Z")
checkpoint4_empty = checkpoint_note(LOG_ID, priv, 7, root2_bytes, 4, "2026-08-02T17:00:00Z")
_seq_sealed_equal = checkpoint_note(LOG_ID, priv, 7, root2_bytes, 3, "2026-08-02T15:00:00Z")
_seq_sealed_earlier = checkpoint_note(LOG_ID, priv, 7, root2_bytes, 3, "2026-08-02T14:00:00Z")
_seq_sealed_off_grid = checkpoint_note(LOG_ID, priv, 7, root2_bytes, 3, "2026-08-02T15:30:00Z")
assert nbf_at("2026-08-02T15:30:00Z") % EPOCH_CADENCE_SECONDS

# A tree size below the head's, once under a root that is not the head
# tree's prefix root at that size — §5's third Equivocation form — and once
# under the prefix root itself, where no Consistency Proof is missing.
_seq_below_entries = [{"type": "publisher_delta", "body": attest_delta(n, synthetic_prior_id(n))}
                      for n in (305, 306, 307, 308, 309)]
_seq_below_entries.sort(key=lambda e: leaf_hash(rfc8785.dumps(e)))
_seq_below_root = merkle_tree_root([leaf_hash(rfc8785.dumps(e)) for e in _seq_below_entries])
_seq_prefix_root = merkle_tree_root(leaves2[:5])
assert _seq_below_root != _seq_prefix_root
_seq_below = checkpoint_note(LOG_ID, priv, 5, _seq_below_root, 3, "2026-08-02T16:00:00Z")
_seq_below_prefix = checkpoint_note(LOG_ID, priv, 5, _seq_prefix_root, 3, "2026-08-02T16:00:00Z")
_seq_below_off_grid = checkpoint_note(LOG_ID, priv, 5, _seq_below_root, 3, "2026-08-02T15:30:00Z")

sequence_cases = [
    {"name": "empty Epoch one cadence after the verified head",
     "verified_head_epoch_number": 2, "verified_checkpoint": checkpoint2,
     "offered_checkpoint": checkpoint3_empty, "signature_verifies": True,
     "expected": "valid", "expected_head_epoch_number": 3},
    {"name": "Checkpoint N+2 offered while Checkpoint N+1 is unobtainable",
     "verified_head_epoch_number": 2, "verified_checkpoint": checkpoint2,
     "offered_checkpoint": checkpoint4_empty, "unobtainable_epoch_number": 3,
     "signature_verifies": True, "expected": "WIST3-E01",
     "expected_head_epoch_number": 2,
     "note": "WIST-3 §3.1: a gap is never an object a Consumer holds. The "
             "offered Checkpoint parses and its signature verifies; the "
             "unobtainable Checkpoint 3 is the WIST3-E01, and nothing of "
             "Epoch 3 or Epoch 4 is applied."},
    {"name": "sealed_at equal to the previous Checkpoint's",
     "verified_head_epoch_number": 2, "verified_checkpoint": checkpoint2,
     "offered_checkpoint": _seq_sealed_equal, "signature_verifies": True,
     "expected": "WIST3-E03", "expected_head_epoch_number": 2},
    {"name": "sealed_at equal to the previous Checkpoint's, signature not verifying",
     "verified_head_epoch_number": 2, "verified_checkpoint": checkpoint2,
     "offered_checkpoint": broken_signature(_seq_sealed_equal), "signature_verifies": False,
     "expected": "WIST3-E03", "expected_head_epoch_number": 2},
    {"name": "sealed_at earlier than the previous Checkpoint's",
     "verified_head_epoch_number": 2, "verified_checkpoint": checkpoint2,
     "offered_checkpoint": _seq_sealed_earlier, "signature_verifies": True,
     "expected": "WIST3-E03", "expected_head_epoch_number": 2},
    {"name": "sealed_at off the epoch_cadence_seconds grid",
     "verified_head_epoch_number": 2, "verified_checkpoint": checkpoint2,
     "offered_checkpoint": _seq_sealed_off_grid, "signature_verifies": True,
     "expected": "WIST3-E03", "expected_head_epoch_number": 2},
    {"name": "tree size below the previous Checkpoint's, validly signed",
     "verified_head_epoch_number": 2, "verified_checkpoint": checkpoint2,
     "offered_checkpoint": _seq_below, "signature_verifies": True,
     "expected": "WIST3-E02", "expected_head_epoch_number": 2,
     "evidence": ["verified_checkpoint", "offered_checkpoint", "larger_tree_leaf_hashes"],
     "larger_tree_leaf_hashes": [h.hex() for h in leaves2]},
    {"name": "tree size below the previous Checkpoint's under that tree's prefix root, validly signed",
     "verified_head_epoch_number": 2, "verified_checkpoint": checkpoint2,
     "offered_checkpoint": _seq_below_prefix, "signature_verifies": True,
     "expected": "WIST3-E03", "expected_head_epoch_number": 2,
     "larger_tree_leaf_hashes": [h.hex() for h in leaves2],
     "note": "WIST-3 §3.1: the smaller size alone is WIST3-E03. The offered "
             "root is the root of Checkpoint 2's tree at size 5, so no "
             "Consistency Proof between the two is missing and §5's third "
             "Equivocation form does not apply."},
    {"name": "tree size below the previous Checkpoint's, signature not verifying",
     "verified_head_epoch_number": 2, "verified_checkpoint": checkpoint2,
     "offered_checkpoint": broken_signature(_seq_below), "signature_verifies": False,
     "expected": "WIST3-E03", "expected_head_epoch_number": 2,
     "larger_tree_leaf_hashes": [h.hex() for h in leaves2]},
    {"name": "off-grid sealed_at and a tree size below the previous Checkpoint's, validly signed",
     "verified_head_epoch_number": 2, "verified_checkpoint": checkpoint2,
     "offered_checkpoint": _seq_below_off_grid, "signature_verifies": True,
     "expected": "WIST3-E02", "expected_head_epoch_number": 2,
     "evidence": ["verified_checkpoint", "offered_checkpoint", "larger_tree_leaf_hashes"],
     "larger_tree_leaf_hashes": [h.hex() for h in leaves2],
     "note": "WIST-3 §3.1: a Checkpoint failing more than one of these "
             "rules is WIST3-E02 where the Equivocation form applies. This "
             "one is off the grid and states a smaller tree under a root "
             "that is not the prefix root, so the off-grid WIST3-E03 does "
             "not displace the evidence."},
]

# WIST-3 §8 steps 4-5: the state file against the manifest, then the
# manifest against the Checkpoint the manifest's `epoch_number` selects.
cold_start_cases = [
    {"name": "manifest matches the archived Checkpoint",
     "manifest": {"epoch_number": 2, "tree_size": 7, "root_hash": root_token(leaves2)},
     "state_tree_size": 7, "checkpoint": checkpoint2, "expected": "valid",
     "expected_head_epoch_number": 2},
    {"name": "manifest naming an empty Epoch restating the previous tree size and root",
     "manifest": {"epoch_number": 3, "tree_size": 7, "root_hash": root_token(leaves2)},
     "state_tree_size": 7, "checkpoint": checkpoint3_empty, "expected": "valid",
     "expected_head_epoch_number": 3},
    {"name": "manifest tree_size does not match",
     "manifest": {"epoch_number": 2, "tree_size": 4, "root_hash": root_token(leaves2)},
     "state_tree_size": 4, "checkpoint": checkpoint2, "expected": "WIST3-E02",
     "expected_head_epoch_number": None},
    {"name": "manifest root_hash does not match",
     "manifest": {"epoch_number": 2, "tree_size": 7, "root_hash": root_token(leaves)},
     "state_tree_size": 7, "checkpoint": checkpoint2, "expected": "WIST3-E02",
     "expected_head_epoch_number": None},
    {"name": "archive file at the manifest's path stating another epoch_number",
     "manifest": {"epoch_number": 2, "tree_size": 7, "root_hash": root_token(leaves2)},
     "state_tree_size": 7, "checkpoint": epoch_1_checkpoint, "expected": "WIST3-E03",
     "expected_head_epoch_number": None,
     "note": "WIST-3 §8 step 5: the manifest's epoch_number selects the "
             "Checkpoint and is never itself compared for divergence. The "
             "file served here states another epoch_number, and with it "
             "another tree size and root; the disposition is the source "
             "fault WIST3-E03 and a re-fetch, never WIST3-E02."},
    {"name": "state file tree_size differing from the manifest's",
     "manifest": {"epoch_number": 2, "tree_size": 7, "root_hash": root_token(leaves2)},
     "state_tree_size": 4, "checkpoint": checkpoint2, "expected": "WIST3-E04",
     "expected_head_epoch_number": None},
]

write_json(WIST3 / "checkpoints.json", {
    "note": "WIST-3 §§3.1, 4-6, 8-10: Checkpoint note form, the §3.1 "
            "sequence failures, Consistency Proofs, rollback, the three "
            "Equivocation forms, the archive path rule, "
            "Witness quorum (WIST-4 §5 checkpoint_witness_quorum), the "
            "§4 size-0 root comparison, and the "
            "§8 steps 4-5 Snapshot cold-start match, over one cumulative tree "
            "of 7 leaves (Epoch 0 of vectors/wist3/epoch.json, the empty "
            "Epoch 1 of empty-epoch.json, and Epoch 2 below). Each case list "
            "judges its own candidates: note_form_cases, sequence_cases, "
            "cold_start_cases, size_zero_cases and "
            "equivocation_cases deliberately carry Checkpoints that "
            "contradict, or continue past, the epochs above them.",
    "log_id": LOG_ID,
    "epoch_cadence_seconds": EPOCH_CADENCE_SECONDS,
    "epochs": [
        {"epoch_number": 0, "checkpoint": epoch["checkpoint"], "entries": entries,
         "leaf_hashes": [h.hex() for h in leaves]},
        {"epoch_number": 1, "checkpoint": epoch_1_checkpoint, "entries": [],
         "leaf_hashes": [h.hex() for h in leaves]},
        {"epoch_number": 2, "checkpoint": checkpoint2, "entries": entries2,
         "leaf_hashes": [h.hex() for h in leaves2]},
    ],
    "note_form_cases": note_form_cases,
    "sequence_cases": sequence_cases,
    "consistency_cases": consistency_cases,
    "rollback_cases": rollback_cases,
    "equivocation_cases": equivocation_cases,
    "archive_cases": archive_cases,
    "witness_roster": witness_roster,
    "quorum_cases": quorum_cases,
    "cold_start_cases": cold_start_cases,
    "size_zero_cases": size_zero_cases,
})
print("wist3 checkpoint vectors written")

# --------------------------------------- WIST-3 §3.4: Aggregator key acts
# Each history below is its own Log — its own Anchor, genesis key and
# cumulative tree — so no two Checkpoints of one origin in this file state
# different trees. Every Entry is a `registry_update`, so canonical Entry
# order (§3.3) is ascending leaf-hash order inside the single type group,
# and the Entry index the key-act tie-break reads is a position nobody
# chose.
KEY_ACT_GRACE_EFFECTIVE = "2026-10-01T00:00:00Z"  # > param_grace_days after every sealed_at below


def agg_key(name: str):
    """A deterministic Aggregator keypair for the key-act histories, derived
    as `witness_keypair` derives a Witness's."""
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(("wist aggregator " + name).encode()).digest())


def raw_from_b64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def aggregator_signature_line(log_id: str, key, note_text: str) -> str:
    """WIST-3 §3.4, §5: one Aggregator signature line over a Checkpoint's note
    text — `base64(note key ID || Ed25519 signature)` under the Log's origin."""
    kid = note_key_id(log_id, raw_public(key))
    return "— %s %s\n" % (log_id, base64.b64encode(kid + key.sign(note_text.encode())).decode())


def checkpoint_signed_by(log_id: str, keys: list, tree_size: int, root: bytes,
                         epoch_number: int, sealed_at: str) -> str:
    """WIST-3 §5: a Checkpoint note carrying one Aggregator signature line per
    key of `keys`; a rotation Checkpoint carries more than one."""
    text = "%s\n%d\n%s\nepoch_number %d\nsealed_at %s\n" % (
        log_id, tree_size, base64.b64encode(root).decode(), epoch_number, sealed_at)
    return text + "\n" + "".join(aggregator_signature_line(log_id, k, text) for k in keys)


def key_update(action: str, key_id: str, effective_at: str, public_key=None) -> dict:
    """WIST-4 §5.1: the `details` contract of a key act; `subject` is the
    `key_id` for both."""
    details = ({"key_id": key_id} if action == "aggregator_key_remove"
               else {"alg": "Ed25519", "key_id": key_id, "public_key": b64u(public_key)})
    return {"wist_version": "1.0.0", "action": action, "subject": key_id,
            "details": details, "effective_at": effective_at}


def parameter_update(parameter: str, value: int, effective_at: str) -> dict:
    return {"wist_version": "1.0.0", "action": "parameter_change", "subject": parameter,
            "details": {"parameter": parameter, "value": value}, "effective_at": effective_at}


def registry_entry(update: dict, signer, signer_key_id: str) -> dict:
    return {"type": "registry_update",
            "body": sign_envelope_with(signer, "update", update, signer_key_id)}


def key_acts_applied(prior: dict, log_id: str, height: int, entries: list):
    """WIST-3 §3.4 over one Epoch: authenticated key acts first, in canonical
    Entry index order, each read at height-1 and evaluated against the
    admitted set; then every other act, read at the height the accepted key
    acts leave. Each admitted key keeps the accepted Envelope that admitted
    it and the accepted Envelope that retired it — of two removals accepted
    in one Epoch, the one at the lower Entry index (§7). Returns (state after
    the Epoch, per-Entry dispositions, the key_ids valid at `height`)."""
    state = {kid: dict(entry) for kid, entry in prior.items()}
    valid_before = {kid for kid, entry in state.items() if entry["removed"] is None}
    admitted_note_ids = {note_key_id(log_id, raw_from_b64u(entry["public_key"]))
                         for entry in state.values()}
    codes = [None] * len(entries)
    for index, entry in enumerate(entries):
        update = entry["body"]["update"]
        if update["action"] not in ("aggregator_key_add", "aggregator_key_remove"):
            continue
        if entry["body"]["sig"]["key_id"] not in valid_before:
            codes[index] = "WIST4-E11"
            continue
        named = update["details"]["key_id"]
        if update["action"] == "aggregator_key_add":
            public_key = update["details"]["public_key"]
            kid = note_key_id(log_id, raw_from_b64u(public_key))
            if named in state or kid in admitted_note_ids:
                codes[index] = "WIST4-E04"
                continue
            state[named] = {"public_key": public_key, "added": height, "removed": None,
                            "adding": entry["body"], "removing": None}
            admitted_note_ids.add(kid)
        elif named not in valid_before:
            codes[index] = "WIST4-E04"
        else:
            state[named]["removed"] = height
            if state[named]["removing"] is None:
                state[named]["removing"] = entry["body"]
    valid_after = {kid for kid, entry in state.items() if entry["removed"] is None}
    for index, entry in enumerate(entries):
        if entry["body"]["update"]["action"] in ("aggregator_key_add", "aggregator_key_remove"):
            continue
        if entry["body"]["sig"]["key_id"] not in valid_after:
            codes[index] = "WIST4-E11"
    return state, codes, valid_after


def key_state_tuples(state: dict) -> list:
    """WIST-3 §7: one `aggregator_key` tuple per key ever admitted, a removed
    key carrying the sealing height of its removal, each carrying the accepted
    key acts verbatim — `null` adding act for the genesis key, `null` removing
    act while the key is valid."""
    return sorted(([["aggregator_key", kid, entry["public_key"], entry["added"], entry["removed"],
                     entry["adding"], entry["removing"]]
                    for kid, entry in state.items()]), key=lambda tuple_: tuple_[1])


def key_history(name: str, note: str, log_id: str, genesis_key_id: str, genesis_priv,
                created_at: str, privs: dict, specs: list, extra=None) -> dict:
    """One signed Log: an Anchor, then an Epoch per spec, each carrying its
    Entries in canonical order, the Checkpoint the Aggregator publishes, the
    candidate Checkpoints §5 judges beside it, and the key registry the
    replay leaves."""
    genesis_public = b64u(raw_public(genesis_priv))
    anchor_inner = {"wist_version": "1.0.0", "log_id": log_id,
                    "genesis_key": {"key_id": genesis_key_id, "alg": "Ed25519",
                                    "public_key": genesis_public},
                    "created_at": created_at}
    state = {genesis_key_id: {"public_key": genesis_public, "added": 0, "removed": None,
                              "adding": None, "removing": None}}
    valid_at = [{"height": -1, "key_ids": [genesis_key_id]}]
    leaves, epochs = [], []
    for height, spec in enumerate(specs):
        annotated = sorted(spec["entries"], key=lambda a: leaf_hash(rfc8785.dumps(a["entry"])))
        entries = [a["entry"] for a in annotated]
        applied_state, codes, valid_after = key_acts_applied(state, log_id, height, entries)
        leaves = leaves + [leaf_hash(rfc8785.dumps(e)) for e in entries]
        root = merkle_tree_root(leaves) if leaves else EMPTY_ROOT
        applied = spec.get("applied", True)
        checkpoint = (checkpoint_signed_by(log_id, [privs[k] for k in spec["signers"]],
                                           len(leaves), root, height, spec["sealed_at"])
                      if spec.get("signers") else None)
        cases = [{"name": case["name"],
                  "checkpoint": checkpoint_signed_by(log_id, [privs[k] for k in case["signers"]],
                                                     len(leaves), root, height, spec["sealed_at"]),
                  "signer_key_ids": case["signers"], "expected": case["expected"]}
                 for case in spec.get("checkpoint_cases", [])]
        acts = [{"entry_index": index,
                 "action": entries[index]["body"]["update"]["action"],
                 "subject": entries[index]["body"]["update"]["subject"],
                 "signer_key_id": entries[index]["body"]["sig"]["key_id"],
                 "code": codes[index], "why": annotated[index]["why"]}
                for index in range(len(entries))]
        epoch = {"epoch_number": height, "sealed_at": spec["sealed_at"],
                 "tree_size": len(leaves), "leaf_hashes": [h.hex() for h in leaves],
                 "entries": entries, "acts": acts, "checkpoint": checkpoint,
                 "checkpoint_cases": cases, "applied": applied,
                 "expected_state": key_state_tuples(applied_state if applied else state),
                 "why": spec["why"]}
        if spec.get("tie_breaks"):
            index_of = {rfc8785.dumps(e): i for i, e in enumerate(entries)}
            ties = []
            for tie in spec["tie_breaks"]:
                low, high = sorted(index_of[rfc8785.dumps(e)] for e in tie["entries"])
                ties.append({"reason": tie["reason"],
                             "accepted_entry_index": low,
                             "accepted_key_id": entries[low]["body"]["update"]["subject"],
                             "failed_entry_index": high,
                             "failed_key_id": entries[high]["body"]["update"]["subject"]})
            epoch["tie_breaks"] = ties
        epochs.append(epoch)
        valid_at.append({"height": height, "key_ids": sorted(valid_after)})
        if applied:
            state = applied_state
    history = {"name": name, "note": note, "log_id": log_id,
               "anchor": sign_envelope_with(genesis_priv, "anchor", anchor_inner, genesis_key_id),
               "epochs": epochs, "valid_at": valid_at,
               "verified_head": max(b["epoch_number"] for b in epochs if b["applied"])}
    history.update(extra or {})
    return history


def aggregator_key_vectors() -> dict:
    histories = []

    # ---- the rotation history: admission, removal, every key-act failure,
    # the genesis key's own removal, and equivocation judged at the height
    # the offered Checkpoint states.
    rot_id = "keys-rotation.example.org"
    material = {n: agg_key("rotation " + n) for n in
                ("k1", "k2", "k3", "k4", "k5", "k6a", "k6b", "k7", "k9", "spare-a", "spare-b")}
    K1, K2, K3, K4 = "test-agg-k1", "test-agg-k2", "test-agg-k3", "test-agg-k4"
    K5, K6, K7, K8 = "test-agg-k5", "test-agg-k6", "test-agg-k7", "test-agg-k8"
    K9, K10, K11, K12 = "test-agg-k9", "test-agg-k10", "test-agg-k11", "test-agg-k12"
    privs = {K1: material["k1"], K2: material["k2"], K3: material["k3"],
             K4: material["k4"], K5: material["k5"]}

    def add(key_id, material_name, signer_key_id, effective_at=KEY_ACT_GRACE_EFFECTIVE):
        return registry_entry(
            key_update("aggregator_key_add", key_id, effective_at,
                       raw_public(material[material_name])),
            privs[signer_key_id], signer_key_id)

    def remove(key_id, signer_key_id, effective_at=KEY_ACT_GRACE_EFFECTIVE):
        return registry_entry(key_update("aggregator_key_remove", key_id, effective_at),
                              privs[signer_key_id], signer_key_id)

    def parameter(value, signer_key_id):
        return registry_entry(parameter_update("quota_base", value, KEY_ACT_GRACE_EFFECTIVE),
                              privs[signer_key_id], signer_key_id)

    epoch0 = [
        {"entry": add(K2, "k2", K1),
         "why": "the genesis key admits a key: a key act of Epoch 0 authenticates "
                "under the keys valid at height -1, the genesis key alone"},
        {"entry": add(K3, "k3", K2),
         "why": "the key this Epoch admits signs a key act of its own Epoch, which "
                "authenticates at height -1, where it is not valid"},
        {"entry": parameter(1500, K2),
         "why": "the key this Epoch admits signs a non-key act of its own Epoch, "
                "which authenticates at height 0, where it is valid"},
    ]
    epoch1 = [
        {"entry": remove(K2, K2),
         "why": "a key signs its own removal: a key act of Epoch 1 authenticates at "
                "height 0, where the key is still valid"},
        {"entry": add(K4, "k4", K2),
         "why": "the key this Epoch removes signs another key act of the same Epoch, "
                "which authenticates at height 0"},
        {"entry": parameter(1600, K2),
         "why": "the key this Epoch removes signs a non-key act of the same Epoch, "
                "which authenticates at height 1, where it is no longer valid"},
    ]
    epoch2 = [
        {"entry": add(K2, "spare-a", K1),
         "why": "an addition naming a key_id removed at a lower height: removal is "
                "permanent and restores no validity"},
        {"entry": add(K4, "spare-b", K1),
         "why": "an addition naming a key_id currently valid"},
        {"entry": add(K10, "k4", K1),
         "why": "an addition whose note key ID equals that of a valid key: the same "
                "public key under a new key_id"},
        {"entry": add(K11, "k2", K1),
         "why": "an addition whose note key ID equals that of a removed key, which "
                "stays in the admitted set"},
        {"entry": remove(K12, K1),
         "why": "a removal naming a key_id never admitted"},
        {"entry": remove(K2, K1, "2026-10-04T00:00:00Z"),
         "why": "a removal naming a key_id already removed at a lower height; its own "
                "Registry Update ID is new, so WIST-4 §5.1's idempotence does not "
                "apply and the act is evaluated"},
        {"entry": add(K5, "k5", K1),
         "why": "the Epoch's one accepted key act: the failures beside it change no "
                "key registry state and the Epoch stays valid"},
    ]
    k6_lower, k6_upper = add(K6, "k6a", K1), add(K6, "k6b", K1)
    k7_entry, k8_entry = add(K7, "k7", K1), add(K8, "k7", K1)
    epoch3 = [
        {"entry": k6_lower, "why": "one of two additions naming key_id " + K6 +
                                   " in one Epoch; the lower Entry index is accepted"},
        {"entry": k6_upper, "why": "the other addition naming key_id " + K6 +
                                   " in one Epoch; the higher Entry index fails"},
        {"entry": k7_entry, "why": "one of two additions of one public key in one Epoch, "
                                   "a note key ID collision decided by Entry index"},
        {"entry": k8_entry, "why": "the other addition of that public key under a second "
                                   "key_id; the higher Entry index fails"},
        {"entry": add(K9, "k9", K1),
         "why": "an addition whose key this Epoch also tries to remove"},
        {"entry": remove(K9, K1),
         "why": "a removal naming a key_id added in this very Epoch, which is not "
                "valid at the previous height"},
        {"entry": remove(K4, K1, "2026-10-02T00:00:00Z"),
         "why": "the first of two removals of one valid key_id in one Epoch"},
        {"entry": remove(K4, K1, "2026-10-03T00:00:00Z"),
         "why": "the second removal of that key_id: accepted, and it changes nothing"},
    ]
    epoch4 = [
        {"entry": remove(K1, K5),
         "why": "the genesis key is removable like any other key, here by a key "
                "admitted in-band"},
    ]

    rotation = key_history(
        "rotation",
        "WIST-3 §3.4 end to end: a key admitted at Epoch 0 and removed at Epoch 1, "
        "every key-act failure the section lists, and the genesis key's own removal "
        "at Epoch 4.",
        rot_id, K1, material["k1"], "2026-08-30T12:00:00Z", privs,
        [
            {"sealed_at": "2026-09-01T00:00:00Z", "entries": epoch0, "signers": [K1, K2],
             "why": "the published Checkpoint is a rotation Checkpoint: two signature "
                    "lines, both under keys valid at height 0",
             "checkpoint_cases": [
                 {"name": "the key admitted in this Epoch signs Checkpoint 0 alone",
                  "signers": [K2], "expected": "valid"},
                 {"name": "the key whose addition did not authenticate signs Checkpoint 0",
                  "signers": [K3], "expected": "WIST3-E03"},
                 {"name": "the genesis key signs Checkpoint 0 alone",
                  "signers": [K1], "expected": "valid"},
             ]},
            {"sealed_at": "2026-09-01T01:00:00Z", "entries": epoch1, "signers": [K1],
             "why": "Checkpoint 1 authenticates under the keys valid at height 1, the "
                    "set this Epoch's accepted key acts leave",
             "checkpoint_cases": [
                 {"name": "the key removed in this Epoch signs Checkpoint 1 alone",
                  "signers": [K2], "expected": "WIST3-E03"},
                 {"name": "the key admitted in this Epoch signs Checkpoint 1 alone",
                  "signers": [K4], "expected": "valid"},
             ]},
            {"sealed_at": "2026-09-01T02:00:00Z", "entries": epoch2, "signers": [K1],
             "why": "six key-act failures beside one accepted addition: each is ignored "
                    "as WIST4-E04 and the Epoch stays valid"},
            {"sealed_at": "2026-09-01T03:00:00Z", "entries": epoch3, "signers": [K1],
             "why": "the failures an Epoch decides against itself: two additions of one "
                    "key_id, two of one public key, a removal of a key added here, and "
                    "two removals of one valid key",
             "tie_breaks": [
                 {"reason": "two additions naming one key_id",
                  "entries": [k6_lower, k6_upper]},
                 {"reason": "two additions of one public key, colliding note key IDs",
                  "entries": [k7_entry, k8_entry]},
             ]},
            {"sealed_at": "2026-09-01T04:00:00Z", "entries": epoch4, "signers": [K5],
             "why": "the genesis key is removed; Checkpoint 4 authenticates under the "
                    "keys valid at height 4, which no longer include it",
             "checkpoint_cases": [
                 {"name": "the removed genesis key signs Checkpoint 4 alone",
                  "signers": [K1], "expected": "WIST3-E03"},
                 {"name": "a valid key signs Checkpoint 4 beside the removed genesis key",
                  "signers": [K1, K5], "expected": "valid"},
             ]},
        ])

    # WIST-3 §5: a Checkpoint at or below the verified head is judged under the
    # keys valid at its own height. Both candidates state Epoch 0's tree size
    # and a different root, so only the signature decides.
    divergent_root = hashlib.sha256(("divergent tree " + rot_id).encode()).digest()
    size_0 = rotation["epochs"][0]["tree_size"]
    sealed_0 = rotation["epochs"][0]["sealed_at"]
    rotation["equivocation_cases"] = [
        {"name": "a differing Epoch 0 Checkpoint signed by a key since removed",
         "epoch_number": 0, "signer_key_ids": [K2],
         "checkpoint": checkpoint_signed_by(rot_id, [privs[K2]], size_0, divergent_root, 0, sealed_0),
         "why": "the key was valid at height 0, the height the offered Checkpoint "
                "states, and its later removal does not repudiate the signature",
         "expected": "WIST3-E02"},
        {"name": "a differing Epoch 0 Checkpoint signed by a key admitted later",
         "epoch_number": 0, "signer_key_ids": [K5],
         "checkpoint": checkpoint_signed_by(rot_id, [privs[K5]], size_0, divergent_root, 0, sealed_0),
         "why": "the key was not valid at height 0, so the Checkpoint fails §5's "
                "signature rule and is not evidence",
         "expected": "WIST3-E03"},
    ]
    # WIST-3 §7: the state a Snapshot at the head carries, and the omissions
    # §7 says do not verify. The accepted parameter_change is live state too:
    # one `parameter` tuple per amendment, keyed by identifier and
    # `effective_at`.
    head_state = rotation["epochs"][-1]["expected_state"] + [
        ["parameter", entry["body"]["update"]["subject"],
         entry["body"]["update"]["effective_at"],
         entry["body"]["update"]["details"]["value"]]
        for epoch in rotation["epochs"] if epoch["applied"]
        for act, entry in zip(epoch["acts"], epoch["entries"])
        if act["code"] is None and act["action"] == "parameter_change"]
    rotation["snapshot_state"] = {
        "tree_size": rotation["epochs"][-1]["tree_size"],
        "epoch_number": rotation["verified_head"],
        "cases": [
            {"name": "every admitted key, removed keys included", "entries": head_state,
             "why": "an aggregator_key tuple exists for every key admitted at or below "
                    "tree_size, a removed key carrying its removal height",
             "verifies": True},
            {"name": "the tuple of a key removed below the head omitted",
             "entries": [t for t in head_state if t[1] != K2],
             "why": "a resuming Consumer evaluates key-act failures against removed "
                    "keys and judges a lower Checkpoint under the keys valid at its "
                    "own height, so the tuple outlives its key",
             "verifies": False},
            {"name": "the removed genesis key's tuple omitted",
             "entries": [t for t in head_state if t[1] != K1],
             "why": "the genesis key is a key like any other once removed",
             "verifies": False},
        ]}
    histories.append(rotation)

    # ---- an Epoch whose accepted removals leave no key valid at its height.
    exh_id = "keys-exhausted.example.org"
    M1, M2 = "test-agg-m1", "test-agg-m2"
    exh = {M1: agg_key("exhausted m1"), M2: agg_key("exhausted m2")}
    histories.append(key_history(
        "keys exhausted",
        "WIST-3 §3.4: an Epoch whose accepted removals leave no key valid at its "
        "height has no valid Checkpoint and is never applied.",
        exh_id, M1, exh[M1], "2026-08-30T12:00:00Z", exh,
        [
            {"sealed_at": "2026-09-02T00:00:00Z", "signers": [M1, M2],
             "why": "the genesis key admits a second key",
             "entries": [{"entry": registry_entry(
                 key_update("aggregator_key_add", M2, KEY_ACT_GRACE_EFFECTIVE,
                            raw_public(exh[M2])), exh[M1], M1),
                 "why": "an accepted addition under the genesis key"}]},
            {"sealed_at": "2026-09-02T01:00:00Z", "signers": [], "applied": False,
             "why": "both removals authenticate at height 0 and are accepted, so no "
                    "key is valid at height 1: no Checkpoint 1 verifies, the Epoch is "
                    "never applied, and the verified head stays at Epoch 0",
             "entries": [
                 {"entry": registry_entry(key_update("aggregator_key_remove", M1,
                                                     KEY_ACT_GRACE_EFFECTIVE), exh[M1], M1),
                  "why": "the genesis key removes itself"},
                 {"entry": registry_entry(key_update("aggregator_key_remove", M2,
                                                     KEY_ACT_GRACE_EFFECTIVE), exh[M2], M2),
                  "why": "the remaining key removes itself"},
             ],
             "checkpoint_cases": [
                 {"name": "Checkpoint 1 signed by the removed genesis key",
                  "signers": [M1], "expected": "WIST3-E03"},
                 {"name": "Checkpoint 1 signed by the other removed key",
                  "signers": [M2], "expected": "WIST3-E03"},
             ]},
        ]))

    # ---- one removal and one addition in one Epoch, in both Entry orders.
    # The acts are identical apart from the addition's effective_at, which is
    # searched only to move the pair's leaf-hash order: §3.4's key set at N
    # does not depend on the order two such acts are evaluated in.
    N1, N2, N3 = "test-agg-n1", "test-agg-n2", "test-agg-n3"
    order = {N1: agg_key("order n1"), N2: agg_key("order n2"), N3: agg_key("order n3")}
    order_remove = registry_entry(
        key_update("aggregator_key_remove", N2, KEY_ACT_GRACE_EFFECTIVE), order[N2], N2)
    remove_leaf = leaf_hash(rfc8785.dumps(order_remove))
    order_adds = {}
    for minute in range(60):
        candidate = registry_entry(
            key_update("aggregator_key_add", N3, "2026-10-01T00:%02d:00Z" % minute,
                       raw_public(order[N3])), order[N2], N2)
        side = "below" if leaf_hash(rfc8785.dumps(candidate)) < remove_leaf else "above"
        order_adds.setdefault(side, candidate)
    assert set(order_adds) == {"below", "above"}, \
        "no effective_at inside the search put the addition on each side of the removal"

    for side, log_id in (("below", "keys-order-a.example.org"), ("above", "keys-order-b.example.org")):
        histories.append(key_history(
            "addition %s removal" % side,
            "WIST-3 §3.4: a key removed at Epoch 1 signs both the removal and an "
            "addition sealed beside it; this history places the addition %s the "
            "removal in canonical Entry order." % side,
            log_id, N1, order[N1], "2026-08-30T12:00:00Z", order,
            [
                {"sealed_at": "2026-09-03T00:00:00Z", "signers": [N1],
                 "why": "the genesis key admits the key that Epoch 1 removes",
                 "entries": [{"entry": registry_entry(
                     key_update("aggregator_key_add", N2, KEY_ACT_GRACE_EFFECTIVE,
                                raw_public(order[N2])), order[N1], N1),
                     "why": "an accepted addition under the genesis key"}]},
                {"sealed_at": "2026-09-03T01:00:00Z", "signers": [N1],
                 "why": "both key acts authenticate at height 0, where the removed key "
                        "is still valid, and both are accepted whichever Entry index "
                        "each holds",
                 "entries": [
                     {"entry": order_remove, "why": "the key removes itself"},
                     {"entry": order_adds[side],
                      "why": "the same key admits its successor in the same Epoch"},
                 ]},
            ]))

    return {
        "note": "WIST-3 §3.4 and §5, WIST-4 §5.1: Aggregator key acts. A key act "
                "sealed in Epoch N authenticates under the keys valid at height N-1 "
                "(the genesis key alone before Epoch 0); every other Registry Update "
                "of Epoch N and Checkpoint N authenticate under the keys valid at N. "
                "An unauthenticated act is WIST4-E11; an authenticated key act that "
                "is a key-act failure is WIST4-E04, ignored, with the Epoch kept. "
                "Each history is a separate Log with its own Anchor and cumulative "
                "tree; `epochs` are in Log order, `entries` in canonical Entry order "
                "(§3.3), `acts` carries one disposition per Entry index, "
                "`expected_state` the WIST-3 §7 aggregator_key tuples a Consumer "
                "holds after the Epoch, and `valid_at` the key_ids valid at each "
                "listed height. `checkpoint` is the Checkpoint the Aggregator "
                "publishes; `checkpoint_cases` are candidates judged beside it. "
                "The parameter_change Entries are here only to fix the "
                "authentication height of a non-key act; their §5 schedule rules are "
                "exercised by vectors/wist4/parameter-combinations.json.",
        "histories": histories,
        "same_registry_histories": ["addition below removal", "addition above removal"],
    }


write_json(WIST3 / "aggregator-keys.json", aggregator_key_vectors())
print("wist3 aggregator key vectors written")

# ---------------------------------------- WIST-3 §7: snapshot content digest
# The record tuple carries Log-derived identifiers only — no page content — so
# the digest stays computable after a Payload is withdrawn, while `delta_id`
# still pins the salted commitment that binds the content itself.
#
# Two records, so that the ordering rule is exercised. The second domain's Delta is not an Entry of the example Epoch:
# this vector demonstrates §7's record encoding, not a materialization of
# Epoch 0.
REDUCED_URL = "https://reduced.example.org/notice"
REDUCED_CONTENT = {
    "extract": "A second domain's notice.",
    "links": {"total": 0, "urls": []},
    "summary": {"title": "Notice", "abstract": "A second domain's record."},
}
reduced_canonical = rfc8785.dumps(REDUCED_CONTENT)
reduced_salt = hashlib.sha256(
    b"wist-test-salt|" + REDUCED_URL.encode()).digest()[:16]
reduced_delta = {
    "wist_version": "1.0.0",
    "publisher": "reduced.example.org",
    "url": REDUCED_URL,
    "change_type": "new",
    "observed_at": "2026-08-02T11:30:00Z",
    "payload": {"commitment": "hmac-sha256:" + hmac.new(
                    reduced_salt, reduced_canonical, hashlib.sha256).hexdigest(),
                "alg": "HMAC-SHA256", "bytes": len(reduced_canonical)},
    "meta": {"lang": "en"},
}
reduced_delta_id = "sha256:" + sha256_hex(rfc8785.dumps(reduced_delta))

RECORD_FIELDS = ["url", "publisher", "delta_id", "observed_at"]

snapshot_records = [
    {"url": DELTA_URL, "publisher": "example.com", "delta_id": delta_id,
     "observed_at": delta["observed_at"]},
    {"url": REDUCED_URL, "publisher": "reduced.example.org",
     "delta_id": reduced_delta_id,
     "observed_at": reduced_delta["observed_at"]},
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
             "Epoch; this vector publishes the record encoding, not a "
             "materialization of Epoch 0. `links` is the tier1/links.parquet "
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
    "tree_size": 0,
    "record_fields": RECORD_FIELDS,
    "records": snapshot_records,
    "content_digest": snapshot_digest,
    "links": snapshot_links,
})

# ------------------------------- WIST-3 §7: applying Deltas along their chains
# A replayer applies a sealed Delta only when its prev is the chain tip the
# state carries for (publisher, url); a fork of a sealed chain and a prev no
# lower Entry sealed are ignored alike, and an ignored Delta never becomes a
# tip (WIST-1 §3.5). Abstract ids: the rule reads prev links, not content.
CHAIN_PUB, CHAIN_URL = "example.com", "https://example.com/a"


def chain_delta(id_, prev, change_type="update", publisher=CHAIN_PUB, url=CHAIN_URL,
                eligible=True):
    delta = {"id": id_, "publisher": publisher, "url": url, "prev": prev,
             "change_type": change_type}
    if not eligible:
        delta["eligible"] = False
    return delta


def chain_replay(deltas):
    tips, ignored = {}, []
    for i, d in enumerate(deltas):
        key = (d["publisher"], d["url"])
        if not d.get("eligible", True) or d["prev"] != tips.get(key):
            ignored.append(i)
            continue
        tips[key] = d["id"]
    return ignored, [{"publisher": p, "url": u, "delta": t}
                     for (p, u), t in sorted(tips.items())]


chain_scenarios = [
    ("linear-chain",
     [chain_delta("d1", None, "new"), chain_delta("d2", "d1"), chain_delta("d3", "d2", "attest")]),
    ("fork-ignored",
     [chain_delta("d1", None, "new"), chain_delta("d2", "d1"), chain_delta("d3", "d1")]),
    ("unsealed-prev-ignored",
     [chain_delta("d1", None, "new"), chain_delta("d2", "d0")]),
    ("successor-of-an-ignored-delta-ignored",
     [chain_delta("d1", None, "new"), chain_delta("d2", "d0"), chain_delta("d3", "d2")]),
    ("chain-continues-through-delete",
     [chain_delta("d1", None, "new"), chain_delta("d2", "d1", "delete"),
      chain_delta("d3", "d2", "new")]),
    ("second-first-delta-ignored",
     [chain_delta("d1", None, "new"), chain_delta("d2", None, "new")]),
    ("publishers-chain-separately",
     [chain_delta("d1", None, "new"),
      chain_delta("e1", None, "new", publisher="www.example.com"),
      chain_delta("e2", "e1", publisher="www.example.com")]),
    ("ineligible-delta-ignored-with-its-successor",
     [chain_delta("d1", None, "new"), chain_delta("d2", "d1", eligible=False),
      chain_delta("d3", "d2")]),
    ("ineligible-first-delta-leaves-no-tip",
     [chain_delta("d1", None, "new", eligible=False), chain_delta("d2", "d1"),
      chain_delta("d3", None, "new")]),
]
chain_cases = []
for label, deltas in chain_scenarios:
    ignored, tips = chain_replay(deltas)
    chain_cases.append({"label": label, "deltas": deltas,
                        "ignored_indices": ignored, "tips": tips})
assert [c["ignored_indices"] for c in chain_cases] == \
    [[], [2], [1], [1, 2], [], [1], [], [1, 2], [0, 1]], "chain replay drifted"
write_json(WIST3 / "chain-materialization.json", spaced_labels({
    "note": ("WIST-3 §§3.3/7, WIST-1 §3.5: per case the sealed Deltas of one Log in "
             "Log order, the indices a replayer ignores, and the chain tip per "
             "(publisher, url) afterwards. A Delta marked eligible false fails a "
             "WIST-1 §7 check at its Epoch and is ignored like a fork; the Epoch "
             "stays accepted."),
    "cases": chain_cases,
}))


# ------------------------------- WIST-3 §7: one URL, one Publisher
def materialization_preference(host, self_declared, candidates):
    """The Publisher whose record a URL materializes: the self-declared host's
    own, else the nearest ancestor's, else the least non-ancestor domain."""
    if self_declared:
        return host if host in candidates else None
    ancestors = [c for c in candidates if host.endswith("." + c)]
    if ancestors:
        return max(ancestors, key=len)
    return min(candidates) if candidates else None


preference_cases = []
for label, host, self_declared, candidates in (
    ("self declaration prevails", "a.example.com", True, ["example.com", "a.example.com"]),
    ("self declaration excludes parents without an own record", "a.example.com", True, ["example.com"]),
    ("nearest ancestor", "a.b.example.com", False, ["example.com", "b.example.com"]),
    ("ancestor over non ancestor", "a.example.com", False, ["zeta.example", "example.com"]),
    ("non ancestors in octet order", "a.example.com", False, ["zeta.example", "alpha.example"]),
    ("single scoped publisher", "a.example.com", False, ["other.example"]),
    ("label boundary is not a suffix match", "a.notexample.com", False, ["example.com", "beta.example"]),
):
    preference_cases.append({"label": label, "host": host, "self_declared": self_declared,
                             "candidates": candidates,
                             "materialized": materialization_preference(host, self_declared, candidates)})
assert [c["materialized"] for c in preference_cases] == \
    ["a.example.com", None, "b.example.com", "example.com", "alpha.example", "other.example", "beta.example"], \
    "materialization preference drifted"
write_json(WIST3 / "materialization-preference.json", spaced_labels({
    "note": ("WIST-3 §7, one URL, one Publisher: candidates are the Publishers holding a live record for "
             "one URL of host at a height; self_declared says whether the host's own seq-0 Declaration "
             "Entry is sealed at or below that height. materialized names the Publisher whose record the "
             "Snapshot carries, null when every candidate is excluded. Which records are live is a Log "
             "question these cases do not decide."),
    "cases": preference_cases,
}))
print("wist3 chain-materialization vector: %d cases" % len(chain_cases))

# ------------------------------------------- WIST-3 §7: the state artifact
# The protocol state at tree_size, one tuple per live item, kinds and
# fields per WIST-3 §7's table. Aligned with snapshot-records above: the same
# two records (chain tips = their only Deltas) and the genesis Aggregator key.
# No `parameter`, `withdrawal` or `label` tuples: nothing is amended,
# withdrawn or labeled at height 0, and Registry defaults are not restated.
# A deleted URL keeps its chain tip (WIST-3 §7): the `delete` is the tip the
# URL's next Delta names as prev, so the state carries a `record` tuple for it
# although no content tuple exists — the tuple's keys are a superset of the
# content tuples' keys.
DELETED_URL = "https://example.com/blog/retired"
retired_new = {
    "wist_version": "1.0.0",
    "publisher": "example.com",
    "url": DELETED_URL,
    "change_type": "new",
    "observed_at": "2026-08-01T09:00:00Z",
    "payload": {"commitment": "hmac-sha256:" + hmac.new(
                    hashlib.sha256(b"wist-test-salt|" + DELETED_URL.encode()).digest()[:16],
                    rfc8785.dumps({"extract": "Retired.", "links": {"total": 0, "urls": []}}),
                    hashlib.sha256).hexdigest(),
                "alg": "HMAC-SHA256",
                "bytes": len(rfc8785.dumps({"extract": "Retired.", "links": {"total": 0, "urls": []}}))},
    "meta": {"lang": "en"},
}
retired_new_id = "sha256:" + sha256_hex(rfc8785.dumps(retired_new))
retired_delete = {
    "wist_version": "1.0.0",
    "publisher": "example.com",
    "url": DELETED_URL,
    "change_type": "delete",
    "observed_at": "2026-08-02T10:00:00Z",
    "prev": retired_new_id,
}
retired_delete_id = "sha256:" + sha256_hex(rfc8785.dumps(retired_delete))
assert all(r["url"] != DELETED_URL for r in snapshot_records), \
    "a deleted URL has no content tuple"

state_entries = [
    ["aggregator_key", "test-agg-k1", b64u(pub_raw), 0, None, None, None],
    ["record", "example.com", DELTA_URL, delta_id],
    ["record", "example.com", DELETED_URL, retired_delete_id],
    ["record", "reduced.example.org", REDUCED_URL, reduced_delta_id],
]


def state_digest_of(entries) -> str:
    """WIST-3 §7: the content_digest construction verbatim, over state tuples."""
    return "sha256:" + sha256_hex(b"".join(sorted(rfc8785.dumps(e) for e in entries)))


state_inner = {"wist_version": "1.0.0", "tree_size": 0, "entries": state_entries}
state_envelope = sign_envelope("state", state_inner, "test-agg-k1")
write_json(EXAMPLES / "snapshot-state.json", state_envelope)
state_bytes = rfc8785.dumps(state_envelope)

tier0_content = b"tier0-placeholder"
tier1_content = b"tier1-placeholder"
links_parquet_content = b"links-placeholder"
manifest = {
    "wist_version": "1.0.0",
    "snapshot_date": "2026-08-02",
    "epoch_number": 0,
    "tree_size": len(leaves),
    "root_hash": epoch_hash,
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
         "tree_size": manifest["tree_size"],
         "manifest_url": "/snapshots/%s/manifest.json" % manifest["snapshot_date"],
         "content_digest": manifest["content_digest"]},
    ],
}
write_json(EXAMPLES / "snapshot-index.json",
           sign_envelope("index", snapshot_index, "test-agg-k1"))
print("wist3 snapshot content digest:", snapshot_digest)
print("wist3 epoch hash:", epoch_hash)
print("wist3 merkle root:", epoch_hash)
print("wist3 leaves:", [l.hex() for l in leaves])
print("wist3 nodes: n01=%s n23=%s" % (n01.hex(), n23.hex()))

# ---------------- WIST-3 §3.4, §7, §8: authenticating a Snapshot's key tuples
# Its own Log — Anchor, genesis key and cumulative tree — whose Entries are key
# acts alone, so every Snapshot of it carries `aggregator_key` tuples and
# nothing else and its content_digest is the empty record set's. A case is a
# whole Snapshot: the three unsealed documents §3.4 names, the Checkpoint of
# the Epoch it is taken at, and the head the Consumer adopts, whose Checkpoint
# and intervening key acts the history supplies.
SNAPSHOT_KEY_EFFECTIVE = "2026-11-01T00:00:00Z"   # > param_grace_days after every sealed_at below
SNAPSHOT_KEY_TIER0 = b"tier0-placeholder"
SNAPSHOT_KEY_CONTENT_DIGEST = content_digest([])


def snapshot_key_vectors() -> dict:
    log_id = "snapshot-keys.example.org"
    G, B, C, D = "test-snap-g", "test-snap-b", "test-snap-c", "test-snap-d"
    X, SPARE, F = "test-snap-x", "test-snap-s", "test-snap-f"
    material = {name: agg_key("snapshot " + name)
                for name in (G, B, C, D, X, SPARE, F)}

    def add_entry(key_id, signer_key_id, effective_at=SNAPSHOT_KEY_EFFECTIVE, key_of=None):
        return registry_entry(
            key_update("aggregator_key_add", key_id, effective_at,
                       raw_public(material[key_of or key_id])),
            material[signer_key_id], signer_key_id)

    def remove_entry(key_id, signer_key_id, effective_at=SNAPSHOT_KEY_EFFECTIVE):
        return registry_entry(key_update("aggregator_key_remove", key_id, effective_at),
                              material[signer_key_id], signer_key_id)

    lower_removal = remove_entry(D, B, "2026-11-02T00:00:00Z")
    upper_removal = remove_entry(D, B, "2026-11-03T00:00:00Z")

    history = key_history(
        "rotation",
        "One Log whose Entries are key acts alone: the genesis key admits a "
        "successor at Epoch 0 and is removed at Epoch 1, two further keys are "
        "admitted at Epochs 2 and 3, and Epoch 4 accepts two removals of one "
        "key. Every Snapshot below is taken at one of these Epochs and read at "
        "one of these heights.",
        log_id, G, material[G], "2026-09-04T12:00:00Z", material,
        [
            {"sealed_at": "2026-09-05T00:00:00Z", "signers": [G, B],
             "why": "the genesis key admits the successor that signs every later "
                    "Checkpoint and unsealed document",
             "entries": [{"entry": add_entry(B, G),
                          "why": "an accepted addition under the genesis key, read at "
                                 "height -1 where the genesis key alone is valid"}]},
            {"sealed_at": "2026-09-06T00:00:00Z", "signers": [B],
             "why": "the genesis key is removed: no document a Consumer adopts a head "
                    "at or above this Epoch for verifies under it again",
             "entries": [{"entry": remove_entry(G, B),
                          "why": "the successor removes the genesis key, a key act read "
                                 "at height 0 where both are valid"}]},
            {"sealed_at": "2026-09-07T00:00:00Z", "signers": [B],
             "why": "a key admitted above the Snapshots taken at Epochs 0 and 1, which "
                    "their tuples therefore cannot name",
             "entries": [{"entry": add_entry(D, B),
                          "why": "an accepted addition under the key valid at height 1"}]},
            {"sealed_at": "2026-09-08T00:00:00Z", "signers": [B, C],
             "why": "a second key admitted above those Snapshots; a Consumer that walks "
                    "to this height learns it from this Epoch's key act",
             "entries": [{"entry": add_entry(C, B),
                          "why": "an accepted addition under the key valid at height 2"}]},
            {"sealed_at": "2026-09-09T00:00:00Z", "signers": [B],
             "why": "two removals of one valid key in one Epoch: both are accepted and "
                    "the §7 tuple carries the one at the lower Entry index",
             "entries": [
                 {"entry": lower_removal,
                  "why": "one of two removals naming " + D + " in this Epoch"},
                 {"entry": upper_removal,
                  "why": "the other removal naming " + D + "; it is accepted too and "
                         "changes no key registry state"},
             ]},
        ])

    def clone(node):
        return json.loads(json.dumps(node))

    def tuples_at(epoch_number):
        return clone(history["epochs"][epoch_number]["expected_state"])

    def tuple_of(epoch_number, key_id):
        return next(t for t in tuples_at(epoch_number) if t[1] == key_id)

    def valid_key_ids(height):
        return next(q["key_ids"] for q in history["valid_at"] if q["height"] == height)

    MEMBER = {"key_id": 1, "public_key": 2, "added": 3, "removed": 4,
              "adding": 5, "removing": 6}

    def replaced(entries, named, **members):
        out = []
        for tuple_ in entries:
            if tuple_[1] != named:
                out.append(tuple_)
                continue
            edited = list(tuple_)
            for name, value in members.items():
                edited[MEMBER[name]] = value
            out.append(edited)
        return out

    def without(entries, key_id):
        return [t for t in entries if t[1] != key_id]

    def key_tuple(key_id, public_key_of, added, removed, adding, removing):
        return ["aggregator_key", key_id, b64u(raw_public(material[public_key_of])),
                added, removed, adding, removing]

    def minted_add(key_id, public_key_of, signer_key_id, effective_at):
        """An `aggregator_key_add` Envelope no Epoch of this Log sealed. §7's
        rules read a carried act's fields and signature, never its membership:
        the heights are the state file signer's assertions."""
        return add_entry(key_id, signer_key_id, effective_at, key_of=public_key_of)["body"]

    def minted_remove(key_id, signer_key_id, effective_at):
        return remove_entry(key_id, signer_key_id, effective_at)["body"]

    def damaged(envelope):
        broken = clone(envelope)
        raw = bytearray(raw_from_b64u(broken["sig"]["value"]))
        raw[0] ^= 0xFF
        broken["sig"]["value"] = b64u(bytes(raw))
        return broken

    def signed_by(key_id, with_key=None):
        return [key_id, material[with_key or key_id]]

    def epoch_root(epoch):
        leaves_ = [bytes.fromhex(h) for h in epoch["leaf_hashes"]]
        return merkle_tree_root(leaves_) if leaves_ else EMPTY_ROOT

    def snapshot_documents(entries, epoch_number, signers, corrupt=()):
        epoch = history["epochs"][epoch_number]
        date = epoch["sealed_at"][:10]
        state = sign_envelope_with(signers["state"][1], "state",
                                   {"wist_version": "1.0.0", "tree_size": epoch["tree_size"],
                                    "entries": entries}, signers["state"][0])
        if "state" in corrupt:
            state = damaged(state)
        octets = rfc8785.dumps(state)
        manifest_inner = {
            "wist_version": "1.0.0", "snapshot_date": date, "epoch_number": epoch_number,
            "tree_size": epoch["tree_size"],
            "root_hash": "sha256:" + epoch_root(epoch).hex(),
            "content_digest": SNAPSHOT_KEY_CONTENT_DIGEST,
            "state": {"path": "state.json", "sha256": sha256_hex(octets),
                      "bytes": len(octets), "state_digest": state_digest_of(entries)},
            "files": [{"path": "tier0/index.sqlite", "sha256": sha256_hex(SNAPSHOT_KEY_TIER0),
                       "bytes": len(SNAPSHOT_KEY_TIER0), "tier": 0}],
        }
        manifest = sign_envelope_with(signers["manifest"][1], "manifest", manifest_inner,
                                      signers["manifest"][0])
        if "manifest" in corrupt:
            manifest = damaged(manifest)
        index_inner = {
            "wist_version": "1.0.0", "updated_at": date + "T12:00:00Z",
            "snapshots": [{"snapshot_date": date, "tree_size": epoch["tree_size"],
                           "manifest_url": "/snapshots/%s/manifest.json" % date,
                           "content_digest": SNAPSHOT_KEY_CONTENT_DIGEST}]}
        index = sign_envelope_with(signers["index"][1], "index", index_inner,
                                   signers["index"][0])
        if "index" in corrupt:
            index = damaged(index)
        return index, manifest, state, manifest_inner["state"]["state_digest"]

    cases = []

    def case(name, why, epoch_number, adopted_head, entries=None, signers=None,
             corrupt=(), checkpoint=None, consumer_registry=None,
             tuple_rules=(), catch_up=(), unsealed=(), self_consistent=None):
        entries = tuples_at(epoch_number) if entries is None else entries
        chosen = {"index": signed_by(B), "manifest": signed_by(B), "state": signed_by(B)}
        chosen.update(signers or {})
        index, manifest, state, digest = snapshot_documents(
            entries, epoch_number, chosen, corrupt)
        rejected = bool(tuple_rules) or bool(catch_up) or bool(unsealed)
        record = {
            "name": name, "why": why, "log": history["name"],
            "epoch_number": epoch_number, "adopted_head": adopted_head,
            "checkpoint": checkpoint or history["epochs"][epoch_number]["checkpoint"],
            "index": index, "manifest": manifest, "state": state,
            "state_digest": digest,
            "expected": "WIST3-E04" if rejected else "accept",
        }
        if consumer_registry is not None:
            record["consumer_registry"] = consumer_registry
        if self_consistent is not None:
            record["self_consistent"] = self_consistent
        if rejected:
            record["violations"] = {"tuple_rules": sorted(tuple_rules),
                                    "catch_up": list(catch_up),
                                    "unsealed_documents": sorted(unsealed)}
        else:
            record["key_ids_at_adopted_head"] = valid_key_ids(adopted_head)
        cases.append(record)
        return record

    # ---- resuming across a rotation.
    case("resume across a key addition",
         "the Snapshot is taken at the Epoch that admitted the key its documents "
         "are signed under, and the Consumer adopts a head two Epochs above it",
         0, 2)
    case("resume after the genesis key's removal",
         "every document is signed by the key admitted below the removal; the "
         "removed genesis key keeps its tuple, now carrying its removing act",
         1, 1)

    # ---- a Snapshot self-consistent under its own tuples and admitted by no
    # chain from the Anchor's genesis key.
    forged_self_signed = tuples_at(1) + [
        key_tuple(X, X, 0, None, minted_add(X, X, X, "2026-11-04T00:00:00Z"), None)]
    case("a forged Snapshot whose key admits itself",
         "the attacker's key is named by a tuple, its adding act is signed by "
         "itself, and every document and the Checkpoint verify under it; rule 5 "
         "asks for a signer valid at the act's height minus one, where only the "
         "genesis key is, so nothing admits the key",
         1, 1, entries=forged_self_signed,
         signers={"index": signed_by(X), "manifest": signed_by(X), "state": signed_by(X)},
         checkpoint=checkpoint_signed_by(log_id, [material[X]],
                                         history["epochs"][1]["tree_size"],
                                         epoch_root(history["epochs"][1]), 1,
                                         history["epochs"][1]["sealed_at"]),
         tuple_rules=[5], self_consistent=True)
    forged_no_act = tuples_at(1) + [key_tuple(X, X, 0, None, None, None)]
    case("a forged Snapshot whose key carries no adding act",
         "a second tuple with a `null` adding act: rule 2 admits exactly one, "
         "the Anchor's genesis key",
         1, 1, entries=forged_no_act,
         signers={"index": signed_by(X), "manifest": signed_by(X), "state": signed_by(X)},
         checkpoint=checkpoint_signed_by(log_id, [material[X]],
                                         history["epochs"][1]["tree_size"],
                                         epoch_root(history["epochs"][1]), 1,
                                         history["epochs"][1]["sealed_at"]),
         tuple_rules=[2], self_consistent=True)
    forged_genesis = [key_tuple(G, X, 0, None, None, None)]
    case("a forged Snapshot restating the genesis key's public key",
         "one tuple, naming the Anchor's genesis key_id under the attacker's "
         "public key, with every document and the Checkpoint signed under it; "
         "only rule 2's comparison against the Anchor catches it",
         0, 0, entries=forged_genesis,
         signers={"index": signed_by(G, X), "manifest": signed_by(G, X),
                  "state": signed_by(G, X)},
         checkpoint=checkpoint_signed_by(log_id, [material[X]],
                                         history["epochs"][0]["tree_size"],
                                         epoch_root(history["epochs"][0]), 0,
                                         history["epochs"][0]["sealed_at"]),
         tuple_rules=[2], self_consistent=True)

    # ---- rule 1: one key_id and one note key ID per tuple set.
    case("two tuples naming one key_id",
         "the second tuple's act names its own key_id and public key and is "
         "signed by the genesis key, so only rule 1 rejects it",
         3, 3, entries=tuples_at(3) + [
             key_tuple(D, SPARE, 0, None,
                       minted_add(D, SPARE, G, "2026-11-05T00:00:00Z"), None)],
         tuple_rules=[1])
    case("two tuples whose keys share a note key ID",
         "one public key under two key_ids: a Checkpoint signature line would "
         "name both (§3.4)",
         3, 3, entries=tuples_at(3) + [
             key_tuple(F, C, 0, None,
                       minted_add(F, C, G, "2026-11-06T00:00:00Z"), None)],
         tuple_rules=[1])

    # ---- rule 2: the tuple with no adding act is the Anchor's genesis key at 0.
    case("the genesis tuple states an added height other than 0",
         "rule 2 fixes the genesis key's added height at 0 whatever its Anchor "
         "signature proves",
         0, 0, entries=replaced(tuples_at(0), G, added=1), tuple_rules=[2])

    # ---- rule 3: the adding act names the tuple's key at a height through E.
    case("an adding act whose public_key is not the tuple's",
         "the act the genesis key signed admits another key than the tuple names",
         0, 0, entries=replaced(tuples_at(0), B,
                                public_key=b64u(raw_public(material[SPARE]))),
         signers={"index": signed_by(G), "manifest": signed_by(G), "state": signed_by(G)},
         tuple_rules=[3])
    case("an adding act whose key_id is not the tuple's",
         "the tuple renames the key the act admits",
         2, 2, entries=replaced(tuples_at(2), D, key_id=F), tuple_rules=[3])
    case("an added height above the Snapshot's Epoch",
         "a key admitted at Epoch 3 cannot be state at Epoch 2; the Consumer "
         "learns it by walking, not from a tuple",
         2, 2, entries=tuples_at(2) + [tuple_of(3, C)], tuple_rules=[3])
    case("an aggregator_key_remove carried as an adding act",
         "rule 3 reads the act's action, not only its signature",
         2, 2, entries=replaced(tuples_at(2), D,
                                adding=minted_remove(D, B, "2026-11-07T00:00:00Z")),
         tuple_rules=[3])

    # ---- rule 4: the removing act and the removed height.
    case("a removed height equal to the added height",
         "a removal is above its addition for every key but the genesis key",
         4, 4, entries=replaced(tuples_at(4), D, removed=2), tuple_rules=[4])
    case("a removed height above the Snapshot's Epoch",
         "a removal sealed at Epoch 4 is not state at Epoch 3",
         3, 3, entries=replaced(tuples_at(3), D, removed=4, removing=tuple_of(4, D)[6]),
         tuple_rules=[4])
    case("a removing act naming another key",
         "the act retires a key_id the tuple does not name",
         4, 4, entries=replaced(tuples_at(4), D,
                                removing=minted_remove(C, B, "2026-11-08T00:00:00Z")),
         tuple_rules=[4])
    case("a removing act beside a null removed height",
         "§7 makes the removing act `null` exactly when the removed height is, "
         "and rule 4's bound on the removed height has nothing to hold of `null`",
         2, 2, entries=replaced(tuples_at(2), D, removing=tuple_of(4, D)[6]),
         tuple_rules=[4])
    case("a removed height beside a null removing act",
         "the converse: a tuple asserting a removal carries the act that made it",
         4, 4, entries=replaced(tuples_at(4), D, removing=None), tuple_rules=[4])

    # ---- rule 5: every act verifies under a key the tuples make valid at h-1.
    case("an act signed by a key added at the act's own height",
         "the signer's tuple admits it at the height it signs, where §3.4 reads "
         "the previous height's keys",
         3, 3, entries=tuples_at(3) + [
             key_tuple(F, F, 3, None,
                       minted_add(F, F, C, "2026-11-09T00:00:00Z"), None)],
         tuple_rules=[5])
    case("an act signed by a key removed below the act's height",
         "the genesis key was removed at Epoch 1 and the act reads height 1",
         3, 3, entries=tuples_at(3) + [
             key_tuple(F, F, 2, None,
                       minted_add(F, F, G, "2026-11-10T00:00:00Z"), None)],
         tuple_rules=[5])
    case("an act whose signature does not verify",
         "the Envelope still passes WIST-4 §5.1's field validation, so rule 5 is "
         "the only rule that reads the signature",
         2, 2, entries=replaced(tuples_at(2), D, adding=damaged(tuple_of(2, D)[5])),
         tuple_rules=[5])

    # ---- §3.4's unsealed documents, judged at the adopted head, one document
    # at a time so that each answer names the document it came from.
    for document in ("index", "manifest", "state"):
        case("the %s signed by a key removed at the adopted head" % document,
             "the key is valid at the Snapshot's Epoch and removed at the Epoch "
             "the Consumer adopts, which the walk from the Snapshot reaches",
             0, 1, signers={document: signed_by(G)}, unsealed=[document])
        case("the %s signed by a key added above the Snapshot's Epoch" % document,
             "no tuple names the key; the Consumer authenticates it from the key "
             "acts of the Epochs it walks and it is valid at the adopted head",
             1, 3, signers={document: signed_by(C)})
        case("the %s signature failing under the key its tuple names" % document,
             "the signer is valid at the adopted head and the signature verifies "
             "at no height",
             1, 1, corrupt=[document], unsealed=[document])

    # ---- the catch-up rule: a Consumer that already holds key state.
    case("a tuple disagreeing with the Consumer's registry below its head",
         "the Consumer's registry holds the genesis key as removed, so the tuple "
         "carries that removed height and removing act or the Snapshot is "
         "rejected; this one omits the removal altogether",
         3, 3, entries=replaced(tuples_at(3), G, removed=None, removing=None),
         consumer_registry={"verified_head": 1, "entries": tuples_at(1)},
         catch_up=[{"key_id": G, "reason": "disagrees"}])
    case("a Snapshot omitting a key the Consumer's registry holds",
         "every key the registry holds has a tuple, and this key was admitted at "
         "a height the Consumer has already walked",
         3, 3, entries=without(tuples_at(3), D),
         consumer_registry={"verified_head": 2, "entries": tuples_at(2)},
         catch_up=[{"key_id": D, "reason": "omitted"}])
    case("a tuple for a key the Consumer's registry does not hold",
         "the tuple is admitted at or below the Consumer's verified head, where "
         "its own replay never saw the key; the tuples and the registry "
         "disagree about a height the Consumer has walked, whichever is wrong",
         3, 3, consumer_registry={"verified_head": 3,
                                  "entries": without(tuples_at(3), D)},
         catch_up=[{"key_id": D, "reason": "unknown"}])
    case("a Consumer registry the tuples agree with",
         "the one surplus tuple names a key admitted above the Consumer's "
         "verified head, which its registry says nothing about",
         3, 3, consumer_registry={"verified_head": 2, "entries": tuples_at(2)})

    # ---- two removals of one key accepted in one Epoch.
    accepted_case = case(
        "the tuple carries the removal at the lower Entry index",
        "the removal §7 names, and the state_digest a replaying Consumer "
        "recomputes at this tree size",
        4, 4)
    alternate_case = case(
        "the tuple carries the removal at the higher Entry index",
        "both removals were accepted, so rules 1 through 5 read this tuple as "
        "they read the one above; the state_digest is what separates them, and "
        "it is not the digest a replay leaves",
        4, 4, entries=replaced(tuples_at(4), D,
                               removing=clone(history["epochs"][4]["entries"][1]["body"])))
    epoch4 = history["epochs"][4]
    carried = tuple_of(4, D)[6]
    removal_tie_break = {
        "log": history["name"], "epoch_number": 4, "key_id": D,
        "accepted_entry_index": next(i for i, e in enumerate(epoch4["entries"])
                                     if e["body"] == carried),
        "accepted_case": accepted_case["name"],
        "accepted_state_digest": accepted_case["state_digest"],
        "alternate_case": alternate_case["name"],
        "alternate_state_digest": alternate_case["state_digest"],
        "why": "WIST-3 §7: of two removals of one key accepted in one Epoch the "
               "tuple carries the one at the lower Entry index, and rules 1 "
               "through 5 do not test which one a tuple carries. Both Envelopes "
               "satisfy those rules, and the two state files have different "
               "state_digests, so the digest a replaying Consumer rebuilds at "
               "this tree size is what falsifies the other one (`WIST3-E04`).",
    }

    mirrors_inner = {"wist_version": "1.0.0", "updated_at": "2026-09-06T12:00:00Z",
                     "mirror_urls": ["https://mirror-1.example/", "https://mirror-2.example/"]}
    mirror_cases = [
        {"name": "signed by a key valid at the adopted head",
         "why": "the list verifies, and §6.1 still lets a Consumer fetch from a "
                "source it names nothing about",
         "log": history["name"], "adopted_head": 1,
         "mirrors": sign_envelope_with(material[B], "mirrors", mirrors_inner, B),
         "authenticated": True, "error": None},
        {"name": "signed by a key removed at the adopted head",
         "why": "§5 gives an unverifiable Mirror list no error code: its entries "
                "stay location hints",
         "log": history["name"], "adopted_head": 1,
         "mirrors": sign_envelope_with(material[G], "mirrors", mirrors_inner, G),
         "authenticated": False, "error": None},
        {"name": "read before the Consumer has a head",
         "why": "§5's other unverifiable case: no adopted head means no key set "
                "to judge the signature under, and still no error code",
         "log": history["name"], "adopted_head": None,
         "mirrors": sign_envelope_with(material[B], "mirrors", mirrors_inner, B),
         "authenticated": False, "error": None},
    ]

    return {
        "note": "WIST-3 §3.4, §7 and §8: a Consumer resuming from a Snapshot "
                "authenticates the state file's `aggregator_key` tuples from the "
                "Anchor's genesis key before it uses any of them, and verifies "
                "the Snapshot index, the manifest and the state file under the "
                "keys valid at the height of the Checkpoint it adopts. `history` "
                "is one Log with its own Anchor, genesis key and cumulative "
                "tree; `epochs` are in Log order and each carries the Checkpoint "
                "the Aggregator published. A case is one Snapshot of that Log: "
                "`epoch_number` is the Epoch it is taken at, `checkpoint` the "
                "Checkpoint of that Epoch it is served with, `adopted_head` the "
                "height of the Checkpoint the Consumer adopts, and `index`, "
                "`manifest` and `state` the three unsealed documents. "
                "`expected` is `accept` with the key_ids valid at the adopted "
                "head, or `WIST3-E04`, the one code every rejection here "
                "carries. `violations` says which requirement the case "
                "isolates: the §7 rules of 1 through 5 the tuples break, the "
                "catch-up clauses `consumer_registry` falsifies — `omitted` "
                "for a key the registry holds and no tuple names, `disagrees` "
                "for a tuple contradicting the registry up to its verified "
                "head, `unknown` for a tuple the registry does not hold whose "
                "added height is not above that head — and the documents whose "
                "signatures do not verify at the adopted head. Those rule "
                "numbers and reason strings are this family's labels, not a "
                "diagnostic the protocol defines: an implementation replaying "
                "the family is compared on the accept-or-`WIST3-E04` outcome, "
                "the key_ids valid at the adopted head, and which of the three "
                "documents verify. `self_consistent` marks a Snapshot whose "
                "Checkpoint and documents all verify under the tuples it "
                "carries, so that the chain to the Anchor is the only thing "
                "rejecting it. `state_digest` is §7's digest over the case's "
                "own tuples; rules 1 through 5 test neither the sealing heights "
                "a tuple asserts nor which of two removals accepted in one "
                "Epoch it carries, and `removal_tie_break` is where the second "
                "of those is falsified instead — by the digest a replaying "
                "Consumer rebuilds. `mirror_cases` carry §5's Mirror list, "
                "which has no error code when it does not verify.",
        "history": history,
        "cases": cases,
        "removal_tie_break": removal_tie_break,
        "mirror_cases": mirror_cases,
    }


write_json(WIST3 / "snapshot-keys.json", snapshot_key_vectors())
print("wist3 snapshot key authentication vectors written")

# --------------------------------------------- WIST-4 §5.1: Registry Update
WIST4 = ROOT / "vectors" / "wist4"
WIST4.mkdir(parents=True, exist_ok=True)
HOUR_S = 3600
DAY_S = 86400

registry_update = {
    "wist_version": "1.0.0",
    "action": "parameter_change",
    "subject": "quota_base",
    "details": {"parameter": "quota_base", "value": 2000},
    "effective_at": "2026-08-09T13:00:00Z",
}
write_json(EXAMPLES / "registry-update.json",
           sign_envelope("update", registry_update, "test-agg-k1"))
print("wist4 registry-update example written")

# ------------------------------------------------------ WIST-2 §3.3: Labels
# The example Labeler is the example Publisher: one Declaration, one Key
# Set, two sequences. Its Label names a URL of another domain.
LABEL_SUBJECT = REDUCED_URL
label = {
    "wist_version": "1.0.0",
    "labeler": "example.com",
    "subject": LABEL_SUBJECT,
    "name": "wist:spam",
    "asserted_at": "2026-08-02T12:30:00Z",
}
label_id = "sha256:" + sha256_hex(rfc8785.dumps(label))
label_envelope = sign_envelope("label", label, KID1)
write_json(EXAMPLES / "label.json", label_envelope)
definition = {
    "wist_version": "1.0.0",
    "labeler": "example.com",
    "name": "wist:spam",
    "description": "https://example.com/labels/spam",
    "treatment": "hide",
    "asserted_at": "2026-08-02T12:00:00Z",
}
write_json(EXAMPLES / "label-definition.json", sign_envelope("definition", definition, KID1))

LABELER_HOST = "labels.sample.net"
labeler_declaration = sign_envelope_with(priv4, "publisher", {
    "wist_version": "1.0.0", "seq": 0, "domain": LABELER_HOST,
    "keys": [jwk(pub4_raw, "2026-08-01T00:00:00Z")]}, KID4)
disputed_label = {
    "wist_version": "1.0.0", "labeler": LABELER_HOST, "subject": "https://example.com/blog/post-1",
    "name": "wist:copied", "asserted_at": "2026-08-02T11:00:00Z",
}
disputed_label_id = "sha256:" + sha256_hex(rfc8785.dumps(disputed_label))
dispute = {
    "wist_version": "1.0.0",
    "disputant": "example.com",
    "label": disputed_label_id,
    "log": "log.example",
    "height": 1,
    "reason": "https://example.com/blog/post-1-is-original",
    "asserted_at": "2026-08-02T12:45:00Z",
}
dispute_id = "sha256:" + sha256_hex(rfc8785.dumps(dispute))
write_json(EXAMPLES / "dispute.json", sign_envelope("dispute", dispute, KID1))

label_feed = {
    "wist_version": "1.0.0",
    "domain": "example.com",
    "generated_at": "2026-08-02T12:30:00Z",
    "deltas": [label_id],
    "next": None,
}
write_json(EXAMPLES / "label-feed.json", sign_envelope("feed", label_feed, KID1))
print("wist2 label examples written:", label_id)


def publisher_instant_s(value: str):
    """A Publisher timestamp as an exact rational instant in seconds."""
    from fractions import Fraction
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})", value)
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    days = datetime.date(year, month, day).toordinal() - datetime.date(1970, 1, 1).toordinal()
    base = Fraction(days * 86400 + hour * 3600 + minute * 60 + second)
    if m.group(7):
        base += Fraction(m.group(7))
    zone = m.group(8)
    if zone not in ("Z", "z"):
        sign = 1 if zone[0] == "+" else -1
        base -= sign * (int(zone[1:3]) * 3600 + int(zone[4:6]) * 60)
    return base


def log_instant_s(value: str) -> int:
    return calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))


def label_vectors():
    cases = []

    def add(name, body=None, *, expected="accepted", signer=priv, key_id=KID1, mutate=None):
        body = dict(label) if body is None else body
        doc = sign_envelope_with(signer, "label", body, key_id)
        if mutate:
            mutate(doc)
        try:
            priv.public_key().verify(base64.urlsafe_b64decode(doc["sig"]["value"] + "=="),
                                     rfc8785.dumps(doc["label"]))
            author_signature = True
        except (KeyError, TypeError, ValueError, InvalidSignature):
            author_signature = False
        code = {"accepted": None, "fields": "WIST2-E06", "self": "WIST2-E06",
                "signature": "WIST1-E01", "binding": "WIST1-E02"}[expected]
        cases.append(dict(name=name, envelope=doc, expected=expected, code=code,
                          author_signature=author_signature,
                          label_id=("sha256:" + sha256_hex(rfc8785.dumps(doc["label"])))
                          if expected == "accepted" else None))

    add("valid Label")
    add("valid Label with a value", dict(label, value=750000))
    add("valid Label on a Canonical Host", dict(label, subject="reduced.example.org"))
    add("valid retraction", dict(label, asserted_at="2026-08-03T09:00:00Z", retracted=True))
    add("value at the floor", dict(label, value=0))
    add("value at the ceiling", dict(label, value=1000000))
    add("value above the ceiling", dict(label, value=1000001), expected="fields")
    add("negative value", dict(label, value=-1), expected="fields")
    add("fractional value", dict(label, value=0.5), expected="fields")
    add("retracted false", dict(label, retracted=False), expected="fields")
    add("unknown member", dict(label, extra=True), expected="fields")
    for field in ("wist_version", "labeler", "subject", "name", "asserted_at"):
        body = dict(label)
        del body[field]
        add("missing " + field, body, expected="fields")
    add("unsupported major", dict(label, wist_version="2.0.0"), expected="fields")
    add("later minor and patch", dict(label, wist_version="1.7.3"))
    add("name without a prefix", dict(label, name="spam"), expected="fields")
    add("name with an empty term", dict(label, name="wist:"), expected="fields")
    add("name with an uppercase term", dict(label, name="wist:Spam"), expected="fields")
    add("name outside the wist registry", dict(label, name="wist:unknown-term"), expected="fields")
    add("name under a Canonical Host prefix", dict(label, name="reduced.example.org:trusted-vendor"))
    add("name under a prefix the Labeler does not control", dict(label, name="labels.sample.net:verified"))
    add("name of 64 characters", dict(label, name="labels.sample.net:" + "a" * 46))
    add("name of 65 characters", dict(label, name="labels.sample.net:" + "a" * 47), expected="fields")
    add("subject not normalized", dict(label, subject="https://Reduced.example.org/notice"), expected="fields")
    add("subject with a fragment", dict(label, subject=LABEL_SUBJECT + "#top"), expected="fields")
    add("subject under http", dict(label, subject="http://reduced.example.org/notice"), expected="fields")
    add("subject host not canonical", dict(label, subject="Reduced.example.org"), expected="fields")
    add("subject at the url cap", dict(label, subject="https://reduced.example.org/" + "a" * (2048 - 2 - len("https://reduced.example.org/"))))
    add("subject over the url cap", dict(label, subject="https://reduced.example.org/" + "a" * (2049 - 2 - len("https://reduced.example.org/"))), expected="fields")
    add("asserted_at without a zone", dict(label, asserted_at="2026-08-02T12:30:00"), expected="fields")
    add("asserted_at with an offset", dict(label, asserted_at="2026-08-02T14:30:00+02:00"))
    add("asserted_at on a leap second", dict(label, asserted_at="2026-06-30T23:59:60Z"), expected="fields")
    add("labeler other than the authenticated domain", dict(label, labeler="reduced.example.org"), expected="fields")
    add("self-label of the domain", dict(label, subject="example.com"), expected="self")
    add("self-label of a scoped host", dict(label, subject="www.example.com"), expected="self")
    add("self-label of an own URL", dict(label, subject="https://example.com/blog/post-1"), expected="self")
    add("self-label of a scoped URL", dict(label, subject="https://blog.example.com/post"), expected="self")
    add("a host outside the declared scope", dict(label, subject="https://sub.example.com/"))
    add("a host with the domain as a prefix", dict(label, subject="https://example.com.sample.net/"))
    add("valid expiry", dict(label, expires_at="2026-09-02T12:30:00Z"))
    add("expiry with an offset instant", dict(label, expires_at="2026-08-02T14:30:01+02:00"))
    add("expiry one second after assertion", dict(label, expires_at="2026-08-02T12:30:01Z"))
    add("expiry at assertion", dict(label, expires_at="2026-08-02T12:30:00Z"), expected="fields")
    add("expiry before assertion", dict(label, expires_at="2026-08-01T12:30:00Z"), expected="fields")
    add("expiry on a leap second", dict(label, expires_at="2026-12-31T23:59:60Z"), expected="fields")
    add("expiry without a zone", dict(label, expires_at="2026-09-02T12:30:00"), expected="fields")
    add("Delta binding on a URL subject", dict(label, delta=disputed_label_id))
    add("Delta binding with an expiry", dict(label, delta=disputed_label_id, expires_at="2026-09-02T12:30:00Z"))
    add("Delta binding on a Canonical Host subject", dict(label, subject="reduced.example.org", delta=disputed_label_id),
        expected="fields")
    add("Delta binding not a Delta ID", dict(label, delta="sha256:xyz"), expected="fields")
    add("Delta binding uppercase hex", dict(label, delta=disputed_label_id.upper().replace("SHA256", "sha256")),
        expected="fields")
    add("signature over other bytes", expected="signature",
        mutate=lambda doc: doc["label"].update(asserted_at="2026-08-02T12:31:00Z"))
    add("signed by the recovery key", signer=priv2, key_id=KID2, expected="binding")
    add("signed under an unknown identifier", key_id=KID5, expected="binding")

    def sealed(asserted_at, height, entry_index, value=None, retracted=False, expires_at=None, delta=None):
        inner = dict(label, asserted_at=asserted_at)
        if value is not None:
            inner["value"] = value
        if retracted:
            inner["retracted"] = True
        if expires_at is not None:
            inner["expires_at"] = expires_at
        if delta is not None:
            inner["delta"] = delta
        return {"label": inner, "label_id": "sha256:" + sha256_hex(rfc8785.dumps(inner)),
                "height": height, "entry_index": entry_index}

    def label_tuple(chosen):
        inner = chosen["label"]
        return ["label", inner["labeler"], inner["subject"], inner["name"], inner.get("value"),
                inner["asserted_at"], inner.get("expires_at"), inner.get("delta"), chosen["label_id"],
                chosen["height"]]

    def current_case(name, items, winner, sealed_at="2026-08-03T12:00:00Z"):
        chosen = items[winner]
        expired = (chosen["label"].get("expires_at") is not None
                   and publisher_instant_s(chosen["label"]["expires_at"]) <= log_instant_s(sealed_at))
        tuple_ = None if chosen["label"].get("retracted") or expired else label_tuple(chosen)
        return {"name": name, "sealed": items, "sealed_at": sealed_at, "current": chosen["label_id"],
                "state_tuple": tuple_}

    current = [
        current_case("greatest asserted_at wins whatever sealed later",
                     [sealed("2026-08-02T12:30:00Z", 1, 0), sealed("2026-08-02T12:00:00Z", 2, 0)], 0),
        current_case("equal instants break by Epoch number",
                     [sealed("2026-08-02T12:30:00Z", 1, 0, 500000), sealed("2026-08-02T12:30:00Z", 2, 0, 700000)], 1),
        current_case("equal instants in one Epoch break by Entry index",
                     [sealed("2026-08-02T12:30:00Z", 3, 4, 500000), sealed("2026-08-02T12:30:00Z", 3, 2, 700000)], 0),
        current_case("a later retraction leaves no tuple",
                     [sealed("2026-08-02T12:30:00Z", 1, 0), sealed("2026-08-03T09:00:00Z", 2, 0, retracted=True)], 1),
        current_case("a retraction older than the assertion applies nothing",
                     [sealed("2026-08-03T09:00:00Z", 1, 0), sealed("2026-08-02T12:30:00Z", 2, 0, retracted=True)], 0),
        current_case("an offset instant compares as an instant",
                     [sealed("2026-08-02T12:30:00Z", 1, 0), sealed("2026-08-02T14:30:01+02:00", 2, 0)], 1),
        current_case("an unexpired Label keeps its tuple",
                     [sealed("2026-08-02T12:30:00Z", 1, 0, expires_at="2026-08-03T12:00:01Z")], 0),
        current_case("a Label expired at the Snapshot's Epoch leaves no tuple",
                     [sealed("2026-08-02T12:30:00Z", 1, 0, expires_at="2026-08-03T12:00:00Z")], 0),
        current_case("an expired Label is still the current one",
                     [sealed("2026-08-02T12:30:00Z", 1, 0, expires_at="2026-08-03T00:00:00Z"),
                      sealed("2026-08-02T12:00:00Z", 2, 0)], 0),
        current_case("a bound Label carries its Delta",
                     [sealed("2026-08-02T12:30:00Z", 1, 0, delta=disputed_label_id)], 0),
    ]
    binding = []
    for name, anchor, delta, applies in (
        ("bound to the live anchor", disputed_label_id, disputed_label_id, True),
        ("bound to an earlier anchor", "sha256:" + sha256_hex(b"a later publication"), disputed_label_id, False),
        ("unbound applies to any anchor", "sha256:" + sha256_hex(b"a later publication"), None, True),
        ("bound with no live record", None, disputed_label_id, False),
        ("unbound with no live record", None, None, False),
    ):
        binding.append({"name": name, "delta": delta, "record_anchor": anchor, "applies": applies})
    return dict(
        note=("WIST-2 section 3.3 and WIST-4 section 6. Field, form, self-labeling and signature cases "
              "over the example Declaration: accepted means the Label validates and its label_id seals; "
              "fields and self are WIST2-E06; signature and binding keep WIST-1 codes. current_cases "
              "replay sealed Labels of one (labeler, subject, name) and give the current Label at the "
              "end and the WIST-3 section 7 tuple the state carries, null where the current Label is "
              "retracted or expired at sealed_at, the Snapshot Epoch's instant. binding_cases read a "
              "Label's delta against the subject record's anchor Delta: a bound Label applies only "
              "while the record stands on that Delta. The clock allowance over asserted_at is "
              "exercised by wist1/delta-clock-time.json."),
        declaration=json.loads((EXAMPLES / "publisher.json").read_text()),
        url_cap_bytes=2048, cases=cases, current_cases=current, binding_cases=binding)


write_json(WIST2V / "labels.json", label_vectors())
print("wist2 labels vector written")


def dispute_vectors():
    disputant_declaration = sign_envelope_with(priv3, "publisher", {
        "wist_version": "1.0.0", "seq": 0, "domain": "reduced.example.org",
        "subdomain_scope": ["www.reduced.example.org"],
        "keys": [jwk(pub3_raw, "2026-08-01T00:00:00Z")]}, KID3)
    sealed_labels = [{"label_id": label_id, "labeler": "example.com", "subject": LABEL_SUBJECT, "height": 1}]
    base = {"wist_version": "1.0.0", "disputant": "reduced.example.org", "label": label_id,
            "log": "log.example", "height": 1, "asserted_at": "2026-08-02T13:00:00Z"}
    cases = []

    def add(name, body=None, *, expected="accepted", signer=priv3, key_id=KID3,
            declaration=disputant_declaration, mutate=None):
        body = dict(base) if body is None else body
        doc = sign_envelope_with(signer, "dispute", body, key_id)
        if mutate:
            mutate(doc)
        code = {"accepted": None, "fields": "WIST2-E06", "unsealed": "WIST2-E06",
                "authority": "WIST2-E06", "signature": "WIST1-E01", "binding": "WIST1-E02"}[expected]
        cases.append(dict(name=name, envelope=doc, declaration=declaration, expected=expected, code=code,
                          dispute_id=("sha256:" + sha256_hex(rfc8785.dumps(doc["dispute"])))
                          if expected == "accepted" else None))

    add("valid dispute")
    add("dispute with a reason", dict(base, reason="https://reduced.example.org/notice-is-original"))
    add("dispute citing another Log", dict(base, log="mirror.log.example", height=7))
    add("dispute of a Label on a scoped host", dict(base), declaration=disputant_declaration)
    add("unknown member", dict(base, extra=True), expected="fields")
    for field in ("wist_version", "disputant", "label", "log", "height", "asserted_at"):
        body = dict(base)
        del body[field]
        add("missing " + field, body, expected="fields")
    add("label not a Label ID", dict(base, label="sha256:xyz"), expected="fields")
    add("negative height", dict(base, height=-1), expected="fields")
    add("reason under http", dict(base, reason="http://reduced.example.org/x"), expected="fields")
    add("reason not normalized", dict(base, reason="https://Reduced.example.org/x"), expected="fields")
    add("log not a Canonical Host", dict(base, log="Log.Example"), expected="fields")
    add("asserted_at on a leap second", dict(base, asserted_at="2026-06-30T23:59:60Z"), expected="fields")
    add("unsupported major", dict(base, wist_version="2.0.0"), expected="fields")
    add("label the Log has not sealed", dict(base, label="sha256:" + sha256_hex(b"never sealed")),
        expected="unsealed")
    add("dispute by a third party", dict(base, disputant=LABELER_HOST), signer=priv4, key_id=KID4,
        declaration=labeler_declaration, expected="authority")
    add("disputant other than the authenticated domain", dict(base, disputant="example.com"), expected="fields")
    add("signature over other bytes", expected="signature",
        mutate=lambda doc: doc["dispute"].update(asserted_at="2026-08-02T13:00:01Z"))
    add("signed under an unknown identifier", key_id=KID5, expected="binding")

    def sealed(asserted_at, height, entry_index, reason=None):
        inner = dict(base, asserted_at=asserted_at)
        if reason is not None:
            inner["reason"] = reason
        return {"dispute": inner, "dispute_id": "sha256:" + sha256_hex(rfc8785.dumps(inner)),
                "height": height, "entry_index": entry_index}

    def current_case(name, items, winner):
        chosen = items[winner]
        inner = chosen["dispute"]
        return {"name": name, "sealed": items, "current": chosen["dispute_id"],
                "state_tuple": ["dispute", inner["label"], inner["disputant"], inner.get("reason"),
                                inner["asserted_at"], chosen["height"]]}

    current = [
        current_case("greatest asserted_at wins whatever sealed later",
                     [sealed("2026-08-02T13:30:00Z", 2, 0, "https://reduced.example.org/why"),
                      sealed("2026-08-02T13:00:00Z", 3, 0)], 0),
        current_case("equal instants break by Log order",
                     [sealed("2026-08-02T13:00:00Z", 2, 1), sealed("2026-08-02T13:00:00Z", 2, 3,
                                                                    "https://reduced.example.org/later")], 1),
    ]
    return dict(
        note=("WIST-2 section 3.3 disputes over sealed Labels: accepted means the dispute validates under "
              "the disputant's Declaration and its dispute_id seals; fields, unsealed and authority are "
              "WIST2-E06 (the named Label must be sealed in this Log and its subject must lie under the "
              "disputant's authority); signature and binding keep WIST-1 codes; log and height are the "
              "disputant's citation and are not checked against this Log. current_cases replay sealed "
              "disputes of one (label, disputant) and give the current dispute and the WIST-3 section 7 "
              "dispute tuple."),
        sealed_labels=sealed_labels, cases=cases, current_cases=current)


write_json(WIST2V / "disputes.json", dispute_vectors())
print("wist2 disputes vector written")


def definition_vectors():
    cases = []

    def add(name, body=None, *, expected="accepted", signer=priv, key_id=KID1, mutate=None):
        body = dict(definition) if body is None else body
        doc = sign_envelope_with(signer, "definition", body, key_id)
        if mutate:
            mutate(doc)
        path = None
        if expected == "accepted":
            path = "labels/definitions/" + sha256_hex(body["name"].encode("utf-8")) + ".json"
        cases.append(dict(name=name, envelope=doc, expected=expected, path=path))

    add("valid definition")
    add("warn treatment", dict(definition, treatment="warn"))
    add("inform treatment", dict(definition, treatment="inform"))
    add("definition of a Canonical Host name", dict(definition, name="example.com:trusted-vendor",
                                                     description="https://example.com/labels/trusted-vendor"))
    add("definition of a name under another prefix", dict(definition, name="labels.sample.net:verified"))
    add("unknown treatment", dict(definition, treatment="block"), expected="rejected")
    add("description under http", dict(definition, description="http://example.com/labels/spam"), expected="rejected")
    add("description not normalized", dict(definition, description="https://Example.com/labels/spam"),
        expected="rejected")
    add("name outside the wist registry", dict(definition, name="wist:unknown-term"), expected="rejected")
    add("name without a prefix", dict(definition, name="spam"), expected="rejected")
    add("unknown member", dict(definition, extra=True), expected="rejected")
    for field in ("wist_version", "labeler", "name", "description", "treatment", "asserted_at"):
        body = dict(definition)
        del body[field]
        add("missing " + field, body, expected="rejected")
    add("unsupported major", dict(definition, wist_version="2.0.0"), expected="rejected")
    add("labeler other than the authenticated domain", dict(definition, labeler="reduced.example.org"),
        expected="rejected")
    add("signature over other bytes", expected="rejected",
        mutate=lambda doc: doc["definition"].update(treatment="warn"))
    add("signed under an unknown identifier", key_id=KID5, expected="rejected")
    return dict(
        note=("WIST-2 section 3.3 label definitions over the example Declaration: accepted means a Consumer "
              "reads the definition at path under the Labeler's well-known prefix; rejected definitions "
              "supply no treatment and the Consumer falls back to inform. A definition is not sealed and "
              "carries no Aggregator code."),
        declaration=json.loads((EXAMPLES / "publisher.json").read_text()), cases=cases)


write_json(WIST2V / "label-definitions.json", definition_vectors())
print("wist2 label-definitions vector written")


def label_table_vectors():
    def entry(height, labeler, subject, name="wist:spam", retracted=False):
        return {"height": height, "labeler": labeler, "subject": subject, "name": name, "retracted": retracted}

    sealed = [
        entry(1, "example.com", "https://reduced.example.org/notice"),
        entry(1, "example.com", "https://reduced.example.org/other"),
        entry(2, "example.com", "https://reduced.example.org/notice", retracted=True),
        entry(2, "example.com", "reduced.example.org", "wist:distrust-seed"),
        entry(3, LABELER_HOST, "https://example.com/blog/post-1", "wist:copied"),
        entry(4, "example.com", "https://reduced.example.org/notice"),
    ]
    labelers = {}
    for e in sealed:
        row = labelers.setdefault(e["labeler"], {"labeler": e["labeler"], "label_count": 0, "retraction_count": 0,
                                                   "subjects": set(), "first_seen_height": e["height"]})
        row["label_count"] += 1
        row["retraction_count"] += int(e["retracted"])
        row["subjects"].add(e["subject"])
        row["first_seen_height"] = min(row["first_seen_height"], e["height"])
    statistics_rows = [{"labeler": r["labeler"], "label_count": r["label_count"],
                        "retraction_count": r["retraction_count"], "distinct_subjects": len(r["subjects"]),
                        "first_seen_height": r["first_seen_height"]}
                       for r in sorted(labelers.values(), key=lambda r: r["labeler"])]
    statistics_cases = [{"label": "four sealed Labels of one Labeler and one of another", "sealed": sealed,
                         "rows": statistics_rows}]

    def cap_case(label, entries, labeler_cap=2, domain_cap=3):
        per_labeler, per_domain = {}, {}
        for e in entries:
            per_domain[e["domain"]] = per_domain.get(e["domain"], 0) + 1
            if e["type"] in ("label", "dispute"):
                per_labeler[e["domain"]] = per_labeler.get(e["domain"], 0) + 1
        expected = None
        if max(per_domain.values()) > domain_cap:
            expected = "WIST3-E03"
        elif per_labeler and max(per_labeler.values()) > labeler_cap:
            expected = "WIST3-E03"
        return {"label": label, "labeler_epoch_entries_max": labeler_cap, "domain_epoch_entries_max": domain_cap,
                "entries": entries, "expected": expected}

    def e(kind, domain):
        return {"type": kind, "domain": domain}

    cap_cases = [
        cap_case("labels at the labeler cap", [e("label", "a.example"), e("label", "a.example")]),
        cap_case("labels over the labeler cap", [e("label", "a.example"), e("label", "a.example"), e("label", "a.example")]),
        cap_case("a dispute counts with the labels", [e("label", "a.example"), e("label", "a.example"), e("dispute", "a.example")]),
        cap_case("Deltas do not count toward the labeler cap",
                 [e("publisher_delta", "a.example"), e("label", "a.example"), e("label", "a.example")]),
        cap_case("labels and Deltas over the domain cap",
                 [e("publisher_delta", "a.example"), e("publisher_delta", "a.example"), e("label", "a.example"),
                  e("label", "a.example")]),
        cap_case("two Labelers at the cap each", [e("label", "a.example"), e("label", "a.example"),
                                                   e("label", "b.example"), e("label", "b.example")]),
    ]

    def persistence_case(label, events, probes, expires_at=None):
        outcomes = []
        for height in probes:
            def live_at(h):
                current = None
                for ev in events:
                    # WIST-2 §3.3: greatest asserted_at, and among equal
                    # instants the one later in Log order, which is the
                    # order the events are listed in.
                    if ev["height"] <= h and (current is None or ev["asserted_at"] >= current["asserted_at"]):
                        current = ev
                if current is None or current.get("retracted"):
                    return False
                if expires_at is not None and expires_at <= h:
                    return False
                return True
            outcomes.append({"height": height, "counted": live_at(height) and live_at(height - 1)})
        return {"label": label, "events": events, "expires_at_height": expires_at, "probes": outcomes}

    def ev(height, asserted_at, retracted=False):
        return {"height": height, "asserted_at": asserted_at, "retracted": retracted}

    persistence_cases = [
        persistence_case("counted from the second consecutive Epoch", [ev(5, "2026-08-02T12:00:00Z")], [4, 5, 6, 7]),
        persistence_case("a retraction stops the count",
                         [ev(5, "2026-08-02T12:00:00Z"), ev(7, "2026-08-02T13:00:00Z", True)], [5, 6, 7, 8]),
        persistence_case("re-asserted after a retraction",
                         [ev(5, "2026-08-02T12:00:00Z"), ev(6, "2026-08-02T13:00:00Z", True),
                          ev(8, "2026-08-02T15:00:00Z")], [7, 8, 9, 10]),
        persistence_case("expiry ends the count", [ev(5, "2026-08-02T12:00:00Z")], [6, 7, 8], expires_at=8),
        persistence_case("equal instants resolve in Log order",
                         [ev(5, "2026-08-02T12:00:00Z", True), ev(6, "2026-08-02T12:00:00Z")], [5, 6, 7]),
    ]
    inactivity_cases = [{"label": label, "last_sealed_height": last, "inactivity_epochs": n, "height": h,
                         "applies": h - last <= n}
                        for label, last, n, h in (("within the window", 100, 720, 820),
                                                  ("one Epoch past the window", 100, 720, 821),
                                                  ("never sealed anything since genesis", 0, 720, 721),
                                                  ("a short window", 100, 24, 124))]
    return spaced_labels({
        "note": ("WIST-3 section 7 tier1/labelers.parquet rows from sealed label Entries (statistics_cases: every "
                 "sealed Label counts, retractions included, subjects distinct, first-seen the lowest height); "
                 "WIST-3 section 3.2 and WIST-4 section 5 per-Labeler cap over label and dispute Entries "
                 "beside the per-domain cap with no suffix-list snapshot in force, so every host is its own "
                 "unit (cap_cases); WIST-4 section 6's recommended default profile: a wist:mismatch or "
                 "wist:unavailable Label counts at a height only when it was current, unretracted and "
                 "unexpired at that height and the one before (persistence_cases; expires_at_height is the "
                 "first height whose Epoch instant reaches the expiry), and a Labeler with no sealed Entry "
                 "within inactivity_epochs is ignored (inactivity_cases)."),
        "statistics_cases": statistics_cases, "cap_cases": cap_cases, "persistence_cases": persistence_cases,
        "inactivity_cases": inactivity_cases})


write_json(WIST3 / "label-tables.json", label_table_vectors())
print("wist3 label-tables vector written")

# ------------------------------------- WIST-4 §5: which amendment is in force
# effective_at is inclusive; the greatest effective_at at or before T
# prevails; an equal pair is broken by Log order (height, then Entry index).
def value_in_force(default, changes, t_s):
    live = [(i, c) for i, c in enumerate(changes) if c["effective_at_s"] <= t_s]
    if not live:
        return default, None
    i, c = max(live, key=lambda ic: (ic[1]["effective_at_s"],
                                     ic[1]["epoch_number"], ic[1]["entry_index"]))
    return c["value"], i


def param_change(epoch_number, entry_index, effective_at_s, value):
    return {"epoch_number": epoch_number, "entry_index": entry_index,
            "sealed_at_s": epoch_number * HOUR_S, "effective_at_s": effective_at_s,
            "value": value}


def param_case(label, default, changes, query_times):
    queries = []
    for t in query_times:
        value, source = value_in_force(default, changes, t)
        queries.append({"t_s": t, "value": value, "from_index": source})
    return {"label": label, "default": default, "changes": changes, "queries": queries}


GRACE_S = 7 * DAY_S
parameter_cases = [
    param_case("effective-at-is-inclusive", 3600,
               [param_change(10, 0, 10 * HOUR_S + GRACE_S, 1800)],
               [10 * HOUR_S + GRACE_S - 1, 10 * HOUR_S + GRACE_S, 10 * HOUR_S + GRACE_S + 1]),
    param_case("later-effective-at-prevails-whatever-sealed-first", 3600,
               [param_change(10, 0, 20 * DAY_S, 900),
                param_change(11, 0, 15 * DAY_S, 1800)],
               [14 * DAY_S, 15 * DAY_S, 20 * DAY_S, 25 * DAY_S]),
    param_case("equal-effective-at-across-epochs", 3600,
               [param_change(10, 0, 20 * DAY_S, 900),
                param_change(12, 0, 20 * DAY_S, 1800)],
               [20 * DAY_S - 1, 20 * DAY_S]),
    param_case("equal-effective-at-in-one-epoch", 3600,
               [param_change(10, 0, 20 * DAY_S, 900),
                param_change(10, 3, 20 * DAY_S, 1800)],
               [20 * DAY_S]),
    param_case("superseded-pair-then-a-later-amendment", 3600,
               [param_change(10, 0, 20 * DAY_S, 900),
                param_change(12, 0, 20 * DAY_S, 1800),
                param_change(30, 0, 40 * DAY_S, 600)],
               [30 * DAY_S, 40 * DAY_S]),
]

write_json(WIST4 / "parameter-in-force.json", spaced_labels({
    "note": "WIST-4 §5 value in force. changes are in Log order with sealing and effective instants; each query gives the value in force at t_s and the index of the amendment it comes from (null for the default).",
    "cases": parameter_cases,
}))
print("wist4 parameter-in-force vector written")

# ----------------------------- WIST-4 §5: the combination rules at sealing
# The rules the bounds table cannot express are checked over every
# prospective map: links_cap_bytes ≥ link_url_cap_bytes + 21 and
# mirror_retention_days × 6 ≥ payload_window_days.
PROSPECTIVE_DEFAULTS = {"links_cap_bytes": 4096, "link_url_cap_bytes": 2048,
                        "mirror_retention_days": 90, "payload_window_days": 180,
                        "labeler_epoch_entries_max": 1000, "domain_epoch_entries_max": 10000}
PROSPECTIVE_FLOORS = {"links_cap_bytes": 21, "link_url_cap_bytes": 14,
                      "mirror_retention_days": 30, "payload_window_days": 30,
                      "labeler_epoch_entries_max": 1, "domain_epoch_entries_max": 1}


def combinations_hold(values):
    return (values["links_cap_bytes"] >= values["link_url_cap_bytes"] + 21
            and values["mirror_retention_days"] * 6 >= values["payload_window_days"]
            and values["labeler_epoch_entries_max"] <= values["domain_epoch_entries_max"])


def prospective_map(changes, at_s):
    result = dict(PROSPECTIVE_DEFAULTS)
    for parameter in result:
        eligible = [c for c in changes if c["parameter"] == parameter and c["effective_at_s"] <= at_s]
        if eligible:
            chosen = max(eligible, key=lambda c: (c["effective_at_s"], c["epoch_height"], c["entry_index"]))
            result[parameter] = chosen["value"]
    return result


def prospective_acceptance(changes):
    accepted, rejected = [], []
    for i, candidate in sorted(enumerate(changes), key=lambda pair: (pair[1]["epoch_height"], pair[1]["entry_index"])):
        tentative = accepted + [candidate]
        instants = {candidate["sealed_at_s"]} | {c["effective_at_s"] for c in tentative
                                                 if c["effective_at_s"] >= candidate["sealed_at_s"]}
        valid = (candidate["value"] >= PROSPECTIVE_FLOORS[candidate["parameter"]]
                 and candidate["effective_at_s"] >= candidate["sealed_at_s"] + 7 * DAY_S)
        for instant in instants:
            valid = valid and combinations_hold(prospective_map(tentative, instant))
        if valid:
            accepted.append(candidate)
        else:
            rejected.append(i)
    return sorted(rejected), accepted


prospective_cases = []
for label, rows, rejected in (
    ("pending link cap then incompatible aggregate cap", [(0, 0, "link_url_cap_bytes", 4000, 10), (1, 0, "links_cap_bytes", 4000, 11)], [1]),
    ("later activation sealed first", [(0, 0, "links_cap_bytes", 3000, 20), (1, 0, "link_url_cap_bytes", 2990, 10)], [1]),
    ("invalid future after earlier activation", [(0, 0, "link_url_cap_bytes", 4000, 20), (1, 0, "links_cap_bytes", 3000, 10)], [1]),
    ("intermediate replacement makes schedule valid", [(0, 0, "link_url_cap_bytes", 4000, 10), (1, 0, "link_url_cap_bytes", 1000, 11), (2, 0, "links_cap_bytes", 3000, 12)], []),
    ("same effective time conflicts", [(0, 0, "link_url_cap_bytes", 4000, 10), (1, 0, "links_cap_bytes", 3000, 10)], [1]),
    ("rejected candidate is not retried", [(0, 0, "link_url_cap_bytes", 4000, 10), (1, 0, "links_cap_bytes", 3000, 10), (2, 0, "link_url_cap_bytes", 1000, 10)], [1]),
    ("canonical same Epoch order", [(0, 1, "link_url_cap_bytes", 4000, 10), (0, 0, "links_cap_bytes", 3000, 10)], [0]),
    ("invalid bound cannot hide behind replacement", [(0, 0, "links_cap_bytes", 20, 10), (1, 0, "links_cap_bytes", 4096, 10)], [0]),
    ("grace period required", [(0, 0, "links_cap_bytes", 4000, 6)], [0]),
    ("aggregate cap exactly the link cap plus its structure", [(0, 0, "links_cap_bytes", 2069, 10)], []),
    ("retention below a sixth of the window", [(0, 0, "payload_window_days", 541, 10)], [0]),
    ("retention exactly a sixth of the window", [(0, 0, "payload_window_days", 540, 10)], []),
    ("window raised after retention raised", [(0, 0, "mirror_retention_days", 120, 10), (1, 0, "payload_window_days", 720, 11)], []),
    ("retention lowered under a pending window", [(0, 0, "payload_window_days", 540, 10), (1, 0, "mirror_retention_days", 60, 10)], [1]),
    ("labeler cap above the domain cap", [(0, 0, "labeler_epoch_entries_max", 20000, 10)], [0]),
    ("labeler cap equal to the domain cap", [(0, 0, "labeler_epoch_entries_max", 10000, 10)], []),
    ("domain cap lowered under the labeler cap", [(0, 0, "domain_epoch_entries_max", 500, 10)], [0]),
    ("both caps lowered in order", [(0, 0, "labeler_epoch_entries_max", 200, 10), (1, 0, "domain_epoch_entries_max", 500, 11)], []),
    ("domain cap lowered under a pending labeler cap", [(0, 0, "labeler_epoch_entries_max", 200, 12), (1, 0, "domain_epoch_entries_max", 150, 11)], [1]),
):
    changes = [{"epoch_height": day * 24, "entry_index": index, "sealed_at_s": day * DAY_S,
                "parameter": parameter, "value": value, "effective_at_s": effective * DAY_S}
               for day, index, parameter, value, effective in rows]
    got, accepted = prospective_acceptance(changes)
    assert got == rejected, label
    instants = sorted({c["effective_at_s"] for c in changes})
    prospective_cases.append({"label": label, "changes": changes, "rejected_indices": got,
        "maps": [{"at_s": t, "values": prospective_map(accepted, t)} for t in instants]})

CLOCK_DEFAULTS = {"record_seal_epochs": 24, "recovery_window_days": 7,
                  "payload_window_days": 180, "param_grace_days": 7}


def clock_value(parameter, at_s, changes):
    eligible = [c for c in changes if c["parameter"] == parameter and c["effective_at_s"] <= at_s]
    return max(eligible, key=lambda c: c["effective_at_s"])["value"] if eligible else CLOCK_DEFAULTS[parameter]


clock_cases = []
for label, parameter, anchor, changed, value, factor, start in (
    ("discovery retains seal count", "record_seal_epochs", 10, 11, 48, 1, 200),
    ("recovery window retains length", "recovery_window_days", 10, 11, 14, 86400, 10),
    ("availability retains span", "payload_window_days", 10, 11, 360, 86400, 10),
    ("grace retains span", "param_grace_days", 10, 11, 14, 86400, 10),
    ("effective at anchor is included", "record_seal_epochs", 11, 11, 48, 1, 200),
):
    changes = [{"parameter": parameter, "effective_at_s": changed, "value": value}]
    selected_value = clock_value(parameter, anchor, changes)
    clock_cases.append({"label": label, "parameter": parameter, "anchor_s": anchor,
        "changes": changes, "query_s": 20, "unit_scale": factor, "start": start,
        "selected_value": selected_value, "endpoint": start + selected_value * factor})

parameter_wire_cases = []
for parameter, value, schema_valid, combinations_hold_at_defaults in (
    ("quota_base", 9007199254740991, True, True),
    ("quota_base", -9007199254740991, False, True),
    ("quota_base", 9007199254740992, False, True),
    ("quota_base", -9007199254740992, False, True),
    ("payload_window_days", 29, False, True),
    ("payload_window_days", 30, True, True),
    ("payload_window_days", 541, True, False),
    ("links_cap_bytes", 2000, True, False),
    ("labeler_epoch_entries_max", 0, False, True),
    ("labeler_epoch_entries_max", 20000, True, False),
    ("epoch_cadence_seconds", 86400, True, True),
    ("epoch_cap_bytes", "65537", False, True),
    ("epoch_cap_bytes", 65537.0, True, True),
):
    canonical = isinstance(value, str) or abs(value) <= 9007199254740991
    inner = {"wist_version": "1.0.0", "action": "parameter_change", "subject": parameter,
        "effective_at": "2026-08-12T00:00:00Z", "details": {"parameter": parameter, "value": value if canonical else 0}}
    envelope = sign_envelope("update", inner, "test-agg-k1")
    envelope["update"]["details"]["value"] = value
    parameter_wire_cases.append({"label": parameter + " value " + repr(value), "envelope": envelope,
        "canonical_integer": canonical, "schema_valid": schema_valid,
        "combinations_hold_at_defaults": combinations_hold_at_defaults,
        "sealed_disposition": "candidate" if schema_valid else "ignored"})
inner = {"wist_version": "1.0.0", "action": "parameter_change", "subject": "quota_base",
    "effective_at": "2026-08-12T00:00:00.5Z", "details": {"parameter": "quota_base", "value": 1}}
parameter_wire_cases.append({"label": "quota_base fractional effective_at",
    "envelope": sign_envelope("update", inner, "test-agg-k1"), "canonical_integer": True,
    "schema_valid": False, "combinations_hold_at_defaults": True, "sealed_disposition": "ignored"})

EPOCH_CAP_DEFAULT = 256 * 1024 * 1024
EPOCH_SIZE_FLOOR = 65537


def epoch_cap_at(changes, at_s):
    eligible = [c for c in changes if c["effective_at_s"] <= at_s]
    return max(eligible, key=lambda c: (c["effective_at_s"], c["epoch_height"], c["entry_index"]))["value"] if eligible else EPOCH_CAP_DEFAULT


def epoch_cap_bounds(changes, at_s):
    values = [epoch_cap_at(changes, t) for t in {at_s} | {c["effective_at_s"] for c in changes if c["effective_at_s"] >= at_s}]
    return min(values), max(values)


def epoch_cap_trace(epochs):
    accepted, largest, probes = [], 0, []
    for height, epoch in enumerate(epochs):
        tentative_max = max(largest, epoch["jcs_bytes"])
        working = list(accepted)
        rejected = []
        for index, amendment in enumerate(epoch["amendments"]):
            change = dict(amendment, epoch_height=height, entry_index=index)
            trial = working + [change]
            if not isinstance(change["value"], int) or change["value"] < EPOCH_SIZE_FLOOR or change["effective_at_s"] < epoch["sealed_at_s"] + 7 * DAY_S or epoch_cap_bounds(trial, epoch["sealed_at_s"])[0] < tentative_max:
                rejected.append(index)
            else:
                working = trial
        cap, _ = epoch_cap_bounds(working, epoch["sealed_at_s"])
        valid = tentative_max <= cap
        probes.append({"rejected_indices": rejected, "sealing_cap": cap, "epoch_valid": valid,
            "largest_bytes": tentative_max if valid else largest,
            "transport_bound_before": EPOCH_CAP_DEFAULT if not probes else epoch_cap_bounds(accepted, epochs[height-1]["sealed_at_s"])[1]})
        if not valid:
            assert height == len(epochs)-1
            break
        accepted, largest = working, tentative_max
    return probes


U2 = 2 * EPOCH_SIZE_FLOOR
U3 = 3 * EPOCH_SIZE_FLOOR
U4 = 4 * EPOCH_SIZE_FLOOR
U8 = 8 * EPOCH_SIZE_FLOOR

epoch_size_cases = []
for label, rows, rejected, valid in (
    ("reduction below a historical Epoch", [(0,U8,[]), (1,U2,[(U4,8)])], [[],[0]], [True,True]),
    ("reduction includes its complete current Epoch", [(0,U8,[(U4,7)])], [[0]], [True]),
    ("reduction equals the current Epoch size", [(0,U4,[(U4,7)]), (7,U4,[])], [[],[]], [True,True]),
    ("pending reduction constrains an intervening Epoch", [(0,U2,[(U4,7)]), (1,U4+1,[])], [[],[]], [True,False]),
    ("pending reduction equality before effectiveness", [(0,U2,[(U4,7)]), (1,U4,[])], [[],[]], [True,True]),
    ("increase is unavailable one second before effectiveness", [(0,U2,[(U4,7),(U8,8)]), (8,U4+1,[])], [[],[]], [True,False]),
    ("increase is available exactly at effectiveness", [(0,U2,[(U4,7),(U8,8)]), (8,U8,[])], [[],[]], [True,True]),
    ("rejected candidate is not rescued by later replacement", [(0,300000,[(U4,7),(U8,7)])], [[0]], [True]),
    ("same-time replacement relaxes a pending reduction", [(0,U2,[(U4,7),(U8,7)]), (1,U8,[])], [[],[]], [True,True]),
    ("out-of-range candidate leaves the schedule unchanged", [(0,EPOCH_SIZE_FLOOR,[(EPOCH_SIZE_FLOOR-1,7),(EPOCH_SIZE_FLOOR,7)])], [[0]], [True]),
    ("restart retains a pending reduction and maximum", [(0,U4,[(U4,7)]), (1,U2,[]), (2,U2,[(U3,9)])], [[],[],[0]], [True,True,True]),
    ("later maximum never revalidates old acceptance", [(0,U2,[(U4,7)]), (1,U2,[(U8,7+1)]), (9,U8,[])], [[],[],[]], [True,True,True]),
    ("verified pending increase permits transport above default", [(0,U2,[(2*EPOCH_CAP_DEFAULT,7)]), (7,EPOCH_CAP_DEFAULT+1,[])], [[],[]], [True,True]),
    ("a fetched Epoch cannot raise its own bound", [(0,EPOCH_CAP_DEFAULT+1,[(2*EPOCH_CAP_DEFAULT,7)])], [[0]], [False]),
    ("schema-invalid candidate is ignored and its Epoch stays valid", [(0,U2,[(str(U4),7),(U8,7)]), (7,U8,[])], [[0],[]], [True,True]),
):
    epochs = [{"sealed_at_s":round(day*DAY_S), "jcs_bytes":size,
        "amendments":[{"value":value,"effective_at_s":effective*DAY_S} for value,effective in amendments]}
        for day,size,amendments in rows]
    if label == "increase is unavailable one second before effectiveness":
        epochs[-1]["sealed_at_s"] -= 1
    probes = epoch_cap_trace(epochs)
    assert [p["rejected_indices"] for p in probes] == rejected, label
    assert [p["epoch_valid"] for p in probes] == valid, label
    epoch_size_cases.append({"label":label,"epochs":epochs,"expected":probes,
        "restart_after":list(range(len(epochs)-1))})

epoch_transport_cases = []
for label, prefix_s, changes, rejected_changes, entries_bytes, valid in (
    ("no verified prefix uses the Registry default", None, [], [], EPOCH_CAP_DEFAULT, True),
    ("no verified prefix rejects entries above the Registry default", None, [], [], EPOCH_CAP_DEFAULT+1, False),
    ("entries attributable to the Epoch at the transport bound", 7*DAY_S, [(EPOCH_SIZE_FLOOR,7)], [], EPOCH_SIZE_FLOOR, True),
    ("entries attributable to the Epoch exceed the transport bound", 7*DAY_S, [(EPOCH_SIZE_FLOOR,7)], [], EPOCH_SIZE_FLOOR+1, False),
    ("the bound is the greatest cap at the prefix's last sealed_at", 10*DAY_S, [(U2,0)], [], U2, True),
    ("an accepted future effective_at raises the bound before it takes effect", 1*DAY_S,
        [(EPOCH_SIZE_FLOOR,1),(2*EPOCH_CAP_DEFAULT,30)], [], EPOCH_CAP_DEFAULT+1, True),
    ("a rejected candidate does not raise the bound", 5*DAY_S, [(EPOCH_SIZE_FLOOR,5)], [(U4,5)], U4, False),
):
    amendments = [{"value":value,"effective_at_s":day*DAY_S,"epoch_height":0,"entry_index":i} for i,(value,day) in enumerate(changes)]
    bound = EPOCH_CAP_DEFAULT if prefix_s is None else epoch_cap_bounds(amendments,prefix_s)[1]
    epoch_transport_cases.append({"label":label,"prefix_sealed_at_s":prefix_s,"accepted_caps":amendments,
        "rejected_caps":[{"value":value,"effective_at_s":day*DAY_S,"epoch_height":0,"entry_index":len(amendments)+j}
            for j,(value,day) in enumerate(rejected_changes)],
        "entries_bytes":entries_bytes,"transport_bound":bound,
        "valid":valid,"error":None if valid else "WIST3-E03"})

for label, values, entries_bytes, valid in (
    ("Snapshot bootstrap with no accepted caps uses the Registry default", [], EPOCH_CAP_DEFAULT, True),
    ("Snapshot bootstrap rejects entries above the Registry default", [], EPOCH_CAP_DEFAULT+1, False),
    ("Snapshot bootstrap authenticated tuple raises the bound", [2*EPOCH_CAP_DEFAULT], 2*EPOCH_CAP_DEFAULT, True),
    ("Snapshot bootstrap entries above the authenticated bound are rejected", [2*EPOCH_CAP_DEFAULT], 2*EPOCH_CAP_DEFAULT+1, False),
):
    epoch_transport_cases.append({"label":label,
        "snapshot_bootstrap":True,"prefix_sealed_at_s":None,
        "accepted_caps":[{"value":value} for value in values],"rejected_caps":[],
        "entries_bytes":entries_bytes,
        "transport_bound":max([EPOCH_CAP_DEFAULT]+values),"valid":valid,
        "error":None if valid else "WIST3-E03"})

LOG_TIMESTAMP_MAX_S = 253402300799
RECOVERY_BASE_S = 1_800_000_000
RECOVERY_LIMIT_S = LOG_TIMESTAMP_MAX_S - RECOVERY_BASE_S
LARGEST_WINDOW_DAYS = (RECOVERY_LIMIT_S - 10 * 86400) // 86400
LARGEST_WINDOW_END_S = 10 * 86400 + LARGEST_WINDOW_DAYS * 86400
LATE_OPENING_DAY = RECOVERY_LIMIT_S // 86400 - 3
recovery_window_cases = []
for label, changes, openings, probes in [
    ("default exact settlement boundary", [], [10], [16 * 86400 + 86399, 17 * 86400]),
    ("later shortening preserves original end", [(0, 11, 2)], [10], [12 * 86400, 17 * 86400]),
    ("later lengthening preserves original end", [(0, 11, 20)], [10], [17 * 86400, 30 * 86400]),
    ("amendment effective at owner applies", [(0, 10, 2)], [10], [12 * 86400 - 1, 12 * 86400]),
    ("in window recovery does not reanchor", [(0, 11, 2)], [10, 11], [13 * 86400, 17 * 86400]),
    ("new window reads amended length", [(0, 11, 2)], [10, 17], [17 * 86400, 19 * 86400]),
    ("largest representable window", [(0, 10, LARGEST_WINDOW_DAYS)], [10],
     [LARGEST_WINDOW_END_S - 1, LARGEST_WINDOW_END_S]),
    ("amendment past the timestamp range is rejected", [(0, 10, LARGEST_WINDOW_DAYS + 1)], [10],
     [16 * 86400 + 86399, 17 * 86400]),
    ("opening near the range end cannot seal", [], [LATE_OPENING_DAY], [LATE_OPENING_DAY * 86400 + 1]),
]:
    amendments, rejected_amendments = [], []
    for i, (sealed, effective, value) in enumerate(changes):
        amendment = {"parameter": "recovery_window_days", "value": value,
                     "epoch_height": i, "entry_index": 0,
                     "sealed_at_s": sealed * 86400, "effective_at_s": effective * 86400}
        if effective * 86400 + value * 86400 > RECOVERY_LIMIT_S:
            rejected_amendments.append(dict(amendment, code="WIST4-E03"))
        else:
            amendments.append(amendment)
    events = []
    end = None
    owner = None
    for day in openings:
        at = day * 86400
        if end is None or at >= end:
            applicable = [change for change in amendments if change["effective_at_s"] <= at]
            days = applicable[-1]["value"] if applicable else 7
            candidate = at + days * 86400
            if candidate > RECOVERY_LIMIT_S:
                events.append({"sealed_at_s": at, "sealable": False, "owner_at_s": None, "window_end_s": None})
                continue
            owner, end = at, candidate
        events.append({"sealed_at_s": at, "sealable": True, "owner_at_s": owner, "window_end_s": str(end)})
    recovery_window_cases.append({"label": label, "accepted_amendments": amendments,
                                  "rejected_amendments": rejected_amendments,
                                  "eligible_recoveries": events,
                                  "probes": [{"at_s": at, "open": end is not None and at < end}
                                             for at in probes]})
assert [[e["sealable"] for e in c["eligible_recoveries"]] for c in recovery_window_cases][-1] == [False]
assert [len(c["rejected_amendments"]) for c in recovery_window_cases] == [0, 0, 0, 0, 0, 0, 0, 1, 0]

write_json(WIST4 / "parameter-combinations.json", spaced_labels({
    "note": "WIST-4 §5 combination rules. prospective_cases: candidates processed in Log order against every prospective map, the rejected indices and the resulting maps at each effective instant. epoch_size_cases and epoch_transport_cases: the Epoch-size guarantee over the sealed prefix and the transport bound it fixes. recovery_window_cases: the Log timestamp range over recovery_window_days. wire_cases: the wire integer domain and the details contract. clock_cases: a parameter read for work already begun stays attached to its anchor.",
    "prospective_defaults": PROSPECTIVE_DEFAULTS,
    "prospective_floors": PROSPECTIVE_FLOORS,
    "prospective_cases": prospective_cases,
    "epoch_cap_default": EPOCH_CAP_DEFAULT,
    "epoch_size_cases": epoch_size_cases,
    "epoch_transport_cases": epoch_transport_cases,
    "recovery_window_base_s": RECOVERY_BASE_S,
    "recovery_window_cases": recovery_window_cases,
    "wire_public_key": b64u(pub_raw),
    "wire_cases": parameter_wire_cases,
    "clock_defaults": CLOCK_DEFAULTS,
    "clock_cases": clock_cases,
}))
print("wist4 parameter-combinations vector written")


# ------------------------------------- WIST-4 §5.1: payload_withdrawal acts
def withdrawal_vectors():
    d1 = "sha256:" + hashlib.sha256(b"withdrawal fixture Delta one").hexdigest()
    d2 = "sha256:" + hashlib.sha256(b"withdrawal fixture Delta two").hexdigest()
    d3 = "sha256:" + hashlib.sha256(b"withdrawal fixture Delta three").hexdigest()
    d0 = "sha256:" + hashlib.sha256(b"withdrawal fixture Delta below the Snapshot").hexdigest()
    sealed = [{"delta_id": d1, "publisher": "site.sample.net", "url": "https://site.sample.net/one", "height": 1},
              {"delta_id": d2, "publisher": "other.sample.org", "url": "https://other.sample.org/two", "height": 4},
              {"delta_id": d3, "publisher": "third.sample.org", "url": "https://third.sample.org/three",
               "height": 5}]

    def act(label, code, *, height=3, delta_id=d1, subject="site.sample.net", signer=priv,
            key_id="test-agg-k1", version="1.0.0", extra=None, details=None, withdrawn_height=None):
        body = ({"delta_id": delta_id, "legal_basis": "court order 12/2026", "jurisdiction": "BR"}
                if details is None else details)
        update = {"wist_version": version, "action": "payload_withdrawal", "subject": subject,
                  "effective_at": "2026-08-05T12:00:00Z", "details": body}
        if extra:
            update.update(extra)
        return {"label": label, "height": height,
                "envelope_json": json.dumps(sign_envelope_with(signer, "update", update, key_id),
                                            ensure_ascii=True),
                "code": code, "withdrawn_height": withdrawn_height}

    acts = [
        act("valid withdrawal", None, withdrawn_height=3),
        act("signed by a key the Log does not hold", "WIST4-E11", signer=priv2, key_id="test-log-r1"),
        act("unsupported major", "WIST4-E11", version="2.0.0"),
        act("unknown member", "WIST4-E11", extra={"note": "x"}),
        act("delta id not a Delta ID", "WIST4-E04",
            details={"delta_id": "sha256:xyz", "legal_basis": "b", "jurisdiction": "BR"}),
        act("missing legal basis", "WIST4-E04", details={"delta_id": d1, "jurisdiction": "BR"}),
        act("subject not a host", "WIST4-E04", subject="not a host!"),
        act("subject is another Publisher", "WIST4-E04", subject="other.sample.org"),
        act("Delta sealed above the act", "WIST4-E04", delta_id=d2, subject="other.sample.org", height=2),
        act("Delta sealed in the act's Epoch", None, delta_id=d2, subject="other.sample.org", height=4,
            withdrawn_height=4),
        act("repeated withdrawal keeps the first height", None, height=6,
            details={"delta_id": d1, "legal_basis": "second order", "jurisdiction": "BR"},
            withdrawn_height=3),
    ]

    state_tuples = [["withdrawal", d1, "site.sample.net", 3], ["withdrawal", d2, "other.sample.org", 4]]
    record_tuples = [["record", d["publisher"], d["url"], d["delta_id"]] for d in sealed]
    resume = {
        "tree_size": 3,
        "adopted": [["withdrawal", d1, "site.sample.net", 3]],
        "walked_deltas": [d for d in sealed if d["height"] > 3],
        "act_cases": [
            act("repeats an adopted withdrawal", None, height=5, withdrawn_height=3),
            act("names a Delta sealed below the Snapshot", None, height=5, delta_id=d0,
                subject="old.sample.net", withdrawn_height=5),
            act("names a walked Delta of another Publisher", "WIST4-E04", height=5, delta_id=d2),
            act("names a walked Delta sealed above the act", "WIST4-E04", height=4, delta_id=d3,
                subject="third.sample.org"),
            act("withdraws a walked Delta", None, height=6, delta_id=d3, subject="third.sample.org",
                withdrawn_height=6),
        ],
        "state_tuples": [["withdrawal", d0, "old.sample.net", 5], ["withdrawal", d1, "site.sample.net", 3],
                         ["withdrawal", d3, "third.sample.org", 6]],
    }
    return spaced_labels({
        "note": ("WIST-4 §5.1: a payload_withdrawal is authenticated under the Log key (WIST4-E11 otherwise) and "
                 "must name a Delta sealed at or below its Epoch whose signed publisher is the subject "
                 "(WIST4-E04 otherwise); the earliest accepted withdrawal's Epoch governs and a later withdrawal "
                 "of the same Delta changes nothing. Acts replay in order; state_tuples are the WIST-3 §7 "
                 "withdrawal tuples the replay leaves, record_tuples the chain tips every sealed Delta moves, "
                 "withdrawn or not, and materialized the sealed Deltas whose content materializes. resume "
                 "replays acts at a Consumer that adopted the tuples at tree_size and walked only the Deltas "
                 "above it: an act naming a Delta it did not walk is accepted as consistent."),
        "log_key": {"key_id": "test-agg-k1", "public_key": b64u(pub_raw)}, "sealed_deltas": sealed,
        "act_cases": acts, "state_tuples": state_tuples, "record_tuples": record_tuples,
        "materialized": [d3], "resume": resume})


write_json(WIST4 / "withdrawal.json", withdrawal_vectors())


# ------------------------------------------ WIST-4 §3.1: Public Suffix List snapshots
SUFFIX_LIST_HEADER = [
    "// Fixture excerpt of the Public Suffix List, https://publicsuffix.org/list/public_suffix_list.dat",
    "// (Mozilla Foundation, MPL-2.0): rules copied verbatim, section markers preserved, most rules omitted.",
]
SUFFIX_LIST_ICANN = ["ac", "biz", "*.ck", "!www.ck", "cn", "com.cn", "公司.cn", "com", "dev", "io", "jp",
                     "ac.jp", "kyoto.jp", "ide.kyoto.jp", "*.kobe.jp", "!city.kobe.jp", "*.mm", "net", "org",
                     "us", "ak.us", "k12.ak.us", "中国"]
SUFFIX_LIST_PRIVATE = ["uk.com", "pages.dev", "github.io"]


def suffix_list_text(private_extra=()):
    lines = SUFFIX_LIST_HEADER + ["", "// ===BEGIN ICANN DOMAINS===", ""] + SUFFIX_LIST_ICANN + [
        "", "// ===END ICANN DOMAINS===", "// ===BEGIN PRIVATE DOMAINS===", ""] + SUFFIX_LIST_PRIVATE + list(
        private_extra) + ["", "// ===END PRIVATE DOMAINS==="]
    return "\n".join(lines) + "\n"


def host_label(label: str) -> str:
    """The fixture's Canonical Host processing of one label: the fixtures use no
    character UTS #46 maps other than by case folding, so lowercase ASCII and
    Punycode are exact here; a general implementation runs the whole profile."""
    if label == "*":
        return label
    label = label.lower()
    return label if label.isascii() else alabel(label)


def canonical_fixture_host(name):
    labels = name.split(".")
    if any(not label for label in labels):
        return None
    return ".".join(host_label(label) for label in labels)


def suffix_rules(text: str):
    """WIST-4 §3.1: every rule line of both sections, labels in Canonical Host form."""
    rules = []
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        rule = stripped.split()[0]
        exception = rule.startswith("!")
        labels = tuple(host_label(label) for label in rule.lstrip("!").split("."))
        rules.append((labels, exception))
    return rules


def registrable_domain(host: str, rules):
    """WIST-4 §3.1: the Public Suffix List algorithm, the host itself where it
    leaves no registrable domain, and the host itself under no snapshot."""
    if rules is None:
        return host, False
    labels = host.split(".")
    matching = []
    for rule, exception in rules:
        if len(rule) > len(labels):
            continue
        if all(r == "*" or r == h for r, h in zip(reversed(rule), reversed(labels))):
            matching.append((rule, exception))
    if not matching:
        prevailing, exception = ("*",), False
    else:
        exceptions = [m for m in matching if m[1]]
        prevailing, exception = max(exceptions or matching, key=lambda m: len(m[0]))
    suffix = len(prevailing) - 1 if exception else len(prevailing)
    if suffix >= len(labels):
        return host, True
    return ".".join(labels[len(labels) - suffix - 1:]), False


def official_suffix_cases(rules):
    cases = []
    for line in (ROOT / "tools" / "psl_test_cases.txt").read_text(encoding="utf-8").split("\n"):
        m = re.fullmatch(r"checkPublicSuffix\((null|'([^']*)'), (null|'([^']*)')\);", line.strip())
        if not m or m.group(1) == "null":
            continue
        raw, expected = m.group(2), m.group(4)
        host = canonical_fixture_host(raw)
        case = {"input": raw, "host": host, "expected": expected, "registrable": None, "public_suffix": None}
        if host is not None:
            registrable, own = registrable_domain(host, rules)
            assert registrable == (host if expected is None else canonical_fixture_host(expected)), raw
            case.update({"registrable": registrable, "public_suffix": own})
        cases.append(case)
    return cases


def registrable_domain_vectors():
    first_text = suffix_list_text()
    second_text = suffix_list_text(["hosts.sample.net"])
    lists = []
    for name, text in (("first", first_text), ("second", second_text)):
        octets = text.encode("utf-8")
        lists.append({"name": name, "text": text, "sha256": "sha256:" + sha256_hex(octets), "bytes": len(octets)})
    by_name = {l["name"]: l for l in lists}
    rules = {l["name"]: suffix_rules(l["text"]) for l in lists}
    rules[None] = None
    ids = {name: by_name[name]["sha256"] for name in by_name}

    def domain_case(label, host, list_name):
        registrable, own = registrable_domain(host, rules[list_name])
        return {"label": label, "list": list_name, "host": host, "registrable": registrable, "public_suffix": own}

    domain_cases = [
        domain_case("shared registrable domain", "a.example.com", "first"),
        domain_case("shared registrable domain sibling", "b.example.com", "first"),
        domain_case("deeper shared host", "x.a.example.com", "first"),
        domain_case("the registrable domain itself", "example.com", "first"),
        domain_case("private section host", "alice.github.io", "first"),
        domain_case("private section sibling", "bob.github.io", "first"),
        domain_case("private suffix is its own unit", "github.io", "first"),
        domain_case("private suffix under an ICANN suffix", "site.pages.dev", "first"),
        domain_case("wildcard exception", "www.ck", "first"),
        domain_case("wildcard suffix host", "test.ck", "first"),
        domain_case("under a wildcard suffix", "b.test.ck", "first"),
        domain_case("unlisted top level", "foo.unlisted", "first"),
        domain_case("deep unlisted top level", "a.b.foo.unlisted", "first"),
        domain_case("single label", "localhost", "first"),
        domain_case("IDN suffix host", alabel("食狮") + "." + alabel("公司") + ".cn", "first"),
        domain_case("unlisted IDN top level", alabel("пример") + "." + alabel("рф"), "first"),
        domain_case("shared before the private rule", "a.hosts.sample.net", "first"),
        domain_case("shared before the private rule sibling", "b.hosts.sample.net", "first"),
        domain_case("separate after the private rule", "a.hosts.sample.net", "second"),
        domain_case("separate after the private rule sibling", "b.hosts.sample.net", "second"),
        domain_case("no snapshot in force", "a.example.com", None),
        domain_case("no snapshot in force sibling", "b.example.com", None),
    ]

    unheld_id = "sha256:" + sha256_hex(b"a snapshot nobody serves\n")

    def act(label, code, *, height, name="first", signer=priv, key_id="test-agg-k1", version="1.0.0",
            subject=None, details=None, extra=None, effective_at=None, in_force_after=None):
        snapshot = by_name[name]
        body = {"sha256": snapshot["sha256"], "bytes": snapshot["bytes"]} if details is None else details
        update = {"wist_version": version, "action": "suffix_list_update",
                  "subject": snapshot["sha256"] if subject is None else subject,
                  "effective_at": effective_at or f"2026-08-0{height + 1}T12:00:00Z", "details": body}
        if extra:
            update.update(extra)
        return {"label": label, "height": height,
                "envelope_json": json.dumps(sign_envelope_with(signer, "update", update, key_id), ensure_ascii=True),
                "code": code, "in_force_after": in_force_after}

    acts = [
        act("first snapshot pinned", None, height=0, in_force_after="first"),
        act("signed by a key the Log does not hold", "WIST4-E11", height=1, name="second",
            signer=priv2, key_id="test-log-r1", in_force_after="first"),
        act("unsupported major", "WIST4-E11", height=1, name="second", version="2.0.0", in_force_after="first"),
        act("unknown member", "WIST4-E11", height=1, name="second", extra={"source": "x"}, in_force_after="first"),
        act("subject names another snapshot", "WIST4-E04", height=2, name="second", subject=ids["first"],
            in_force_after="first"),
        act("malformed snapshot identifier", "WIST4-E04", height=2, subject="sha256:xyz",
            details={"sha256": "sha256:xyz", "bytes": 1}, in_force_after="first"),
        act("zero bytes", "WIST4-E04", height=2, name="second",
            details={"sha256": ids["second"], "bytes": 0}, in_force_after="first"),
        act("missing bytes", "WIST4-E04", height=2, name="second",
            details={"sha256": ids["second"]}, in_force_after="first"),
        act("bytes disagree with the named file", "WIST4-E04", height=2, name="second",
            details={"sha256": ids["second"], "bytes": by_name["second"]["bytes"] + 1}, in_force_after="first"),
        act("second snapshot pinned", None, height=3, name="second", in_force_after="second"),
        act("repeated pin of the snapshot in force", None, height=5, name="second",
            effective_at="2026-08-06T13:00:00Z", in_force_after="second"),
        dict(act("names a file no source holds", "WIST4-E04", height=6, subject=unheld_id,
                 details={"sha256": unheld_id, "bytes": 7}, in_force_after="second"),
             consumer="WIST3-E01"),
    ]
    in_force = [{"height": 0, "list": None}, {"height": 1, "list": "first"}, {"height": 2, "list": "first"},
                {"height": 3, "list": "first"}, {"height": 4, "list": "second"}, {"height": 5, "list": "second"},
                {"height": 6, "list": "second"}]
    force_at = {row["height"]: row["list"] for row in in_force}

    def entry(kind, domain):
        return {"type": kind, "domain": domain}

    def capacity(label, height, entries, cap=2):
        counts = {}
        for e in entries:
            unit = registrable_domain(e["domain"], rules[force_at[height]])[0]
            counts[unit] = counts.get(unit, 0) + 1
        expected = "WIST3-E03" if max(counts.values()) > cap else None
        return {"label": label, "height": height, "domain_epoch_entries_max": cap, "entries": entries,
                "expected": expected}

    capacity_cases = [
        capacity("three hosts of one registrable domain", 2,
                 [entry("publisher_delta", "a.example.com"), entry("publisher_delta", "b.example.com"),
                  entry("publisher_delta", "c.example.com")]),
        capacity("two private section hosts at the cap each", 2,
                 [entry("publisher_delta", "alice.github.io"), entry("publisher_delta", "alice.github.io"),
                  entry("publisher_delta", "bob.github.io"), entry("label", "bob.github.io")]),
        capacity("a Label counts with the Deltas", 2,
                 [entry("publisher_delta", "a.hosts.sample.net"), entry("publisher_delta", "a.hosts.sample.net"),
                  entry("label", "b.hosts.sample.net")]),
        capacity("the same Entries after the private rule", 4,
                 [entry("publisher_delta", "a.hosts.sample.net"), entry("publisher_delta", "a.hosts.sample.net"),
                  entry("label", "b.hosts.sample.net")]),
        capacity("no snapshot in force keys on the host", 0,
                 [entry("publisher_delta", "a.example.com"), entry("publisher_delta", "a.example.com"),
                  entry("publisher_delta", "b.example.com"), entry("publisher_delta", "b.example.com")]),
        capacity("the same Entries under the first snapshot", 1,
                 [entry("publisher_delta", "a.example.com"), entry("publisher_delta", "a.example.com"),
                  entry("publisher_delta", "b.example.com"), entry("publisher_delta", "b.example.com")]),
    ]

    def quota(label, height, pings, base=2):
        noise = {}
        rows = []
        for ping in pings:
            host, is_noise = ping[0], ping[1]
            at = ping[2] if len(ping) > 2 else height
            unit = registrable_domain(host, rules[force_at[at]])[0]
            row = {"host": host, "noise": is_noise}
            if len(ping) > 2:
                row["height"] = at
            if noise.get(unit, 0) >= base:
                rows.append(dict(row, expected=429))
                continue
            if is_noise:
                noise[unit] = noise.get(unit, 0) + 1
            rows.append(dict(row, expected=202))
        return {"label": label, "height": height, "quota_base": base, "pings": rows}

    pings = [("a.example.com", True), ("b.example.com", True), ("c.example.com", False), ("alice.github.io", True),
             ("alice.github.io", True), ("alice.github.io", False), ("bob.github.io", True),
             ("a.hosts.sample.net", True), ("b.hosts.sample.net", True), ("c.hosts.sample.net", True)]
    quota_cases = [quota("one UTC day under the first snapshot", 2, pings),
                   quota("the same Pings under the second snapshot", 4, pings),
                   quota("the same Pings with no snapshot in force", 0, pings),
                   quota("a snapshot change inside the day", 3,
                         [("a.hosts.sample.net", True, 3), ("b.hosts.sample.net", True, 3),
                          ("c.hosts.sample.net", True, 3), ("a.hosts.sample.net", True, 4),
                          ("a.hosts.sample.net", True, 4), ("a.hosts.sample.net", True, 4),
                          ("b.hosts.sample.net", True, 4), ("c.hosts.sample.net", False, 4)])]

    state_tuples = [{"tree_size": 0, "entries": [["suffix_list", ids["first"], 0]]},
                    {"tree_size": 2, "entries": [["suffix_list", ids["first"], 0]]},
                    {"tree_size": 3, "entries": [["suffix_list", ids["second"], 3]]},
                    {"tree_size": 6, "entries": [["suffix_list", ids["second"], 3]]}]
    return spaced_labels({
        "note": ("WIST-4 §3.1, WIST-2 §4, WIST-3 §3.2 and §7. lists are Public Suffix List snapshots as octets "
                 "(text is the exact UTF-8 file). official_cases transcribe the Public Suffix List project's "
                 "checkPublicSuffix cases over the first snapshot: host is the input's Canonical Host (null where "
                 "it has none), expected the project's answer and registrable the Registrable Domain, the host "
                 "itself where the list leaves none. domain_cases read a host under a named snapshot or under "
                 "none. act_cases replay in Epoch order under the Log key: a suffix_list_update is in force from "
                 "the Epoch after its sealing Epoch (in_force lists the snapshot in force at each height). "
                 "capacity_cases count publisher_delta and label Entries per Registrable Domain under the "
                 "snapshot in force at the Epoch; quota_cases apply quota_base to the noise Pings of one UTC day "
                 "per Registrable Domain in order, each Ping under the snapshot in force at its own height where "
                 "one is given; an act carrying consumer names a file no source holds, which fails its contract "
                 "at the Aggregator and stops a Consumer with WIST3-E01; state_tuples are the WIST-3 §7 "
                 "suffix_list tuple at a tree_size."),
        "log_key": {"key_id": "test-agg-k1", "public_key": b64u(pub_raw)},
        "lists": lists, "official_cases": official_suffix_cases(rules["first"]), "domain_cases": domain_cases,
        "act_cases": acts, "in_force": in_force, "capacity_cases": capacity_cases, "quota_cases": quota_cases,
        "state_tuples": state_tuples})


write_json(WIST4 / "registrable-domain.json", registrable_domain_vectors())


# ------------------------------------- WIST-3 §6: static-file octet bounds
# A Consumer stops reading a response before buffering bytes beyond the
# limit when a tile exceeds 8192 octets or an entry bundle exceeds
# 16 777 472 octets (256 leaves of 65 537, §6); §3.3 caps one Entry's own
# JCS serialization at 65 535 octets. All three are WIST3-E03; equality
# with a bound is permitted.
def padded_entry(target_bytes: int) -> dict:
    pad = target_bytes - len(rfc8785.dumps({"type": "publisher_delta", "body": {"pad": ""}}))
    assert pad >= 0
    entry = {"type": "publisher_delta", "body": {"pad": "x" * pad}}
    assert len(rfc8785.dumps(entry)) == target_bytes
    return entry

def filler_octets(n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        out += hashlib.sha256(len(out).to_bytes(8, "big")).digest()
    return bytes(out[:n])

TILE_BOUND_BYTES = 8192
BUNDLE_BOUND_BYTES = 256 * 65537
ENTRY_JCS_BOUND_BYTES = 65535
entry_at_bound = padded_entry(ENTRY_JCS_BOUND_BYTES)
entry_over_bound = padded_entry(ENTRY_JCS_BOUND_BYTES + 1)

# WIST-3 §6: the forms that already exclude reproducing a Checkpoint's
# root, so `valid` here means only that the form admits recomputation —
# which root a tile or bundle reproduces is the separate check §4 fixes.
def form_entry(index: int) -> bytes:
    """One synthetic Entry's leaf data for the form cases below: all of one
    length, so a bundle's octet count is its Entry count times a constant."""
    return rfc8785.dumps({"type": "publisher_delta", "body": {"pad": "%04d" % index}})

def form_bundle(count: int, start: int = 0) -> bytes:
    return entry_bundle_bytes([form_entry(i) for i in range(start, start + count)])

FULL_TILE_PATH = tile_path(0, 0)
PARTIAL_TILE_PATH = tile_path(0, 1, 44)
FULL_BUNDLE_PATH = tile_path("entries", 0)
PARTIAL_BUNDLE_PATH = tile_path("entries", 1, 44)

tile_form_cases = [
    {"name": "full-tile path holding 256 hashes", "path": FULL_TILE_PATH,
     "octets_hex": filler_octets(256 * 32).hex(), "expected": "valid"},
    {"name": "partial path holding the 44 hashes its width states", "path": PARTIAL_TILE_PATH,
     "octets_hex": filler_octets(44 * 32).hex(), "expected": "valid"},
    {"name": "empty tile", "path": FULL_TILE_PATH, "octets_hex": "", "expected": "WIST3-E03"},
    {"name": "tile length not a multiple of 32 octets", "path": PARTIAL_TILE_PATH,
     "octets_hex": filler_octets(44 * 32 - 1).hex(), "expected": "WIST3-E03"},
    {"name": "full-tile path holding 255 hashes", "path": FULL_TILE_PATH,
     "octets_hex": filler_octets(255 * 32).hex(), "expected": "WIST3-E03"},
    {"name": "partial path .p/44 holding 43 hashes", "path": PARTIAL_TILE_PATH,
     "octets_hex": filler_octets(43 * 32).hex(), "expected": "WIST3-E03"},
    {"name": "partial path .p/0, one hash", "path": tile_path(0, 1) + ".p/0",
     "octets_hex": filler_octets(32).hex(), "expected": "WIST3-E03",
     "note": "Every tile at a .p/0 path is WIST3-E03: the width is outside 1 "
             "through 255, and no octets isolate that from the other rules — "
             "an empty file is rejected as empty and any other holds a "
             "number of hashes the path does not state. The case fixes the "
             "disposition rather than discriminating the width rule."},
    {"name": "partial path .p/256, 256 hashes", "path": tile_path(0, 1) + ".p/256",
     "octets_hex": filler_octets(256 * 32).hex(), "expected": "WIST3-E03",
     "note": "The octets are exactly what a full tile holds, so the path's "
             "width being outside 1 through 255 is the only ground for "
             "rejection."},
]

bundle_form_cases = [
    {"name": "full bundle path holding 256 Entries", "path": FULL_BUNDLE_PATH,
     "octets_hex": form_bundle(256).hex(), "expected": "valid"},
    {"name": "partial path holding the 44 Entries its width states", "path": PARTIAL_BUNDLE_PATH,
     "octets_hex": form_bundle(44).hex(), "expected": "valid"},
    {"name": "length prefix cut short at the 44th Entry", "path": PARTIAL_BUNDLE_PATH,
     "octets_hex": (form_bundle(43) + b"\x00").hex(), "expected": "WIST3-E03"},
    {"name": "leaf data cut short at the 44th Entry", "path": PARTIAL_BUNDLE_PATH,
     "octets_hex": (form_bundle(43) + len(form_entry(43)).to_bytes(2, "big")
                    + form_entry(43)[:8]).hex(), "expected": "WIST3-E03"},
    {"name": "one octet after the 44th Entry", "path": PARTIAL_BUNDLE_PATH,
     "octets_hex": (form_bundle(44) + b"\x00").hex(), "expected": "WIST3-E03"},
    {"name": "full bundle path holding 257 Entries", "path": FULL_BUNDLE_PATH,
     "octets_hex": form_bundle(257).hex(), "expected": "WIST3-E03"},
    {"name": "partial path .p/44 holding 43 Entries", "path": PARTIAL_BUNDLE_PATH,
     "octets_hex": form_bundle(43).hex(), "expected": "WIST3-E03"},
]

epoch_range_cases = [
    {"name": "Epoch Entries filling the leaf range", "size_previous": 4, "size": 7,
     "entry_leaf_indexes": [4, 5, 6], "expected": "valid"},
    {"name": "Epoch Entries short of the leaf range", "size_previous": 4, "size": 7,
     "entry_leaf_indexes": [4, 5], "expected": "WIST3-E03"},
    {"name": "Epoch Entries reaching past the leaf range", "size_previous": 4, "size": 7,
     "entry_leaf_indexes": [4, 5, 7], "expected": "WIST3-E03"},
]

write_json(ROOT / "vectors/wist3/tile-bounds.json", {
    "note": "WIST-3 §6 static-file octet bounds, the malformed forms §6 excludes, and §3.3's "
            "per-Entry bound. A Consumer stops "
            "reading a response before buffering bytes past a bound; equality with a bound is "
            "permitted, and every excess is WIST3-E03. The entry bundle case states its bound "
            "and declared size arithmetically, per §6's 'sum over the Epoch's Entries of each "
            "JCS length plus two' formula, rather than embedding 16 777 472 literal octets. In "
            "tile_form_cases, bundle_form_cases and epoch_range_cases, 'valid' says only that "
            "the form admits recomputation against a Checkpoint's root, which §4's separate "
            "check decides; the Entries there are synthetic leaf data of one length, and no "
            "Checkpoint in this suite states a root over them.",
    "tile": {
        "bound_bytes": TILE_BOUND_BYTES,
        "at_bound_hex": filler_octets(TILE_BOUND_BYTES).hex(), "at_bound_expected": "valid",
        "over_bound_hex": filler_octets(TILE_BOUND_BYTES + 1).hex(), "over_bound_expected": "WIST3-E03",
    },
    "entry_bundle": {
        "bound_bytes": BUNDLE_BOUND_BYTES,
        "at_bound_declared_bytes": BUNDLE_BOUND_BYTES, "at_bound_expected": "valid",
        "over_bound_declared_bytes": BUNDLE_BOUND_BYTES + 1, "over_bound_expected": "WIST3-E03",
    },
    "entry_jcs": {
        "bound_bytes": ENTRY_JCS_BOUND_BYTES,
        "at_bound_entry": entry_at_bound, "at_bound_expected": "valid",
        "over_bound_entry": entry_over_bound, "over_bound_expected": "WIST3-E03",
    },
    "tile_hash_octets": 32,
    "full_tile_hashes": 256,
    "tile_form_cases": tile_form_cases,
    "bundle_form_cases": bundle_form_cases,
    "epoch_range_cases": epoch_range_cases,
})

def unix_seconds(ts: str) -> int:
    """RFC 3339 UTC -> integer POSIX seconds (86400 s/day, no leap seconds)."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:[0-5][0-9]Z", ts, re.ASCII):
        raise ValueError("invalid Log timestamp")
    year_zero = ts.startswith("0000-")
    parsed = datetime.datetime.strptime("0400" + ts[4:] if year_zero else ts, "%Y-%m-%dT%H:%M:%SZ")
    return calendar.timegm(parsed.timetuple()) - (146097 * 86400 if year_zero else 0)


timestamp_cases = []
for value, seconds in (
    ("0000-01-01T00:00:00Z", -62167219200),
    ("0000-02-29T00:00:00Z", -62162121600),
    ("1970-01-01T00:00:00Z", 0),
    ("1969-12-31T23:59:59Z", -1),
    ("2000-02-29T00:00:00Z", 951782400),
    ("2016-12-31T23:59:59Z", 1483228799),
    ("2017-01-01T00:00:00Z", 1483228800),
    ("9999-12-30T21:59:59Z", 253402207199),
    ("9999-12-30T22:00:00Z", 253402207200),
    ("9999-12-30T22:00:01Z", 253402207201),
    ("9999-12-31T00:00:00Z", 253402214400),
    ("9999-12-31T23:59:59Z", 253402300799),
):
    assert unix_seconds(value) == seconds
    timestamp_cases.append({"value": value, "unix_seconds": seconds})
timestamp_invalid = [
    "2016-12-31T23:59:60Z", "2016-12-31T23:59:61Z", "2017-01-01T00:00:60Z",
    "2016-12-31T23:59:59.0Z", "2016-12-31T23:59:59+00:00",
    "2016-12-31t23:59:59z", "2016-12-31T24:00:00Z", "2016-12-31T23:60:00Z",
    "1900-02-29T00:00:00Z", "2017-02-29T00:00:00Z", "2016-13-01T00:00:00Z",
    "2016-12-31T23:59:59Z\n",
    "２０１６-12-31T23:59:59Z", "2016-12-31T23:59:５９Z",
    "9999-12-31T23:59:60Z", "9999-12-31T24:00:00Z",
    "9999-02-29T00:00:00Z", "10000-01-01T00:00:00Z",
    "-0001-12-31T23:59:59Z", "0000-00-01T00:00:00Z",
    "0000-01-00T00:00:00Z", "0000-04-31T00:00:00Z",
]
for value in timestamp_invalid:
    try:
        unix_seconds(value)
    except ValueError:
        pass
    else:
        raise AssertionError(value)
    timestamp_cases.append({"value": value, "unix_seconds": None})

timestamp_fields = []
for stem, path in (
    ("feed", ["feed", "generated_at"]),
    ("registry-update", ["update", "effective_at"]),
):
    timestamp_fields.append({"schema": stem + ".schema.json", "document": json.loads((EXAMPLES / (stem + ".json")).read_text()), "path": path})
timestamp_probe = "2017-01-01T00:00:00Z"
for entry, path in (
    (["parameter", "record_seal_epochs", timestamp_probe, 2], [2]),
    (["recovery_window", "example.com", 1, timestamp_probe, {}, 1], [3]),
    (["label", "labeler.example", "https://example.com/blog/post-1", "wist:spam", None, timestamp_probe, None, None, "sha256:" + "0" * 64, 1], [5]),
    (["label", "labeler.example", "https://example.com/blog/post-1", "wist:spam", None, "2026-08-02T12:00:00Z", timestamp_probe, None, "sha256:" + "0" * 64, 1], [6]),
    (["dispute", "sha256:" + "0" * 64, "example.com", None, timestamp_probe, 1], [4]),
):
    document = json.loads((EXAMPLES / "snapshot-state.json").read_text())
    document["state"]["entries"] = [entry]
    timestamp_fields.append({"schema": "snapshot-state.schema.json", "document": document,
                             "path": ["state", "entries", 0] + path})
checkpoint_note_lines = checkpoint_text.split("\n\n", 1)[0].split("\n")
checkpoint_sig_block = checkpoint_text.split("\n\n", 1)[1]

write_json(ROOT / "vectors/wist3/timestamps.json", {
    "note": "WIST-3 §3.1 whole-second literal-Z profile, including §7 Snapshot state. Null unix_seconds means reject, including invalid calendar dates. Field cases supply schema-valid structural baselines; mutating a signed value requires re-signing before testing signature verification. The schema-only leap-second check does not depend on format validation. The Checkpoint's `sealed_at` extension line (WIST-3 §5) is no longer a JSON Schema field, so `checkpoint_field_case` supplies the note's own five lines and signature block instead, for a structural-only (parse_checkpoint, not verify_checkpoint) probe of the same three field_accept/field_reject/field_reject_non_ascii values.",
    "cases": timestamp_cases,
    "distances": [{"from": "2016-12-31T23:59:59Z", "to": "2017-01-01T00:00:00Z", "seconds": 1}],
    "field_cases": timestamp_fields,
    "checkpoint_field_case": {
        "note_lines": checkpoint_note_lines,
        "sig_block": checkpoint_sig_block,
        "sealed_at_line_index": 4,
    },
    "field_accept": "2016-12-31T23:59:59Z",
    "field_reject": "2016-12-31T23:59:60Z",
    "field_reject_non_ascii": "２０１６-12-31T23:59:59Z",
})


def delta_diagnostic_vectors():
    publisher = {
        "wist_version": "1.0.0", "domain": "example.com", "seq": 0,
        "keys": [jwk(pub_raw, "2026-08-01T00:00:00Z")],
        "subdomain_scope": ["other.example"],
    }
    previous_source = sign_envelope("publisher", publisher, KID1)
    cases = []
    for binding, scope, future, chain in itertools.product(
            ("valid", "bad signature", "missing", "future"), (True, False),
            (False, True), (True, False)):
        source = json.loads(json.dumps(publisher))
        source["seq"] = 1
        source["prev_declaration"] = "sha256:" + sha256_hex(rfc8785.dumps(publisher))
        source["subdomain_scope"] = ["other.example"] if scope else []
        if binding == "future":
            source["keys"][0]["nbf"] = nbf_at("2026-08-04T11:00:00Z")
        declaration = sign_envelope("publisher", source, KID1)
        observed = "2026-08-04T10:10:00.00000000000000000001Z" if future else "2026-08-04T07:10:00-03:00"
        previous = {
            "wist_version": "1.0.0", "publisher": "example.com", "url": "https://other.example/page",
            "change_type": "new", "observed_at": "2026-08-04T09:00:00Z" if chain else observed,
            "payload": delta["payload"], "meta": {"lang": "en"},
        }
        predecessor = sign_envelope("delta", previous, KID1)
        candidate = {
            "wist_version": "1.0.0", "publisher": "example.com", "url": previous["url"], "change_type": "attest",
            "observed_at": observed, "prev": "sha256:" + sha256_hex(rfc8785.dumps(previous)),
            "meta": {"lang": "en"},
        }
        envelope = sign_envelope("delta", candidate, KID5 if binding == "missing" else KID1)
        if binding == "bad signature":
            envelope["sig"]["value"] = b64u(Ed25519PrivateKey.from_private_bytes(bytes([99]) * 32).sign(rfc8785.dumps(candidate)))
        errors = []
        if binding != "valid":
            errors.append("WIST1-E01" if binding == "bad signature" else "WIST1-E02")
        if not scope:
            errors.append("WIST1-E03")
        if future:
            errors.append("WIST1-E06")
        if not chain:
            errors.append("WIST1-E07")
        name = f"{binding}, scope {scope}, excess skew {future}, increasing time {chain}"
        for field in ("valid", "timestamp", "signature encoding"):
            probe = json.loads(json.dumps(envelope))
            if field == "timestamp":
                probe["delta"]["observed_at"] = "2026-08-04T10:10:60Z"
                probe = sign_envelope("delta", probe["delta"], probe["sig"]["key_id"])
                if binding == "bad signature":
                    probe["sig"]["value"] = b64u(Ed25519PrivateKey.from_private_bytes(bytes([99]) * 32).sign(rfc8785.dumps(probe["delta"])))
            elif field == "signature encoding":
                alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                value = probe["sig"]["value"]
                probe["sig"]["value"] = value[:-1] + alphabet[alphabet.index(value[-1]) + 1]
            cases.append({"name": name + ", field " + field, "field": field,
                          "declaration": declaration, "predecessor": predecessor,
                          "envelope": probe, "validator_time": "2026-08-04T10:00:00Z",
                          "clock_skew_seconds": 600,
                          "allowed": sorted(errors) if field == "valid" else ["WIST1-E14"]})
    return {
        "note": "WIST-1 §7. Each case supplies the already selected Publisher's current Declaration, "
                "its authenticated previous source and an already accepted predecessor. That predecessor "
                "was accepted under previous_declaration with an allowance sufficient at its validation "
                "instant (the present clock/allowance need not equal that context) and is "
                "the only chain tip. The current source is fresh: no cached-key refresh is pending. "
                "allowed is the complete set for the exercised checks; [] means these checks pass, not "
                "complete admission. Field failures suppress semantic diagnostics. Signature encoding "
                "twins retain signature bytes but set an unused base64url bit. URL fixtures are already "
                "normalized ASCII; only authority is varied. Payload content is the standard example. "
                "No Log inclusion, source selection, live clock/refresh/retrieval, Payload validation, "
                "recovery or ambiguous-author attribution is established.",
        "previous_declaration": previous_source, "cases": cases,
    }


write_json(WIST1 / "delta-diagnostics.json", delta_diagnostic_vectors())


def delta_field_vectors():
    base = {
        "wist_version": "1.0.0", "publisher": "example.com",
        "url": "https://example.com/page", "change_type": "new",
        "observed_at": "2026-08-04T10:00:00Z",
        "payload": delta["payload"], "meta": {"lang": "en"},
    }
    cases = []

    def add(name, inner, allowed=(), envelope_changes=None):
        for damaged in (False, True):
            envelope = sign_envelope("delta", inner, KID1)
            envelope = json.loads(json.dumps(envelope))
            if damaged:
                envelope["sig"]["value"] = b64u(
                    Ed25519PrivateKey.from_private_bytes(bytes([99]) * 32).sign(rfc8785.dumps(inner)))
            for path, value in (envelope_changes or []):
                node = envelope
                for part in path[:-1]:
                    node = node[part]
                if value == "REMOVE":
                    del node[path[-1]]
                else:
                    node[path[-1]] = value
            errors = set(allowed)
            if damaged and "WIST1-E14" not in errors:
                errors.add("WIST1-E01")
            cases.append({"name": name + (" with invalid signature" if damaged else ""),
                          "envelope": envelope,
                          "id": "sha256:" + sha256_hex(rfc8785.dumps(inner)),
                          "allowed": sorted(errors)})

    def change(name, path, value, allowed=("WIST1-E14",)):
        inner = json.loads(json.dumps(base))
        node = inner
        for part in path[:-1]:
            node = node[part]
        if value == "REMOVE":
            del node[path[-1]]
        else:
            node[path[-1]] = value
        add(name, inner, allowed)

    add("valid content commitment", base)
    change("valid predecessor spelling", ["prev"], "sha256:" + sha256_hex(rfc8785.dumps(delta)), ())
    for version in ("1.0.1", "1.1.0", "1." + "9" * 80 + "." + "9" * 80):
        change("supported version " + version, ["wist_version"], version, ())
    for version in ("0.0.0", "2.0.0", "10.0.0", "9" * 80 + ".0.0"):
        change("unsupported major " + version, ["wist_version"], version, ("WIST1-E15",))
    for version in ("1.0", "1.0.0.0", "1.0.0-rc.1", "1.0.0+build", "2.00.0", "2.0.0\n"):
        change("malformed version " + repr(version), ["wist_version"], version)
    for field, value, label in (("publisher", "REMOVE", "absent Publisher"),
                                ("extra", True, "unknown field"),
                                ("observed_at", "invalid", "invalid timestamp")):
        inner = json.loads(json.dumps(base)); inner["wist_version"] = "2.0.0"
        if value == "REMOVE":
            del inner[field]
        else:
            inner[field] = value
        add("unsupported major with " + label, inner, ("WIST1-E14",))
    inner = json.loads(json.dumps(base)); inner["wist_version"] = "2.0.0"
    inner["change_type"] = "update"; del inner["payload"]
    add("unsupported major with missing predecessor and commitment", inner,
        ("WIST1-E07", "WIST1-E09", "WIST1-E15"))
    for field in ("wist_version", "publisher", "url", "change_type", "observed_at", "meta"):
        for value, label in (("REMOVE", "absent"), (None, "null"), (False, "boolean")):
            change(field + " " + label, [field], value)
    for path, value, label in [
        (["extra"], 1, "unknown Delta member"),
        (["change_type"], "replace", "unknown change type"),
        (["wist_version"], "01.0.0", "leading zero version"),
        (["wist_version"], "1.0.0\n", "version final newline"),
        (["wist_version"], "１.0.0", "non ASCII version"),
        (["prev"], None, "null predecessor"),
        (["prev"], "sha256:" + "a" * 63, "short predecessor"),
        (["prev"], "sha256:" + "a" * 64 + "\n", "predecessor final newline"),
        (["payload"], None, "null commitment"),
        (["payload", "extra"], 1, "unknown commitment member"),
        (["payload", "commitment"], "REMOVE", "absent commitment digest"),
        (["payload", "commitment"], delta["payload"]["commitment"] + "\n", "commitment final newline"),
        (["payload", "alg"], "SHA256", "wrong commitment algorithm"),
        (["payload", "bytes"], -1, "negative bytes"),
        (["payload", "bytes"], 0.5, "fractional bytes"),
        (["payload", "bytes"], True, "boolean bytes"),
        (["payload", "bytes"], "1", "string bytes"),
        (["payload", "bytes"], "REMOVE", "absent bytes"),
        (["meta", "extra"], 1, "unknown metadata member"),
        (["meta", "lang"], "REMOVE", "absent language"),
        (["meta", "lang"], "EN", "uppercase primary language"),
        (["meta", "lang"], "en\n", "language final newline"),
        (["meta", "lang"], "en-abcdefghi", "long language subtag"),
        (["meta", "topics"], None, "null topics"),
        (["meta", "topics"], ["topic"] * 11, "eleven topics"),
        (["meta", "topics"], ["😀" * 65], "topic scalar overflow"),
        (["meta", "topics"], [5], "nonstrings in topics"),
        (["meta", "license"], None, "null license"),
        (["meta", "license"], "😀" * 65, "license scalar overflow"),
    ]:
        change(label, path, value)
    for path, value, label in [
        (["meta", "lang"], "zh-Hant-HK", "language multiple subtags"),
        (["meta", "lang"], "en-a-a", "lexical language without registry checks"),
        (["meta", "topics"], ["😀" * 64] * 10, "ten scalar boundary topics"),
        (["meta", "license"], "😀" * 64, "license scalar boundary"),
        (["meta", "license"], "", "empty license"),
        (["payload", "bytes"], 0, "zero bytes"),
        (["payload", "bytes"], 0.0, "decimal zero bytes"),
        (["payload", "bytes"], 38944.0, "decimal byte cap"),
    ]:
        change(label, path, value, ())
    for path, value, label in [
        (["extra"], 1, "unknown Envelope member"),
        (["sig", "extra"], 1, "unknown signature member"),
        (["sig", "key_id"], "😀" * 65, "signature identifier scalar overflow"),
        (["sig", "key_id"], None, "null signature identifier"),
        (["sig", "alg"], "Ed448", "wrong signature algorithm"),
        (["sig", "alg"], "REMOVE", "absent signature algorithm"),
        (["sig"], None, "null signature"),
        (["sig"], "REMOVE", "absent signature"),
    ]:
        add(label, base, ("WIST1-E14",), [(path, value)])
    change("absent new commitment", ["payload"], "REMOVE", ("WIST1-E09",))
    change("oversized commitment", ["payload", "bytes"], 38945, ("WIST1-E04",))
    change("bytes beyond unsigned integer storage", ["payload", "bytes"], 1e30)
    change("safe integer bytes above default cap", ["payload", "bytes"], 9007199254740991, ("WIST1-E04",))
    change("unsafe integer bytes", ["payload", "bytes"], 9007199254740992.0)
    for name, amount, cap, allowed in [
        ("raised commitment cap", 38945, 38945, ()),
        ("lowered commitment cap", 38944, 38943, ("WIST1-E04",)),
    ]:
        change(name, ["payload", "bytes"], amount, allowed)
        for case in cases[-2:]:
            case["commitment_cap_bytes"] = cap
    for cap, allowed in [(26, ()), (25, ("WIST1-E11",))]:
        add("URL active cap " + str(cap), base, allowed)
        for case in cases[-2:]:
            case["url_cap_bytes"] = cap
    change("URL octet cap", ["url"], "https://example.com/" + "a" * 2028, ("WIST1-E11",))
    change("URL raised cap", ["url"], "https://example.com/" + "a" * 2030, ())
    for case in cases[-2:]:
        case["url_cap_bytes"] = 2052
    change("HTTP URL", ["url"], "http://example.com/page", ("WIST1-E03",))
    for kind in ("attest", "delete"):
        inner = json.loads(json.dumps(base)); inner["change_type"] = kind
        add(kind + " forbidden commitment", inner, ("WIST1-E14",))
        del inner["payload"]
        add(kind + " absent predecessor", inner, ("WIST1-E07",))
    inner = json.loads(json.dumps(base)); inner["change_type"] = "update"; del inner["payload"]
    add("update absent predecessor and commitment", inner, ("WIST1-E07", "WIST1-E09"))
    inner["meta"]["lang"] = "en\n"
    add("malformed metadata precedes semantic omissions", inner, ("WIST1-E14",))
    transports = []
    for malformed, wrong_id, foreign in itertools.product((False, True), repeat=3):
        inner = json.loads(json.dumps(base))
        if malformed:
            inner["change_type"] = "replace"
        doc = sign_envelope("delta", inner, KID1)
        actual_id = "sha256:" + sha256_hex(rfc8785.dumps(inner))
        transports.append({"envelope": doc, "requested_id": "sha256:" + "0" * 64 if wrong_id else actual_id,
                           "feed_domain": "other.example" if foreign else "example.com",
                           "expected": "WIST1-E14" if malformed else "WIST2-E03" if wrong_id or foreign else "association_satisfied"})
    return {"note": "WIST-1 sections 3.7/7 and WIST-2 section 5. Each allowed set covers only field, "
            "signature, URL and static change-type/commitment checks under fresh supplied authority. "
            "Caps use defaults unless a case supplies an active cap; no parameter schedule replay is asserted. "
            "An empty set is not complete admission. No predecessor history, live clock, refresh/retrieval, "
            "Payload content, Log inclusion or durable state is supplied. Commitment mutations do not "
            "assert Payload validity. Transport cases supply logical Feed and requested ID without HTTP.",
            "author_key": b64u(pub_raw), "cases": cases, "transport_cases": transports}


write_json(WIST1 / "delta-fields.json", delta_field_vectors())


def delta_attribution_vectors():
    keys = [Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32) for n in range(91, 99)]
    parent, child, external = "example.com", "child.example.com", "elsewhere.example"
    url = "https://child.example.com/page"

    def binding(key, nbf="2026-08-01T00:00:00Z"):
        return jwk(raw_public(key), nbf)

    def declaration(domain, key, extra=(), **fields):
        inner = {"wist_version": "1.0.0", "domain": domain, "seq": 0,
                 "keys": [binding(key), *extra]}
        if domain != child:
            inner["subdomain_scope"] = [child]
        inner.update(fields)
        return sign_envelope_with(key, "publisher", inner, kid_of(raw_public(key)))

    def signed(domain, key, **fields):
        inner = dict(delta, publisher=domain, url=url)
        inner.update(fields)
        return sign_envelope_with(key, "delta", inner, kid_of(raw_public(key)))

    shared = [declaration(domain, keys[0]) for domain in (parent, child)]
    distinct = [shared[0], declaration(child, keys[1])]
    copied = [shared[0], declaration(child, keys[1], [binding(keys[0])])]
    cases = []

    def add(name, declarations, envelopes, outcomes, **extra):
        cases.append(dict(name=name, declarations=declarations, envelopes=envelopes,
                          expected=outcomes, delta_ids=[decl_hash(e["delta"]) for e in envelopes], **extra))

    add("shared keys retain separate authors and IDs", shared,
        [signed(d, keys[0]) for d in (parent, child)], ["accepted", "accepted"])
    add("distinct keys and equal content retain separate IDs", distinct,
        [signed(parent, keys[0]), signed(child, keys[1])], ["accepted", "accepted"])
    add("copied key does not steal an existing author's Delta", copied,
        [signed(parent, keys[0])], ["accepted"])
    changed = signed(parent, keys[0]); changed["delta"]["publisher"] = child
    add("author tampering requires a new signature even with shared keys", shared, [changed], ["WIST1-E01"])
    unlisted = signed(parent, keys[0]); unlisted["sig"]["key_id"] = kid_of(raw_public(keys[1]))
    add("unlisted identifier cannot borrow another domain's key", copied, [unlisted], ["WIST1-E02"])
    add("unknown author cannot borrow a scoped matching key", shared,
        [signed("unknown.example", keys[0])], ["WIST1-E02"])
    add("another domain's matching identifier does not suppress author", distinct,
        [signed(child, keys[1])], ["accepted"])
    add("explicit nonancestor scope", [declaration(external, keys[0])],
        [signed(external, keys[0])], ["accepted"])
    no_scope = declaration(parent, keys[0], subdomain_scope=[])
    add("another author's scope supplies no authority", [no_scope, shared[1]],
        [signed(parent, keys[0])], ["WIST1-E03"])
    future = declaration(parent, keys[0], keys=[binding(keys[0], nbf="2026-08-03T00:00:00Z")])
    add("another author's earlier key supplies no bound", [future, shared[1]],
        [signed(parent, keys[0])], ["WIST1-E02"])
    expired = declaration(parent, keys[0], keys=[dict(binding(keys[0]), exp=nbf_at("2026-08-01T12:00:00Z"))])
    add("another author's unexpired key supplies no bound", [expired, shared[1]],
        [signed(parent, keys[0])], ["WIST1-E02"])
    excluded = declaration(parent, keys[1], keys=[binding(keys[1]),
        jwk(b"\x01" + bytes(31), "2026-08-01T00:00:00Z")])
    add("excluded author entry cannot borrow another domain's usable key", [excluded, shared[1]],
        [signed(parent, keys[0])], ["WIST1-E02"])
    for host in ("a", "xn--bcher-kva.example", "ab--cd.example"):
        add("canonical host " + host, [declaration(host, keys[0])],
            [signed(host, keys[0])], ["accepted"])
    for name, host in [("missing", None), ("null", None), ("number", 1), ("array", []),
                       ("empty", ""), ("uppercase", "EXAMPLE.com"), ("dot", "example.com."),
                       ("Unicode", "bücher.example"), ("port", "example.com:443"),
                       ("bad A label", "xn--.example"), ("oversized", "a" * 64 + ".com")]:
        env = signed(parent, keys[0])
        env["delta"]["publisher"] = host
        if name == "missing":
            del env["delta"]["publisher"]
        env = sign_envelope_with(keys[0], "delta", env["delta"], kid_of(raw_public(keys[7])))
        add("Publisher field " + name, shared, [env], ["WIST1-E14"])
    valid = signed(parent, keys[0])
    for feed_domain, seen, redirected, expected in [
            (parent, False, "www.example.com", "accepted"),
            (parent, True, "www.example.com", "accepted"),
            (child, False, child, "WIST2-E03"), (child, True, child, "WIST2-E03")]:
        add("Feed association " + feed_domain + (" seen" if seen else " new"),
            [declaration(parent, keys[0], subdomain_scope=[child, "www.example.com"]), shared[1]],
            [valid], [expected], feed_domain=feed_domain, already_seen=seen,
            serving_host=redirected)
    malformed = signed(parent, keys[0]); del malformed["delta"]["publisher"]
    add("Publisher field precedes Feed association", shared, [malformed], ["WIST1-E14"],
        feed_domain=child, already_seen=True)

    start = datetime.datetime(2026, 8, 2, 12, tzinfo=datetime.timezone.utc)
    def timestamp(height):
        return (start + datetime.timedelta(hours=height)).isoformat().replace("+00:00", "Z")
    first = declaration(parent, keys[0], recovery_keys=[binding(keys[7])])
    def replacement(previous, key, signer, **fields):
        inner = dict(previous["publisher"], seq=previous["publisher"]["seq"] + 1,
                     prev_declaration=decl_hash(previous["publisher"]), keys=[binding(key)])
        inner.update(fields)
        return sign_envelope_with(signer, "publisher", inner, kid_of(raw_public(signer)))
    ordinary = replacement(first, keys[2], keys[0])
    owner = replacement(ordinary, keys[3], keys[7])
    competitor = replacement(owner, keys[4], keys[4])
    follower = replacement(owner, keys[5], keys[3], seq=4)
    reset = replacement(follower, keys[6], keys[6], seq=5)
    declarations_at = {0: [first, declaration(child, keys[0]), declaration(external, keys[2])],
                       1: [ordinary], 2: [owner], 3: [competitor], 4: [follower], 171: [reset]}
    authors_at = {0: keys[0], 1: keys[2], 2: keys[3], 3: keys[3], 4: keys[5],
                  170: keys[5], 171: keys[6], 172: keys[6]}
    epochs, tips, envelopes, probes = [], {}, {}, []
    tree_leaves = []
    for height in range(173):
        entries = [{"type": "publisher_declaration", "body": env}
                   for env in declarations_at.get(height, [])]
        if height in (0, 1, 170, 171, 172):
            env = signed(parent, authors_at[height], observed_at=timestamp(height))
            if parent in tips:
                env["delta"].pop("payload")
                env["delta"].update(change_type="attest", prev=tips[parent])
                env = sign_envelope_with(authors_at[height], "delta", env["delta"],
                                         kid_of(raw_public(authors_at[height])))
            entries.append({"type": "publisher_delta", "body": env})
            tips[parent] = decl_hash(env["delta"]); envelopes[height] = env
        if height == 0:
            env = signed(child, keys[0], observed_at=timestamp(height))
            entries.append({"type": "publisher_delta", "body": env})
            tips[child] = decl_hash(env["delta"])
        entries.sort(key=lambda e: ((0 if e["type"] == "publisher_declaration" else 2),
                                     leaf_hash(rfc8785.dumps(e))))
        epoch, tree_leaves = seal("log-key", priv, tree_leaves, entries, height, timestamp(height))
        epochs.append(epoch)
        if height in (0, 1, 3, 4, 170, 171):
            def probe(name, domain, key, expected, stage=None, **fields):
                stage = stage or ("admission" if height in (3, 4) else "sealing")
                env = signed(domain, key, observed_at=timestamp(height + 1), prev=tips[domain])
                env["delta"].pop("payload"); env["delta"]["change_type"] = "attest"
                env["delta"].update(fields)
                env = sign_envelope_with(key, "delta", env["delta"], kid_of(raw_public(key)))
                probes.append(dict(name=name, height=height, stage=stage, envelope=env, expected=expected))
            key = keys[3] if height in (3, 4) else authors_at[height]
            probe("same author continues at " + str(height), parent, key, "accepted")
            probe("foreign predecessor at " + str(height), parent, key, "WIST1-E07", prev=tips[child])
            probe("wrong URL predecessor at " + str(height), parent, key, "WIST1-E07", url="https://child.example.com/other")
            env = signed(parent, key, observed_at=timestamp(height + 1))
            probes.append(dict(name="chain cannot restart at " + str(height), height=height,
                               stage="admission" if height in (3, 4) else "sealing", envelope=env, expected="WIST1-E07"))
            if height in (3, 4):
                for candidate, expected in [(keys[2], "accepted"), (keys[3], "accepted"),
                                            (keys[4], "WIST1-E02"), (keys[5], "WIST1-E02")]:
                    probe("frozen recovery sources at " + str(height) + " " + str(len(probes)),
                          parent, candidate, expected, stage="admission")
                probe("foreign recovery source cannot authorize child " + str(height),
                      child, keys[2], "WIST1-E02", stage="admission")
            if height == 170:
                probe("expired recovery union", parent, keys[2], "WIST1-E02", stage="admission")
    versions = []
    for name, version, mutation, expected in [
            ("current draft", "1.0.0", None, "accepted"),
            ("same version old draft lacks author", "1.0.0", "missing", "WIST1-E14"),
            ("unknown fields remain forbidden", "1.0.0", "unknown", "WIST1-E14"),
            ("unimplemented major", "2.0.0", None, "WIST1-E15")]:
        env = signed(parent, keys[0], wist_version=version)
        if mutation == "missing": del env["delta"]["publisher"]
        if mutation == "unknown": env["delta"]["extra"] = True
        env = sign_envelope_with(keys[0], "delta", env["delta"], kid_of(raw_public(keys[0])))
        versions.append(dict(name=name, envelope=env, expected=expected))
    return dict(
        note="WIST-1 sections 3.1, 3.5 and 3.8, WIST-2 section 5 and WIST-3 section 7. "
             "Cases test signed author, key, scope and optional logical Feed association, with current initial "
             "Declarations supplied; accepted means those checks only. No live discovery or transport is exercised. "
             "The authenticated hourly history uses the default seven-day recovery window and supplies an "
             "independently pinned head; its Deltas exercise sealing bindings and chain ownership. Probes run "
             "after the named Epoch's Declaration stage and accepted Deltas, using that prefix's sources/tips; "
             "their later observed_at is a supplied test timestamp, not an inclusion claim. Clock, Payload, "
             "quotas and Payloads remain separate. Identity projections exercise owner/reset attribution: whether "
             "the Publisher identity current at at_height is the one that signed at reference_height. "
             "Version cases assume a validator of this exact draft implementing only wire major 1.",
        cases=cases, log_key=dict(key_id="log-key", public_key=b64u(pub_raw)),
        recovery_window_days=7, declaration_activation_epochs=0, epochs=epochs,
        pinned_head=root_token(tree_leaves), probes=probes,
        projection_cases=[
            dict(at_height=4, reference_height=0, publisher=parent, expected_current_identity=True),
            dict(at_height=170, reference_height=0, publisher=parent, expected_current_identity=True),
            dict(at_height=171, reference_height=0, publisher=parent, expected_current_identity=False),
            dict(at_height=171, reference_height=171, publisher=parent, expected_current_identity=True),
            dict(at_height=171, reference_height=0, publisher=child, expected_current_identity=True)],
        version_cases=versions)


write_json(WIST1 / "delta-attribution.json", delta_attribution_vectors())


def recovery_scope_vectors():
    keys = {name: Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        ("wist recovery scope " + name).encode()).digest())
        for name in ("old", "owner", "competitor", "recovery", "admin")}
    start = datetime.datetime(2026, 8, 2, tzinfo=datetime.timezone.utc)
    early = "2026-08-02T00:00:00Z"
    later = "2026-08-02T00:00:01Z"
    domain = "example.com"
    hosts = [domain, "old.example", "owner.example", "retained.example",
             "follower.example", "competitor.example", "stale.example"]

    def timestamp(height):
        return (start + datetime.timedelta(hours=height)).isoformat().replace("+00:00", "Z")

    kids = {name: kid_of(raw_public(key)) for name, key in keys.items()}

    def binding(name, nbf=early):
        return jwk(raw_public(keys[name]), nbf)

    histories, probes = {}, []
    for shared in (False, True):
        name = "shared public key with distinct bounds" if shared else "distinct source public keys"
        owner_key = "old" if shared else "owner"
        owner_binding = binding(owner_key, nbf=later if shared else early)
        initial = sign_envelope_with(keys["old"], "publisher", dict(
            wist_version="1.0.0", domain=domain, seq=0, keys=[binding("old")],
            recovery_keys=[binding("recovery")], subdomain_scope=["stale.example"]), kids["old"])

        def replace(previous, seq, bindings, scope, signer):
            inner = dict(previous["publisher"], seq=seq,
                         prev_declaration=decl_hash(previous["publisher"]),
                         keys=bindings, subdomain_scope=scope)
            return sign_envelope_with(keys[signer], "publisher", inner, kids[signer])

        prior = replace(initial, 1, [binding("old")],
                        ["old.example", "retained.example"], "old")
        owner = replace(prior, 2, [owner_binding, binding("admin")],
                        ["owner.example", "retained.example"], "recovery")
        competitor = replace(owner, 3, [binding("competitor")],
                             ["competitor.example"], "competitor")
        follower = replace(owner, 4, [owner_binding, binding("admin")],
                           ["old.example", "retained.example", "follower.example"], "admin")
        latest = replace(follower, 5, [binding("competitor")], [], "competitor")
        deadline = replace(follower, 6, [owner_binding], [], "admin")
        deadline["publisher"].pop("subdomain_scope")
        deadline = sign_envelope_with(keys["admin"], "publisher", deadline["publisher"], kids["admin"])
        restored = replace(deadline, 7, [owner_binding], hosts[1:], owner_key)
        declarations = {0: [initial], 1: [prior, owner], 2: [competitor], 3: [follower],
                        168: [latest], 169: [deadline], 170: [restored]}
        epochs, tree_leaves = [], []
        for height in range(171):
            entries = [recovery_order_entry(env) for env in declarations.get(height, [])]
            entries.sort(key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
            epoch, tree_leaves = seal("log-key", priv, tree_leaves, entries, height, timestamp(height))
            epochs.append(epoch)
        histories[name] = dict(epochs=epochs, pinned_head=root_token(tree_leaves))

        def add(label, height, stage, signer, host, expected, observed_at=later,
                identifier=None, damage=None):
            env = sign_envelope_with(keys[signer], "delta", dict(delta,
                publisher=domain, url="https://" + host + "/scope", observed_at=observed_at),
                identifier or kids[signer])
            if damage == "signature":
                env["sig"]["value"] = b64u(bytes(64))
            elif damage == "encoding":
                env["sig"]["value"] += "="
            probes.append(dict(name=label, history=name, height=height, stage=stage,
                               envelope=env, expected=expected))

        for height in (1, 2, 3, 168):
            for signer in ("old", owner_key) if not shared else ("old",):
                allowed = ({domain, "old.example", "owner.example", "retained.example"} if shared else
                           {domain, "old.example", "retained.example"} if signer == "old" else
                           {domain, "owner.example", "retained.example"})
                for host in hosts:
                    add(f"frozen source {signer} {host} at {height}", height, "admission", signer, host,
                        "accepted" if host in allowed else "WIST1-E03")
            add(f"competitor signature at {height}", height, "admission", "competitor", domain, "WIST1-E02")
            add(f"forged signature under the old identifier at {height}", height, "admission", "competitor",
                domain, "WIST1-E01", identifier=kids["old"])
            add(f"unknown identifier at {height}", height, "admission", "old", domain, "WIST1-E02",
                identifier=KID5)
            add(f"malformed signature field at {height}", height, "admission", "old", domain, "WIST1-E14",
                identifier=KID5, damage="encoding")
        if shared:
            for height in (1, 3, 168):
                add(f"scope cannot borrow future binding at {height}", height, "admission", "old",
                    "owner.example", "WIST1-E03", observed_at=early)
                add(f"eligible old source at {height}", height, "admission", "old", "old.example",
                    "accepted", observed_at=early)
                add(f"inclusive owner bound at {height}", height, "admission", "old", "owner.example",
                    "accepted", observed_at="2026-08-02t01:00:01.000+01:00")
                add(f"fraction below owner bound at {height}", height, "admission", "old", "owner.example",
                    "WIST1-E03", observed_at="2026-08-02T00:00:00.999999999999Z")
        for host in (domain, "owner.example", "retained.example"):
            expected = "WIST1-E13" if host == "owner.example" else "accepted"
            add("owner queued copy settlement " + host, 169, "settlement", owner_key, host, expected)
        for host in (domain, "old.example", "retained.example"):
            add("old queued copy settlement " + host, 169, "settlement", "old", host,
                "accepted" if shared else "WIST1-E13")
        for height in (169, 170):
            for host in hosts:
                for stage in ("admission", "sealing"):
                    add(f"post settlement {stage} {host} at {height}", height, stage, owner_key, host,
                        "accepted" if height == 170 or host == domain else "WIST1-E03")
        for host in (domain, "old.example", "owner.example", "retained.example"):
            add("historical scope before deadline " + host, 1, "admission", owner_key, host,
                "accepted" if shared or host != "old.example" else "WIST1-E03")
        add("historical pre recovery scope", 0, "sealing", "old", "stale.example", "accepted")
        add("historical scope cannot borrow later grant", 0, "sealing", "old", "old.example", "WIST1-E03")
        add("omitted scope retains Publisher domain", 169, "sealing", owner_key, domain, "accepted")
        add("settlement invalid signature", 169, "settlement", owner_key, domain,
            "WIST1-E13", damage="signature")
        add("settlement malformed field", 169, "settlement", owner_key, domain,
            "WIST1-E14", damage="encoding")
    return dict(note="WIST-1 sections 3.2, 5.1 and 5.2. Authenticated hourly Declaration histories "
        "open recovery at height 1 after a same-Epoch ordinary predecessor, accept a competitor and "
        "a legitimate follower, accept a higher-sequence competitor at 168, settle at 169, then apply "
        "a scope-removing Declaration in that same deadline Epoch. Height 170 grants scopes again. "
        "Admission and sealing probes run after the named Epoch's Declaration stage; settlement probes "
        "run immediately before height 169's Declaration stage. Queued-copy probes reuse height-1 "
        "authority-eligible Envelopes; damaged settlement probes are conditional stage inputs and do not "
        "claim prior queue acceptance. "
        "accepted establishes only signature/binding and scope authority. Probe timestamps are signed "
        "inputs, not claimed live validation times. Chains, clocks, Payload, quotas, durable queue/status "
        "effects and actual Delta inclusion are not exercised. Trusted Log key and pinned heads are "
        "fixture inputs. Signature-invalid twins are checked independently by the reference.",
        log_key=dict(key_id="log-key", public_key=b64u(pub_raw)), recovery_window_days=7, declaration_activation_epochs=0,
        histories=histories, probes=probes)


write_json(WIST1 / "recovery-scope.json", recovery_scope_vectors())


def declaration_refresh_vectors():
    import copy
    domain = "localhost"
    now = "2026-08-09T14:00:00Z"
    seeds = [bytes([n]) * 32 for n in (1, 7, 11)]
    signing = [Ed25519PrivateKey.from_private_bytes(seed) for seed in seeds]

    def signed(inner, body, key, identifier=None):
        return {inner: body, "sig": {"key_id": identifier or kid_of(raw_public(signing[key])),
            "alg": "Ed25519", "value": b64u(signing[key].sign(rfc8785.dumps(body)))}}

    def binding(key, at="2026-08-09T00:00:00Z"):
        return jwk(raw_public(signing[key]), at)

    def declaration(keys, previous=None, signer=0):
        body = dict(wist_version="1.0.0", domain=domain, keys=keys,
                    seq=0 if previous is None else previous["publisher"]["seq"] + 1)
        if previous:
            body["prev_declaration"] = "sha256:" + sha256_hex(rfc8785.dumps(previous["publisher"]))
        return signed("publisher", body, signer)

    original = declaration([binding(0)])
    rotated = declaration([binding(1)], original)
    third = declaration([binding(1), binding(2)], rotated, 1)

    def delta_object(path, key, identifier=None, previous=None, **changes):
        body = copy.deepcopy(delta)
        body.update(publisher=domain, url=f"https://{domain}/{path}", observed_at=now)
        if previous:
            body.update(prev="sha256:" + sha256_hex(rfc8785.dumps(previous["delta"])),
                        change_type="update", observed_at="2026-08-09T14:00:01Z")
        body.update(changes)
        return signed("delta", body, key, identifier)

    cases = []
    def add(name, objects, responses, *, initial=original, feed_key=0, listed=None,
            errors=(), accepted=None, suspended=False, content_budget=None, cached=False):
        ids = ["sha256:" + sha256_hex(rfc8785.dumps(doc["delta"])) for doc in objects]
        feed = signed("feed", dict(wist_version="1.0.0", domain=domain, generated_at=now,
            deltas=ids if listed is None else [ids[i] for i in listed], next=None), feed_key)
        cases.append(dict(name=name, cached=cached, initial=initial, responses=responses,
            feed=feed, deltas=[dict(id=id, envelope=doc) for id, doc in zip(ids, objects)],
            content_budget=content_budget,
            expected=dict(accepted=[ids[i] for i in (range(len(ids)) if accepted is None else accepted)],
                rejected=[[ids[i], code] for i, code in errors], suspended=suspended,
                declaration_requests=1 + len(responses))))

    add("unlisted key rotation", [delta_object("a", 1)], [rotated])
    future = declaration([binding(0), binding(1, at="2026-08-10T00:00:00Z")])
    add("future binding replacement", [delta_object("a", 1)],
        [declaration([binding(1)], future)], initial=future)
    expired = declaration([binding(0), dict(binding(1), exp=nbf_at("2026-08-09T12:00:00Z"))])
    add("expired binding replacement", [delta_object("a", 1)],
        [declaration([binding(1)], expired)], initial=expired)
    excluded_key = jwk(bytes([1]) + bytes(31), "2026-08-09T00:00:00Z")
    excluded = declaration([binding(0), excluded_key])
    add("excluded binding replacement", [delta_object("a", 1)],
        [declaration([binding(1)], excluded)], initial=excluded)
    for name, response in (("unchanged", original), ("unavailable", None),
                           ("invalid signature", dict(rotated, sig=original["sig"]))):
        add(name + " refresh", [delta_object("a", 1)], [response],
            errors=[(0, "WIST1-E02")], accepted=[])
    tampered = delta_object("a", 1)
    tampered["sig"]["value"] = b64u(bytes(64))
    add("remaining signature failure", [tampered], [rotated], errors=[(0, "WIST1-E01")], accepted=[])
    malformed = delta_object("a", 1, observed_at="invalid")
    add("fields do not trigger retry", [malformed], [], errors=[(0, "WIST1-E14")], accepted=[])
    foreign = delta_object("a", 1, publisher="example.com")
    add("foreign Publisher does not trigger retry", [foreign], [], errors=[(0, "WIST2-E03")], accepted=[])
    add("separate Delta attempts", [delta_object("a", 1), delta_object("b", 2)], [rotated, third])
    add("Feed attempt independent from Delta", [delta_object("a", 2)], [rotated, third], feed_key=1)
    ancestor = delta_object("a", 2)
    leaf = delta_object("a", 1, previous=ancestor)
    add("retrieved predecessor has separate attempt", [ancestor, leaf], [rotated, third], listed=[1])
    add("revalidated ID shares attempt", [ancestor, leaf],
        [rotated, declaration([binding(2)], rotated, 1)], listed=[1],
        errors=[(1, "WIST1-E02")], accepted=[0])
    add("initial discovery outside exhausted content budget", [], [], content_budget=0, suspended=True)
    add("periodic discovery outside exhausted content budget", [], [], content_budget=0, suspended=True, cached=True)
    add("Delta retry at content budget boundary", [delta_object("a", 1)], [rotated],
        content_budget="feed and deltas", suspended=True, accepted=[])
    add("Feed retry at content budget boundary", [delta_object("a", 1)], [rotated], feed_key=1,
        content_budget="feed", suspended=True, accepted=[])
    add("failed Delta retry at content budget boundary", [delta_object("a", 1)], [original],
        content_budget="feed and deltas", errors=[(0, "WIST1-E02")], accepted=[])
    page_cases = [
        ("Page first contact needs inclusion", original, 0, 0, [], [original], True, None),
        ("Page refresh cannot supply unsealed authority", original, 0, 1, [original], [rotated], True, None),
        ("Page unchanged refresh", original, 0, 1, [original], [original], True, None),
        ("Page unavailable refresh", original, 0, 1, [original], [None], True, None),
        ("Page invalid refresh", original, 0, 1, [original], [dict(rotated, sig=original["sig"])], True, None),
        ("Page shares the live Feed attempt", original, 1, 1, [original], [rotated], True, None),
        ("Page retry at content budget boundary", original, 0, 1, [original], [rotated], True, "feed and page"),
        ("Page retired source needs no retry", rotated, 1, 0, [original, rotated], [], False, None),
        ("Page first-next source needs no retry", rotated, 1, 1, [original, rotated], [], False, None),
        ("Page later source remains ineligible", third, 2, 2, [original, rotated, third], [third], True, None),
        ("Feed and Delta retries remain independent across a Page walk", original, 1, 0, [original], [rotated, third], False, None),
    ]
    for name, initial, feed_key, page_key, sealed, responses, fails, budget in page_cases:
        delta_key = 2 if len(responses) == 2 else feed_key
        add(name, [delta_object("page-live", delta_key)], responses, initial=initial,
            feed_key=feed_key, accepted=[] if fails else [0], content_budget=budget)
        case = cases[-1]
        body = dict(case["feed"]["feed"], next=f"https://{domain}/.well-known/wist/feed/0.json")
        case["feed"] = signed("feed", body, feed_key)
        case["page"] = signed("feed", dict(wist_version="1.0.0", domain=domain,
            generated_at="2026-08-09T12:30:00Z", deltas=[], next=None), page_key)
        case["sealed"] = [dict(at=f"2026-08-09T{12 + i}:00:00Z", envelope=doc)
                          for i, doc in enumerate(sealed)]
        case["expected"]["noise"] = "WIST2-E04" if fails else None
    return dict(note="WIST-1 section 5.1 and WIST-2 section 5. Signed ordinary-rotation transport "
        "sequences; initial is the first publisher.json response and optionally already cached. "
        "responses lists failure-triggered Declaration responses; null is HTTP unavailability. "
        "Serve feed and each Delta unchanged, with examples/payload.json for every commitment. "
        "Budget strings mean the exact JCS byte lengths of the named served objects, with no "
        "Declaration bytes. An absent numeric limit means a sufficient content budget. "
        "Declaration request counts include initial or periodic discovery. Optional sealed entries "
        "supply the authenticated-prefix context held fixed during a Page walk; they do not prove "
        "Epoch inclusion. Optional empty Pages isolate authentication, not Page cardinality or publication. "
        "Resume and recovery "
        "settlement, complete HTTP resource bounds, sealing and durability require separate integration.",
        domain=domain, now="2026-08-09T14:01:00Z", payload=payload, cases=cases)


write_json(ROOT / "vectors/wist2/declaration-refresh.json", declaration_refresh_vectors())


def feed_field_vectors():
    base = dict(wist_version="1.0.0", domain="localhost",
                generated_at="2026-08-09T14:00:00Z", deltas=[], next=None)
    cases = []

    def add(name, body=None, *, expected="accepted", mutate=None, live=True):
        body = dict(base) if body is None else body
        doc = sign_envelope("feed", body, KID1)
        if mutate:
            mutate(doc)
        try:
            priv.public_key().verify(base64.urlsafe_b64decode(doc["sig"]["value"] + "=="),
                                     rfc8785.dumps(doc["feed"]))
            author_signature = True
        except (KeyError, TypeError, ValueError, InvalidSignature):
            author_signature = False
        cases.append(dict(name=name, envelope=doc, expected=expected, live=live,
                          author_signature=author_signature,
                          code={"fields": "WIST2-E01", "domain": "WIST2-E04",
                                "signature": "WIST2-E04", "accepted": None}[expected],
                          rejection_noise=expected in ("domain", "signature"),
                          declaration_retries=int(expected == "signature")))

    add("valid empty Feed")
    for value in ("0000-02-29T00:00:00Z", "9999-12-31T23:59:59Z"):
        add("timestamp boundary " + value, dict(base, generated_at=value))
    add("unbounded release components", dict(base, wist_version="1." + "9" * 80 + "." + "8" * 80))
    for field in base:
        body = dict(base)
        del body[field]
        add("missing " + field, body, expected="fields")
        if field != "next":
            add("null " + field, dict(base, **{field: None}), expected="fields")
    for domain in ("LOCALHOST", "localhost.", "", "xn--.example", "a" * 64,
                   "a." * 127 + "a", "localhost:443", "bücher.example", 7, [], {}):
        add("invalid domain " + repr(domain), dict(base, domain=domain), expected="fields")
    for host in ("-foo.example", "r2---sn-x.example", "xn--bcher-kva.example"):
        add("valid foreign host " + host, dict(base, domain=host), expected="domain")
    invalid = [
        ("generated_at", value) for value in (
            "2026-02-29T00:00:00Z", "1900-02-29T00:00:00Z", "2026-08-09T24:00:00Z",
            "2026-08-09T14:00:60Z", "2026-08-09T14:00:00.0Z", "2026-08-09T14:00:00+00:00",
            "2026-08-09t14:00:00z", "2026-08-09T14:00:00Z\n", "10000-01-01T00:00:00Z")]
    invalid += [("wist_version", value) for value in (
        "01.0.0", "1.00.0", "1.0.00", "١.0.0", "1.0.0\n", "1.0.0-beta", "1.0.0+build", "1.0", "1..0")]
    invalid += [("next", value) for value in (7, [], "http://localhost/.well-known/wist/feed/0.json",
                 "https://localhost/.well-known/wist/feed/0.json#part")]
    invalid += [("deltas", value) for value in ("wrong", [None], ["sha256:" + "A" * 64],
                ["sha256:" + "0" * 64 + "\n"], ["sha256:" + "0" * 64] * 2)]
    for index, (field, value) in enumerate(invalid):
        body = dict(base, **{field: value})
        add(f"invalid {field} {index}", body, expected="fields")
        add(f"invalid {field} {index} with foreign domain", dict(body, domain="other.example"), expected="fields")
        add(f"invalid {field} {index} with bad signature", body, expected="fields",
            mutate=lambda doc: doc["sig"].update(value=b64u(bytes(64))))
    for count in (1000, 1001):
        ids = ["sha256:" + hashlib.sha256(str(i).encode()).hexdigest() for i in range(count)]
        add(f"Delta count {count}", dict(base, deltas=ids),
            expected="accepted" if count == 1000 else "fields", live=count > 1000)
    for field in ("key_id", "alg", "value"):
        add("missing signature " + field, expected="fields", mutate=lambda doc, f=field: doc["sig"].pop(f))
    for field, value in (("key_id", "é" * 65), ("key_id", None), ("alg", "Other"),
                         ("value", "A" * 85 + "B"), ("value", "A" * 86 + "=="), ("value", None)):
        add("invalid signature " + field + " " + repr(value), expected="fields",
            mutate=lambda doc, f=field, v=value: doc["sig"].update({f: v}))
        add("invalid signature " + field + " " + repr(value) + " with foreign domain",
            dict(base, domain="other.example"), expected="fields",
            mutate=lambda doc, f=field, v=value: doc["sig"].update({f: v}))
    add("scalar key identifier boundary", mutate=lambda doc: doc["sig"].update(key_id="é" * 64), expected="signature")
    add("unknown Envelope member", expected="fields", mutate=lambda doc: doc.update(extra=True))
    add("unknown Feed member", dict(base, extra=True), expected="fields")
    add("unknown signature member", expected="fields", mutate=lambda doc: doc["sig"].update(extra=True))
    add("missing Feed", expected="fields", mutate=lambda doc: doc.pop("feed"))
    add("missing signature", expected="fields", mutate=lambda doc: doc.pop("sig"))
    add("foreign domain", dict(base, domain="other.example"), expected="domain")
    add("foreign domain and bad signature", dict(base, domain="other.example"), expected="domain",
        mutate=lambda doc: doc["sig"].update(value=b64u(bytes(64))))
    add("bad signature", expected="signature", mutate=lambda doc: doc["sig"].update(value=b64u(bytes(64))))
    source = sign_envelope("publisher", dict(wist_version="1.0.0", domain="localhost", seq=0,
        keys=[jwk(pub_raw, "2026-08-09T00:00:00Z")]), KID1)
    return dict(description="Feed Envelope field and identity precedence under WIST-2 section 5. "
                "Serve each live candidate unchanged after the supplied Declaration, re-serving that "
                "Declaration on retry. Field checks also apply to Pages; these supplied-context probes "
                "establish no Page publication, history partitioning or Feed regression state.",
                host="localhost", declaration=source, cases=cases)


write_json(ROOT / "vectors/wist2/feed-fields.json", feed_field_vectors())


def feed_next_vectors():
    host = "localhost"
    prefix = f"https://{host}/.well-known/wist/"
    fresh = "sha256:" + hashlib.sha256(b"feed-next unseen Delta").hexdigest()
    retained = "2026-08-09T14:00:00Z"
    base = dict(wist_version="1.0.0", domain=host, generated_at=retained, deltas=[fresh], next=None)
    codes = {"fields": "WIST2-E01", "domain": "WIST2-E04", "signature": "WIST2-E04",
             "regression": "WIST2-E05", "unread": None, "end": None, "target": "WIST2-E01",
             "followed": None}
    cases = []

    def add(name, next_value, expected, body=None, *, live=True, seen=(), mutate=None):
        body = dict(base if body is None else body, next=next_value)
        doc = sign_envelope("feed", body, KID1)
        if mutate:
            mutate(doc)
        cases.append(dict(name=name, envelope=doc, live=live, seen=list(seen), expected=expected,
                          code=codes[expected],
                          next_read=expected in ("end", "target", "followed"),
                          fetch=next_value if expected == "followed" else None,
                          deltas_admitted=expected in ("unread", "end", "target", "followed"),
                          declaration_retries=int(expected == "signature")))

    add("null next ends the walk", None, "end")
    add("Page 0 target", prefix + "feed/0.json", "followed")
    add("query preserved", prefix + "feed/0.json?v=2&x=%2F", "followed")
    add("empty query preserved", prefix + "feed/0.json?", "followed")
    add("encoded separator inside the layout", prefix + "feed/a%2Fb.json", "followed")
    add("uppercase escape of a reserved octet", prefix + "feed/%E2%82%AC.json", "followed")
    add("regressed Page with valid target", prefix + "feed/0.json", "followed",
        dict(base, generated_at="2026-08-09T13:00:00Z"), live=False)
    bad = "https://www.localhost/.well-known/wist/feed/0.json"
    for name, value in (
            ("scope host", bad),
            ("foreign host", "https://other.example/.well-known/wist/feed/0.json"),
            ("uppercase host", "https://LOCALHOST/.well-known/wist/feed/0.json"),
            ("explicit default port", "https://localhost:443/.well-known/wist/feed/0.json"),
            ("other port", "https://localhost:8443/.well-known/wist/feed/0.json"),
            ("userinfo", "https://user@localhost/.well-known/wist/feed/0.json"),
            ("no host", "https://"),
            ("empty path", "https://localhost"),
            ("layout root without slash", prefix[:-1]),
            ("prefix elsewhere in the path", "https://localhost/x/.well-known/wist/feed/0.json"),
            ("doubled slash before the prefix", "https://localhost//.well-known/wist/feed/0.json"),
            ("sibling layout", "https://localhost/.well-known/wistx/feed/0.json"),
            ("dot segment", prefix + "feed/../publisher.json"),
            ("encoded dot segment", prefix + "%2E%2E/secret.json"),
            ("encoded separator in prefix", "https://localhost/.well-known/wist%2Ffeed/0.json"),
            ("lowercase escape hex", prefix + "feed/%e2%82%ac.json"),
            ("encoded unreserved octet", prefix + "feed/%7Ea.json"),
            ("lowercase escape hex in the query", prefix + "feed/0.json?x=%2f"),
            ("control octet", prefix + "feed/0.json\n")):
        add(name, value, "target")
    for name, value in (("non string", 7), ("array", []),
                        ("http scheme", "http://localhost/.well-known/wist/feed/0.json"),
                        ("uppercase scheme", "HTTPS://localhost/.well-known/wist/feed/0.json"),
                        ("fragment", prefix + "feed/0.json#0"), ("empty string", "")):
        add(name, value, "fields")
    add("ingested Feed with bad target", bad, "unread", seen=[fresh])
    add("empty Feed with bad target", bad, "unread", dict(base, deltas=[]))
    add("ingested Feed with valid target", prefix + "feed/0.json", "unread", seen=[fresh])
    add("bad signature with bad target", bad, "signature",
        mutate=lambda doc: doc["sig"].update(value=b64u(bytes(64))))
    add("foreign domain with bad target", bad, "domain", dict(base, domain="other.example"))
    add("regressed live Feed with bad target", bad, "regression",
        dict(base, generated_at="2026-08-09T13:00:00Z"))
    add("regressed Page with bad target", bad, "target",
        dict(base, generated_at="2026-08-09T13:00:00Z"), live=False)
    source = sign_envelope("publisher", dict(wist_version="1.0.0", domain=host, seq=0,
        subdomain_scope=["www.localhost"],
        keys=[jwk(pub_raw, "2026-08-09T00:00:00Z")]), KID1)
    return dict(description="Feed and Page next targets under WIST-2 section 3.2. Each case is the "
                "object the walk reached, live or sealed, after the supplied Declaration; seen lists "
                "the Delta IDs already seen and retained_generated_at the durable live-Feed "
                "observation. fetch is the exact URL a following Aggregator requests; a target "
                "failure keeps the object's Deltas and fetches nothing.",
                host=host, retained_generated_at=retained, declaration=source, cases=cases)


write_json(ROOT / "vectors/wist2/feed-next.json", feed_next_vectors())


def feed_regression_vectors():
    source = feed_field_vectors()["declaration"]
    early = "2026-08-09T13:59:59Z"
    base = "2026-08-09T14:00:00Z"
    later = "2026-08-09T14:00:01Z"
    final = "9999-12-31T23:59:59Z"

    def observation(name, at, retained, code=None, *, domain="localhost", bad_signature=False,
                    extra=False):
        body = dict(wist_version="1.0.0", domain=domain, generated_at=at, deltas=[], next=None)
        if extra:
            body["extra"] = True
        doc = sign_envelope("feed", body, KID1)
        if bad_signature:
            doc["sig"]["value"] = b64u(bytes(64))
        retained_s = None
        if retained is not None:
            civil = retained if not retained.startswith("0000") else "0400" + retained[4:]
            retained_s = calendar.timegm(time.strptime(civil, "%Y-%m-%dT%H:%M:%SZ"))
            if retained.startswith("0000"):
                retained_s -= 146097 * 86400
        return dict(name=name, envelope=doc, retained=retained, retained_s=retained_s, code=code,
                    noise="WIST2-E04" if code == "WIST2-E04" else
                    "WIST2-E02" if code is None else None,
                    declaration_retries=int(bad_signature and not extra and domain == "localhost"))

    cases = [dict(name="nondecreasing observations", observations=[
        observation("first", base, base),
        observation("equal", base, base),
        observation("older", early, base, "WIST2-E05"),
        observation("newer", later, later),
        observation("previous maximum", base, later, "WIST2-E05"),
        observation("equal maximum", later, later)]),
        dict(name="only authenticated fields establish a baseline", observations=[
            observation("invalid fields", final, None, "WIST2-E01", extra=True),
            observation("invalid signature", final, None, "WIST2-E04", bad_signature=True),
            observation("foreign domain", final, None, "WIST2-E04", domain="other.example"),
            observation("first authenticated", base, base),
            observation("invalid newer signature", final, base, "WIST2-E04", bad_signature=True),
            observation("newer authenticated", later, later)]),
        dict(name="regression diagnostic follows authentication", observations=[
            observation("baseline", base, base),
            observation("older invalid fields and signature", early, base, "WIST2-E01",
                        extra=True, bad_signature=True),
            observation("older foreign domain and signature", early, base, "WIST2-E04",
                        domain="other.example", bad_signature=True),
            observation("older bad signature", early, base, "WIST2-E04", bad_signature=True),
            observation("older authenticated", early, base, "WIST2-E05")]),
        dict(name="full range without a validator clock bound", observations=[
            observation("year zero", "0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"),
            observation("final representable second", final, final),
            observation("clock contemporary regression", base, final, "WIST2-E05"),
            observation("equal final second", final, final)])]
    return dict(description="WIST-2 section 3.2 ordered live Feed observations. Start each case "
                "without retained state and reopen durable state between observations. Serve the "
                "supplied Declaration on discovery and retries. Empty Feeds isolate observation "
                "state; Pages, downstream failures and Declaration transitions require integration.",
                host="localhost", declaration=source, cases=cases)


write_json(ROOT / "vectors/wist2/feed-regression.json", feed_regression_vectors())

def delta_cap_time_vectors():
    start = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc)

    def at(seconds):
        return (start + datetime.timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')

    defaults = dict(url_cap_bytes=2048, extract_cap_bytes=32768,
                    links_cap_bytes=4096, link_url_cap_bytes=2048, summary_cap_bytes=2048)
    low = dict(url_cap_bytes=64, extract_cap_bytes=32,
               links_cap_bytes=256, link_url_cap_bytes=64, summary_cap_bytes=32)
    high = {key: value * 2 for key, value in low.items()}
    schedule = [(0, 169, low, False), (1, 169, low, True),
                (169, 338, high, True), (170, 338, high, False),
                (338, 507, low, False), (339, 507, low, True)]

    def profile(seconds):
        return defaults if seconds < 169 * 3600 else low if seconds < 338 * 3600 else high if seconds < 507 * 3600 else low

    def links(size):
        urls = [f'https://outside.example/{n}' + 'x' * 17 for n in range(5)]
        value = dict(total=len(urls), urls=urls)
        urls[-1] += 'x' * (size - len(rfc8785.dumps(value)))
        assert len(rfc8785.dumps(value)) == size
        return value

    objects = {}
    for cohort in ('early', 'later'):
        for field in (*low, 'derived'):
            for extra in (0, 1):
                name = f'{cohort} {field} {extra}'
                content = dict(extract='', links=dict(total=0, urls=[]), summary=dict(title=''))
                url = 'https://example.com/' + name.replace(' ', '/')
                if field == 'url_cap_bytes':
                    url += 'x' * (low[field] + extra - len(rfc8785.dumps(url)))
                elif field == 'extract_cap_bytes':
                    content['extract'] = 'x' * (low[field] - 2 + extra)
                elif field == 'summary_cap_bytes':
                    content['summary']['title'] = 'x' * (low[field] - 12 + extra)
                elif field == 'link_url_cap_bytes':
                    link = 'https://outside.example/'
                    link += 'x' * (low[field] + extra - len(rfc8785.dumps(link)))
                    content['links'] = dict(total=1, urls=[link])
                elif field == 'links_cap_bytes':
                    content['links'] = links(low[field] + extra)
                else:
                    content = dict(extract='x' * (low['extract_cap_bytes'] - 2 + extra),
                                   links=links(low['links_cap_bytes']),
                                   summary=dict(title='x' * (low['summary_cap_bytes'] - 12)))
                salt = hashlib.sha256(('wist cap fixture ' + name).encode()).digest()[:16]
                payload = dict(wist_version='1.0.0', salt=b64u(salt), content=content)
                raw = rfc8785.dumps(content)
                body = dict(wist_version='1.0.0', publisher='example.com', url=url,
                            observed_at='2026-08-04T04:00:00+03:00', change_type='new',
                            meta=dict(lang='en'), payload=dict(
                                commitment='hmac-sha256:' + hmac.new(salt, raw, hashlib.sha256).hexdigest(),
                                alg='HMAC-SHA256', bytes=len(raw)))
                objects[name] = dict(envelope=sign_envelope('delta', body, KID1), payload=payload,
                                     id=decl_hash(body), sealed_height=168 if cohort == 'early' else 338)

    anchor = objects['early extract_cap_bytes 1']
    attestation_body = dict(wist_version='1.0.0', publisher='example.com',
                            url=anchor['envelope']['delta']['url'], change_type='attest',
                            observed_at=at(169 * 3600), meta=dict(lang='en'), prev=anchor['id'])
    attestation = sign_envelope('delta', attestation_body, KID1)
    replacement = objects['later extract_cap_bytes 1']
    body = dict(replacement['envelope']['delta'], url=attestation_body['url'], change_type='update',
                observed_at=at(337 * 3600), prev=decl_hash(attestation_body))
    replacement.update(envelope=sign_envelope('delta', body, KID1), id=decl_hash(body))

    ranks = dict(publisher_declaration=0, registry_update=1, publisher_delta=2)

    def epoch(height, leaves, entries):
        entries = sorted(entries, key=lambda entry: (ranks[entry['type']], leaf_hash(rfc8785.dumps(entry))))
        return seal('test-log-k1', priv, leaves, entries, height, at(height * 3600))

    epochs, tree_leaves = [], []
    leaves_before = []
    for height in range(509):
        entries = []
        if height == 0:
            entries.append(dict(type='publisher_declaration', body=sign_envelope('publisher', publisher, KID1)))
        if height == 169:
            entries.append(dict(type='publisher_delta', body=attestation))
        for seal_height, effective, values, links_only in schedule:
            if height == seal_height:
                for parameter, value in values.items():
                    if (parameter == 'links_cap_bytes') != links_only:
                        continue
                    update = dict(wist_version='1.0.0', action='parameter_change', subject=parameter,
                                  details=dict(parameter=parameter, value=value), effective_at=at(effective * 3600))
                    entries.append(dict(type='registry_update', body=sign_envelope('update', update, 'test-log-k1')))
        entries.extend(dict(type='publisher_delta', body=obj['envelope'])
                       for obj in objects.values() if obj['sealed_height'] == height)
        leaves_before.append(tree_leaves)
        current, tree_leaves = epoch(height, tree_leaves, entries)
        epochs.append(current)

    def result(obj, caps, with_payload=True):
        body = obj['envelope']['delta']
        content = obj['payload']['content']
        if len(rfc8785.dumps(body['url'])) > caps['url_cap_bytes']:
            return 'WIST1-E11'
        if (body['payload']['bytes'] > sum(caps[key] for key in ('extract_cap_bytes', 'links_cap_bytes', 'summary_cap_bytes')) + 32
                or with_payload and (any(len(rfc8785.dumps(content[field])) > caps[field + '_cap_bytes'] for field in ('extract', 'links', 'summary'))
                                     or any(len(rfc8785.dumps(url)) > caps['link_url_cap_bytes'] for url in content['links']['urls']))):
            return 'WIST1-E04'
        return None

    probes = []
    for name, obj in objects.items():
        for boundary in (169, 338, 507):
            for before in (True, False):
                begin = boundary * 3600 - int(before)
                caps = profile(begin)
                probes.append(dict(name=f'{name} admission {boundary} {before}', object=name,
                                   stage='admission', prefix_height=boundary - 1, started_at=at(begin),
                                   completed_at=at(boundary * 3600 + 1), restart=True,
                                   expected_profile=caps, expected_delta=result(obj, caps, False), expected=result(obj, caps)))
            caps = profile(boundary * 3600)
            probes.append(dict(name=f'{name} sealing {boundary}', object=name, stage='sealing',
                               candidate_height=boundary, admitted_at=at(168 * 3600),
                               restart=True, expected_profile=caps, expected_delta=result(obj, caps, False), expected=result(obj, caps)))
        for replay in (obj['sealed_height'], 508):
            caps = profile(obj['sealed_height'] * 3600)
            probes.append(dict(name=f'{name} historical {replay}', object=name, stage='historical',
                               prefix_height=replay, checked_at=at(replay * 3600), restart=True,
                               expected_profile=caps, expected_delta=result(obj, caps, False), expected=result(obj, caps)))

    invalid_epochs = []
    for name, obj in objects.items():
        if name.startswith('later') and name.endswith('1'):
            body = dict(obj['envelope']['delta'])
            if body['change_type'] == 'update':
                body.update(change_type='new', url='https://example.com/invalid/extract',
                            observed_at='2026-08-04T01:00:00Z')
                del body['prev']
            envelope = sign_envelope('delta', body, KID1)
            candidate, candidate_leaves = epoch(169, leaves_before[169],
                                                [dict(type='publisher_delta', body=envelope)])
            invalid_epochs.append(dict(name=name, epoch=candidate, pinned_head=root_token(candidate_leaves),
                                       payload=obj['payload'], expected=result(obj, low)))
    return dict(note='WIST-1 section 3.6 and WIST-4 section 5. One authenticated hourly history supplies a Declaration, cap amendments and unique content-bearing Deltas. Amendments have at least seven days of grace; lower link caps precede lower aggregate caps, and larger aggregate caps precede larger link caps. Probes independently check caps at each stage, not admission membership or permission to re-admit included IDs; admission probes resume their retained attempt across a boundary, sealing probes recheck objects under a supplied earlier valid cap profile, and historical probes retrieve the committing Delta profile from its actual inclusion. Repeating a probe with restart reconstructs inputs from the pinned prefix, not current defaults. Invalid candidate Epochs branch from height 168. Cap checks, signatures, inclusion and commitments are exercised; live queue mutation, crash durability, HTTP retrieval and complete governance acceptance are not established.',
                log_key=dict(key_id='test-log-k1', public_key=b64u(pub_raw)), defaults=defaults,
                epochs=epochs, pinned_head=root_token(tree_leaves), objects=objects, probes=probes, invalid_epochs=invalid_epochs)


write_json(WIST1 / 'delta-cap-time.json', delta_cap_time_vectors())


def payload_link_vectors():
    candidates = [
        ('empty', [], 0, None),
        ('external', ['https://example.org/'], 1, None),
        ('declared remainder', ['https://example.org/'], 2, None),
        ('empty prefix', [], 1, None),
        ('document order', ['https://z.example.org/', 'https://a.example.org/'], 2, None),
        ('query identity', ['https://example.org/?b=2&a=1', 'https://example.org/?a=1&b=2'], 2, None),
        ('empty query', ['https://example.org/?'], 1, None),
        ('nondefault port', ['https://example.org:8443/'], 1, None),
        ('suffix lookalike', ['https://notexample.com/', 'https://example.com.evil.org/'], 2, None),
        ('reserved escape', ['https://example.org/a%2Fb'], 1, None),
        ('duplicate', ['https://example.org/', 'https://example.org/'], 2, 'WIST1-E12'),
        ('underdeclared total', ['https://example.org/'], 0, 'WIST1-E12'),
        ('internal domain', ['https://example.com/'], 1, 'WIST1-E12'),
        ('internal subdomain', ['https://a.b.example.com/'], 1, 'WIST1-E12'),
        ('internal port', ['https://example.com:8443/'], 1, 'WIST1-E12'),
        ('fragment', ['https://example.org/#part'], 1, 'WIST1-E12'),
        ('empty fragment', ['https://example.org/#'], 1, 'WIST1-E12'),
        ('insecure scheme', ['http://example.org/'], 1, 'WIST1-E12'),
        ('uppercase host', ['https://EXAMPLE.ORG/'], 1, 'WIST1-E12'),
        ('normalization alias', ['https://example.org/', 'https://EXAMPLE.ORG/'], 2, 'WIST1-E12'),
        ('default port', ['https://example.org:443/'], 1, 'WIST1-E12'),
        ('empty path', ['https://example.org'], 1, 'WIST1-E12'),
        ('dot segment', ['https://example.org/a/../b'], 1, 'WIST1-E12'),
        ('encoded dot segment', ['https://example.org/a/%2E%2E/b'], 1, 'WIST1-E12'),
        ('unreserved escape', ['https://example.org/%7Ename'], 1, 'WIST1-E12'),
        ('escape case', ['https://example.org/a%2fb'], 1, 'WIST1-E12'),
        ('invalid escape', ['https://example.org/%zz'], 1, 'WIST1-E12'),
        ('userinfo', ['https://user@example.org/'], 1, 'WIST1-E12'),
        ('relative path', ['/external'], 1, 'WIST1-E12'),
        ('empty authority', ['https:///external'], 1, 'WIST1-E12'),
        ('control character', ['https://example.org/a\n'], 1, 'WIST1-E12'),
    ]
    cases = []
    for i, (name, urls, total, expected) in enumerate(candidates):
        content = dict(extract='Content', links=dict(total=total, urls=urls), summary=dict(title='Title'))
        salt = hashlib.sha256(f'payload link fixture {i}'.encode()).digest()[:16]
        payload = dict(wist_version='1.0.0', salt=b64u(salt), content=content)
        body = dict(wist_version='1.0.0', publisher='example.com', url=f'https://example.com/link-case-{i}',
                    change_type='new', observed_at='2026-08-09T12:00:00Z', meta=dict(lang='en'),
                    payload=dict(commitment='hmac-sha256:' + hmac.new(salt, rfc8785.dumps(content), hashlib.sha256).hexdigest(),
                                 alg='HMAC-SHA256', bytes=len(rfc8785.dumps(content))))
        cases.append(dict(name=name, envelope=sign_envelope('delta', body, KID1), payload=payload, expected=expected))
    return dict(spec='WIST-1 section 3.6; WIST-2 section 5', public_key=b64u(pub_raw), cases=cases)


write_json(WIST1 / 'payload-links.json', payload_link_vectors())


def payload_field_vectors():
    import copy
    base = dict(wist_version='1.0.0', salt=b64u(bytes(range(16))),
                content=dict(extract='Content', links=dict(total=1, urls=['https://example.org/']),
                             summary=dict(title='Title')))
    cases = []

    def add(name, payload, allowed=(), caps=None, corrupt=False, wrong_length=False):
        content = payload.get('content', base['content']) if isinstance(payload, dict) else base['content']
        encoded = rfc8785.dumps(content)
        salt = bytes(range(16))
        if isinstance(payload, dict) and isinstance(payload.get('salt'), str):
            try:
                salt = base64.urlsafe_b64decode(payload['salt'] + '=' * (-len(payload['salt']) % 4))
            except ValueError:
                pass
        if len(salt) < 16 or corrupt:
            salt = bytes(32) if corrupt else bytes(range(16))
        commitment = 'hmac-sha256:' + hmac.new(salt, encoded, hashlib.sha256).hexdigest()
        body = dict(wist_version='1.0.0', publisher='example.com',
                    url=f'https://example.com/field-case-{len(cases)}', change_type='new',
                    observed_at='2026-08-09T12:00:00Z', meta=dict(lang='en'),
                    payload=dict(commitment=commitment,
                                 alg='HMAC-SHA256', bytes=len(encoded) + int(wrong_length)))
        case = dict(name=name, envelope=sign_envelope('delta', body, KID1),
                    payload=payload, allowed=sorted(allowed), preimage=dict(salt=b64u(salt), content=content))
        if caps:
            caps = dict(caps)
            if 'links_cap_bytes' in caps:
                caps.setdefault('link_url_cap_bytes', caps['links_cap_bytes'] - 21)
            if caps.get('link_url_cap_bytes', 2048) + 21 > caps.get('links_cap_bytes', 4096):
                caps['links_cap_bytes'] = caps['link_url_cap_bytes'] + 21
            case['caps'] = caps
        cases.append(case)

    def changed(path, value):
        payload = copy.deepcopy(base)
        target = payload
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        return payload

    add('valid', copy.deepcopy(base))
    for path in [[], ['content'], ['content', 'links'], ['content', 'summary']]:
        original = base
        for key in path:
            original = original[key]
        for key in original:
            payload = copy.deepcopy(base)
            target = payload
            for part in path:
                target = target[part]
            del target[key]
            add('missing ' + '.'.join([*path, key]), payload, ['WIST1-E14'])
        payload = copy.deepcopy(base)
        target = payload
        for part in path:
            target = target[part]
        target['unknown'] = True
        add('unknown at ' + ('.'.join(path) or 'root'), payload, ['WIST1-E14'])
        for value in [None, [], 'object']:
            payload = changed(path, value) if path else value
            add('object type ' + ('.'.join(path) or 'root') + ' ' + repr(value), payload, ['WIST1-E14'])
    for path in [['wist_version'], ['salt'], ['content', 'extract'],
                 ['content', 'links', 'urls'], ['content', 'links', 'total'],
                 ['content', 'summary', 'title'], ['content', 'summary', 'abstract']]:
        for value in [None, {}, True]:
            add('field type ' + '.'.join(path) + ' ' + repr(value), changed(path, value), ['WIST1-E14'])
    add('nonstring URL', changed(['content', 'links', 'urls'], [1]), ['WIST1-E14'])
    for version in ['0.0.0', '2.0.0', '9' * 40 + '.0.0']:
        add('unsupported ' + version, changed(['wist_version'], version), ['WIST1-E15'])
    for version in ['1.1.0', '1.0.1', '1.' + '9' * 40 + '.' + '8' * 40]:
        add('supported ' + version, changed(['wist_version'], version))
    for version in ['', '01.0.0', '1.01.0', '1.0.00', '1.0', '1.0.0.0',
                    '1.0.0-alpha', '1.0.0+build', '1.0.0\n', '\u0661.0.0', '1.\u0660.0']:
        add('version spelling ' + repr(version), changed(['wist_version'], version), ['WIST1-E14'])
    for salt in ['', b64u(bytes(15)), base['salt'] + '=', base['salt'] + '\n',
                 base['salt'][:-1] + 'x', '+' * 22, 'A' * 23 + '/']:
        add('salt spelling ' + repr(salt), changed(['salt'], salt), ['WIST1-E14'])
    for length in [16, 17, 18, 32]:
        add('salt octets ' + str(length), changed(['salt'], b64u(bytes(length))))
    for label, total in [('zero', 0), ('decimal integral', 1.0), ('exponent integral', 1e0), ('maximum safe', 9007199254740991)]:
        payload = changed(['content', 'links', 'total'], total)
        if total == 0:
            payload['content']['links']['urls'] = []
        add('integer value ' + label, payload)
        if label == 'exponent integral':
            cases[-1]['payload_json'] = json.dumps(payload).replace('"total": 1.0', '"total": 1e0')
    payload = changed(['content', 'links', 'total'], -0.0)
    payload['content']['links']['urls'] = []
    add('negative zero', payload)
    for total in [-1, 0.5, 9007199254740992.0, '1']:
        add('invalid integer ' + repr(total), changed(['content', 'links', 'total'], total), ['WIST1-E14'])
    for field, bound in [('title', 256), ('abstract', 1500)]:
        for text, allowed, label in [('x' * bound, [], 'boundary'),
                                     ('x' * (bound + 1), ['WIST1-E14'], 'excess'),
                                     ('\U0001f600' * bound, [], 'astral'),
                                     ('\U0001f600' * (bound + 1), ['WIST1-E14'], 'astral excess')]:
            add(field + ' ' + label, changed(['content', 'summary', field], text), allowed,
                dict(summary_cap_bytes=8192))
    add('empty abstract', changed(['content', 'summary', 'abstract'], ''))
    for field, value, caps in [
            ('extract', 'x' * 32769, dict(extract_cap_bytes=40000)),
            ('links', dict(total=1, urls=['https://example.org/' + 'x' * 2100]), dict(link_url_cap_bytes=4096))]:
        add('increased cap ' + field, changed(['content', field], value), caps=caps)
    for field, value, caps in [
            ('extract', 'x' * 8, dict(extract_cap_bytes=10)),
            ('extract', '\U0001f600' * 2, dict(extract_cap_bytes=10)),
            ('extract', '\n' * 4, dict(extract_cap_bytes=10)),
            ('links', base['content']['links'], dict(links_cap_bytes=len(rfc8785.dumps(base['content']['links'])))),
            ('summary', base['content']['summary'], dict(summary_cap_bytes=len(rfc8785.dumps(base['content']['summary']))))]:
        add('exact cap ' + field + ' ' + repr(value), changed(['content', field], value), caps=caps)
        add('exceeded cap ' + field + ' ' + repr(value), changed(['content', field], value), ['WIST1-E04'],
            {key: value - 1 for key, value in caps.items()})
    add('URL octet cap', copy.deepcopy(base), ['WIST1-E04'], dict(link_url_cap_bytes=14))
    add('declared length', copy.deepcopy(base), ['WIST1-E10'], wrong_length=True)
    add('commitment mismatch', copy.deepcopy(base), ['WIST1-E10'], corrupt=True)
    add('duplicate links', changed(['content', 'links'], dict(total=2, urls=['https://example.org/'] * 2)), ['WIST1-E12'])
    add('non-normalized link', changed(['content', 'links', 'urls'], ['http://example.org/']), ['WIST1-E12'])
    add('internal link', changed(['content', 'links', 'urls'], ['https://example.com/']), ['WIST1-E12'])
    add('underdeclared links', changed(['content', 'links', 'total'], 0), ['WIST1-E12'])
    payload = changed(['wist_version'], '2.0.0')
    payload['content']['links']['urls'] = ['http://example.org/']
    add('semantic combination', payload, ['WIST1-E04', 'WIST1-E10', 'WIST1-E12', 'WIST1-E15'],
        dict(extract_cap_bytes=2), corrupt=True, wrong_length=True)
    for path, value in [(['content', 'summary', 'abstract'], None), (['wist_version'], '02.0.0'),
                        (['content', 'links', 'total'], 0.5)]:
        combined = copy.deepcopy(payload)
        target = combined
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        add('field precedence ' + '.'.join(path), combined, ['WIST1-E14'],
            dict(extract_cap_bytes=2), corrupt=True, wrong_length=True)
    raw = json.dumps(base)
    wire_cases = [
        ('duplicate version', raw.replace('"wist_version": "1.0.0"', '"wist_version": "2.0.0", "wist_version": "1.0.0"')),
        ('identical duplicate', raw.replace('"title": "Title"', '"title": "Title", "title": "Title"')),
        ('duplicate content', raw.replace('"extract": "Content"', '"extract": "Other", "extract": "Content"')),
        ('duplicate total', raw.replace('"total": 1', '"total": 2, "total": 1')),
        ('escaped duplicate', raw.replace('"total": 1', '"\\u0074otal": 2, "total": 1')),
        ('duplicate before field error', raw[:-1] + ', "extra": [{"a": 1, "a": 2}]}'),
        ('lone surrogate', raw.replace('"Content"', '"\\ud800"')),
        ('nonfinite magnitude', raw.replace('"total": 1', '"total": 1e400')),
        ('invalid number', raw.replace('"total": 1', '"total": 01')),
        ('trailing document', raw + '{}'),
    ]
    for name, wire in wire_cases:
        add(name, copy.deepcopy(base), ['WIST1-E05'])
        cases[-1]['payload_json'] = wire
    add('escaped member', copy.deepcopy(base))
    cases[-1]['payload_json'] = raw.replace('"total": 1', '"\\u0074otal": 1')
    return dict(spec='WIST-1 sections 3.1, 3.6 and 7; WIST-3 section 6.1',
                public_key=b64u(pub_raw), cases=cases)


write_json(WIST1 / 'payload-fields.json', payload_field_vectors())


def delta_clock_time_vectors():
    start = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc)

    def at(seconds):
        return (start + datetime.timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')

    changes = [(168, 60), (169, 1200), (170, 0), (171, -60),
               (172, 9007199254740991), (173, -9007199254740991)]
    amendments = []
    for hour, value in changes:
        update = dict(wist_version='1.0.0', action='parameter_change', subject='clock_skew_seconds',
                      details=dict(parameter='clock_skew_seconds', value=value), effective_at=at(hour * 3600))
        amendments.append(dict(sealed_at=at(0), envelope=sign_envelope('update', update, KID1), accepted=True))
    for label, effective, value in [('bad signature', 168 * 3600, 9000), ('short grace', 3600, 9999)]:
        update = dict(wist_version='1.0.0', action='parameter_change', subject='clock_skew_seconds',
                      details=dict(parameter='clock_skew_seconds', value=value), effective_at=at(effective))
        signed = sign_envelope('update', update, KID1)
        if label == 'bad signature':
            signed['sig']['value'] = b64u(bytes(64))
        amendments.append(dict(sealed_at=at(0), envelope=signed, accepted=False))

    def allowance(seconds):
        return next((value for hour, value in reversed(changes) if hour * 3600 <= seconds), 600)

    probes = []

    def add(name, stage, clock_s, observed, expected, **context):
        body = dict(delta, observed_at=observed, url='https://example.com/clock/' + str(len(probes)))
        probes.append(dict(name=name, stage=stage, envelope=sign_envelope('delta', body, KID1),
                           expected_clock=at(clock_s), expected_allowance=allowance(clock_s),
                           expected=expected, **context))

    for hour, value in changes:
        for offset in [-3600, 0]:
            instant = hour * 3600 + offset
            skew = allowance(instant)
            if abs(skew) < 10000:
                boundary = at(instant + skew)
                observations = [(boundary.replace('Z', '.00000000000000000001Z'), 'WIST1-E06'),
                                (boundary, None),
                                (at(instant + skew - 1).replace('Z', '.99999999999999999999Z'), None)]
            else:
                observations = [(at(instant), None if skew > 0 else 'WIST1-E06'),
                                ('0000-01-01T00:00:00+23:59', None if skew > 0 else 'WIST1-E06'),
                                ('9999-12-31T23:59:59-23:59', None if skew > 0 else 'WIST1-E06')]
            for index, (observed, expected) in enumerate(observations):
                add(f'historical {hour} {offset} {index}', 'historical', instant, observed, expected,
                    sealed_at=at(instant), checked_at=at(174 * 3600))
                add(f'sealing {hour} {offset} {index}', 'sealing', instant, observed, expected,
                    candidate_sealed_at=at(instant), admitted_at=at(instant - 1))
        instant = hour * 3600 - 1
        skew = allowance(instant)
        observed_offset = skew if abs(skew) < 10000 else 0
        for extra in [0, 1]:
            observed = at(instant + observed_offset)
            if extra:
                observed = observed.replace('Z', '.00000000000000000001Z')
            observed_scaled = observed_offset * 10**20 + extra
            add(f'admission across {hour} {extra}', 'admission', instant, observed,
                None if observed_scaled <= skew * 10**20 else 'WIST1-E06',
                started_at=at(instant), completed_at=at(instant + 2))
            add(f'new attempt after {hour} {extra}', 'admission', instant + 2, observed,
                None if observed_scaled <= (2 + allowance(instant + 2)) * 10**20 else 'WIST1-E06',
                started_at=at(instant + 2), completed_at=at(instant + 3))
    return dict(description='WIST-1 section 3.4 and WIST-4 section 5. Signed candidates with supplied '
                'inclusion contexts; amendments share the initial Epoch in listed order. Only the '
                'clock_skew_seconds parameter varies. Context timestamps do not prove Epoch inclusion. '
                'Clock relation outcomes assume other Delta obligations have passed; each new attempt '
                'captures its own context. Historical checked_at and sealing admitted_at are distractors.',
                public_key=b64u(pub_raw), default=600, amendments=amendments, probes=probes)


write_json(WIST1 / 'delta-clock-time.json', delta_clock_time_vectors())


# --------------------------------------------- WIST-2 §5 and §8: fetch bounds
def fetch_bounds_vectors():
    def dest(label, address, cls, opt_in=False):
        return {"label": label, "address": address, "loopback_opt_in": opt_in, "class": cls,
                "allowed": cls is None}

    destinations = [
        dest("public IPv4", "93.184.216.34", None),
        dest("public IPv6", "2606:2800:220:1:248:1893:25c8:1946", None),
        dest("loopback", "127.0.0.1", "loopback"),
        dest("loopback end of range", "127.255.255.254", "loopback"),
        dest("loopback under the local opt in", "127.0.0.1", None, True),
        dest("IPv6 loopback", "::1", "loopback"),
        dest("IPv6 loopback under the local opt in", "::1", None, True),
        dest("unspecified", "0.0.0.0", "unspecified"),
        dest("IPv6 unspecified", "::", "unspecified"),
        dest("private ten", "10.1.2.3", "private"),
        dest("private one seven two", "172.31.0.9", "private"),
        dest("private one nine two", "192.168.1.1", "private"),
        dest("public neighbour of the private block", "172.32.0.1", None),
        dest("link local", "169.254.1.1", "link-local"),
        dest("cloud metadata", "169.254.169.254", "link-local"),
        dest("shared address space", "100.64.0.1", "shared address space"),
        dest("shared address space end of range", "100.127.255.255", "shared address space"),
        dest("public after shared address space", "100.128.0.0", None),
        dest("broadcast", "255.255.255.255", "broadcast"),
        dest("multicast", "224.0.0.1", "multicast"),
        dest("documentation one", "192.0.2.1", "documentation"),
        dest("documentation two", "198.51.100.7", "documentation"),
        dest("documentation three", "203.0.113.9", "documentation"),
        dest("benchmarking", "198.18.0.1", "benchmarking"),
        dest("benchmarking end of range", "198.19.255.255", "benchmarking"),
        dest("public after benchmarking", "198.20.0.1", None),
        dest("reserved", "240.0.0.1", "reserved"),
        dest("unique local", "fd12::1", "unique local"),
        dest("IPv6 link local", "fe80::1", "link-local"),
        dest("IPv6 multicast", "ff02::1", "multicast"),
        dest("IPv6 documentation", "2001:db8::1", "documentation"),
        dest("IPv4 mapped private", "::ffff:10.0.0.1", "private"),
        dest("IPv4 mapped public", "::ffff:93.184.216.34", None),
        dest("six to four private", "2002:c0a8:101::1", "private"),
        dest("six to four public", "2002:5db8:d822::1", None),
        dest("NAT64 cloud metadata", "64:ff9b::a9fe:a9fe", "link-local"),
        dest("NAT64 public", "64:ff9b::5db8:d822", None),
    ]
    resolutions = [
        {"label": "every answer public", "addresses": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
         "allowed": True},
        {"label": "one private answer refuses the name", "addresses": ["93.184.216.34", "10.0.0.5"],
         "allowed": False},
        {"label": "one mapped loopback answer refuses the name", "addresses": ["::ffff:127.0.0.1", "93.184.216.34"],
         "allowed": False},
        {"label": "no answer", "addresses": [], "allowed": False},
    ]
    defaults = {"url_cap_bytes": 2048, "extract_cap_bytes": 32768, "links_cap_bytes": 4096,
                "summary_cap_bytes": 2048}
    amended = {"url_cap_bytes": 4096, "extract_cap_bytes": 65536, "links_cap_bytes": 8192,
               "summary_cap_bytes": 4096}

    def bound(obj, params):
        if obj in ("declaration", "feed", "page", "mirrors"):
            return 1 << 20
        if obj in ("delta", "label"):
            return 16384 + 2 * params["url_cap_bytes"]
        return params["extract_cap_bytes"] + params["links_cap_bytes"] + params["summary_cap_bytes"] + 4096

    object_bounds = []
    for name, params in (("defaults", defaults), ("amended", amended)):
        for obj in ("declaration", "feed", "page", "mirrors", "delta", "label", "payload"):
            object_bounds.append({"label": f"{obj} under the {name}", "object": obj, "parameters": params,
                                  "bound": bound(obj, params)})

    def work(label, budget, work_bytes, work_objects, size, object_bound=20480):
        if budget == 0 or work_bytes == 0 or work_objects == 0:
            outcome, debited = "suspended", 0
        else:
            limit = min(object_bound, budget, work_bytes)
            if size <= limit:
                outcome, debited = "fetched", size
            elif limit < object_bound:
                outcome, debited = "suspended", limit
            else:
                outcome, debited = "failed", 0
        return {"label": label, "object_bound": object_bound, "budget_remaining": budget,
                "work_bytes_remaining": work_bytes, "work_objects_remaining": work_objects,
                "object_bytes": size, "outcome": outcome, "debited": debited}

    work_cases = [
        work("within every bound", 100000, 50000, 5, 10000),
        work("exactly the remaining budget", 10000, 50000, 5, 10000),
        work("crosses the remaining budget", 5000, 50000, 5, 10000),
        work("crosses the per pull octet limit", 100000, 6000, 5, 10000),
        work("no objects left in the pull", 100000, 50000, 0, 10),
        work("budget spent", 0, 50000, 5, 10),
        work("above its own bound", 100000, 50000, 5, 30000),
        work("above its own bound and the remaining budget", 5000, 50000, 5, 30000),
    ]
    def label_feed(label, feed_walk, budget, pages, pulled, suspended):
        return {"label": label, "feed_walk": feed_walk, "budget_remaining": budget, "label_feed_pages": pages,
                "label_feed_pulled": pulled, "suspended": suspended}

    label_feed_cases = [
        label_feed("Feed pull failed", "failed", 100000, 1, False, False),
        label_feed("Feed walk suspended", "suspended", 0, 1, False, True),
        label_feed("Feed walk completed and budget spent", "completed", 0, 1, False, False),
        label_feed("Feed walk completed and the budget covers the live Label Feed only", "completed", 1, 2,
                   True, True),
        label_feed("Feed walk completed and the budget covers every Page", "completed", 100000, 2, True, False),
    ]
    well_known = "/.well-known/wist/feed.json"
    redirect_cases = [{
        "label": "a scope grant and a scope removal inside one pull",
        "requested_host": "example.com",
        "steps": [
            {"redirect_to": "https://www.example.com" + well_known, "allowed": False},
            {"redirect_to": "https://example.com/feed-moved.json", "allowed": True},
            {"declaration": {"domain": "example.com", "subdomain_scope": ["www.example.com"]}},
            {"redirect_to": "https://www.example.com" + well_known, "allowed": True},
            {"redirect_to": "https://cdn.example.com" + well_known, "allowed": False},
            {"declaration": {"domain": "example.com", "subdomain_scope": ["cdn.example.com"]}},
            {"redirect_to": "https://www.example.com" + well_known, "allowed": False},
            {"redirect_to": "https://cdn.example.com" + well_known, "allowed": True},
            {"redirect_to": "http://cdn.example.com" + well_known, "allowed": False},
            {"redirect_to": "https://example.com/other.json", "allowed": True},
        ],
    }]
    return spaced_labels({
        "note": ("WIST-2 §8 and §5, ADR-0044. destinations classify one address, allowed only when the class is "
                 "null; loopback_opt_in is the single-machine opt-in. resolutions decide a name from every "
                 "address it resolves to. object_bounds are the octets an Aggregator reads at most, under the "
                 "parameter map given. work_cases replay one fetch under the remaining daily budget and a "
                 "per-pull limit: fetched debits the object, suspended debits the octets read up to the bound, "
                 "failed is an object above its own bound. redirect_cases replay redirects and accepted "
                 "Declarations in order for one requested Canonical Host. label_feed_cases decide whether a "
                 "pull reaches the Label Feed after its Feed walk and whether it ends suspended: budget_remaining "
                 "counts whole Label Feed pages the budget still covers, label_feed_pages the pages the walk "
                 "would read."),
        "destinations": destinations, "resolutions": resolutions, "object_bounds": object_bounds,
        "work_cases": work_cases, "redirect_cases": redirect_cases, "label_feed_cases": label_feed_cases})


write_json(ROOT / "vectors" / "wist2" / "fetch-bounds.json", fetch_bounds_vectors())

# ------------------------------------------- WIST-1 §5.1/§5.2: key directory
def fingerprint_of(entries):
    """WIST-1 §5.1 Key Set fingerprint: sha256 over the JCS array of kids in byte order."""
    kids = sorted(entry["kid"] for entry in entries)
    return "sha256:" + sha256_hex(rfc8785.dumps(kids))


def key_directory_vectors():
    start = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc)

    def timestamp(hour, seconds=0):
        return (start + datetime.timedelta(hours=hour, seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    rfc8037_x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    thumbprints = [{"name": "RFC 8037 appendix A.3 key", "x": rfc8037_x,
                    "kid": kid_of(base64.urlsafe_b64decode(rfc8037_x + "="))}]
    for name, raw in (("fixture signing key", pub_raw), ("fixture recovery key", pub2_raw),
                      ("second signing key", pub3_raw), ("second recovery key", pub4_raw)):
        thumbprints.append({"name": name, "x": b64u(raw), "kid": kid_of(raw)})
    fingerprints = [
        {"name": "example Declaration signing set", "kids": [KID1], "fingerprint": fingerprint_of(publisher["keys"])},
        {"name": "two keys listed in reverse byte order", "kids": sorted([KID1, KID3], reverse=True),
         "fingerprint": fingerprint_of([{"kid": KID1}, {"kid": KID3}])},
    ]
    dns_record = {"domain": "example.com", "name": "_wist.example.com",
                  "txt": "v=wist1; keys=" + fingerprint_of(publisher["keys"])}

    entry_cases = []
    def entry(name, inner, signer, kid, expected):
        entry_cases.append({"name": name, "envelope": sign_envelope_with(signer, "publisher", inner, kid),
                            "expected": expected})
    k1 = publisher["keys"][0]
    entry("thumbprint of another key", variant(keys=[dict(k1, kid=KID3)]), priv, KID3, "WIST1-E14")
    entry("thumbprint with one character changed", variant(keys=[dict(k1, kid=("A" if KID1[0] != "A" else "B") + KID1[1:])]),
          priv, KID1, "WIST1-E14")
    entry("recovery thumbprint of another key", variant(recovery_keys=[dict(publisher["recovery_keys"][0], kid=KID4)]),
          priv, KID1, "WIST1-E14")
    entry("exp equal to nbf", variant(keys=[dict(k1, exp=k1["nbf"])]), priv, KID1, "WIST1-E14")
    entry("exp below nbf", variant(keys=[dict(k1, exp=k1["nbf"] - 1)]), priv, KID1, "WIST1-E14")
    entry("exp one second after nbf", variant(keys=[dict(k1, exp=k1["nbf"] + 1)]), priv, KID1, "initial")
    entry("recovery entry with exp", variant(recovery_keys=[dict(publisher["recovery_keys"][0], exp=k1["nbf"] + 86400)]),
          priv, KID1, "initial")
    entry("same key twice with distinct windows", variant(keys=[k1, dict(k1, nbf=k1["nbf"] + 1)]), priv, KID1, "WIST1-E08")
    entry("same key in both sets", variant(recovery_keys=[dict(k1, nbf=k1["nbf"] + 1)]), priv, KID1, "WIST1-E08")
    entry("extra member alg", variant(keys=[dict(k1, alg="Ed25519")]), priv, KID1, "WIST1-E14")
    entry("next keys well formed", variant(next_keys=fingerprint_of([{"kid": KID3}])), priv, KID1, "initial")
    entry("next keys malformed", variant(next_keys="sha256:" + "0" * 63), priv, KID1, "WIST1-E14")

    window_cases = []
    base_nbf = nbf_at(timestamp(10))
    def window(name, keys, signer, kid, observed_at, expected):
        declaration = sign_envelope_with(priv, "publisher", variant(keys=keys), KID1)
        inner = dict(delta, url="https://example.com/key-directory", observed_at=observed_at)
        window_cases.append({"name": name, "declaration": declaration,
                             "envelope": sign_envelope_with(signer, "delta", inner, kid), "expected": expected})
    bounded = [jwk(pub_raw, base_nbf, base_nbf + 3600)]
    window("half a second before nbf", bounded, priv, KID1, timestamp(10, -1)[:-1] + ".5Z", "WIST1-E02")
    window("at nbf", bounded, priv, KID1, timestamp(10), "accepted")
    window("fraction after nbf", bounded, priv, KID1, timestamp(10)[:-1] + ".000000000000000000001Z", "accepted")
    window("half a second before exp", bounded, priv, KID1, timestamp(10, 3599)[:-1] + ".5Z", "accepted")
    window("at exp", bounded, priv, KID1, timestamp(11), "WIST1-E02")
    window("fraction after exp", bounded, priv, KID1, timestamp(11)[:-1] + ".000000000000000000001Z", "WIST1-E02")
    window("offset spelling inside window", bounded, priv, KID1, "2026-08-04T07:30:00-03:00", "accepted")
    window("offset spelling at exp", bounded, priv, KID1, "2026-08-04T12:00:00+01:00", "WIST1-E02")
    window("valid signature outside window", bounded, priv, KID1, timestamp(12), "WIST1-E02")
    overlap = [jwk(pub_raw, base_nbf - 86400, base_nbf + 3600), jwk(pub3_raw, base_nbf + 1800)]
    window("overlap outgoing key before its exp", overlap, priv, KID1, timestamp(10, 1800), "accepted")
    window("overlap outgoing key at its exp", overlap, priv, KID1, timestamp(11), "WIST1-E02")
    window("overlap incoming key before its nbf", overlap, priv3, KID3, timestamp(10, 1799)[:-1] + ".999Z", "WIST1-E02")
    window("overlap incoming key at its nbf", overlap, priv3, KID3, timestamp(10, 1800), "accepted")
    window("overlap incoming key without exp far later", overlap, priv3, KID3, "2030-01-01T00:00:00Z", "accepted")
    window("overlap outgoing key signature under incoming kid", overlap, priv, KID3, timestamp(10, 1800), "WIST1-E01")
    window("nbf zero admits the Unix time origin", [jwk(pub_raw, 0)], priv, KID1, "1970-01-01T00:00:00Z", "accepted")
    window("instant before the Unix time origin precedes every nbf", [jwk(pub_raw, 0)], priv, KID1, "1969-12-31T23:59:59.999Z", "WIST1-E02")
    window("nbf at the last NumericDate", [jwk(pub_raw, 253402300799)], priv, KID1, "9999-12-31T23:59:59Z", "accepted")
    window("recovery only key supplies no authority", bounded, priv2, KID2, timestamp(10), "WIST1-E02")

    commitment_cases = []
    committed = variant(next_keys=fingerprint_of([{"kid": KID3}]))
    committed_hash = decl_hash(committed)
    def commitment(name, stored, fetched, signer, kid, expected):
        commitment_cases.append({"name": name, "stored": sign_envelope_with(priv, "publisher", stored, KID1),
                                 "fetched": sign_envelope_with(signer, "publisher", fetched, kid), "expected": expected})
    history_nbf = nbf_at(timestamp(0))
    K3, K4 = jwk(pub3_raw, history_nbf), jwk(pub4_raw, history_nbf)
    successor = dict(committed, seq=1, prev_declaration=committed_hash, keys=[K3])
    del successor["next_keys"]
    commitment("committed set installed", committed, successor, priv, KID1, "ordinary_rotation")
    commitment("committed set installed with a new commitment", committed,
               dict(successor, next_keys=fingerprint_of([{"kid": KID4}])), priv, KID1, "ordinary_rotation")
    commitment("uncommitted set installed", committed, dict(successor, keys=[K4]), priv, KID1, "WIST1-E08")
    commitment("committed set is exact", committed, dict(successor, keys=[k1, K3]), priv, KID1, "WIST1-E08")
    commitment("signing set and commitment kept", committed,
               dict(committed, seq=1, prev_declaration=committed_hash, contact="mailto:security@example.com"),
               priv, KID1, "ordinary_rotation")
    dropped = dict(committed, seq=1, prev_declaration=committed_hash)
    del dropped["next_keys"]
    commitment("commitment dropped without rotating", committed, dropped, priv, KID1, "WIST1-E08")
    commitment("commitment changed without rotating", committed,
               dict(committed, seq=1, prev_declaration=committed_hash, next_keys=fingerprint_of([{"kid": KID4}])),
               priv, KID1, "WIST1-E08")
    commitment("signing key window changed without rotating", committed,
               dict(committed, seq=1, prev_declaration=committed_hash, keys=[dict(k1, exp=base_nbf + 86400)]),
               priv, KID1, "ordinary_rotation")
    commitment("recovery rotation overrides the commitment", committed,
               dict(successor, keys=[K4]), priv2, KID2, "recovery_rotation")
    commitment("fresh identity is not bound by the commitment", committed,
               dict(successor, keys=[K4]), priv4, KID4, "fresh_identity")
    commitment("commitment adopted by an ordinary rotation", publisher,
               variant(seq=1, prev_declaration=stored_hash, next_keys=fingerprint_of([{"kid": KID3}])),
               priv, KID1, "ordinary_rotation")

    # Signed hourly Epoch histories for the activation delay.
    initial = sign_envelope_with(priv, "publisher", publisher, KID1)
    def signed(previous, seq, signer, kid, **changes):
        inner = dict(previous["publisher"], seq=seq,
                     prev_declaration=decl_hash(previous["publisher"]), **changes)
        return sign_envelope_with(signer, "publisher", inner, kid)
    fresh = signed(initial, 1, priv3, KID3, keys=[K3])
    follower = signed(fresh, 2, priv3, KID3, keys=[K4])
    reversal = signed(initial, 2, priv, KID1, contact="mailto:owner@example.com")
    recovery_reversal = signed(initial, 2, priv2, KID2, keys=[K3], recovery_keys=[jwk(pub4_raw, base_nbf)])
    below_floor = signed(initial, 1, priv, KID1, contact="mailto:owner@example.com")
    fresh_beside_pending = signed(initial, 2, priv4, KID4, keys=[K4])
    second_fresh = signed(fresh, 3, priv4, KID4, keys=[K4])

    def history(events, length, **fields):
        epochs, tree_leaves = [], []
        for height in range(length):
            entries = [recovery_order_entry(events[height])] if height in events else []
            epoch, tree_leaves = seal("test-log-k1", priv, tree_leaves, entries, height, timestamp(height))
            epochs.append(epoch)
        return dict(epochs=epochs, pinned_head=root_token(tree_leaves), **fields)

    def state(current, pending=None, activation=None, floor=0, reset=None, window_end=None):
        return {"current_declaration": decl_hash(current["publisher"]),
                "pending_head": decl_hash(pending["publisher"]) if pending else None,
                "activation_height": activation, "highest_accepted_seq": floor,
                "reset_height": reset, "window_end": window_end}

    histories = {
        "activated": history({0: initial, 2: fresh}, 28, expected_states=[
            (1, state(initial)), (2, state(initial, fresh, 26, 1)), (25, state(initial, fresh, 26, 1)),
            (26, state(fresh, floor=1, reset=26)), (27, state(fresh, floor=1, reset=26))]),
        "pending follower": history({0: initial, 2: fresh, 3: follower}, 28, expected_states=[
            (2, state(initial, fresh, 26, 1)), (3, state(initial, follower, 26, 2)),
            (26, state(follower, floor=2, reset=26))]),
        "reversed by a signing key": history({0: initial, 2: fresh, 4: reversal}, 28, expected_states=[
            (3, state(initial, fresh, 26, 1)), (4, state(reversal, floor=2)), (26, state(reversal, floor=2)),
            (27, state(reversal, floor=2))]),
        "reversed by a recovery key": history({0: initial, 2: fresh, 4: recovery_reversal}, 6, expected_states=[
            (3, state(initial, fresh, 26, 1)),
            (4, state(recovery_reversal, floor=2, window_end=timestamp(4 + 168))),
            (5, state(recovery_reversal, floor=2, window_end=timestamp(4 + 168)))]),
        "activation delay zero": history({0: initial, 2: fresh}, 4, declaration_activation_epochs=0,
                                         expected_states=[(1, state(initial)), (2, state(fresh, floor=1, reset=2)),
                                                          (3, state(fresh, floor=1, reset=2))]),
    }
    for name, value in histories.items():
        value["expected_states"] = [{"height": h, "state": s} for h, s in value["expected_states"]]
    snapshot_tuples = [
        {"history": "activated", "height": 3,
         "declaration": ["declaration", "example.com", initial, 0, 1],
         "pending_declaration": ["pending_declaration", "example.com", fresh, 2, 26]},
        {"history": "pending follower", "height": 5,
         "declaration": ["declaration", "example.com", initial, 0, 2],
         "pending_declaration": ["pending_declaration", "example.com", follower, 3, 26]},
        {"history": "activated", "height": 26,
         "declaration": ["declaration", "example.com", fresh, 2, 1], "pending_declaration": None},
        {"history": "reversed by a signing key", "height": 5,
         "declaration": ["declaration", "example.com", reversal, 4, 2], "pending_declaration": None},
    ]

    def rejection(name, history_name, height, candidate, expected):
        return {"name": name, "history": history_name, "prefix_height": height,
                "candidate_sealed_at": timestamp(height + 1), "candidate": candidate, "expected": expected}
    rejections = [
        rejection("fresh identity naming current beside a pending head", "activated", 3, fresh_beside_pending, "WIST1-E08"),
        rejection("reversal below the pending sequence floor", "activated", 3, below_floor, "WIST1-E08"),
        rejection("fresh identity naming the pending head is accepted", "activated", 3, second_fresh, "fresh_identity"),
        rejection("reversal after activation names a superseded predecessor", "activated", 26, reversal, "WIST1-E08"),
        rejection("pending head cannot be named after reversal", "reversed by a signing key", 5, follower, "WIST1-E08"),
        rejection("re-serve of the pending head installs nothing", "activated", 3, fresh, "idempotent"),
    ]

    delta_probes = []
    def probe(name, history_name, height, signer, kid, expected):
        inner = dict(delta, url="https://example.com/activation", observed_at=timestamp(height))
        delta_probes.append({"name": name, "history": history_name, "prefix_height": height,
                             "envelope": sign_envelope_with(signer, "delta", inner, kid), "expected": expected})
    probe("pending key supplies no authority", "activated", 3, priv3, KID3, "WIST1-E02")
    probe("current key keeps authority while pending", "activated", 3, priv, KID1, "accepted")
    probe("activated key has authority", "activated", 26, priv3, KID3, "accepted")
    probe("replaced key loses authority at activation", "activated", 26, priv, KID1, "WIST1-E02")
    probe("reversed key never gains authority", "reversed by a signing key", 27, priv3, KID3, "WIST1-E02")
    probe("owner key keeps authority after reversal", "reversed by a signing key", 27, priv, KID1, "accepted")
    probe("follower key waits for activation", "pending follower", 4, priv4, KID4, "WIST1-E02")
    probe("follower key has authority after activation", "pending follower", 27, priv4, KID4, "accepted")
    probe("zero delay activates at once", "activation delay zero", 2, priv3, KID3, "accepted")

    write_json(WIST1 / "key-directory.json", {
        "note": "WIST-1 sections 5.1 and 5.2. thumbprints are RFC 7638 known answers; fingerprints and "
                "dns_record apply the Key Set fingerprint. entry_cases are initial Declarations judged on "
                "field and uniqueness rules. window_cases judge a Delta's key check under the supplied "
                "Declaration alone: accepted means the named binding is inside its window and verifies. "
                "commitment_cases evaluate fetched against stored as declaration-binding.json does. "
                "Each history is an authenticated hourly Epoch chain; expected_states hold after the "
                "named height applies, snapshot_tuples are the WIST-3 section 7 tuples at that height, "
                "rejections apply a candidate to the next Epoch after prefix_height and must leave the "
                "prefix state unchanged when rejected, and delta_probes judge only the key check against "
                "the Declaration current after prefix_height. The parameter map is a trusted fixture "
                "input; a history's own declaration_activation_epochs overrides the file default. No live "
                "transport, queue, Payload or quota behavior is established.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "declaration_activation_epochs": 24,
        "thumbprints": thumbprints, "fingerprints": fingerprints, "dns_record": dns_record,
        "entry_cases": entry_cases, "window_cases": window_cases, "commitment_cases": commitment_cases,
        "histories": histories, "snapshot_tuples": snapshot_tuples, "rejections": rejections,
        "delta_probes": delta_probes})


key_directory_vectors()
print("wist1 key-directory vector written")
