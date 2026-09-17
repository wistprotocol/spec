#!/usr/bin/env python3
"""Generate deterministic WIST-1/WIST-3 test vectors and signed examples.

Never uses wall-clock or randomness: fixed seed, fixed timestamps.
Re-running always produces byte-identical output.
"""
import base64, calendar, datetime, hashlib, hmac, itertools, json, pathlib, re, time
from decimal import Decimal, localcontext

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ed25519_curve
import link_extraction
from merkle import audit_path, leaf_hash, node_hash
from merkle import merkle_root as merkle_tree_root

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
fresh_identity_dropping_recovery = variant(seq=1, prev_declaration=stored_hash, keys=[K2])
del fresh_identity_dropping_recovery["recovery_keys"]
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
            "accepted as a fresh identity whose history starts here (WIST-3 §7)."},
    {"name": "fresh identity inside an open recovery window",
     "stored": sign_envelope("publisher", stored_decl, "test-k1"),
     "fetched": sign_envelope_with(priv3, "publisher", fresh_identity, "test-k2"),
     "recovery_window_open": True,
     "expected": "fresh_identity",
     "why": "§5.2: an open window changes nothing about acceptance — the "
            "Declaration is sealed and superseded at the window's end, "
            "because rejecting it at ingest would leave a thief's attempt "
            "invisible to a party replaying the Log."},
    {"name": "fresh identity dropping the recovery keys",
     "stored": sign_envelope("publisher", stored_decl, "test-k1"),
     "fetched": sign_envelope_with(priv3, "publisher", fresh_identity_dropping_recovery, "test-k2"),
     "expected": "WIST1-E08",
     "why": "§5.2: recovery keys protect themselves against every Declaration "
            "not signed by one of them — a fresh identity included, or a "
            "party holding only the web server could shed them and sever "
            "the owner's path back."},
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
             "`recovery_rotation`, `fresh_identity` (accepted; resets only outside an open recovery window), "
             "or the error code the evaluation rejects with."),
    "recovery_window_open": False,
    "cases": declaration_cases,
})
print("wist1 declaration-sequence vector written")


def binding_case(name, incoming, signer, key_id, expected, stored=stored_decl):
    return {"name": name,
            "stored": sign_envelope("publisher", stored, "test-k1") if stored else None,
            "fetched": sign_envelope_with(signer, "publisher", incoming, key_id),
            "expected": expected}

binding_cases = []
for array, original, other in (("keys", stored_decl["keys"][0], K2),
                                ("recovery_keys", stored_decl["recovery_keys"][0], R2)):
    for duplicate in (dict(original), dict(other, key_id=original["key_id"])):
        for reverse in (False, True):
            entries = [original, duplicate]
            if reverse:
                entries.reverse()
            incoming = variant(seq=1, prev_declaration=stored_hash, **{array: entries})
            binding_cases.append(binding_case(
                f"duplicate {array} identifier {'reversed' if reverse else 'forward'} "
                f"{'identical' if duplicate == original else 'different key'}",
                incoming, priv, "test-k1", "WIST1-E08"))
            initial = variant(**{array: entries})
            binding_cases.append(binding_case(
                f"initial duplicate {array} {'reversed' if reverse else 'forward'} "
                f"{'identical' if duplicate == original else 'different key'}",
                initial, priv, "test-k1", "WIST1-E08", stored=None))

reused = variant(seq=1, prev_declaration=stored_hash,
                 keys=[dict(K2, key_id="test-k1")])
alias = dict(stored_decl["keys"][0], key_id="alias")
renamed = variant(seq=1, prev_declaration=stored_hash, keys=[alias])
recovery_alias = dict(stored_decl["recovery_keys"][0], key_id="recovery-alias")
renamed_recovery = variant(seq=1, prev_declaration=stored_hash,
                           keys=[recovery_alias], recovery_keys=[R2])
binding_cases.extend([
    binding_case("reused identifier new signer", reused, priv3, "test-k1", "fresh_identity"),
    binding_case("reused identifier old signer", reused, priv, "test-k1", "ordinary_rotation"),
    binding_case("renamed signing key preserves identity", renamed, priv, "alias", "ordinary_rotation"),
    binding_case("signing aliases remain valid", variant(seq=1, prev_declaration=stored_hash,
                 keys=[stored_decl["keys"][0], alias]), priv, "alias", "ordinary_rotation"),
    binding_case("renamed recovery key retains authority", renamed_recovery,
                 priv2, "recovery-alias", "recovery_rotation"),
    binding_case("renamed signing key cannot alter recovery", dict(renamed, recovery_keys=[R2]),
                 priv, "alias", "WIST1-E08"),
    binding_case("reused identifier cannot alter recovery", dict(reused, recovery_keys=[R2]),
                 priv3, "test-k1", "WIST1-E08"),
    binding_case("unrelated signature under known identifier", reused, priv4, "test-k1", "WIST1-E01"),
    binding_case("unknown signer identifier", reused, priv3, "unknown", "WIST1-E02"),
    binding_case("incoming recovery key cannot self authorize", recovery_rotated,
                 priv4, "test-r2", "WIST1-E02"),
    binding_case("initial self signature", stored_decl, priv, "test-k1", "initial", stored=None),
    binding_case("initial signature names second signing key",
                 variant(keys=[K2, stored_decl["keys"][0]]), priv, "test-k1", "initial", stored=None),
])
write_json(WIST1 / "declaration-binding.json", {
    "note": "WIST-1 section 5.2: authenticate sig.key_id against previous signing/recovery "
            "and incoming signing entries; classify verified public bytes by previous set membership. "
            "A null stored value tests the initial self-signed Declaration. Duplicate key_id is WIST1-E08.",
    "cases": binding_cases,
})

def recovery_order_entry(envelope):
    return {"type": "publisher_declaration", "body": envelope}


def recovery_order_leaf(envelope):
    return leaf_hash(rfc8785.dumps(recovery_order_entry(envelope)))


def recovery_order_case(name, reverse_leaves, split_blocks=False, ordinary_first=False):
    initial = sign_envelope("publisher", publisher, "test-k1")
    prefix = [initial]
    if ordinary_first:
        ordinary = variant(seq=1, prev_declaration=decl_hash(publisher),
                           contact="mailto:rotation@example.com")
        prefix.append(sign_envelope("publisher", ordinary, "test-k1"))
    first_inner = variant(seq=len(prefix),
                          prev_declaration=decl_hash(prefix[-1]["publisher"]),
                          keys=[K2], recovery_keys=[R2])
    first = sign_envelope_with(priv2, "publisher", first_inner, "test-r1")
    for nonce in range(1000):
        second_inner = dict(first_inner, seq=first_inner["seq"] + 1,
                            prev_declaration=decl_hash(first_inner),
                            contact=f"mailto:recovery{nonce}@example.com")
        second = sign_envelope_with(priv4, "publisher", second_inner, "test-r2")
        if (recovery_order_leaf(second) < recovery_order_leaf(first)) == reverse_leaves:
            break
    else:
        raise AssertionError("no discriminating recovery leaf order")
    batches = [[initial], prefix[1:] + [first, second]]
    if split_blocks:
        batches = [[initial], [first], [second]]
    blocks, previous = [], "sha256:genesis"
    for height, batch in enumerate(batches):
        entries = sorted(map(recovery_order_entry, batch),
                         key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
        leaves = [leaf_hash(rfc8785.dumps(entry)) for entry in entries]
        block_header = {"wist_version": "1.0.0", "block_number": height,
                        "prev_block_hash": previous,
                        "sealed_at": f"2026-08-04T{height:02d}:00:00Z",
                        "merkle_root": "sha256:" + merkle_tree_root(leaves).hex(),
                        "entry_count": len(entries)}
        block = sign_envelope_with(priv, "header", block_header, "test-log-k1")
        block["entries"] = entries
        blocks.append(block)
        previous = decl_hash(block_header)
    return {"name": name, "blocks": blocks, "pinned_head": previous,
            "expected": {"application_sequences": list(range(len(prefix) + 2)),
                         "owner_sequence": first_inner["seq"], "owner_height": 1,
                         "owner_declaration": decl_hash(first_inner),
                         "opened_at": blocks[1]["header"]["sealed_at"],
                         "windows_opened": 1},
            "recovery_leaves_reversed": reverse_leaves}


write_json(WIST1 / "recovery-order.json", {
    "note": "WIST-1 section 5.2 and WIST-3 section 3.3 recovery ownership over "
            "valid serial Declaration histories. The supplied Log key and pinned head "
            "are trusted fixture inputs. All queries are at the final Block, strictly "
            "inside the default seven-day recovery window; no settlement, conflicting "
            "candidate disposition or identity-reset result is asserted. The second "
            "recovery is signed by the recovery key installed by the first.",
    "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
    "recovery_window_days": 7,
    "cases": [
        recovery_order_case("same Block reversed recovery leaves", True),
        recovery_order_case("same Block ascending recovery leaves", False),
        recovery_order_case("later Block does not reopen recovery", True, split_blocks=True),
        recovery_order_case("ordinary predecessor before two recoveries", True, ordinary_first=True),
    ],
})

def recovery_settlement_vectors():
    extra = {name: Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        ("wist settlement " + name).encode()).digest()) for name in ("third", "fourth", "alien")}
    key_entries = {name: {"key_id": "test-" + name, "alg": "Ed25519",
                          "public_key": b64u(raw_public(key)),
                          "valid_from": "2026-08-03T12:00:00Z"}
                   for name, key in extra.items()}
    initial = sign_envelope("publisher", publisher, "test-k1")

    def signed(previous, seq, signer, key_id, **changes):
        inner = dict(previous["publisher"], seq=seq,
                     prev_declaration=decl_hash(previous["publisher"]), **changes)
        return sign_envelope_with(signer, "publisher", inner, key_id)

    owner = signed(initial, 1, priv2, "test-r1", keys=[K2], recovery_keys=[R2])
    fresh = signed(owner, 2, priv, "test-k1", keys=publisher["keys"])
    descendant = signed(fresh, 3, priv, "test-k1", keys=[key_entries["third"]])
    alien = signed(owner, 2, extra["alien"], "test-alien", keys=[key_entries["alien"]])
    ordinary = signed(owner, 2, priv3, "test-k2", keys=[key_entries["third"]])
    second = signed(owner, 2, priv4, "test-r2", keys=[key_entries["fourth"]],
                    recovery_keys=publisher["recovery_keys"])
    after_second = signed(second, 3, priv, "test-k1", keys=publisher["keys"])
    shared = signed(owner, 2, priv, "test-k1", keys=publisher["keys"] + [K2])
    wrong_branch = signed(shared, 3, priv3, "test-k2", keys=[key_entries["third"]])
    right_branch = signed(owner, 3, priv3, "test-k2", keys=[key_entries["third"]])
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
                "keys": [key["key_id"] for key in inner["keys"]],
                "recovery_keys": [key["key_id"] for key in inner.get("recovery_keys", [])],
                "envelope": env}
    cases = []
    for name, window, effective, superseded in scenarios:
        events = [initial, owner] + window
        blocks, previous = [], "sha256:genesis"
        for height in range(170):
            entries = [recovery_order_entry(events[height])] if height < len(events) else []
            root = recovery_order_leaf(events[height]) if entries else hashlib.sha256(b"\x00").digest()
            header = {"wist_version": "1.0.0", "block_number": height,
                      "prev_block_hash": previous, "sealed_at": timestamp(height),
                      "merkle_root": "sha256:" + root.hex(), "entry_count": len(entries)}
            block = sign_envelope_with(priv, "header", header, "test-log-k1")
            block["entries"] = entries
            blocks.append(block)
            previous = decl_hash(header)
        served = []
        for index, (signer, key_id) in enumerate([
                (priv, "test-k1"), (priv3, "test-k2"),
                (extra["third"], "test-third"), (extra["fourth"], "test-fourth"),
                (extra["alien"], "test-alien"), (priv3, "test-k2")]):
            inner = dict(delta, url=f"https://example.com/settlement/{index}",
                         observed_at=timestamp(10))
            env = sign_envelope_with(signer, "delta", inner, key_id)
            served.append({"delta_id": decl_hash(inner), "signer": key_id, "envelope": env})
        queued = [d for d in served if d["signer"] in {"test-k1", "test-k2"}]
        effective_ids = [key["key_id"] for key in effective["publisher"]["keys"]]
        probes = []
        for height, env in enumerate(events[2:], 2):
            predecessor = next(e for e in events[:height]
                               if decl_hash(e["publisher"]) == env["publisher"]["prev_declaration"])
            altered = publisher["recovery_keys"] if predecessor["publisher"]["recovery_keys"] == [R2] else [R2]
            signer_id = env["sig"]["key_id"]
            if signer_id in [key["key_id"] for key in predecessor["publisher"]["recovery_keys"]]:
                continue
            signer = {"test-k1": priv, "test-k2": priv3,
                      "test-alien": extra["alien"]}[signer_id]
            twin = signed(predecessor, env["publisher"]["seq"], signer, signer_id,
                          keys=env["publisher"]["keys"], recovery_keys=altered)
            probes.append({"name": "unauthorized recovery set replacement",
                           "prefix_height": height - 1, "candidate": twin,
                           "expected_result": "WIST1-E08"})
        stale = signed(initial, len(events), priv, "test-k1")
        probes.append({"name": "pre recovery predecessor cannot return",
                       "prefix_height": len(events) - 1, "candidate": stale,
                       "expected_result": "WIST1-E08"})
        bad = json.loads(json.dumps(owner))
        raw = bytearray(base64.urlsafe_b64decode(bad["sig"]["value"] + "=="))
        raw[0] ^= 1
        bad["sig"]["value"] = b64u(raw)
        probes.append({"name": "invalid Declaration author signature",
                       "prefix_height": 0, "candidate": bad, "expected_result": "WIST1-E01"})
        cases.append({"name": name, "blocks": blocks, "pinned_head": previous,
                      "initial_declaration": projection(initial),
                      "pre_recovery_keys": ["test-k1"], "recovery_declaration": projection(owner),
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
    old_delta = sign_envelope_with(priv, "delta", sample, "test-k1")
    new_delta = sign_envelope_with(priv3, "delta", sample, "test-k2")
    rebound = dict(K2, key_id="test-k1")
    rebound_delta = sign_envelope_with(priv3, "delta", sample, "test-k1")
    bad_delta = json.loads(json.dumps(new_delta))
    bad_delta["sig"]["value"] = old_delta["sig"]["value"]
    def binding(name, before, opening, final, env, queued, eligible):
        binding_cases.append({"name": name, "pre_recovery_keys": before,
                              "recovery_keys": opening, "settlement_keys": final,
                              "envelope": env, "delta_id": decl_hash(env["delta"]),
                              "expected_queued": queued, "expected_eligible": eligible})
    binding("reused identifier checks the second admission set", publisher["keys"], [rebound],
            [rebound], rebound_delta, True, True)
    binding("old binding queues but fails settlement", publisher["keys"], [rebound],
            [rebound], old_delta, True, False)
    binding("renamed same public key does not retain Delta identifier", publisher["keys"], [K2],
            [dict(K2, key_id="renamed")], new_delta, True, False)
    binding("settlement valid_from excludes previously queued Delta", publisher["keys"], [K2],
            [dict(K2, valid_from=timestamp(11))], new_delta, True, False)
    binding("valid_from equality is eligible", publisher["keys"], [dict(K2, valid_from=timestamp(10))],
            [dict(K2, valid_from=timestamp(10))], new_delta, True, True)
    binding("future valid_from prevents queue admission", publisher["keys"], [dict(K2, valid_from=timestamp(11))],
            [K2], new_delta, False, False)
    binding("known identifier with invalid signature is not queued", publisher["keys"], [K2],
            [K2], bad_delta, False, False)
    binding("unknown identifier is not queued", publisher["keys"], [K2], [K2],
            sign_envelope_with(priv3, "delta", sample, "unknown"), False, False)
    binding("later re serve of rejected Delta ID under a restored key", publisher["keys"], [K2],
            publisher["keys"], old_delta, True, True)
    binding_cases[-1]["re_serve_of"] = 1
    write_json(WIST1 / "recovery-settlement.json", {
        "note": "WIST-1 section 5.2. Each case supplies 170 authenticated hourly Blocks, "
                "opening recovery at height 1 and settling at height 169. Declaration projections "
                "must match their signed Envelopes and Block Entries. All key identifiers in each history "
                "have fixed public-key and valid_from bindings; separate binding_cases vary them. "
                "Every timestamp probe uses whole-second literal-Z values; this family does not "
                "establish the broader RFC 3339 profile of observed_at or valid_from. Signed served Deltas are "
                "distinct new URLs received in array order at hour 10; their shape and signature "
                "eligibility are exercised, not Payload availability, quotas or actual Block packing. "
                "expected.eligible denotes signature-eligible survivors in acceptance order, not proof "
                "of their eventual inclusion. Each probe independently replaces the next Block's "
                "Declaration as an unsealed candidate and must reject without changing its prefix. "
                "Snapshot recovery is not established by these histories.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "cases": cases, "binding_cases": binding_cases})


recovery_settlement_vectors()

def recovery_binding_vectors():
    signers = {name: Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        ("wist recovery binding " + name).encode()).digest()) for name in ("a", "b", "c")}
    instant = "2026-08-04T10:00:00.0000000001Z"
    future = "2026-08-04T10:00:00.0000000002Z"
    equivalent = "2026-08-04t11:00:00.000000000100+01:00"
    excluded = b64u((1).to_bytes(32, "little"))

    def key(name, valid_from=instant, key_id="shared", public=None):
        return {"key_id": key_id, "alg": "Ed25519",
                "public_key": public or b64u(raw_public(signers[name])), "valid_from": valid_from}

    scenarios = [
        ("both eligible", key("a"), key("b"), ("accepted", "accepted", "WIST1-E01")),
        ("old future", key("a", future), key("b"), ("WIST1-E01", "accepted", "WIST1-E01")),
        ("owner future", key("a"), key("b", future), ("accepted", "WIST1-E01", "WIST1-E01")),
        ("both future", key("a", future), key("b", future), ("WIST1-E02",) * 3),
        ("same public old future", key("a", future), key("a", equivalent),
         ("accepted", "WIST1-E01", "WIST1-E01")),
        ("same public owner future", key("a", equivalent), key("a", future),
         ("accepted", "WIST1-E01", "WIST1-E01")),
        ("old excluded", key("a", public=excluded), key("b"),
         ("WIST1-E01", "accepted", "WIST1-E01")),
        ("owner excluded", key("a"), key("b", public=excluded),
         ("accepted", "WIST1-E01", "WIST1-E01")),
        ("both excluded", key("a", public=excluded), key("b", public=excluded), ("WIST1-E02",) * 3),
        ("excluded and future", key("a", public=excluded), key("b", future), ("WIST1-E02",) * 3),
        ("future and excluded", key("a", future), key("b", public=excluded), ("WIST1-E02",) * 3),
        ("eligible differently named alias", key("a", future), key("a", key_id="renamed"),
         ("WIST1-E02",) * 3),
    ]
    histories, cases = {}, []
    for name, before, opening, outcomes in scenarios:
        for reverse in (False, True):
            history_name = name + (" reversed arrays" if reverse else "")
            old_keys = publisher["keys"] + [before]
            new_keys = [K2, opening]
            if reverse:
                old_keys.reverse()
                new_keys.reverse()
            initial = sign_envelope("publisher", dict(publisher, keys=old_keys), "test-k1")
            owner = sign_envelope_with(priv2, "publisher", dict(publisher, seq=1,
                prev_declaration=decl_hash(initial["publisher"]), keys=new_keys,
                recovery_keys=[R2]), "test-r1")
            follower = sign_envelope_with(priv3, "publisher", dict(owner["publisher"], seq=2,
                prev_declaration=decl_hash(owner["publisher"]), keys=[key("c", key_id="test-k3")]), "test-k2")
            blocks, previous = [], "sha256:genesis"
            for height, env in enumerate((initial, owner, follower)):
                header = {"wist_version": "1.0.0", "block_number": height,
                          "prev_block_hash": previous, "sealed_at": f"2026-08-04T{height:02d}:00:00Z",
                          "merkle_root": "sha256:" + recovery_order_leaf(env).hex(), "entry_count": 1}
                blocks.append(dict(sign_envelope_with(priv, "header", header, "test-log-k1"),
                                   entries=[recovery_order_entry(env)]))
                previous = decl_hash(header)
            histories[history_name] = {"blocks": blocks, "pinned_head": previous}

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

            for signer_name, outcome in zip(("a", "b", "c"), outcomes):
                add("signature " + signer_name, signers[signer_name], "shared", outcome)
            no_eligible = outcomes == ("WIST1-E02",) * 3
            add("invalid signature", signers["a"], "shared",
                "WIST1-E02" if no_eligible else "WIST1-E01", damage="signature")
            add("unknown identifier", signers["a"], "unknown", "WIST1-E02")
            add("pre recovery only recovery key", priv2, "test-r1", "WIST1-E02")
            add("owner only recovery key", priv4, "test-r2", "WIST1-E02")
            add("follower only signing key", signers["c"], "test-k3", "WIST1-E02")
            add("retired owner signing key", priv3, "test-k2", "accepted")
            add("malformed signature before missing authority", signers["a"], "unknown",
                "WIST1-E14", damage="encoding")
            add("leap label before missing authority", signers["a"], "unknown", "WIST1-E14",
                observed_at="2016-12-31T23:59:60Z")
            add("fraction beyond nanoseconds", signers["a"], "shared", outcomes[0],
                observed_at="2026-08-04T10:00:00.00000000010000000000000000001Z")
            add("offset equality", signers["b"], "shared", outcomes[1], observed_at=equivalent)
    write_json(WIST1 / "recovery-bindings.json", {
        "note": "WIST-1 sections 4, 5.1 and 5.2. Each history authenticates an initial Declaration, "
                "a recovery owner and an ordinary recovery-chain follower in three hourly Blocks. "
                "The supplied Log key and pinned head are trusted fixture inputs. Every independent Delta "
                "probe uses the prefix through prefix_height; the open window freezes the initial and "
                "owner signing bindings even after the follower. accepted denotes only successful Delta "
                "key verification, not queue mutation, complete Delta/chain eligibility, Payload availability, "
                "quotas, clock skew, actual sealing, settlement or Snapshot restoration. Timestamp probes "
                "exercise exact bound ordering and field rejection; accepted probes supply no live clock. "
                "Reversed-array histories re-sign Declarations and rebuild authenticated hashes.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "histories": histories, "cases": cases})


recovery_binding_vectors()

def recovery_heads_vectors():
    def signed(previous, seq, signer, key_id, **changes):
        inner = dict(previous["publisher"], seq=seq,
                     prev_declaration=decl_hash(previous["publisher"]), **changes)
        return sign_envelope_with(signer, "publisher", inner, key_id)

    initial = sign_envelope("publisher", publisher, "test-k1")
    owner = signed(initial, 1, priv2, "test-r1", keys=[K2], recovery_keys=[R2])
    fresh = signed(owner, 10, priv, "test-k1", keys=publisher["keys"])
    follower = signed(owner, 11, priv3, "test-k2", contact="mailto:owner@example.com")
    fresh_again = signed(follower, 20, priv, "test-k1", keys=publisher["keys"])
    recovered = signed(follower, 21, priv4, "test-r2", recovery_keys=publisher["recovery_keys"])
    competitor = signed(recovered, 30, priv, "test-k1", keys=publisher["keys"])
    after = signed(recovered, 31, priv3, "test-k2", contact="mailto:after@example.com")
    events = {0: initial, 1: owner, 2: fresh, 3: follower, 4: fresh_again,
              5: recovered, 6: competitor, 169: after}
    blocks, previous = [], "sha256:genesis"
    start = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc)
    def timestamp(hour):
        return (start + datetime.timedelta(hours=hour)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for height in range(171):
        entries = [recovery_order_entry(events[height])] if height in events else []
        root = (recovery_order_leaf(events[height]) if entries
                else hashlib.sha256(b"\x00").digest())
        header = {"wist_version": "1.0.0", "block_number": height,
                  "prev_block_hash": previous, "sealed_at": timestamp(height),
                  "merkle_root": "sha256:" + root.hex(), "entry_count": len(entries)}
        block = sign_envelope_with(priv, "header", header, "test-log-k1")
        block["entries"] = entries
        blocks.append(block)
        previous = decl_hash(header)
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
    via_fresh = signed(fresh, 11, priv3, "test-k2", keys=[K2])
    probe("same key naming competitor is fresh", 2, 3, via_fresh,
          "fresh_identity", state(via_fresh, owner, 11))
    for seq in (2, 10):
        candidate = signed(owner, seq, priv3, "test-k2")
        probe(f"sequence {seq} cannot ignore accepted competitor", 2, 3,
              candidate, "WIST1-E08", state(fresh, owner, 10))
    stale = signed(owner, 12, priv3, "test-k2")
    probe("old recovery ancestor cannot fork advanced chain", 3, 4, stale,
          "WIST1-E08", state(follower, follower, 11))
    probe("current Declaration is idempotent", 3, 4, follower,
          "idempotent", state(follower, follower, 11))
    sibling = signed(owner, 11, priv3, "test-k2", contact="mailto:sibling@example.com")
    probe("same predecessor is not identical publisher bytes", 3, 4, sibling,
          "WIST1-E08", state(follower, follower, 11))
    probe("recovery follower uses named head recovery protection", 4, 5, recovered,
          "recovery_rotation", state(recovered, recovered, 21))
    off_chain = signed(fresh_again, 21, priv4, "test-r2",
                       recovery_keys=publisher["recovery_keys"])
    probe("recovery of competitor cannot take window ownership", 4, 5, off_chain,
          "recovery_rotation", state(off_chain, follower, 21))
    stolen = signed(owner, 11, priv, "test-k1", keys=publisher["keys"],
                     recovery_keys=publisher["recovery_keys"])
    probe("fresh competitor cannot restore old recovery keys", 2, 3, stolen,
          "WIST1-E08", state(fresh, owner, 10))
    bad_signature = json.loads(json.dumps(follower))
    raw = bytearray(base64.urlsafe_b64decode(bad_signature["sig"]["value"] + "=="))
    raw[0] ^= 1
    bad_signature["sig"]["value"] = b64u(raw)
    probe("Block inclusion cannot replace author verification", 2, 3, bad_signature,
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
    probe("legitimate follower in deadline Block", 168, 169, after,
          "ordinary_rotation", state(after, None, 31))
    obsolete = signed(competitor, 31, priv, "test-k1")
    probe("superseded predecessor in deadline Block rejects", 168, 169, obsolete,
          "WIST1-E08", state(recovered, None, 30))
    low_seq = signed(recovered, 22, priv3, "test-k2")
    probe("settlement retains competing sequence floor", 168, 169, low_seq,
          "WIST1-E08", state(recovered, None, 30))
    new_recovery = signed(recovered, 31, priv2, "test-r1")
    probe("recovery at deadline opens a new window", 168, 169, new_recovery,
          "recovery_rotation", state(new_recovery, new_recovery, 31, opened_at=169, windows=2))
    probe("superseded predecessor remains rejected after settlement", 170, 171,
          signed(competitor, 32, priv, "test-k1"), "WIST1-E08", state(after, None, 31))
    competitor_recovery = signed(fresh, 11, priv4, "test-r2",
                                 recovery_keys=publisher["recovery_keys"])
    branch_header = dict(blocks[3]["header"],
                         merkle_root="sha256:" + recovery_order_leaf(competitor_recovery).hex())
    branch_block = sign_envelope_with(priv, "header", branch_header, "test-log-k1")
    branch_block["entries"] = [recovery_order_entry(competitor_recovery)]
    branch = {"blocks": blocks[:3] + [branch_block], "pinned_head": decl_hash(branch_header),
              "expected_state": state(competitor_recovery, owner, 11)}
    follows_named = signed(owner, 12, priv3, "test-k2")
    probe("ordinary follower preserves named head recovery set", 3, 4, follows_named,
          "ordinary_rotation", state(follows_named, follows_named, 12), branch=0)
    follows_competitor_set = signed(owner, 12, priv3, "test-k2",
                                    recovery_keys=publisher["recovery_keys"])
    probe("current competitor recovery set cannot replace named head set", 3, 4,
          follows_competitor_set, "WIST1-E08", state(competitor_recovery, owner, 11), branch=0)
    low_seq_after_restore = signed(recovered, 22, priv3, "test-k2")
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
                "Log key and final pinned head authenticate one complete hourly Block chain. "
                "An optional branch index selects an independently pinned alternate history. "
                "Queries replay through prefix_height, settle at candidate_sealed_at, then "
                "evaluate one independent unsealed candidate. Rejection preserves the "
                "post-settlement state. No invalid candidate is asserted to be a valid "
                "sealed Entry. No identity or conflicting-batch result is asserted.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "blocks": blocks, "pinned_head": previous,
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

    initial = sign_envelope("publisher", publisher, "test-k1")
    owner = signed(initial, 1, priv2, "test-r1", keys=[K2], recovery_keys=[R2])
    fresh = signed(owner, 2, priv, "test-k1", keys=publisher["keys"])
    branch = signed(fresh, 3, priv, "test-k1", contact="mailto:branch@example.com")
    branch_recovery = signed(branch, 4, priv4, "test-r2", keys=[K2])
    follower = signed(owner, 5, priv3, "test-k2", contact="mailto:follower@example.com")
    competitor = signed(follower, 6, priv, "test-k1", keys=publisher["keys"])
    newest = signed(follower, 7, priv3, "test-k2", contact="mailto:newest@example.com")
    recovered = signed(owner, 3, priv4, "test-r2", keys=publisher["keys"])
    recovered_again = signed(recovered, 4, priv4, "test-r2", contact="mailto:again@example.com")
    fresh_after_recovery = signed(recovered, 4, priv3, "test-k2", keys=[K2], contact="mailto:after-recovery@example.com")
    after = signed(newest, 8, priv, "test-k1", keys=publisher["keys"])
    late = signed(owner, 3, priv, "test-k1", keys=publisher["keys"], contact="mailto:late@example.com")
    declarations = dict(initial=initial, owner=owner, fresh=fresh, branch=branch,
                        branch_recovery=branch_recovery, follower=follower,
                        competitor=competitor, newest=newest, recovered=recovered,
                        recovered_again=recovered_again, fresh_after_recovery=fresh_after_recovery,
                        after=after, late=late)
    start = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc)
    def timestamp(hour, seconds=0):
        return (start + datetime.timedelta(hours=hour, seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    def block(height, previous, names):
        entries = sorted((recovery_order_entry(declarations[name]) for name in names),
                         key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
        leaves = [leaf_hash(rfc8785.dumps(entry)) for entry in entries]
        root = merkle_tree_root(leaves) if leaves else hashlib.sha256(b"\x00").digest()
        header = dict(wist_version="1.0.0", block_number=height, prev_block_hash=previous,
                      sealed_at=timestamp(height), merkle_root="sha256:" + root.hex(),
                      entry_count=len(entries))
        result = sign_envelope_with(priv, "header", header, "test-log-k1")
        result["entries"] = entries
        return result
    blocks, previous = [], "sha256:genesis"
    for height in range(168):
        result = block(height, previous, ["initial"] if height == 0 else ["owner"] if height == 1 else [])
        blocks.append(result)
        previous = decl_hash(result["header"])

    cases = []
    def case(name, accepted, sealed, retained, discarded, current, floor,
             post=None, log_current=None, log_floor=None, new_window=False, boundary=None,
             new_window_owner=None, log_reset=False, overdue=False):
        before = block(168, previous, sealed)
        post = post or []
        deadline = block(169, decl_hash(before["header"]), retained + [item[0] for item in post if item[1] != "WIST1-E08"])
        probes = [{"declaration": item, "expected": result} for item, result in post]
        cases.append({
            "name": name,
            "admitted_at": boundary or timestamp(167, 1),
            "admitted": accepted,
            "last_inside_block": before,
            "last_inside_pin": decl_hash(before["header"]),
            "expected_settlement": {"current": current, "floor": floor,
                                    "queue_source": "owner", "retained": retained,
                                    "removed": discarded},
            "removed_recovery_sealing_violation": overdue,
            "at_deadline": probes,
            "expected_after_repeat": {"current": post[-1][0] if post and post[-1][1] != "WIST1-E08" else current,
                                      "floor": declarations[post[-1][0]]["publisher"]["seq"]
                                      if post and post[-1][1] != "WIST1-E08" else floor},
            "deadline_block": deadline,
            "deadline_pin": decl_hash(deadline["header"]),
            "expected_log": {"current": log_current or (post[-1][0] if post and post[-1][1] != "WIST1-E08" else current),
                             "floor": log_floor if log_floor is not None else (declarations[post[-1][0]]["publisher"]["seq"]
                                       if post and post[-1][1] != "WIST1-E08" else floor),
                             "window_end": timestamp(337) if new_window else None,
                             "reset_height": 169 if log_reset else None},
        })
        if new_window:
            cases[-1]["expected_window_owner"] = new_window_owner or "recovered"
        if discarded == ["fresh"]:
            revival = block(169, decl_hash(before["header"]), ["fresh"])
            cases[-1]["forbidden_revival"] = {"block": revival, "pin": decl_hash(revival["header"]),
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
        "note": "WIST-1 section 5.2. Shared signed hourly prefix plus each case's last inside Block "
                "and deadline Block authenticate sealed Declaration state. Named signed admission "
                "candidates are separate supplied local events, not claims of inclusion. Admission "
                "happens at admitted_at, including when later than last_inside_block. Settle at "
                "deadline, evaluate at_deadline candidates in order, then repeat admission settlement "
                "before evaluating the deadline Block. No Delta, Payload, quota, Snapshot, durable "
                "storage or authenticated Audit Record eligibility is asserted.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "deadline": timestamp(169),
        "blocks": blocks, "pinned_head": previous,
        "declarations": declarations, "cases": cases,
    })


recovery_admission_vectors()

def declaration_conflict_vectors():
    def signed(previous, seq, signer=priv, key_id="test-k1", **changes):
        inner = dict(previous["publisher"], seq=seq,
                     prev_declaration=decl_hash(previous["publisher"]), **changes)
        return sign_envelope_with(signer, "publisher", inner, key_id)

    def block(previous, height, batch):
        entries = sorted(map(recovery_order_entry, batch),
                         key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
        instant = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc) + datetime.timedelta(hours=height)
        hashes = [leaf_hash(rfc8785.dumps(entry)) for entry in entries]
        root = merkle_tree_root(hashes) if hashes else hashlib.sha256(b"\x00").digest()
        header = {"wist_version": "1.0.0", "block_number": height,
                  "prev_block_hash": previous,
                  "sealed_at": instant.isoformat().replace("+00:00", "Z"),
                  "merkle_root": "sha256:" + root.hex(), "entry_count": len(entries)}
        return dict(sign_envelope_with(priv, "header", header, "test-log-k1"), entries=entries)

    def state(current, chain=None, floor=None, windows=0, reset=None):
        return {"current_envelope": decl_hash(current),
                "recovery_envelope": decl_hash(chain) if chain else None,
                "highest_accepted_seq": current["publisher"]["seq"] if floor is None else floor,
                "window_end": "2026-08-11T01:00:00Z" if chain else None,
                "windows_opened": windows, "reset_height": reset}

    initial = sign_envelope("publisher", publisher, "test-k1")
    owner = signed(initial, 1, priv2, "test-r1", keys=[K2], recovery_keys=[R2])
    fresh = signed(owner, 2, keys=publisher["keys"])
    blocks, previous = [], "sha256:genesis"
    for height in range(169):
        batch = [initial] if height == 0 else [owner] if height == 1 else [fresh] if height == 2 else []
        blocks.append(block(previous, height, batch))
        previous = decl_hash(blocks[-1]["header"])
    prefixes = {"empty": [], "initial": blocks[:1], "open": blocks[:3], "deadline": blocks}
    initial_state = {"example.com": state(initial)}
    open_state = {"example.com": state(fresh, owner, windows=1)}
    cases = []

    def add(name, prefix, batch, expected, result="accepted", isolated=(), invalid=(), **fields):
        history = prefixes[prefix]
        previous = decl_hash(history[-1]["header"]) if history else "sha256:genesis"
        candidate = block(previous, len(history), batch)
        cases.append({"name": name, "prefix": prefix, "block": candidate,
                      "pinned_head": decl_hash(candidate["header"]),
                      "expected_results": [result], "expected_state": expected,
                      "signature_valid": [entry["body"] not in invalid for entry in candidate["entries"]],
                      "expected_accepted_head": decl_hash(candidate["header"]) if result == "accepted" else previous,
                      "isolated_candidates": [{"previous": p, "incoming": e, "expected_result": r}
                                              for p, e, r in isolated], **fields})

    ordinary = signed(initial, 1, keys=[K2])
    recovery_same = sign_envelope_with(priv2, "publisher", ordinary["publisher"], "test-r1")
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
        [initial, sign_envelope_with(priv2, "publisher", publisher, "test-r1")], initial_state)
    alternate_initial = sign_envelope("publisher", dict(publisher, contact="mailto:other@example.com"), "test-k1")
    add("distinct initial Declarations", "empty", [initial, alternate_initial], {}, "WIST1-E08",
        [(None, initial, "initial"), (None, alternate_initial, "initial")])
    add("identical initial Envelopes", "empty", [initial, initial], initial_state)
    other = sign_envelope("publisher", dict(publisher, domain="aaa.example.net", subdomain_scope=[],
                                           contact="mailto:keys@aaa.example.net"), "test-k1")
    add("equal sequences across domains", "empty", [initial, other],
        {"example.com": state(initial), "aaa.example.net": state(other)})
    lower = signed(initial, 1, contact="mailto:lower@example.com")
    left = signed(lower, 2, contact="mailto:left@example.com")
    right = signed(lower, 2, contact="mailto:right@example.com")
    add("reject lower sequence and other domain effects", "initial", [other, lower, left, right],
        initial_state, "WIST1-E08",
        [(None, other, "initial"), (initial, lower, "ordinary_rotation"),
         (lower, left, "ordinary_rotation"), (lower, right, "ordinary_rotation")])
    follower = signed(owner, 3, priv3, "test-k2", contact="mailto:follower@example.com")
    competitor = signed(fresh, 3, contact="mailto:competitor@example.com")
    add("distinct eligible recovery heads", "open", [follower, competitor], open_state, "WIST1-E08",
        [(owner, follower, "ordinary_rotation"), (fresh, competitor, "ordinary_rotation")])
    restored_alternate = sign_envelope_with(priv3, "publisher", owner["publisher"], "test-k2")
    add("settlement precedes restored current re serves", "deadline", [owner, restored_alternate],
        {"example.com": state(owner, floor=2, windows=1)})
    after_left = signed(owner, 3, priv3, "test-k2", contact="mailto:afterleft@example.com")
    after_right = signed(owner, 3, priv3, "test-k2", contact="mailto:afterright@example.com")
    add("rejected deadline Block does not settle", "deadline", [after_left, after_right],
        open_state, "WIST1-E08",
        [(owner, after_left, "ordinary_rotation"), (owner, after_right, "ordinary_rotation")])
    alias_inner = dict(ordinary["publisher"], keys=[K2, dict(K2, key_id="alias")])
    alias_one = sign_envelope_with(priv3, "publisher", alias_inner, "test-k2")
    alias_two = sign_envelope_with(priv3, "publisher", alias_inner, "alias")
    add("same authority distinct signature identifiers", "initial", [alias_one, alias_two],
        initial_state, "WIST1-E08",
        [(initial, alias_one, "fresh_identity"), (initial, alias_two, "fresh_identity")])
    invalid_author = sign_envelope_with(priv4, "publisher", ordinary["publisher"], "test-k1")
    add("conflict does not filter invalid signatures", "initial", [ordinary, invalid_author],
        initial_state, "WIST1-E08",
        [(initial, ordinary, "ordinary_rotation"), (initial, invalid_author, "WIST1-E01")],
        invalid=[invalid_author])
    add("duplicate does not waive first signature check", "initial", [invalid_author, invalid_author],
        initial_state, "WIST1-E01", [(initial, invalid_author, "WIST1-E01")], invalid=[invalid_author])
    add("current object and changed sibling conflict", "initial", [initial, alternate_initial],
        initial_state, "WIST1-E08")
    add("initial and duplicate replacement in one Block", "empty", [initial, ordinary, ordinary],
        {"example.com": state(ordinary)})
    invalid_other = sign_envelope_with(priv4, "publisher", other["publisher"], "test-k1")
    add("different domains may report either failure", "initial", [invalid_other, ordinary, recovery_same],
        initial_state, "WIST1-E08", [(None, invalid_other, "WIST1-E01")], invalid=[invalid_other],
        expected_results=["WIST1-E01", "WIST1-E08"])
    write_json(WIST1 / "declaration-conflicts.json", {
        "note": "WIST-1 section 5.2 and WIST-3 section 3.3 equal-sequence Declaration groups. "
                "Each case appends its Block to the named authenticated prefix; trusted fixture "
                "inputs are the supplied Log key, pinned head and default seven-day window. "
                "Expected state hashes commit to whole installed Envelopes, including signatures. "
                "The deadline prefix ends one hour before settlement. Candidate classification "
                "probes are independent of batch acceptance; signature_valid checks only cryptographic "
                "authorship against fixture key bindings, not eligibility or idempotent installation. "
                "No Snapshot eligibility is asserted. Domain iteration order is immaterial to accepted state.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "prefixes": prefixes, "cases": cases})


declaration_conflict_vectors()

def declaration_field_vectors():
    conflicts = json.loads((WIST1 / "declaration-conflicts.json").read_text())
    initial = sign_envelope("publisher", publisher, "test-k1")
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
        cases.append({"name": name, "envelope": sign_envelope("publisher", inner, "test-k1"),
                      "expected": expected, "author_signature_valid": True})

    for path, value in (
        (["seq"], None), (["seq"], True), (["seq"], 1.5), (["seq"], -1),
        (["seq"], float(2**53)), (["prev_declaration"], None),
        (["prev_declaration"], "sha256:bad"), (["keys"], []),
        (["recovery_keys"], None), (["subdomain_scope"], None),
        (["contact"], None), (["contact"], "x" * 257),
        (["domain"], "bad host.example"), (["subdomain_scope"], ["bad host.example"]),
        (["keys", 0, "key_id"], "x" * 65), (["keys", 0, "alg"], "other"),
        (["keys", 0, "public_key"], "!" * 43),
        (["wist_version"], "1.0"), (["unknown"], True),
    ):
        add("invalid " + " ".join(map(str, path)) + " " + str(value)[:12], path, value)
    for path in (["seq"], ["domain"], ["keys"], ["keys", 0, "valid_from"]):
        add("missing " + " ".join(map(str, path)), path, remove=True)
    add("missing semantic predecessor", ["prev_declaration"], remove=True, expected="WIST1-E08")
    add("well shaped wrong predecessor", ["prev_declaration"], "sha256:" + "00" * 32,
        expected="WIST1-E08")
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
    for position, (value, valid) in enumerate(times):
        add(f"signing valid from {position}", ["keys", 0, "valid_from"], value,
            expected="ordinary_rotation" if valid else "WIST1-E14")
        add(f"recovery valid from {position}", ["recovery_keys", 0, "valid_from"], value,
            expected="WIST1-E08" if valid else "WIST1-E14")
    for field, value in (("sig", None), ("unknown", True)):
        env = sign_envelope("publisher", ordinary, "test-k1")
        env[field] = value
        cases.append({"name": "Envelope " + field, "envelope": env,
                      "expected": "WIST1-E14", "author_signature_valid": field != "sig"})
    for field, value in (("value", "bad"), ("key_id", None), ("alg", "other"), ("unknown", True)):
        env = sign_envelope("publisher", ordinary, "test-k1")
        env["sig"][field] = value
        cases.append({"name": "signature " + field, "envelope": env,
                      "expected": "WIST1-E14", "author_signature_valid": field != "value"})
    bad_signature = sign_envelope_with(priv4, "publisher", ordinary, "test-k1")
    cases.append({"name": "valid fields invalid signature", "envelope": bad_signature,
                  "expected": "WIST1-E01", "author_signature_valid": False})
    cases.append({"name": "invalid fields and invalid signature",
                  "envelope": sign_envelope_with(priv4, "publisher", dict(ordinary, contact=None), "test-k1"),
                  "expected": "WIST1-E14", "author_signature_valid": False})
    delta_cases = []
    for position, (value, valid) in enumerate(times):
        inner = {key: value for key, value in delta.items() if key != "payload"}
        inner.update(change_type="delete", observed_at=value, prev=decl_hash(delta))
        delta_cases.append({"name": f"observed at {position}",
                            "envelope": sign_envelope("delta", inner, "test-k1"),
                            "expected": "well_formed" if valid else "WIST1-E14"})
    absent = {key: value for key, value in delta.items() if key not in ("payload", "observed_at")}
    absent.update(change_type="delete", prev=decl_hash(delta))
    delta_cases.append({"name": "missing observed at", "envelope": sign_envelope("delta", absent, "test-k1"),
                        "expected": "WIST1-E14"})

    key_time_cases = []
    for name, valid_from, observed_at, expected in [
        ("fraction beyond integer parser defaults", "2026-08-04T10:00:00." + "0" * 4400 + "2Z", "2026-08-04T10:00:00." + "0" * 4400 + "1Z", "WIST1-E02"),
        ("fraction follows whole second", "2026-08-04T10:00:00Z", "2026-08-04T10:00:00.5Z", "key_bound_satisfied"),
        ("arbitrary precision equality", "2026-08-04T10:00:00.000000000000000000000000000001Z", "2026-08-04T07:00:00.000000000000000000000000000001000-03:00", "key_bound_satisfied"),
        ("no fractional rounding", "2026-08-04T10:00:00.000000000000000000000000000002Z", "2026-08-04T10:00:00.000000000000000000000000000001Z", "WIST1-E02"),
        ("unknown local offset equality", "2026-08-04T10:00:00-00:00", "2026-08-04t10:00:00.000z", "key_bound_satisfied"),
        ("numeric offset equality", "2026-08-04T10:00:00+01:30", "2026-08-04T08:30:00Z", "key_bound_satisfied"),
        ("positive leap boundary", "2016-12-31T23:59:59.9Z", "2017-01-01T00:00:00Z", "key_bound_satisfied"),
        ("inserted leap label invalid", "2016-12-31T23:59:59Z", "2016-12-31T23:59:60Z", "WIST1-E14"),
        ("future leap key invalid", "2030-06-30T23:59:60Z", "2030-07-01T00:00:00Z", "WIST1-E14"),
        ("hypothetical deletion keeps 59", "2030-06-30T23:59:58Z", "2030-06-30T23:59:59Z", "key_bound_satisfied"),
        ("hypothetical deletion boundary", "2030-06-30T23:59:59.9Z", "2030-07-01T00:00:00Z", "key_bound_satisfied"),
        ("future key retains inclusive bound", "2030-07-01T00:00:00Z", "2030-06-30T23:59:59.99999999999999999999Z", "WIST1-E02"),
        ("offset below written year range", "0000-01-01T00:00:00+23:59", "0000-01-01T00:00:00+23:58", "key_bound_satisfied"),
        ("offset above written year range", "9999-12-31T23:59:59-23:58", "9999-12-31T23:59:59.00000000001-23:59", "key_bound_satisfied"),
        ("year zero leap day", "0000-02-29T23:59:59Z", "0000-03-01T00:00:00Z", "key_bound_satisfied"),
    ]:
        declaration = dict(publisher, keys=[dict(publisher["keys"][0], valid_from=valid_from)])
        inner = {key: value for key, value in delta.items() if key != "payload"}
        inner.update(change_type="delete", observed_at=observed_at, prev=decl_hash(delta))
        key_time_cases.append({"name": name,
                               "declaration": sign_envelope("publisher", declaration, "test-k1"),
                               "envelope": sign_envelope("delta", inner, "test-k1"),
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
            case["predecessor"] = sign_envelope("delta", predecessor, "test-k1")
            inner["prev"] = decl_hash(predecessor)
        case["envelope"] = sign_envelope("delta", inner, "test-k1")
        relation_cases.append(case)

    def block(previous, height, batch):
        entries = sorted(map(recovery_order_entry, batch),
                         key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
        instant = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc) + datetime.timedelta(hours=height)
        header = {"wist_version": "1.0.0", "block_number": height, "prev_block_hash": previous,
                  "sealed_at": instant.isoformat().replace("+00:00", "Z"),
                  "merkle_root": "sha256:" + merkle_tree_root([
                      leaf_hash(rfc8785.dumps(entry)) for entry in entries]).hex(),
                  "entry_count": len(entries)}
        return dict(sign_envelope_with(priv, "header", header, "test-log-k1"), entries=entries)

    batches = []
    other = sign_envelope("publisher", dict(publisher, domain="other.example"), "test-k1")
    for case in cases:
        batch = block(decl_hash(conflicts["prefixes"]["initial"][-1]["header"]), 1,
                      [other, case["envelope"]])
        batches.append({"name": case["name"], "prefix": "initial", "block": batch,
                        "pinned_head": decl_hash(batch["header"]),
                        "expected": "accepted" if case["expected"] == "ordinary_rotation" else case["expected"]})
    valid = sign_envelope("publisher", ordinary, "test-k1")
    malformed = json.loads(json.dumps(valid))
    malformed["sig"]["unknown"] = True
    later = dict(ordinary, seq=2, prev_declaration=decl_hash(ordinary), contact=None)
    for name, members, expected in (
        ("field error precedes same sequence conflict", [valid, malformed], "WIST1-E14"),
        ("field error rolls back lower sequence", [valid, sign_envelope_with(priv3, "publisher", later, "test-k2")], "WIST1-E14"),
        ("repaired field accepts both sequences", [valid, sign_envelope_with(
            priv3, "publisher", dict(later, contact="mailto:security@example.com"), "test-k2")], "accepted"),
    ):
        batch = block(decl_hash(conflicts["prefixes"]["initial"][-1]["header"]), 1, members + [other])
        batches.append({"name": name, "prefix": "initial", "block": batch,
                        "pinned_head": decl_hash(batch["header"]), "expected": expected})
    for prefix in ("empty", "initial", "open", "deadline"):
        history = conflicts["prefixes"][prefix]
        current = initial if prefix in ("empty", "initial") else history[2]["entries"][0]["body"]
        env = json.loads(json.dumps(current))
        env["sig"]["unknown"] = True
        batch = block(decl_hash(history[-1]["header"]) if history else "sha256:genesis",
                      len(history), [other, env])
        batches.append({"name": "malformed re serve " + prefix, "prefix": prefix, "block": batch,
                        "pinned_head": decl_hash(batch["header"]), "expected": "WIST1-E14"})
    for prefix in ("empty", "initial", "open", "deadline"):
        history = conflicts["prefixes"][prefix]
        current = initial if prefix in ("empty", "initial") else history[2]["entries"][0]["body"]
        for array in ("keys", "recovery_keys"):
            inner = json.loads(json.dumps(current["publisher"]))
            inner[array][0]["valid_from"] = "2016-12-31T23:59:60Z"
            env = sign_envelope("publisher", inner, "test-k1")
            batch = block(decl_hash(history[-1]["header"]) if history else "sha256:genesis",
                          len(history), [other, env])
            batches.append({"name": "leap field rolls back " + array + " " + prefix,
                            "prefix": prefix, "block": batch,
                            "pinned_head": decl_hash(batch["header"]), "expected": "WIST1-E14"})
    write_json(WIST1 / "declaration-fields.json", {
        "note": "WIST-1 sections 3.4, 5.1 and 7. Signature-valid field mutations use the supplied fixture "
                "author key independently of eligibility. Each Declaration case replaces stored; each batch "
                "appends to its named authenticated prefix. Rejection preserves the full accepted state and head, "
                "including due settlement and other domains. Delta cases assert timestamp field syntax only, "
                "not full clock, chain or Payload eligibility. Timestamp fields follow the event-independent "
                "Gregorian profile in WIST-1 section 3.4, rejecting every leap label; the 2030-06-30 "
                "deletion is hypothetical and asserts no IERS announcement. Key-time cases authenticate "
                "one supplied binding and assert only field validity and its inclusive bound. Elapsed cases "
                "use exact civil-clock seconds. Relation cases isolate the inclusive 600-second clock bound "
                "and strict predecessor ordering; predecessor authorship and ID are checked but lower Log "
                "position, chain availability and clock acquisition are supplied assumptions. Hostname coverage is limited to ASCII structural examples. No full field profile, "
                "cryptographic key admission, Snapshot restoration or live service conformance is asserted.",
        "log_key": conflicts["log_key"], "author_key": b64u(pub_raw), "stored": initial,
        "recovery_window_days": 7, "prefixes": conflicts["prefixes"],
        "cases": cases, "delta_cases": delta_cases, "block_cases": batches,
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
        old = sign_envelope("publisher", previous, "test-k1") if previous else None
        env = sign_envelope_with(signer, "publisher", incoming, key_id)
        cases.append({"name": name, "stored": old, "fetched": env, "expected": expected,
                      "author_key": b64u(raw_public(signer)),
                      "expected_usable": {field: [key for key in incoming.get(field, [])
                                                   if key["public_key"] not in excluded_values]
                                          for field in ("keys", "recovery_keys")}})

    for label, raw in excluded.items():
        bad = dict(K2, key_id="excluded", public_key=b64u(raw))
        for field in ("keys", "recovery_keys"):
            initial = variant(**{field: stored_decl[field] + [bad]})
            add("initial unused " + field + " " + label, None, initial, priv, "test-k1", "initial")
            ordinary = dict(initial, seq=1, prev_declaration=decl_hash(initial),
                            keys=[K2, bad] if field == "keys" else [K2])
            add("ordinary unused " + field + " " + label, initial, ordinary,
                priv, "test-k1", "ordinary_rotation")
        incoming = variant(seq=1, prev_declaration=stored_hash, keys=[K2, bad])
        add("recovery unused " + label, stored_decl, incoming, priv2, "test-r1", "recovery_rotation")
        add("excluded incoming named signer " + label, stored_decl, incoming, priv3, "excluded", "WIST1-E02")
        previous = variant(recovery_keys=[stored_decl["recovery_keys"][0], bad])
        incoming = dict(previous, seq=1, prev_declaration=decl_hash(previous), keys=[K2])
        add("excluded previous recovery named signer " + label, previous, incoming,
            priv3, "excluded", "WIST1-E02")
        add("valid recovery carries excluded entry " + label, previous, incoming,
            priv2, "test-r1", "recovery_rotation")
        changed = dict(incoming, recovery_keys=stored_decl["recovery_keys"])
        add("excluded recovery entry still protected " + label, previous, changed,
            priv, "test-k1", "WIST1-E08")
        add("valid recovery removes excluded entry " + label, previous, changed,
            priv2, "test-r1", "recovery_rotation")
        add("initial no usable signing keys " + label, None, variant(keys=[bad]),
            priv3, "excluded", "WIST1-E02")
        add("replacement no usable signing keys " + label, stored_decl,
            variant(seq=1, prev_declaration=stored_hash, keys=[bad]), priv, "test-k1", "ordinary_rotation")
        previous = variant(keys=stored_decl["keys"] + [dict(bad, key_id="test-k2")])
        incoming = variant(seq=1, prev_declaration=decl_hash(previous), keys=[K2])
        add("excluded old binding permits incoming signer " + label, previous, incoming,
            priv3, "test-k2", "fresh_identity")
        incoming = variant(seq=1, prev_declaration=stored_hash, keys=[dict(bad, key_id="test-k1"), K2])
        add("excluded incoming binding permits old signer " + label, stored_decl, incoming,
            priv, "test-k1", "ordinary_rotation")
        duplicate = variant(keys=stored_decl["keys"] + [dict(bad, key_id="test-k1")])
        add("excluded duplicate identifier " + label, None, duplicate, priv, "test-k1", "WIST1-E08")
        overlap = variant(keys=stored_decl["keys"] + [bad], recovery_keys=[dict(bad, key_id="other")])
        add("excluded cross set overlap " + label, None, overlap, priv, "test-k1", "WIST1-E08")
        previous = variant(recovery_keys=[bad])
        incoming = dict(previous, seq=1, prev_declaration=decl_hash(previous), recovery_keys=[])
        add("no usable recovery key does not unprotect entries " + label, previous, incoming,
            priv, "test-k1", "WIST1-E08")
    mixed = dict(K2, key_id="mixed", public_key=b64u(bytes.fromhex(
        "b502ff3d92e31d8190b4aa4ea0414005167fad089c4de9dac8a2fc850fed4f58")))
    add("non small mixed order key remains usable", None,
        variant(keys=stored_decl["keys"] + [mixed]), priv, "test-k1", "initial")
    add("usable named binding invalid signature", stored_decl,
        variant(seq=1, prev_declaration=stored_hash, keys=[K2]), priv4, "test-k2", "WIST1-E01")
    add("future valid from does not exclude Declaration signer", None,
        variant(keys=[dict(stored_decl["keys"][0], valid_from="9999-12-31T23:59:59Z")]),
        priv, "test-k1", "initial")
    write_json(WIST1 / "declaration-key-eligibility.json", {
        "note": "WIST-1 sections 4 and 5.2 derive usable keys while retaining every signed entry. "
                "stored is null for initial admission; otherwise it is an authenticated initial Declaration. "
                "Each fetched signature is independently verifiable under author_key, even when that key has "
                "no eligible named binding. expected_usable describes cryptographic key exclusion only, "
                "even for rejected Envelopes, and is not installed state. Fixtures use canonical base64url "
                "and ordinary valid fields. No temporal authority selection, full field/encoding profile, live "
                "admission, Delta replay or Snapshot result is asserted.",
        "cases": cases})


declaration_key_eligibility_vectors()

def base64url_vectors():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    fields = []
    for kind, size in (("public_key", 32), ("signature", 64), ("salt", 16), ("salt", 17), ("salt", 18)):
        encoded = b64u(bytes(range(size)))
        unused = (6 - (size * 8) % 6) % 6
        for index, character in enumerate(alphabet):
            fields.append({"name": f"{kind} {size} octets final sextet {index}", "kind": kind,
                           "encoded": encoded[:-1] + character,
                           "expected": "well_formed" if index % (2**unused) == 0 else "WIST1-E14"})
    for kind, size in (("public_key", 32), ("signature", 64), ("salt", 16)):
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
        env = sign_envelope("publisher", inner, "test-k1")
        if signature_bits:
            env["sig"]["value"] = alias(env["sig"]["value"], signature_bits)
        cases.append({"name": name, "stored": previous, "envelope": env, "expected": expected})

    initial = sign_envelope("publisher", publisher, "test-k1")
    ordinary = variant(seq=1, prev_declaration=stored_hash, keys=[K2])
    add("canonical initial", publisher, expected="initial")
    add("canonical ordinary", ordinary, initial, "ordinary_rotation")
    add("canonical in set alias", variant(keys=[publisher["keys"][0],
        dict(publisher["keys"][0], key_id="alias")]), expected="initial")
    add("canonical cross set overlap", variant(recovery_keys=[
        dict(publisher["keys"][0], key_id="alias")]), expected="WIST1-E08")
    for bits in range(1, 4):
        for field in ("keys", "recovery_keys"):
            mutated = json.loads(json.dumps(publisher))
            mutated[field][0]["public_key"] = alias(mutated[field][0]["public_key"], bits)
            add(f"initial {field} unused bits {bits}", mutated)
            incoming = dict(mutated, seq=1, prev_declaration=stored_hash)
            add(f"replacement {field} unused bits {bits}", incoming, initial)
        bad = dict(K2, public_key=alias(K2["public_key"], bits))
        add(f"unused signing key unused bits {bits}", variant(keys=publisher["keys"] + [bad]))
        bad = dict(publisher["keys"][0], key_id="alias",
                   public_key=alias(publisher["keys"][0]["public_key"], bits))
        add(f"cross set byte alias unused bits {bits}", variant(recovery_keys=[bad]))
        excluded = dict(K2, public_key=alias(b64u((1).to_bytes(32, "little")), bits))
        add(f"excluded point malformed spelling {bits}", variant(keys=publisher["keys"] + [excluded]))
    for bits in range(1, 16):
        add(f"initial signature unused bits {bits}", publisher, signature_bits=bits)
        add(f"replacement signature unused bits {bits}", ordinary, initial, signature_bits=bits)
    conflicts = json.loads((WIST1 / "declaration-conflicts.json").read_text())
    blocks = []
    for prefix in ("empty", "initial", "open", "deadline"):
        history = conflicts["prefixes"][prefix]
        current = initial if prefix in {"empty", "initial"} else next(
            entry["body"] for block in history for entry in block["entries"]
            if entry["body"]["publisher"]["seq"] == (1 if prefix == "deadline" else 2))
        malformed = json.loads(json.dumps(current))
        malformed["sig"]["value"] = alias(malformed["sig"]["value"], 1)
        other = sign_envelope("publisher", dict(publisher, domain="other.example"), "test-k1")
        for reject in (False, True):
            members = [other, current] + ([malformed] if reject else [])
            entries = sorted(map(recovery_order_entry, members), key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
            instant = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc) + datetime.timedelta(hours=len(history))
            header = {"wist_version": "1.0.0", "block_number": len(history),
                      "prev_block_hash": decl_hash(history[-1]["header"]) if history else "sha256:genesis",
                      "sealed_at": instant.isoformat().replace("+00:00", "Z"),
                      "merkle_root": "sha256:" + merkle_tree_root([leaf_hash(rfc8785.dumps(entry)) for entry in entries]).hex(),
                      "entry_count": len(entries)}
            block = dict(sign_envelope_with(priv, "header", header, "test-log-k1"), entries=entries)
            blocks.append({"name": prefix + (" rejects signature alias" if reject else " accepts canonical twin"),
                           "prefix": prefix, "block": block, "pinned_head": decl_hash(header),
                           "expected": "WIST1-E14" if reject else "accepted"})
    write_json(WIST1 / "base64url.json", {
        "note": "WIST-1 section 2 canonical base64url. Field cases establish encoding/length only, not point "
                "eligibility or signatures. Declaration author signatures are valid under author_key even when "
                "permissive decoding is needed to inspect a rejected signature alias; acceptance never repairs it. "
                "Each Block appends to its named authenticated prefix; rejection preserves all state and the "
                "accepted head, including due settlement and other domains. Canonical twins exercise acceptance. "
                "Full field formats, live services, transport wrappers and Snapshot restoration are not established.",
        "author_key": b64u(pub_raw), "log_key": conflicts["log_key"], "recovery_window_days": 7,
        "fields": fields, "cases": cases, "prefixes": conflicts["prefixes"], "block_cases": blocks})


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
                          'envelope': sign_envelope('publisher', inner, 'test-k1'),
                          'expected': 'initial' if host['expected'] == 'well_formed' else 'WIST1-E14'})
    conflicts = json.loads((WIST1 / 'declaration-conflicts.json').read_text())
    blocks = []

    def add_block(name, prefix, members, expected, domains=None):
        history = conflicts['prefixes'][prefix]
        entries = sorted(map(recovery_order_entry, members), key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
        instant = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc) + datetime.timedelta(hours=len(history))
        header = {'wist_version': '1.0.0', 'block_number': len(history),
                  'prev_block_hash': decl_hash(history[-1]['header']) if history else 'sha256:genesis',
                  'sealed_at': instant.isoformat().replace('+00:00', 'Z'),
                  'merkle_root': 'sha256:' + merkle_tree_root([leaf_hash(rfc8785.dumps(entry)) for entry in entries]).hex(),
                  'entry_count': len(entries)}
        blocks.append({'name': name, 'prefix': prefix,
                       'block': dict(sign_envelope_with(priv, 'header', header, 'test-log-k1'), entries=entries),
                       'pinned_head': decl_hash(header), 'expected': expected,
                       'expected_domains': sorted(domains) if domains is not None else None})

    for case in cases:
        add_block(case['name'], 'empty', [case['envelope']],
                  'accepted' if case['expected'] == 'initial' else 'WIST1-E14',
                  [case['envelope']['publisher']['domain']] if case['expected'] == 'initial' else None)
    initial = sign_envelope('publisher', publisher, 'test-k1')
    other = sign_envelope('publisher', variant(domain='other.example'), 'test-k1')
    for spelling in ('EXAMPLE.com', 'example.com.'):
        alias = sign_envelope('publisher', variant(domain=spelling), 'test-k1')
        add_block('canonical and alternate ' + spelling, 'empty', [initial, alias, other], 'WIST1-E14')
    upper_idn = sign_envelope('publisher', variant(domain='bücher.example'), 'test-k1')
    canonical_idn = sign_envelope('publisher', variant(domain='xn--bcher-kva.example'), 'test-k1')
    add_block('U label and A label identity', 'empty', [upper_idn, canonical_idn], 'WIST1-E14')
    add_block('canonical duplicate identity', 'empty', [canonical_idn, canonical_idn], 'accepted', ['xn--bcher-kva.example'])
    sibling = sign_envelope('publisher', variant(domain='xn--bcher-kva.example', contact='other'), 'test-k1')
    add_block('canonical identity conflicts', 'empty', [canonical_idn, sibling], 'WIST1-E08')
    add_block('distinct canonical identities', 'empty', [initial, canonical_idn, other], 'accepted',
              ['example.com', 'xn--bcher-kva.example', 'other.example'])
    for prefix in ('initial', 'open', 'deadline'):
        history = conflicts['prefixes'][prefix]
        current = initial if prefix == 'initial' else next(
            entry['body'] for block in history for entry in block['entries']
            if entry['body']['publisher']['seq'] == (1 if prefix == 'deadline' else 2))
        malformed = dict(current['publisher'], subdomain_scope=['EXAMPLE.com'])
        bad = sign_envelope('publisher', malformed, 'test-k1')
        add_block(prefix + ' field before conflict and settlement', prefix, [current, bad, other], 'WIST1-E14')
        add_block(prefix + ' canonical acceptance twin', prefix, [current, other], 'accepted',
                  ['example.com', 'other.example'])
    write_json(WIST1 / 'declaration-hosts.json', {
        'note': 'WIST-1 sections 2 and 5.1 signed Canonical Host representation. Host cases distinguish '
                'canonicalization from signed spelling eligibility. Every Declaration case has a valid '
                'author signature but only expected initial cases have valid host fields. Each candidate '
                'Block appends to its named authenticated prefix. Rejection preserves all state and the '
                'accepted head, including due recovery settlement. These fixtures do not establish full '
                'Unicode mapping coverage, RFC 3339 eligibility, discovery, live service validation or '
                'Snapshot recovery. Single label host acceptance asserts no suffix policy.',
        'author_key': b64u(pub_raw), 'log_key': conflicts['log_key'], 'recovery_window_days': 7,
        'hosts': host_cases, 'cases': cases, 'prefixes': conflicts['prefixes'], 'block_cases': blocks})


declaration_host_vectors()

# ------------------------------ WIST-1 §5.2: the Key Set at a sealing height
# The ordinary resolution rule over key_ids alone: a Delta sealed at height N
# verifies under the highest-seq Declaration sealed at a height <= N, the
# Block's own Declarations included (WIST-3 §3.3 applies them first). The
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
        "the rotation's Block and nowhere at or above it — the Block's own "
        "Declaration applies first (WIST-3 §3.3) — while the new key "
        "verifies from that Block onward."),
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
    "note": ("WIST-1 §5.2 historical verification, ordinary case, over key_ids "
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
# Over key_ids alone: a Page verifies under the Key Set current at its
# generated_at — the Declaration with the greatest sealed_at not later than
# it — or, where that Key Set lacks the signer, under the first Declaration
# sealed after generated_at. Declarations here are all applicable (the
# recovery exception is exercised by wist1/recovery-settlement.json).
def page_keyset_current(declarations, generated_at_s):
    at_or_before = [d for d in declarations if d["sealed_at_s"] <= generated_at_s]
    return max(at_or_before, key=lambda d: (d["sealed_at_s"], d["seq"]))["keys"] \
        if at_or_before else []


def page_keyset_next(declarations, generated_at_s):
    """§3.2: the Key Set of the first Block after generated_at sealing a
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
        "two rotations sealed in one block",
        [{"label": "genesis", "seq": 0, "sealed_at_s": 100, "keys": ["k1"]},
         {"label": "rotation", "seq": 1, "sealed_at_s": 200, "keys": ["k2"]},
         {"label": "second rotation", "seq": 2, "sealed_at_s": 200, "keys": ["k3"]}],
        [{"page": 0, "generated_at_s": 150, "signer": "k3"},
         {"page": 1, "generated_at_s": 150, "signer": "k2"},
         {"page": 2, "generated_at_s": 200, "signer": "k3"},
         {"page": 3, "generated_at_s": 200, "signer": "k2"}],
        "§3.2: one Block seals seq 1 and seq 2, so both resolutions read the "
        "Block's Key Set — the highest seq's, as WIST-1 §5.2 resolves it at "
        "that height. k3 verifies under next for a Page cut before the Block "
        "and under current for one cut at its instant; k2 was the Key Set at "
        "no instant and verifies under neither."),
]

write_json(WIST2V / "page-keyset.json", {
    "note": ("WIST-2 §3.2 Key Set resolution for a sealed Page, over key_ids "
             "alone: `declarations` carry seq, sealing instant and keys, every "
             "one applicable; each Page carries generated_at and signer. Each "
             "`expected` row gives the Key Set current at generated_at, that "
             "of the first Block after it sealing a Declaration (the highest "
             "seq's where it seals several), and which of the two the Page "
             "verifies under (`current`, `next`, or null for WIST2-E04)."),
    "cases": page_cases,
})
print("wist2 page-keyset vector written")

def page_binding_vectors():
    def binding(identifier, key, excluded=False):
        return dict(key_id=identifier, alg="Ed25519",
                    public_key=b64u(bytes(32) if excluded else raw_public(key)),
                    valid_from="2099-01-01T00:00:00Z")

    histories = {}
    for name, bindings in {
        "renamed": [binding("old", priv2), binding("new", priv2), binding("later", priv3)],
        "reused": [binding("shared", priv2), binding("shared", priv3), binding("shared", priv4)],
        "excluded": [binding("shared", priv2, True), binding("shared", priv3), binding("shared", priv4)],
    }.items():
        sources = []
        previous = None
        for seq, key in enumerate(bindings):
            body = dict(wist_version="1.0.0", domain="example.com", seq=seq,
                        keys=[binding("anchor", priv), key])
            if previous:
                body["prev_declaration"] = decl_hash(previous["publisher"])
            envelope = sign_envelope_with(priv, "publisher", body, "anchor")
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

    probe("renamed public key uses first next named entry", "renamed", "new", priv2, "next")
    probe("old alias still verifies current", "renamed", "old", priv2, "current")
    probe("absent alias cannot borrow identical public bytes", "renamed", "absent", priv2, "WIST2-E04")
    probe("alias from a later Block cannot supply authority", "renamed", "later", priv3, "WIST2-E04")
    probe("renamed identifier is current at exact seal", "renamed", "new", priv2, "current", "2026-08-09T13:00:00Z")
    probe("retired alias cannot borrow current public bytes", "renamed", "old", priv2, "WIST2-E04", "2026-08-09T13:00:00Z")
    probe("renamed identifier before first contact is too late", "renamed", "new", priv2, "WIST2-E04", "2026-08-09T11:00:00Z")
    probe("first contact resolves original named entry", "renamed", "old", priv2, "next", "2026-08-09T11:00:00Z")
    probe("invalid signature under permitted aliases rejects", "renamed", "new", priv4, "WIST2-E04")
    probe("reused identifier verifies current bytes", "reused", "shared", priv2, "current")
    probe("reused identifier verifies first next bytes", "reused", "shared", priv3, "next")
    probe("reused identifier cannot borrow later bytes", "reused", "shared", priv4, "WIST2-E04")
    probe("excluded current entry permits first next", "excluded", "shared", priv3, "next")
    probe("excluded current entry cannot borrow later bytes", "excluded", "shared", priv4, "WIST2-E04")
    probe("current succeeds without a following Declaration", "renamed", "later", priv3, "current", "2026-08-09T15:00:00Z")
    probe("retired bytes fail without a following Declaration", "renamed", "new", priv2, "WIST2-E04", "2026-08-09T15:00:00Z")
    return dict(note="WIST-2 §3.2 named-entry verification over signed ordinary Declaration chains. "
                "Sealing positions are supplied inputs, without Block inclusion or recovery proofs. "
                "Empty Delta lists isolate signature/source selection; these are not publication or "
                "Page-size fixtures. Future valid_from values distinguish Pages from Delta filtering.",
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

# ---------------------------------------------------------------- WIST-3: block
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
    return sign_envelope("delta", inner, "test-k1")

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
# Two records, so that the ordering rule is exercised. The second domain's Delta is not an Entry of the example Block:
# this vector demonstrates §7's record encoding, not a materialization of
# Block 0.
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
             "WIST-1 §7 check at its Block and is ignored like a fork; the Block "
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
# The protocol state at log_position, one tuple per live item, kinds and
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
    ["aggregator_key", "test-agg-k1", b64u(pub_raw), 0, None],
    ["record", "example.com", DELTA_URL, delta_id],
    ["record", "example.com", DELETED_URL, retired_delete_id],
    ["record", "reduced.example.org", REDUCED_URL, reduced_delta_id],
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
label_envelope = sign_envelope("label", label, "test-k1")
write_json(EXAMPLES / "label.json", label_envelope)
definition = {
    "wist_version": "1.0.0",
    "labeler": "example.com",
    "name": "wist:spam",
    "description": "https://example.com/labels/spam",
    "treatment": "hide",
    "asserted_at": "2026-08-02T12:00:00Z",
}
write_json(EXAMPLES / "label-definition.json", sign_envelope("definition", definition, "test-k1"))

LABELER_HOST = "labels.sample.net"
labeler_declaration = sign_envelope_with(priv4, "publisher", {
    "wist_version": "1.0.0", "seq": 0, "domain": LABELER_HOST,
    "keys": [{"key_id": "l-k1", "alg": "Ed25519", "public_key": b64u(pub4_raw),
              "valid_from": "2026-08-01T00:00:00Z"}]}, "l-k1")
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
write_json(EXAMPLES / "dispute.json", sign_envelope("dispute", dispute, "test-k1"))

label_feed = {
    "wist_version": "1.0.0",
    "domain": "example.com",
    "generated_at": "2026-08-02T12:30:00Z",
    "deltas": [label_id],
    "next": None,
}
write_json(EXAMPLES / "label-feed.json", sign_envelope("feed", label_feed, "test-k1"))
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

    def add(name, body=None, *, expected="accepted", signer=priv, key_id="test-k1", mutate=None):
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
    add("signed by the recovery key", signer=priv2, key_id="test-r1", expected="binding")
    add("signed under an unknown key_id", key_id="test-k9", expected="binding")

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
                inner["asserted_at"], inner.get("expires_at"), inner.get("delta"), chosen["height"]]

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
        current_case("equal instants break by Block height",
                     [sealed("2026-08-02T12:30:00Z", 1, 0, 500000), sealed("2026-08-02T12:30:00Z", 2, 0, 700000)], 1),
        current_case("equal instants in one Block break by Entry index",
                     [sealed("2026-08-02T12:30:00Z", 3, 4, 500000), sealed("2026-08-02T12:30:00Z", 3, 2, 700000)], 0),
        current_case("a later retraction leaves no tuple",
                     [sealed("2026-08-02T12:30:00Z", 1, 0), sealed("2026-08-03T09:00:00Z", 2, 0, retracted=True)], 1),
        current_case("a retraction older than the assertion applies nothing",
                     [sealed("2026-08-03T09:00:00Z", 1, 0), sealed("2026-08-02T12:30:00Z", 2, 0, retracted=True)], 0),
        current_case("an offset instant compares as an instant",
                     [sealed("2026-08-02T12:30:00Z", 1, 0), sealed("2026-08-02T14:30:01+02:00", 2, 0)], 1),
        current_case("an unexpired Label keeps its tuple",
                     [sealed("2026-08-02T12:30:00Z", 1, 0, expires_at="2026-08-03T12:00:01Z")], 0),
        current_case("a Label expired at the Snapshot's Block leaves no tuple",
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
              "retracted or expired at sealed_at, the Snapshot Block's instant. binding_cases read a "
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
        "keys": [{"key_id": "r-k1", "alg": "Ed25519", "public_key": b64u(pub3_raw),
                  "valid_from": "2026-08-01T00:00:00Z"}]}, "r-k1")
    sealed_labels = [{"label_id": label_id, "labeler": "example.com", "subject": LABEL_SUBJECT, "height": 1}]
    base = {"wist_version": "1.0.0", "disputant": "reduced.example.org", "label": label_id,
            "log": "log.example", "height": 1, "asserted_at": "2026-08-02T13:00:00Z"}
    cases = []

    def add(name, body=None, *, expected="accepted", signer=priv3, key_id="r-k1",
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
    add("dispute by a third party", dict(base, disputant=LABELER_HOST), signer=priv4, key_id="l-k1",
        declaration=labeler_declaration, expected="authority")
    add("disputant other than the authenticated domain", dict(base, disputant="example.com"), expected="fields")
    add("signature over other bytes", expected="signature",
        mutate=lambda doc: doc["dispute"].update(asserted_at="2026-08-02T13:00:01Z"))
    add("signed under an unknown key_id", key_id="r-k9", expected="binding")

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

    def add(name, body=None, *, expected="accepted", signer=priv, key_id="test-k1", mutate=None):
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
    add("signed under an unknown key_id", key_id="test-k9", expected="rejected")
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
        return {"label": label, "labeler_block_entries_max": labeler_cap, "domain_block_entries_max": domain_cap,
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
                    if ev["height"] <= h and (current is None or ev["asserted_at"] > current["asserted_at"]):
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
        persistence_case("counted from the second consecutive Block", [ev(5, "2026-08-02T12:00:00Z")], [4, 5, 6, 7]),
        persistence_case("a retraction stops the count",
                         [ev(5, "2026-08-02T12:00:00Z"), ev(7, "2026-08-02T13:00:00Z", True)], [5, 6, 7, 8]),
        persistence_case("re-asserted after a retraction",
                         [ev(5, "2026-08-02T12:00:00Z"), ev(6, "2026-08-02T13:00:00Z", True),
                          ev(8, "2026-08-02T15:00:00Z")], [7, 8, 9, 10]),
        persistence_case("expiry ends the count", [ev(5, "2026-08-02T12:00:00Z")], [6, 7, 8], expires_at=8),
    ]
    inactivity_cases = [{"label": label, "last_sealed_height": last, "inactivity_blocks": n, "height": h,
                         "applies": h - last <= n}
                        for label, last, n, h in (("within the window", 100, 720, 820),
                                                  ("one Block past the window", 100, 720, 821),
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
                 "first height whose Block instant reaches the expiry), and a Labeler with no sealed Entry "
                 "within inactivity_blocks is ignored (inactivity_cases)."),
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
                                     ic[1]["block_number"], ic[1]["entry_index"]))
    return c["value"], i


def param_change(block_number, entry_index, effective_at_s, value):
    return {"block_number": block_number, "entry_index": entry_index,
            "sealed_at_s": block_number * HOUR_S, "effective_at_s": effective_at_s,
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
    param_case("equal-effective-at-across-blocks", 3600,
               [param_change(10, 0, 20 * DAY_S, 900),
                param_change(12, 0, 20 * DAY_S, 1800)],
               [20 * DAY_S - 1, 20 * DAY_S]),
    param_case("equal-effective-at-in-one-block", 3600,
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
                        "labeler_block_entries_max": 1000, "domain_block_entries_max": 10000}
PROSPECTIVE_FLOORS = {"links_cap_bytes": 21, "link_url_cap_bytes": 14,
                      "mirror_retention_days": 30, "payload_window_days": 30,
                      "labeler_block_entries_max": 1, "domain_block_entries_max": 1}


def combinations_hold(values):
    return (values["links_cap_bytes"] >= values["link_url_cap_bytes"] + 21
            and values["mirror_retention_days"] * 6 >= values["payload_window_days"]
            and values["labeler_block_entries_max"] <= values["domain_block_entries_max"])


def prospective_map(changes, at_s):
    result = dict(PROSPECTIVE_DEFAULTS)
    for parameter in result:
        eligible = [c for c in changes if c["parameter"] == parameter and c["effective_at_s"] <= at_s]
        if eligible:
            chosen = max(eligible, key=lambda c: (c["effective_at_s"], c["block_height"], c["entry_index"]))
            result[parameter] = chosen["value"]
    return result


def prospective_acceptance(changes):
    accepted, rejected = [], []
    for i, candidate in sorted(enumerate(changes), key=lambda pair: (pair[1]["block_height"], pair[1]["entry_index"])):
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
    ("canonical same Block order", [(0, 1, "link_url_cap_bytes", 4000, 10), (0, 0, "links_cap_bytes", 3000, 10)], [0]),
    ("invalid bound cannot hide behind replacement", [(0, 0, "links_cap_bytes", 20, 10), (1, 0, "links_cap_bytes", 4096, 10)], [0]),
    ("grace period required", [(0, 0, "links_cap_bytes", 4000, 6)], [0]),
    ("aggregate cap exactly the link cap plus its structure", [(0, 0, "links_cap_bytes", 2069, 10)], []),
    ("retention below a sixth of the window", [(0, 0, "payload_window_days", 541, 10)], [0]),
    ("retention exactly a sixth of the window", [(0, 0, "payload_window_days", 540, 10)], []),
    ("window raised after retention raised", [(0, 0, "mirror_retention_days", 120, 10), (1, 0, "payload_window_days", 720, 11)], []),
    ("retention lowered under a pending window", [(0, 0, "payload_window_days", 540, 10), (1, 0, "mirror_retention_days", 60, 10)], [1]),
    ("labeler cap above the domain cap", [(0, 0, "labeler_block_entries_max", 20000, 10)], [0]),
    ("labeler cap equal to the domain cap", [(0, 0, "labeler_block_entries_max", 10000, 10)], []),
    ("domain cap lowered under the labeler cap", [(0, 0, "domain_block_entries_max", 500, 10)], [0]),
    ("both caps lowered in order", [(0, 0, "labeler_block_entries_max", 200, 10), (1, 0, "domain_block_entries_max", 500, 11)], []),
    ("domain cap lowered under a pending labeler cap", [(0, 0, "labeler_block_entries_max", 200, 12), (1, 0, "domain_block_entries_max", 150, 11)], [1]),
):
    changes = [{"block_height": day * 24, "entry_index": index, "sealed_at_s": day * DAY_S,
                "parameter": parameter, "value": value, "effective_at_s": effective * DAY_S}
               for day, index, parameter, value, effective in rows]
    got, accepted = prospective_acceptance(changes)
    assert got == rejected, label
    instants = sorted({c["effective_at_s"] for c in changes})
    prospective_cases.append({"label": label, "changes": changes, "rejected_indices": got,
        "maps": [{"at_s": t, "values": prospective_map(accepted, t)} for t in instants]})

CLOCK_DEFAULTS = {"record_seal_blocks": 24, "recovery_window_days": 7,
                  "payload_window_days": 180, "param_grace_days": 7}


def clock_value(parameter, at_s, changes):
    eligible = [c for c in changes if c["parameter"] == parameter and c["effective_at_s"] <= at_s]
    return max(eligible, key=lambda c: c["effective_at_s"])["value"] if eligible else CLOCK_DEFAULTS[parameter]


clock_cases = []
for label, parameter, anchor, changed, value, factor, start in (
    ("discovery retains seal count", "record_seal_blocks", 10, 11, 48, 1, 200),
    ("recovery window retains length", "recovery_window_days", 10, 11, 14, 86400, 10),
    ("availability retains span", "payload_window_days", 10, 11, 360, 86400, 10),
    ("grace retains span", "param_grace_days", 10, 11, 14, 86400, 10),
    ("effective at anchor is included", "record_seal_blocks", 11, 11, 48, 1, 200),
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
    ("labeler_block_entries_max", 0, False, True),
    ("labeler_block_entries_max", 20000, True, False),
    ("block_cadence_seconds", 86400, True, True),
    ("block_decompressed_cap_bytes", "4096", False, True),
    ("block_decompressed_cap_bytes", 4096.0, True, True),
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

BLOCK_CAP_DEFAULT = 256 * 1024 * 1024


def block_cap_at(changes, at_s):
    eligible = [c for c in changes if c["effective_at_s"] <= at_s]
    return max(eligible, key=lambda c: (c["effective_at_s"], c["block_height"], c["entry_index"]))["value"] if eligible else BLOCK_CAP_DEFAULT


def block_cap_bounds(changes, at_s):
    values = [block_cap_at(changes, t) for t in {at_s} | {c["effective_at_s"] for c in changes if c["effective_at_s"] >= at_s}]
    return min(values), max(values)


def block_cap_trace(blocks):
    accepted, largest, probes = [], 0, []
    for height, block in enumerate(blocks):
        tentative_max = max(largest, block["jcs_bytes"])
        working = list(accepted)
        rejected = []
        for index, amendment in enumerate(block["amendments"]):
            change = dict(amendment, block_height=height, entry_index=index)
            trial = working + [change]
            if not isinstance(change["value"], int) or change["value"] < 1024 or change["effective_at_s"] < block["sealed_at_s"] + 7 * DAY_S or block_cap_bounds(trial, block["sealed_at_s"])[0] < tentative_max:
                rejected.append(index)
            else:
                working = trial
        cap, _ = block_cap_bounds(working, block["sealed_at_s"])
        valid = tentative_max <= cap
        probes.append({"rejected_indices": rejected, "sealing_cap": cap, "block_valid": valid,
            "largest_bytes": tentative_max if valid else largest,
            "transport_bound_before": BLOCK_CAP_DEFAULT if not probes else block_cap_bounds(accepted, blocks[height-1]["sealed_at_s"])[1]})
        if not valid:
            assert height == len(blocks)-1
            break
        accepted, largest = working, tentative_max
    return probes


block_size_cases = []
for label, rows, rejected, valid in (
    ("reduction below a historical Block", [(0,8192,[]), (1,2048,[(4096,8)])], [[],[0]], [True,True]),
    ("reduction includes its complete current Block", [(0,8192,[(4096,7)])], [[0]], [True]),
    ("reduction equals the current Block size", [(0,4096,[(4096,7)]), (7,4096,[])], [[],[]], [True,True]),
    ("pending reduction constrains an intervening Block", [(0,2048,[(4096,7)]), (1,4097,[])], [[],[]], [True,False]),
    ("pending reduction equality before effectiveness", [(0,2048,[(4096,7)]), (1,4096,[])], [[],[]], [True,True]),
    ("increase is unavailable one second before effectiveness", [(0,2048,[(4096,7),(8192,8)]), (8,4097,[])], [[],[]], [True,False]),
    ("increase is available exactly at effectiveness", [(0,2048,[(4096,7),(8192,8)]), (8,8192,[])], [[],[]], [True,True]),
    ("rejected candidate is not rescued by later replacement", [(0,5000,[(4096,7),(8192,7)])], [[0]], [True]),
    ("same-time replacement relaxes a pending reduction", [(0,2048,[(4096,7),(8192,7)]), (1,8192,[])], [[],[]], [True,True]),
    ("out-of-range candidate leaves the schedule unchanged", [(0,2048,[(1023,7),(8192,7)])], [[0]], [True]),
    ("restart retains a pending reduction and maximum", [(0,4096,[(4096,7)]), (1,2048,[]), (2,2048,[(3072,9)])], [[],[],[0]], [True,True,True]),
    ("later maximum never revalidates old acceptance", [(0,2048,[(4096,7)]), (1,2048,[(8192,7+1)]), (9,8192,[])], [[],[],[]], [True,True,True]),
    ("verified pending increase permits transport above default", [(0,2048,[(2*BLOCK_CAP_DEFAULT,7)]), (7,BLOCK_CAP_DEFAULT+1,[])], [[],[]], [True,True]),
    ("a fetched Block cannot raise its own bound", [(0,BLOCK_CAP_DEFAULT+1,[(2*BLOCK_CAP_DEFAULT,7)])], [[0]], [False]),
    ("schema-invalid candidate is ignored and its Block stays valid", [(0,2048,[("4096",7),(8192,7)]), (7,8192,[])], [[0],[]], [True,True]),
):
    blocks = [{"sealed_at_s":round(day*DAY_S), "jcs_bytes":size,
        "amendments":[{"value":value,"effective_at_s":effective*DAY_S} for value,effective in amendments]}
        for day,size,amendments in rows]
    if label == "increase is unavailable one second before effectiveness":
        blocks[-1]["sealed_at_s"] -= 1
    probes = block_cap_trace(blocks)
    assert [p["rejected_indices"] for p in probes] == rejected, label
    assert [p["block_valid"] for p in probes] == valid, label
    block_size_cases.append({"label":label,"blocks":blocks,"expected":probes,
        "restart_after":list(range(len(blocks)-1))})

block_transport_cases = []
for label, prefix_s, changes, declared, chunks, stage in (
    ("genesis rejects above default before decompression", None, [], BLOCK_CAP_DEFAULT+1, [], "frame"),
    ("missing declared size is rejected", None, [], None, [], "frame"),
    ("exact transport bound is allowed", 7*DAY_S, [(4096,7)], 4096, [2048,2048], "decoded"),
    ("declared excess is rejected before decompression", 7*DAY_S, [(4096,7)], 4097, [], "frame"),
    ("false small declaration cannot overrun the bound", 7*DAY_S, [(4096,7)], 4096, [2048,2049], "stream"),
    ("false declaration within the bound still fails", 7*DAY_S, [(4096,7)], 3000, [2048,1024], "length"),
    ("future increase enlarges the transport bound", 0, [(2*BLOCK_CAP_DEFAULT,7)], BLOCK_CAP_DEFAULT+1, [BLOCK_CAP_DEFAULT,1], "decoded"),
    ("superseded increase cannot enlarge transport", 7*DAY_S, [(8192,7),(4096,7)], 4097, [], "frame"),
    ("expired larger cap cannot enlarge transport", 8*DAY_S, [(8192,7),(4096,8)], 4097, [], "frame"),
    ("future smaller cap does not lower transport early", 0, [(4096,7)], 8192, [8192], "decoded"),
):
    amendments = [{"value":value,"effective_at_s":day*DAY_S,"block_height":0,"entry_index":i} for i,(value,day) in enumerate(changes)]
    bound = BLOCK_CAP_DEFAULT if prefix_s is None else block_cap_bounds(amendments,prefix_s)[1]
    block_transport_cases.append({"label":label,"prefix_sealed_at_s":prefix_s,"accepted_caps":amendments,
        "declared_bytes":declared,"decoded_chunk_bytes":chunks,"transport_bound":bound,
        "result":stage,"error":None if stage=="decoded" else "WIST3-E03"})

for values, declared, result in (([], BLOCK_CAP_DEFAULT+1, "frame"), ([2*BLOCK_CAP_DEFAULT], BLOCK_CAP_DEFAULT+1, "decoded"), ([4096], 8192, "decoded")):
    block_transport_cases.append({"label":"Snapshot bootstrap caps " + str(values),
        "snapshot_bootstrap":True,"prefix_sealed_at_s":None,
        "accepted_caps":[{"value":value} for value in values],
        "declared_bytes":declared,"decoded_chunk_bytes":[declared] if result=="decoded" else [],
        "transport_bound":max([BLOCK_CAP_DEFAULT]+values),"result":result,
        "error":None if result=="decoded" else "WIST3-E03"})

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
                     "block_height": i, "entry_index": 0,
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
    "note": "WIST-4 §5 combination rules. prospective_cases: candidates processed in Log order against every prospective map, the rejected indices and the resulting maps at each effective instant. block_size_cases and block_transport_cases: the Block-size guarantee over the sealed prefix and the transport bound it fixes. recovery_window_cases: the Log timestamp range over recovery_window_days. wire_cases: the wire integer domain and the details contract. clock_cases: a parameter read for work already begun stays attached to its anchor.",
    "prospective_defaults": PROSPECTIVE_DEFAULTS,
    "prospective_floors": PROSPECTIVE_FLOORS,
    "prospective_cases": prospective_cases,
    "block_cap_default": BLOCK_CAP_DEFAULT,
    "block_size_cases": block_size_cases,
    "block_transport_cases": block_transport_cases,
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
    sealed = [{"delta_id": d1, "publisher": "site.sample.net", "height": 1},
              {"delta_id": d2, "publisher": "other.sample.org", "height": 4}]

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
        act("signed by a key the Log does not hold", "WIST4-E11", signer=priv2, key_id="test-r1"),
        act("unsupported major", "WIST4-E11", version="2.0.0"),
        act("unknown member", "WIST4-E11", extra={"note": "x"}),
        act("delta id not a Delta ID", "WIST4-E04",
            details={"delta_id": "sha256:xyz", "legal_basis": "b", "jurisdiction": "BR"}),
        act("missing legal basis", "WIST4-E04", details={"delta_id": d1, "jurisdiction": "BR"}),
        act("subject not a host", "WIST4-E04", subject="not a host!"),
        act("subject is another Publisher", "WIST4-E04", subject="other.sample.org"),
        act("Delta sealed above the act", "WIST4-E04", delta_id=d2, subject="other.sample.org", height=2),
        act("Delta sealed in the act's Block", None, delta_id=d2, subject="other.sample.org", height=4,
            withdrawn_height=4),
        act("repeated withdrawal keeps the first height", None, height=6,
            details={"delta_id": d1, "legal_basis": "second order", "jurisdiction": "BR"},
            withdrawn_height=3),
    ]

    state_tuples = [["withdrawal", d1, "site.sample.net", 3], ["withdrawal", d2, "other.sample.org", 4]]
    return spaced_labels({
        "note": ("WIST-4 §5.1: a payload_withdrawal is authenticated under the Log key (WIST4-E11 otherwise) and "
                 "must name a Delta sealed at or below its Block whose signed publisher is the subject "
                 "(WIST4-E04 otherwise); the earliest accepted withdrawal's Block governs and a later withdrawal "
                 "of the same Delta changes nothing. Acts replay in order; state_tuples are the WIST-3 §7 "
                 "withdrawal tuples the replay leaves."),
        "log_key": {"key_id": "test-agg-k1", "public_key": b64u(pub_raw)}, "sealed_deltas": sealed,
        "act_cases": acts, "state_tuples": state_tuples})


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
            signer=priv2, key_id="test-r1", in_force_after="first"),
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
        return {"label": label, "height": height, "domain_block_entries_max": cap, "entries": entries,
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
        for host, is_noise in pings:
            unit = registrable_domain(host, rules[force_at[height]])[0]
            if noise.get(unit, 0) >= base:
                rows.append({"host": host, "noise": is_noise, "expected": 429})
                continue
            if is_noise:
                noise[unit] = noise.get(unit, 0) + 1
            rows.append({"host": host, "noise": is_noise, "expected": 202})
        return {"label": label, "height": height, "quota_base": base, "pings": rows}

    pings = [("a.example.com", True), ("b.example.com", True), ("c.example.com", False), ("alice.github.io", True),
             ("alice.github.io", True), ("alice.github.io", False), ("bob.github.io", True),
             ("a.hosts.sample.net", True), ("b.hosts.sample.net", True), ("c.hosts.sample.net", True)]
    quota_cases = [quota("one UTC day under the first snapshot", 2, pings),
                   quota("the same Pings under the second snapshot", 4, pings),
                   quota("the same Pings with no snapshot in force", 0, pings)]

    state_tuples = [{"log_position": 0, "entries": [["suffix_list", ids["first"], 0]]},
                    {"log_position": 2, "entries": [["suffix_list", ids["first"], 0]]},
                    {"log_position": 3, "entries": [["suffix_list", ids["second"], 3]]},
                    {"log_position": 6, "entries": [["suffix_list", ids["second"], 3]]}]
    return spaced_labels({
        "note": ("WIST-4 §3.1, WIST-2 §4, WIST-3 §3.2 and §7. lists are Public Suffix List snapshots as octets "
                 "(text is the exact UTF-8 file). official_cases transcribe the Public Suffix List project's "
                 "checkPublicSuffix cases over the first snapshot: host is the input's Canonical Host (null where "
                 "it has none), expected the project's answer and registrable the Registrable Domain, the host "
                 "itself where the list leaves none. domain_cases read a host under a named snapshot or under "
                 "none. act_cases replay in Block order under the Log key: a suffix_list_update is in force from "
                 "the Block after its sealing Block (in_force lists the snapshot in force at each height). "
                 "capacity_cases count publisher_delta and label Entries per Registrable Domain under the "
                 "snapshot in force at the Block; quota_cases apply quota_base to the noise Pings of one UTC day "
                 "per Registrable Domain in order; state_tuples are the WIST-3 §7 suffix_list tuple at a "
                 "log_position."),
        "log_key": {"key_id": "test-agg-k1", "public_key": b64u(pub_raw)},
        "lists": lists, "official_cases": official_suffix_cases(rules["first"]), "domain_cases": domain_cases,
        "act_cases": acts, "in_force": in_force, "capacity_cases": capacity_cases, "quota_cases": quota_cases,
        "state_tuples": state_tuples})


write_json(WIST4 / "registrable-domain.json", registrable_domain_vectors())


# ------------------------------------------------ WIST-3 §6: Block frames
def raw_frame(payload, declared=None, single=True, width=4, chunks=None):
    size = len(payload) if declared is None else declared
    flag = {0: 0, 1: 0, 2: 1, 4: 2, 8: 3}[width]
    header = bytes.fromhex("28b52ffd") + bytes([flag * 64 + (32 if single else 0)])
    if not single:
        header += b"\x10"
    if width:
        header += (size - (256 if width == 2 else 0)).to_bytes(width, "little")
    pieces = [payload] if chunks is None else chunks
    return header + b"".join(
        (len(piece) * 8 + int(index == len(pieces) - 1)).to_bytes(3, "little") + piece
        for index, piece in enumerate(pieces))


transport_block = json.loads((EXAMPLES / "block.json").read_text())
transport_bytes = rfc8785.dumps(transport_block)
transport_size = len(transport_bytes)
transport_frame = raw_frame(transport_bytes)
transport_parts = {
    "block": transport_frame,
    "short size": raw_frame(transport_bytes, width=2),
    "wide size": raw_frame(transport_bytes, width=8),
    "window header": raw_frame(transport_bytes, single=False),
    "undersized window": raw_frame(transport_bytes, single=False)[:5] + b"\x00" + raw_frame(transport_bytes, single=False)[6:],
    "multiple raw blocks": raw_frame(transport_bytes, chunks=[transport_bytes[:200], transport_bytes[200:]]),
    "empty": raw_frame(b"", width=1),
    "nonempty": raw_frame(b"x", width=1),
    "skippable empty": bytes.fromhex("502a4d18") + bytes(4),
    "skippable payload": bytes.fromhex("5f2a4d18") + (4).to_bytes(4, "little") + b"meta",
    "trailing byte": b"\x00",
    "truncated": transport_frame[:-1],
    "truncated header": transport_frame[:6],
    "missing size": raw_frame(transport_bytes, single=False, width=0),
    "false smaller size": raw_frame(transport_bytes, declared=transport_size - 1),
    "false larger size": raw_frame(transport_bytes, declared=transport_size + 1),
}
transport_cases = []
for name in ("block", "short size", "wide size", "window header", "multiple raw blocks"):
    transport_cases.append({"label": "single frame " + name, "parts": [name],
                            "bound": transport_size, "expected": "valid"})
for tail in ("empty", "nonempty", "skippable empty", "skippable payload", "trailing byte"):
    transport_cases.append({"label": "reject trailing " + tail, "parts": ["block", tail],
                            "bound": transport_size + 1, "expected": "WIST3-E03"})
for parts in (["skippable empty", "block"], ["skippable payload", "block"],
              ["empty", "block"], ["block", "block"], ["skippable empty"],
              ["truncated"], ["truncated header"], ["missing size"],
              ["false smaller size"], ["false larger size"], ["undersized window"]):
    transport_cases.append({"label": "reject " + " then ".join(parts), "parts": parts,
                            "bound": transport_size + 1, "expected": "WIST3-E03"})
transport_cases.append({"label": "declared size exceeds bound by one", "parts": ["block"],
                        "bound": transport_size - 1, "expected": "WIST3-E03"})
write_json(ROOT / "vectors/wist3/block-frames.json", {
    "note": "WIST-3 §6. Each case concatenates the exact byte fragments named by parts in order. Valid cases decode to JCS(block). Raw Zstandard data blocks isolate frame composition from entropy coding. Bounds exercise transport decoding, not Registry amendment admission.",
    "block": transport_block,
    "fragments_hex": {name: part.hex() for name, part in transport_parts.items()},
    "cases": transport_cases,
})

def epoch_seconds(ts: str) -> int:
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
    assert epoch_seconds(value) == seconds
    timestamp_cases.append({"value": value, "epoch_seconds": seconds})
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
        epoch_seconds(value)
    except ValueError:
        pass
    else:
        raise AssertionError(value)
    timestamp_cases.append({"value": value, "epoch_seconds": None})

timestamp_fields = []
for stem, path in (
    ("block", ["header", "sealed_at"]),
    ("checkpoint", ["checkpoint", "sealed_at"]),
    ("feed", ["feed", "generated_at"]),
    ("registry-update", ["update", "effective_at"]),
):
    timestamp_fields.append({"schema": stem + ".schema.json", "document": json.loads((EXAMPLES / (stem + ".json")).read_text()), "path": path})
timestamp_probe = "2017-01-01T00:00:00Z"
for entry, path in (
    (["parameter", "record_seal_blocks", timestamp_probe, 2], [2]),
    (["recovery_window", "example.com", 1, timestamp_probe, {}, 1], [3]),
    (["label", "labeler.example", "https://example.com/blog/post-1", "wist:spam", None, timestamp_probe, None, None, 1], [5]),
    (["label", "labeler.example", "https://example.com/blog/post-1", "wist:spam", None, "2026-08-02T12:00:00Z", timestamp_probe, None, 1], [6]),
    (["dispute", "sha256:" + "0" * 64, "example.com", None, timestamp_probe, 1], [4]),
):
    document = json.loads((EXAMPLES / "snapshot-state.json").read_text())
    document["state"]["entries"] = [entry]
    timestamp_fields.append({"schema": "snapshot-state.schema.json", "document": document,
                             "path": ["state", "entries", 0] + path})
write_json(ROOT / "vectors/wist3/timestamps.json", {
    "note": "WIST-3 §3.1 whole-second literal-Z profile, including §7 Snapshot state. Null epoch_seconds means reject, including invalid calendar dates. Field cases supply schema-valid structural baselines; mutating a signed value requires re-signing before testing signature verification. The schema-only leap-second check does not depend on format validation.",
    "cases": timestamp_cases,
    "distances": [{"from": "2016-12-31T23:59:59Z", "to": "2017-01-01T00:00:00Z", "seconds": 1}],
    "field_cases": timestamp_fields,
    "field_accept": "2016-12-31T23:59:59Z",
    "field_reject": "2016-12-31T23:59:60Z",
    "field_reject_non_ascii": "２０１６-12-31T23:59:59Z",
})


def delta_diagnostic_vectors():
    publisher = {
        "wist_version": "1.0.0", "domain": "example.com", "seq": 0,
        "keys": [{"key_id": "test-k1", "alg": "Ed25519",
                  "public_key": b64u(pub_raw), "valid_from": "2026-08-01T00:00:00Z"}],
        "subdomain_scope": ["other.example"],
    }
    previous_source = sign_envelope("publisher", publisher, "test-k1")
    cases = []
    for binding, scope, future, chain in itertools.product(
            ("valid", "bad signature", "missing", "future"), (True, False),
            (False, True), (True, False)):
        source = json.loads(json.dumps(publisher))
        source["seq"] = 1
        source["prev_declaration"] = "sha256:" + sha256_hex(rfc8785.dumps(publisher))
        source["subdomain_scope"] = ["other.example"] if scope else []
        if binding == "future":
            source["keys"][0]["valid_from"] = "2026-08-04T11:00:00Z"
        declaration = sign_envelope("publisher", source, "test-k1")
        observed = "2026-08-04T10:10:00.00000000000000000001Z" if future else "2026-08-04T07:10:00-03:00"
        previous = {
            "wist_version": "1.0.0", "publisher": "example.com", "url": "https://other.example/page",
            "change_type": "new", "observed_at": "2026-08-04T09:00:00Z" if chain else observed,
            "payload": delta["payload"], "meta": {"lang": "en"},
        }
        predecessor = sign_envelope("delta", previous, "test-k1")
        candidate = {
            "wist_version": "1.0.0", "publisher": "example.com", "url": previous["url"], "change_type": "attest",
            "observed_at": observed, "prev": "sha256:" + sha256_hex(rfc8785.dumps(previous)),
            "meta": {"lang": "en"},
        }
        envelope = sign_envelope("delta", candidate, "absent" if binding == "missing" else "test-k1")
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
            envelope = sign_envelope("delta", inner, "test-k1")
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
        doc = sign_envelope("delta", inner, "test-k1")
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

    def binding(key, identifier="shared", valid_from="2026-08-01T00:00:00Z"):
        return {"key_id": identifier, "alg": "Ed25519", "public_key": b64u(raw_public(key)),
                "valid_from": valid_from}

    def declaration(domain, key, extra=(), **fields):
        inner = {"wist_version": "1.0.0", "domain": domain, "seq": 0,
                 "keys": [binding(key), *extra]}
        if domain != child:
            inner["subdomain_scope"] = [child]
        inner.update(fields)
        return sign_envelope_with(key, "publisher", inner, "shared")

    def signed(domain, key, **fields):
        inner = dict(delta, publisher=domain, url=url)
        inner.update(fields)
        return sign_envelope_with(key, "delta", inner, "shared")

    shared = [declaration(domain, keys[0]) for domain in (parent, child)]
    distinct = [shared[0], declaration(child, keys[1])]
    copied = [shared[0], declaration(child, keys[1], [binding(keys[0], "copied")])]
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
    alias = signed(parent, keys[0]); alias["sig"]["key_id"] = "copied"
    add("unsigned alias cannot borrow another domain's key", copied, [alias], ["WIST1-E02"])
    add("unknown author cannot borrow a scoped matching key", shared,
        [signed("unknown.example", keys[0])], ["WIST1-E02"])
    add("another domain's matching identifier does not suppress author", distinct,
        [signed(child, keys[1])], ["accepted"])
    add("explicit nonancestor scope", [declaration(external, keys[0])],
        [signed(external, keys[0])], ["accepted"])
    no_scope = declaration(parent, keys[0], subdomain_scope=[])
    add("another author's scope supplies no authority", [no_scope, shared[1]],
        [signed(parent, keys[0])], ["WIST1-E03"])
    future = declaration(parent, keys[0], keys=[binding(keys[0], valid_from="2026-08-03T00:00:00Z")])
    add("another author's earlier key supplies no bound", [future, shared[1]],
        [signed(parent, keys[0])], ["WIST1-E02"])
    excluded = declaration(parent, keys[1], keys=[binding(keys[1], "own"),
        dict(binding(keys[0]), public_key=b64u(b"\x01" + bytes(31)))])
    excluded = sign_envelope_with(keys[1], "publisher", excluded["publisher"], "own")
    add("excluded author binding cannot borrow copied usable key", [excluded, shared[1]],
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
        env = sign_envelope_with(keys[0], "delta", env["delta"], "absent")
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
    first = declaration(parent, keys[0], recovery_keys=[binding(keys[7], "recovery")])
    def replacement(previous, key, signer, signer_id="shared", **fields):
        inner = dict(previous["publisher"], seq=previous["publisher"]["seq"] + 1,
                     prev_declaration=decl_hash(previous["publisher"]), keys=[binding(key)])
        inner.update(fields)
        return sign_envelope_with(signer, "publisher", inner, signer_id)
    ordinary = replacement(first, keys[2], keys[0])
    owner = replacement(ordinary, keys[3], keys[7], "recovery")
    competitor = replacement(owner, keys[4], keys[4])
    follower = replacement(owner, keys[5], keys[3], seq=4)
    reset = replacement(follower, keys[6], keys[6], seq=5)
    declarations_at = {0: [first, declaration(child, keys[0]), declaration(external, keys[2])],
                       1: [ordinary], 2: [owner], 3: [competitor], 4: [follower], 171: [reset]}
    authors_at = {0: keys[0], 1: keys[2], 2: keys[3], 3: keys[3], 4: keys[5],
                  170: keys[5], 171: keys[6], 172: keys[6]}
    blocks, tips, envelopes, probes = [], {}, {}, []
    previous = "sha256:genesis"
    for height in range(173):
        entries = [{"type": "publisher_declaration", "body": env}
                   for env in declarations_at.get(height, [])]
        if height in (0, 1, 170, 171, 172):
            env = signed(parent, authors_at[height], observed_at=timestamp(height))
            if parent in tips:
                env["delta"].pop("payload")
                env["delta"].update(change_type="attest", prev=tips[parent])
                env = sign_envelope_with(authors_at[height], "delta", env["delta"], "shared")
            entries.append({"type": "publisher_delta", "body": env})
            tips[parent] = decl_hash(env["delta"]); envelopes[height] = env
        if height == 0:
            env = signed(child, keys[0], observed_at=timestamp(height))
            entries.append({"type": "publisher_delta", "body": env})
            tips[child] = decl_hash(env["delta"])
        entries.sort(key=lambda e: ((0 if e["type"] == "publisher_declaration" else 2),
                                     leaf_hash(rfc8785.dumps(e))))
        header = {"wist_version": "1.0.0", "block_number": height, "prev_block_hash": previous,
                  "sealed_at": timestamp(height), "entry_count": len(entries),
                  "merkle_root": "sha256:" + (merkle_tree_root([leaf_hash(rfc8785.dumps(e)) for e in entries]) if entries else leaf_hash(b"" )).hex()}
        block = dict(sign_envelope_with(priv, "header", header, "log-key"), entries=entries)
        blocks.append(block); previous = decl_hash(header)
        if height in (0, 1, 3, 4, 170, 171):
            def probe(name, domain, key, expected, stage=None, **fields):
                stage = stage or ("admission" if height in (3, 4) else "sealing")
                env = signed(domain, key, observed_at=timestamp(height + 1), prev=tips[domain])
                env["delta"].pop("payload"); env["delta"]["change_type"] = "attest"
                env["delta"].update(fields)
                env = sign_envelope_with(key, "delta", env["delta"], "shared")
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
                                            (keys[4], "WIST1-E01"), (keys[5], "WIST1-E01")]:
                    probe("frozen recovery sources at " + str(height) + " " + str(len(probes)),
                          parent, candidate, expected, stage="admission")
                probe("foreign recovery source cannot authorize child " + str(height),
                      child, keys[2], "WIST1-E01", stage="admission")
            if height == 170:
                probe("expired recovery union", parent, keys[2], "WIST1-E01", stage="admission")
    versions = []
    for name, version, mutation, expected in [
            ("current draft", "1.0.0", None, "accepted"),
            ("same version old draft lacks author", "1.0.0", "missing", "WIST1-E14"),
            ("unknown fields remain forbidden", "1.0.0", "unknown", "WIST1-E14"),
            ("unimplemented major", "2.0.0", None, "WIST1-E15")]:
        env = signed(parent, keys[0], wist_version=version)
        if mutation == "missing": del env["delta"]["publisher"]
        if mutation == "unknown": env["delta"]["extra"] = True
        env = sign_envelope_with(keys[0], "delta", env["delta"], "shared")
        versions.append(dict(name=name, envelope=env, expected=expected))
    return dict(
        note="WIST-1 sections 3.1, 3.5 and 3.8, WIST-2 section 5 and WIST-3 section 7. "
             "Cases test signed author, key, scope and optional logical Feed association, with current initial "
             "Declarations supplied; accepted means those checks only. No live discovery or transport is exercised. "
             "The authenticated hourly history uses the default seven-day recovery window and supplies an "
             "independently pinned head; its Deltas exercise sealing bindings and chain ownership. Probes run "
             "after the named Block's Declaration stage and accepted Deltas, using that prefix's sources/tips; "
             "their later observed_at is a supplied test timestamp, not an inclusion claim. Clock, Payload, "
             "quotas and Payloads remain separate. Identity projections exercise owner/reset attribution: whether "
             "the Publisher identity current at at_height is the one that signed at reference_height. "
             "Version cases assume a validator of this exact draft implementing only wire major 1.",
        cases=cases, log_key=dict(key_id="log-key", public_key=b64u(pub_raw)),
        recovery_window_days=7, blocks=blocks, pinned_head=previous, probes=probes,
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
    early = "2026-08-02T00:00:00.0000000001Z"
    later = "2026-08-02T00:00:00.0000000002Z"
    domain = "example.com"
    hosts = [domain, "old.example", "owner.example", "retained.example",
             "follower.example", "competitor.example", "stale.example"]

    def timestamp(height):
        return (start + datetime.timedelta(hours=height)).isoformat().replace("+00:00", "Z")

    def binding(name, identifier="shared", valid_from=early):
        return dict(key_id=identifier, alg="Ed25519", public_key=b64u(raw_public(keys[name])),
                    valid_from=valid_from)

    histories, probes = {}, []
    for shared in (False, True):
        name = "shared public key with distinct bounds" if shared else "distinct source public keys"
        owner_key = "old" if shared else "owner"
        owner_binding = binding(owner_key, valid_from=later if shared else early)
        initial = sign_envelope_with(keys["old"], "publisher", dict(
            wist_version="1.0.0", domain=domain, seq=0, keys=[binding("old")],
            recovery_keys=[binding("recovery", "recovery")], subdomain_scope=["stale.example"]), "shared")

        def replace(previous, seq, bindings, scope, signer, identifier="shared"):
            inner = dict(previous["publisher"], seq=seq,
                         prev_declaration=decl_hash(previous["publisher"]),
                         keys=bindings, subdomain_scope=scope)
            return sign_envelope_with(keys[signer], "publisher", inner, identifier)

        prior = replace(initial, 1, [binding("old")],
                        ["old.example", "retained.example"], "old")
        owner = replace(prior, 2, [owner_binding, binding("admin", "admin")],
                        ["owner.example", "retained.example"], "recovery", "recovery")
        competitor = replace(owner, 3, [binding("competitor")],
                             ["competitor.example"], "competitor")
        follower = replace(owner, 4, [owner_binding, binding("admin", "admin")],
                           ["old.example", "retained.example", "follower.example"], "admin", "admin")
        latest = replace(follower, 5, [binding("competitor")], [], "competitor")
        deadline = replace(follower, 6, [owner_binding], [], "admin", "admin")
        deadline["publisher"].pop("subdomain_scope")
        deadline = sign_envelope_with(keys["admin"], "publisher", deadline["publisher"], "admin")
        restored = replace(deadline, 7, [owner_binding], hosts[1:], owner_key)
        declarations = {0: [initial], 1: [prior, owner], 2: [competitor], 3: [follower],
                        168: [latest], 169: [deadline], 170: [restored]}
        blocks, previous = [], "sha256:genesis"
        for height in range(171):
            entries = [recovery_order_entry(env) for env in declarations.get(height, [])]
            entries.sort(key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
            leaves = [leaf_hash(rfc8785.dumps(entry)) for entry in entries]
            header = dict(wist_version="1.0.0", block_number=height, prev_block_hash=previous,
                          sealed_at=timestamp(height), entry_count=len(entries),
                          merkle_root="sha256:" + (merkle_tree_root(leaves) if leaves else leaf_hash(b"")).hex())
            blocks.append(dict(sign_envelope_with(priv, "header", header, "log-key"), entries=entries))
            previous = decl_hash(header)
        histories[name] = dict(blocks=blocks, pinned_head=previous)

        def add(label, height, stage, signer, host, expected, observed_at=later,
                identifier="shared", damage=None):
            env = sign_envelope_with(keys[signer], "delta", dict(delta,
                publisher=domain, url="https://" + host + "/scope", observed_at=observed_at), identifier)
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
            add(f"competitor signature at {height}", height, "admission", "competitor", domain, "WIST1-E01")
            add(f"unknown identifier at {height}", height, "admission", "old", domain, "WIST1-E02",
                identifier="unknown")
            add(f"malformed signature field at {height}", height, "admission", "old", domain, "WIST1-E14",
                identifier="unknown", damage="encoding")
        if shared:
            for height in (1, 3, 168):
                add(f"scope cannot borrow future binding at {height}", height, "admission", "old",
                    "owner.example", "WIST1-E03", observed_at=early)
                add(f"eligible old source at {height}", height, "admission", "old", "old.example",
                    "accepted", observed_at=early)
                add(f"inclusive owner bound at {height}", height, "admission", "old", "owner.example",
                    "accepted", observed_at="2026-08-02t01:00:00.000000000200+01:00")
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
        "open recovery at height 1 after a same-Block ordinary predecessor, accept a competitor and "
        "a legitimate follower, accept a higher-sequence competitor at 168, settle at 169, then apply "
        "a scope-removing Declaration in that same deadline Block. Height 170 grants scopes again. "
        "Admission and sealing probes run after the named Block's Declaration stage; settlement probes "
        "run immediately before height 169's Declaration stage. Queued-copy probes reuse height-1 "
        "authority-eligible Envelopes; damaged settlement probes are conditional stage inputs and do not "
        "claim prior queue acceptance. "
        "accepted establishes only signature/binding and scope authority. Probe timestamps are signed "
        "inputs, not claimed live validation times. Chains, clocks, Payload, quotas, durable queue/status "
        "effects and actual Delta inclusion are not exercised. Trusted Log key and pinned heads are "
        "fixture inputs. Signature-invalid twins are checked independently by the reference.",
        log_key=dict(key_id="log-key", public_key=b64u(pub_raw)), recovery_window_days=7,
        histories=histories, probes=probes)


write_json(WIST1 / "recovery-scope.json", recovery_scope_vectors())


def declaration_refresh_vectors():
    import copy
    domain = "localhost"
    now = "2026-08-09T14:00:00Z"
    seeds = [bytes([n]) * 32 for n in (1, 7, 11)]
    signing = [Ed25519PrivateKey.from_private_bytes(seed) for seed in seeds]

    def signed(inner, body, key, identifier=None):
        return {inner: body, "sig": {"key_id": identifier or f"k{key + 1}",
            "alg": "Ed25519", "value": b64u(signing[key].sign(rfc8785.dumps(body)))}}

    def binding(key, identifier=None, at="2026-08-09T00:00:00Z"):
        return dict(key_id=identifier or f"k{key + 1}", alg="Ed25519",
            public_key=b64u(signing[key].public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)), valid_from=at)

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

    add("absent identifier rotation", [delta_object("a", 1)], [rotated])
    reused = declaration([binding(1, "k1")], original)
    add("reused identifier rotation", [delta_object("a", 1, "k1")], [reused])
    future = declaration([binding(0), binding(1, at="2026-08-10T00:00:00Z")])
    add("future binding replacement", [delta_object("a", 1)],
        [declaration([binding(1)], future)], initial=future)
    excluded_key = binding(1)
    excluded_key["public_key"] = b64u(bytes([1]) + bytes(31))
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
        "Block inclusion. Optional empty Pages isolate authentication, not Page cardinality or publication. "
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
        doc = sign_envelope("feed", body, "test-k1")
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
        keys=[dict(key_id="test-k1", alg="Ed25519", public_key=b64u(pub_raw),
                   valid_from="2026-08-09T00:00:00Z")]), "test-k1")
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
        doc = sign_envelope("feed", body, "test-k1")
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
        keys=[dict(key_id="test-k1", alg="Ed25519", public_key=b64u(pub_raw),
                   valid_from="2026-08-09T00:00:00Z")]), "test-k1")
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
        doc = sign_envelope("feed", body, "test-k1")
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
                objects[name] = dict(envelope=sign_envelope('delta', body, 'test-k1'), payload=payload,
                                     id=decl_hash(body), sealed_height=168 if cohort == 'early' else 338)

    anchor = objects['early extract_cap_bytes 1']
    attestation_body = dict(wist_version='1.0.0', publisher='example.com',
                            url=anchor['envelope']['delta']['url'], change_type='attest',
                            observed_at=at(169 * 3600), meta=dict(lang='en'), prev=anchor['id'])
    attestation = sign_envelope('delta', attestation_body, 'test-k1')
    replacement = objects['later extract_cap_bytes 1']
    body = dict(replacement['envelope']['delta'], url=attestation_body['url'], change_type='update',
                observed_at=at(337 * 3600), prev=decl_hash(attestation_body))
    replacement.update(envelope=sign_envelope('delta', body, 'test-k1'), id=decl_hash(body))

    ranks = dict(publisher_declaration=0, registry_update=1, publisher_delta=2)

    def block(height, previous, entries):
        entries = sorted(entries, key=lambda entry: (ranks[entry['type']], leaf_hash(rfc8785.dumps(entry))))
        hashes = [leaf_hash(rfc8785.dumps(entry)) for entry in entries]
        root = merkle_tree_root(hashes) if hashes else hashlib.sha256(b'\x00').digest()
        header = dict(wist_version='1.0.0', block_number=height, prev_block_hash=previous,
                      sealed_at=at(height * 3600), merkle_root='sha256:' + root.hex(), entry_count=len(entries))
        return dict(sign_envelope('header', header, 'test-log-k1'), entries=entries)

    blocks = []
    previous = 'sha256:genesis'
    for height in range(509):
        entries = []
        if height == 0:
            entries.append(dict(type='publisher_declaration', body=sign_envelope('publisher', publisher, 'test-k1')))
        if height == 169:
            entries.append(dict(type='publisher_delta', body=attestation))
        for seal, effective, values, links_only in schedule:
            if height == seal:
                for parameter, value in values.items():
                    if (parameter == 'links_cap_bytes') != links_only:
                        continue
                    update = dict(wist_version='1.0.0', action='parameter_change', subject=parameter,
                                  details=dict(parameter=parameter, value=value), effective_at=at(effective * 3600))
                    entries.append(dict(type='registry_update', body=sign_envelope('update', update, 'test-log-k1')))
        entries.extend(dict(type='publisher_delta', body=obj['envelope'])
                       for obj in objects.values() if obj['sealed_height'] == height)
        current = block(height, previous, entries)
        blocks.append(current)
        previous = decl_hash(current['header'])

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

    invalid_blocks = []
    for name, obj in objects.items():
        if name.startswith('later') and name.endswith('1'):
            body = dict(obj['envelope']['delta'])
            if body['change_type'] == 'update':
                body.update(change_type='new', url='https://example.com/invalid/extract',
                            observed_at='2026-08-04T01:00:00Z')
                del body['prev']
            envelope = sign_envelope('delta', body, 'test-k1')
            candidate = block(169, decl_hash(blocks[168]['header']),
                              [dict(type='publisher_delta', body=envelope)])
            invalid_blocks.append(dict(name=name, block=candidate, pinned_head=decl_hash(candidate['header']),
                                       payload=obj['payload'], expected=result(obj, low)))
    return dict(note='WIST-1 section 3.6 and WIST-4 section 5. One authenticated hourly history supplies a Declaration, cap amendments and unique content-bearing Deltas. Amendments have at least seven days of grace; lower link caps precede lower aggregate caps, and larger aggregate caps precede larger link caps. Probes independently check caps at each stage, not admission membership or permission to re-admit included IDs; admission probes resume their retained attempt across a boundary, sealing probes recheck objects under a supplied earlier valid cap profile, and historical probes retrieve the committing Delta profile from its actual inclusion. Repeating a probe with restart reconstructs inputs from the pinned prefix, not current defaults. Invalid candidate Blocks branch from height 168. Cap checks, signatures, inclusion and commitments are exercised; live queue mutation, crash durability, HTTP retrieval and complete governance acceptance are not established.',
                log_key=dict(key_id='test-log-k1', public_key=b64u(pub_raw)), defaults=defaults,
                blocks=blocks, pinned_head=previous, objects=objects, probes=probes, invalid_blocks=invalid_blocks)


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
        cases.append(dict(name=name, envelope=sign_envelope('delta', body, 'test-k1'), payload=payload, expected=expected))
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
        case = dict(name=name, envelope=sign_envelope('delta', body, 'test-k1'),
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
        amendments.append(dict(sealed_at=at(0), envelope=sign_envelope('update', update, 'test-k1'), accepted=True))
    for label, effective, value in [('bad signature', 168 * 3600, 9000), ('short grace', 3600, 9999)]:
        update = dict(wist_version='1.0.0', action='parameter_change', subject='clock_skew_seconds',
                      details=dict(parameter='clock_skew_seconds', value=value), effective_at=at(effective))
        signed = sign_envelope('update', update, 'test-k1')
        if label == 'bad signature':
            signed['sig']['value'] = b64u(bytes(64))
        amendments.append(dict(sealed_at=at(0), envelope=signed, accepted=False))

    def allowance(seconds):
        return next((value for hour, value in reversed(changes) if hour * 3600 <= seconds), 600)

    probes = []

    def add(name, stage, clock_s, observed, expected, **context):
        body = dict(delta, observed_at=observed, url='https://example.com/clock/' + str(len(probes)))
        probes.append(dict(name=name, stage=stage, envelope=sign_envelope('delta', body, 'test-k1'),
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
                'inclusion contexts; amendments share the initial Block in listed order. Only the '
                'clock_skew_seconds parameter varies. Context timestamps do not prove Block inclusion. '
                'Clock relation outcomes assume other Delta obligations have passed; each new attempt '
                'captures its own context. Historical checked_at and sealing admitted_at are distractors.',
                public_key=b64u(pub_raw), default=600, amendments=amendments, probes=probes)


write_json(WIST1 / 'delta-clock-time.json', delta_clock_time_vectors())
