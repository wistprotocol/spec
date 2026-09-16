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

import ecvrf
import link_extraction
import notice_evidence
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
                "Snapshot recovery and appeal authority are not established by these histories.",
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
    traces = [
        (0, state(initial, None, 0, windows=0)),
        (1, state(owner, owner, 1)), (2, state(fresh, owner, 10)),
        (3, state(follower, follower, 11)), (4, state(fresh_again, follower, 20)),
        (5, state(recovered, recovered, 21)), (6, state(competitor, recovered, 30)),
        (168, state(competitor, recovered, 30)), (169, state(after, None, 31)),
        (170, state(after, None, 31)),
    ]
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
    write_json(WIST1 / "recovery-heads.json", {
        "note": "WIST-1 section 5.2 accepted sequence and recovery heads. The supplied "
                "Log key and final pinned head authenticate one complete hourly Block chain. "
                "An optional branch index selects an independently pinned alternate history. "
                "Queries replay through prefix_height, settle at candidate_sealed_at, then "
                "evaluate one independent unsealed candidate. Rejection preserves the "
                "post-settlement state. No invalid candidate is asserted to be a valid "
                "sealed Entry. No identity, sanction or conflicting-batch result is asserted.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "blocks": blocks, "pinned_head": previous,
        "branches": [branch],
        "expected_prefix_states": [{"height": height, "state": expected}
                                   for height, expected in traces],
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
                "No Audit Record, appeal or Snapshot "
                "eligibility is asserted. Domain iteration order is immaterial to accepted state.",
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
    appeal_cases = []
    for case in cases:
        if not (case["name"].startswith("initial unused keys")
                or case["name"] in {"replacement no usable signing keys noncanonical point",
                                    "non small mixed order key remains usable",
                                    "future valid from does not exclude Declaration signer"}):
            continue
        notice = decl_hash({"conditional_notice": case["name"]})
        for key in case["fetched"]["publisher"]["keys"]:
            signer = next((private for private in (priv, priv2, priv3, priv4)
                           if b64u(raw_public(private)) == key["public_key"]), priv)
            update = {"wist_version": "1.0.0", "action": "appeal", "subject": "example.com",
                      "effective_at": "2026-08-04T00:00:00Z", "details": {"notice": notice}}
            expected = ("WIST4-E05" if key["public_key"] in excluded_values else
                        "signature_valid" if b64u(raw_public(signer)) == key["public_key"] else "WIST1-E01")
            appeal_cases.append({"declaration_case": case["name"], "accepted_notice": notice,
                                 "appeal": sign_envelope_with(signer, "update", update, key["key_id"]),
                                 "expected": expected})
    write_json(WIST1 / "declaration-key-eligibility.json", {
        "note": "WIST-1 sections 4 and 5.2 derive usable keys while retaining every signed entry. "
                "stored is null for initial admission; otherwise it is an authenticated initial Declaration. "
                "Each fetched signature is independently verifiable under author_key, even when that key has "
                "no eligible named binding. expected_usable describes cryptographic key exclusion only, "
                "even for rejected Envelopes, and is not installed state. Fixtures use canonical base64url "
                "and ordinary valid fields. Each appeal_case supplies an already-eligible notice and selects "
                "the named case's accepted fetched Declaration as its authority source; only key exclusion and "
                "signature verification are asserted. No notice evidence, temporal authority selection, appeal "
                "process, full field/encoding profile, live admission, Delta replay or Snapshot result is asserted.",
        "cases": cases, "appeal_cases": appeal_cases})


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
                'Snapshot recovery. Single label host acceptance asserts no canary eligibility or suffix policy.',
        'author_key': b64u(pub_raw), 'log_key': conflicts['log_key'], 'recovery_window_days': 7,
        'hosts': host_cases, 'cases': cases, 'prefixes': conflicts['prefixes'], 'block_cases': blocks})


declaration_host_vectors()

def recovery_identity_vectors():
    def signed(previous, seq, signer, key_id, **changes):
        inner = dict(previous["publisher"], seq=seq,
                     prev_declaration=decl_hash(previous["publisher"]), **changes)
        return sign_envelope_with(signer, "publisher", inner, key_id)

    cases = []
    start = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc)
    def timestamp(hour):
        return (start + datetime.timedelta(hours=hour)).strftime("%Y-%m-%dT%H:%M:%SZ")

    for fresh_before_owner in (False, True):
        initial = sign_envelope("publisher", publisher, "test-k1")
        before = signed(initial, 1, priv3, "test-k2", keys=[K2]) if fresh_before_owner else initial
        owner = signed(before, 2, priv2, "test-r1", keys=[K2], recovery_keys=[R2])
        for nonce in range(1000):
            competitor = signed(owner, 3, priv, "test-k1", keys=publisher["keys"],
                                contact=f"mailto:competitor{nonce}@example.com")
            if recovery_order_leaf(competitor) < recovery_order_leaf(owner):
                break
        else:
            raise AssertionError("no reversed owner and competitor leaves")
        follower = signed(owner, 4, priv3, "test-k2", contact="mailto:chain@example.com")
        fresh = signed(follower, 5, priv, "test-k1", keys=publisher["keys"])
        descendant = signed(fresh, 6, priv, "test-k1", contact="mailto:descendant@example.com")
        last_competitor = signed(descendant, 7, priv3, "test-k2", keys=[K2])
        reset_height = 171 if fresh_before_owner else 172
        outside = signed(follower, 8, priv, "test-k1", keys=publisher["keys"])
        opening = ([before] if fresh_before_owner else []) + [owner, competitor]
        events = {0: [initial], 3: opening, 4: [follower], 5: [fresh],
                  6: [descendant], 170: [last_competitor], reset_height: [outside]}
        blocks, previous = [], "sha256:genesis"
        for height in range(175):
            entries = sorted(map(recovery_order_entry, events.get(height, [])),
                             key=lambda entry: leaf_hash(rfc8785.dumps(entry)))
            hashes = [leaf_hash(rfc8785.dumps(entry)) for entry in entries]
            root = merkle_tree_root(hashes) if hashes else hashlib.sha256(b"\x00").digest()
            header = {"wist_version": "1.0.0", "block_number": height,
                      "prev_block_hash": previous, "sealed_at": timestamp(height),
                      "merkle_root": "sha256:" + root.hex(), "entry_count": len(entries)}
            block = sign_envelope_with(priv, "header", header, "test-log-k1")
            block["entries"] = entries
            blocks.append(block)
            previous = decl_hash(header)
        resets = ([3] if fresh_before_owner else []) + [reset_height]
        next_owner = signed(follower, 8, priv4, "test-r2")
        next_competitor = signed(next_owner, 9, priv, "test-k1", keys=publisher["keys"])
        cases.append({"name": "fresh before recovery owner" if fresh_before_owner else "recovery before fresh competitor",
                      "blocks": blocks, "pinned_head": previous,
                      "expected_resets": resets,
                      "probes": [
                          {"name": "recovery descendant of competitor preserves identity", "prefix_height": 5,
                           "candidate_sealed_at": timestamp(6),
                           "candidate": signed(fresh, 6, priv4, "test-r2", recovery_keys=publisher["recovery_keys"]),
                           "expected_result": "recovery_rotation", "expected_reset": 3 if fresh_before_owner else None},
                          {"name": "new deadline window prevents later same Block reset", "prefix_height": 170,
                           "candidate_sealed_at": timestamp(171), "candidate": next_owner,
                           "expected_result": "recovery_rotation", "successor": next_competitor,
                           "expected_successor_result": "fresh_identity",
                           "expected_reset": 3 if fresh_before_owner else None},
                          {"name": "fresh restored head replacement at deadline resets", "prefix_height": 170,
                           "candidate_sealed_at": timestamp(171), "candidate": outside,
                           "expected_result": "fresh_identity", "expected_reset": 171},
                          {"name": "last predeadline fresh competitor does not reset", "prefix_height": 169,
                           "candidate_sealed_at": timestamp(170), "candidate": last_competitor,
                           "expected_result": "fresh_identity", "expected_reset": 3 if fresh_before_owner else None},
                          {"name": "deadline competitor predecessor rejects without reset", "prefix_height": 170,
                           "candidate_sealed_at": timestamp(171),
                           "candidate": signed(last_competitor, 8, priv3, "test-k2"),
                           "expected_result": "WIST1-E08", "expected_reset": 3 if fresh_before_owner else None},
                          {"name": "restored head idempotence creates no reset", "prefix_height": 170,
                           "candidate_sealed_at": timestamp(171), "candidate": follower,
                           "expected_result": "idempotent", "expected_reset": 3 if fresh_before_owner else None},
                      ]})
    inputs = {"deltas": [{"label": "old a", "height": 0, "url": "https://example.com/a"},
                         {"label": "old b", "height": 0, "url": "https://example.com/b"},
                         {"label": "new a", "height": 172, "url": "https://example.com/a"}],
              "consistent": [{"height": 1, "delta": "old a"}, {"height": 7, "delta": "old b"},
                             {"height": 173, "delta": "new a"}],
              "findings": [{"height": 2, "delta": "old a", "severity": 3},
                           {"height": 8, "delta": "old b", "severity": 1},
                           {"height": 173, "delta": "new a", "severity": 1}],
              "lifts": [9], "notice_target": {"notice_height": 5, "activation_height": 2, "level": 3}}
    decay = json.loads((ROOT / "vectors/wist4/decay-table.json").read_text())["values"]
    for case in cases:
        rows, active, seen, reset = [], set(), [], None
        for height in range(len(case["blocks"])):
            if height in case["expected_resets"]:
                reset, active, seen = height, set(), []
            if height in inputs["lifts"]:
                active.clear()
            eligible = {d["label"]: d for d in inputs["deltas"]
                        if (reset is None or d["height"] >= reset) and d["height"] <= height}
            for finding in inputs["findings"]:
                if finding["height"] != height or finding["delta"] not in eligible:
                    continue
                had_three = 3 in active
                seen.append(finding)
                active.add(1)
                if len(seen) >= 3:
                    active.add(2)
                if len(seen) >= 10 or finding["severity"] == 3:
                    active.add(3)
                if had_three or sum(f["severity"] == 3 for f in seen) >= 3:
                    active.add(4)
            urls = {eligible[c["delta"]]["url"] for c in inputs["consistent"]
                    if c["height"] <= height and c["delta"] in eligible}
            first = min((d["height"] for d in eligible.values()), default=height)
            rows.append({"height": height, "reset_height": reset, "A": (height - first) // 24,
                         "C": len(urls), "penalty_n": sum(f["severity"] * decay[(height - f["height"]) // 24]
                                                                  for f in seen),
                         "finding_heights": [f["height"] for f in seen], "active_rungs": sorted(active)})
        case["expected_projection"] = rows
        case["expected_notice_target_matches_identity"] = case["expected_resets"][0] != 3
    write_json(ROOT / "vectors/wist4/recovery-identity.json", {
        "note": "WIST-1 section 5.2 and WIST-4 section 6.3. Each signed hourly Block history "
                "authenticates Declarations only. expected_resets is derived in Declaration application "
                "order, including same-Block predecessors, competitors and settlement. The separate "
                "projection_inputs are abstract, already-eligible WIST-4 stage inputs at the same heights; "
                "they are not asserted to occur in these Declaration-only Blocks. Projection results "
                "test identity scoping, ongoing age/credit/decay, latched rungs and a supplied lawful lift, "
                "not Audit Record eligibility, signature validity or notice admission. notice_target "
                "tests only whether the supplied earlier activation survives identity scoping. "
                "Probes independently settle the indicated prefix then evaluate an unsealed Declaration "
                "and any successor in the same candidate Block, in sequence order.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "projection_inputs": inputs, "cases": cases})


recovery_identity_vectors()


def recovery_appeal_vectors():
    start = datetime.datetime(2026, 8, 4, tzinfo=datetime.timezone.utc)
    signing_keys = [priv, priv3, Ed25519PrivateKey.from_private_bytes(bytes([85]) * 32),
                    Ed25519PrivateKey.from_private_bytes(bytes([102]) * 32)]

    def timestamp(hour):
        return (start + datetime.timedelta(hours=hour)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def storage_key(entry):
        return (0 if entry["type"] == "publisher_declaration" else 1,
                leaf_hash(rfc8785.dumps(entry)))

    def key(index, key_id, valid_from=None):
        return {"key_id": key_id, "alg": "Ed25519",
                "public_key": b64u(raw_public(signing_keys[index])),
                "valid_from": valid_from or timestamp(-24)}

    def signed(previous, seq, signer, key_id, **changes):
        inner = dict(previous["publisher"], seq=seq,
                     prev_declaration=decl_hash(previous["publisher"]), **changes)
        return sign_envelope_with(signer, "publisher", inner, key_id)

    initial = sign_envelope("publisher", publisher, "test-k1")
    owner = signed(initial, 1, priv2, "test-r1", keys=[K2], recovery_keys=[R2])
    future = "2030-01-01T00:00:00Z"
    follower = signed(owner, 3, priv3, "test-k2",
                      keys=[key(2, "test-k3", future), key(2, "test-k3-alias", future)])
    cases = []
    for second_window in (False, True):
        for nonce in range(1000):
            competitor = signed(owner, 2, priv, "test-k2", keys=[key(0, "test-k2")],
                                contact=f"mailto:competitor{nonce}@example.com")
            if recovery_order_leaf(competitor) < recovery_order_leaf(owner):
                break
        else:
            raise AssertionError("no reversed recovery leaves")
        off_chain = signed(follower, 4, priv, "test-k3", keys=[key(0, "test-k3")])
        deadline = signed(follower, 5, priv4 if second_window else signing_keys[2],
                          "test-r2" if second_window else "test-k3", keys=[key(3, "test-k4")])
        deadline_entries = [deadline]
        if second_window:
            deadline_entries.append(signed(deadline, 6, priv, "test-k4", keys=[key(0, "test-k4")]))
            after = signed(deadline, 7, signing_keys[3], "test-k4", keys=[key(1, "test-k2-later")])
        else:
            after = signed(deadline, 6, priv, "test-k1", keys=publisher["keys"])
        declarations = {0: [initial], 1: [owner, competitor], 3: [follower],
                        4: [off_chain], 169: deadline_entries, 170: [after]}
        authority = {0: initial, 1: owner, 2: owner, 3: follower, 4: follower,
                     168: follower, 169: deadline, 170: after, 171: after}
        notices = {}
        for height in authority:
            declaration_leaves = list(map(recovery_order_leaf, declarations.get(height, [])))
            for nonce in range(1000):
                inner = {"wist_version": "1.0.0", "action": "notice", "subject": "example.com",
                         "effective_at": timestamp(-24 if second_window else 400),
                         "details": {"kind": "sanction", "level": 3,
                                     "activation": decl_hash({"activation_input": height}),
                                     "reason": f"Contested finding {height}, authority case {nonce}",
                                     "appeal_deadline": timestamp(height + 336)},
                         "evidence": [decl_hash({"evidence_input": height})]}
                envelope = sign_envelope_with(priv, "update", inner, "test-log-k1")
                hashed = leaf_hash(rfc8785.dumps({"type": "registry_update", "body": envelope}))
                if not declaration_leaves or (hashed > max(declaration_leaves) if second_window
                                              else hashed < min(declaration_leaves)):
                    notices[height] = envelope
                    break
            else:
                raise AssertionError("no notice position twin")
        blocks, previous = [], "sha256:genesis"
        for height in range(172):
            entries = list(map(recovery_order_entry, declarations.get(height, [])))
            if height in notices:
                entries.append({"type": "registry_update", "body": notices[height]})
            if height == 171:
                entries.append({"type": "registry_update", "body": notices[1]})
            entries.sort(key=storage_key)
            leaves = [leaf_hash(rfc8785.dumps(entry)) for entry in entries]
            root = merkle_tree_root(leaves) if leaves else hashlib.sha256(b"\x00").digest()
            header = {"wist_version": "1.0.0", "block_number": height,
                      "prev_block_hash": previous, "sealed_at": timestamp(height),
                      "merkle_root": "sha256:" + root.hex(), "entry_count": len(entries)}
            block = sign_envelope_with(priv, "header", header, "test-log-k1")
            block["entries"] = entries
            blocks.append(block)
            previous = decl_hash(header)
        author_rejections = []
        for entry_type in ("publisher_declaration", "registry_update"):
            entries = json.loads(json.dumps(blocks[1]["entries"]))
            signature = next(entry["body"]["sig"] for entry in entries if entry["type"] == entry_type)
            raw = bytearray(base64.urlsafe_b64decode(signature["value"] + "=="))
            raw[0] ^= 1
            signature["value"] = b64u(raw)
            entries.sort(key=storage_key)
            header = dict(blocks[1]["header"], merkle_root="sha256:" + merkle_tree_root(
                [leaf_hash(rfc8785.dumps(entry)) for entry in entries]).hex())
            block = sign_envelope_with(priv, "header", header, "test-log-k1")
            block["entries"] = entries
            author_rejections.append({"type": entry_type, "block": block, "pinned_head": decl_hash(header)})
        entries = blocks[1]["entries"][-1:] + blocks[1]["entries"][:-1]
        header = dict(blocks[1]["header"], merkle_root="sha256:" + merkle_tree_root(
            [leaf_hash(rfc8785.dumps(entry)) for entry in entries]).hex())
        ordering_rejection = sign_envelope_with(priv, "header", header, "test-log-k1")
        ordering_rejection["entries"] = entries
        probes = []

        def probe(name, notice_height, prefix, signer, key_id, expected, effective_hour=0,
                  subject="example.com", notice_id=None, corrupt=False):
            inner = {"wist_version": "1.0.0", "action": "appeal", "subject": subject,
                     "effective_at": timestamp(effective_hour),
                     "details": {"notice": notice_id or decl_hash(notices[notice_height]["update"])}}
            envelope = sign_envelope_with(signer, "update", inner, key_id)
            if corrupt:
                raw = bytearray(base64.urlsafe_b64decode(envelope["sig"]["value"] + "=="))
                raw[0] ^= 1
                envelope["sig"]["value"] = b64u(raw)
            probes.append({"name": name, "notice_height": notice_height, "prefix_height": prefix,
                           "appeal": envelope, "expected": expected})

        for height, declaration in authority.items():
            entry = declaration["publisher"]["keys"][0]
            signer = next(private for private in signing_keys
                          if b64u(raw_public(private)) == entry["public_key"])
            for prefix in sorted({height, max(height, 4), max(height, 168), 169, 170, 171}):
                if prefix < height:
                    continue
                probe(f"notice {height} preserves authority at prefix {prefix}",
                      height, prefix, signer, entry["key_id"], "authorized", effective_hour=400)
            probe(f"notice {height} rejects corrupted author signature", height, 171,
                  signer, entry["key_id"], "WIST1-E01", corrupt=True)
            probe(f"notice {height} rejects recovery signer", height, 171,
                  priv4, "test-r2", "WIST4-E05")
        probe("pre recovery notice rejects recovered signing key", 0, 171, priv3, "test-k2", "WIST4-E05")
        probe("opening notice rejects frozen admission union key", 1, 1, priv, "test-k1", "WIST4-E05")
        for prefix in (1, 4, 169, 171):
            probe(f"competitor reuses notice identifier at prefix {prefix}",
                  1, prefix, priv, "test-k2", "WIST1-E01")
        probe("later follower cannot rewrite opening notice", 1, 171,
              signing_keys[2], "test-k3", "WIST4-E05")
        probe("same public key under later identifier is not notice alias", 1, 171,
              priv3, "test-k2-later", "WIST4-E05")
        probe("admitted alias with future valid from", 3, 3,
              signing_keys[2], "test-k3-alias", "authorized", effective_hour=-24)
        probe("future effective at does not change notice binding", 3, 171,
              signing_keys[2], "test-k3-alias", "authorized", effective_hour=400)
        probe("unlisted alias cannot select same public key", 3, 171,
              signing_keys[2], "test-k3-unlisted", "WIST4-E05")
        probe("off chain reused follower identifier", 4, 171, priv, "test-k3", "WIST1-E01")
        probe("deadline notice cannot use restored predecessor keys", 169, 171,
              signing_keys[2], "test-k3", "WIST4-E05")
        probe("post deadline notice cannot use previous signing key", 170, 171,
              signing_keys[3], "test-k4", "WIST4-E05")
        probe("appeal cannot use another domain notice authority", 1, 171,
              priv3, "test-k2", "WIST4-E05", subject="other.example")
        probe("unsealed notice supplies no authority", 1, 171, priv3, "test-k2", "WIST4-E05",
              notice_id=decl_hash({"unsealed_notice": True}))
        probe("future notice supplies no authority to earlier prefix", 3, 2,
              signing_keys[2], "test-k3", "WIST4-E05")
        cases.append({"name": "new recovery at settlement" if second_window else "rotation then fresh identity",
                      "blocks": blocks, "pinned_head": previous,
                      "notice_leaf_after_declaration_leaves": second_window,
                      "author_rejections": author_rejections,
                      "ordering_rejection": ordering_rejection,
                      "assumed_eligible_notices": [decl_hash(env["update"]) for env in notices.values()],
                      "expected_authority": [{"height": height, "declaration": decl_hash(env["publisher"]),
                                              "keys": env["publisher"]["keys"]}
                                             for height, env in authority.items()],
                      "probes": probes})
    write_json(ROOT / "vectors/wist4/recovery-appeals.json", {
        "note": "WIST-4 section 7 notice-era appeal key selection. Signed hourly Blocks authenticate "
                "Declaration history and notice inclusion; each Declaration and notice has its own signature. "
                "assumed_eligible_notices are conditional stage inputs: these histories do not contain "
                "the Audit Records or activations needed to establish notice evidence eligibility. "
                "Their activation/evidence identifiers label supplied inputs, not proven findings. "
                "Probes are independent, unsealed appeals evaluated against the indicated accepted prefix; "
                "authorized means signature-authorized only, not process acceptance, timeliness or sealing. "
                "Every probe starts with no appeal slot occupied. The future-dated signing entries and "
                "effective_at twins distinguish appeal authority from Delta observed_at validation. "
                "Author rejection twins have valid Block signatures: an invalid Declaration invalidates "
                "its Block; an invalid notice signature supplies no appeal authority. The ordering twin "
                "rejects a Registry Update stored before the Declaration group. "
                "The branches exercise fresh identity and a second recovery window at or after settlement. "
                "No Snapshot restoration or live appeal publication is established.",
        "log_key": {"key_id": "test-log-k1", "public_key": b64u(pub_raw)},
        "recovery_window_days": 7, "cases": cases})


recovery_appeal_vectors()

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
HALF_OBS = PAD + "one two three four five six seven eight ten"
# Han: a page with no spaces at all, long enough to clear the mass guard
# only once each character counts as its own word.
HAN_REF = "\u5929\u5730\u7384\u9ec4\u5b87\u5b99\u6d2a\u8352\u65e5\u6708"
HAN_OBS = HAN_REF + "\u76c8\u6603\u8fb0\u5bbf\u5217\u5f35\u5bd2\u4f86" * 5
# Six letters each carrying U+0330: six grapheme clusters over twelve code
# points, and an observed text holding five of the six.
TILDE_REF = "q\u0330w\u0330r\u0330t\u0330y\u0330p\u0330"
TILDE_OBS = "q\u0330w\u0330r\u0330t\u0330y\u0330"
SIM_FIXTURES = []
for label, ref, obs, shingle in (
    # Whole-document containment: the committed text embedded in template
    # furniture scores full marks — the case the quotient exists for.
    ("containment-full", REF9, "home about " + REF9 + " contact " + PAD, 8),
    # 9 words -> two 8-word shingles; the observed drops the last word, so
    # exactly one shingle survives: 500000, exercising the denominator |A|.
    ("containment-half", REF9, HALF_OBS, 8),
    # Below the guard: a bot-interstitial-sized page is not_auditable,
    # never similarity 0.
    ("mass-guard", REF9, "please enable javascript to view this site", 8),
    # Short reference (2 words): the grapheme branch, contained verbatim.
    ("short-reference-graphemes", "hello world", PAD + "hello world", 8),
    # §5: `shingle_size` governs the branch threshold as well as the
    # length, so the same pair that takes the word branch at 8 takes the
    # grapheme branch at 10 — the reference has 9 words — and the two
    # branches score it differently.
    ("amended-shingle-size-takes-the-grapheme-branch", REF9, HALF_OBS, 10),
    # And a shorter amendment leaves both texts on the word branch with a
    # shorter shingle, which the same pair scores differently again.
    ("amended-shingle-size-shortens-the-word-shingle", REF9, HALF_OBS, 4),
    # §5 step 2 is default full case-folding, not a lowercase: it folds
    # sharp s to "ss", so the two spellings are one word.
    ("full-case-folding-folds-sharp-s",
     "die stra\u00dfe ist lang und breit und sch\u00f6n und alt",
     PAD + "DIE STRASSE IST LANG UND BREIT UND SCH\u00d6N UND ALT", 8),
    # §5 step 1 is NFC: the decomposed and precomposed spellings of the
    # same reference are one text.
    ("nfc-precomposes-before-comparison",
     "cafe\u0301 au lait est tres bon ici aujourd hui",
     PAD + "caf\u00e9 au lait est tres bon ici aujourd hui", 8),
    # §5 step 3 is untailored UAX #29: Han characters each stand as their
    # own word, so a page written without spaces has as many words as
    # characters and clears the mass guard, where a whitespace split
    # would see one word and rule it not_auditable.
    ("han-segments-per-character", HAN_REF, HAN_OBS, 8),
    # §5 step 4 discards every segment carrying no L* or N* character, so
    # the punctuation between the words is not part of the word sequence.
    ("punctuation-segments-are-discarded",
     "alpha, beta; gamma. delta! epsilon? zeta: eta - theta",
     PAD + "alpha beta gamma delta epsilon zeta eta theta", 8),
    # The short branch shingles extended grapheme clusters of the
    # normalized form, not code points: each letter here carries a
    # combining tilde below, so six clusters span twelve code points and
    # the two units cap the shingle length differently.
    ("short-branch-counts-grapheme-clusters", TILDE_REF, PAD + TILDE_OBS, 8),
):
    sim = link_extraction.similarity(ref, obs, shingle_size=shingle)
    SIM_FIXTURES.append({"label": label, "reference": ref, "observed": obs,
                         "shingle_size": shingle, "similarity": sim,
                         "verdict_input": "not_auditable" if sim is None else sim})
assert [f["verdict_input"] for f in SIM_FIXTURES] == \
    [1_000_000, 500_000, "not_auditable", 1_000_000, 885_714, 833_333,
     1_000_000, 1_000_000, 1_000_000, 1_000_000, 0], \
    "similarity fixtures drifted"

write_json(WIST2V / "text-extraction.json", {
    "note": ("WIST-2 §12's whole-document text extraction over raw HTML "
             "octets, and WIST-4 §5's reference-containment similarity over "
             "its output. html_hex decodes to the exact input; expected is "
             "the observed text a conforming Auditor produces. similarity "
             "cases carry min_observed_words = 40 (the Registry default) "
             "and their own shingle_size; a null similarity is the mass "
             "guard ruling not_auditable."),
    "min_observed_words": 40,
    "extraction": TEXT_FIXTURES,
    "similarity": SIM_FIXTURES,
})
print("wist2 text-extraction vector:",
      [c["label"] for c in TEXT_FIXTURES + SIM_FIXTURES])

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

# ------------------------------- WIST-3 §7: applying Deltas along their chains
# A replayer applies a sealed Delta only when its prev is the chain tip the
# state carries for (publisher, url); a fork of a sealed chain and a prev no
# lower Entry sealed are ignored alike, and an ignored Delta never becomes a
# tip (WIST-1 §3.5). Abstract ids: the rule reads prev links, not content.
CHAIN_PUB, CHAIN_URL = "example.com", "https://example.com/a"


def chain_delta(id_, prev, change_type="update", publisher=CHAIN_PUB, url=CHAIN_URL):
    return {"id": id_, "publisher": publisher, "url": url, "prev": prev,
            "change_type": change_type}


def chain_replay(deltas):
    tips, ignored = {}, []
    for i, d in enumerate(deltas):
        key = (d["publisher"], d["url"])
        if d["prev"] != tips.get(key):
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
]
chain_cases = []
for label, deltas in chain_scenarios:
    ignored, tips = chain_replay(deltas)
    chain_cases.append({"label": label, "deltas": deltas,
                        "ignored_indices": ignored, "tips": tips})
assert [c["ignored_indices"] for c in chain_cases] == \
    [[], [2], [1], [1, 2], [], [1], []], "chain replay drifted"
write_json(WIST3 / "chain-materialization.json", spaced_labels({
    "note": ("WIST-3 §7, WIST-1 §3.5: per case the sealed Deltas of one Log in "
             "Log order, the indices a replayer ignores, and the chain tip per "
             "(publisher, url) afterwards."),
    "cases": chain_cases,
}))
print("wist3 chain-materialization vector: %d cases" % len(chain_cases))

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
    # WIST-4 §5.2: the same salt over the same body with the signer appended,
    # so that no other signer can credit this value.
    "credit_commitment": audit_commit(RESPONSE_BODY + b"audit.example.net"),
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
        "credit_commitment": {
            "message_hex": (RESPONSE_BODY + b"audit.example.net").hex(),
            "value": audit_record["credit_commitment"]},
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
link_profile_defaults = {"similarity_consistent": 600_000,
                         "similarity_variance_floor": 300_000,
                         "link_agreement_consistent": 600_000,
                         "link_variance_floor": 300_000,
                         "min_observed_words": 40}
link_profile_cases = []
for parameter, amended in [("link_agreement_consistent", 800_000),
                           ("link_agreement_consistent", 400_000),
                           ("link_variance_floor", 400_000),
                           ("link_variance_floor", 200_000)]:
    for audited_at in (604_800 - 3600, 604_800):
        profile = dict(link_profile_defaults)
        if audited_at >= 604_800:
            profile[parameter] = amended
        readings = []
        probes = sorted({0, 1_000_000, 299_999, 300_000, 599_999, 600_000,
                         amended - 1, amended, amended + 1})
        for change in ("new", "update", "attest", "delete"):
            for agreement in probes:
                verdict = ("consistent" if change == "delete" or agreement >= profile["link_agreement_consistent"]
                           else "link_variance" if agreement >= profile["link_variance_floor"]
                           else "link_inconsistent")
                readings.append({"reference_change": change,
                                 "similarity": 0 if change == "delete" else 1_000_000,
                                 "link_agreement": agreement, "verdict": verdict})
        for similarity, verdict in ((500_000, "dynamic_variance"), (200_000, "inconsistent")):
            readings.append({"reference_change": "update", "similarity": similarity,
                             "link_agreement": 0, "verdict": verdict})
        link_profile_cases.append({
            "label": f"{parameter}={amended}, audited at {audited_at}",
            "change": {"parameter": parameter, "value": amended, "effective_at_s": 604_800},
            "audited_delta_sealed_at_s": audited_at,
            "reference_delta_sealed_at_s": 691_200,
            "fetched_at_s": 691_200, "record_sealed_at_s": 694_800,
            "query_sealed_at_s": 1_296_000,
            "reset": {"value": link_profile_defaults[parameter], "effective_at_s": 1_296_000},
            "expected_profile": profile, "readings": readings})
write_json(WIST4 / "link-agreement.json", {
    "note": "Worked link_agreement cases (WIST-4 §5), integer micro-units.",
    "verdict_profiles": {"note": "Accepted amendments scheduled at least seven days before effectiveness are premises. The reference and query follow the audited Block; the reset is sealed at the reference Block. Readings have a usable reference and HTML with sufficient observed words. These cases isolate temporal profiles and verdict bands, not Record eligibility or measurement truth.",
                         "defaults": link_profile_defaults, "cases": link_profile_cases},
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


def sampling_rate(reputation_u: int, displaced: bool) -> int:
    """§4: a level-1 sanction or an escalation in force displaces the formula
    to sampling_ceiling; nothing else does, the Provisional cap included."""
    return SAMPLING_CEILING_1E7 if displaced else sampling_p_1e7(reputation_u)


rate_cases = [
    {"label": label, "reputation_u": rep_u, "level1_or_escalation": displaced,
     "p_1e7": sampling_rate(rep_u, displaced),
     "is_ceiling": sampling_rate(rep_u, displaced) == SAMPLING_CEILING_1E7}
    for label, rep_u, displaced in [
        ("provisional-cap-under-no-rung", 100_000, False),
        ("provisional-cap-under-a-level-1-rung", 100_000, True),
        ("reputation-zero-under-no-rung", 0, False),
        ("full-reputation-under-no-rung", 1_000_000, False),
        ("full-reputation-under-escalation", 1_000_000, True),
    ]
]
assert [c["p_1e7"] for c in rate_cases] == [2_900_000, 5_000_000, 3_200_000, 200_000, 5_000_000], \
    "rate cases drifted"

parameter_rate_cases = []
for slope in [-9_007_199_254_740_991, -1, 0, 9_007_199_254_740_991]:
    for rep_u in [0, 999_999, 1_000_000]:
        for displaced in [False, True]:
            rate = SAMPLING_CEILING_1E7 if displaced else max(
                SAMPLING_FLOOR_1E7,
                min(SAMPLING_CEILING_1E7, SAMPLING_FLOOR_1E7 + slope * (1_000_000 - rep_u)))
            parameter_rate_cases.append({
                "parameters": {"floor_1e7": SAMPLING_FLOOR_1E7,
                               "ceiling_1e7": SAMPLING_CEILING_1E7, "slope_per_micro": slope},
                "reputation_u": rep_u, "level1_or_escalation": displaced, "p_1e7": rate,
            })

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
    "rate_cases": spaced_labels(rate_cases),
    "parameter_rate_cases": parameter_rate_cases,
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
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:[0-5][0-9]Z", ts, re.ASCII):
        raise ValueError("invalid Log timestamp")
    year_zero = ts.startswith("0000-")
    parsed = datetime.datetime.strptime("0400" + ts[4:] if year_zero else ts, "%Y-%m-%dT%H:%M:%SZ")
    return calendar.timegm(parsed.timetuple()) - (146097 * 86400 if year_zero else 0)


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
RATION_WINDOW_DAYS = 30
COVERAGE_FAILURES_MAX = 24
ESCALATIONS = {"l2": (3, 90, 0), "l3_count": (10, 90, 0), "l4_sev3": (3, 180, 3)}
APPEAL_WINDOW_DAYS = 14
APPEAL_SEAL_DAYS = 7
RULING_DEADLINE_DAYS = 30


def independent(a: str, b: str) -> bool:
    """WIST-4 §3: no shared suffix of two or more labels."""
    sa, sb = a.split(".")[-2:], b.split(".")[-2:]
    if len(sa) < 2 or len(sb) < 2:
        return True
    return sa != sb


def confirming_index(records, window_hours, quorum=2):
    for prev, nxt in zip(records, records[1:]):
        assert (nxt["block_height"], nxt["entry_index"]) > \
               (prev["block_height"], prev["entry_index"]), "not in Log order"
        assert nxt["sealed_at_s"] >= prev["sealed_at_s"], "sealed_at decreased"
    window_s = window_hours * HOUR_S
    for i, record in enumerate(records):
        held = [r for r in records[:i + 1]
                if record["sealed_at_s"] - r["sealed_at_s"] <= window_s]
        if any(all(independent(a["auditor"], b["auditor"])
                   for a, b in itertools.combinations(group, 2))
               for group in itertools.combinations(held, quorum)):
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

quorum_cases = []
for label, data, expected in (
    ("three inside window", [(0, AUD_A), (30, AUD_B), (72, AUD_C)], 2),
    ("stale member beside fresh pair", [(0, AUD_A), (100, AUD_B), (110, AUD_C)], None),
    ("later complete quorum", [(0, AUD_A), (100, AUD_B), (110, AUD_C), (120, AUD_A)], 3),
    ("third member one second late", [(0, AUD_A), (30, AUD_B), (72, AUD_C)], None),
    ("dependent member", [(0, AUD_A), (30, AUD_A2), (60, AUD_B)], None),
    ("same Block quorum", [(0, AUD_A), (0, AUD_B), (0, AUD_C)], 2),
):
    records = [rec(1 if label == "same Block quorum" else i + 1, i, t * HOUR_S, auditor)
               for i, (t, auditor) in enumerate(data)]
    if label == "third member one second late":
        records[-1]["sealed_at_s"] += 1
    got = confirming_index(records, 72, 3)
    assert got == expected
    for verdict in ("inconsistent", "link_inconsistent"):
        quorum_cases.append({"label": label + " " + verdict.replace("_", " "),
                             "verdict": verdict, "confirm_auditors": 3,
                             "records": records, "confirming_index": got,
                             "severity": None if got is None else
                                 1 if verdict == "link_inconsistent" else ci_severity(records, got)})

quorum_contradiction_cases = []
for label, agreeing, consistent, expected_confirmed, expected_contradicted in (
    ("consistent pair is insufficient", [], [(10, AUD_B), (20, AUD_C)], False, False),
    ("consistent quorum at endpoint", [], [(10, AUD_B), (20, AUD_C), (72, "watch.third.org")], False, True),
    ("consistent quorum member too late", [], [(10, AUD_B), (20, AUD_C), (73, "watch.third.org")], False, False),
    ("confirming pair is insufficient", [(10, AUD_B)], [(20, AUD_B), (30, AUD_C), (40, "watch.third.org")], False, True),
    ("confirming quorum contains trigger", [(10, AUD_B), (20, AUD_C)], [(30, AUD_B), (40, AUD_C), (50, "watch.third.org")], True, False),
    ("dependent consistent member", [], [(10, AUD_B), (20, AUD_C), (30, "peer.example.org")], False, False),
):
    agreeing_ids = [AUD_A] + [a for t, a in agreeing if 0 <= t <= 72]
    consistent_ids = [a for t, a in consistent if 0 <= t <= 72]
    def complete_quorum(ids):
        return any(all(independent(a, b) for a, b in itertools.combinations(group, 2))
                   for group in itertools.combinations(ids, 3))
    confirmed = complete_quorum(agreeing_ids)
    contradicted = not confirmed and complete_quorum(consistent_ids)
    assert (confirmed, contradicted) == (expected_confirmed, expected_contradicted)
    for verdict in ("inconsistent", "link_inconsistent"):
        quorum_contradiction_cases.append({"label": label + " " + verdict.replace("_", " "),
            "confirm_auditors": 3, "trigger": {"auditor": AUD_A, "verdict": verdict, "sealed_at_s": 0},
            "records": sorted([{"auditor": auditor, "verdict": kind, "sealed_at_s": t * HOUR_S}
                        for kind, data in ((verdict, agreeing), ("consistent", consistent))
                        for t, auditor in data], key=lambda r: r["sealed_at_s"]),
            "closing_sealed_at_s": 73 * HOUR_S,
            "confirmed": confirmed, "contradicted": contradicted})

write_json(WIST4 / "confirmation.json", spaced_labels({
    "note": "WIST-4 §5/§7 confirming-block selection and severity over one Delta's inconsistent Records in Log order.",
    "confirm_window_hours": CONFIRM_WINDOW_HOURS,
    "severity_bands": {"minor_floor": SEVERITY_MINOR_FLOOR,
                       "misleading_floor": SEVERITY_MISLEADING_FLOOR,
                       "inconsistent_below": INCONSISTENT_EFFECTIVE_BELOW},
    "independence": independence_cases,
    "cases": confirmation_cases,
    "quorum_cases": quorum_cases,
    "quorum_contradiction_cases": quorum_contradiction_cases,
}))


def most_recent_reset(resets, n):
    below = [r for r in resets if r <= n]
    return max(below) if below else None


def in_scope(height, reset, n):
    """§6.3: a Delta sealed at R is the fresh identity's own — Declarations
    apply before Deltas within a Block — so the reset bound is inclusive."""
    return height <= n and (reset is None or height >= reset)


def record_in_scope(record_height, audited_height, reset, n):
    """§6.1: a Record counts by its own height against N and by its
    audited Delta's height against the reset, at or above R."""
    return record_height <= n and (reset is None or audited_height >= reset)


def derive_inputs(case):
    reset = most_recent_reset(case["resets"], case["n"]["height"])
    n_h, n_s = case["n"]["height"], case["n"]["sealed_at_s"]
    accepted = [d for d in case["accepted"] if in_scope(d["height"], reset, n_h)]
    a_days = 0
    if accepted:
        first = min(accepted, key=lambda d: d["height"])
        a_days = (n_s - first["sealed_at_s"]) // DAY_S
    urls = {a["url"] for a in case["consistent_audits"]
            if record_in_scope(a["height"], a["audited_height"], reset, n_h)
            and a["change"] in ("new", "update")}
    c = min(len(urls), C_CAP)
    entries = []
    for finding in case["confirmed"]:
        if not record_in_scope(finding["height"], finding["audited_height"], reset, n_h):
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
         {"height": 30, "audited_height": 28, "url": "https://site.example/a", "change": "new"},
         {"height": 40, "audited_height": 38, "url": "https://site.example/a", "change": "update"},
         {"height": 50, "audited_height": 48, "url": "https://site.example/b", "change": "update"},
         {"height": 60, "audited_height": 58, "url": "https://site.example/c", "change": "attest"},
         {"height": 70, "audited_height": 68, "url": "https://site.example/d", "change": "delete"}],
     "confirmed": [
         {"height": 80, "audited_height": 78, "sealed_at_s": 100 * DAY_S, "delta_id": "sha256:bb", "severity": 2},
         {"height": 81, "audited_height": 78, "sealed_at_s": 100 * DAY_S, "delta_id": "sha256:aa", "severity": 3},
         {"height": 90, "audited_height": 88, "sealed_at_s": 120 * DAY_S, "delta_id": "sha256:cc", "severity": 1}]},
    {"label": "reset-rescopes-everything",
     "resets": [55], "n": {"height": 100, "sealed_at_s": 130 * DAY_S},
     "accepted": [{"height": 10, "sealed_at_s": 100 * DAY_S},
                  {"height": 60, "sealed_at_s": 120 * DAY_S}],
     "consistent_audits": [
         {"height": 50, "audited_height": 48, "url": "https://site.example/a", "change": "new"},
         {"height": 70, "audited_height": 68, "url": "https://site.example/b", "change": "new"}],
     "confirmed": [
         {"height": 55, "audited_height": 53, "sealed_at_s": 110 * DAY_S, "delta_id": "sha256:aa", "severity": 3},
         {"height": 90, "audited_height": 88, "sealed_at_s": 125 * DAY_S, "delta_id": "sha256:bb", "severity": 1}]},
    {"label": "reset-with-nothing-after",
     "resets": [90], "n": {"height": 100, "sealed_at_s": 130 * DAY_S},
     "accepted": [{"height": 10, "sealed_at_s": 100 * DAY_S}],
     "consistent_audits": [
         {"height": 30, "audited_height": 28, "url": "https://site.example/a", "change": "new"}],
     "confirmed": [
         {"height": 80, "audited_height": 78, "sealed_at_s": 100 * DAY_S, "delta_id": "sha256:aa", "severity": 3}]},
    {"label": "audits-straddling-a-reset",
     "resets": [55], "n": {"height": 100, "sealed_at_s": 130 * DAY_S},
     "accepted": [{"height": 50, "sealed_at_s": 100 * DAY_S},
                  {"height": 56, "sealed_at_s": 120 * DAY_S}],
     "consistent_audits": [
         {"height": 58, "audited_height": 50, "url": "https://site.example/a", "change": "new"},
         {"height": 58, "audited_height": 56, "url": "https://site.example/b", "change": "update"},
         {"height": 57, "audited_height": 57, "url": "https://site.example/c", "change": "new"}],
     "confirmed": [
         {"height": 60, "audited_height": 50, "sealed_at_s": 121 * DAY_S, "delta_id": "sha256:aa", "severity": 3},
         {"height": 60, "audited_height": 57, "sealed_at_s": 121 * DAY_S, "delta_id": "sha256:bb", "severity": 1},
         {"height": 54, "audited_height": 50, "sealed_at_s": 119 * DAY_S, "delta_id": "sha256:cc", "severity": 2}]},
    {"label": "excluded-first-delta-still-ages",
     "resets": [], "n": {"height": 100, "sealed_at_s": 130 * DAY_S},
     "accepted": [{"height": 10, "sealed_at_s": 100 * DAY_S, "excluded": True},
                  {"height": 20, "sealed_at_s": 110 * DAY_S, "excluded": False}],
     "consistent_audits": [], "confirmed": []},
    {"label": "delta-sealed-at-the-reset-height",
     "resets": [55], "n": {"height": 100, "sealed_at_s": 130 * DAY_S},
     "accepted": [{"height": 54, "sealed_at_s": 118 * DAY_S},
                  {"height": 55, "sealed_at_s": 120 * DAY_S},
                  {"height": 70, "sealed_at_s": 125 * DAY_S}],
     "consistent_audits": [
         {"height": 58, "audited_height": 54, "url": "https://site.example/a", "change": "new"},
         {"height": 58, "audited_height": 55, "url": "https://site.example/b", "change": "new"}],
     "confirmed": [
         {"height": 60, "audited_height": 55, "sealed_at_s": 121 * DAY_S, "delta_id": "sha256:aa", "severity": 3},
         {"height": 60, "audited_height": 54, "sealed_at_s": 121 * DAY_S, "delta_id": "sha256:bb", "severity": 2}]},
]
for case in derivation_scenarios:
    case["expected"] = derive_inputs(case)
    if case["label"] == "excluded-first-delta-still-ages":
        assert case["expected"]["a_days"] == 30, "age dates from the excluded Delta"
        materialized_only = dict(case, accepted=[d for d in case["accepted"] if not d["excluded"]])
        assert derive_inputs(materialized_only)["a_days"] == 20, "the ruled-out reading must differ"

write_json(WIST4 / "derivation.json", spaced_labels({
    "note": "WIST-4 §6.1/§6.3 inputs derived from one domain's Log events. A Record's audited_height is the sealing height of its audited_delta; a Delta sealed at the reset height R is the fresh identity's. penalty_inputs rows are [severity, t_days]. An accepted Delta flagged `excluded` is kept out of materialization by WIST-3 §7's one-URL, one-Publisher rule and still ages the domain.",
    "c_cap": C_CAP,
    "cases": derivation_scenarios,
}))


def within_days_ending_at(t_s, end_s, days):
    return t_s <= end_s and end_s - t_s < days * DAY_S


def pair_status(selected, recorded, attested):
    if not selected:
        return "discharged" if attested else "failed"
    return "discharged" if all(d in recorded for d in selected) else "failed"


DISCHARGING_VOIDS = {"removed after anchor block", "coverage failure at sealing",
                     "malformed as evidence"}


def void_record_discharges(voids):
    """§3, §10: a Record void only for a removal after the Block its duty is
    anchored to, for coverage failure, or as malformed evidence still
    discharges the duty; any reason under which no duty existed discharges
    nothing, whatever else is also true of the Record."""
    return all(v in DISCHARGING_VOIDS for v in voids)


def duty_anchor_s(named_by, audited_s, trigger_s):
    """§4: the Block a duty is anchored to — the audited Block for a VRF
    selection, B₁ for a Delta the extension rule names."""
    return trigger_s if named_by == "extension" else audited_s


def removal_void(named_by, audited_s, trigger_s, removed_s):
    """§10: which WIST4-E01 case a removal puts a Record in, read at the
    anchor Block — held there and removed after is the carve-out, removed
    at or before it is a key never admitted at that Block."""
    anchor_s = duty_anchor_s(named_by, audited_s, trigger_s)
    return "removed after anchor block" if removed_s > anchor_s \
        else "never admitted at anchor block"


def pair_counts(attestation, chain_gap_in_window):
    if attestation == "unmet":
        return True
    if attestation == "unmet-chain-contradicted":
        return False
    assert attestation == "missing"
    return True


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
    {"label": label, "attestation": att, "chain_gap_in_window": chain,
     "counts": pair_counts(att, chain)}
    for label, att, chain in [
        ("attested-unmet-counts", "unmet", False),
        ("chain-contradiction-stops-count", "unmet-chain-contradicted", False),
        ("unattested-counts", "missing", False),
        ("bare-chain-gap-does-not-exclude-unattested", "missing", True),
        ("bare-chain-gap-does-not-shield-attested", "unmet", True),
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
coverage_discharge_cases = [
    {"label": label, "void": voids, "discharges": void_record_discharges(voids)}
    for label, voids in [
        ("standing-record", []),
        ("removed-after-the-anchor-block", ["removed after anchor block"]),
        ("in-coverage-failure-at-sealing", ["coverage failure at sealing"]),
        ("malformed-as-evidence", ["malformed as evidence"]),
        ("never-admitted-at-the-anchor-block", ["never admitted at anchor block"]),
        ("proof-gives-no-standing", ["proof without standing"]),
        ("outside-the-selection-domain", ["outside selection domain"]),
        ("self-audit", ["self audit"]),
        ("both-carve-outs", ["removed after anchor block", "coverage failure at sealing"]),
        ("malformed-beside-a-carve-out", ["malformed as evidence", "coverage failure at sealing"]),
        ("carve-out-beside-a-no-duty-case", ["removed after anchor block", "self audit"]),
        ("malformed-beside-a-no-duty-case", ["malformed as evidence", "never admitted at anchor block"]),
    ]
]
AUDITED_S, TRIGGER_S = 100 * DAY_S, 101 * DAY_S
coverage_anchor_cases = [
    {"label": label, "named_by": named_by, "audited_sealed_at_s": AUDITED_S,
     "trigger_sealed_at_s": TRIGGER_S, "removed_at_s": removed_s,
     "void": removal_void(named_by, AUDITED_S, TRIGGER_S, removed_s),
     "discharges": void_record_discharges(
         [removal_void(named_by, AUDITED_S, TRIGGER_S, removed_s)])}
    for label, named_by, removed_s in [
        ("draw-removed-after-the-audited-block", "draw", AUDITED_S + HOUR_S),
        ("draw-removed-at-the-audited-block", "draw", AUDITED_S),
        ("extension-removed-after-b1", "extension", TRIGGER_S + HOUR_S),
        ("extension-removed-between-the-audited-block-and-b1", "extension", TRIGGER_S - HOUR_S),
        ("extension-removed-at-b1", "extension", TRIGGER_S),
    ]
]
assert [c["discharges"] for c in coverage_anchor_cases] == [True, False, True, False, False], \
    "anchor cases drifted"


def signature_void(signed_under, record_block_key, duty_block_key):
    """§3, §4: a Record's signature reads the key held at its own Block; its
    proof reads the key admitted at the duty's Block. Signed under the key
    held at its Block it stands; signed under the duty Block's key after
    that key was removed it is void by the carve-out and still discharges;
    signed under a key never admitted at the duty Block it discharges
    nothing."""
    if signed_under == record_block_key:
        return None
    if signed_under == duty_block_key:
        return "removed after anchor block"
    return "never admitted at anchor block"


coverage_signature_cases = [
    {"label": label, "duty_block_key": duty, "record_block_key": at_record,
     "signed_under": signed, "proof_under": duty,
     "void": signature_void(signed, at_record, duty),
     "counts": signature_void(signed, at_record, duty) is None,
     "discharges": void_record_discharges(
         [] if signature_void(signed, at_record, duty) is None
         else [signature_void(signed, at_record, duty)])}
    for label, duty, at_record, signed in [
        ("steady-key-signs-and-proves", "k0", "k0", "k0"),
        ("rotated-record-signed-under-the-new-key-with-the-old-proof", "k0", "k1", "k1"),
        ("rotated-record-signed-under-the-removed-duty-key", "k0", "k1", "k0"),
        ("exited-auditor-signs-under-the-removed-duty-key", "k0", None, "k0"),
        ("signed-under-a-key-never-admitted", "k0", "k1", "k2"),
    ]
]
assert [(c["counts"], c["discharges"]) for c in coverage_signature_cases] == \
    [(True, True), (True, True), (False, True), (False, True), (False, False)], \
    "signature cases drifted"


# The establishing height: the height from which a failed duty enters the §4
# count — the attestation's Block, or the record_seal_blocks-th Block sealed
# after the coverage deadline. The vector runs a one-hour cadence and its own
# record_seal_blocks so the Block list stays readable.
COVERAGE_DEADLINE_HOURS = 72
VECTOR_RECORD_SEAL_BLOCKS = 4


def unattested_height(blocks, deadline_s, record_seal_blocks):
    after = [b for b in blocks if b["sealed_at_s"] > deadline_s]
    if len(after) < record_seal_blocks:
        return None
    return after[record_seal_blocks - 1]["height"]


def establishing_height(blocks, deadline_s, attestation_height, record_seal_blocks):
    """§4: the earlier of the two evidence heights the Log carries — the
    attestation's Block, or the record_seal_blocks-th Block after the
    deadline. A party reading the Log between the two carries only the
    unattested rule's evidence, and an attestation sealed later confirms
    a failure already counted from that height."""
    evidence = [h for h in (attestation_height,
                            unattested_height(blocks, deadline_s, record_seal_blocks))
                if h is not None]
    return min(evidence) if evidence else None


def failure_counts_at(establishing, audited_sealed_at_s, n_height, n_sealed_at_s):
    return (establishing is not None and establishing <= n_height
            and within_days_ending_at(audited_sealed_at_s, n_sealed_at_s, RATION_WINDOW_DAYS))


def hourly_block(height):
    return {"height": height, "sealed_at_s": height * HOUR_S}


AUDITED = hourly_block(100)
DEADLINE_S = AUDITED["sealed_at_s"] + COVERAGE_DEADLINE_HOURS * HOUR_S
coverage_establishing_scenarios = [
    ("attested-unmet-establishes-at-the-attestation",
     [hourly_block(h) for h in range(170, 185)], 174, [173, 174, 175, 176, 177]),
    ("a-later-attestation-confirms-the-unattested-failure-and-moves-nothing",
     [hourly_block(h) for h in range(170, 185)], 180, [175, 176, 179, 180, 181]),
    ("unattested-establishes-record-seal-blocks-after-the-deadline",
     [hourly_block(h) for h in range(170, 185)], None, [172, 175, 176, 177]),
    ("deadline-not-yet-passed-by-record-seal-blocks",
     [hourly_block(h) for h in range(170, 176)], None, [174, 175]),
    ("evidence-outside-the-window-counts-at-no-height",
     [hourly_block(h) for h in range(817, 825)], 820, [819, 820, 824]),
]
coverage_establishing_cases = []
for label, blocks, attestation_height, probes in coverage_establishing_scenarios:
    establishing = establishing_height(
        blocks, DEADLINE_S, attestation_height, VECTOR_RECORD_SEAL_BLOCKS)
    coverage_establishing_cases.append({
        "label": label,
        "audited_block": AUDITED,
        "coverage_deadline_hours": COVERAGE_DEADLINE_HOURS,
        "coverage_deadline_s": DEADLINE_S,
        "record_seal_blocks": VECTOR_RECORD_SEAL_BLOCKS,
        "blocks": blocks,
        "attestation_height": attestation_height,
        "establishing_height": establishing,
        "counts_at": [
            {"height": h, "sealed_at_s": h * HOUR_S,
             "counts": failure_counts_at(establishing, AUDITED["sealed_at_s"], h, h * HOUR_S)}
            for h in probes
        ],
    })
assert [c["establishing_height"] for c in coverage_establishing_cases] == [174, 176, 176, None, 820], \
    "establishing heights drifted"
assert [p["counts"] for p in coverage_establishing_cases[1]["counts_at"]] == \
    [False, True, True, True, True], "a later attestation must move nothing"
assert not any(p["counts"] for p in coverage_establishing_cases[4]["counts_at"]), \
    "evidence past the window must count at no height"


# prev_record is per (Auditor, Log): one Auditor publishing into two Logs
# chains each Log's items to each other, so neither Log sees a gap it cannot
# attribute. Under the ruled-out global-publication-order reading both Logs
# see a permanent gap, which the amnesty rule turns into a permanent amnesty.
def chain_gap(sealed, prev_of):
    ids = {item for item in sealed}
    return any(prev_of[item] is not None and prev_of[item] not in ids for item in sealed)


chain_publications = [
    {"id": "sha256:p1", "log": "log-a"},
    {"id": "sha256:p2", "log": "log-b"},
    {"id": "sha256:p3", "log": "log-a"},
    {"id": "sha256:p4", "log": "log-b"},
    {"id": "sha256:p5", "log": "log-a"},
]
per_log_prev, global_prev, last_per_log, last_global = {}, {}, {}, None
for item in chain_publications:
    per_log_prev[item["id"]] = last_per_log.get(item["log"])
    global_prev[item["id"]] = last_global
    last_per_log[item["log"]] = item["id"]
    last_global = item["id"]

coverage_chain_scope_cases = []
for label, suppressed in [("nothing-suppressed", []), ("log-a-suppresses-one-item", ["sha256:p3"])]:
    logs = []
    for log_id in ("log-a", "log-b"):
        sealed = [item["id"] for item in chain_publications
                  if item["log"] == log_id and item["id"] not in suppressed]
        logs.append({
            "log": log_id,
            "sealed": sealed,
            "chain_gap": chain_gap(sealed, per_log_prev),
            "chain_gap_under_global_publication_order": chain_gap(sealed, global_prev),
        })
    coverage_chain_scope_cases.append({
        "label": label,
        "publications": chain_publications,
        "suppressed": suppressed,
        "prev_record": per_log_prev,
        "prev_record_under_global_publication_order": global_prev,
        "logs": logs,
    })
assert [l["chain_gap"] for c in coverage_chain_scope_cases for l in c["logs"]] \
    == [False, False, True, False], "chain scope cases drifted"
assert all(l["chain_gap_under_global_publication_order"]
           for l in coverage_chain_scope_cases[0]["logs"]), \
    "the global-order reading must show the gap the per-Log rule rules out"

late_discharge_cases = []
for label, selected_deltas, records, coverage_height, pull_height in (
    ("unmet pull then late complete Record", ["delta a"], [(100, "delta a", [])], None, 80),
    ("fallback then late complete Record", ["delta a"], [(100, "delta a", [])], None, None),
    ("partial completion remains failed", ["delta a", "delta b"], [(100, "delta a", []), (103, "delta b", [])], None, 80),
    ("invalid Record cannot discharge", ["delta a"], [(100, "delta a", ["bad_vrf_proof"])], None, 80),
    ("empty selection late coverage attestation", [], [], 100, 80),
):
    entries = [{"sealed_height": h, "delta": d, "void": voids} for h, d, voids in records]
    establishing = min(96, pull_height) if pull_height is not None else 96
    probes = []
    for n in (79, 80, 95, 96, 99, 100, 102, 103):
        held = {e["delta"] for e in entries if e["sealed_height"] <= n and void_record_discharges(e["void"])}
        complete = set(selected_deltas) <= held if selected_deltas else coverage_height is not None and coverage_height <= n
        probes.append({"height": n, "complete": complete,
                       "counts": establishing <= n and not complete})
    late_discharge_cases.append({"label": label, "audited_height": 0,
        "deadline_height": 72, "record_seal_blocks": 24, "pull_height": pull_height,
        "selected": selected_deltas, "records": entries, "coverage_attestation_height": coverage_height,
        "probes": probes})

attribution_cases = []
for label, found, successor_auditor, successor_log, successor_height, missing_arrives, expected in (
    ("related missing predecessor", ["missing a"], AUD_A, "log a", 81, None, True),
    ("unrelated missing predecessor", ["missing b"], AUD_A, "log a", 81, None, False),
    ("empty receipt supplies no attribution", [], AUD_A, "log a", 81, None, False),
    ("another Auditor cannot contradict", ["missing a"], AUD_B, "log a", 81, None, False),
    ("another Log cannot contradict", ["missing a"], AUD_A, "log b", 81, None, False),
    ("successor in pull Block qualifies", ["missing a"], AUD_A, "log a", 80, None, True),
    ("successor before pull does not contradict", ["missing a"], AUD_A, "log a", 79, None, False),
    ("missing predecessor arrives", ["missing a"], AUD_A, "log a", 81, 90, False),
    ("future successor supplies no proof", ["missing a"], AUD_A, "log a", 91, None, False),
):
    attributable = (successor_auditor == AUD_A and successor_log == "log a"
                    and 80 <= successor_height <= 90 and "missing a" in found
                    and (missing_arrives is None or missing_arrives > 90))
    assert attributable == expected
    attribution_cases.append({"label": label, "auditor": AUD_A, "log": "log a",
        "pull": {"height": 80, "found": found},
        "successor": {"auditor": successor_auditor, "log": successor_log,
                      "height": successor_height, "prev_record": "missing a"},
        "predecessor_sealed_height": missing_arrives, "n_height": 90,
        "chain_contradicts": attributable})

fabricated_predecessor = "sha256:" + sha256_hex(b"fabricated predecessor label")
suppression_empty_hash = "sha256:" + sha256_hex(empty_canonical)
suppression_successor = sign_envelope_with(priv2, "update", {"wist_version": "1.0.0",
    "action": "coverage_attestation", "subject": "audit.sample.net", "effective_at": "2026-08-05T12:00:00Z",
    "details": {"block": suppression_empty_hash, "prev_record": fabricated_predecessor,
        "vrf_proof": ecvrf.prove(SEED2, bytes.fromhex(suppression_empty_hash[7:])).hex()}}, "receipt-auditor-k1")
suppression_receipt_cases = []
for label, found, expected in (
    ("fabricated predecessor without receipt", None, False),
    ("Aggregator acknowledged missing ID", [fabricated_predecessor], True),
    ("receipt names another ID", ["sha256:" + "2" * 64], False),
    ("receipt reports empty path", [], False),
):
    receipt = None if found is None else sign_envelope("update", {"wist_version": "1.0.0",
        "action": "pull_attestation", "subject": "audit.sample.net", "effective_at": "2026-08-05T12:00:00Z",
        "details": {"block": block_hash, "found": found}}, "test-agg-k1")
    exempt = receipt is not None and fabricated_predecessor in found
    assert exempt == expected
    suppression_receipt_cases.append({"label": label, "receipt": receipt, "exempt": exempt})

# ------------------------------------ WIST-4 §4: attestation eligibility
# Signed pull and coverage attestations under supplied duty contexts: the
# §9.1 Envelope partition, the signing rule each class fixes, the named
# Block and duty, and the proof a coverage attestation must verify.
ATTESTATION_LOG_KEY = {"key_id": "test-agg-k1", "public_key": b64u(pub_raw)}
ATTESTATION_AUDITORS = [
    {"auditor_id": "audit.sample.net", "key_id": "receipt-auditor-k1", "public_key": b64u(pub2_raw)},
    {"auditor_id": "checker.sample.org", "key_id": "checker-k1", "public_key": b64u(pub3_raw)},
]
ATTESTATION_DUTY_BLOCK = block_hash
ATTESTATION_OTHER_BLOCK = suppression_empty_hash


def attestation_case(label, action, code, effect, *, signer=priv2, key_id="receipt-auditor-k1",
                     subject="audit.sample.net", block=None, found=None, proof_seed=SEED2,
                     proof_block=None, prev_record=None, version="1.0.0", extra=None,
                     drop=(), block_sealed_below=True, subject_admitted=True,
                     key_held_at_block=True, key_held_at_duty_block=False, duty_set_empty=True,
                     raw=None):
    block = ATTESTATION_DUTY_BLOCK if block is None else block
    details = {"block": block}
    if action == "pull_attestation":
        details["found"] = [] if found is None else found
        signer, key_id = priv, ATTESTATION_LOG_KEY["key_id"]
    else:
        proof_block = block if proof_block is None else proof_block
        details["vrf_proof"] = ecvrf.prove(proof_seed, bytes.fromhex(proof_block[7:])).hex()
        details["prev_record"] = prev_record
    for name in drop:
        details.pop(name)
    update = {"wist_version": version, "action": action, "subject": subject,
              "effective_at": "2026-08-05T12:00:00Z", "details": details}
    if extra:
        update.update(extra)
    doc = sign_envelope_with(signer, "update", update, key_id)
    text = json.dumps(doc, ensure_ascii=True) if raw is None else raw(json.dumps(doc, ensure_ascii=True))
    return {"label": label, "action": action, "envelope_json": text,
            "context": {"block_sealed_below": block_sealed_below, "subject_admitted_at_block": subject_admitted,
                        "key_held_at_block": key_held_at_block,
                        "key_held_at_duty_block": key_held_at_duty_block,
                        "duty_set_empty": duty_set_empty},
            "code": code, "effect": effect}


attestation_cases = [
    attestation_case("valid pull attestation", "pull_attestation", None, "attested"),
    attestation_case("pull signed by an Auditor key", "pull_attestation", "WIST4-E11", "ignored",
                     raw=lambda s: s),
    attestation_case("pull unsupported major", "pull_attestation", "WIST4-E11", "ignored", version="2.0.0"),
    attestation_case("pull unknown member", "pull_attestation", "WIST4-E11", "ignored", extra={"note": "x"}),
    attestation_case("pull one label subject", "pull_attestation", "WIST4-E04", "ignored", subject="localhost"),
    attestation_case("pull malformed found ID", "pull_attestation", "WIST4-E04", "ignored", found=["not an id"]),
    attestation_case("pull missing found", "pull_attestation", "WIST4-E04", "ignored", drop=("found",)),
    attestation_case("pull names a Block not sealed below", "pull_attestation", "WIST4-E04", "ignored",
                     block_sealed_below=False),
    attestation_case("pull for a subject without a duty", "pull_attestation", "WIST4-E04", "ignored",
                     subject_admitted=False),
    attestation_case("unauthentic pull naming an unsealed Block", "pull_attestation", "WIST4-E11", "ignored",
                     block_sealed_below=False, raw=lambda s: s),
    attestation_case("valid coverage attestation discharges an empty duty set", "coverage_attestation", None,
                     "discharged"),
    attestation_case("coverage attestation for a nonempty duty set reveals the draw", "coverage_attestation",
                     None, "draw", duty_set_empty=False),
    attestation_case("coverage attestation with a predecessor", "coverage_attestation", None, "discharged",
                     prev_record="sha256:" + "3" * 64),
    attestation_case("coverage attestation missing prev_record", "coverage_attestation", "WIST4-E04", "ignored",
                     drop=("prev_record",)),
    attestation_case("coverage attestation prev_record not an ID", "coverage_attestation", "WIST4-E04",
                     "ignored", prev_record="predecessor"),
    attestation_case("coverage attestation malformed proof", "coverage_attestation", "WIST4-E04", "ignored",
                     raw=lambda s: s.replace('"vrf_proof": "', '"vrf_proof": "0', 1)),
    attestation_case("coverage attestation proof under another key", "coverage_attestation", "WIST4-E01",
                     "ignored", proof_seed=SEED3),
    attestation_case("coverage attestation proof over another Block", "coverage_attestation", "WIST4-E01",
                     "ignored", proof_block=ATTESTATION_OTHER_BLOCK),
    attestation_case("coverage attestation signed by another Auditor", "coverage_attestation", "WIST4-E11",
                     "ignored", signer=priv3, key_id="checker-k1"),
    attestation_case("coverage attestation under the duty Block key after removal", "coverage_attestation",
                     None, "discharged", key_held_at_block=False, key_held_at_duty_block=True),
    attestation_case("coverage attestation under a key held at neither Block", "coverage_attestation",
                     "WIST4-E11", "ignored", key_held_at_block=False, key_held_at_duty_block=False),
    attestation_case("coverage attestation for a subject without a duty", "coverage_attestation", "WIST4-E04",
                     "ignored", subject_admitted=False),
    attestation_case("coverage attestation naming a Block not sealed below", "coverage_attestation",
                     "WIST4-E04", "ignored", block_sealed_below=False),
    attestation_case("unauthentic coverage attestation with a failing proof", "coverage_attestation",
                     "WIST4-E11", "ignored", signer=priv3, key_id="checker-k1", proof_seed=SEED3),
]
# the two pull cases marked with an identity `raw` are re-signed under the wrong key below
for case in attestation_cases:
    if case["label"] in ("pull signed by an Auditor key", "unauthentic pull naming an unsealed Block"):
        doc = json.loads(case["envelope_json"])
        case["envelope_json"] = json.dumps(sign_envelope_with(priv2, "update", doc["update"], "receipt-auditor-k1"),
                                           ensure_ascii=True)
assert len({c["label"] for c in attestation_cases}) == len(attestation_cases)


# ------------------------------------ WIST-4 §4: removal for coverage failure
REMOVAL_COUNTING = [{"height": h, "block_hash": "sha256:" + sha256_hex(f"failed duty block {h}".encode())}
                    for h in (3, 7, 11, 19, 23)]
removal_evidence = sorted(b["block_hash"] for b in REMOVAL_COUNTING)
removal_envelope = sign_envelope("update", {"wist_version": "1.0.0", "action": "auditor_remove",
    "subject": "audit.sample.net", "effective_at": "2026-08-05T12:00:00Z",
    "details": {"key_id": "receipt-auditor-k1"}, "evidence": removal_evidence}, "test-agg-k1")
removal_cases = [{
    "label": "coverage failure removal names the counting Blocks",
    "head": {"height": 120, "sealed_at_s": 120 * HOUR_S},
    "held_key_id": "receipt-auditor-k1",
    "counting_duties": REMOVAL_COUNTING,
    "envelope_json": json.dumps(removal_envelope, ensure_ascii=True),
    "record_id_twin": "sha256:" + sha256_hex(b"a Record ID is not a failed Block"),
}]


# ---------------------------------------- WIST-4 §4: what the sealed prefix decides
def derivation_probe_counts(case, height, *, prefix_before_block=False, exemption_only_if_attested=False,
                            unauthentic_successor_contradicts=False):
    """Whether the pair counts at `height` under the chosen reading; the
    keyword flags select the readings the vector rules out."""
    established = [h for h in (case.get("pull_height"), case["fallback_height"]) if h is not None]
    established = min(established) if established else None
    if established is None or established > height:
        return False
    if case.get("complete_at") is not None and case["complete_at"] <= height:
        return False
    pull = case.get("pull_height")
    successor = case.get("successor")
    if pull is not None and successor is not None and pull <= height and pull <= successor["height"] <= height \
            and successor["names_found"] and (successor["authentic"] or unauthentic_successor_contradicts) \
            and not (exemption_only_if_attested and case["fallback_height"] < pull):
        return False
    return True


derivation_cases = []
for label, case, probes in (
    ("silent pair fails without a draw",
     {"duty_height": 5, "proof_sealed": False, "pull_height": None, "fallback_height": 101, "complete_at": None},
     [100, 101, 130]),
    ("fallback then contradicted attestation exempts",
     {"duty_height": 5, "proof_sealed": False, "pull_height": 105, "fallback_height": 101, "complete_at": None,
      "successor": {"height": 106, "names_found": True, "authentic": True}},
     [101, 104, 105, 106, 130]),
    ("unauthentic successor supplies no exemption",
     {"duty_height": 5, "proof_sealed": False, "pull_height": 80, "fallback_height": 101, "complete_at": None,
      "successor": {"height": 81, "names_found": True, "authentic": False}},
     [79, 80, 90]),
):
    derivation_cases.append({"label": label, **case,
                             "probes": [{"height": h, "counts": derivation_probe_counts(case, h)} for h in probes]})
assert [[p["counts"] for p in c["probes"]] for c in derivation_cases] == \
    [[False, True, True], [True, True, True, False, False], [False, True, True]], "derivation cases drifted"
same_block_case = {
    "label": "same Block discharge is read before the Block's Records are weighed",
    "coverage_failures_max": COVERAGE_FAILURES_MAX,
    "counting_duty_heights_before_block": list(range(0, 25)),
    "block_height": 121,
    "completed_in_block": [0, 1],
    "in_coverage_failure_at_block": False,
    "in_coverage_failure_under_prior_prefix_reading": True,
}
assert len(same_block_case["counting_duty_heights_before_block"]) - len(same_block_case["completed_in_block"]) \
    <= COVERAGE_FAILURES_MAX < len(same_block_case["counting_duty_heights_before_block"])

write_json(WIST4 / "coverage.json", spaced_labels({
    "note": "WIST-4 §4 coverage-failure counting: pair status, the count at Block N, the coverage-failure state, which void Records (§10) still discharge the duty — `void` lists every reason the Record is void, empty for a standing Record — per anchor case the Block a removal is read against (the audited Block for a draw, B₁ for a Delta the extension rule names), the establishing height from which a failed duty enters the count — the earlier of the attestation's Block and the record_seal_blocks-th Block after the deadline, read from the Log up to N and never from an attestation sealed above it — and the per-(Auditor, Log) `prev_record` chain. A gap alone supplies no exemption. The establishing cases run a one-hour Block cadence and their own `record_seal_blocks` so the Block list stays readable; `chain_gap_under_global_publication_order` is the ruled-out reading, present so a harness can check the two disagree.",
    "coverage_deadline_hours": 72,
    "coverage_failures_max": COVERAGE_FAILURES_MAX,
    "record_seal_blocks": 24,
    "window_days": RATION_WINDOW_DAYS,
    "pair_cases": coverage_pair_cases,
    "counting_cases": coverage_counting_cases,
    "authenticated_gap": {"note": "The successor is sealed after the receipts in the same Log; its named predecessor is absent. The original pair is established and incomplete. The successor covers a different, empty Block, so it does not discharge that pair.",
        "keys": [{"key_id": "receipt-auditor-k1", "public_key": b64u(pub2_raw)}, {"key_id": "test-agg-k1", "public_key": b64u(pub_raw)}],
        "pulled_block": block_hash, "successor": suppression_successor, "cases": suppression_receipt_cases},
    "state_cases": coverage_state_cases,
    "discharge_cases": coverage_discharge_cases,
    "anchor_cases": coverage_anchor_cases,
    "signature_cases": coverage_signature_cases,
    "establishing_cases": coverage_establishing_cases,
    "chain_scope_cases": coverage_chain_scope_cases,
    "late_discharge_cases": late_discharge_cases,
    "attribution_cases": attribution_cases,
    "attestation_note": ("WIST-4 §4 attestation eligibility: signed pull and coverage attestations with the "
                         "Log key, two Auditor keys, the duty Block hash and supplied contexts saying whether "
                         "the named Block is sealed below the attestation, whether the subject held a duty "
                         "there, which Blocks the signing key was held at, and whether the duty set is empty; "
                         "`code` is the §9.1/§10.2 diagnostic and `effect` what an accepted attestation does."),
    "attestation_log_key": ATTESTATION_LOG_KEY,
    "attestation_auditors": ATTESTATION_AUDITORS,
    "attestation_duty_block": ATTESTATION_DUTY_BLOCK,
    "attestation_cases": attestation_cases,
    "derivation_note": ("WIST-4 §4 readings of the sealed prefix: a pair with no verifying proof sealed by its "
                        "Auditor is failed; an attested pair is exempt while contradicted even when the "
                        "fallback established it first; only an authentic successor contradicts; and the "
                        "coverage-failure state at a Block reads that Block's own discharges before its "
                        "Records are weighed."),
    "derivation_cases": derivation_cases,
    "same_block_case": same_block_case,
    "removal_note": ("WIST-4 §4: the auditor_remove a coverage failure requires is Log-signed, retires the key "
                     "the Auditor holds at the removal's Block and lists as evidence the Block Hashes of every "
                     "failed duty Block counting there in ascending octet order; a Record ID is not a failed Block."),
    "removal_log_key": ATTESTATION_LOG_KEY,
    "removal_cases": removal_cases,
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


def closes_at(blocks, b1_s, window_hours):
    """WIST-4 §4: the extension closes at the first Block sealed more than
    confirm_window_hours after B₁ — from then on nothing can pair with the
    triggering Record, so what the window holds is settled."""
    window_s = window_hours * HOUR_S
    return next((b["height"] for b in blocks if b["sealed_at_s"] > b1_s + window_s), None)


def contradiction(trigger, records, blocks, summoned, window_hours):
    """WIST-4 §4: a summoning Record is contradicted when its extension
    closes with no confirmation and an independent consistent pair sealed
    inside the window (endpoint included). Records are those for the same
    Delta sealed at or after B₁, in Log order."""
    window_s = window_hours * HOUR_S
    b1_s = trigger["sealed_at_s"]
    inside = [r for r in records if b1_s <= r["sealed_at_s"] <= b1_s + window_s]
    confirmed = any(r["verdict"] == trigger["verdict"]
                    and independent(r["auditor"], trigger["auditor"]) for r in inside)
    consistent = [r for r in inside if r["verdict"] == "consistent"]
    pair = any(independent(a["auditor"], b["auditor"])
               for i, a in enumerate(consistent) for b in consistent[i + 1:])
    closes = closes_at(blocks, b1_s, window_hours)
    contradicted = summoned and not confirmed and pair and closes is not None
    return {"closes_at_height": closes, "confirmed": confirmed,
            "independent_consistent_pair": pair, "contradicted": contradicted,
            "establishing_height": closes if contradicted else None}


def escalation_in_force(establishing, n_height, n_s):
    return (establishing is not None and establishing["height"] <= n_height
            and within_days_ending_at(establishing["sealed_at_s"], n_s, RATION_WINDOW_DAYS))


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
AUD_B2 = "eye.example.org"
B1 = hourly_block(1000)
CONTRADICTION_GRID = [hourly_block(h) for h in range(1000, 1081)]


def ext_rec(auditor, verdict, hours_after_b1):
    return {"auditor": auditor, "verdict": verdict,
            "height": B1["height"] + hours_after_b1,
            "sealed_at_s": B1["sealed_at_s"] + hours_after_b1 * HOUR_S}


CONTRADICTION_TRIGGER = ext_rec(AUD_A, "inconsistent", 0)
contradiction_scenarios = [
    ("two-independent-consistent-inside-the-window", True,
     [ext_rec(AUD_B, "consistent", 40), ext_rec(AUD_C, "consistent", 60)]),
    ("confirmed-inside-the-window", True,
     [ext_rec(AUD_B, "inconsistent", 50), ext_rec(AUD_C, "consistent", 60),
      ext_rec(AUD_A2, "consistent", 61)]),
    ("consistent-pair-not-independent", True,
     [ext_rec(AUD_B, "consistent", 40), ext_rec(AUD_B2, "consistent", 60)]),
    ("second-consistent-after-the-window", True,
     [ext_rec(AUD_B, "consistent", 60), ext_rec(AUD_C, "consistent", 73)]),
    ("consistent-exactly-at-the-window-end", True,
     [ext_rec(AUD_B, "consistent", 40), ext_rec(AUD_C, "consistent", 72)]),
    ("confirming-record-exactly-at-the-window-end", True,
     [ext_rec(AUD_B, "consistent", 40), ext_rec(AUD_C, "consistent", 60),
      ext_rec(AUD_B2, "inconsistent", 72)]),
    ("confirming-record-one-block-past-the-window", True,
     [ext_rec(AUD_B, "consistent", 40), ext_rec(AUD_C, "consistent", 60),
      ext_rec(AUD_B2, "inconsistent", 73)]),
    ("rationed-out-trigger-cannot-be-contradicted", False,
     [ext_rec(AUD_B, "consistent", 40), ext_rec(AUD_C, "consistent", 60)]),
    ("consistent-sealed-in-b1-counts", True,
     [ext_rec(AUD_B, "consistent", 0), ext_rec(AUD_C, "consistent", 60)]),
]
contradiction_cases = []
for label, summoned, records in contradiction_scenarios:
    outcome = contradiction(CONTRADICTION_TRIGGER, records, CONTRADICTION_GRID,
                            summoned, CONFIRM_WINDOW_HOURS)
    establishing = (hourly_block(outcome["establishing_height"])
                    if outcome["establishing_height"] is not None else None)
    probes = [B1["height"] + 72, B1["height"] + 73,
              B1["height"] + 73 + 30 * 24 - 1, B1["height"] + 73 + 30 * 24]
    contradiction_cases.append({
        "label": label, "trigger": CONTRADICTION_TRIGGER, "summoned": summoned,
        "records": records, **outcome,
        "escalation_at": [
            {"height": h, "sealed_at_s": h * HOUR_S,
             "in_force": escalation_in_force(establishing, h, h * HOUR_S)}
            for h in probes],
    })
assert [c["contradicted"] for c in contradiction_cases] == \
    [True, False, False, False, True, False, True, False, True], "contradiction cases drifted"
assert all(c["closes_at_height"] == B1["height"] + 73 for c in contradiction_cases)
assert [p["in_force"] for p in contradiction_cases[0]["escalation_at"]] == \
    [False, True, True, False], "escalation window drifted"

extension_order_cases = []
for label, rows in (
    ("two Deltas one remaining slot", [(0, "delta a", AUD_A, "inconsistent"), (1, "delta b", AUD_A, "inconsistent")]),
    ("mixed kinds share ration", [(0, "delta a", AUD_A, "link_inconsistent"), (1, "delta b", AUD_A, "inconsistent")]),
    ("mixed kinds share Delta trigger sequence", [(0, "delta a", AUD_A, "inconsistent"), (1, "delta a", AUD_B, "link_inconsistent")]),
    ("later peer does not cancel summons", [(0, "delta a", AUD_A, "inconsistent"), (1, "delta a", AUD_B, "inconsistent")]),
):
    records = [{"block_height": 10, "entry_index": entry, "sealed_at_s": 36000,
                "delta": delta, "auditor": auditor, "verdict": verdict}
               for entry, delta, auditor, verdict in rows]
    prior_triggers = [(AUD_A, 0), (AUD_A, 3600)]
    candidates, outcomes, peers = [], [], []
    for i, r in enumerate(records):
        earlier = [e for e in records[:i] if e["delta"] == r["delta"]]
        eligible = not earlier
        candidates.append(eligible)
        attempt = prior_triggers + [(r["auditor"], r["sealed_at_s"])]
        fires = eligible and rationed_summons(attempt, 30, 3)[-1]
        outcomes.append(fires)
        if fires:
            prior_triggers.append(attempt[-1])
        peers.append([a for a in (AUD_A, AUD_B, AUD_C)
                      if fires and independent(a, r["auditor"])])
    extension_order_cases.append({"label": label, "records": records,
        "prior_triggers": [[AUD_A, 0], [AUD_A, 3600]],
        "roster": [AUD_A, AUD_B, AUD_C], "publisher_domain": "page.publisher.test",
        "eligible": candidates, "summons": outcomes, "summoned_auditors": peers})

# ------------------------------------ WIST-4 §4: only evidence counts
# A Record §3/§10.1 rejects neither triggers, suppresses, excludes nor joins a
# quorum. Each case seals signed Records in Log order for one or more Deltas;
# the checker derives every rejection from the bytes and supplied contexts
# before replaying the rule over the surviving evidence.
EVIDENCE_ROSTER = [AUD_A, AUD_A2, AUD_B, AUD_B2, AUD_C]
EVIDENCE_PUBLISHER = "www.publisher.example"
EVIDENCE_THRESHOLDS = {"similarity_consistent": 600_000, "similarity_variance_floor": 300_000,
                       "link_agreement_consistent": 600_000, "link_variance_floor": 300_000}


def evidence_private_key(auditor):
    seed = hashlib.sha256(b"extension-evidence:" + auditor.encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


EVIDENCE_KEYS = {auditor: {"key_id": auditor + "-k1",
                           "public_key": b64u(raw_public(evidence_private_key(auditor)))}
                 for auditor in EVIDENCE_ROSTER}


def evidence_delta(label):
    return "sha256:" + hashlib.sha256(("extension evidence delta " + label).encode()).hexdigest()


def evidence_scores_valid(verdict, similarity, link_agreement, th=EVIDENCE_THRESHOLDS):
    """WIST-4 §5's band table for a `new`/`modify` audit; a mismatch is the
    §3 malformed-evidence rejection."""
    if verdict == "consistent":
        return similarity >= th["similarity_consistent"] and (
            link_agreement is None or link_agreement >= th["link_agreement_consistent"])
    if verdict == "inconsistent":
        return similarity < th["similarity_variance_floor"]
    if verdict == "dynamic_variance":
        return th["similarity_variance_floor"] <= similarity < th["similarity_consistent"]
    if verdict == "link_variance":
        return similarity >= th["similarity_consistent"] and link_agreement is not None \
            and th["link_variance_floor"] <= link_agreement < th["link_agreement_consistent"]
    if verdict == "link_inconsistent":
        return similarity >= th["similarity_consistent"] and link_agreement is not None \
            and link_agreement < th["link_variance_floor"]
    return similarity is None and link_agreement is None


def evidence_record(auditor, verdict, delta, hours_after_b1, mutation="none", entry=0):
    import copy
    height = B1["height"] + hours_after_b1
    sealed_at_s = B1["sealed_at_s"] + hours_after_b1 * HOUR_S
    body = copy.deepcopy(audit_record)
    body.update(audited_delta=delta, reference_delta=delta, auditor_id=auditor, verdict=verdict,
                fetched_at=datetime.datetime.fromtimestamp(sealed_at_s, datetime.timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%SZ"))
    body["credit_commitment"] = audit_commit(RESPONSE_BODY + auditor.encode())
    if verdict == "consistent":
        body["similarity"], body["link_agreement"] = 940_000, 1_000_000
    elif verdict == "inconsistent":
        body["similarity"] = 100_000
        body.pop("link_agreement")
    elif verdict == "link_inconsistent":
        body["similarity"], body["link_agreement"] = 950_000, 100_000
    context = {"standing": True, "removed": False, "coverage_failure": False}
    rejected = []
    if mutation == "mis-scored":
        body["similarity"] = 940_000 if verdict == "inconsistent" else 250_000
        rejected = ["WIST4-E02"]
    elif mutation == "missing-evidence":
        del body["evidence_commitment"]
        rejected = ["WIST4-E02"]
    elif mutation == "unsupported-major":
        body["wist_version"] = "2.0.0"
        rejected = ["WIST4-E10"]
    elif mutation == "no-standing":
        context["standing"] = False
        rejected = ["WIST4-E01"]
    elif mutation in ("removed", "coverage-failure"):
        context[mutation.replace("-", "_")] = True
        rejected = ["WIST4-E01"]
    signer = auditor
    if mutation == "wrong-signer":
        signer = next(a for a in EVIDENCE_ROSTER if a != auditor)
        rejected = ["WIST4-E01"]
    doc = sign_envelope_with(evidence_private_key(signer), "record", body, EVIDENCE_KEYS[signer]["key_id"])
    if mutation == "forged":
        doc["sig"]["value"] = b64u(bytes(64))
        rejected = ["WIST4-E01"]
    elif mutation == "unknown-member":
        doc["unknown"] = True
        rejected = ["WIST4-E09"]
    assert mutation == "none" or rejected, mutation
    assert evidence_scores_valid(verdict, body.get("similarity"), body.get("link_agreement")) \
        == (mutation != "mis-scored")
    return {"block_height": height, "entry_index": entry, "sealed_at_s": sealed_at_s,
            "auditor": auditor, "verdict": verdict, "delta": delta, "mutation": mutation,
            "record_json": json.dumps(doc, ensure_ascii=True), "context": context,
            "rejected": rejected}


def evidence_replay(records, roster, publisher, window_hours, triggers_max, window_days,
                    count_rejected=False):
    """The extension rule over Records in Log order. Only evidence counts;
    `count_rejected` is the ruled-out reading, present for the twin."""
    counted = [r for r in records if count_rejected or not r["rejected"]]
    such = ("inconsistent", "link_inconsistent")
    summoning, eligible, summons, peers, outcomes = [], [], [], [], []
    for r in records:
        counts = count_rejected or not r["rejected"]
        prior = [e for e in counted if e["delta"] == r["delta"] and e["verdict"] in such
                 and (e["block_height"], e["entry_index"]) < (r["block_height"], r["entry_index"])]
        candidate = counts and r["verdict"] in such and not any(
            r["sealed_at_s"] - e["sealed_at_s"] <= window_hours * HOUR_S for e in prior)
        spent = sum(1 for auditor, at_s in summoning
                    if auditor == r["auditor"] and within_days_ending_at(at_s, r["sealed_at_s"], window_days))
        fires = candidate and spent < triggers_max
        filers = [e["auditor"] for e in prior] + [r["auditor"]]
        peers.append([a for a in roster if fires and independent(a, publisher)
                      and all(independent(a, f) for f in filers)])
        if fires:
            summoning.append((r["auditor"], r["sealed_at_s"]))
        eligible.append(candidate)
        summons.append(fires)
        if candidate:
            later = [e for e in counted if e["delta"] == r["delta"] and e is not r
                     and e["sealed_at_s"] >= r["sealed_at_s"]]
            outcomes.append({"record_index": records.index(r),
                             **contradiction(r, later, CONTRADICTION_GRID, fires, window_hours)})
    return eligible, summons, peers, outcomes


def evidence_case(label, rows):
    records = [evidence_record(*row) for row in rows]
    eligible, summons, peers, outcomes = evidence_replay(
        records, EVIDENCE_ROSTER, EVIDENCE_PUBLISHER, CONFIRM_WINDOW_HOURS,
        EXTENSION_TRIGGERS_MAX, RATION_WINDOW_DAYS)
    alternative = evidence_replay(
        records, EVIDENCE_ROSTER, EVIDENCE_PUBLISHER, CONFIRM_WINDOW_HOURS,
        EXTENSION_TRIGGERS_MAX, RATION_WINDOW_DAYS, count_rejected=True)
    assert (eligible, summons, peers, [o["contradicted"] for o in outcomes]) != \
        (alternative[0], alternative[1], alternative[2], [o["contradicted"] for o in alternative[3]]), label
    for r, e, s, p in zip(records, eligible, summons, peers):
        r.update(eligible=e, summons=s, summoned_auditors=p)
    return {"label": label, "records": records, "triggers": outcomes}


D0, D1, D2, D3 = (evidence_delta(x) for x in "wxyz")
evidence_cases = [
    evidence_case(f"{mutation}-filing-then-valid-trigger",
                  [(AUD_A, "inconsistent", D0, 0, mutation), (AUD_B, "inconsistent", D0, 1)])
    for mutation in ("mis-scored", "missing-evidence", "unsupported-major", "unknown-member",
                     "forged", "wrong-signer", "no-standing", "removed", "coverage-failure")
] + [
    evidence_case("rejected-link-filing-then-valid-trigger",
                  [(AUD_A, "link_inconsistent", D0, 0, "mis-scored"), (AUD_B, "inconsistent", D0, 1)]),
    evidence_case("rejected-filer-excludes-no-peer",
                  [(AUD_A, "inconsistent", D0, 0), (AUD_B, "inconsistent", D0, 50, "mis-scored"),
                   (AUD_C, "inconsistent", D0, 73)]),
    evidence_case("rejected-filing-spends-no-ration",
                  [(AUD_A, "inconsistent", D0, 0, "forged"), (AUD_A, "inconsistent", D1, 1),
                   (AUD_A, "inconsistent", D2, 2), (AUD_A, "inconsistent", D3, 3)]),
    evidence_case("rejected-consistent-joins-no-pair",
                  [(AUD_A, "inconsistent", D0, 0), (AUD_B, "consistent", D0, 40),
                   (AUD_C, "consistent", D0, 60, "unsupported-major")]),
    evidence_case("coverage-failure-consistent-joins-no-pair",
                  [(AUD_A, "inconsistent", D0, 0), (AUD_B, "consistent", D0, 40),
                   (AUD_C, "consistent", D0, 60, "coverage-failure")]),
    evidence_case("rejected-confirmation-confirms-nothing",
                  [(AUD_A, "inconsistent", D0, 0), (AUD_C, "consistent", D0, 40),
                   (AUD_B, "inconsistent", D0, 50, "mis-scored"), (AUD_B2, "consistent", D0, 60)]),
    evidence_case("forged-confirmation-confirms-nothing",
                  [(AUD_A, "inconsistent", D0, 0), (AUD_C, "consistent", D0, 40),
                   (AUD_B, "inconsistent", D0, 50, "forged"), (AUD_B2, "consistent", D0, 60)]),
]
assert [c["records"][1]["summons"] for c in evidence_cases[:10]] == [True] * 10
assert all(set(c["records"][1]["summoned_auditors"]) == {AUD_A, AUD_A2, AUD_C} for c in evidence_cases[:10])
by_label = {c["label"]: c for c in evidence_cases}
assert by_label["rejected-filer-excludes-no-peer"]["records"][2]["summoned_auditors"] == [AUD_B, AUD_B2]
assert by_label["rejected-filing-spends-no-ration"]["records"][3]["summons"]
assert [t["contradicted"] for t in by_label["rejected-consistent-joins-no-pair"]["triggers"]] == [False]
assert [t["contradicted"] for t in by_label["rejected-confirmation-confirms-nothing"]["triggers"]] == [True]

write_json(WIST4 / "extension.json", spaced_labels({
    "note": ("WIST-4 §4 extension rule: trigger, ration, summoned set, and the "
             "contradiction that escalates the audited domain's sampling. A "
             "contradiction case lists the Records for the Delta sealed at or after "
             "B₁ in Log order, the Block at which the extension closes, whether the "
             "trigger was confirmed, whether an independent consistent pair sealed "
             "inside the window, and the heights at which escalated sampling is and "
             "is not in force for the domain."),
    "confirm_window_hours": CONFIRM_WINDOW_HOURS,
    "extension_triggers_max": EXTENSION_TRIGGERS_MAX,
    "ration_window_days": RATION_WINDOW_DAYS,
    "escalation_window_days": RATION_WINDOW_DAYS,
    "deadline_cases": [
        {"b1_sealed_at_s": 1000, "confirm_window_hours": 72,
         "deadline_s": extension_deadline_s(1000, 72)},
        {"b1_sealed_at_s": 0, "confirm_window_hours": 73,
         "deadline_s": extension_deadline_s(0, 73)},
    ],
    "trigger_cases": extension_trigger_cases,
    "ration_cases": extension_ration_cases,
    "order_cases": extension_order_cases,
    "summons_cases": extension_summons_cases,
    "contradiction_blocks": CONTRADICTION_GRID,
    "contradiction_cases": contradiction_cases,
    "evidence_note": ("WIST-4 §4, only evidence counts: signed Records in Log order for one or "
                      "more Deltas, each with its signer's key, the supplied standing/removal/"
                      "coverage-failure context and the §3/§10.1 rejection a validator derives "
                      "from the bytes and that context; per Record whether it is an eligible "
                      "trigger, whether it summons, and whom; per eligible trigger the "
                      "contradiction outcome over the surviving evidence on contradiction_blocks. "
                      "fetched_at equals the Record's Block sealed_at and reference_delta the "
                      "audited Delta, so the interval and chain tests pass by construction and "
                      "are not exercised; every Record audits a `new` Delta under the default "
                      "band thresholds with no amendment in force."),
    "evidence_publisher": EVIDENCE_PUBLISHER,
    "evidence_roster": EVIDENCE_ROSTER,
    "evidence_keys": EVIDENCE_KEYS,
    "evidence_thresholds": EVIDENCE_THRESHOLDS,
    "evidence_cases": evidence_cases,
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
# A rotation between the audited Block and B₁: each Block's proof verifies
# under the key the Auditor held at that Block's sealed_at (§3), so the B₁
# proof under the audited Block's key gives no standing.
rotated_trigger_pi = ecvrf.prove(SEED2, trigger_alpha)
rotated_audited_pi = ecvrf.prove(SEED2, alpha)
STEADY = {"audited_block": b64u(pub_raw), "trigger_block": b64u(pub_raw)}
ROTATED = {"audited_block": b64u(pub_raw), "trigger_block": b64u(pub2_raw)}
write_json(WIST4 / "extension-proof.json", spaced_labels({
    "note": ("WIST-4 §3, §4: the Block an Audit Record's vrf_proof is over. "
             "audited_block carries audited_delta; trigger_block is B₁, the Block "
             "sealing the triggering Record. Each case gives the proof, the key the "
             "Auditor held at each Block's sealed_at (admitted_at), the Block the "
             "proof verifies over under that Block's key, and the standing it earns."),
    "auditor_public_key": b64u(pub_raw),
    "rotated_public_key": b64u(pub2_raw),
    "audited_delta": delta_id,
    "audited_block": {"block_hash": block_hash, "alpha_hex": alpha.hex()},
    "trigger_block": {"block_hash": "sha256:" + sha256_hex(empty_canonical),
                      "alpha_hex": trigger_alpha.hex()},
    "reputation_u": EXTENSION_REPUTATION_U,
    "cases": [
        {"label": "extension-proof-over-trigger-block", "vrf_proof_hex": trigger_pi.hex(),
         "admitted_at": STEADY,
         "named_by_extension": True, "proof_block": "trigger", "standing": "extension"},
        {"label": "audited-block-proof-unselected", "vrf_proof_hex": pi.hex(),
         "admitted_at": STEADY,
         "named_by_extension": True, "proof_block": "audited", "standing": "WIST4-E01"},
        {"label": "proof-over-neither-block", "vrf_proof_hex": neither_pi.hex(),
         "admitted_at": STEADY,
         "named_by_extension": True, "proof_block": None, "standing": "WIST4-E01"},
        {"label": "trigger-proof-but-not-summoned", "vrf_proof_hex": trigger_pi.hex(),
         "admitted_at": STEADY,
         "named_by_extension": False, "proof_block": "trigger", "standing": "WIST4-E01"},
        {"label": "rotated-between-the-blocks-proof-under-the-key-held-at-b1",
         "vrf_proof_hex": rotated_trigger_pi.hex(), "admitted_at": ROTATED,
         "named_by_extension": True, "proof_block": "trigger", "standing": "extension"},
        {"label": "rotated-between-the-blocks-b1-proof-under-the-audited-blocks-key",
         "vrf_proof_hex": trigger_pi.hex(), "admitted_at": ROTATED,
         "named_by_extension": True, "proof_block": None, "standing": "WIST4-E01"},
        {"label": "rotated-between-the-blocks-audited-proof-under-the-key-held-at-b1",
         "vrf_proof_hex": rotated_audited_pi.hex(), "admitted_at": ROTATED,
         "named_by_extension": True, "proof_block": None, "standing": "WIST4-E01"},
    ],
}))
print("wist4 extension-proof vector written")

# ------------------------------------- WIST-4 §9: which amendment is in force
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
    "note": "WIST-4 §9 value in force. changes are in Log order with sealing and effective instants; each query gives the value in force at t_s and the index of the amendment it comes from (null for the default).",
    "cases": parameter_cases,
}))
print("wist4 parameter-in-force vector written")

# --------------------------- WIST-4 §9: the coverage-countability combination
# §4 counts a failed duty from its establishing height and only while the
# audited Block is inside the 30 whole days ending at the height read, so
# the evidence lag and the span the failures occupy share one window. The
# §9 sum bounds the pair; the simulation below is the fact it stands for —
# an Auditor failing every Block, every grid point sealed, counted at every
# height — so the vector carries the reachability and not only the arithmetic.
COUNT_WINDOW_S = 30 * DAY_S


def countability_rule(cadence_s, deadline_hours, seal_blocks, failures_max):
    return deadline_hours * 3600 + (seal_blocks + failures_max) * cadence_s < COUNT_WINDOW_S


def establishing_lag(cadence_s, deadline_hours, seal_blocks):
    """The §4 height a duty establishes at: the seal_blocks-th Block sealed
    after the deadline, on a grid where every point is sealed."""
    return ((deadline_hours * 3600) // cadence_s + seal_blocks) * cadence_s


def max_counted(cadence_s, lag_s):
    lag_blocks = lag_s // cadence_s
    window_blocks = COUNT_WINDOW_S // cadence_s
    best = 0
    for n in range(lag_blocks + window_blocks + 3):
        counted = [h for h in range(max(0, n - window_blocks - 1), n - lag_blocks + 1)
                   if h >= 0 and (n - h) * cadence_s < COUNT_WINDOW_S]
        best = max(best, len(counted))
    return best


def countability_case(label, cadence_s, deadline_hours, seal_blocks, changed,
                      failures_max=24):
    unattested = establishing_lag(cadence_s, deadline_hours, seal_blocks)
    attested = establishing_lag(cadence_s, deadline_hours, 1)
    def side(lag):
        reached = max_counted(cadence_s, lag)
        return {"establishing_lag_s": lag, "max_counted_at_any_height": reached,
                "predicate_reachable": reached > failures_max}
    return {
        "label": label,
        "changed": changed,
        "block_cadence_seconds": cadence_s,
        "coverage_deadline_hours": deadline_hours,
        "record_seal_blocks": seal_blocks,
        "coverage_failures_max": failures_max,
        "sum_s": deadline_hours * 3600 + (seal_blocks + failures_max) * cadence_s,
        "rule_holds": countability_rule(cadence_s, deadline_hours, seal_blocks, failures_max),
        "deadline_on_grid": (deadline_hours * 3600) % cadence_s == 0,
        "unattested": side(unattested),
        "attested_next_block": side(attested),
    }


countability_cases = [
    countability_case("registry-defaults", 3600, 72, 24, "block_cadence_seconds"),
    countability_case("cadence-at-the-tables-maximum", 86400, 72, 24, "block_cadence_seconds"),
    countability_case("the-last-seal-deadline-the-rule-admits", 3600, 72, 623, "record_seal_blocks"),
    countability_case("one-block-past-it", 3600, 72, 624, "record_seal_blocks"),
    countability_case("a-deadline-between-two-blocks", 5000, 2, 493, "record_seal_blocks"),
    countability_case("conservative rejection with twenty five countable failures", 5000, 4, 492, "record_seal_blocks"),
    countability_case("one later seal leaves twenty four countable failures", 5000, 4, 493, "record_seal_blocks"),
]
assert [c["unattested"]["max_counted_at_any_height"] for c in countability_cases[-2:]] == [25, 24]
assert all(not c["rule_holds"] for c in countability_cases[-2:])



# §4's extension pull happens once the extension deadline passes and before
# the next Block, and seals within record_seal_blocks Blocks of the pull, the
# next Block being the first — so a Record published at the deadline seals no
# later than record_seal_blocks cadences after it. The §9 sum bounds that
# against the confirmation window; the simulation is the latest seal on a
# fully sealed grid.
def extension_window_rule(cadence_s, window_hours, seal_blocks):
    return (window_hours // 2) * 3600 + seal_blocks * cadence_s <= window_hours * 3600


def latest_extension_seal(cadence_s, window_hours, seal_blocks):
    deadline_s = (window_hours // 2) * 3600
    next_block_s = (deadline_s // cadence_s + 1) * cadence_s
    return next_block_s + (seal_blocks - 1) * cadence_s


def extension_window_case(label, cadence_s, window_hours, seal_blocks, changed):
    latest = latest_extension_seal(cadence_s, window_hours, seal_blocks)
    return {
        "label": label,
        "changed": changed,
        "block_cadence_seconds": cadence_s,
        "confirm_window_hours": window_hours,
        "record_seal_blocks": seal_blocks,
        "extension_deadline_s": (window_hours // 2) * 3600,
        "sum_s": (window_hours // 2) * 3600 + seal_blocks * cadence_s,
        "window_s": window_hours * 3600,
        "rule_holds": extension_window_rule(cadence_s, window_hours, seal_blocks),
        "latest_seal_s": latest,
        "seals_inside_window": latest <= window_hours * 3600,
    }


extension_window_cases = [
    extension_window_case("registry-defaults", 3600, 72, 24, "block_cadence_seconds"),
    extension_window_case("cadence-at-the-tables-maximum", 86400, 72, 24, "block_cadence_seconds"),
    extension_window_case("the-last-seal-deadline-the-rule-admits", 3600, 72, 36, "record_seal_blocks"),
    extension_window_case("one-block-past-it", 3600, 72, 37, "record_seal_blocks"),
    extension_window_case("a-deadline-between-two-blocks", 5000, 73, 26, "block_cadence_seconds"),
]
assert [c["rule_holds"] for c in extension_window_cases] == [True, False, True, False, True]
assert all(c["rule_holds"] == c["seals_inside_window"] for c in extension_window_cases
           if c["extension_deadline_s"] % c["block_cadence_seconds"] == 0)

PROSPECTIVE_DEFAULTS = {"sampling_floor": 200_000, "sampling_ceiling": 5_000_000}


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
        valid = candidate["value"] >= 1 and candidate["effective_at_s"] >= candidate["sealed_at_s"] + 7 * DAY_S
        for instant in instants:
            values = prospective_map(tentative, instant)
            valid = valid and values["sampling_floor"] <= values["sampling_ceiling"]
        if valid:
            accepted.append(candidate)
        else:
            rejected.append(i)
    return sorted(rejected), accepted


prospective_cases = []
for label, rows, rejected in (
    ("pending floor then incompatible ceiling", [(0, 0, "sampling_floor", 4_000_000, 10), (1, 0, "sampling_ceiling", 3_000_000, 11)], [1]),
    ("later activation sealed first", [(0, 0, "sampling_ceiling", 3_000_000, 20), (1, 0, "sampling_floor", 4_000_000, 10)], [1]),
    ("invalid future after earlier activation", [(0, 0, "sampling_floor", 4_000_000, 20), (1, 0, "sampling_ceiling", 3_000_000, 10)], [1]),
    ("intermediate replacement makes schedule valid", [(0, 0, "sampling_floor", 4_000_000, 10), (1, 0, "sampling_floor", 2_000_000, 11), (2, 0, "sampling_ceiling", 3_000_000, 12)], []),
    ("same effective time conflicts", [(0, 0, "sampling_floor", 4_000_000, 10), (1, 0, "sampling_ceiling", 3_000_000, 10)], [1]),
    ("rejected candidate is not retried", [(0, 0, "sampling_floor", 4_000_000, 10), (1, 0, "sampling_ceiling", 3_000_000, 10), (2, 0, "sampling_floor", 2_000_000, 10)], [1]),
    ("canonical same Block order", [(0, 1, "sampling_floor", 4_000_000, 10), (0, 0, "sampling_ceiling", 3_000_000, 10)], [0]),
    ("invalid bound cannot hide behind replacement", [(0, 0, "sampling_floor", 0, 10), (1, 0, "sampling_floor", 200_000, 10)], [0]),
    ("grace period required", [(0, 0, "sampling_floor", 400_000, 6)], [0]),
):
    changes = [{"block_height": day * 24, "entry_index": index, "sealed_at_s": day * DAY_S,
                "parameter": parameter, "value": value, "effective_at_s": effective * DAY_S}
               for day, index, parameter, value, effective in rows]
    got, accepted = prospective_acceptance(changes)
    assert got == rejected, label
    instants = sorted({c["effective_at_s"] for c in changes})
    prospective_cases.append({"label": label, "changes": changes, "rejected_indices": got,
        "maps": [{"at_s": t, "values": prospective_map(accepted, t)} for t in instants]})

CLOCK_DEFAULTS = {"confirm_auditors": 2, "confirm_window_hours": 72,
    "coverage_deadline_hours": 72, "record_seal_blocks": 24,
    "appeal_window_days": 14, "appeal_seal_days": 7, "ruling_deadline_days": 30,
    "canary_lead_blocks": 24, "canary_lifetime_blocks": 1440,
    "canary_reveal_min_blocks": 168, "payload_window_days": 180}


def clock_value(parameter, at_s, changes):
    eligible = [c for c in changes if c["parameter"] == parameter and c["effective_at_s"] <= at_s]
    return max(eligible, key=lambda c: c["effective_at_s"])["value"] if eligible else CLOCK_DEFAULTS[parameter]


clock_cases = []
for label, parameter, anchor, changed, value, factor, start in (
    ("coverage retains deadline", "coverage_deadline_hours", 10, 11, 96, 3600, 10),
    ("coverage retains seal count", "record_seal_blocks", 10, 11, 48, 1, 200),
    ("extension retains close", "confirm_window_hours", 10, 11, 96, 3600, 10),
    ("checkpoint retains seal count", "record_seal_blocks", 10, 11, 48, 1, 200),
    ("commitment retains lead", "canary_lead_blocks", 10, 11, 48, 1, 200),
    ("commitment retains lifetime", "canary_lifetime_blocks", 10, 11, 2880, 1, 200),
    ("newest Delta fixes reveal minimum", "canary_reveal_min_blocks", 10, 11, 336, 1, 200),
    ("reveal retains scoring span", "payload_window_days", 10, 11, 360, 86400, 10),
    ("notice retains appeal span", "appeal_window_days", 10, 11, 28, 86400, 10),
    ("notice retains seal span", "appeal_seal_days", 10, 11, 14, 86400, 10 + 14 * 86400),
    ("accepted appeal fixes ruling span", "ruling_deadline_days", 12, 11, 60, 86400, 12),
    ("effective at anchor is included", "coverage_deadline_hours", 11, 11, 96, 3600, 11),
):
    changes = [{"parameter": parameter, "effective_at_s": changed, "value": value}]
    selected_value = clock_value(parameter, anchor, changes)
    clock_cases.append({"label": label, "parameter": parameter, "anchor_s": anchor,
        "changes": changes, "query_s": 20, "unit_scale": factor, "start": start,
        "selected_value": selected_value, "endpoint": start + selected_value * factor})

confirmation_clock_cases = []
for label, parameter, effective_h, value, hours, expected in (
    ("quorum increase before second Record", "confirm_auditors", 24, 3, [0, 48, 49], 2),
    ("shorter window excludes stale member", "confirm_window_hours", 48, 24, [0, 49, 50], 2),
    ("established confirmation survives amendment", "confirm_auditors", 48, 3, [0, 24, 49], 1),
    ("quorum activation equality", "confirm_auditors", 24, 3, [0, 24, 25], 2),
):
    changes = [{"parameter": parameter, "effective_at_s": effective_h * 3600, "value": value}]
    times = [h * 3600 for h in hours]
    first = next((i for i,t in enumerate(times) if sum(t - u <= clock_value("confirm_window_hours", t, changes) * 3600
        for u in times[:i+1]) >= clock_value("confirm_auditors", t, changes)), None)
    assert first == expected
    confirmation_clock_cases.append({"label": label, "changes": changes,
        "record_times_s": times, "confirming_index": first})

parameter_wire_cases = []
for parameter, value, schema_valid, combinations_hold in (
    ("quota_base", 9007199254740991, True, True),
    ("quota_base", -9007199254740991, True, True),
    ("quota_base", 9007199254740992, False, True),
    ("quota_base", -9007199254740992, False, True),
    ("provisional_cap_u", -1, False, True),
    ("provisional_cap_u", 0, True, True),
    ("block_cadence_seconds", 86400, True, False),
):
    canonical = abs(value) <= 9007199254740991
    inner = {"wist_version": "1.0.0", "action": "parameter_change", "subject": "log.sample.net",
        "effective_at": "2026-08-12T00:00:00Z", "details": {"parameter": parameter, "value": value if canonical else 0}}
    envelope = sign_envelope("update", inner, "test-process-k1")
    envelope["update"]["details"]["value"] = value
    parameter_wire_cases.append({"label": parameter + " value " + str(value), "envelope": envelope,
        "canonical_integer": canonical, "schema_valid": schema_valid,
        "combinations_hold_at_defaults": combinations_hold})

def cadence_transition_safe(profiles):
    for i,p in enumerate(profiles):
        end = profiles[i+1]["from_s"] if i+1 < len(profiles) else None
        latest_close = None if end is None else end + p["confirm_window_hours"] * 3600
        cadence = max(q["block_cadence_seconds"] for q in profiles[i:]
            if latest_close is None or q["from_s"] < latest_close)
        if (p["confirm_window_hours"] // 2) * 3600 + p["record_seal_blocks"] * cadence > p["confirm_window_hours"] * 3600:
            return False
    return True


cadence_transition_cases = []
for label, rows, expected in (
    ("new map alone misses old extension", [(0,72,3600), (10*DAY_S,96,7200)], False),
    ("larger window staged before slower cadence", [(0,72,3600), (10*DAY_S,96,3600), (13*DAY_S,96,7200)], True),
    ("one second before old profile expires", [(0,72,3600), (10*DAY_S,96,3600), (13*DAY_S-1,96,7200)], False),
    ("later interval still overlaps old profile", [(0,72,3600), (10*DAY_S,96,3600), (11*DAY_S,96,7200)], False),
    ("short cadence increase remains bounded conservatively", [(0,72,3600), (10*DAY_S,96,7200), (10*DAY_S+3600,96,3600)], False),
):
    profiles = [{"from_s":t, "confirm_window_hours":cw, "record_seal_blocks":24, "block_cadence_seconds":cadence} for t,cw,cadence in rows]
    assert all((p["confirm_window_hours"]//2)*3600 + 24*p["block_cadence_seconds"] <= p["confirm_window_hours"]*3600 for p in profiles)
    assert cadence_transition_safe(profiles) == expected
    anchor = 10*DAY_S-2*3600; pull = anchor+36*3600
    grid = [anchor]
    while len([t for t in grid if t > pull]) < 24:
        profile = max((p for p in profiles if p["from_s"] <= grid[-1]), key=lambda p:p["from_s"])
        cadence = profile["block_cadence_seconds"]
        grid.append((grid[-1]//cadence+1)*cadence)
    latest_seal = [t for t in grid if t > pull][23]
    cadence_transition_cases.append({"label":label, "profiles":profiles, "transition_valid":expected,
        "anchor_s":anchor, "pull_s":pull, "window_end_s":anchor+72*3600,
        "latest_seal_s":latest_seal, "actual_seal_inside_window":latest_seal<=anchor+72*3600})
assert not cadence_transition_cases[0]["actual_seal_inside_window"]
assert cadence_transition_cases[1]["actual_seal_inside_window"]

RETENTION_PROFILES = [
    {"from_s":0, "appeal_window_days":14, "appeal_seal_days":7, "ruling_deadline_days":30, "mirror_retention_days":51},
    {"from_s":47*DAY_S, "appeal_window_days":1, "appeal_seal_days":1, "ruling_deadline_days":60, "mirror_retention_days":62},
    {"from_s":90*DAY_S, "appeal_window_days":1, "appeal_seal_days":1, "ruling_deadline_days":75, "mirror_retention_days":77},
]


def retention_profile(at_s):
    return max((p for p in RETENTION_PROFILES if p["from_s"] <= at_s), key=lambda p:p["from_s"])


def retention_at(notices, n_s):
    ends = []
    for notice in notices:
        if notice["sealed_at_s"] > n_s or not notice["accepted"]:
            continue
        profile = retention_profile(notice["sealed_at_s"])
        t = notice["sealed_at_s"] + (profile["appeal_window_days"] + profile["appeal_seal_days"]) * DAY_S
        end = t
        appeal = notice["appeal_s"]
        if appeal is not None and appeal <= min(t,n_s):
            end = appeal + retention_profile(appeal)["ruling_deadline_days"] * DAY_S
            merits = notice["merits_ruling_s"]
            if merits is not None and appeal <= merits <= min(end,n_s):
                end = merits
        ends.append(end)
    return {"process_ends_s":ends, "must_serve":n_s < 51*DAY_S or any(n_s<=e for e in ends)}


retention_cases = []
for label, rows in (
    ("old notice and newer ruling span", [(40,60,None,None,True)]),
    ("unappealed statement cannot close retention early", [(40,None,None,54,True)]),
    ("accepted merits ruling closes process", [(40,60,80,None,True)]),
    ("late appeal does not extend retention", [(40,62,None,None,True)]),
    ("overlapping notices retain shared evidence", [(40,None,None,None,True), (60,None,None,None,True)]),
    ("rejected notice creates no retention duty", [(40,60,None,None,False)]),
):
    notices = [{"sealed_at_s":n*DAY_S, "appeal_s":None if a is None else a*DAY_S,
        "merits_ruling_s":None if r is None else r*DAY_S, "unappealed_s":None if u is None else u*DAY_S,
        "accepted":accepted} for n,a,r,u,accepted in rows]
    probes = sorted({51*DAY_S-1,51*DAY_S,55*DAY_S,60*DAY_S,61*DAY_S,61*DAY_S+1,
        62*DAY_S,62*DAY_S+1,80*DAY_S,80*DAY_S+1,119*DAY_S,120*DAY_S,120*DAY_S+1})
    retention_cases.append({"label":label, "evidence_first_served_s":0,
        "notices":notices, "probes":[{"n_s":t, **retention_at(notices,t)} for t in probes]})
assert retention_cases[0]["probes"][-2]["must_serve"] and not retention_cases[0]["probes"][-1]["must_serve"]

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
            if change["value"] < 1024 or change["effective_at_s"] < block["sealed_at_s"] + 7 * DAY_S or block_cap_bounds(trial, block["sealed_at_s"])[0] < tentative_max:
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

recovery_window_cases = []
for label, changes, openings, probes in [
    ("default exact settlement boundary", [], [10], [16 * 86400 + 86399, 17 * 86400]),
    ("later shortening preserves original end", [(0, 11, 2)], [10], [12 * 86400, 17 * 86400]),
    ("later lengthening preserves original end", [(0, 11, 20)], [10], [17 * 86400, 30 * 86400]),
    ("amendment effective at owner applies", [(0, 10, 2)], [10], [12 * 86400 - 1, 12 * 86400]),
    ("in window recovery does not reanchor", [(0, 11, 2)], [10, 11], [13 * 86400, 17 * 86400]),
    ("new window reads amended length", [(0, 11, 2)], [10, 17], [17 * 86400, 19 * 86400]),
    ("maximum wire days retains exact endpoint", [(0, 10, (1 << 53) - 1)], [10], [9999 * 86400]),
]:
    amendments = [{"parameter": "recovery_window_days", "value": value,
                   "block_height": i, "entry_index": 0,
                   "sealed_at_s": sealed * 86400, "effective_at_s": effective * 86400}
                  for i, (sealed, effective, value) in enumerate(changes)]
    events = []
    end = None
    owner = None
    for day in openings:
        at = day * 86400
        if end is None or at >= end:
            owner = at
            applicable = [change for change in amendments if change["effective_at_s"] <= at]
            days = applicable[-1]["value"] if applicable else 7
            end = at + days * 86400
        events.append({"sealed_at_s": at, "owner_at_s": owner, "window_end_s": str(end)})
    recovery_window_cases.append({"label": label, "accepted_amendments": amendments,
                                  "eligible_recoveries": events,
                                  "probes": [{"at_s": at, "open": at < end} for at in probes]})

write_json(WIST4 / "parameter-combinations.json", spaced_labels({
    "note": "WIST-4 §9 combination rules. `cases`: the coverage-countability rule — each case gives the four participants, the sum the rule bounds, and — from a simulation of an Auditor that fails every Block on a fully sealed grid — the greatest number of failures any single height carries, under the unattested establishing height and under an attestation sealed in the next Block; the rule reads each deadline onto the grid, so it holds exactly when the unattested predicate is reachable wherever the deadline is a whole number of Blocks. `extension_window_cases`: the rule keeping an extension Record sealable inside the confirmation window — each case gives the three participants, the sum, and the latest instant after B₁ at which a Record published at the extension deadline seals on a fully sealed grid.",
    "window_days": 30,
    "cases": countability_cases,
    "extension_window_cases": extension_window_cases,
    "block_cap_default": BLOCK_CAP_DEFAULT,
    "block_size_cases": block_size_cases,
    "block_transport_cases": block_transport_cases,
    "prospective_defaults": PROSPECTIVE_DEFAULTS,
    "prospective_cases": prospective_cases,
    "retention_profiles": RETENTION_PROFILES,
    "retention_cases": retention_cases,
    "recovery_window_cases": recovery_window_cases,
    "cadence_transition_cases": cadence_transition_cases,
    "wire_public_key": b64u(pub_raw),
    "wire_cases": parameter_wire_cases,
    "clock_defaults": CLOCK_DEFAULTS,
    "clock_cases": clock_cases,
    "confirmation_clock_cases": confirmation_clock_cases,
}))
print("wist4 parameter-combinations vector written")

# ---------------------------------------- WIST-4 §5: the unauditable predicate
# Two blocking Records from independent Auditors inside the horizon ending
# at N, with no clearing Record from an Auditor independent of both sealed
# after the later of the two and at or below N.
UNAUDITABLE_HORIZON_DAYS = 30
CLEARING_VERDICTS = ("consistent", "inconsistent", "dynamic_variance",
                     "link_variance", "link_inconsistent")


def record_blocks(record):
    """§5: a blocking Record is a robots_excluded Record or a not_auditable
    Record whose `unmeasured` side is the observed one; a reference-side
    not_auditable Record blocks nothing."""
    if record["verdict"] == "unreachable":
        return bool(record.get("robots_excluded"))
    return record["verdict"] == "not_auditable" and record.get("unmeasured") == "observed"


def robots(auditor, sealed_at_s):
    return {"auditor": auditor, "sealed_at_s": sealed_at_s, "verdict": "unreachable",
            "robots_excluded": True, "unmeasured": None}


def unmeasured(auditor, sealed_at_s, side):
    return {"auditor": auditor, "sealed_at_s": sealed_at_s, "verdict": "not_auditable",
            "robots_excluded": False, "unmeasured": side}


def unauditable_at(blocking, others, n_s, horizon_days):
    live = [b for b in blocking if record_blocks(b)
            and within_days_ending_at(b["sealed_at_s"], n_s, horizon_days)]
    for i, b1 in enumerate(live):
        for b2 in live[i + 1:]:
            if not independent(b1["auditor"], b2["auditor"]):
                continue
            later = max(b1["sealed_at_s"], b2["sealed_at_s"])
            cleared = any(
                later < c["sealed_at_s"] <= n_s and c["verdict"] in CLEARING_VERDICTS
                and independent(c["auditor"], b1["auditor"])
                and independent(c["auditor"], b2["auditor"])
                for c in others)
            if not cleared:
                return True
    return False


def unauditable_case(label, blocking, others, n_s):
    blocking = [dict(b, blocks=record_blocks(b)) for b in blocking]
    return {"label": label, "blocking": blocking, "other_records": others,
            "n_sealed_at_s": n_s,
            "unauditable": unauditable_at(blocking, others, n_s, UNAUDITABLE_HORIZON_DAYS)}


N_S = 100 * DAY_S
A1, A2, A3, A2_KIN = "audit.example.org", "checker.example.net", "verify.example.com", "other.example.net"
A3_KIN, A4 = "mirror.example.com", "probe.sample.org"
unauditable_cases = [
    unauditable_case("two-independent-blocking-inside-the-horizon",
                     [robots(A1, N_S - 20 * DAY_S),
                      robots(A2, N_S - 10 * DAY_S)], [], N_S),
    unauditable_case("second-blocking-exactly-thirty-days-before-n",
                     [robots(A1, N_S - 30 * DAY_S),
                      robots(A2, N_S - 10 * DAY_S)], [], N_S),
    unauditable_case("second-blocking-one-second-inside-the-horizon",
                     [robots(A1, N_S - 30 * DAY_S + 1),
                      robots(A2, N_S - 10 * DAY_S)], [], N_S),
    unauditable_case("blocking-pair-not-independent",
                     [robots(A2, N_S - 20 * DAY_S),
                      robots(A2_KIN, N_S - 10 * DAY_S)], [], N_S),
    unauditable_case("cleared-by-a-third-independent-auditor",
                     [robots(A1, N_S - 20 * DAY_S),
                      robots(A2, N_S - 10 * DAY_S)],
                     [{"auditor": A3, "sealed_at_s": N_S - 5 * DAY_S, "verdict": "consistent"}], N_S),
    unauditable_case("clearing-auditor-dependent-on-a-blocker",
                     [robots(A1, N_S - 20 * DAY_S),
                      robots(A2, N_S - 10 * DAY_S)],
                     [{"auditor": A2_KIN, "sealed_at_s": N_S - 5 * DAY_S, "verdict": "consistent"}], N_S),
    unauditable_case("clearing-record-before-the-later-blocking",
                     [robots(A1, N_S - 20 * DAY_S),
                      robots(A2, N_S - 10 * DAY_S)],
                     [{"auditor": A3, "sealed_at_s": N_S - 15 * DAY_S, "verdict": "consistent"}], N_S),
    unauditable_case("unreachable-does-not-clear",
                     [robots(A1, N_S - 20 * DAY_S),
                      robots(A2, N_S - 10 * DAY_S)],
                     [{"auditor": A3, "sealed_at_s": N_S - 5 * DAY_S, "verdict": "unreachable"}], N_S),
    unauditable_case("clearing-record-above-n",
                     [robots(A1, N_S - 20 * DAY_S),
                      robots(A2, N_S - 10 * DAY_S)],
                     [{"auditor": A3, "sealed_at_s": N_S + DAY_S, "verdict": "consistent"}], N_S),
    unauditable_case("clearing-record-at-the-later-blocking-instant",
                     [robots(A1, N_S - 20 * DAY_S),
                      robots(A2, N_S - 10 * DAY_S)],
                     [{"auditor": A3, "sealed_at_s": N_S - 10 * DAY_S, "verdict": "consistent"}], N_S),
    unauditable_case("clearing-record-exactly-at-n",
                     [robots(A1, N_S - 20 * DAY_S),
                      robots(A2, N_S - 10 * DAY_S)],
                     [{"auditor": A3, "sealed_at_s": N_S, "verdict": "consistent"}], N_S),
    unauditable_case("three-blockers-one-pair-uncleared",
                     [robots(A1, N_S - 20 * DAY_S),
                      robots(A2, N_S - 10 * DAY_S),
                      robots(A3, N_S - 5 * DAY_S)],
                     [{"auditor": A3_KIN, "sealed_at_s": N_S - 2 * DAY_S, "verdict": "consistent"}], N_S),
    unauditable_case("three-blockers-every-pair-cleared",
                     [robots(A1, N_S - 20 * DAY_S),
                      robots(A2, N_S - 10 * DAY_S),
                      robots(A3, N_S - 5 * DAY_S)],
                     [{"auditor": A4, "sealed_at_s": N_S - 2 * DAY_S, "verdict": "consistent"}], N_S),
]
assert [c["unauditable"] for c in unauditable_cases[-4:]] == [True, False, True, False], \
    "unauditable boundary cases drifted"

unauditable_cases += [
    unauditable_case("two-reference-side-not-auditable-records-block-nothing",
                     [unmeasured(A1, N_S - 20 * DAY_S, "reference"),
                      unmeasured(A2, N_S - 10 * DAY_S, "reference")], [], N_S),
    unauditable_case("an-observed-side-not-auditable-record-beside-a-robots-exclusion-blocks",
                     [robots(A1, N_S - 20 * DAY_S),
                      unmeasured(A2, N_S - 10 * DAY_S, "observed")], [], N_S),
    unauditable_case("a-reference-side-record-beside-a-robots-exclusion-blocks-nothing",
                     [robots(A1, N_S - 20 * DAY_S),
                      unmeasured(A2, N_S - 10 * DAY_S, "reference")], [], N_S),
    unauditable_case("two-observed-side-not-auditable-records-block",
                     [unmeasured(A1, N_S - 20 * DAY_S, "observed"),
                      unmeasured(A2, N_S - 10 * DAY_S, "observed")], [], N_S),
]
assert [c["unauditable"] for c in unauditable_cases[-4:]] == [False, True, False, True], \
    "blocking-cause cases drifted"

fetch_budget_cases = []
for label, remaining, reference_bytes, observed_bytes, side in (
    ("budget stops reference", 4096, 4097, 8192, "reference"),
    ("reference completes exactly at budget", 4096, 4096, 8192, "observed"),
    ("budget stops URL after reference", 4096, 2048, 8192, "observed"),
    ("held reference with exhausted budget", 0, 0, 8192, "observed"),
    ("no reference with exhausted budget", 0, 4096, 8192, "reference"),
):
    assert reference_bytes + observed_bytes > remaining
    assert ("observed" if reference_bytes <= remaining else "reference") == side
    fetch_budget_cases.append({"label": label, "daily_budget_bytes": 1073741824,
        "bytes_already_spent": 1073741824 - remaining, "reference_bytes_needed": reference_bytes,
        "observed_bytes_needed": observed_bytes,
        "record": {"verdict": "not_auditable", "unmeasured": side},
        "blocks": side == "observed", "two_independent_records_unauditable": side == "observed"})

fetch_transport_cases = [{"label": side + " " + limit, "stopped_side": side, "limit": limit,
    "record": {"verdict": "not_auditable", "unmeasured": "reference"} if side == "reference" else {"verdict": "unreachable"},
    "blocks": False} for side in ("reference", "observed") for limit in ("timeout", "redirect ceiling")]

write_json(WIST4 / "unauditable.json", spaced_labels({
    "note": "WIST-4 §5 unauditable predicate at Block N. blocking are the URL's Records that may block — robots_excluded Records and not_auditable Records with their `unmeasured` side, `blocks` saying whether each does — other_records its Records of any other verdict, both as (auditor, sealing instant).",
    "unauditable_horizon_days": UNAUDITABLE_HORIZON_DAYS,
    "clearing_verdicts": list(CLEARING_VERDICTS),
    "fetch_budget": {"note": "Concrete reference-first fetch traces; the protocol does not require that order. All completed references verify and have nonempty extracts. Zero reference bytes needed means a usable reference is already held. No timeout, redirect or URL cap intervenes. The daily budget alone stops each trace; two independent same-URL Records are queried at their sealing Block without a clearing Record.",
        "cases": fetch_budget_cases},
    "fetch_transport": {"note": "A reference-side interruption leaves the reference unavailable from every source; observed-side cases already hold a verified nonempty reference. No byte limit or robots exclusion intervenes. These cases isolate outcome classification after the stated transport limit has stopped acquisition.",
        "cases": fetch_transport_cases},
    "cases": unauditable_cases,
}))
print("wist4 unauditable vector written")

# ----------------------------------------- WIST-4 §3, §4: the Auditor roster
# One admitted key per auditor_id at any height. Removes sealed at an instant
# apply before admits sealed at it, which is what lets a rotation seal in one
# Block; every other roster act §3/§4 reject is a case here (WIST4-E07).
ROSTER_LOG_ID = "log.example.org"


def roster_entry(sealed_at_s, action, auditor_id, key_id, evidence=None, public_key=None):
    """evidence, on an auditor_remove, is the Registry Update's own member:
    present and naming at least one ID for a removal for cause, absent for an
    exit or a rotation (§4, §9.1). public_key is an abstract label for the
    key octets an admit names; it defaults to one per key_id."""
    e = {"sealed_at_s": sealed_at_s, "action": action,
         "auditor_id": auditor_id, "key_id": key_id}
    if action == "auditor_admit":
        e["public_key"] = public_key or "pk-" + key_id
    if evidence:
        e["evidence"] = evidence
    return e


def roster_replay(log_id, entries):
    """Rejected Entry indices under §3/§4, in Log order. A removal retires
    the key_id and the public_key admitted under it; an admit naming either
    a retired one or one another admission holds is rejected."""
    key_of, retired, barred, rejected = {}, set(), set(), []
    instants = sorted({e["sealed_at_s"] for e in entries})
    for t in instants:
        at_t = [(i, e) for i, e in enumerate(entries) if e["sealed_at_s"] == t]
        incumbent = dict(key_of)
        for i, e in at_t:
            if e["action"] != "auditor_remove":
                continue
            held = incumbent.get(e["auditor_id"])
            if held is None or held[0] != e["key_id"]:
                rejected.append(i)
                continue
            key_of.pop(e["auditor_id"], None)
            retired.update(held)
            if e.get("evidence"):
                barred.add(e["auditor_id"])
        admits = [(i, e) for i, e in at_t if e["action"] == "auditor_admit"]
        subjects = [e["auditor_id"] for _, e in admits]
        for i, e in admits:
            held_strings = {x for held in key_of.values() for x in held}
            if (e["key_id"] in retired or e["public_key"] in retired
                    or e["key_id"] in held_strings or e["public_key"] in held_strings
                    or e["auditor_id"] in barred
                    or e["auditor_id"] in key_of or subjects.count(e["auditor_id"]) > 1
                    or not independent(e["auditor_id"], log_id)):
                rejected.append(i)
                continue
            key_of[e["auditor_id"]] = (e["key_id"], e["public_key"])
    return sorted(rejected)


def roster_admitted_at(log_id, entries, auditor_id, t):
    """The key auditor_id holds at instant t: admitted at or before t and not
    removed at or before t."""
    rejected = set(roster_replay(log_id, entries))
    key = None
    for i, e in enumerate(entries):
        if i in rejected or e["auditor_id"] != auditor_id or e["sealed_at_s"] > t:
            continue
        key = e["key_id"] if e["action"] == "auditor_admit" else None
    return key


AUD_R, AUD_R2 = "audit.example.net", "checker.sample.org"
roster_scenarios = [
    ("rotation-in-one-block",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_remove", AUD_R, "k1"),
      roster_entry(3600, "auditor_admit", AUD_R, "k2")],
     [(AUD_R, 0), (AUD_R, 3599), (AUD_R, 3600), (AUD_R, 7200)]),
    ("overlapping-admit-rejected",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_admit", AUD_R, "k2")],
     [(AUD_R, 3600), (AUD_R, 7200)]),
    ("retired-key-id-rejected",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_remove", AUD_R, "k1"),
      roster_entry(7200, "auditor_admit", AUD_R, "k1")],
     [(AUD_R, 7200)]),
    ("barred-subject-rejected",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_remove", AUD_R, "k1", evidence=["sha256:void-record"]),
      roster_entry(7200, "auditor_admit", AUD_R, "k2")],
     [(AUD_R, 7200)]),
    ("exit-then-re-entry-allowed",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_remove", AUD_R, "k1"),
      roster_entry(7200, "auditor_admit", AUD_R, "k2")],
     [(AUD_R, 5000), (AUD_R, 7200)]),
    ("removal-ends-admission-at-its-instant",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_remove", AUD_R, "k1")],
     [(AUD_R, 3599), (AUD_R, 3600)]),
    ("dependent-on-the-log-id-rejected",
     [roster_entry(0, "auditor_admit", "audit.example.org", "k1"),
      roster_entry(0, "auditor_admit", "checker.example.net", "k2")],
     [("audit.example.org", 0), ("checker.example.net", 0)]),
    ("remove-of-a-key-not-held-rejected",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_remove", AUD_R, "k9"),
      roster_entry(7200, "auditor_admit", AUD_R, "k2")],
     [(AUD_R, 3600), (AUD_R, 7200)]),
    ("two-admits-for-one-subject-in-one-block-both-rejected",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(0, "auditor_admit", AUD_R, "k2"),
      roster_entry(3600, "auditor_admit", AUD_R, "k3")],
     [(AUD_R, 0), (AUD_R, 3600)]),
    ("same-public-key-under-a-fresh-key-id-after-exit-rejected",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_remove", AUD_R, "k1"),
      roster_entry(7200, "auditor_admit", AUD_R, "k2", public_key="pk-k1"),
      roster_entry(10800, "auditor_admit", AUD_R, "k3")],
     [(AUD_R, 7200), (AUD_R, 10800)]),
    ("public-key-held-by-another-auditor-rejected",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_admit", AUD_R2, "k2", public_key="pk-k1"),
      roster_entry(7200, "auditor_admit", AUD_R2, "k3")],
     [(AUD_R, 3600), (AUD_R2, 3600), (AUD_R2, 7200)]),
    ("key-id-held-by-another-auditor-rejected",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_admit", AUD_R2, "k1", public_key="pk-other"),
      roster_entry(7200, "auditor_admit", AUD_R2, "k2")],
     [(AUD_R, 3600), (AUD_R2, 3600), (AUD_R2, 7200)]),
    ("retired-key-id-re-admitted-by-another-auditor-rejected",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_remove", AUD_R, "k1"),
      roster_entry(7200, "auditor_admit", AUD_R2, "k1", public_key="pk-other")],
     [(AUD_R2, 7200)]),
    ("rejected-for-cause-remove-bars-nothing",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_remove", AUD_R, "k9", evidence=["sha256:void-record"]),
      roster_entry(7200, "auditor_remove", AUD_R, "k1"),
      roster_entry(10800, "auditor_admit", AUD_R, "k2")],
     [(AUD_R, 3600), (AUD_R, 7200), (AUD_R, 10800)]),
    ("same-block-for-cause-remove-and-admit-rejected",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_remove", AUD_R, "k1", evidence=["sha256:void-record"]),
      roster_entry(3600, "auditor_admit", AUD_R, "k2")],
     [(AUD_R, 3599), (AUD_R, 3600)]),
    ("rotation-beside-a-second-admit-in-one-block",
     [roster_entry(0, "auditor_admit", AUD_R, "k1"),
      roster_entry(3600, "auditor_remove", AUD_R, "k1"),
      roster_entry(3600, "auditor_admit", AUD_R, "k2"),
      roster_entry(3600, "auditor_admit", AUD_R, "k3"),
      roster_entry(7200, "auditor_admit", AUD_R, "k4")],
     [(AUD_R, 3599), (AUD_R, 3600), (AUD_R, 7200)]),
]
for exit_first in (True, False):
    removals = [roster_entry(3600, "auditor_remove", AUD_R, "k1"),
                roster_entry(3600, "auditor_remove", AUD_R, "k1", evidence=["sha256:void-record"])]
    if not exit_first:
        removals.reverse()
    roster_scenarios.append(("exit before cause" if exit_first else "cause before exit",
        [roster_entry(0, "auditor_admit", AUD_R, "k1"), *removals,
         roster_entry(3600, "auditor_admit", AUD_R, "k2"),
         roster_entry(7200, "auditor_admit", AUD_R, "k3")],
        [(AUD_R, 3599), (AUD_R, 3600), (AUD_R, 7200)]))
roster_cases = [
    {"label": label, "log_id": ROSTER_LOG_ID, "entries": entries,
     "rejected_indices": roster_replay(ROSTER_LOG_ID, entries),
     "admitted_key_at": [
         {"auditor_id": aid, "sealed_at_s": t,
          "key_id": roster_admitted_at(ROSTER_LOG_ID, entries, aid, t)}
         for aid, t in queries]}
    for label, entries, queries in roster_scenarios
]
assert [c["rejected_indices"] for c in roster_cases] == \
    [[], [1], [2], [2], [], [], [0], [1, 2], [0, 1], [2], [1], [1], [2], [1], [2], [2, 3], [3, 4], [3, 4]], "roster rejections drifted"
def roster_batch(initial, acts):
    rejected = {i for i, a in enumerate(acts)
                if sum(b["action"] == a["action"] and b["subject"] == a["subject"] for b in acts) > 1}
    held = dict(initial["observers"]) | initial["auditors"]
    for i, a in enumerate(acts):
        if (not independent(a["subject"], ROSTER_LOG_ID)
                or a["subject"] in initial["auditors"]
                or a["action"] == "auditor_admit" and a["subject"] in initial["barred"]
                or a["key_id"] in initial["retired_key_ids"]
                or a["public_key"] in initial["retired_public_keys"]
                or any(subject != a["subject"] and (key["key_id"] == a["key_id"] or key["public_key"] == a["public_key"])
                       for subject, key in held.items())):
            rejected.add(i)
    admitting = {a["subject"] for i, a in enumerate(acts) if i not in rejected and a["action"] == "auditor_admit"}
    rejected |= {i for i, a in enumerate(acts) if a["action"] == "observer_register" and a["subject"] in admitting}
    candidates = [(i, a) for i, a in enumerate(acts) if i not in rejected]
    for (i, a), (j, b) in itertools.combinations(candidates, 2):
        if a["subject"] != b["subject"] and (a["key_id"] == b["key_id"] or a["public_key"] == b["public_key"]):
            rejected.update((i, j))
    auditors, observers = dict(initial["auditors"]), dict(initial["observers"])
    for i, a in enumerate(acts):
        if i in rejected:
            continue
        key = {k: a[k] for k in ("key_id", "public_key")}
        if a["action"] == "auditor_admit":
            auditors[a["subject"]] = key
            observers.pop(a["subject"], None)
        else:
            observers[a["subject"]] = key
    return {"rejected_indices": sorted(rejected), "auditors": auditors, "observers": observers}


def roster_candidate(action, subject, key, public=None):
    return {"action": action, "subject": subject, "key_id": key, "public_key": public or "pk " + key}

RA, RB, RC = "watch.alpha.test", "watch.beta.test", "watch.gamma.test"
REG, ADM = "observer_register", "auditor_admit"
old_observer = {RA: {"key_id": "old", "public_key": "pk old"}}
roster_batch_cases = []
for label, observers, auditors, acts, rejected in (
    ("two rotations preserve incumbent", old_observer, {}, [roster_candidate(REG, RA, "new a"), roster_candidate(REG, RA, "new b")], [0, 1]),
    ("registrations share key id", {}, {}, [roster_candidate(REG, RA, "same", "pk a"), roster_candidate(REG, RB, "same", "pk b")], [0, 1]),
    ("registrations share public key", {}, {}, [roster_candidate(REG, RA, "a", "pk same"), roster_candidate(REG, RB, "b", "pk same")], [0, 1]),
    ("admission and registration share key", {}, {}, [roster_candidate(ADM, RA, "same"), roster_candidate(REG, RB, "same")], [0, 1]),
    ("admissions share public key", {}, {}, [roster_candidate(ADM, RA, "a", "pk same"), roster_candidate(ADM, RB, "b", "pk same")], [0, 1]),
    ("connected key conflicts all rejected", {}, {}, [roster_candidate(REG, RA, "a", "pk a"), roster_candidate(ADM, RB, "a", "pk b"), roster_candidate(REG, RC, "c", "pk b")], [0, 1, 2]),
    ("rotation cannot release key in same Block", old_observer, {}, [roster_candidate(REG, RA, "new"), roster_candidate(REG, RB, "old")], [1]),
    ("same subject admission precedes registration", old_observer, {}, [roster_candidate(REG, RA, "new"), roster_candidate(ADM, RA, "old")], [0]),
    ("invalid contender does not veto", {}, {RA: {"key_id": "held", "public_key": "pk held"}}, [roster_candidate(REG, RB, "shared", "pk held"), roster_candidate(REG, RC, "shared", "pk free")], [0]),
    ("rejected admission does not retry registration", old_observer, {}, [roster_candidate(REG, RA, "new"), roster_candidate(ADM, RA, "shared"), roster_candidate(REG, RB, "shared")], [0, 1, 2]),
):
    initial = {"observers": observers, "auditors": auditors, "barred": [],
               "retired_key_ids": [], "retired_public_keys": []}
    result = roster_batch(initial, acts)
    assert result["rejected_indices"] == rejected, label
    roster_batch_cases.append({"label": label, "initial_after_removals": initial,
                               "acts": acts, "expected": result})

ADMISSION_SUBJECT = "watch.sample.net"
admission_registration = sign_envelope_with(priv2, "update", {"wist_version": "1.0.0",
    "action": "observer_register", "subject": ADMISSION_SUBJECT, "effective_at": "2026-08-02T12:00:00Z",
    "details": {"key_id": "observer-k1", "alg": "Ed25519", "public_key": b64u(pub2_raw)}}, "observer-k1")
admission_record = dict(audit_record, auditor_id=ADMISSION_SUBJECT,
    credit_commitment=audit_commit(RESPONSE_BODY + ADMISSION_SUBJECT.encode()),
    vrf_proof=ecvrf.prove(SEED2, alpha).hex())
admission_record_envelope = sign_envelope_with(priv2, "record", admission_record, "observer-k1")
admission_head = "sha256:" + sha256_hex(rfc8785.dumps(admission_record))
admission_checkpoints = [sign_envelope_with(priv2, "update", {"wist_version": "1.0.0",
    "action": "observer_checkpoint", "subject": ADMISSION_SUBJECT,
    "effective_at": f"2026-08-0{day}T12:00:00Z", "details": {"head": admission_head}}, "observer-k1") for day in (3,4)]
admission_checkpoint_ids = ["sha256:" + sha256_hex(rfc8785.dumps(e["update"])) for e in admission_checkpoints]
admission_board = {t: [0,0,0] for t in ("provisional", "standing", "mature")}
admission_cases = []
for label, registered, checkpoint_indices, selected_checkpoint, declared_board, error in (
    ("new Auditor without Observer history", False, [], None, None, None),
    ("former Observer needs track record", True, [0], None, None, "WIST4-E04"),
    ("new Auditor cannot cite track record", False, [], 0, admission_board, "WIST4-E04"),
    ("Observer cites latest checkpoint", True, [0,1], 1, admission_board, None),
    ("no checkpoint to cite", True, [], 0, admission_board, "WIST4-E04"),
    ("older checkpoint is not latest", True, [0,1], 0, admission_board, "WIST4-E04"),
    ("scoreboard disagreement preserves admission", True, [0,1], 1, dict(admission_board, mature=[100,100,0]), None),
):
    details = {"key_id": "admitted-k1", "alg": "Ed25519", "public_key": b64u(pub4_raw)}
    if selected_checkpoint is not None:
        details["track_record"] = {"checkpoint": admission_checkpoint_ids[selected_checkpoint], "scoreboard": declared_board}
    envelope = sign_envelope("update", {"wist_version": "1.0.0", "action": "auditor_admit",
        "subject": ADMISSION_SUBJECT, "effective_at": "2026-08-05T12:00:00Z", "details": details}, "test-agg-k1")
    history = ([{"height": 1, "envelope": admission_registration}] if registered else []) + [
        {"height": 2+i, "envelope": admission_checkpoints[i]} for i in checkpoint_indices]
    valid = (selected_checkpoint is None if not registered else bool(checkpoint_indices) and selected_checkpoint == max(checkpoint_indices))
    assert valid == (error is None), label
    admission_cases.append({"label": label, "history": history, "admission_height": 4, "envelope": envelope,
        "recomputed_scoreboard": admission_board, "error": error,
        "admitted_key": "admitted-k1" if valid else None})

for selected in (0, 1):
    for reverse in (False, True):
        details = {"key_id": "admitted-k1", "alg": "Ed25519", "public_key": b64u(pub4_raw),
            "track_record": {"checkpoint": admission_checkpoint_ids[selected], "scoreboard": admission_board}}
        envelope = sign_envelope("update", {"wist_version": "1.0.0", "action": "auditor_admit",
            "subject": ADMISSION_SUBJECT, "effective_at": "2026-08-05T12:00:00Z", "details": details}, "test-agg-k1")
        order = (1, 0) if reverse else (0, 1)
        history = [{"height": 1, "envelope": admission_registration}] + [
            {"height": 2, "envelope": admission_checkpoints[i]} for i in order]
        valid = admission_checkpoint_ids[selected] == max(admission_checkpoint_ids)
        admission_cases.append({"label": "same head checkpoint citation " + str(selected) + (" reversed" if reverse else " forward"),
            "history": history, "admission_height": 4, "envelope": envelope,
            "recomputed_scoreboard": admission_board, "error": None if valid else "WIST4-E04",
            "admitted_key": "admitted-k1" if valid else None})

write_json(WIST4 / "roster.json", spaced_labels({
    "note": ("WIST-4 §3, §4 roster derivation: per case a Log prefix of roster "
             "acts in Log order, the indices a replayer rejects (WIST4-E07), and "
             "the key an auditor_id holds at queried instants; a removal retires "
             "the key_id and the public_key admitted under it, and an admit naming "
             "either a retired one or one another admission holds is rejected. "
             "public_key is an abstract label for the key octets. An auditor_remove "
             "carries `evidence` exactly as the Registry Update does: present and "
             "naming at least one ID when the removal is for cause, absent for an "
             "exit or a rotation. Batch cases start after removals with signatures and "
             "the non-roster details contracts already validated; their inputs "
             "exercise key and subject conflicts, not admission merits."),
    "cases": roster_cases,
    "batch_cases": roster_batch_cases,
    "admission": {"note": "Prior registration and checkpoint Entries are valid. The supplied Record is the checkpoint head. No canary reveals are live, so every recomputed scoreboard is zero; admission remains discretionary even with that score. These cases isolate the evidence contract, with roster conflicts absent.",
        "keys": [{"key_id": "observer-k1", "public_key": b64u(pub2_raw)}, {"key_id": "test-agg-k1", "public_key": b64u(pub_raw)}],
        "record_envelope": admission_record_envelope, "cases": admission_cases},
}))
print("wist4 roster vector: %d cases" % len(roster_cases))

# ------------------- WIST-4 §§3, 3.1, 9.1: signed roster acts and their timing
# Every Entry is checked as a Registry Update under §9.1 — raw JSON, fields,
# version, authenticity, in that precedence — before §3.1's batch, so an
# ineligible act is no candidate there; an admission reads Observer history
# and citable checkpoints below its Block; a checkpoint reads the
# registrations in force after its Block's batch; an admitted public_key is
# a string until a Record or proof under it is verified (§3).
ACTS_LOG_ID = "log.example.org"
ACTS_LOG_KEY_ID = "test-agg-k1"
ACTS_SMALL_ORDER = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
ACTS_A, ACTS_B, ACTS_C = "watch.alpha.test", "watch.beta.test", "checker.gamma.test"
ACTS_HOSTNAME = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+")
ACTS_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
ACTS_B64U_64 = re.compile(r"[A-Za-z0-9_-]{85}[AQgw]")
ACTS_B64U_32 = re.compile(r"[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]")
ACTS_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ACTS_INSTANT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9]Z")


def acts_key(label):
    seed = hashlib.sha256(b"roster-acts:" + label.encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


ACTS_PRIV = {k: acts_key(k) for k in ("obs-a1", "obs-a2", "obs-b1", "aud-a", "aud-a2", "aud-b", "stranger")}
ACTS_PUB = {k: b64u(raw_public(v)) for k, v in ACTS_PRIV.items()}
ACTS_PUB["small-order"] = b64u(ACTS_SMALL_ORDER)


def acts_update(action, subject, details=None, evidence=None, version="1.0.0",
                effective="2026-08-05T12:00:00Z"):
    update = {"wist_version": version, "action": action, "subject": subject,
              "effective_at": effective}
    if details is not None:
        update["details"] = details
    if evidence is not None:
        update["evidence"] = evidence
    return update


def acts_admit(subject, key, track_record=None, **kw):
    details = {"key_id": key, "alg": "Ed25519", "public_key": ACTS_PUB[key]}
    if track_record is not None:
        details["track_record"] = track_record
    return acts_update("auditor_admit", subject, details, **kw)


def acts_remove(subject, key, evidence=None, **kw):
    return acts_update("auditor_remove", subject, {"key_id": key}, evidence, **kw)


def acts_register(subject, key, **kw):
    return acts_update("observer_register", subject,
                       {"key_id": key, "alg": "Ed25519", "public_key": ACTS_PUB[key]}, **kw)


def acts_checkpoint(subject, head, **kw):
    return acts_update("observer_checkpoint", subject, {"head": head}, **kw)


def acts_log_signed(update):
    return sign_envelope("update", update, ACTS_LOG_KEY_ID)


def acts_self_signed(update, key, key_id=None):
    return sign_envelope_with(ACTS_PRIV[key], "update", update, key_id or key)


def acts_id(update):
    return "sha256:" + sha256_hex(rfc8785.dumps(update))


def acts_track(checkpoint_update):
    return {"checkpoint": acts_id(checkpoint_update),
            "scoreboard": {t: [0, 0, 0] for t in ("provisional", "standing", "mature")}}


def acts_entry(envelope, expect, why):
    text = envelope if isinstance(envelope, str) else json.dumps(envelope)
    return {"envelope_json": text, "expect": expect, "why": why}


def acts_tampered(envelope):
    """A well-formed signature over other bytes: the field checks pass and
    only verification fails."""
    other = dict(envelope["update"], effective_at="2026-08-05T12:00:01Z")
    forged = dict(envelope, sig=dict(envelope["sig"]))
    forged["sig"]["value"] = sign_envelope("update", other, ACTS_LOG_KEY_ID)["sig"]["value"]
    return forged


def acts_eligibility(text):
    """§9.1 raw JSON, field and version checks, before authentication."""
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError("duplicate member")
            result[k] = v
        return result
    try:
        doc = json.loads(text, object_pairs_hook=unique)
        rfc8785.dumps(doc)
    except (ValueError, rfc8785.CanonicalizationError):
        return "WIST1-E05", None
    u, s = doc.get("update"), doc.get("sig")
    general = (isinstance(doc, dict) and set(doc) == {"update", "sig"}
               and isinstance(u, dict) and isinstance(s, dict)
               and set(s) == {"key_id", "alg", "value"}
               and isinstance(s["key_id"], str) and len(s["key_id"]) <= 64
               and s["alg"] == "Ed25519"
               and isinstance(s["value"], str) and ACTS_B64U_64.fullmatch(s["value"])
               and {"wist_version", "action", "subject", "effective_at"} <= set(u)
               and set(u) <= {"wist_version", "action", "subject", "effective_at", "details", "evidence"}
               and isinstance(u["wist_version"], str) and ACTS_VERSION.fullmatch(u["wist_version"])
               and u["action"] in ("auditor_admit", "auditor_remove", "observer_register", "observer_checkpoint")
               and isinstance(u["subject"], str) and len(u["subject"]) <= 256
               and isinstance(u["effective_at"], str) and ACTS_INSTANT.fullmatch(u["effective_at"]))
    if general:
        try:
            datetime.datetime.strptime(u["effective_at"], "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            general = False
    if not general:
        return "WIST4-E11", None
    d = u.get("details")
    contract = isinstance(u["subject"], str) and ACTS_HOSTNAME.fullmatch(u["subject"]) and len(u["subject"]) <= 253
    if u["action"] in ("auditor_admit", "observer_register"):
        contract = (contract and isinstance(d, dict) and {"key_id", "alg", "public_key"} <= set(d)
                    and isinstance(d["key_id"], str) and len(d["key_id"]) <= 64 and d["alg"] == "Ed25519"
                    and isinstance(d["public_key"], str) and ACTS_B64U_32.fullmatch(d["public_key"]))
        if contract and "track_record" in d:
            t = d["track_record"]
            contract = (isinstance(t, dict) and set(t) == {"checkpoint", "scoreboard"}
                        and isinstance(t["checkpoint"], str) and ACTS_DIGEST.fullmatch(t["checkpoint"])
                        and isinstance(t["scoreboard"], dict) and set(t["scoreboard"]) == {"provisional", "standing", "mature"}
                        and all(isinstance(row, list) and len(row) == 3 and all(isinstance(n, int) and n >= 0 for n in row)
                                for row in t["scoreboard"].values()))
    elif u["action"] == "auditor_remove":
        contract = contract and isinstance(d, dict) and isinstance(d.get("key_id"), str) and len(d["key_id"]) <= 64
        if "evidence" in u:
            e = u["evidence"]
            contract = contract and isinstance(e, list) and len(e) >= 1 and all(isinstance(x, str) and len(x) <= 256 for x in e)
    else:
        contract = contract and isinstance(d, dict) and isinstance(d.get("head"), str) and ACTS_DIGEST.fullmatch(d["head"])
    if not contract:
        return "WIST4-E04", None
    if u["wist_version"].split(".")[0] != "1":
        return "WIST4-E11", None
    return None, doc


def acts_verifies(doc, public_key_b64u):
    try:
        key = Ed25519PublicKey_from_raw(base64.urlsafe_b64decode(public_key_b64u + "="))
        key.verify(base64.urlsafe_b64decode(doc["sig"]["value"] + "=="), rfc8785.dumps(doc["update"]))
        return True
    except Exception:
        return False


def Ed25519PublicKey_from_raw(raw):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    return Ed25519PublicKey.from_public_bytes(raw)


def acts_replay(blocks):
    """Outcomes per Entry and the roster after the last Block, by §9.1's
    eligibility gate, §3.1's batch and its post-batch checkpoint rule."""
    auditors, observers = {}, {}          # subject -> (key_id, public_key)
    retired, barred = set(), set()
    registered_below, checkpoints = set(), []   # subjects; (subject, height, id)
    outcomes = []
    for block in blocks:
        height = block["height"]
        codes = [None] * len(block["entries"])
        docs = [None] * len(block["entries"])
        for i, entry in enumerate(block["entries"]):
            code, doc = acts_eligibility(entry["envelope_json"])
            if code:
                codes[i] = code
                continue
            u = doc["update"]
            if u["action"] in ("auditor_admit", "auditor_remove"):
                if not (doc["sig"]["key_id"] == ACTS_LOG_KEY_ID and acts_verifies(doc, b64u(pub_raw))):
                    codes[i] = "WIST4-E11"
                    continue
            elif u["action"] == "observer_register":
                if not (doc["sig"]["key_id"] == u["details"]["key_id"] and acts_verifies(doc, u["details"]["public_key"])):
                    codes[i] = "WIST4-E11"
                    continue
            docs[i] = doc
        acts = [i for i, d in enumerate(docs) if d and d["update"]["action"] != "observer_checkpoint"]
        incumbent = dict(auditors)
        for i in acts:
            u = docs[i]["update"]
            if u["action"] != "auditor_remove":
                continue
            held = incumbent.get(u["subject"])
            if held is None or held[0] != u["details"]["key_id"]:
                codes[i] = "WIST4-E07"
                continue
            auditors.pop(u["subject"], None)
            retired.update(held)
            if u.get("evidence"):
                barred.add(u["subject"])
            codes[i] = "accepted"
        candidates = [i for i in acts if docs[i]["update"]["action"] != "auditor_remove"]
        live = set(candidates)
        for i in candidates:
            u = docs[i]["update"]
            if sum(1 for j in candidates if docs[j]["update"]["action"] == u["action"]
                   and docs[j]["update"]["subject"] == u["subject"]) > 1:
                codes[i] = "WIST4-E07"
                live.discard(i)
        for i in sorted(live):
            u = docs[i]["update"]
            key = (u["details"]["key_id"], u["details"]["public_key"])
            held_elsewhere = any(subject != u["subject"] and (k[0] == key[0] or k[1] == key[1])
                                 for mapping in (auditors, observers) for subject, k in mapping.items())
            if (not independent(u["subject"], ACTS_LOG_ID) or u["subject"] in auditors
                    or (u["action"] == "auditor_admit" and u["subject"] in barred)
                    or key[0] in retired or key[1] in retired or held_elsewhere):
                codes[i] = "WIST4-E07"
                live.discard(i)
                continue
            if u["action"] == "auditor_admit":
                history = u["subject"] in registered_below
                cited = u["details"].get("track_record")
                newest = max((c for c in checkpoints if c[0] == u["subject"] and c[1] < height),
                             key=lambda c: (c[1], c[2].encode()), default=None)
                ok = (cited is None) if not history else (cited is not None and newest is not None
                                                          and cited["checkpoint"] == newest[2])
                if not ok:
                    codes[i] = "WIST4-E04"
                    live.discard(i)
        admitting = {docs[i]["update"]["subject"] for i in live if docs[i]["update"]["action"] == "auditor_admit"}
        for i in sorted(live):
            u = docs[i]["update"]
            if u["action"] == "observer_register" and u["subject"] in admitting:
                codes[i] = "WIST4-E07"
                live.discard(i)
        for i in sorted(live):
            u = docs[i]["update"]
            for j in live:
                v = docs[j]["update"]
                if v["subject"] != u["subject"] and (v["details"]["key_id"] == u["details"]["key_id"]
                                                     or v["details"]["public_key"] == u["details"]["public_key"]):
                    codes[i] = "WIST4-E07"
        live = {i for i in live if codes[i] is None}
        for i in live:
            u = docs[i]["update"]
            key = (u["details"]["key_id"], u["details"]["public_key"])
            if u["action"] == "auditor_admit":
                auditors[u["subject"]] = key
                observers.pop(u["subject"], None)
            else:
                observers[u["subject"]] = key
            codes[i] = "accepted"
        for i, d in enumerate(docs):
            if not d or d["update"]["action"] != "observer_checkpoint":
                continue
            u = d["update"]
            registered = observers.get(u["subject"])
            if registered and d["sig"]["key_id"] == registered[0] and acts_verifies(d, registered[1]):
                checkpoints.append((u["subject"], height, acts_id(u)))
                codes[i] = "accepted"
            else:
                codes[i] = "WIST4-E07"
        registered_below.update(observers)
        outcomes.append(codes)
    return outcomes, {"auditors": {s: k[0] for s, k in auditors.items()},
                      "observers": {s: k[0] for s, k in observers.items()},
                      "checkpoints": [c[2] for c in sorted(checkpoints, key=lambda c: (c[1], c[2].encode()))]}


def acts_case(label, *blocks):
    """blocks: lists of (envelope, expect, why) tuples, one list per Block,
    sealed at heights 1, 2, …"""
    case = {"label": label, "blocks": [{"height": h, "entries": [acts_entry(*e) for e in entries]}
                                        for h, entries in enumerate(blocks, 1)]}
    outcomes, state = acts_replay(case["blocks"])
    expected = [[e["expect"] for e in b["entries"]] for b in case["blocks"]]
    assert outcomes == expected, (label, outcomes, expected)
    case.update(auditors_after=state["auditors"], observers_after=state["observers"],
                checkpoints_after=state["checkpoints"])
    return case


def acts_json_mutation(envelope, old, new):
    text = json.dumps(envelope)
    assert text.count(old) == 1, old
    return text.replace(old, new)


UNSEALED_HEAD = "sha256:" + sha256_hex(b"an ID no Entry carries")
roster_act_cases = []
admit_a = acts_admit(ACTS_A, "aud-a")
signed_admit_a = acts_log_signed(admit_a)
valid_admit = (signed_admit_a, "accepted", "Log-signed admission with complete fields")
noncanonical_sig = dict(signed_admit_a, sig=dict(signed_admit_a["sig"], value=signed_admit_a["sig"]["value"][:-1] + "B"))
for label, envelope, expect, why in (
    ("valid admission", signed_admit_a, "accepted", "complete fields, supported version, Log signature"),
    ("unknown envelope member", dict(signed_admit_a, extra=1), "WIST4-E11", "an unknown Envelope member is a general field failure"),
    ("unknown update member", acts_log_signed(dict(admit_a, note="x")), "WIST4-E11", "signed over the unknown member, so only the field fails"),
    ("unknown sig member", dict(signed_admit_a, sig=dict(signed_admit_a["sig"], note="x")), "WIST4-E11", "the signature block admits no unknown member"),
    ("signature alg spelling", dict(signed_admit_a, sig=dict(signed_admit_a["sig"], alg="ed25519")), "WIST4-E11", "alg is the exact constant Ed25519"),
    ("signature value non canonical", noncanonical_sig, "WIST4-E11", "nonzero trailing base64url bits fail the exact pattern"),
    ("signature value trailing newline", acts_json_mutation(signed_admit_a, signed_admit_a["sig"]["value"] + '"', signed_admit_a["sig"]["value"] + '\\n"'), "WIST4-E11", "exact whole-string patterns reject a trailing newline"),
    ("version leading zero", acts_log_signed(acts_admit(ACTS_A, "aud-a", version="01.0.0")), "WIST4-E11", "components carry no leading zero"),
    ("version trailing newline", acts_log_signed(acts_admit(ACTS_A, "aud-a", version="1.0.0\n")), "WIST4-E11", "signed over the malformed spelling, so only the field fails"),
    ("version unsupported major", acts_log_signed(acts_admit(ACTS_A, "aud-a", version="2.0.0")), "WIST4-E11", "a major other than 1 is not implemented"),
    ("version later minor accepted", acts_log_signed(acts_admit(ACTS_A, "aud-a", version="1.7.3")), "accepted", "a different minor or patch alone never rejects"),
    ("effective at leap second", acts_log_signed(acts_admit(ACTS_A, "aud-a", effective="2026-08-05T12:00:60Z")), "WIST4-E11", "a leap second is rejected, never normalized"),
    ("effective at no instant", acts_log_signed(acts_admit(ACTS_A, "aud-a", effective="2026-02-30T12:00:00Z")), "WIST4-E11", "the pattern passes but the calendar has no such day"),
    ("effective at offset form", acts_log_signed(acts_admit(ACTS_A, "aud-a", effective="2026-08-05T12:00:00+00:00")), "WIST4-E11", "only the whole-second literal-Z form compares against sealed_at"),
    ("details missing public key", acts_log_signed(acts_update("auditor_admit", ACTS_A, {"key_id": "aud-a", "alg": "Ed25519"})), "WIST4-E04", "a REQUIRED details member is missing"),
    ("details public key non canonical", acts_log_signed(acts_update("auditor_admit", ACTS_A, {"key_id": "aud-a", "alg": "Ed25519", "public_key": ACTS_PUB["aud-a"][:-1] + "B"})), "WIST4-E04", "the key pattern is exact and canonical"),
    ("details key id too long", acts_log_signed(acts_update("auditor_admit", ACTS_A, {"key_id": "k" * 65, "alg": "Ed25519", "public_key": ACTS_PUB["aud-a"]})), "WIST4-E04", "key_id exceeds the contract's bound"),
    ("subject one label", acts_log_signed(acts_admit("localhost", "aud-a")), "WIST4-E04", "an auditor_id has at least two labels"),
    ("subject uppercase", acts_log_signed(acts_admit("Watch.Alpha.Test", "aud-a")), "WIST4-E04", "the contract fixes lowercase hostname shape"),
    ("subject dependent on log id", acts_log_signed(acts_admit("audit.example.org", "aud-a")), "WIST4-E07", "eligible fields, then the roster's independence rule"),
    ("signature tampered", acts_tampered(signed_admit_a), "WIST4-E11", "well-formed signature over other bytes"),
    ("signed by a non Log key", acts_self_signed(admit_a, "stranger"), "WIST4-E11", "an admission verifies only under a Log key valid at its Block"),
    ("unknown member precedes details", dict(acts_log_signed(acts_update("auditor_admit", ACTS_A, {"key_id": "aud-a", "alg": "Ed25519"})), extra=1), "WIST4-E11", "E11 takes precedence over E04"),
    ("details precede signature", acts_tampered(acts_log_signed(acts_update("auditor_admit", ACTS_A, {"key_id": "aud-a", "alg": "Ed25519"}))), "WIST4-E04", "field failures take precedence over authenticity"),
    ("unknown member precedes signature", dict(acts_tampered(signed_admit_a), extra=1), "WIST4-E11", "field failures take precedence over authenticity"),
    ("fields precede roster rule", dict(acts_log_signed(acts_admit("audit.example.org", "aud-a")), extra=1), "WIST4-E11", "an ineligible act reaches no roster rule"),
    ("duplicate member", acts_json_mutation(signed_admit_a, '"subject": "watch.alpha.test"', '"subject": "watch.alpha.test", "subject": "watch.alpha.test"'), "WIST1-E05", "duplicate decoded member names fail JSON eligibility"),
    ("nested duplicate member", acts_json_mutation(signed_admit_a, '"alg": "Ed25519", "public_key"', '"alg": "Ed25519", "alg": "Ed25519", "public_key"'), "WIST1-E05", "duplicates inside details fail the same way"),
):
    roster_act_cases.append(acts_case("admission " + label, [(envelope, expect, why)]))

remove_a = acts_remove(ACTS_A, "aud-a")
signed_remove_a = acts_log_signed(remove_a)
for label, envelope, expect, why in (
    ("valid removal", signed_remove_a, "accepted", "the subject holds the named key before the Block"),
    ("empty evidence", acts_log_signed(acts_remove(ACTS_A, "aud-a", evidence=[])), "WIST4-E04", "evidence, where present, names at least one ID"),
    ("subject one label", acts_log_signed(acts_remove("localhost", "aud-a")), "WIST4-E04", "the removal names an auditor_id in hostname shape"),
    ("unknown member", dict(signed_remove_a, extra=1), "WIST4-E11", "general field failure"),
    ("tampered signature", acts_tampered(signed_remove_a), "WIST4-E11", "authenticity fails under the Log key"),
    ("unheld key", acts_log_signed(acts_remove(ACTS_A, "aud-b")), "WIST4-E07", "eligible fields, then the roster rule"),
    ("fields precede roster rule", dict(acts_log_signed(acts_remove(ACTS_A, "aud-b")), extra=1), "WIST4-E11", "an ineligible act reaches no roster rule"),
):
    roster_act_cases.append(acts_case("removal " + label, [valid_admit], [(envelope, expect, why)]))
roster_act_cases.append(acts_case("removal for cause bars the subject", [valid_admit],
    [(acts_log_signed(acts_remove(ACTS_A, "aud-a", evidence=[admission_head])), "accepted", "evidence makes the removal for cause")],
    [(acts_log_signed(acts_admit(ACTS_A, "aud-a2")), "WIST4-E07", "a barred subject is not re-admitted")]))

register_b = acts_register(ACTS_B, "obs-b1")
signed_register_b = acts_self_signed(register_b, "obs-b1")
small_order_register = acts_update("observer_register", ACTS_B, {"key_id": "small-order", "alg": "Ed25519", "public_key": ACTS_PUB["small-order"]})
for label, envelope, expect, why in (
    ("valid registration", signed_register_b, "accepted", "self-signed under the key it registers"),
    ("signed under another identifier", acts_self_signed(register_b, "obs-b1", key_id="obs-b2"), "WIST4-E11", "sig.key_id must be the very key_id the details name"),
    ("signed by the Log key", sign_envelope("update", register_b, "obs-b1"), "WIST4-E11", "the signature verifies under no key the rule admits"),
    ("under a small order key", acts_self_signed(small_order_register, "stranger", key_id="small-order"), "WIST4-E11", "nothing verifies under an unusable point"),
    ("unknown member", dict(signed_register_b, extra=1), "WIST4-E11", "general field failure"),
    ("subject one label", acts_self_signed(acts_register("localhost", "obs-b1"), "obs-b1"), "WIST4-E04", "an observer_id has at least two labels"),
    ("version unsupported major", acts_self_signed(acts_register(ACTS_B, "obs-b1", version="2.0.0"), "obs-b1"), "WIST4-E11", "the act's own version check"),
    ("dependent on log id", acts_self_signed(acts_register("watch.example.org", "obs-b1"), "obs-b1"), "WIST4-E07", "eligible fields, then the independence rule"),
):
    roster_act_cases.append(acts_case("registration " + label, [(envelope, expect, why)]))

register_a = acts_register(ACTS_A, "obs-a1")
valid_register = (acts_self_signed(register_a, "obs-a1"), "accepted", "self-signed registration")
checkpoint_a = acts_checkpoint(ACTS_A, admission_head)
signed_checkpoint_a = acts_self_signed(checkpoint_a, "obs-a1")
for label, envelope, expect, why in (
    ("valid checkpoint", signed_checkpoint_a, "accepted", "signed by the key registered at its Block"),
    ("head malformed", acts_self_signed(acts_checkpoint(ACTS_A, "sha256:notahash"), "obs-a1"), "WIST4-E04", "head is a REQUIRED details member checked by spelling"),
    ("head names a Delta", acts_self_signed(acts_checkpoint(ACTS_A, delta_id), "obs-a1"), "accepted", "replay reads spelling only; the scoreboard resolves what it covers"),
    ("head names no sealed entry", acts_self_signed(acts_checkpoint(ACTS_A, UNSEALED_HEAD), "obs-a1"), "accepted", "no sealed Entry is required under a head"),
    ("under an unregistered key", acts_self_signed(checkpoint_a, "stranger"), "WIST4-E07", "the key is not registered for the subject"),
    ("under the Log key", sign_envelope("update", checkpoint_a, ACTS_LOG_KEY_ID), "WIST4-E07", "an Aggregator key registers nothing"),
    ("for an unregistered subject", acts_self_signed(acts_checkpoint(ACTS_B, admission_head), "obs-a1"), "WIST4-E07", "the subject holds no registered key"),
    ("tampered signature", dict(signed_checkpoint_a, sig=dict(signed_checkpoint_a["sig"], value=acts_self_signed(acts_checkpoint(ACTS_A, UNSEALED_HEAD), "obs-a1")["sig"]["value"])), "WIST4-E07", "not authenticated under the registered key"),
    ("unknown member", dict(signed_checkpoint_a, extra=1), "WIST4-E11", "general field failure"),
    ("fields precede key rule", dict(acts_self_signed(checkpoint_a, "stranger"), extra=1), "WIST4-E11", "an ineligible act reaches no key rule"),
    ("version unsupported major", acts_self_signed(acts_checkpoint(ACTS_A, admission_head, version="2.0.0"), "obs-a1"), "WIST4-E11", "the act's own version check"),
):
    roster_act_cases.append(acts_case("checkpoint " + label, [valid_register], [(envelope, expect, why)]))

admit_a2 = acts_admit(ACTS_A, "aud-a2")
roster_act_cases.append(acts_case("ineligible admission forms no group", [
    valid_admit,
    (dict(acts_log_signed(admit_a2), extra=1), "WIST4-E11", "no candidate, so no same-subject group")]))
roster_act_cases.append(acts_case("two eligible admissions form a group", [
    (signed_admit_a, "WIST4-E07", "same-subject group of two"),
    (acts_log_signed(admit_a2), "WIST4-E07", "same-subject group of two")]))
roster_act_cases.append(acts_case("malformed details form no group", [
    valid_admit,
    (acts_log_signed(acts_update("auditor_admit", ACTS_A, {"key_id": "aud-a2", "alg": "Ed25519"})), "WIST4-E04", "rejected before the batch")]))
roster_act_cases.append(acts_case("unauthenticated admission holds no key", [
    valid_admit,
    (acts_self_signed(acts_admit(ACTS_B, "aud-a"), "stranger"), "WIST4-E11", "no candidate, so no cross-subject key conflict")]))
checkpoint_1 = acts_self_signed(checkpoint_a, "obs-a1")
roster_act_cases.append(acts_case("evidence rule is inside the batch",
    [valid_register, (checkpoint_1, "accepted", "checkpoint beside its own registration")],
    [(acts_log_signed(acts_admit(ACTS_A, "aud-a", acts_track(checkpoint_a))), "WIST4-E07", "stage 1 sees both admissions"),
     (acts_log_signed(admit_a2), "WIST4-E07", "the missing track_record is a stage 2 question never reached")]))
roster_act_cases.append(acts_case("roster rule precedes evidence rule",
    [valid_register, (checkpoint_1, "accepted", "checkpoint beside its own registration")],
    [(acts_log_signed(acts_admit(ACTS_A, "aud-a", acts_track(checkpoint_a))), "accepted", "cites the newest checkpoint below")],
    [(acts_log_signed(acts_remove(ACTS_A, "aud-a", evidence=[admission_head])), "accepted", "removal for cause")],
    [(acts_log_signed(admit_a2), "WIST4-E07", "barred subject; the missing track_record is not reached")]))

roster_act_cases.append(acts_case("registration beside admission establishes no history", [
    (acts_self_signed(register_a, "obs-a1"), "WIST4-E07", "stage 3 rejects the registration beside the accepted admission"),
    (signed_admit_a, "accepted", "no accepted registration below the Block, so no track_record is due")]))
assert roster_act_cases[-1]["auditors_after"] == {ACTS_A: "aud-a"} and roster_act_cases[-1]["observers_after"] == {}
roster_act_cases.append(acts_case("admission citing a same Block registration", [
    valid_register,
    (acts_log_signed(acts_admit(ACTS_A, "aud-a", acts_track(checkpoint_a))), "WIST4-E04", "no Observer history below the Block, yet a citation")]))
assert roster_act_cases[-1]["observers_after"] == {ACTS_A: "obs-a1"}
rotation_a = acts_self_signed(acts_register(ACTS_A, "obs-a2"), "obs-a2")
roster_act_cases.append(acts_case("rotation beside admission",
    [valid_register], [(checkpoint_1, "accepted", "checkpoint under the registered key")],
    [(rotation_a, "WIST4-E07", "stage 3 rejects the rotation beside the accepted admission"),
     (acts_log_signed(acts_admit(ACTS_A, "aud-a", acts_track(checkpoint_a))), "accepted", "cites the newest checkpoint below")]))
assert roster_act_cases[-1]["auditors_after"] == {ACTS_A: "aud-a"} and roster_act_cases[-1]["observers_after"] == {}
checkpoint_later = acts_checkpoint(ACTS_A, admission_head, effective="2026-08-06T12:00:00Z")
roster_act_cases.append(acts_case("same Block rotation and checkpoints",
    [valid_register],
    [(rotation_a, "accepted", "rotation to obs-a2"),
     (acts_self_signed(checkpoint_a, "obs-a1"), "WIST4-E07", "the old key is not registered after the Block's batch"),
     (acts_self_signed(checkpoint_later, "obs-a2"), "accepted", "the new key is registered from this Block's sealed_at")]))
assert roster_act_cases[-1]["checkpoints_after"] == [acts_id(checkpoint_later)]
roster_act_cases.append(acts_case("checkpoint beside its registration", [
    valid_register, (checkpoint_1, "accepted", "registered from this Block's sealed_at")]))
roster_act_cases.append(acts_case("checkpoint beside the admission of its subject",
    [valid_register], [(checkpoint_1, "accepted", "checkpoint below the admission")],
    [(acts_log_signed(acts_admit(ACTS_A, "aud-a", acts_track(checkpoint_a))), "accepted", "cites the newest checkpoint below"),
     (acts_self_signed(checkpoint_later, "obs-a1"), "WIST4-E07", "the subject holds no registered key once admitted in this Block")]))
assert roster_act_cases[-1]["checkpoints_after"] == [acts_id(checkpoint_a)]
roster_act_cases.append(acts_case("citation of a same Block checkpoint",
    [valid_register], [(checkpoint_1, "accepted", "checkpoint below the admission")],
    [(acts_self_signed(checkpoint_later, "obs-a1"), "accepted", "the admission is rejected, so the registration continues"),
     (acts_log_signed(acts_admit(ACTS_A, "aud-a", acts_track(checkpoint_later))), "WIST4-E04", "a same-Block checkpoint is never citable; the newest below is the earlier one")]))
assert roster_act_cases[-1]["observers_after"] == {ACTS_A: "obs-a1"}
assert roster_act_cases[-1]["checkpoints_after"] == [acts_id(checkpoint_a), acts_id(checkpoint_later)]
checkpoint_b = acts_checkpoint(ACTS_B, admission_head)
roster_act_cases.append(acts_case("rejected admission keeps the registration for its checkpoint",
    [valid_register, (acts_self_signed(register_b, "obs-b1"), "accepted", "second Observer"),
     (checkpoint_1, "accepted", "beside its registration"),
     (acts_self_signed(checkpoint_b, "obs-b1"), "accepted", "beside its registration")],
    [(acts_log_signed(acts_admit(ACTS_A, "aud-a", acts_track(checkpoint_a))), "WIST4-E07", "cross-subject key conflict at stage 4"),
     (acts_log_signed(acts_admit(ACTS_B, "aud-a", acts_track(checkpoint_b))), "WIST4-E07", "cross-subject key conflict at stage 4"),
     (acts_self_signed(checkpoint_later, "obs-a1"), "accepted", "the registration outlives the rejected admission")]))
assert roster_act_cases[-1]["observers_after"] == {ACTS_A: "obs-a1", ACTS_B: "obs-b1"} and roster_act_cases[-1]["auditors_after"] == {}

small_order_admit = acts_update("auditor_admit", ACTS_A, {"key_id": "small-order", "alg": "Ed25519", "public_key": ACTS_PUB["small-order"]})
roster_act_cases.append(acts_case("small order key is admitted as a string",
    [(acts_log_signed(small_order_admit), "accepted", "the admission checks spelling; replay reads no point validity")],
    [(acts_log_signed(acts_update("auditor_admit", ACTS_B, {"key_id": "other-id", "alg": "Ed25519", "public_key": ACTS_PUB["small-order"]})), "WIST4-E07", "the public_key is held by another subject"),
     (acts_log_signed(acts_update("auditor_admit", ACTS_C, {"key_id": "small-order", "alg": "Ed25519", "public_key": ACTS_PUB["aud-b"]})), "WIST4-E07", "the key_id is held by another subject")],
    [(acts_log_signed(acts_remove(ACTS_A, "small-order")), "accepted", "retires like any key")],
    [(acts_log_signed(acts_admit(ACTS_A, "aud-a")), "accepted", "a fresh key after the exit")]))
assert roster_act_cases[-1]["auditors_after"] == {ACTS_A: "aud-a"}
small_order_record = dict(audit_record, auditor_id=ACTS_A,
                          credit_commitment=audit_commit(RESPONSE_BODY + ACTS_A.encode()))
small_order_probe = sign_envelope_with(ACTS_PRIV["stranger"], "record", small_order_record, "small-order")

assert len(roster_act_cases) == len({c["label"] for c in roster_act_cases})
write_json(WIST4 / "roster-acts.json", spaced_labels({
    "spec": "WIST-4 sections 3, 3.1, 9.1, 10.2",
    "note": ("Signed roster-act histories: Blocks at heights 1, 2, ... in Log order, each Entry a Registry "
             "Update Envelope as raw JSON with its replay outcome. Eligibility follows section 9.1 in "
             "precedence: raw JSON (WIST1-E05), general fields and version (WIST4-E11), the action's "
             "details/evidence/subject contract (WIST4-E04), then authenticity (WIST4-E11; a checkpoint "
             "under an unregistered key is WIST4-E07); only eligible acts enter section 3.1's batch, where "
             "roster rules are WIST4-E07 and the evidence rule is WIST4-E04. An admission reads Observer "
             "history and citable checkpoints below its Block; a checkpoint reads the registrations after "
             "its Block's batch; an admitted public_key is a string at replay. Blocks are unsigned "
             "contexts here: consumers seal them under their own Log key at their own strictly increasing "
             "instants. The auditors, observers and accepted checkpoint IDs after the last Block are listed per "
             "case, checkpoints ordered by height then ID octets, since Entry position within a Block carries no meaning."),
    "log_id": ACTS_LOG_ID,
    "log_key": {"key_id": ACTS_LOG_KEY_ID, "public_key": b64u(pub_raw)},
    "keys": [{"key_id": k, "public_key": v} for k, v in sorted(ACTS_PUB.items())],
    "record_probe": {"note": ("A Record under the admitted small-order key: the roster holds the key as a string, "
                              "and every signature and proof under it fails verification."),
                     "envelope": small_order_probe, "expect": "WIST4-E01"},
    "cases": roster_act_cases,
}))
print("wist4 roster acts vector: %d cases" % len(roster_act_cases))

# ------------------------------------- WIST-4 §4: the Block's selection domain
# The VRF test runs over the Deltas of a Block that WIST-3 §7's one-URL,
# one-Publisher rule does not exclude at the Block's height: a parent's Delta
# for a host whose own seq-0 Declaration is sealed at or below the Block is
# outside every Auditor's draw. Abstract ids; the rule reads heights and hosts.
PARENT, SUB = "example.com", "blog.example.com"


def domain_entry(id_, publisher, url_host):
    return {"delta_id": id_, "publisher": publisher, "url_host": url_host}


def selection_domain_excluded(block_height, declarations, entries):
    declared = {d["domain"]: d["seq0_height"] for d in declarations}
    return [i for i, e in enumerate(entries)
            if e["url_host"] != e["publisher"]
            and e["url_host"] in declared and declared[e["url_host"]] <= block_height]


selection_domain_scenarios = [
    ("own-host-always-selectable", 9, [{"domain": SUB, "seq0_height": 5}],
     [domain_entry("d1", PARENT, PARENT)]),
    ("parent-delta-before-the-declaration", 4, [{"domain": SUB, "seq0_height": 5}],
     [domain_entry("d1", PARENT, SUB)]),
    ("parent-delta-at-the-declaration-height", 5, [{"domain": SUB, "seq0_height": 5}],
     [domain_entry("d1", PARENT, SUB)]),
    ("parent-delta-after-the-declaration", 9, [{"domain": SUB, "seq0_height": 5}],
     [domain_entry("d1", PARENT, SUB)]),
    ("subdomain-own-delta-selectable", 9, [{"domain": SUB, "seq0_height": 5}],
     [domain_entry("d1", SUB, SUB)]),
    ("unrelated-declaration-excludes-nothing", 9,
     [{"domain": "shop.example.com", "seq0_height": 1}],
     [domain_entry("d1", PARENT, SUB)]),
    ("mixed-block", 9, [{"domain": SUB, "seq0_height": 5}],
     [domain_entry("d1", PARENT, PARENT), domain_entry("d2", PARENT, SUB),
      domain_entry("d3", SUB, SUB), domain_entry("d4", PARENT, "shop.example.com")]),
]
selection_domain_cases = [
    {"label": label, "block_height": height, "declarations": declarations,
     "entries": entries,
     "excluded_indices": selection_domain_excluded(height, declarations, entries)}
    for label, height, declarations, entries in selection_domain_scenarios
]
assert [c["excluded_indices"] for c in selection_domain_cases] == \
    [[], [], [0], [0], [], [], [1]], "selection domain drifted"
self_audit_cases = [
    {"label": label, "auditor_id": auditor, "publisher": publisher,
     "barred": not independent(auditor, publisher)}
    for label, auditor, publisher in [
        ("independent-publisher", "audit.example.org", "shop.example.net"),
        ("publisher-under-the-auditors-suffix", "audit.example.net", "blog.example.net"),
        ("publisher-is-the-auditors-own-host", "audit.example.net", "audit.example.net"),
        ("shared-two-label-public-suffix", "a.com.br", "b.com.br"),
        ("auditor-is-the-publishers-subdomain", "audit.shop.example.org", "shop.example.org"),
    ]
]

write_json(WIST4 / "selection-domain.json", spaced_labels({
    "note": ("WIST-4 §4 selection domain: per case a Block's height, the seq-0 "
             "Declaration heights of self-declared hosts, the Block's Deltas as "
             "(publisher, url_host), and the indices outside every Auditor's draw; "
             "self_audit_cases give (auditor_id, publisher) pairs and whether §3 "
             "bars that Auditor from the Publisher's Deltas."),
    "cases": selection_domain_cases,
    "self_audit_cases": self_audit_cases,
}))
print("wist4 selection-domain vector: %d cases" % len(selection_domain_cases))


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
    return last_met is not None and (last_clear is None or last_clear <= last_met)


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
    return last_met is not None and (last_clear is None or last_clear <= last_met)


def ladder_level(levels, n_s):
    """WIST-4 §7: the highest rung in force at N, rungs given low to high."""
    for i in range(len(levels) - 1, -1, -1):
        met, clear = levels[i]
        if in_force(met, clear, n_s):
            return i + 1
    return 0


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
    ("appeal-sealed-at-t-discharges", 0, (14 + 7) * DAY_S, None),
    ("appeal-sealed-after-the-window-by-t-discharges", 0, 16 * DAY_S, None),
]
sanction_void_cases = [
    {"label": label, "notice_sealed_at_s": notice, "appeal_sealed_at_s": appeal,
     "ruling": ruling,
     "void_at_s": state_void_at(notice, appeal,
                                None if ruling is None else (ruling[0], ruling[1]))}
    for label, notice, appeal, ruling in sanction_void_scenarios
]
assert [c["void_at_s"] for c in sanction_void_cases[-3:]] == \
    [21 * DAY_S, 51 * DAY_S, 46 * DAY_S], "appeal timeliness reads the Block"
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

# §7: the three reversals that hang on a `notice` reach the level-3 and
# level-4 states and nothing below them, so a void leaves whichever lower
# rung its own criterion still puts in force. A `sanction_lift` reaches
# every rung at its height, and the criteria keep running past it.
VOID_AT_S = 21 * DAY_S
LIFT_AT_S = 21 * DAY_S
sanction_ladder_scenarios = [
    ("void-leaves-level-two",
     [[0], [0], [0], []], [[], [], [VOID_AT_S], []], 30 * DAY_S),
    ("void-leaves-level-one-when-two-was-never-met",
     [[0], [], [0], []], [[], [], [VOID_AT_S], []], 30 * DAY_S),
    ("void-of-level-four-leaves-level-two",
     [[0], [0], [0], [0]], [[], [], [VOID_AT_S], [VOID_AT_S]], 30 * DAY_S),
    ("before-the-void-the-level-stands",
     [[0], [0], [0], []], [[], [], [VOID_AT_S], []], 20 * DAY_S),
    ("lift-clears-every-rung",
     [[0], [0], [0], []], [[LIFT_AT_S], [LIFT_AT_S], [LIFT_AT_S], [LIFT_AT_S]],
     30 * DAY_S),
    ("a-criterion-met-after-a-lift-is-in-force-again",
     [[0, 25 * DAY_S], [0], [0], []],
     [[LIFT_AT_S], [LIFT_AT_S], [LIFT_AT_S], [LIFT_AT_S]], 30 * DAY_S),
]
sanction_ladder_cases = [
    {"label": label, "met_times_s": met, "clear_times_s": clear, "n_s": n,
     "level": ladder_level([(met[i], clear[i]) for i in range(4)], n)}
    for label, met, clear, n in sanction_ladder_scenarios
]


# §7: a lift clears rungs, never findings, so the count criteria keep reading
# every finding sealed before it; and level 4's three-severity-3 branch is the
# first to fire only where the level-3 state was cleared between the findings.
def ladder_from_findings(findings, lifts):
    l1 = criterion_times(findings, 1, None, 0)
    l2 = criterion_times(findings, *ESCALATIONS["l2"])
    l3 = sorted(set(criterion_times(findings, *ESCALATIONS["l3_count"])
                    + criterion_times(findings, 1, None, 3)))
    l4_count = criterion_times(findings, *ESCALATIONS["l4_sev3"])
    l4_accrual = l4_accrual_times(findings, l3, lifts)
    l4 = sorted(set(l4_count + l4_accrual))
    return [l1, l2, l3, l4], l4_count, l4_accrual


sanction_reversal_scenarios = [
    ("three-severity-3-across-two-lifts-reach-level-4-by-the-count-branch",
     [finding(0, 3), finding(30, 3), finding(50, 3)], [21 * DAY_S, 40 * DAY_S],
     [20, 25, 30, 45, 50]),
    ("without-the-lifts-the-second-finding-reaches-level-4-by-accrual",
     [finding(0, 3), finding(30, 3), finding(50, 3)], [], [20, 30, 50]),
    ("a-lift-clears-rungs-not-findings",
     [finding(0, 1), finding(10, 1), finding(20, 1)], [15 * DAY_S], [12, 20]),
]
sanction_reversal_cases = []
for label, findings, lifts, probe_days in sanction_reversal_scenarios:
    levels, l4_count, l4_accrual = ladder_from_findings(findings, lifts)
    sanction_reversal_cases.append({
        "label": label, "findings": findings, "lift_times_s": lifts,
        "met_times_s": levels, "l4_count_branch_times_s": l4_count,
        "l4_accrual_branch_times_s": l4_accrual,
        "probes": [{"n_s": d * DAY_S,
                    "level": ladder_level([(m, lifts) for m in levels], d * DAY_S)}
                   for d in probe_days],
    })
assert [[p["level"] for p in c["probes"]] for c in sanction_reversal_cases] == \
    [[3, 0, 3, 0, 4], [3, 4, 4], [1, 2]], "reversal cases drifted"
assert sanction_reversal_cases[0]["l4_accrual_branch_times_s"] == [] and \
    sanction_reversal_cases[0]["l4_count_branch_times_s"] == [50 * DAY_S]

def sanction_transitions(blocks):
    active, findings, levels = set(), [], []
    for block in blocks:
        if block["lift"]:
            active.clear()
        active.difference_update(block["void_levels"])
        for finding in sorted(block["findings"], key=lambda f: f["entry_index"]):
            was_three = 3 in active
            findings.append((block["sealed_at_s"], finding["severity"]))
            recent = [s for t, s in findings if block["sealed_at_s"] - t < 90 * DAY_S]
            severe = [s for t, s in findings if block["sealed_at_s"] - t < 180 * DAY_S and s == 3]
            active.add(1)
            if len(recent) >= 3:
                active.add(2)
            if len(recent) >= 10 or finding["severity"] == 3:
                active.add(3)
            if was_three or finding["severity"] == 3 and len(severe) >= 3:
                active.add(4)
        levels.append(sorted(active))
    return levels

sanction_transition_cases = []
for label, rows, expected in (
    ("level two survives evidence aging", [(0, [1], False, []), (1, [1], False, []), (2, [1], False, []), (120, [], False, [])], [1, 1, 2, 2]),
    ("high void preserves aged lower rung", [(0, [1], False, []), (1, [1], False, []), (2, [1], False, []), (3, [3], False, []), (120, [], False, [3])], [1, 1, 2, 3, 2]),
    ("void rearms only on qualifying new finding", [(0, [3], False, []), (10, [], False, [3]), (11, [], False, []), (12, [1], False, []), (13, [3], False, []), (14, [1], False, [])], [3, 1, 1, 1, 3, 4]),
    ("lift precedes same Block finding", [(0, [3], False, []), (1, [1], True, [])], [3, 1]),
    ("same Block severity and further finding", [(0, [3, 1], False, [])], [4]),
    ("same Block reverse finding order", [(0, [1, 3], False, [])], [3]),
    ("one finding cannot be its own further finding", [(0, [3], False, [])], [3]),
    ("void precedes same Block new severity finding", [(0, [3], False, []), (1, [3], False, [3])], [3, 3]),
):
    blocks = [{"height": i, "sealed_at_s": day * DAY_S, "lift": lift,
               "void_levels": voids, "findings": [{"entry_index": j, "severity": severity}
                                                   for j, severity in enumerate(severities)]}
              for i, (day, severities, lift, voids) in enumerate(rows)]
    active = sanction_transitions(blocks)
    assert [max(a, default=0) for a in active] == expected
    sanction_transition_cases.append({"label": label, "blocks": blocks,
                                     "active_rungs": active, "levels": expected})

def process_result(notice, acts, n_s, activation_s=-1):
    if notice["update"]["details"]["kind"] != "sanction":
        return {"appeal_index": None, "merits_index": None, "unappealed_index": None, "void_at_s": None}
    notice_id = "sha256:" + sha256_hex(rfc8785.dumps(notice["update"]))
    seen, entries = set(), []
    for i, event in sorted(enumerate(acts), key=lambda pair: pair[1]["sealed_at_s"]):
        if event["sealed_at_s"] > n_s:
            continue
        inner = event["envelope"]["update"]
        rid = "sha256:" + sha256_hex(rfc8785.dumps(inner))
        if rid in seen:
            continue
        seen.add(rid)
        if (notice["update"]["details"]["kind"] == "sanction"
                and inner["subject"] == notice["update"]["subject"]
                and inner["details"]["notice"] == notice_id):
            entries.append((i, event["sealed_at_s"], inner))
    def first_slot(candidates):
        for instant in sorted({t for _, t, _ in candidates}):
            group = [e for e in candidates if e[1] == instant]
            if len(group) == 1:
                return group[0]
        return None
    appeal = first_slot([e for e in entries if e[2]["action"] == "appeal"])
    timely = appeal if appeal is not None and appeal[1] <= 21 * DAY_S else None
    merits = first_slot([e for e in entries if e[2]["action"] == "appeal_ruling"
                        and e[1] > activation_s
                        and e[2]["details"]["outcome"] in ("upheld", "overturned")
                        and timely is not None and timely[1] <= e[1] <= timely[1] + 30 * DAY_S])
    unappealed = first_slot([e for e in entries if e[2]["action"] == "appeal_ruling"
                           and e[2]["details"]["outcome"] == "unappealed"
                           and 14 * DAY_S <= e[1] <= 21 * DAY_S
                           and (timely is None or e[1] < timely[1])])
    void = None
    if timely is None:
        if unappealed is None and n_s >= 21 * DAY_S:
            void = 21 * DAY_S
    elif merits is not None:
        if merits[2]["details"]["outcome"] == "overturned":
            void = merits[1]
    elif n_s >= timely[1] + 30 * DAY_S:
        void = timely[1] + 30 * DAY_S
    return {"appeal_index": None if appeal is None else appeal[0],
            "merits_index": None if merits is None else merits[0],
            "unappealed_index": None if unappealed is None else unappealed[0],
            "void_at_s": void}

process_notice = sign_envelope("update", {
    "wist_version": "1.0.0", "action": "notice", "subject": "page.publisher.test",
    "effective_at": "2026-08-02T00:00:00Z",
    "details": {"kind": "sanction", "level": 3, "activation": "sha256:" + "1" * 64, "reason": "confirmed evidence",
                "appeal_deadline": "2026-08-16T00:00:00Z"},
    "evidence": ["sha256:" + "0" * 64],
}, "test-process-k1")
process_notice_id = "sha256:" + sha256_hex(rfc8785.dumps(process_notice["update"]))
process_cases = []
for label, rows, void_day in (
    ("first upheld ruling wins", [(1, "appeal"), (10, "upheld"), (11, "overturned")], None),
    ("first overturned ruling wins", [(1, "appeal"), (10, "overturned"), (11, "upheld")], 10),
    ("same Block conflicting rulings both rejected", [(1, "appeal"), (10, "upheld"), (10, "overturned")], 31),
    ("valid ruling after rejected conflict", [(1, "appeal"), (10, "upheld"), (10, "overturned"), (11, "upheld")], None),
    ("same Block competing appeals both rejected", [(1, "appeal"), (1, "appeal")], 21),
    ("later appeal after rejected conflict", [(1, "appeal"), (1, "appeal"), (2, "appeal")], 32),
    ("later distinct appeal cannot restart clock", [(1, "appeal"), (20, "appeal")], 31),
    ("same Block appeal before ruling", [(10, "upheld"), (10, "appeal")], None),
    ("ruling before appeal is ineligible", [(0, "upheld"), (1, "appeal")], 31),
    ("appeal overrides earlier unappealed statement", [(14, "unappealed"), (20, "appeal")], 50),
    ("late merits ruling cannot cure expiry", [(1, "appeal"), (32, "upheld")], 31),
    ("ruling exactly at deadline", [(1, "appeal"), (31, "upheld")], None),
    ("duplicate appeal ID is idempotent", [(1, "appeal"), (1, "duplicate")], 31),
    ("same Block competing unappealed statements", [(14, "unappealed"), (14, "unappealed")], 21),
):
    acts = []
    for i, (day, kind) in enumerate(rows):
        if kind == "duplicate":
            envelope = acts[0]["envelope"]
        else:
            details = {"notice": process_notice_id}
            if kind != "appeal":
                details.update({"outcome": kind, "reasoning": "decision " + str(i)})
            else:
                details["statement"] = "appeal " + str(i)
            envelope = sign_envelope("update", {
                "wist_version": "1.0.0", "action": "appeal" if kind == "appeal" else "appeal_ruling",
                "subject": "page.publisher.test", "effective_at": "2026-08-02T00:00:00Z",
                "details": details,
            }, "test-process-k1")
        acts.append({"sealed_at_s": day * DAY_S, "envelope": envelope})
    result = process_result(process_notice, acts, 60 * DAY_S)
    assert result["void_at_s"] == (None if void_day is None else void_day * DAY_S), label
    process_cases.append({"label": label, "acts": acts,
        "probes": [{"n_s": day * DAY_S, "expected": process_result(process_notice, acts, day * DAY_S)}
                   for day in sorted({0, 14, 21, 31, 50, 60} | {d for d, _ in rows})]})

for outcome, later in (("overturned", False), ("overturned", True), ("upheld", False)):
    inner = json.loads(json.dumps(process_notice["update"]))
    inner["evidence"].append(inner["details"]["activation"])
    notice = sign_envelope("update", inner, "test-process-k1")
    notice_id = "sha256:" + sha256_hex(rfc8785.dumps(inner))
    acts = []
    rows = [(0, "appeal"), (0, outcome)] + ([(3600, "overturned")] if later else [])
    for i, (instant, kind) in enumerate(rows):
        details = {"notice": notice_id}
        if kind != "appeal":
            details.update(outcome=kind, reasoning="activation ruling " + str(i))
        envelope = sign_envelope("update", {
            "wist_version": "1.0.0", "subject": inner["subject"],
            "effective_at": "2026-08-02T00:00:00Z",
            "action": "appeal" if kind == "appeal" else "appeal_ruling", "details": details,
        }, "test-process-k1")
        acts.append({"sealed_at_s": instant, "envelope": envelope})
    expected_merits = 2 if later else None
    assert process_result(notice, acts, 3600, 0)["merits_index"] == expected_merits
    process_cases.append({"label": "activation Block " + outcome + (" with later ruling" if later else " alone"),
        "notice": notice, "activation_sealed_at_s": 0, "activation_severity": 3,
        "acts": acts, "same_block_ruling_error": "WIST4-E05",
        "levels": [3, 1 if later else 3],
        "probes": [{"n_s": t, "expected": process_result(notice, acts, t, 0)} for t in (0, 3600)]})

for label in ("nonexistent notice", "other subject notice", "recovery notice"):
    notice = json.loads(json.dumps(process_notice))
    if label == "recovery notice":
        inner = notice["update"]
        inner["details"] = {"kind": "recovery"}
        inner.pop("evidence")
        notice = sign_envelope("update", inner, "test-process-k1")
    target = "sha256:" + sha256_hex(rfc8785.dumps(notice["update"]))
    envelope = sign_envelope("update", {
        "wist_version": "1.0.0", "action": "appeal",
        "subject": "other.publisher.test" if label == "other subject notice" else "page.publisher.test",
        "effective_at": "2026-08-02T00:00:00Z",
        "details": {"notice": "sha256:" + "1" * 64 if label == "nonexistent notice" else target},
    }, "test-process-k1")
    acts = [{"sealed_at_s": DAY_S, "envelope": envelope}]
    process_cases.append({"label": label, "notice": notice, "acts": acts,
        "probes": [{"n_s": 21 * DAY_S, "expected": process_result(notice, acts, 21 * DAY_S)}]})
    assert process_cases[-1]["probes"][0]["expected"]["appeal_index"] is None

retired_escalation_cases = []
for parameter, value, severities, expected in (
    ("escalation_l2", 1, [1, 1, 1], [1, 1, 2]),
    ("escalation_l3", 1, [1, 3], [1, 3]),
    ("escalation_l4", 1, [3, 1], [3, 4]),
):
    envelope = sign_envelope("update", {"wist_version": "1.0.0", "action": "parameter_change",
        "subject": "log.sample.net", "effective_at": "2026-08-12T00:00:00Z",
        "details": {"parameter": parameter, "value": value}}, "test-process-k1")
    blocks = [{"height": i + 200, "sealed_at_s": (8 + i) * DAY_S, "lift": False,
        "void_levels": [], "findings": [{"entry_index": 0, "severity": severity}]}
        for i, severity in enumerate(severities)]
    active = sanction_transitions(blocks)
    assert [max(a) for a in active] == expected
    retired_escalation_cases.append({"label": parameter + " has no numeric mapping", "envelope": envelope,
        "sealed_at": "2026-08-01T00:00:00Z", "error": "WIST4-E03", "blocks": blocks,
        "active_rungs": active, "levels": expected})

primary_findings = []
for n, similarities in enumerate(([0, 0], [200000, 250000])):
    ids = ["sha256:" + sha256_hex(("primary finding " + str(n) + " record " + str(i)).encode()) for i in range(2)]
    primary_findings.append({"subject": "site.sample.net", "confirming_record": ids[-1],
        "records": [{"id": ident, "effective_similarity": similarity} for ident,similarity in zip(ids,similarities)]})
primary_cases = []
all_primary_ids = [r["id"] for f in primary_findings for r in f["records"]]
primary_rejected_ids = ["sha256:" + sha256_hex(b"primary rejected optional record")]
for label, primary, evidence, severity, subject, error in (
    ("mixed optional findings", primary_findings[0]["confirming_record"], all_primary_ids, 3, "site.sample.net", None),
    ("unnoticed level three sanction is recorded", primary_findings[0]["confirming_record"], all_primary_ids, 3, "site.sample.net", None),
    ("citation of a rejected Record resolves", primary_findings[0]["confirming_record"], all_primary_ids + primary_rejected_ids, 3, "site.sample.net", None),
    ("reversed mixed evidence", primary_findings[0]["confirming_record"], list(reversed(all_primary_ids)), 3, "site.sample.net", None),
    ("minor primary with severe optional finding", primary_findings[1]["confirming_record"], all_primary_ids, 1, "site.sample.net", None),
    ("severity from optional finding is wrong", primary_findings[0]["confirming_record"], all_primary_ids, 1, "site.sample.net", "WIST4-E05"),
    ("first quorum member is not confirming Record", all_primary_ids[0], all_primary_ids, 3, "site.sample.net", "WIST4-E05"),
    ("primary quorum incomplete", primary_findings[0]["confirming_record"], all_primary_ids[1:], 3, "site.sample.net", "WIST4-E05"),
    ("finding belongs to another subject", primary_findings[0]["confirming_record"], all_primary_ids, 3, "other.sample.net", "WIST4-E05"),
    ("missing primary selector", None, all_primary_ids, 3, "site.sample.net", "WIST4-E04"),
):
    details = {"level": 3, "severity": severity}
    if primary is not None:
        details["finding"] = primary
    envelope = sign_envelope("update", {"wist_version": "1.0.0", "action": "sanction",
        "subject": subject, "effective_at": "2026-08-12T00:00:00Z", "details": details,
        "evidence": evidence}, "test-process-k1")
    f = next((f for f in primary_findings if f["confirming_record"] == primary), None)
    valid = f is not None and subject == f["subject"] and all(r["id"] in evidence for r in f["records"])
    if valid:
        sim = max(r["effective_similarity"] for r in f["records"])
        valid = severity == (1 if sim >= 150000 else 2 if sim >= 50000 else 3)
    assert valid == (error is None), label
    primary_cases.append({"label": label, "envelope": envelope, "error": error,
                          "noticed": label != "unnoticed level three sanction is recorded"})

NOTICE_ACTIVATION_A = "sha256:" + sha256_hex(b"notice activation A")
NOTICE_ACTIVATION_B = "sha256:" + sha256_hex(b"notice activation B")
notice_target_cases = []
for label, rows, accepted_expected, remaining in (
    ("one process survives later notice", [(1,3,NOTICE_ACTIVATION_A,0), (2,3,NOTICE_ACTIVATION_A,1)], [0], None),
    ("simultaneous notices conflict", [(1,3,NOTICE_ACTIVATION_A,0), (1,3,NOTICE_ACTIVATION_A,1)], [], NOTICE_ACTIVATION_A),
    ("conflict allows later notice", [(1,3,NOTICE_ACTIVATION_A,0), (1,3,NOTICE_ACTIVATION_A,1), (2,3,NOTICE_ACTIVATION_A,2)], [2], None),
    ("duplicate notice is one process", [(1,3,NOTICE_ACTIVATION_A,0), (1,3,NOTICE_ACTIVATION_A,0), (2,3,NOTICE_ACTIVATION_A,0)], [0], None),
    ("wrong level blocks nobody", [(1,4,NOTICE_ACTIVATION_A,0), (1,3,NOTICE_ACTIVATION_A,1)], [1], None),
    ("unknown activation", [(1,3,NOTICE_ACTIVATION_B,0)], [], NOTICE_ACTIVATION_A),
    ("same Block activation", [(0,3,NOTICE_ACTIVATION_A,0)], [0], None),
    ("missing activation", [(1,3,None,0)], [], NOTICE_ACTIVATION_A),
    ("foreign subject activation", [(1,3,NOTICE_ACTIVATION_A,0)], [], NOTICE_ACTIVATION_A),
    ("notice cannot target cleared activation", [(3,3,NOTICE_ACTIVATION_A,0)], [], NOTICE_ACTIVATION_B),
    ("old reversal leaves rearmed rung", [(1,3,NOTICE_ACTIVATION_A,0)], [0], NOTICE_ACTIVATION_B),
):
    notices = []
    for height,level,activation,variant in rows:
        details = {"kind": "sanction", "level": level, "reason": "confirmed finding " + str(variant),
            "appeal_deadline": "2026-08-16T00:00:00Z"}
        if activation is not None:
            details["activation"] = activation
        envelope = sign_envelope("update", {"wist_version": "1.0.0", "action": "notice",
            "subject": "other.sample.net" if label == "foreign subject activation" else "site.sample.net", "effective_at": "2026-08-02T00:00:00Z", "details": details,
            "evidence": [NOTICE_ACTIVATION_A, "sha256:" + "2" * 64]}, "test-process-k1")
        notices.append({"height": height, "envelope": envelope})
    seen, accepted = set(), []
    for height in sorted({n["height"] for n in notices}):
        eligible = []
        for i,n in enumerate(notices):
            if n["height"] != height:
                continue
            u = n["envelope"]["update"]; ident = sha256_hex(rfc8785.dumps(u))
            if ident in seen:
                continue
            seen.add(ident)
            if (u["details"].get("activation") == NOTICE_ACTIVATION_A and u["details"]["level"] == 3 and not accepted
                    and u["subject"] == "site.sample.net" and label != "notice cannot target cleared activation"):
                eligible.append(i)
        if len(eligible) == 1:
            accepted.extend(eligible)
    assert accepted == accepted_expected, label
    current = NOTICE_ACTIVATION_B if label in ("old reversal leaves rearmed rung", "notice cannot target cleared activation") else NOTICE_ACTIVATION_A
    after = None if accepted and current == NOTICE_ACTIVATION_A else current
    assert after == remaining
    notice_target_cases.append({"label": label, "activation": {"subject": "site.sample.net", "level": 3,
        "record_id": NOTICE_ACTIVATION_A, "height": 0, "cleared_height": 2 if label == "notice cannot target cleared activation" else None}, "notices": notices,
        "accepted_indices": accepted, "current_activation_at_reversal": current,
        "activation_after_reversal": after})

# ------------------------------------ WIST-4 §§6.3/7: ladder inputs and identity
def identity_scoped_transitions(blocks, count_pre_reset=False, honor_rejected_lifts=False):
    active, findings, levels = set(), [], []
    for block in blocks:
        if block.get("reset"):
            active.clear()
            findings.clear()
        if block["lift"] and (block.get("lift_accepted", True) or honor_rejected_lifts):
            active.clear()
        for finding in sorted(block["findings"], key=lambda f: f["entry_index"]):
            if finding.get("pre_reset") and not count_pre_reset:
                continue
            was_three = 3 in active
            findings.append((block["sealed_at_s"], finding["severity"]))
            recent = [s for t, s in findings if block["sealed_at_s"] - t < 90 * DAY_S]
            severe = [s for t, s in findings if block["sealed_at_s"] - t < 180 * DAY_S and s == 3]
            active.add(1)
            if len(recent) >= 3:
                active.add(2)
            if len(recent) >= 10 or finding["severity"] == 3:
                active.add(3)
            if was_three or finding["severity"] == 3 and len(severe) >= 3:
                active.add(4)
        levels.append(sorted(active))
    return levels


identity_scope_cases = []
for label, rows, expected in (
    ("a pre reset finding arms nothing", [(0, [(3, False)], False, True, False), (5, [(3, True)], True, True, False),
                                         (6, [(1, False)], False, True, False)], [3, 0, 1]),
    ("a reset lifts every rung", [(0, [(3, False)], False, True, False), (2, [], True, True, False)], [3, 0]),
    ("a rejected lift clears nothing", [(0, [(1, False)], False, True, False), (1, [], False, False, True),
                                       (2, [], False, True, True)], [1, 1, 0]),
):
    blocks = []
    for i, (day, severities, reset, lift_accepted, lift) in enumerate(rows):
        blocks.append({"height": i, "sealed_at_s": day * DAY_S, "reset": reset, "lift": lift,
                       "lift_accepted": lift_accepted, "void_levels": [],
                       "findings": [{"entry_index": j, "severity": severity, "pre_reset": pre}
                                    for j, (severity, pre) in enumerate(severities)]})
    active = identity_scoped_transitions(blocks)
    assert [max(a, default=0) for a in active] == expected, label
    identity_scope_cases.append({"label": label, "blocks": blocks, "active_rungs": active, "levels": expected})
assert identity_scoped_transitions(identity_scope_cases[0]["blocks"], count_pre_reset=True)[1] == [1, 3]
assert identity_scoped_transitions(identity_scope_cases[2]["blocks"], honor_rejected_lifts=True)[1] == []


def instant_level(case, at_s, sealed_only=False):
    """WIST-4 §7, enforcement at an instant: the derived level at the latest
    Block sealed at or before the instant, voided to the fallback rung where
    an undischarged sealing or ruling deadline is at or before the instant.
    `sealed_only` is the ruled-out reading that waits for the next Block."""
    latest = max((b for b in case["blocks"] if b <= at_s), default=None)
    if latest is None:
        return 0
    t_s = case["notice_sealed_at_s"] + (APPEAL_WINDOW_DAYS + APPEAL_SEAL_DAYS) * DAY_S
    discharged = case["discharge_sealed_at_s"] is not None and case["discharge_sealed_at_s"] <= latest
    void_at = None if discharged else t_s
    boundary = latest if sealed_only else at_s
    return case["fallback_level"] if void_at is not None and void_at <= boundary else case["level"]


instant_cases = []
for label, discharge, probes in (
    ("silence voids between Blocks", None, [20 * DAY_S, 21 * DAY_S, 21 * DAY_S + HOUR_S, 22 * DAY_S]),
    ("discharge sealed before T keeps the state", 15 * DAY_S, [21 * DAY_S + HOUR_S, 22 * DAY_S]),
):
    case = {"label": label, "notice_sealed_at_s": 0, "level": 3, "fallback_level": 1,
            "blocks": [0, 15 * DAY_S, 22 * DAY_S], "discharge_sealed_at_s": discharge}
    case["probes"] = [{"at_s": at, "level": instant_level(case, at)} for at in probes]
    instant_cases.append(case)
assert [[p["level"] for p in c["probes"]] for c in instant_cases] == [[3, 1, 1, 1], [3, 3]], "instant cases drifted"
assert instant_level(instant_cases[0], 21 * DAY_S + HOUR_S, sealed_only=True) == 3, "the sealed-only reading must differ"


def lift_case(label, code, *, signer=priv, key_id="test-agg-k1", subject="site.sample.net", version="1.0.0",
              extra=None, details=None):
    update = {"wist_version": version, "action": "sanction_lift", "subject": subject,
              "effective_at": "2026-08-05T12:00:00Z", "details": {"reason": "discretionary"} if details is None else details}
    if extra:
        update.update(extra)
    return {"label": label, "envelope_json": json.dumps(sign_envelope_with(signer, "update", update, key_id),
                                                          ensure_ascii=True), "code": code}


lift_cases = [
    lift_case("valid lift", None),
    lift_case("lift signed by an Auditor key", "WIST4-E11", signer=priv2, key_id="receipt-auditor-k1"),
    lift_case("lift unsupported major", "WIST4-E11", version="2.0.0"),
    lift_case("lift unknown member", "WIST4-E11", extra={"note": "x"}),
    lift_case("lift subject not a host", "WIST4-E04", subject="not a host!"),
    lift_case("lift without details", None, details={}),
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
    "ladder_cases": sanction_ladder_cases,
    "reversal_cases": sanction_reversal_cases,
    "transition_cases": sanction_transition_cases,
    "identity_scope_note": ("WIST-4 §§6.3/7: a finding whose Delta is sealed below the identity's most recent "
                            "reset arms no rung of the fresh identity (`pre_reset`), a reset lifts every rung "
                            "and clears the findings the counts read, and a rejected `sanction_lift` "
                            "(`lift_accepted` false) clears nothing."),
    "identity_scope_cases": identity_scope_cases,
    "lift_note": ("WIST-4 §9.1: a sanction_lift is authenticated under the Log key; Envelope, version, "
                  "unknown-member and signature failures are WIST4-E11, a subject outside the Canonical "
                  "Host shape WIST4-E04."),
    "lift_log_key": ATTESTATION_LOG_KEY,
    "lift_cases": lift_cases,
    "instant_note": ("WIST-4 §7, enforcement between Blocks: the Aggregator reads the latest sealed Block's "
                     "derived level and treats an undischarged sealing deadline T at or before the instant "
                     "as void from the instant, falling to the highest active rung at or below 2; a "
                     "discharge sealed before T keeps the state. Blocks are sealing instants."),
    "instant_cases": instant_cases,
    "notice_target_cases": notice_target_cases,
    "notice_evidence_cases": notice_evidence.cases(),
    "retired_escalation_cases": retired_escalation_cases,
    "primary": {"note": "Each supplied closed confirming set has two independent Auditors within the default window, in listed Log order; all Records are valid and sealed before the sanction. IDs denote those fixture Records; rejected_available_ids are Records §3/§10.1 reject that are nevertheless sealed and so available to cite. Notice and level eligibility are satisfied independently except where `noticed` is false, which records a sanction sealed before any accepted notice of its level: recorded, not rejected. These cases isolate the primary finding/evidence contract.",
                "rejected_available_ids": primary_rejected_ids,
        "findings": primary_findings, "cases": primary_cases},
    "process": {"note": "Each notice's activation and evidence are supplied valid premises. Unless a case gives activation_sealed_at_s, its target was armed below the notice Block. Explicit activation-Block cases supply the new severity-3 finding and exercise its timing with rung replay.",
                "public_key": b64u(pub_raw), "notice_sealed_at_s": 0,
                "notice": process_notice, "cases": process_cases},
}))


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
        act("signed by an Auditor key", "WIST4-E11", signer=priv2, key_id="receipt-auditor-k1"),
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

    def record_case(label, withdrawal_height, record_height, verdict, unmeasured=None,
                    reference_withdrawn=True):
        e02 = (reference_withdrawn and record_height > withdrawal_height
               and not (verdict == "not_auditable" and unmeasured == "reference"))
        return {"label": label, "withdrawal_height": withdrawal_height, "record_height": record_height,
                "reference_withdrawn": reference_withdrawn, "verdict": verdict, "unmeasured": unmeasured,
                "expected": "WIST4-E02" if e02 else "evidence"}

    records = [
        record_case("measured below the withdrawal", 3, 2, "consistent"),
        record_case("measured in the withdrawal's Block", 3, 3, "inconsistent"),
        record_case("measured above the withdrawal", 3, 4, "consistent"),
        record_case("inconsistent above the withdrawal", 3, 5, "inconsistent"),
        record_case("unreachable above the withdrawal", 3, 4, "unreachable"),
        record_case("not auditable observed above the withdrawal", 3, 4, "not_auditable", "observed"),
        record_case("not auditable reference above the withdrawal", 3, 4, "not_auditable", "reference"),
        record_case("another reference above the withdrawal", 3, 4, "consistent", reference_withdrawn=False),
    ]
    return spaced_labels({
        "note": ("WIST-4 §9.1: a payload_withdrawal is authenticated under the Log key (WIST4-E11 otherwise) and "
                 "must name a Delta sealed at or below its Block whose signed publisher is the subject "
                 "(WIST4-E04 otherwise); the earliest accepted withdrawal's Block governs. WIST-4 §5: a Record "
                 "sealed above that Block whose reference_delta is the withdrawn Delta is evidence only as "
                 "not_auditable with unmeasured reference; Records at or below it stand. Acts replay in order."),
        "log_key": ATTESTATION_LOG_KEY, "sealed_deltas": sealed, "act_cases": acts, "record_cases": records})


write_json(WIST4 / "withdrawal.json", withdrawal_vectors())


# ------------------------ WIST-4 §5.1, §5.2: canary domains, credit, hard hit
# A planter commits to future served bytes as a Merkle root, the canary
# domain later binds leaves to its Deltas, and every measured Record's
# credit_commitment — the Payload salt over the served bytes with the signer
# appended — is scored against the revealed bytes. The three revealed leaves
# below are one URL's chain: the example Delta and two attests of it, so
# every leaf's Reference Payload is examples/payload.json and its salt.
CANARY_PLANTER = "planter.example.io"
CANARY_DOMAIN = "example.com"
CANARY_AUD_A, CANARY_AUD_B, CANARY_AUD_C = AUD_A, AUD_B, AUD_C


def canary_nonce(i: int) -> bytes:
    """A production nonce is 16+ CSPRNG octets, fresh per leaf; this
    generator derives one from a fixed string so the vector stays
    byte-reproducible."""
    return hashlib.sha256(b"wist-test-canary-nonce|" + str(i).encode()).digest()[:16]


CANARY_FILLER = " ".join("filler%d" % k for k in range(40))


def canary_page(text: str, nonce: bytes | None) -> bytes:
    comment = "" if nonce is None else "<!-- wist-canary: %s -->" % nonce.hex()
    return ("<!doctype html><html><body>%s<p>%s</p><p>%s</p></body></html>"
            % (comment, text, CANARY_FILLER)).encode()


def canary_derived(body: bytes) -> tuple[int | None, str]:
    """§5 over the served bytes: the band, or not_auditable below the mass
    guard, where §5.2 derives no band and so no hard hit."""
    sim = link_extraction.similarity(EXTRACT, link_extraction.extract_text(body))
    if sim is None:
        return None, "not_auditable"
    verdict = ("consistent" if sim >= 600_000 else
               "dynamic_variance" if sim >= 300_000 else "inconsistent")
    return sim, verdict


def credit_commit(key: bytes, body: bytes, auditor_id: str) -> str:
    return "hmac-sha256:" + hmac.new(key, body + auditor_id.encode(), hashlib.sha256).hexdigest()


def hard_hit(reproduces: bool, verdict: str, derived: int | None) -> bool:
    if derived is None:
        return False
    return reproduces and ((verdict == "consistent" and derived < 300_000)
                           or (verdict == "inconsistent" and derived >= 600_000))


def canary_attest(prev_id: str, observed_at: str) -> str:
    inner = {"wist_version": "1.0.0", "publisher": "example.com", "url": DELTA_URL, "change_type": "attest",
             "observed_at": observed_at, "prev": prev_id, "meta": {"lang": "en"}}
    return "sha256:" + sha256_hex(rfc8785.dumps(inner))


CANARY_D1 = delta_id
CANARY_D2 = canary_attest(CANARY_D1, "2026-08-03T12:00:00Z")
CANARY_D3 = canary_attest(CANARY_D2, "2026-08-04T12:00:00Z")
CANARY_D4 = canary_attest(CANARY_D3, "2026-08-05T12:00:00Z")


def canary_thin_page(nonce: bytes) -> bytes:
    """A leaf whose observed text falls below the mass guard: §5 derives no
    band over it, so §5.2 derives no hard hit on it."""
    return ("<!doctype html><html><body><!-- wist-canary: %s --><p>Too few words to measure.</p></body></html>"
            % nonce.hex()).encode()


CANARY_LEAF_SPECS = [
    ("watermark", canary_page(EXTRACT, canary_nonce(0)), CANARY_D1, 124, 900_000, False),
    ("fraud", canary_page("Nothing served here resembles the committed text at all.",
                          canary_nonce(1)), CANARY_D2, 200, 300_000, False),
    ("dynamic", canary_page("WIST is an open, verifiable, push-based web",
                            canary_nonce(2)), CANARY_D3, 300, 100_000, True),
    ("unrevealed", canary_page("unrevealed", canary_nonce(3)), None, None, None, None),
    ("thin", canary_thin_page(canary_nonce(4)), CANARY_D4, 400, 400_000, False),
]
canary_leaf_hashes = [leaf_hash(body) for _, body, *_ in CANARY_LEAF_SPECS]
canary_root = "sha256:" + merkle_tree_root(canary_leaf_hashes).hex()
canary_leaves = []
for index, (cls, body, did, height, rep_u, provisional) in enumerate(CANARY_LEAF_SPECS):
    entry = {"index": index, "class": cls, "nonce_hex": canary_nonce(index).hex(),
             "served_bytes_hex": body.hex(),
             "leaf_hash": "sha256:" + canary_leaf_hashes[index].hex(),
             "revealed": did is not None}
    if did is not None:
        sim, verdict = canary_derived(body)
        tier = ("provisional" if provisional else
                "mature" if rep_u >= 500_000 else "standing")
        entry.update({"delta_id": did, "delta_height": height,
                      "path": ["sha256:" + h.hex() for h in audit_path(index, canary_leaf_hashes)],
                      "derived_similarity": sim, "derived_verdict": verdict,
                      "domain_reputation_u": rep_u, "domain_provisional": provisional,
                      "tier": tier})
    canary_leaves.append(entry)
assert [l.get("derived_verdict") for l in canary_leaves] == \
    ["consistent", "inconsistent", "dynamic_variance", None, "not_auditable"], "canary leaf verdicts drifted"
assert canary_leaves[2]["derived_similarity"] == 333_333, "the dynamic leaf must sit in the buffer band"
assert canary_leaves[4]["derived_similarity"] is None, "the thin leaf must fall below the mass guard"

PAYLOAD_PAGE = canary_page(EXTRACT, None)
OTHER_SALT = bytes(b ^ 0x01 for b in salt)


def canary_credit_case(label, auditor_id, index, held, verdict, key=None, copied_from=None):
    leaf_body = CANARY_LEAF_SPECS[index][1]
    derived = canary_leaves[index]["derived_similarity"]
    key = salt if key is None else key
    if held is None:
        # §5: an unreachable or not_auditable Record carries no commitment,
        # so it can credit nothing and hit nothing — an encounter without credit.
        return {"label": label, "auditor_id": auditor_id, "leaf_index": index, "held": None,
                "salt": "reference", "copied_from": None, "verdict": verdict,
                "response_commitment": None, "credit_commitment": None,
                "reproduces": False, "hard_hit": False}
    body = {"leaf": leaf_body, "payload_page": PAYLOAD_PAGE,
            "other_nonce": canary_page(EXTRACT, canary_nonce(99))}[held]
    signer = copied_from or auditor_id
    sealed = credit_commit(key, body, signer)
    reproduces = sealed == credit_commit(salt, leaf_body, auditor_id)
    return {"label": label, "auditor_id": auditor_id, "leaf_index": index, "held": held,
            "salt": "reference" if key == salt else "other",
            "copied_from": copied_from, "verdict": verdict,
            "response_commitment": "hmac-sha256:" + hmac.new(key, body, hashlib.sha256).hexdigest(),
            "credit_commitment": sealed, "reproduces": reproduces,
            "hard_hit": hard_hit(reproduces, verdict, derived)}


canary_credit_cases = [
    canary_credit_case("fetcher-credits-the-watermark", CANARY_AUD_A, 0, "leaf", "consistent"),
    canary_credit_case("payload-bytes-earn-no-credit", CANARY_AUD_B, 0, "payload_page", "consistent"),
    canary_credit_case("a-copied-credit-value-is-worthless", CANARY_AUD_C, 0, "leaf", "consistent",
                       copied_from=CANARY_AUD_A),
    canary_credit_case("consistent-on-the-fraud-leaf-is-a-hard-hit", CANARY_AUD_A, 1, "leaf", "consistent"),
    canary_credit_case("inconsistent-on-the-fraud-leaf-credits", CANARY_AUD_B, 1, "leaf", "inconsistent"),
    canary_credit_case("inconsistent-on-the-watermark-is-a-hard-hit", CANARY_AUD_C, 0, "leaf", "inconsistent"),
    canary_credit_case("consistent-in-the-buffer-band-is-no-hit", CANARY_AUD_A, 2, "leaf", "consistent"),
    canary_credit_case("inconsistent-in-the-buffer-band-is-no-hit", CANARY_AUD_B, 2, "leaf", "inconsistent"),
    canary_credit_case("a-cloaked-fetch-misses", CANARY_AUD_C, 2, "other_nonce", "consistent"),
    canary_credit_case("the-wrong-salt-reproduces-nothing", CANARY_AUD_B, 0, "leaf", "consistent",
                       key=OTHER_SALT),
    canary_credit_case("a-measured-verdict-on-a-thin-leaf-credits-and-is-no-hit", CANARY_AUD_A, 4, "leaf",
                       "consistent"),
    canary_credit_case("the-honest-record-on-a-thin-leaf-is-not-auditable-without-credit", CANARY_AUD_B, 4,
                       None, "not_auditable"),
]
assert [c["reproduces"] for c in canary_credit_cases] == \
    [True, False, False, True, True, True, True, True, False, False, True, False], "credit cases drifted"
assert [c["hard_hit"] for c in canary_credit_cases] == \
    [False, False, False, True, False, True, False, False, False, False, False, False], "hard-hit cases drifted"
assert canary_credit_cases[2]["credit_commitment"] == canary_credit_cases[0]["credit_commitment"], \
    "the copier must seal the very value it copied"

CANARY_PARAMS = {"canary_lead_blocks": 24, "canary_reveal_min_blocks": 168,
                 "canary_lifetime_blocks": 1440, "epoch_blocks": 24,
                 "observer_checkpoint_budget": 1024, "canary_leaves_max": 1024,
                 "canary_commitments_max": 8, "similarity_consistent": 600_000,
                 "similarity_variance_floor": 300_000, "min_observed_words": 40,
                 "latency_threshold_u": 500_000, "payload_window_days": 180}


def scoring_window_open(reveal_sealed_at_s, n_sealed_at_s, days):
    """§5.1: open at N while the whole days from the reveal's Block to N
    are fewer than payload_window_days — end-inclusive, start-exclusive,
    as every window in the document is measured."""
    return n_sealed_at_s >= reveal_sealed_at_s and (n_sealed_at_s - reveal_sealed_at_s) // DAY_S < days


CANARY_REVEAL_BLOCK = 500
canary_scoring_window_cases = [
    {"label": label, "reveal_height": CANARY_REVEAL_BLOCK,
     "reveal_sealed_at_s": CANARY_REVEAL_BLOCK * HOUR_S,
     "n_height": n, "n_sealed_at_s": n * HOUR_S,
     "payload_window_days": CANARY_PARAMS["payload_window_days"],
     "whole_days": ((n - CANARY_REVEAL_BLOCK) * HOUR_S) // DAY_S,
     "open": scoring_window_open(CANARY_REVEAL_BLOCK * HOUR_S, n * HOUR_S,
                                 CANARY_PARAMS["payload_window_days"])}
    for label, n in [
        ("open-at-the-reveals-own-block", CANARY_REVEAL_BLOCK),
        ("open-inside-the-window", CANARY_REVEAL_BLOCK + 2000),
        ("open-at-the-last-block-inside-the-window", CANARY_REVEAL_BLOCK + 180 * 24 - 1),
        ("lapsed-at-the-first-block-a-whole-window-later", CANARY_REVEAL_BLOCK + 180 * 24),
        ("lapsed-after-the-window", CANARY_REVEAL_BLOCK + 180 * 24 + 1),
    ]
]
assert [c["open"] for c in canary_scoring_window_cases] == [True, True, True, False, False], \
    "scoring window cases drifted"


def canary_timing(commitment_height, delta_heights, reveal_height, suffixes, p=CANARY_PARAMS):
    rotation = (max(-(-suffixes // p["observer_checkpoint_budget"]), 1) - 1) * p["epoch_blocks"]
    earliest = max(delta_heights) + p["canary_reveal_min_blocks"] + rotation
    latest = commitment_height + p["canary_lifetime_blocks"]
    lead_ok = all(h >= commitment_height + p["canary_lead_blocks"] for h in delta_heights)
    return {"earliest_reveal_height": earliest, "latest_reveal_height": latest,
            "lead_respected": lead_ok,
            "valid": lead_ok and earliest <= reveal_height <= latest}


canary_timing_scenarios = [
    ("reveal-at-the-minimum", 100, [124, 200], 368, 1),
    ("reveal-one-block-early", 100, [124, 200], 367, 1),
    ("reveal-at-the-lifetime", 100, [124, 200], 1540, 1),
    ("reveal-one-block-late", 100, [124, 200], 1541, 1),
    ("a-delta-inside-the-lead", 100, [123, 200], 400, 1),
    ("an-over-budget-roster-delays-the-minimum", 100, [124, 200], 400, 2049),
    ("the-delayed-minimum-met", 100, [124, 200], 416, 2049),
    ("no-observer-registered-reveal-at-the-minimum", 100, [124, 200], 368, 0),
    ("no-observer-registered-reveal-one-block-early", 100, [124, 200], 367, 0),
]
canary_timing_cases = [
    {"label": label, "commitment_height": c, "delta_heights": ds, "reveal_height": r,
     "suffixes_registered": sfx, **canary_timing(c, ds, r, sfx)}
    for label, c, ds, r, sfx in canary_timing_scenarios
]
assert [c["valid"] for c in canary_timing_cases] == \
    [True, False, True, False, False, False, True, True, False], "canary timing cases drifted"
assert canary_timing_cases[7]["earliest_reveal_height"] == canary_timing_cases[0]["earliest_reveal_height"], \
    "an empty Observer roster must add no rotation and subtract none"

# The scoreboard: per identity, per tier of the audited domain, encountered /
# credited / hard hits over the Records fixed before the reveal.
canary_scoreboard_records = [
    {"auditor_id": CANARY_AUD_A, "leaf_index": 0, "verdict": "consistent", "held": "leaf", "fixed_before_reveal": True},
    {"auditor_id": CANARY_AUD_A, "leaf_index": 1, "verdict": "consistent", "held": "leaf", "fixed_before_reveal": True},
    {"auditor_id": CANARY_AUD_A, "leaf_index": 2, "verdict": "inconsistent", "held": "leaf", "fixed_before_reveal": True},
    {"auditor_id": CANARY_AUD_B, "leaf_index": 0, "verdict": "consistent", "held": "payload_page", "fixed_before_reveal": True},
    {"auditor_id": CANARY_AUD_B, "leaf_index": 1, "verdict": "inconsistent", "held": "leaf", "fixed_before_reveal": False},
    {"auditor_id": CANARY_AUD_A, "leaf_index": 4, "verdict": "consistent", "held": "leaf", "fixed_before_reveal": True},
    {"auditor_id": CANARY_AUD_B, "leaf_index": 4, "verdict": "not_auditable", "held": None, "fixed_before_reveal": True},
]
for r in canary_scoreboard_records:
    body = {"leaf": CANARY_LEAF_SPECS[r["leaf_index"]][1], "payload_page": PAYLOAD_PAGE,
            None: None}[r["held"]]
    r["credit_commitment"] = None if body is None else credit_commit(salt, body, r["auditor_id"])


def scoreboard(records, auditor_id):
    board = {t: [0, 0, 0] for t in ("provisional", "standing", "mature")}
    for r in records:
        if r["auditor_id"] != auditor_id or not r["fixed_before_reveal"]:
            continue
        leaf = canary_leaves[r["leaf_index"]]
        row = board[leaf["tier"]]
        row[0] += 1
        reproduces = r["credit_commitment"] is not None and r["credit_commitment"] == credit_commit(
            salt, CANARY_LEAF_SPECS[r["leaf_index"]][1], auditor_id)
        row[1] += reproduces
        row[2] += hard_hit(reproduces, r["verdict"], leaf["derived_similarity"])
    return board


canary_scoreboards = {a: scoreboard(canary_scoreboard_records, a) for a in (CANARY_AUD_A, CANARY_AUD_B)}
assert canary_scoreboards[CANARY_AUD_A] == {"provisional": [1, 1, 0], "standing": [2, 2, 1], "mature": [1, 1, 0]}
assert canary_scoreboards[CANARY_AUD_B] == {"provisional": [0, 0, 0], "standing": [1, 0, 0], "mature": [1, 0, 0]}

canary_commitment_envelope = sign_envelope("update", {
    "wist_version": "1.0.0", "action": "canary_commitment", "subject": CANARY_PLANTER,
    "effective_at": "2026-08-02T12:00:00Z",
    "details": {"root": canary_root, "leaves": len(canary_leaves)},
}, "test-canary-k1")
canary_commitment_id = "sha256:" + sha256_hex(rfc8785.dumps(canary_commitment_envelope["update"]))
canary_membership_cases = []
for label, mutation, expected in (
    ("all revealed leaves", None, True),
    ("wrong starting hash", "hash", False),
    ("missing starting hash", "missing", False),
    ("malformed starting hash", "malformed", False),
    ("short path", "short", False),
    ("surplus path", "surplus", False),
    ("wrong sibling", "sibling", False),
    ("out of range index", "index", False),
):
    leaves = [{k: l[k] for k in ("index", "delta_id", "leaf_hash", "path")}
              for l in canary_leaves if l["revealed"]]
    leaves = json.loads(json.dumps(leaves))
    first = leaves[0]
    if mutation == "hash":
        first["leaf_hash"] = canary_leaves[1]["leaf_hash"]
    elif mutation == "missing":
        del first["leaf_hash"]
    elif mutation == "malformed":
        first["leaf_hash"] = "sha256:00"
    elif mutation == "short":
        first["path"].pop()
    elif mutation == "surplus":
        first["path"].append(canary_root)
    elif mutation == "sibling":
        first["path"][0] = canary_root
    elif mutation == "index":
        first["index"] = len(canary_leaves)
    envelope = sign_envelope("update", {
        "wist_version": "1.0.0", "action": "canary_reveal", "subject": CANARY_DOMAIN,
        "effective_at": "2026-08-26T04:00:00Z",
        "details": {"commitment": canary_commitment_id, "leaves": leaves},
    }, "test-canary-k1")
    canary_membership_cases.append({"label": label, "envelope": envelope,
                                    "membership_valid": expected,
                                    "error": None if expected else "WIST4-E08"})

binding_commitments = [canary_commitment_envelope]
other_commitment = json.loads(json.dumps(canary_commitment_envelope["update"]))
other_commitment["effective_at"] = "2026-08-02T13:00:00Z"
binding_commitments.append(sign_envelope("update", other_commitment, "test-canary-k1"))
binding_ids = ["sha256:" + sha256_hex(rfc8785.dumps(e["update"])) for e in binding_commitments]


def binding_reveal(commitment_index, leaf_index, bad=False, variant=0):
    leaf = canary_leaves[leaf_index]
    inner = {"wist_version": "1.0.0", "action": "canary_reveal", "subject": CANARY_DOMAIN,
        "effective_at": "2026-08-26T04:00:" + f"{variant:02d}" + "Z",
        "details": {"commitment": binding_ids[commitment_index], "leaves": [
            {k: leaf[k] for k in ("index", "delta_id", "leaf_hash", "path")}]}}
    if bad:
        inner["details"]["leaves"][0]["path"] = []
    return sign_envelope("update", inner, "test-canary-k1")

binding_cases = []
for label, rows, expected in (
    ("later commitment reuses Delta", [(400,0,0,False,0), (401,1,0,False,0)], [0]),
    ("simultaneous Delta collision", [(400,0,0,False,0), (400,1,0,False,0)], []),
    ("disjoint commitments", [(400,0,0,False,0), (400,1,1,False,0)], [0,1]),
    ("same commitment simultaneous partial reveals", [(400,0,0,False,0), (400,0,1,False,1)], []),
    ("identical replay counts once", [(400,0,0,False,0), (400,0,0,False,0), (401,0,0,False,0)], [0]),
    ("invalid membership blocks nobody", [(400,0,0,True,0), (400,1,0,False,0)], [1]),
    ("rejected collision reserves nothing", [(400,0,0,False,0), (400,1,0,False,0), (401,0,0,False,1)], [2]),
):
    events = [{"height": h, "envelope": binding_reveal(c,l,b,v), "other_requirements_valid": not b}
        for h,c,l,b,v in rows]
    seen, used_commits, used_deltas, accepted = set(), set(), set(), []
    for height in sorted({e["height"] for e in events}):
        candidates = []
        for i,e in enumerate(events):
            if e["height"] != height:
                continue
            inner = e["envelope"]["update"]
            ident = sha256_hex(rfc8785.dumps(inner))
            if ident in seen:
                continue
            seen.add(ident)
            details = inner["details"]
            ds = {leaf["delta_id"] for leaf in details["leaves"]}
            if e["other_requirements_valid"] and details["commitment"] not in used_commits and not ds & used_deltas:
                candidates.append((i,details["commitment"],ds))
        survivors = [a for a in candidates if not any(a[0] != b[0] and (a[1] == b[1] or a[2] & b[2]) for b in candidates)]
        for i,c,ds in survivors:
            accepted.append(i); used_commits.add(c); used_deltas.update(ds)
    assert accepted == expected, label
    binding_cases.append({"label": label, "events": events, "accepted_indices": accepted})

scoring_profile_defaults = {"shingle_size": 8, "min_observed_words": 40,
    "similarity_consistent": 600000, "similarity_variance_floor": 300000}
scoring_profile_cases = []
profile_words = ["word" + str(i) for i in range(47)]
for parameter, value, matched, verdict, old_sim, new_sim, old_hit, new_hit in (
    ("similarity_consistent", 500000, 29, "inconsistent", 550000, 550000, False, True),
    ("similarity_variance_floor", 150001, 15, "consistent", 200000, 200000, True, False),
    ("shingle_size", 1, 29, "inconsistent", 550000, 617021, False, True),
    ("min_observed_words", 60, 47, "inconsistent", 1000000, None, True, False),
):
    reference = " ".join(profile_words)
    observed = " ".join(profile_words[:matched] + ["extra" + str(i) for i in range(50-matched)])
    body = ('<html><body data-nonce="' + canary_nonce(121).hex() + '"><p>' + observed + '</p></body></html>').encode()
    for after in (False, True):
        profile = dict(scoring_profile_defaults)
        if after:
            profile[parameter] = value
        sim = link_extraction.similarity(reference, link_extraction.extract_text(body),
            profile["min_observed_words"], profile["shingle_size"])
        expected_sim, expected_hit = (new_sim, new_hit) if after else (old_sim, old_hit)
        assert sim == expected_sim
        scoring_profile_cases.append({"label": parameter + (" at amendment" if after else " before amendment"),
            "audited_delta_sealed_at_s": 7*DAY_S if after else 6*DAY_S,
            "record_fixed_at_s": 7*DAY_S if after else 6*DAY_S+3600,
            "reveal_sealed_at_s": 15*DAY_S, "queries_s": [15*DAY_S, 16*DAY_S],
            "change": {"parameter": parameter, "value": value, "effective_at_s": 7*DAY_S},
            "reference_extract": reference, "served_bytes_hex": body.hex(),
            "verdict": verdict, "credit_reproduces": True,
            "expected": {"profile": profile, "derived_similarity": expected_sim, "hard_hit": expected_hit}})

score_occurrences = [0, 0, 1, 2, 2, 3, 4, 5, 6]
write_json(WIST4 / "canary.json", spaced_labels({
    "note": ("WIST-4 §5.1, §5.2: a canary commitment over five leaves of served bytes "
             "(four revealed, one not), each carrying a nonce, one of them below the "
             "mass guard; the credit_commitment check per signer; the hard hit over "
             "both canary classes with the dynamic_variance buffer between, and no "
             "hit where §5 derives no band; reveal timing against the lead, the "
             "minimum with the checkpoint-budget rotation, and the lifetime; the "
             "scoring window's endpoints on the Block grid; and the "
             "per-tier scoreboard. Every revealed leaf's Reference Payload is "
             "examples/payload.json, whose salt keys every commitment here. Nonces are "
             "derived from a fixed string for reproducibility; a planter draws them "
             "from a CSPRNG."),
    "parameters": CANARY_PARAMS,
    "salt_source": "examples/payload.json",
    "reference_extract": EXTRACT,
    "planter": CANARY_PLANTER,
    "canary_domain": CANARY_DOMAIN,
    "commitment": {"root": canary_root, "leaves": len(CANARY_LEAF_SPECS), "height": 100},
    "membership": {"public_key": b64u(pub_raw),
                   "commitment_envelope": canary_commitment_envelope,
                   "cases": canary_membership_cases},
    "payload_page_hex": PAYLOAD_PAGE.hex(),
    "alternate_inputs": {"other_nonce_body_hex": canary_page(EXTRACT, canary_nonce(99)).hex(),
                         "other_salt_hex": OTHER_SALT.hex()},
    "leaves": canary_leaves,
    "credit_cases": canary_credit_cases,
    "binding": {"note": "All timing, domain and authorization prerequisites are satisfied; the events isolate membership and binding replay. An occurrence index denotes the same fixed Record in scoreboard_records, regardless of how many Entries or checkpoints carry it.",
        "commitment_envelopes": binding_commitments, "cases": binding_cases,
        "record_occurrences": score_occurrences, "scoreboards": canary_scoreboards},
    "timing_cases": canary_timing_cases,
    "scoring_window_cases": canary_scoring_window_cases,
    "scoring_profile": {"note": "Otherwise-valid Records and reveals with matching credit commitments and live scoring windows are premises. The accepted amendment was scheduled at least seven days before effectiveness. These cases isolate the extraction/band profile, recomputed from exact served bytes and reference extracts; amendment validation, signatures, membership and credit are exercised separately.",
        "defaults": scoring_profile_defaults, "cases": scoring_profile_cases},
    "scoreboard_records": canary_scoreboard_records,
    "scoreboards": canary_scoreboards,
}))
print("wist4 canary vector written; root", canary_root)

# ------------------------------ WIST-4 §3.1: epochs and the checkpoint budget
# Epochs are counted from Block 0, each spanning the epoch_blocks in force at
# its first Block; an epoch budgets suffixes by a hash over the epoch number,
# one Observer per suffix by the same hash.
OBS_EPOCH_DEFAULT = 24


def epoch_priority(epoch: int, name: str) -> str:
    return hashlib.sha256(epoch.to_bytes(8, "big") + name.encode()).hexdigest()


def two_label_suffix(host: str) -> str:
    return ".".join(host.split(".")[-2:])


def suffix_groups(observers):
    groups = {}
    for o in observers:
        groups.setdefault(two_label_suffix(o), []).append(o)
    return groups


def epoch_budget(observers, epoch, budget, sort_keys=None):
    """§3.1: suffixes in a fixed order by SHA-256(suffix); the epoch budgets
    the window of one budget starting at position epoch × budget mod S, and
    within each suffix the Observer least by the per-epoch hash."""
    groups = suffix_groups(observers)
    suffix_key = lambda sfx: (hashlib.sha256(sfx.encode()).hexdigest() if sort_keys is None else sort_keys["suffixes"][sfx], sfx.encode())
    observer_key = lambda o: (epoch_priority(epoch, o) if sort_keys is None else sort_keys["observers"][o], o.encode())
    order = sorted(groups, key=suffix_key)
    size = len(order)
    positions = [(epoch * budget + k) % size for k in range(min(budget, size))] if size else []
    chosen = [min(groups[order[p]], key=observer_key) for p in positions]
    return order, positions, chosen


def epoch_budget_rehashed(observers, epoch, budget):
    """The ruled-out reading: an order drawn afresh each epoch over
    SHA-256(be64(epoch) ‖ suffix), which bounds no suffix's wait."""
    groups = suffix_groups(observers)
    order = sorted(groups, key=lambda sfx: epoch_priority(epoch, sfx))
    return [min(groups[sfx], key=lambda o: epoch_priority(epoch, o)) for sfx in order[:budget]]


def budget_bound_epochs(suffixes: int, budget: int) -> int:
    return -(-suffixes // budget) if suffixes else 0


OBSERVERS = ["a.example.net", "b.example.net", "c.example.org", "d.sample.net", "e.other.io"]
TWO_SUFFIXES = ["a.example.net", "b.sample.net"]
observer_budget_cases = []
for label, observers, budget, epochs in [
    ("under-budget-every-suffix-budgeted", OBSERVERS, 5, [0, 1]),
    ("over-budget-rotates-across-epochs", OBSERVERS, 2, [0, 1, 2, 3]),
    ("a-crowd-under-one-suffix-shares-one-slot", OBSERVERS[:2] + ["f.example.net", "g.other.io"], 1,
     [0, 1, 2, 3]),
    ("two-suffixes-and-one-slot-alternate", TWO_SUFFIXES, 1, [5, 6, 7, 8]),
]:
    per_epoch = []
    for e in epochs:
        order, positions, chosen = epoch_budget(observers, e, budget)
        entry = {"epoch": e, "suffix_order": order, "positions": positions, "budgeted": chosen}
        if observers is TWO_SUFFIXES:
            entry["budgeted_under_per_epoch_rehash"] = epoch_budget_rehashed(observers, e, budget)
        per_epoch.append(entry)
    suffixes = len(suffix_groups(observers))
    bound = budget_bound_epochs(suffixes, budget)
    first = epochs[0]
    for start in range(first, first + bound):
        seen = set()
        for e in range(start, start + bound):
            seen.update(two_label_suffix(o) for o in epoch_budget(observers, e, budget)[2])
        assert len(seen) == suffixes, f"{label}: a suffix waits longer than the bound"
    observer_budget_cases.append({"label": label, "registered": observers, "budget": budget,
                                  "suffixes": suffixes, "bound_epochs": bound, "epochs": per_epoch})
rotating = observer_budget_cases[1]["epochs"]
assert len({tuple(e["budgeted"]) for e in rotating}) > 1, "the over-budget case must rotate"
assert all(len(e["budgeted"]) == 1 for e in observer_budget_cases[2]["epochs"]) and \
    len({e["budgeted"][0] for e in observer_budget_cases[2]["epochs"]}) > 1, \
    "the crowd case must share one slot and rotate inside it"
alternate = observer_budget_cases[3]["epochs"]
assert [two_label_suffix(e["budgeted"][0]) for e in alternate] == \
    ["example.net", "sample.net", "example.net", "sample.net"], "two suffixes under one slot must alternate"
assert [two_label_suffix(e["budgeted_under_per_epoch_rehash"][0]) for e in alternate[:3]] == \
    ["example.net"] * 3, "the ruled-out reading must show the repeated winner"


def epoch_of_block(block, changes, default=OBS_EPOCH_DEFAULT):
    """changes: [(effective_at_s, value)]; a Block's sealed_at is block * HOUR_S."""
    start, index = 0, 0
    while True:
        length = value_in_force(default, [{"effective_at_s": t, "value": v, "block_number": 0,
                                           "entry_index": 0} for t, v in changes],
                                start * HOUR_S)[0]
        if block < start + length:
            return index, start, length
        start += length
        index += 1


EPOCH_CHANGES = [(100 * HOUR_S, 48)]
observer_epoch_probes = [23, 24, 47, 96, 99, 100, 119, 120, 167, 168]
observer_epoch_cases = [
    {"block": b, "sealed_at_s": b * HOUR_S,
     **dict(zip(("epoch", "epoch_first_block", "epoch_length"),
                epoch_of_block(b, EPOCH_CHANGES)))}
    for b in observer_epoch_probes
]
assert [c["epoch"] for c in observer_epoch_cases] == [0, 1, 1, 4, 4, 4, 4, 5, 5, 6], "epoch cases drifted"

# A checkpoint covers its head and everything behind it through prev_record;
# a Record credits only under a checkpoint sealed below the reveal's Block.
OBS_CHAIN = ["sha256:c1", "sha256:c2", "sha256:c3", "sha256:c4", "sha256:c5"]
OBS_PREV = {item: (OBS_CHAIN[i - 1] if i else None) for i, item in enumerate(OBS_CHAIN)}
OBS_CHECKPOINTS = [{"head": "sha256:c3", "height": 50}, {"head": "sha256:c5", "height": 65}]


def covered_before(item, checkpoints, reveal_height):
    for cp in checkpoints:
        if cp["height"] >= reveal_height:
            continue
        cursor = cp["head"]
        while cursor is not None:
            if cursor == item:
                return True
            cursor = OBS_PREV[cursor]
    return False


observer_coverage_cases = [
    {"label": label, "reveal_height": reveal,
     "fixed_before_reveal": {item: covered_before(item, OBS_CHECKPOINTS, reveal) for item in OBS_CHAIN}}
    for label, reveal in [("reveal-between-the-checkpoints", 60),
                          ("reveal-after-both", 70),
                          ("reveal-at-the-first-checkpoints-height", 50)]
]
assert [list(c["fixed_before_reveal"].values()) for c in observer_coverage_cases] == \
    [[True, True, True, False, False], [True] * 5, [False] * 5], "coverage cases drifted"

OPPORTUNITY_OBSERVERS = ["watch." + suffix for suffix in ("a.example", "b.example", "c.example", "d.example", "e.example", "f.example", "g.example", "h.example")]
OPPORTUNITY_OBSERVERS.sort(key=lambda host: hashlib.sha256(two_label_suffix(host).encode()).digest())


def opportunity_epochs(initial, changes, initial_budget, initial_length=24):
    rows, start, number = [], 0, 0
    while start <= 620:
        roster, budget, length = list(initial), initial_budget, initial_length
        for c in changes:
            if c["height"] <= start:
                roster = c.get("registered", roster)
                budget = c.get("observer_checkpoint_budget", budget)
                length = c.get("epoch_blocks", length)
        budgeted = epoch_budget(roster, number, budget)[2] if roster else []
        rows.append({"number": number, "first": start, "last": start + length - 1,
            "registered": roster, "budget": budget, "seal_blocks": 24,
            "budgeted_suffixes": sorted(two_label_suffix(o) for o in budgeted)})
        start += length; number += 1
    return rows


opportunity_cases = []
for label, initial, budget, changes, expected in (
    ("roster growth delays original suffix", OPPORTUNITY_OBSERVERS[:1], 1,
        [{"height":24, "registered":OPPORTUNITY_OBSERVERS}], 263),
    ("budget reduction delays original suffixes", OPPORTUNITY_OBSERVERS, 8,
        [{"height":216, "amendment_sealed_height":48, "observer_checkpoint_budget":1}], 503),
    ("longer epochs delay checkpoint sealing", OPPORTUNITY_OBSERVERS[:1], 1,
        [{"height":216, "amendment_sealed_height":48, "epoch_blocks":48, "canary_reveal_min_blocks":216}], 383),
    ("faster cadence needs more Blocks before checkpoint", OPPORTUNITY_OBSERVERS[:1], 1,
        [{"height":216, "amendment_sealed_height":48, "block_cadence_seconds":1800, "canary_reveal_min_blocks":216}], 383),
    ("removed original suffix needs no checkpoint", OPPORTUNITY_OBSERVERS[:1], 1,
        [{"height":24, "registered":[]}], 168),
):
    newest = 192 if any("amendment_sealed_height" in c for c in changes) else 0
    deadline_s = (newest + 72) * 3600
    numeric_minimum = newest + 168
    block_times = [0]
    for h in range(1,720):
        cadence = 3600
        for c in changes:
            if c["height"] <= h-1:
                cadence = c.get("block_cadence_seconds", cadence)
        block_times.append((block_times[-1] // cadence + 1) * cadence)
    epochs = opportunity_epochs(initial, changes, budget)
    original = {two_label_suffix(o) for o in initial}
    current = set(original)
    for c in changes:
        if "registered" in c:
            current = {two_label_suffix(o) for o in c["registered"]}
    waits = []
    for suffix in original & current:
        waits.append(min(epochs[i+1]["last"] + e["seal_blocks"] for i,e in enumerate(epochs[:-1])
            if block_times[e["last"]] >= deadline_s and suffix in e["budgeted_suffixes"]))
    coverage_last = [h for h,t in enumerate(block_times) if t > deadline_s][23]
    earliest = max([numeric_minimum, coverage_last + 1] + waits)
    assert earliest == expected, (label, earliest)
    probes = sorted({newest+96,newest+97,numeric_minimum-1,numeric_minimum,earliest-1,earliest})
    opportunity_cases.append({"label": label, "newest_delta_height":newest, "coverage_deadline_s":deadline_s,
        "record_seal_blocks":24, "numeric_minimum":numeric_minimum, "initial_registered":initial,
        "initial_budget":budget, "changes":changes, "block_times_s":block_times,
        "epochs":epochs, "earliest_reveal_height":earliest,
        "probes":[{"height":h, "valid":h>=earliest} for h in probes]})

observer_ordering_cases = []
for tied in (True, False):
    registered = ["z.sample.net", "b.example.net", "a.example.net"]
    keys = {"suffixes": {"example.net": "00"*32 if tied else "ff"*32, "sample.net": "00"*32},
        "observers": {"a.example.net": "00"*32 if tied else "ff"*32,
            "b.example.net": "00"*32, "z.sample.net": "00"*32}}
    expected = ["a.example.net", "z.sample.net"] if tied else ["z.sample.net", "b.example.net"]
    epochs = []
    for epoch in (0, 1):
        order, positions, chosen = epoch_budget(registered, epoch, 1, keys)
        assert chosen == [expected[epoch]]
        epochs.append({"epoch": epoch, "suffix_order": order, "positions": positions, "budgeted": chosen})
    observer_ordering_cases.append({"label": "equal supplied digests" if tied else "digest precedes name",
        "registered": registered, "budget": 1,
        "sort_keys": {kind: [{"name": name, "sort_key_hex": key} for name,key in values.items()]
            for kind,values in keys.items()}, "epochs": epochs})

write_json(WIST4 / "observer-checkpoints.json", spaced_labels({
    "note": ("WIST-4 §3.1: which Observers an epoch budgets (suffixes in a fixed order by "
             "SHA-256 over the suffix, the epoch's window of one budget starting at "
             "position epoch × budget mod S, one Observer per suffix by SHA-256 over the "
             "big-endian epoch number and the observer_id; every suffix budgeted at least "
             "once in any bound_epochs consecutive epochs, and budgeted_under_per_epoch_rehash "
             "the ruled-out fresh draw that repeats a winner), which epoch a Block belongs "
             "to under a mid-Log change of epoch_blocks (each epoch spans the value in "
             "force at its first Block), and which chain items a sealed checkpoint fixes "
             "before a reveal."),
    "opportunity_cases": opportunity_cases,
    "epoch_blocks_default": OBS_EPOCH_DEFAULT,
    "budget_cases": observer_budget_cases,
    "ordering_boundary": {"note": "Counterfactual sort keys supplied at the ordering boundary for both evaluated epochs, not SHA-256 preimages or a claimed collision. Ordinary budget_cases verify the actual SHA-256 computations separately. These cases exercise secondary ordering and primary digest precedence through the same budget walk.",
        "cases": observer_ordering_cases},
    "epoch_changes": [{"effective_at_s": t, "value": v} for t, v in EPOCH_CHANGES],
    "epoch_cases": observer_epoch_cases,
    "chain": OBS_CHAIN,
    "prev_record": OBS_PREV,
    "checkpoints": OBS_CHECKPOINTS,
    "coverage_cases": observer_coverage_cases,
}))
print("wist4 observer-checkpoints vector written")

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

print("wist4 replay-derivation vectors: confirmation=%d derivation=%d coverage=%d+%d+%d+%d+%d extension=%d+%d+%d+%d sanctions=%d+%d+%d+%d+%d cases" % (
    len(confirmation_cases), len(derivation_scenarios),
    len(coverage_pair_cases), len(coverage_counting_cases), len(coverage_state_cases),
    len(coverage_establishing_cases), len(coverage_chain_scope_cases),
    len(extension_trigger_cases), len(extension_ration_cases),
    len(extension_summons_cases), len(contradiction_cases),
    len(sanction_criterion_cases), len(sanction_accrual_cases),
    len(sanction_void_cases), len(sanction_in_force_cases),
    len(sanction_ladder_cases)))


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
    ("audit-record", ["record", "fetched_at"]),
    ("registry-update", ["update", "effective_at"]),
):
    timestamp_fields.append({"schema": stem + ".schema.json", "document": json.loads((EXAMPLES / (stem + ".json")).read_text()), "path": path})
notice_timestamp = sign_envelope("update", {
    "wist_version": "1.0.0", "action": "notice", "subject": "example.com",
    "details": {"kind": "sanction", "level": 3, "activation": "sha256:" + "1" * 64,
                "reason": "Confirmed evidence", "appeal_deadline": "2017-01-15T00:00:00Z"},
    "evidence": ["sha256:" + "1" * 64], "effective_at": "2017-01-01T00:00:00Z",
}, "log1")
timestamp_fields.append({"schema": "registry-update.schema.json", "document": notice_timestamp,
                         "path": ["update", "details", "appeal_deadline"]})
timestamp_probe = "2017-01-01T00:00:00Z"
for entry, path in (
    (["parameter", "confirm_auditors", timestamp_probe, 2], [2]),
    (["sanction_state", "example.com", 3, ["sha256:" + "1" * 64], [["appeal", timestamp_probe]]], [4, 0, 1]),
    (["recovery_window", "example.com", 1, timestamp_probe], [3]),
    (["reputation_inputs", "example.com", timestamp_probe, None, 0, [], []], [2]),
    (["reputation_inputs", "example.com", timestamp_probe, None, 0, [], [[timestamp_probe, 1]]], [6, 0, 0]),
    (["escalation", "example.com", timestamp_probe], [2]),
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
        note="WIST-1 sections 3.1, 3.5 and 3.8, WIST-2 section 5, WIST-3 section 7 and WIST-4 section 6.1. "
             "Cases test signed author, key, scope and optional logical Feed association, with current initial "
             "Declarations supplied; accepted means those checks only. No live discovery or transport is exercised. "
             "The authenticated hourly history uses the default seven-day recovery window and supplies an "
             "independently pinned head; its Deltas exercise sealing bindings and chain ownership. Probes run "
             "after the named Block's Declaration stage and accepted Deltas, using that prefix's sources/tips; "
             "their later observed_at is a supplied test timestamp, not an inclusion claim. Clock, Payload, "
             "quotas, audit eligibility and actual notice acceptance remain separate. Conditional identity "
             "projections exercise owner/reset attribution, not cryptographic validation of audit evidence. "
             "Version cases assume a validator of this exact draft implementing only wire major 1.",
        cases=cases, log_key=dict(key_id="log-key", public_key=b64u(pub_raw)),
        recovery_window_days=7, blocks=blocks, pinned_head=previous, probes=probes,
        projection_cases=[
            dict(at_height=4, audited_height=0, publisher=parent, expected_current_identity=True),
            dict(at_height=170, audited_height=0, publisher=parent, expected_current_identity=True),
            dict(at_height=171, audited_height=0, publisher=parent, expected_current_identity=False),
            dict(at_height=171, audited_height=171, publisher=parent, expected_current_identity=True),
            dict(at_height=171, audited_height=0, publisher=child, expected_current_identity=True)],
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
                    update = dict(wist_version='1.0.0', action='parameter_change', subject='log.example.net',
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

    reference_probes = []
    for name, fetched in (('early extract_cap_bytes 1', 169), ('later extract_cap_bytes 1', 508)):
        obj = objects[name]
        caps = profile(obj['sealed_height'] * 3600)
        reference_probes.append(dict(reference=name, audited_id=decl_hash(attestation_body),
                                     fetched_at=at(fetched * 3600), expected_profile=caps,
                                     expected=result(obj, caps)))

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
    return dict(note='WIST-1 section 3.6 and WIST-4 section 9. One authenticated hourly history supplies a Declaration, cap amendments and unique content-bearing Deltas. Amendments have at least seven days of grace; lower link caps precede lower aggregate caps, and larger aggregate caps precede larger link caps. Probes independently check caps at each stage, not admission membership or permission to re-admit included IDs; admission probes resume their retained attempt across a boundary, sealing probes recheck objects under a supplied earlier valid cap profile, and historical probes retrieve the committing Delta profile from its actual inclusion. Repeating a probe with restart reconstructs inputs from the pinned prefix, not current defaults. Invalid candidate Blocks branch from height 168. Cap checks, signatures, inclusion and commitments are exercised; live queue mutation, crash durability, HTTP retrieval, complete governance acceptance and audit verdicts are not established.',
                log_key=dict(key_id='test-log-k1', public_key=b64u(pub_raw)), defaults=defaults,
                blocks=blocks, pinned_head=previous, objects=objects, probes=probes, reference_probes=reference_probes, invalid_blocks=invalid_blocks)


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
    return dict(description='WIST-1 section 3.4 and WIST-4 section 9. Signed candidates with supplied '
                'inclusion contexts; amendments share the initial Block in listed order. Only the '
                'clock_skew_seconds parameter varies. Context timestamps do not prove Block inclusion. '
                'Clock relation outcomes assume other Delta obligations have passed; each new attempt '
                'captures its own context. Historical checked_at and sealing admitted_at are distractors.',
                public_key=b64u(pub_raw), default=600, amendments=amendments, probes=probes)


write_json(WIST1 / 'delta-clock-time.json', delta_clock_time_vectors())

def record_field_vectors():
    import copy
    base = copy.deepcopy(audit_record)
    cases = []

    def add(name, body=None, allowed=(), discharge=True, mutate=None, **context):
        body = copy.deepcopy(base if body is None else body)
        doc = sign_envelope('record', body, 'test-aud-k1')
        if context.get('forged', False):
            doc['sig']['value'] = b64u(bytes(64))
        if mutate:
            mutate(doc)
        cases.append(dict(name=name, record_json=json.dumps(doc, ensure_ascii=True),
                          context=dict(duty=True, identity=True, removed=False,
                                       coverage_failure=False, semantic_evidence_error=False),
                          allowed=list(allowed), discharge=discharge))
        cases[-1]['context'].update({k: v for k, v in context.items() if k != 'forged'})

    def changed(field, value):
        body = copy.deepcopy(base)
        body[field] = value
        return body

    evidence = {'reference_delta', 'fetched_at', 'verdict', 'response_commitment',
                'credit_commitment', 'ref_extract_commitment', 'evidence_commitment',
                'similarity', 'link_agreement', 'robots_excluded', 'unmeasured'}
    add('valid measured')
    for field in base:
        body = copy.deepcopy(base)
        del body[field]
        if field == 'link_agreement':
            add('missing optional link score', body)
        else:
            code = 'WIST4-E02' if field in evidence else 'WIST4-E09'
            add('missing ' + field, body, [code], code == 'WIST4-E02')
    for field in base:
        if field == 'prev_record':
            continue
        for value in (None, [], True):
            code = 'WIST4-E02' if field in evidence else 'WIST4-E09'
            add('type ' + field + ' ' + repr(value), changed(field, value), [code], code == 'WIST4-E02')
    for field in ('response_commitment', 'credit_commitment', 'ref_extract_commitment',
                  'evidence_commitment', 'audited_delta', 'reference_delta', 'vrf_proof',
                  'auditor_id', 'fetched_at'):
        code = 'WIST4-E02' if field in evidence else 'WIST4-E09'
        for value in (base[field] + '\n', '', base[field].upper()):
            if value == base[field]:
                continue
            add('spelling ' + field + ' ' + repr(value), changed(field, value), [code], code == 'WIST4-E02')
    for field in ('response_commitment', 'credit_commitment', 'ref_extract_commitment', 'evidence_commitment'):
        add('bare digest ' + field, changed(field, 'sha256:' + 'a' * 64), ['WIST4-E02'])
    for value in (False, None, {}, 'sha256:' + 'a' * 64 + '\n'):
        if value is None:
            continue
        add('predecessor ' + repr(value), changed('prev_record', value), ['WIST4-E09'], False)
    add('predecessor ID', changed('prev_record', 'sha256:' + 'a' * 64))
    for version in ('1.1.0', '1.0.1', '1.' + '9' * 5000 + '.' + '8' * 80):
        add('supported version ' + version[:20], changed('wist_version', version))
    for version in ('0.0.0', '2.0.0', '9' * 5000 + '.0.0'):
        add('unsupported version ' + version[:20], changed('wist_version', version), ['WIST4-E10'], False)
    for version in ('', '01.0.0', '1.01.0', '1.0.00', '1.0', '1.0.0.0',
                    '1.0.0-alpha', '1.0.0+build', '1.0.0\n', '\u0661.0.0', '1.\u0660.0'):
        add('version spelling ' + repr(version), changed('wist_version', version), ['WIST4-E09'], False)
    for value in ('2026-02-29T00:00:00Z', '2026-08-02T14:00:60Z', '2026-08-02T14:00:00.0Z',
                  '2026-08-02T14:00:00+00:00', '2026-08-02t14:00:00z'):
        add('invalid fetch instant ' + value, changed('fetched_at', value), ['WIST4-E02'])
    for value in ('0000-02-29T00:00:00Z', '9999-12-31T23:59:59Z'):
        add('calendar endpoint ' + value, changed('fetched_at', value))
    for field in ('similarity', 'link_agreement'):
        for value in (-1, 1000001, 0.5, '940000'):
            add('invalid score ' + field + ' ' + repr(value), changed(field, value), ['WIST4-E02'])
        for value in (0, -0.0, 1000000.0):
            body = changed(field, value)
            if value == 0:
                body['verdict'] = 'inconsistent' if field == 'similarity' else 'link_inconsistent'
            add('integer value ' + field + ' ' + repr(value), body)
    for path in ((), ('record',), ('sig',)):
        def mutate(doc, path=path):
            target = doc
            for key in path:
                target = target[key]
            target['unknown'] = True
        add('unknown at ' + ('.'.join(path) or 'Envelope'), allowed=['WIST4-E09'], discharge=False, mutate=mutate)
    for key in ('record', 'sig'):
        add('missing container ' + key, allowed=['WIST4-E09'], discharge=False,
            mutate=lambda doc, key=key: doc.pop(key))
        for value in (None, [], 'object'):
            add('container ' + key + ' ' + repr(value), allowed=['WIST4-E09'], discharge=False,
                mutate=lambda doc, key=key, value=value: doc.update({key: value}))
    for field in ('key_id', 'alg', 'value'):
        add('missing signature ' + field, allowed=['WIST4-E09'], discharge=False,
            mutate=lambda doc, field=field: doc['sig'].pop(field))
    for field, value in (('key_id', 'x' * 65), ('key_id', None), ('alg', 'other'),
                         ('value', 'B' * 86), ('value', b64u(bytes(64)) + '\n')):
        add('signature field ' + field + ' ' + repr(value), allowed=['WIST4-E09'], discharge=False,
            mutate=lambda doc, field=field, value=value: doc['sig'].update({field: value}))
    add('signature scalar boundary', mutate=lambda doc: doc['sig'].update(key_id='\U0001f600' * 64))
    add('signature scalar excess', allowed=['WIST4-E09'], discharge=False,
        mutate=lambda doc: doc['sig'].update(key_id='\U0001f600' * 65))
    for verdict in ('unreachable', 'not_auditable'):
        body = copy.deepcopy(base)
        body['verdict'] = verdict
        for field in ('response_commitment', 'credit_commitment', 'ref_extract_commitment',
                      'evidence_commitment', 'similarity', 'link_agreement'):
            body.pop(field)
        if verdict == 'not_auditable':
            body['unmeasured'] = 'observed'
        else:
            body['robots_excluded'] = True
        add('valid ' + verdict, body)
        for field in ('response_commitment', 'credit_commitment', 'ref_extract_commitment',
                      'evidence_commitment', 'similarity', 'link_agreement'):
            invalid = copy.deepcopy(body)
            invalid[field] = base[field]
            add(verdict + ' forbidden ' + field, invalid, ['WIST4-E02'])
        if verdict == 'not_auditable':
            for value in ('reference',):
                add('unmeasured ' + value, dict(body, unmeasured=value))
            for value in (None, 'other'):
                add('unmeasured ' + repr(value), dict(body, unmeasured=value), ['WIST4-E02'])
            del body['unmeasured']
            add('missing unmeasured', body, ['WIST4-E02'])
    for field, value in (('robots_excluded', True), ('robots_excluded', False), ('unmeasured', 'observed')):
        add('measured forbidden ' + field + ' ' + repr(value), changed(field, value), ['WIST4-E02'])
    for verdict in ('link_variance', 'link_inconsistent'):
        body = changed('verdict', verdict)
        body.pop('link_agreement')
        add(verdict + ' missing score', body, ['WIST4-E02'])
    for label, context in (('forged', dict(forged=True)), ('missing duty', dict(duty=False)),
                           ('identity mismatch', dict(identity=False)), ('removed', dict(removed=True)),
                           ('coverage failure', dict(coverage_failure=True))):
        discharge = label in ('removed', 'coverage failure')
        add(label, allowed=['WIST4-E01'], discharge=discharge, **context)
        body = changed('credit_commitment', 'malformed')
        add('evidence plus ' + label, body, ['WIST4-E02'], discharge, **context)
    body = changed('wist_version', '2.0.0')
    body['credit_commitment'] = 'malformed'
    add('evidence before unsupported', body, ['WIST4-E02'], False)
    body['unknown'] = True
    add('structure before evidence and unsupported', body, ['WIST4-E09'], False, forged=True)
    add('unsupported and forged', changed('wist_version', '2.0.0'),
        ['WIST4-E01', 'WIST4-E10'], False, forged=True)
    add('semantic evidence', allowed=['WIST4-E02'], semantic_evidence_error=True)
    add('semantic evidence and missing duty', allowed=['WIST4-E01', 'WIST4-E02'],
        discharge=False, semantic_evidence_error=True, duty=False)
    for context, discharge, label in ((dict(removed=True, duty=False), False, 'removed without duty'),
                                       (dict(removed=True, forged=True), False, 'removed with forgery'),
                                       (dict(removed=True, coverage_failure=True), True, 'removed in coverage failure')):
        add(label, allowed=['WIST4-E01'], discharge=discharge, **context)
        add('evidence and ' + label, changed('credit_commitment', 'malformed'),
            ['WIST4-E02'], discharge, **context)
    add('unknown evidence name at Envelope', allowed=['WIST4-E09'], discharge=False,
        mutate=lambda doc: doc.update(verdict='consistent'))
    add('unknown evidence name at signature', allowed=['WIST4-E09'], discharge=False,
        mutate=lambda doc: doc['sig'].update(verdict='consistent'))
    for length in (63, 64):
        add('hostname label ' + str(length), changed('auditor_id', 'a' * length + '.example.net'),
            [] if length == 63 else ['WIST4-E09'], length == 63)
    for value in (None, [], 'object', 1):
        add('root type ' + repr(value), allowed=['WIST4-E09'], discharge=False)
        cases[-1]['record_json'] = json.dumps(value)
    add('finite integer outside score range', changed('similarity', 9007199254740992.0), ['WIST4-E02'])
    cases[-1]['record_json'] = cases[-1]['record_json'].replace('9007199254740992.0', '9007199254740992')
    add('unknown finite integer outside safe range', allowed=['WIST4-E09'], discharge=False,
        mutate=lambda doc: doc.update(unknown=9007199254740992))
    add('decimal rounds into score range', changed('similarity', 1000000.0))
    cases[-1]['record_json'] = cases[-1]['record_json'].replace('1000000.0', '1000000.00000000001')
    raw = cases[0]['record_json']
    wires = (
        ('duplicate Envelope', raw.replace('"record":', '"record": null, "record":', 1)),
        ('escaped duplicate verdict', raw.replace('"verdict":', '"\\u0076erdict": "inconsistent", "verdict":', 1)),
        ('duplicate signature algorithm', raw.replace('"alg":', '"alg": "other", "alg":', 1)),
        ('nested unknown duplicate', raw[:-1] + ', "unknown": {"x": 0, "\\u0078": 1}}'),
        ('trailing document', raw + '{}'),
        ('lone surrogate', raw.replace('audit.example.net', '\\ud800')),
        ('nonfinite', raw.replace('940000', 'NaN')),
    )
    for name, wire in wires:
        add(name, allowed=['WIST1-E05'], discharge=False)
        cases[-1]['record_json'] = wire
    add('escaped unique member')
    cases[-1]['record_json'] = raw.replace('"verdict":', '"\\u0076erdict":')
    add('integral exponent')
    cases[-1]['record_json'] = raw.replace('940000', '9.4e5')
    return dict(spec='WIST-4 section 10.1; WIST-1 section 4', public_key=b64u(pub_raw),
                scope='Standing, identity binding, removal, coverage failure and semantic evidence are supplied contexts; signatures and fields are verified. JSON strings preserve raw member spellings. Score bands, reference histories and commitment preimages are outside this field-only corpus.',
                cases=cases)


write_json(WIST4 / 'record-fields.json', record_field_vectors())
