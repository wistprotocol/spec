#!/usr/bin/env python3
import base64, calendar, hashlib, hmac, json, pathlib, time

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import catalogs
import combined_view
import items
import sealing
import tree_files
from merkle import leaf_hash, merkle_root as merkle_tree_root

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "vectors" / "multilog"
OUT.mkdir(parents=True, exist_ok=True)

EMPTY_ROOT = hashlib.sha256(b"").digest()


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def keypair(seed: bytes):
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub


def sign_envelope(priv: Ed25519PrivateKey, inner_name: str, inner: dict, key_id: str) -> dict:
    canonical = rfc8785.dumps(inner)
    sig = priv.sign(canonical)
    return {inner_name: inner,
            "sig": {"key_id": key_id, "alg": "Ed25519", "value": b64u(sig)}}


def kid_of_x(x: str) -> str:
    """WIST-1 §5.1: the RFC 7638 thumbprint of an Ed25519 OKP JWK, computed over
    the entry's `x` string as written (mirrors gen_vectors.py)."""
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


def note_key_id(name: str, raw_pub: bytes) -> bytes:
    """[signed-note] note key ID (WIST-3 §3.4)."""
    return hashlib.sha256(name.encode() + b"\x0a\x01" + raw_pub).digest()[:4]


def checkpoint_note(log_id: str, priv: Ed25519PrivateKey, raw_pub: bytes, tree_size: int,
                    root: bytes, epoch_number: int, sealed_at: str) -> str:
    """WIST-3 §5: a signed Checkpoint note."""
    text = "%s\n%d\n%s\nepoch_number %d\nsealed_at %s\n" % (
        log_id, tree_size, base64.b64encode(root).decode(), epoch_number, sealed_at)
    kid = note_key_id(log_id, raw_pub)
    sig = priv.sign(text.encode())
    return text + "\n— %s %s\n" % (log_id, base64.b64encode(kid + sig).decode())


def root_token(leaves: list) -> str:
    root = merkle_tree_root(leaves) if leaves else EMPTY_ROOT
    return "sha256:" + root.hex()


def seal(log_id: str, priv: Ed25519PrivateKey, raw_pub: bytes, leaves: list,
        wrapped_entries: list, epoch_number: int, sealed_at: str) -> tuple:
    """WIST-3 §§3-5: extend the cumulative Log tree `leaves` with one
    Epoch's entries and seal it. Returns (epoch, new_leaves)."""
    new_leaves = leaves + [leaf_hash(rfc8785.dumps(e)) for e in wrapped_entries]
    root = merkle_tree_root(new_leaves) if new_leaves else EMPTY_ROOT
    note = checkpoint_note(log_id, priv, raw_pub, len(new_leaves), root, epoch_number, sealed_at)
    return {"checkpoint": note, "entries": wrapped_entries}, new_leaves


def write_json(path: pathlib.Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n")


PUB_SEED = bytes([0x11] * 32)
SECOND_SEED = bytes(range(32))
pub_priv, pub_pub = keypair(PUB_SEED)
second_priv, second_pub = keypair(SECOND_SEED)

DOMAIN = "example.com"
ITEM_URL = "https://example.com/shared-post"

PUB_KID = kid_of(pub_pub)
SECOND_KID = kid_of(second_pub)

declaration = {
    "wist_version": "1.0.0",
    "domain": DOMAIN,
    "keys": [jwk(pub_pub, "2026-08-02T00:00:00Z"), jwk(second_pub, "2026-08-02T00:00:00Z")],
    "seq": 0,
}
declaration_envelope = sign_envelope(pub_priv, "publisher", declaration, PUB_KID)

CONTENT = {
    "extract": "Sealed once, read from two Logs.",
    "links": {"total": 0, "urls": []},
    "summary": {"title": "Shared Post"},
}
salt = hashlib.sha256(b"wist-test-salt|multilog|" + ITEM_URL.encode()).digest()[:16]
item, payload = items.new_page_item(
    DOMAIN, {"url": ITEM_URL, "lang": "en", "modified": "2026-08-02T12:00:00Z", "content": CONTENT}, b64u(salt))
item_id = items.item_id(item)
tree, _ = tree_files.write_tree([item])
catalog = {"wist_version": "1.0.0", "publisher": DOMAIN, "collection": "default",
           "generated_at": "2026-08-02T12:30:00Z", "size": 1, "root": items.root_string([item]), "tree": tree}
catalog_id = catalogs.catalog_id(catalog)
catalog_envelopes = {"log-a": sign_envelope(pub_priv, "catalog", catalog, PUB_KID),
                     "log-b": sign_envelope(second_priv, "catalog", catalog, SECOND_KID)}
assert catalog_envelopes["log-a"]["sig"] != catalog_envelopes["log-b"]["sig"]

wrapped_declaration = {"type": "publisher_declaration", "body": declaration_envelope}
wrapped_item = {"type": "publisher_item", "body": items.publisher_item_body(item, catalog, [item])}
PARAMETERS = {
    "clock_skew_seconds": 600, "catalog_items_max": 16777216, "catalog_refresh_seconds": 604800,
    "payload_window_days": 180, "domain_epoch_entries_max": 10000, "url_cap_bytes": 2048,
    "extract_cap_bytes": 32768, "links_cap_bytes": 4096, "link_url_cap_bytes": 2048, "summary_cap_bytes": 2048,
    "collections_max": 16, "scope_entries_max": 32, "recovery_window_days": 7, "declaration_activation_epochs": 24}


def build_log(log_id: str, seed: bytes, key_id: str, heartbeat_before_publications: bool) -> dict:
    priv, pub = keypair(seed)
    anchor = {
        "wist_version": "1.0.0",
        "log_id": log_id,
        "genesis_key": {"key_id": key_id, "alg": "Ed25519", "public_key": b64u(pub)},
        "created_at": "2026-08-02T00:00:00Z",
    }
    anchor_envelope = sign_envelope(priv, "anchor", anchor, key_id)
    publications = sealing.canonical_order(
        [{"type": "publisher_catalog", "body": catalog_envelopes[log_id]}, wrapped_item])
    plan = [[wrapped_declaration]] + ([[]] if heartbeat_before_publications else []) + [publications]

    leaves, epochs, replayed = [], [], []
    for number, entries in enumerate(plan):
        sealed_at = f"2026-08-02T{13 + number:02d}:00:00Z"
        epoch, leaves = seal(log_id, priv, pub, leaves, entries, number, sealed_at)
        epochs.append(epoch)
        replayed.append({"height": number, "sealed_at": sealed_at, "parameters": PARAMETERS, "entries": entries})
    results, state = sealing.replay(replayed)
    assert all(r["status"] == "accepted" and all(d is None or d["disposition"] == "valid" for d in r["entries"])
               for r in results), log_id

    return {
        "log_id": log_id,
        "anchor": anchor_envelope,
        "genesis_seed_hex": seed.hex(),
        "epochs": epochs,
        "checkpoint": epochs[-1]["checkpoint"],
        "tree_size": len(leaves),
        "root": root_token(leaves),
    }, state.url_state(DOMAIN, ITEM_URL)


log_a, state_a = build_log("log-a", bytes([0xAA] * 32), "log-a-genesis", heartbeat_before_publications=False)
log_b, state_b = build_log("log-b", bytes([0xBB] * 32), "log-b-genesis", heartbeat_before_publications=True)
assert len(log_a["epochs"]) != len(log_b["epochs"])
combined = combined_view.combined_state({"log-a": state_a, "log-b": state_b})
assert combined["logs"] == ["log-a", "log-b"] and combined["state"]["item"] == item_id

vector = {
    "description": (
        "One Catalog and one Item sealed independently by two Logs (WIST-3 §7, Several Logs, and §8, "
        "Following more than one Log). log-a seals the Publisher's Declaration in Epoch 0 and, in Epoch 1, "
        "the Catalog and the publisher_item Entry of its one Item; log-b seals the same Declaration in Epoch 0, "
        "an empty Epoch 1, and the same Catalog and Item in Epoch 2. The Catalog's inner object, and with it "
        "its Catalog ID, is the same in both Logs, while its Envelope carries a signature under another key of "
        "the Declaration in each; the publisher_item Entry is byte-identical. A Consumer holding both Logs "
        "deduplicates Catalogs and Items by ID, and the record each Log holds for the Publisher and URL, "
        "proved against one Catalog and carrying one Item, combines into one state held by both Logs."
    ),
    "note": (
        "Each Log entry's genesis_seed_hex is test-harness material, not "
        "protocol content: the Ed25519 seed behind that Log's genesis_key, "
        "included so a conformance harness can build that Log's own "
        "Snapshot artifacts (state/manifest/index) signed under the same "
        "key its Epochs are sealed with — the same role vectors/wist1/"
        "keypair.json's seed_hex plays for the Publisher's key. TEST ONLY — "
        "never use in production."
    ),
    "publisher_declaration": declaration_envelope,
    "catalog_id": catalog_id,
    "item": item,
    "item_id": item_id,
    "payload": payload,
    "logs": [log_a, log_b],
    "expected": {
        "log_states": {"log-a": state_a, "log-b": state_b},
        "combined": combined,
    },
}

write_json(OUT / "dedup.json", vector)
