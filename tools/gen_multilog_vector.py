#!/usr/bin/env python3
"""Generate the multi-log dedup vector (WIST-3 §8, "Following more than one
Log"): one Publisher Declaration and one Delta, sealed independently by two
Logs with distinct genesis keys, at different heights.

Never uses wall-clock or randomness: fixed seeds, fixed timestamps.
Re-running always produces byte-identical output.
"""
import base64, hashlib, hmac, json, pathlib

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from merkle import leaf_hash, node_hash

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "vectors" / "multilog"
OUT.mkdir(parents=True, exist_ok=True)


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


def merkle_root_of(wrapped_entries: list) -> str:
    """WIST-3 §4, over empty and non-empty entry lists alike."""
    if not wrapped_entries:
        return "sha256:" + leaf_hash(b"").hex()
    leaves = [leaf_hash(rfc8785.dumps(e)) for e in wrapped_entries]
    level = leaves
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return "sha256:" + level[0].hex()


def seal_block(priv: Ed25519PrivateKey, key_id: str, block_number: int, prev_block_hash: str,
               sealed_at: str, wrapped_entries: list) -> tuple:
    header = {
        "wist_version": "1.0.0",
        "block_number": block_number,
        "prev_block_hash": prev_block_hash,
        "sealed_at": sealed_at,
        "merkle_root": merkle_root_of(wrapped_entries),
        "entry_count": len(wrapped_entries),
    }
    header_canonical = rfc8785.dumps(header)
    block_hash = "sha256:" + sha256_hex(header_canonical)
    sig = priv.sign(header_canonical)
    block = {"header": header, "entries": wrapped_entries,
             "sig": {"key_id": key_id, "alg": "Ed25519", "value": b64u(sig)}}
    return block, block_hash


def write_json(path: pathlib.Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n")


# One Publisher, self-signed, shared verbatim by both Logs — WIST-3 §8's
# claim is that a Delta ID does not depend on which Log carries it, so the
# same signed Declaration and Delta envelopes are sealed twice, unmodified.
PUB_SEED = bytes([0x11] * 32)
pub_priv, pub_pub = keypair(PUB_SEED)

DOMAIN = "example.com"
DELTA_URL = "https://example.com/shared-post"

declaration = {
    "wist_version": "1.0.0",
    "domain": DOMAIN,
    "keys": [{"key_id": "pub-k1", "alg": "Ed25519", "public_key": b64u(pub_pub),
              "valid_from": "2026-08-02T00:00:00Z"}],
    "seq": 0,
}
declaration_envelope = sign_envelope(pub_priv, "publisher", declaration, "pub-k1")

CONTENT = {
    "extract": "Sealed once, read from two Logs.",
    "links": {"total": 0, "urls": []},
    "summary": {"title": "Shared Post"},
}
content_canonical = rfc8785.dumps(CONTENT)
salt = hashlib.sha256(b"wist-test-salt|multilog|" + DELTA_URL.encode()).digest()[:16]
commitment = "hmac-sha256:" + hmac.new(salt, content_canonical, hashlib.sha256).hexdigest()
payload = {"wist_version": "1.0.0", "salt": b64u(salt), "content": CONTENT}

delta = {
    "wist_version": "1.0.0",
    "url": DELTA_URL,
    "change_type": "new",
    "observed_at": "2026-08-02T12:00:00Z",
    "payload": {"commitment": commitment, "alg": "HMAC-SHA256", "bytes": len(content_canonical)},
    "meta": {"lang": "en"},
}
delta_canonical = rfc8785.dumps(delta)
delta_id = "sha256:" + sha256_hex(delta_canonical)
delta_envelope = sign_envelope(pub_priv, "delta", delta, "pub-k1")

wrapped_declaration = {"type": "publisher_declaration", "body": declaration_envelope}
wrapped_delta = {"type": "publisher_delta", "body": delta_envelope}


def build_log(log_id: str, seed: bytes, key_id: str, heartbeat_before_delta: bool) -> dict:
    """log-a seals Declaration (Block 0) then the Delta (Block 1). log-b
    inserts an empty heartbeat Block between the two, sealing the same
    Delta one Block later — different heights, same Delta ID, per WIST-3
    §8: identity does not depend on height or Log.
    """
    priv, pub = keypair(seed)
    anchor = {
        "wist_version": "1.0.0",
        "log_id": log_id,
        "genesis_key": {"key_id": key_id, "alg": "Ed25519", "public_key": b64u(pub)},
        "created_at": "2026-08-02T00:00:00Z",
    }
    anchor_envelope = sign_envelope(priv, "anchor", anchor, key_id)

    block0, hash0 = seal_block(priv, key_id, 0, "sha256:genesis",
                                "2026-08-02T13:00:00Z", [wrapped_declaration])
    blocks = [block0]
    prev_hash, next_number, next_hour = hash0, 1, 14

    if heartbeat_before_delta:
        heartbeat, hash_hb = seal_block(priv, key_id, next_number, prev_hash,
                                         f"2026-08-02T{next_hour:02d}:00:00Z", [])
        blocks.append(heartbeat)
        prev_hash, next_number, next_hour = hash_hb, next_number + 1, next_hour + 1

    delta_sealed_at = f"2026-08-02T{next_hour:02d}:00:00Z"
    delta_block, delta_hash = seal_block(priv, key_id, next_number, prev_hash,
                                          delta_sealed_at, [wrapped_delta])
    blocks.append(delta_block)

    checkpoint = {
        "wist_version": "1.0.0",
        "block_number": next_number,
        "block_hash": delta_hash,
        "sealed_at": delta_sealed_at,
    }
    checkpoint_envelope = sign_envelope(priv, "checkpoint", checkpoint, key_id)

    return {
        "log_id": log_id,
        "anchor": anchor_envelope,
        "genesis_seed_hex": seed.hex(),
        "blocks": blocks,
        "checkpoint": checkpoint_envelope,
    }


log_a = build_log("log-a", bytes([0xAA] * 32), "log-a-genesis", heartbeat_before_delta=False)
log_b = build_log("log-b", bytes([0xBB] * 32), "log-b-genesis", heartbeat_before_delta=True)

assert log_a["blocks"][-1]["header"]["block_number"] != log_b["blocks"][-1]["header"]["block_number"], \
    "the two Logs must seal the Delta at different heights"
assert json.loads(rfc8785.dumps(log_a["blocks"][-1]["entries"][0])) == \
       json.loads(rfc8785.dumps(log_b["blocks"][-1]["entries"][0])), \
    "the sealed Delta entry must be byte-identical across Logs"

vector = {
    "description": (
        "One Delta sealed independently by two Logs (WIST-3 §8, \"Following "
        "more than one Log\"): identity is stable, a Consumer holding both "
        "deduplicates by Delta ID, and derived state stays per Log. log-a "
        "seals the Publisher's Declaration in Block 0 and the Delta in "
        "Block 1; log-b seals the same Declaration in Block 0, an empty "
        "heartbeat Block 1, and the same Delta in Block 2 — different "
        "heights, same Delta ID."
    ),
    "note": (
        "Each Log entry's genesis_seed_hex is test-harness material, not "
        "protocol content: the Ed25519 seed behind that Log's genesis_key, "
        "included so a conformance harness can build that Log's own "
        "Snapshot artifacts (state/manifest/index) signed under the same "
        "key its Blocks are sealed with — the same role vectors/wist1/"
        "keypair.json's seed_hex plays for the Publisher's key. TEST ONLY — "
        "never use in production."
    ),
    "publisher_declaration": declaration_envelope,
    "delta": delta_envelope,
    "payload": payload,
    "delta_id": delta_id,
    "logs": [log_a, log_b],
    "expected": {
        "merged_records": [
            {"url": DELTA_URL, "publisher": DOMAIN, "delta_id": delta_id,
             "sources": ["log-a", "log-b"]}
        ]
    },
}

write_json(OUT / "dedup.json", vector)
print("multilog delta id:", delta_id)
print("log-a head:", log_a["blocks"][-1]["header"]["block_number"], log_a["checkpoint"]["checkpoint"]["block_hash"])
print("log-b head:", log_b["blocks"][-1]["header"]["block_number"], log_b["checkpoint"]["checkpoint"]["block_hash"])
