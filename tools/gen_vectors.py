#!/usr/bin/env python3
"""Generate deterministic DC-1/DC-3 test vectors and signed examples.

Never uses wall-clock or randomness: fixed seed, fixed timestamps.
Re-running always produces byte-identical output.
"""
import base64, hashlib, json, pathlib

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from merkle import audit_path, leaf_hash, node_hash

ROOT = pathlib.Path(__file__).resolve().parents[1]
DC1 = ROOT / "vectors" / "dc1"
EXAMPLES = ROOT / "examples"
DC1.mkdir(parents=True, exist_ok=True)
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

# ---------------------------------------------------------------- DC-1: delta
EXTRACT = "DeltaCommons is an open, verifiable, push-based web index protocol."
delta = {
    "dc_version": "1.0.0",
    "url": "https://example.com/blog/post-1",
    "change_type": "new",
    "observed_at": "2026-08-02T12:00:00Z",
    "extract": EXTRACT,
    "extract_hash": "sha256:" + sha256_hex(EXTRACT.encode()),
    "summary": {"title": "Post 1", "abstract": "An introduction to DeltaCommons."},
    "meta": {"lang": "en", "topics": ["software"], "license": "CC-BY-4.0"},
}

delta_canonical = rfc8785.dumps(delta)
delta_id = "sha256:" + sha256_hex(delta_canonical)
delta_envelope = sign_envelope("delta", delta, "test-k1")

write_json(DC1 / "keypair.json",
           {"seed_hex": SEED.hex(), "public_key": b64u(pub_raw),
            "warning": "test vector key — NEVER use in production"})
(DC1 / "delta.canonical").write_bytes(delta_canonical)
write_json(DC1 / "envelope.json", delta_envelope)
(DC1 / "id.txt").write_text(delta_id + "\n")
write_json(EXAMPLES / "delta.json", delta_envelope)
print("dc1 delta id:", delta_id)

# ------------------------------------------------------------ DC-1: publisher
publisher = {
    "dc_version": "1.0.0",
    "domain": "example.com",
    "subdomain_scope": ["www.example.com", "blog.example.com"],
    "keys": [
        {"key_id": "test-k1", "alg": "Ed25519", "public_key": b64u(pub_raw),
         "valid_from": "2026-08-02T12:00:00Z"}
    ],
    "contact": "mailto:webmaster@example.com",
}
write_json(EXAMPLES / "publisher.json", sign_envelope("publisher", publisher, "test-k1"))
print("dc1 publisher example written")

# ----------------------------------------------------------------- DC-2: feed
feed = {
    "dc_version": "1.0.0",
    "domain": "example.com",
    "generated_at": "2026-08-02T12:00:00Z",
    "deltas": [delta_id],
    "next": None,
}
write_json(EXAMPLES / "feed.json", sign_envelope("feed", feed, "test-k1"))
print("dc2 feed example written")

# ------------------------------------------------------------ DC-3: log anchor
anchor = {
    "dc_version": "1.0.0",
    "log_id": "log.example.org",
    "genesis_key": {"key_id": "test-agg-k1", "alg": "Ed25519",
                    "public_key": b64u(pub_raw)},
    "created_at": "2026-08-02T00:00:00Z",
}
write_json(EXAMPLES / "log-anchor.json", sign_envelope("anchor", anchor, "test-agg-k1"))
print("dc3 log anchor example written")

# ---------------------------------------------------------------- DC-3: block
DC3 = ROOT / "vectors" / "dc3"
DC3.mkdir(parents=True, exist_ok=True)

def attest_delta(n: int, prev_id: str) -> dict:
    inner = {
        "dc_version": "1.0.0",
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
        "dc_version": "1.0.0",
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

leaves = [leaf_hash(rfc8785.dumps(e)) for e in entries]
n01 = node_hash(leaves[0], leaves[1])
n23 = node_hash(leaves[2], leaves[3])
merkle_root = "sha256:" + node_hash(n01, n23).hex()

header = {
    "dc_version": "1.0.0",
    "block_number": 0,
    "prev_block_hash": "sha256:genesis",
    "sealed_at": "2026-08-02T13:00:00Z",
    "merkle_root": merkle_root,
    "entry_count": 4,
}
block_inner = header                      # header only — DC-3 §3.1
block_canonical = rfc8785.dumps(block_inner)
block_hash = "sha256:" + sha256_hex(block_canonical)
block_sig = priv.sign(block_canonical)
block = {"header": header, "entries": entries,
         "sig": {"key_id": "test-agg-k1", "alg": "Ed25519", "value": b64u(block_sig)}}

inclusion_proof = {"index": 0, "entry_count": len(entries),
                   "path": [h.hex() for h in audit_path(0, leaves)]}

write_json(DC3 / "block.json", block)
write_json(DC3 / "inclusion-proof.json", inclusion_proof)
write_json(EXAMPLES / "block.json", block)

checkpoint = {
    "dc_version": "1.0.0",
    "block_number": 0,
    "block_hash": block_hash,
    "sealed_at": "2026-08-02T13:00:00Z",
}
write_json(EXAMPLES / "checkpoint.json", sign_envelope("checkpoint", checkpoint, "test-agg-k1"))

tier0_content = b"tier0-placeholder"
tier1_content = b"tier1-placeholder"
manifest = {
    "dc_version": "1.0.0",
    "snapshot_date": "2026-08-02",
    "log_position": 0,
    "embedding_model": {"name": "example-embed", "version": "1",
                        "dim": 384, "quantization": "int8"},
    "files": [
        {"path": "tier0/index.sqlite", "sha256": sha256_hex(tier0_content),
         "bytes": len(tier0_content), "tier": 0},
        {"path": "tier1/extracts.parquet", "sha256": sha256_hex(tier1_content),
         "bytes": len(tier1_content), "tier": 1},
    ],
}
write_json(EXAMPLES / "snapshot-manifest.json",
           sign_envelope("manifest", manifest, "test-agg-k1"))
print("dc3 block hash:", block_hash)
print("dc3 merkle root:", merkle_root)
print("dc3 leaves:", [l.hex() for l in leaves])
print("dc3 nodes: n01=%s n23=%s" % (n01.hex(), n23.hex()))

# ------------------------------------------------- DC-4: audit + registry
import hmac as hmac_mod

audit_record = {
    "dc_version": "1.0.0",
    "audited_delta": delta_id,
    "auditor_id": "audit.example.org",
    "fetched_at": "2026-08-02T14:00:00Z",
    "response_hash": "sha256:" + sha256_hex(b"response-placeholder"),
    "ref_extract_hash": "sha256:" + sha256_hex(EXTRACT.encode()),
    "similarity": 0.94,
    "verdict": "consistent",
    "evidence": "warc:sha256:" + sha256_hex(b"warc-placeholder"),
}
write_json(EXAMPLES / "audit-record.json",
           sign_envelope("record", audit_record, "test-aud-k1"))

registry_update = {
    "dc_version": "1.0.0",
    "action": "auditor_admit",
    "subject": "audit.example.org",
    "details": {"public_key": b64u(pub_raw), "key_id": "test-aud-k1"},
    "effective_at": "2026-08-02T12:00:00Z",
}
write_json(EXAMPLES / "registry-update.json",
           sign_envelope("update", registry_update, "test-agg-k1"))
print("dc4 audit-record and registry-update examples written")

# Worked sampling example (DC-4 §4): HMAC-SHA256(block hash raw, delta ID)
raw_block_hash = bytes.fromhex(block_hash.split(":")[1])
mac = hmac_mod.new(raw_block_hash, delta_id.encode(), hashlib.sha256).digest()
draw = int.from_bytes(mac[:8], "big") / 2**64
print("dc4 sampling hmac[:8] hex:", mac[:8].hex())
print("dc4 sampling draw: %.10f" % draw)
for rep, label in ((0.10, "quarantined"), (0.90, "reputable")):
    p = min(max(0.02 + 0.30 * (1 - rep), 0.02), 0.50)
    print("dc4 sampling rep=%.2f (%s): p=%.3f -> %s" % (
        rep, label, p, "AUDIT" if draw < p else "no audit"))
