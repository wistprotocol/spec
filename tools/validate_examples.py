#!/usr/bin/env python3
"""Validate examples/ against schemas/ and verify vectors/. Exit 0 = green."""
import base64, hashlib, json, pathlib, sys

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parents[1]
failures = []

def check(label, fn):
    try:
        fn()
        print(f"PASS {label}")
    except Exception as e:
        failures.append(label)
        print(f"FAIL {label}: {e}")

def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def leaf_hash(b): return hashlib.sha256(b"\x00" + b).digest()
def node_hash(l, r): return hashlib.sha256(b"\x01" + l + r).digest()

def verify_inclusion(block, proof):
    idx, n, path = proof["index"], proof["entry_count"], proof["path"]
    assert n == len(block["entries"]), "entry_count mismatch"
    assert 0 <= idx < n, "index out of range"
    h = leaf_hash(rfc8785.dumps(block["entries"][idx]))
    lo, hi, p = 0, n, 0
    while hi - lo > 1:
        k = 1
        while k * 2 < hi - lo:
            k *= 2
        assert p < len(path), "path too short"
        sib = bytes.fromhex(path[p]); p += 1
        if idx - lo < k:
            h = node_hash(h, sib); hi = lo + k
        else:
            h = node_hash(sib, h); lo = lo + k
    assert p == len(path), "unused path elements"
    assert "sha256:" + h.hex() == block["header"]["merkle_root"], "root mismatch"

# 1. Schema validation: examples/<stem>.json <-> schemas/<stem>.schema.json
for example in sorted((ROOT / "examples").glob("*.json")):
    schema_path = ROOT / "schemas" / f"{example.stem}.schema.json"
    def _v(example=example, schema_path=schema_path):
        if not schema_path.exists():
            raise FileNotFoundError(f"no schema for {example.name}")
        schema = json.loads(schema_path.read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(json.loads(example.read_text()))
    check(f"schema:{example.name}", _v)

INNER_KEY = {
    "delta.json": "delta", "publisher.json": "publisher", "feed.json": "feed",
    "block.json": None,  # block signs its header only — checked separately
    "checkpoint.json": "checkpoint", "snapshot-manifest.json": "manifest",
    "audit-record.json": "record", "registry-update.json": "update",
}

def load_test_pubkey():
    return b64u_decode(json.loads((ROOT / "vectors" / "dc1" / "keypair.json").read_text())["public_key"])

def verify_envelope(obj, inner_key, pub_raw):
    canonical = rfc8785.dumps(obj[inner_key])
    Ed25519PublicKey.from_public_bytes(pub_raw).verify(
        b64u_decode(obj["sig"]["value"]), canonical)

for example in sorted((ROOT / "examples").glob("*.json")):
    inner = INNER_KEY.get(example.name, "MISSING")
    if inner == "MISSING":
        failures.append(f"signatures:{example.name}")
        print(f"FAIL signatures:{example.name}: no inner-key mapping")
    elif inner is not None:
        check(f"signatures:{example.name}",
              lambda e=example, i=inner: verify_envelope(
                  json.loads(e.read_text()), i, load_test_pubkey()))

# 2. DC-1 vectors: recompute ID and verify signature
dc1 = ROOT / "vectors" / "dc1"
if (dc1 / "envelope.json").exists():
    def _dc1():
        env = json.loads((dc1 / "envelope.json").read_text())
        keys = json.loads((dc1 / "keypair.json").read_text())
        canonical = rfc8785.dumps(env["delta"])
        assert canonical == (dc1 / "delta.canonical").read_bytes(), "canonical bytes mismatch"
        delta_id = "sha256:" + hashlib.sha256(canonical).hexdigest()
        assert delta_id == (dc1 / "id.txt").read_text().strip(), "delta ID mismatch"
        pub = Ed25519PublicKey.from_public_bytes(b64u_decode(keys["public_key"]))
        pub.verify(b64u_decode(env["sig"]["value"]), canonical)
    check("vectors:dc1", _dc1)

# 3. DC-3 vectors: recompute merkle root and verify inclusion proof
dc3 = ROOT / "vectors" / "dc3"
if (dc3 / "block.json").exists():
    def _dc3():
        block = json.loads((dc3 / "block.json").read_text())
        leaves = [leaf_hash(rfc8785.dumps(e)) for e in block["entries"]]
        level = leaves[:]
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    nxt.append(node_hash(level[i], level[i + 1]))
                else:
                    nxt.append(level[i])
            level = nxt
        root = "sha256:" + level[0].hex()
        assert root == block["header"]["merkle_root"], "merkle root mismatch"
        proof = json.loads((dc3 / "inclusion-proof.json").read_text())
        verify_inclusion(block, proof)
    check("vectors:dc3", _dc3)

def _block_checks():
    block = json.loads((ROOT / "examples" / "block.json").read_text())
    cp = json.loads((ROOT / "examples" / "checkpoint.json").read_text())
    assert block["header"]["entry_count"] == len(block["entries"]), "entry_count mismatch"
    # Block Hash definition lives in DC-3 §3.1: header only.
    signed_bytes = rfc8785.dumps(block["header"])
    block_hash = "sha256:" + hashlib.sha256(signed_bytes).hexdigest()
    assert cp["checkpoint"]["block_hash"] == block_hash, "checkpoint does not bind block"
    assert cp["checkpoint"]["block_number"] == block["header"]["block_number"], "block_number mismatch"
    Ed25519PublicKey.from_public_bytes(load_test_pubkey()).verify(
        b64u_decode(block["sig"]["value"]), signed_bytes)
check("blockhash+binding+entrycount", _block_checks)

def _merkle_empty():
    expected = "sha256:" + hashlib.sha256(b"\x00").hexdigest()
    assert expected == "sha256:6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", \
        "empty-tree constant drifted"
check("merkle-empty", _merkle_empty)

def _negative_index():
    """A proof carrying a falsified index MUST NOT verify (DC-3 §4)."""
    import copy
    block = copy.deepcopy(json.loads((ROOT / "vectors" / "dc3" / "block.json").read_text()))
    proof = copy.deepcopy(json.loads((ROOT / "vectors" / "dc3" / "inclusion-proof.json").read_text()))
    # verify_inclusion(block, proof) fetches its leaf via block["entries"][proof["index"]],
    # so merely relabeling proof["index"] (leaving block untouched) makes it fetch a
    # genuinely different, distinct Entry — which fails on leaf-content grounds alone and
    # would mask the defect under test regardless of how "side" is handled. A mirror
    # colluding in this attack controls what it serves at each position, so simulate that:
    # keep entry 0's real (leaf, path) pair — the one this proof actually authenticates —
    # but relabel it as occupying position 3.
    block["entries"][3] = block["entries"][proof["index"]]
    proof["index"] = 3
    try:
        verify_inclusion(block, proof)
    except Exception:
        return  # correctly rejected
    raise AssertionError("falsified index verified — index is unauthenticated")
check("negative:falsified-index", _negative_index)

sys.exit(1 if failures else 0)
