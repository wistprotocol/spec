#!/usr/bin/env python3
"""Validate examples/ against schemas/ and verify vectors/. Exit 0 = green."""
import base64, calendar, hashlib, hmac, json, pathlib, re, sys, time

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

import ecvrf
from merkle import audit_path, leaf_hash, merkle_root, node_hash

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

def verify_inclusion(block, proof):
    """RFC 6962 audit-path verification (DC-3 §4).

    Walks from the leaf to the root using the node's own index (`fn`) and
    the index of the last node at the current level (`sn`), rather than
    reading a claimed "side" out of the proof: `fn` odd means the node is a
    right child (its sibling, consumed from `path`, is on the left); `fn`
    even and `fn < sn` means it's a left child with a real right sibling
    (consumed on the right); `fn == sn` (even) means it is the lone,
    unpaired trailing node at this level and is promoted unchanged,
    consuming nothing. This is what makes a proof authenticate `index`
    itself, not just membership: an attacker cannot relabel `index` without
    changing which siblings the walk demands.
    """
    idx, n, path = proof["index"], proof["entry_count"], proof["path"]
    assert 0 <= idx < n, "index out of range"
    assert n == block["header"]["entry_count"], "entry_count mismatch"
    h = leaf_hash(rfc8785.dumps(block["entries"][idx]))
    fn, sn, p = idx, n - 1, 0
    while sn > 0:
        if fn % 2 == 1:                 # fn is a right child: sibling on the left
            assert p < len(path), "path too short"
            h = node_hash(bytes.fromhex(path[p]), h); p += 1
        elif fn < sn:                   # fn is a left child with a real sibling
            assert p < len(path), "path too short"
            h = node_hash(h, bytes.fromhex(path[p])); p += 1
        # else: fn == sn, fn even -> lone node, promoted unchanged, no proof consumed
        fn //= 2; sn //= 2
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
    "log-anchor.json": "anchor",
    "status.json": None,  # not a signed Envelope — plain JSON (DC-2 §7.1)
    "payload.json": None,  # unsigned: its integrity comes from the Delta's
                           # commitment, not from a signature (DC-3 §6.1)
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

# 2b. The payload commitment: the only thing binding a Delta to content that
# the Log does not carry. Everything downstream — the audit metric, snapshot
# materialization, the withdrawal guarantee — rests on this recomputation.
def _load_payload_and_delta():
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    delta = json.loads((ROOT / "examples" / "delta.json").read_text())["delta"]
    return payload, delta

def _commit(salt_b64: str, content: dict) -> str:
    return "hmac-sha256:" + hmac.new(
        b64u_decode(salt_b64), rfc8785.dumps(content), hashlib.sha256).hexdigest()

def _payload_commitment():
    payload, delta = _load_payload_and_delta()
    assert delta["payload"]["alg"] == "HMAC-SHA256", "commitment algorithm is not HMAC-SHA256"
    assert len(b64u_decode(payload["salt"])) >= 16, "salt is shorter than 128 bits (DC-1 §3.6)"
    assert _commit(payload["salt"], payload["content"]) == delta["payload"]["commitment"], \
        "the Payload does not reproduce the Delta's commitment"
check("payload:commitment", _payload_commitment)

def _payload_length():
    payload, delta = _load_payload_and_delta()
    n = len(rfc8785.dumps(payload["content"]))
    assert delta["payload"]["bytes"] == n, \
        f"the Delta declares {delta['payload']['bytes']} octets, JCS(content) is {n}"
    assert n <= 34816, "JCS(content) exceeds the 34816-octet cap (DC-1 §3.6)"
check("payload:length", _payload_length)

def _payload_tamper():
    """One mutated octet MUST break the commitment (DC-1 §3.6).

    Binding is the whole reason the extract can leave the signed object: a
    Publisher must not be able to serve one text and later claim it committed
    to another, and a Mirror must not be able to substitute a Payload. Each
    case below changes exactly one octet of what the commitment covers, or of
    the salt that keys it, and every one must fail to reproduce it.
    """
    import copy
    payload, delta = _load_payload_and_delta()
    committed = delta["payload"]["commitment"]
    assert _commit(payload["salt"], payload["content"]) == committed, \
        "the untampered Payload does not verify, so no mutation below proves anything"

    def flip_last(s: str) -> str:
        last = s[-1]
        return s[:-1] + ("A" if last != "A" else "B")

    mutations = {}
    m = copy.deepcopy(payload)
    m["content"]["extract"] = flip_last(m["content"]["extract"])
    mutations["extract"] = m
    m = copy.deepcopy(payload)
    m["content"]["summary"]["title"] = flip_last(m["content"]["summary"]["title"])
    mutations["summary.title"] = m
    m = copy.deepcopy(payload)
    m["content"]["summary"]["abstract"] = flip_last(m["content"]["summary"]["abstract"])
    mutations["summary.abstract"] = m
    m = copy.deepcopy(payload)
    m["salt"] = flip_last(m["salt"])
    mutations["salt"] = m

    for label, mutated in mutations.items():
        assert mutated != payload, f"{label}: the mutation did not change the Payload"
        assert _commit(mutated["salt"], mutated["content"]) != committed, \
            f"{label}: a mutated Payload still reproduces the commitment"
check("negative:payload-tamper", _payload_tamper)

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

def _merkle_exhaustive():
    """Property test — the real acceptance criterion for verify_inclusion.

    A single index-0 vector cannot expose a verifier that only handles
    uniform-left or uniform-right walks: index 0 is a left child at every
    level and index n-1 a right child at every level, so a verifier that
    derives direction incorrectly still accepts both while silently
    miscomputing every interior index. This builds a synthetic tree for
    every size n in 1..64 and, for every valid index, checks that
    verify_inclusion (a) accepts the correct audit path, (b) rejects that
    same path under every other in-range `index` (position is
    authenticated, not just membership), and (c) rejects it with one
    sibling removed or one appended (the path's length is bound to
    `index`/`entry_count`, not read off the proof).
    """
    def _expect_reject(block, proof):
        try:
            verify_inclusion(block, proof)
        except Exception:
            return
        raise AssertionError(
            f"expected rejection, got acceptance: entry_count={proof['entry_count']} "
            f"claimed_index={proof['index']} path_len={len(proof['path'])}")

    exercised = 0
    for n in range(1, 65):
        entries = [{"i": j} for j in range(n)]
        leaves = [leaf_hash(rfc8785.dumps(e)) for e in entries]
        root = "sha256:" + merkle_root(leaves).hex()
        block = {"header": {"entry_count": n, "merkle_root": root}, "entries": entries}
        for idx in range(n):
            path_hex = [h.hex() for h in audit_path(idx, leaves)]
            proof = {"index": idx, "entry_count": n, "path": path_hex}
            verify_inclusion(block, proof)                    # (a) correct proof verifies
            exercised += 1
            for other in range(n):                            # (b) position authentication
                if other != idx:
                    _expect_reject(block, {**proof, "index": other})
            if path_hex:                                      # (c) path too short
                _expect_reject(block, {**proof, "path": path_hex[:-1]})
            filler = path_hex[0] if path_hex else leaves[0].hex()
            _expect_reject(block, {**proof, "path": path_hex + [filler]})  # path too long
    assert exercised == sum(range(1, 65)), "did not exercise every (n, index) pair"
check("merkle-exhaustive", _merkle_exhaustive)

# 4. DC-4 §4: the ECVRF primitive itself, then the sampling vector built on it.
# The RFC 9381 Appendix B.3 vectors are the acceptance criterion for ecvrf.py:
# a VRF that is subtly wrong still *looks* verifiable, so the primitive is
# re-proved against the RFC on every harness run, not just at authoring time.
check("ecvrf:rfc9381-b3-vectors", ecvrf.self_test)

def _dc4_sampling():
    v = json.loads((ROOT / "vectors" / "dc4" / "sampling.json").read_text())
    pk = b64u_decode(v["auditor_public_key"])
    alpha, pi = bytes.fromhex(v["alpha_hex"]), bytes.fromhex(v["vrf_proof_hex"])
    # alpha is the 32 raw octets of the Block Hash: the hex digest decoded,
    # with the "sha256:" prefix NOT part of alpha (DC-4 §4).
    block = json.loads((ROOT / "examples" / "block.json").read_text())
    block_hash = "sha256:" + hashlib.sha256(rfc8785.dumps(block["header"])).hexdigest()
    assert v["block_hash"] == block_hash, "sampling vector is not bound to the example Block"
    assert alpha == bytes.fromhex(block_hash.split(":")[1]), "alpha is not the raw Block Hash"
    assert ecvrf.verify(pk, alpha, pi), "VRF proof does not verify"
    beta = ecvrf.proof_to_hash(pi)
    assert beta.hex() == v["beta_hex"], "beta mismatch"
    d8 = hashlib.sha256(beta + v["delta_id"].encode()).digest()[:8]
    assert d8.hex() == v["draw_first8_hex"], "draw bytes mismatch"
    assert int.from_bytes(d8, "big") == v["D"], "D mismatch"
    # The §4 selection test, recomputed in integers only. Every Delta named
    # here must be a real Entry of the example Block, and its D must follow
    # from beta and the Delta ID rather than being asserted.
    par = v["parameters"]
    assert (par["floor_1e7"], par["ceiling_1e7"], par["slope_per_micro"]) \
        == (200_000, 5_000_000, 3), "sampling parameters drifted from §9"
    seen = set()
    for c in v["selection"]:
        entry = block["entries"][c["entry_index"]]
        did = "sha256:" + hashlib.sha256(rfc8785.dumps(entry["body"]["delta"])).hexdigest()
        assert did == c["delta_id"], f"{c['label']}: delta_id is not that Entry's ID"
        first8 = hashlib.sha256(beta + c["delta_id"].encode()).digest()[:8]
        assert first8.hex() == c["draw_first8_hex"], f"{c['label']}: draw bytes"
        D = int.from_bytes(first8, "big")
        assert D == c["D"] and 0 <= D < 2**64, f"{c['label']}: D"
        p_1e7 = min(max(par["floor_1e7"]
                        + par["slope_per_micro"] * (1_000_000 - c["reputation_u"]),
                        par["floor_1e7"]), par["ceiling_1e7"])
        assert p_1e7 == c["p_1e7"], f"{c['label']}: p_1e7"
        lhs, rhs = D * 10**7, p_1e7 * 2**64
        assert (lhs, rhs) == (c["lhs"], c["rhs"]), f"{c['label']}: comparison operands"
        assert c["selected"] == (lhs < rhs), f"{c['label']}: selection outcome"
        # The integer test must agree with the rational it renders, at every
        # published point: D/2^64 < p_1e7/1e7.
        from fractions import Fraction
        assert c["selected"] == (Fraction(D, 2**64) < Fraction(p_1e7, 10**7)), \
            f"{c['label']}: integer test disagrees with the exact rational"
        seen.add(c["selected"])
    assert seen == {True, False}, "vector must show both a selected and a rejected Delta"
    # A proof for a different Block MUST NOT verify against this alpha: this is
    # what stops an Auditor reusing one draw across Blocks.
    assert not ecvrf.verify(pk, bytes(32), pi), "proof verified against wrong alpha"
check("vectors:dc4-sampling", _dc4_sampling)

def _dc4_audit_record_proof():
    """The published Record's vrf_proof must verify for the Block it audits."""
    rec = json.loads((ROOT / "examples" / "audit-record.json").read_text())["record"]
    v = json.loads((ROOT / "vectors" / "dc4" / "sampling.json").read_text())
    alpha = bytes.fromhex(v["alpha_hex"])
    assert ecvrf.verify(load_test_pubkey(), alpha, bytes.fromhex(rec["vrf_proof"])), \
        "audit record vrf_proof does not verify"
    assert rec["vrf_proof"] == v["vrf_proof_hex"], "record proof differs from vector proof"
check("vectors:dc4-audit-record-proof", _dc4_audit_record_proof)

def _dc4_audit_commitments():
    """Every content-derived value in an Audit Record is salted (DC-4 §5).

    Moving extracts out of the Log achieves nothing if the Log keeps bare
    digests of the same text: a party holding a copy could recompute one and
    confirm the text was there, which is precisely the confirmability the
    Payload salt exists to destroy. So the Auditor's three content-derived
    values are committed under that same salt, and this recomputes all three
    from their preimages.
    """
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    rec = json.loads((ROOT / "examples" / "audit-record.json").read_text())["record"]
    v = json.loads((ROOT / "vectors" / "dc4" / "audit-commitments.json").read_text())
    salt = b64u_decode(payload["salt"])
    assert v["audited_delta"] == rec["audited_delta"], \
        "the commitment vector does not describe the example Record"
    for field, entry in v["commitments"].items():
        expected = "hmac-sha256:" + hmac.new(
            salt, bytes.fromhex(entry["message_hex"]), hashlib.sha256).hexdigest()
        assert expected == entry["value"], f"{field}: vector value is not HMAC(salt, message)"
        assert rec[field] == expected, f"{field}: the Record does not carry that commitment"
    # The Auditor's reference extraction in a `consistent` audit is the Payload's
    # own extract, so this one is recomputable from the Payload alone — which is
    # what ties the Record's key to the Delta's key rather than to a second salt.
    assert rec["ref_extract_commitment"] == "hmac-sha256:" + hmac.new(
        salt, payload["content"]["extract"].encode(), hashlib.sha256).hexdigest(), \
        "ref_extract_commitment is not keyed by the audited Payload's salt"
check("audit:commitments", _dc4_audit_commitments)

def _dc4_audit_commitment_tamper():
    """One mutated octet, or the wrong salt, MUST break each commitment.

    Binding must hold for the Auditor's values exactly as it does for the
    Publisher's: a Record must not be able to stand for a capture other than
    the one it was computed over. And keying MUST be to the Payload's salt,
    not to any salt the Auditor could retain past a withdrawal.
    """
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    v = json.loads((ROOT / "vectors" / "dc4" / "audit-commitments.json").read_text())
    salt = b64u_decode(payload["salt"])
    other_salt = bytes(b ^ 0x01 for b in salt)
    assert other_salt != salt, "the alternative salt is not different"
    for field, entry in v["commitments"].items():
        msg = bytearray(bytes.fromhex(entry["message_hex"]))
        assert msg, f"{field}: empty preimage proves nothing"
        mutated = bytearray(msg)
        mutated[-1] ^= 0x01
        assert bytes(mutated) != bytes(msg), f"{field}: the mutation changed nothing"
        assert "hmac-sha256:" + hmac.new(
            salt, bytes(mutated), hashlib.sha256).hexdigest() != entry["value"], \
            f"{field}: a mutated preimage still reproduces the commitment"
        assert "hmac-sha256:" + hmac.new(
            other_salt, bytes(msg), hashlib.sha256).hexdigest() != entry["value"], \
            f"{field}: the commitment does not depend on the salt"
check("negative:audit-commitment-tamper", _dc4_audit_commitment_tamper)

# DC-3 §6.2: after a withdrawal the Log retains no unsalted digest of the
# withdrawn content. That sentence is a claim about every object format in the
# suite, so the guard below enumerates every schema and every example rather
# than any single object.
#
# Each entry names a digest-shaped field that is NOT derived from page content,
# with what it actually covers. Anything digest-shaped and not on this list must
# be an `hmac-sha256:` commitment under the Payload salt, or it fails. Adding a
# field here is the deliberate act of asserting it carries no content.
NON_CONTENT_DIGESTS = {
    ("delta.schema.json", "prev"): "a Delta ID: SHA-256 of Canonical Bytes, which carry the salted commitment and no content",
    ("publisher.schema.json", "prev_declaration"): "SHA-256 of a Declaration, which carries keys and no content",
    ("feed.schema.json", "deltas"): "Delta IDs",
    ("block.schema.json", "prev_block_hash"): "SHA-256 of a Block header",
    ("block.schema.json", "merkle_root"): "root over Entries, which carry commitments and no content",
    ("checkpoint.schema.json", "block_hash"): "SHA-256 of a Block header",
    ("audit-record.schema.json", "audited_delta"): "a Delta ID",
    ("registry-update.schema.json", "evidence"): "Audit Record IDs: SHA-256 over Records that themselves carry only commitments",
    ("registry-update.schema.json", "delta_id"): "a Delta ID",
    ("status.schema.json", "delta_id"): "a Delta ID",
    ("snapshot-manifest.schema.json", "sha256"): "a whole tier file, not any one record (DC-3 §7); and a manifest is a static artifact, not a Log Entry",
    ("audit-record.schema.json", "vrf_proof"): "an ECVRF proof over a Block Hash (DC-4 §4); hex-shaped but not a digest of anything fetched",
    ("payload.schema.json", "salt"): "the salt itself: drawn from a CSPRNG, never derived from the content it keys (DC-1 §3.6)",
}

DIGEST_NAME = re.compile(r"hash|digest|sha\d|checksum|commitment", re.IGNORECASE)

# A pattern is digest-shaped if it accepts a digest. Probing the pattern beats
# pattern-matching the pattern: `^[0-9a-f]{64}$`, `^[0-9A-F]{64}$` and
# `^[a-f0-9]{64}$` are the same constraint written three ways, and a regex over
# the regex catches whichever spelling it was written to catch.
DIGEST_PROBES = [p + "0" * n
                 for n in (32, 40, 56, 64, 96, 128, 160)
                 for p in ("", "sha256:", "warc:sha256:", "hmac-sha256:")]

def _is_digest_shaped(pattern: str) -> bool:
    if not pattern:
        return False
    try:
        rx = re.compile(pattern)
    except re.error:
        return True          # an unparseable pattern constrains nothing usable
    return any(rx.search(probe) for probe in DIGEST_PROBES)

def _walk_schema(node, schema_name, findings, key=None):
    """Collect every digest-shaped leaf, by property name and by pattern shape.

    Two detectors, because either alone is escapable: a field named
    `withdrawn_content` with pattern `^[0-9a-f]{64}$` carries no telltale name,
    and a field named `extract_hash` with no pattern at all carries no telltale
    pattern. What neither reaches is a field with an innocuous name and no
    pattern at all — an unconstrained string can hold a digest whatever it is
    called. The example scan below covers that for what the suite ships, and
    DC-4 §9.1 covers it normatively for what an implementation may add.
    """
    if isinstance(node, dict):
        pattern = node.get("pattern", "")
        if key is not None and (DIGEST_NAME.search(key) or _is_digest_shaped(pattern)):
            findings.append((schema_name, key, pattern))
        for name, sub in node.get("properties", {}).items():
            _walk_schema(sub, schema_name, findings, name)
        for kw in ("items", "then", "else", "not", "contains",
                   "additionalProperties", "propertyNames"):
            if isinstance(node.get(kw), dict):
                _walk_schema(node[kw], schema_name, findings, key)
        for kw in ("allOf", "anyOf", "oneOf"):
            for sub in node.get(kw, []):
                if isinstance(sub, dict):
                    _walk_schema(sub, schema_name, findings, key)
        # `if` shapes a branch rather than declaring a field, but a digest
        # smuggled into one would still be a schema-blessed field name.
        if isinstance(node.get("if"), dict):
            _walk_schema(node["if"], schema_name, findings, key)
    return findings

def _no_unsalted_content_digest():
    """No object in the suite carries a bare digest of page content.

    Moving extracts out of the Log achieves nothing if any object keeps an
    unsalted hash of the same text, so this holds the whole suite to the rule
    DC-3 §6.2 states: a content-derived value is committed under the Payload
    salt or it is not carried at all. Every schema is enumerated; every
    digest-shaped field must either be an `hmac-sha256:` commitment or appear
    in NON_CONTENT_DIGESTS with a reason.
    """
    schemas = sorted((ROOT / "schemas").glob("*.schema.json"))
    assert len(schemas) >= 9, f"only {len(schemas)} schemas enumerated; the sweep is not suite-wide"
    offenders = []
    for path in schemas:
        for name, key, pattern in _walk_schema(
                json.loads(path.read_text()), path.name, []):
            if pattern.startswith("^hmac-sha256:"):
                continue                       # a salted commitment
            if (name, key) in NON_CONTENT_DIGESTS:
                continue                       # declared to carry no content
            offenders.append(f"{name}: {key} (pattern {pattern!r})")
    assert not offenders, \
        "digest-shaped fields that are neither salted commitments nor declared " \
        "content-free:\n  " + "\n  ".join(offenders)

    # The examples must not smuggle one through an unconstrained object either
    # (DC-4 §9.1): registry-update `details` is `{"type": "object"}` for several
    # actions, so a bare digest there would satisfy every schema in the suite.
    allowed_keys = {key for _, key in NON_CONTENT_DIGESTS}
    def scan(node, key, where):
        if isinstance(node, dict):
            for k, v in node.items():
                scan(v, k, where)
        elif isinstance(node, list):
            for v in node:
                scan(v, key, where)
        elif isinstance(node, str):
            bare = re.fullmatch(r"(sha256:|warc:sha256:)?[0-9a-f]{64}", node)
            if bare and key not in allowed_keys:
                raise AssertionError(
                    f"{where}: bare digest at {key!r} = {node} — commit it under "
                    "the Payload salt (DC-3 §6.2) or do not carry it")
    for example in sorted((ROOT / "examples").glob("*.json")):
        scan(json.loads(example.read_text()), None, example.name)
check("repo:no-unsalted-content-digest", _no_unsalted_content_digest)

def _dc4_coverage_attestation():
    """§4's in-band coverage proof must be expressible as a Registry Update.

    An Auditor whose VRF selects nothing in a Block publishes a
    `coverage_attestation` carrying that Block's vrf_proof, so the proof
    reaches the Log either way and shirking is detectable without any
    out-of-band challenge.
    """
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    actions = schema["properties"]["update"]["properties"]["action"]["enum"]
    assert "coverage_attestation" in actions, "action enum lacks coverage_attestation"
    # The enum is append-only. Reordering it would silently reinterpret nothing
    # in the Log (actions are strings), but it invites an implementation to key
    # on position; pinning the established prefix leaves appends the only edit.
    established = ["aggregator_key_add", "aggregator_key_remove", "auditor_admit",
                   "auditor_remove", "sanction", "sanction_lift", "notice", "appeal",
                   "appeal_ruling", "parameter_change", "coverage_attestation"]
    assert actions[:len(established)] == established, \
        "the action enum was reordered rather than appended to"
    v = json.loads((ROOT / "vectors" / "dc4" / "sampling.json").read_text())
    attestation = {
        "update": {
            "dc_version": "1.0.0",
            "action": "coverage_attestation",
            "subject": "audit.example.org",
            "details": {"vrf_proof": v["vrf_proof_hex"]},
            "effective_at": "2026-08-02T16:00:00Z",
        },
        "sig": json.loads(
            (ROOT / "examples" / "registry-update.json").read_text())["sig"],
    }
    Draft202012Validator(schema).validate(attestation)
check("schema:dc4-coverage-attestation", _dc4_coverage_attestation)

def _dc4_payload_withdrawal():
    """A withdrawal is only distinguishable from censorship if it is typed.

    DC-3 §6.2 rests on the Log carrying, for every withdrawn Payload, an entry
    naming which Delta, on what legal basis, at whose demand. A withdrawal
    missing any of the three would let an operator record an unfalsifiable
    "we removed something", which is what a quiet drop looks like.
    """
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    actions = schema["properties"]["update"]["properties"]["action"]["enum"]
    assert "payload_withdrawal" in actions, "action enum lacks payload_withdrawal"
    delta_id = (ROOT / "vectors" / "dc1" / "id.txt").read_text().strip()
    withdrawal = {
        "update": {
            "dc_version": "1.0.0",
            "action": "payload_withdrawal",
            "subject": "example.com",
            "details": {"delta_id": delta_id,
                        "legal_basis": "GDPR Art. 17(1)(a)",
                        "jurisdiction": "EU"},
            "effective_at": "2026-08-02T16:00:00Z",
        },
        "sig": json.loads(
            (ROOT / "examples" / "registry-update.json").read_text())["sig"],
    }
    v = Draft202012Validator(schema)
    v.validate(withdrawal)
    import copy
    for missing in ("delta_id", "legal_basis", "jurisdiction"):
        bad = copy.deepcopy(withdrawal)
        del bad["update"]["details"][missing]
        assert not v.is_valid(bad), f"a withdrawal without {missing} validates"
    bad = copy.deepcopy(withdrawal)
    bad["update"]["details"]["delta_id"] = "not-a-delta-id"
    assert not v.is_valid(bad), "a withdrawal naming no well-formed Delta ID validates"
check("schema:dc4-payload-withdrawal", _dc4_payload_withdrawal)

def _dc4_appendix_figures():
    """DC-4's worked example must quote the vector, not a remembered figure.

    Figures transcribed into prose drift silently from the vectors that
    produced them. This pins every published figure to
    vectors/dc4/sampling.json.
    """
    v = json.loads((ROOT / "vectors" / "dc4" / "sampling.json").read_text())
    spec = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    flat = spec.replace("`<br>`", "")   # long hex is wrapped inside table cells
    for field in ("block_hash", "alpha_hex", "vrf_proof_hex", "beta_hex",
                  "delta_id", "draw_first8_hex", "auditor_public_key"):
        assert v[field] in flat, f"DC-4 does not quote sampling.json {field}"
    for c in v["selection"]:
        for field in ("delta_id", "draw_first8_hex", "lhs_approx", "rhs_approx"):
            assert c[field] in flat, \
                f"DC-4 does not quote {c['label']} {field} = {c[field]}"
        for n in (c["D"], c["p_1e7"], c["reputation_u"]):
            assert str(n) in flat or f"{n:,}".replace(",", " ") in flat, \
                f"DC-4 does not quote {c['label']} value {n}"
    # No floating-point rendering of the sampling rate may survive in §4's
    # normative text: the integers are the definition, decimals only a reading.
    section4 = flat.split("## 4. Audit Sampling")[1].split("## 5.")[0]
    for stale in ("draw(d) <", "0.30 x (1 - reputation)", "clamp(0.02"):
        assert stale not in section4, f"§4 still specifies sampling in floats: {stale!r}"
check("spec:dc4-appendix-figures", _dc4_appendix_figures)

# 5. DC-4 §6: reputation, recomputed from the normative decay table using
# nothing but integers. A float anywhere in this check would defeat its point.
DC4 = ROOT / "vectors" / "dc4"

def _dc4_decay_table():
    raw = (DC4 / "decay-table.json").read_bytes()
    # Structural assertions run BEFORE the digest pin. The digest would catch
    # any mutation first and report only "digest mismatch", which tells an
    # implementer nothing about what is wrong with the table it is holding.
    t = json.loads(raw)
    assert t["scale"] == 1_000_000_000, "decay scale drifted"
    assert t["max_days"] == 1825, "decay horizon drifted"
    v = t["values"]
    assert len(v) == t["max_days"] + 1, "table length does not match max_days"
    assert all(isinstance(x, int) and not isinstance(x, bool) for x in v), \
        "decay table must hold integers, not floats"
    assert v[0] == 1_000_000_000, "decay(0) must be exactly 1e9"
    assert all(v[i] > v[i + 1] for i in range(len(v) - 1)), \
        "decay table must be strictly decreasing"
    assert v[-1] > 0, "the horizon value must be positive (expiry is the step to 0)"
    # Only now the byte-level pin, which is what implementations key on.
    digest = hashlib.sha256(raw).hexdigest()
    spec = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    assert digest in spec, f"DC-4 §6.1 does not pin the decay table digest {digest}"
check("vectors:dc4-decay-table", _dc4_decay_table)

def _dc4_reputation():
    """Recompute every published intermediate from §6, in integers only."""
    r = json.loads((DC4 / "reputation.json").read_text())
    table = json.loads((DC4 / "decay-table.json").read_text())
    values, scale, max_days = table["values"], table["scale"], table["max_days"]
    k, micro = r["constants"], r["micro_scale"]
    assert r["decay_scale"] == scale, "vectors disagree about the decay scale"
    assert micro == 1_000_000, "reputation resolution drifted"

    def decay(t):
        return values[t] if t <= max_days else 0

    discriminating = []

    def recompute(case):
        A, C = case["A"], case["C"]
        assert C == min(case["distinct_audited_urls"], k["c_cap"]), "C_cap not applied"
        base = k["base_at_age_0"] + (
            (micro - k["base_at_age_0"]) * min(A, k["age_normalization_days"])
        ) // k["age_normalization_days"]
        assert base == case["base_u"], f"base_u mismatch in {case['label']}"
        # §6's evaluation-order rule: the division binds to the product before
        # it and never absorbs the leading constant. The other parse must be
        # observably wrong at every published row, so an implementation that
        # reads the rule the other way fails this vector instead of shipping.
        folded = (k["base_at_age_0"]
                  + (micro - k["base_at_age_0"]) * min(A, k["age_normalization_days"])
                  ) // k["age_normalization_days"]
        assert folded != base, \
            f"{case['label']}: the mis-parsed base_u coincides here, so this row " \
            "cannot discriminate the two readings"
        penalty = 0
        prev_t = -1
        for inc in case["inconsistencies"]:
            assert inc["severity"] in (1, 2, 3), "severity out of range"
            assert inc["t_days"] >= prev_t, "incidents not in ascending t_i order"
            prev_t = inc["t_days"]
            assert inc["decay"] == decay(inc["t_days"]), "decay value not from the table"
            penalty += inc["severity"] * decay(inc["t_days"])
        assert penalty == case["penalty_n"], f"penalty_n mismatch in {case['label']}"
        num = base * (C + 1) * scale
        den = (C + 1) * scale + k["penalty_weight"] * penalty
        assert num == case["numerator"] and den == case["denominator"], \
            f"numerator/denominator mismatch in {case['label']}"
        formula = max(0, min(micro, num // den))
        assert formula == case["formula_u"], f"formula_u mismatch in {case['label']}"
        provisional = A < k["gate_age_days"] or C < k["gate_c"]
        assert provisional == case["provisional"], f"gate mismatch in {case['label']}"
        # The cap is a ceiling, never a floor: min(formula, cap).
        rep = min(formula, k["provisional_cap_u"]) if provisional else formula
        assert rep == case["reputation_u"], f"reputation_u mismatch in {case['label']}"
        assert rep <= formula, "the Provisional cap acted as a floor"
        q = k["quota_base"] + (k["quota_slope"] * rep) // micro
        assert q == case["Q"], f"Q mismatch in {case['label']}"
        # Same rule for Q: dividing reputation_u first collapses the slope to
        # zero for every sub-unit reputation.
        divided_first = k["quota_base"] + k["quota_slope"] * (rep // micro)
        if rep < micro:
            assert divided_first != q, \
                f"{case['label']}: the mis-parsed Q coincides here"
            discriminating.append(case["label"])
        # §4's integer sampling rate for this reputation, recomputed here.
        p = min(max(200_000 + 3 * (micro - rep), 200_000), 5_000_000)
        assert p == case["p_1e7"], f"p_1e7 mismatch in {case['label']}"
        assert case["p_readable"] == "0.%07d" % p, "readable p does not match p_1e7"
        return rep

    w = r["worked_example"]
    # A and t_i are Block-derived, not asserted: recompute them from sealed_at.
    def secs(ts):
        return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    s = w["sealed_at"]
    assert (secs(s["block_n"]) - secs(s["first_delta_block"])) // 86400 == w["A"], \
        "A is not the whole-day count between the two Block sealed_at values"
    assert (secs(s["block_n"]) - secs(s["confirming_block"])) // 86400 == \
        w["inconsistencies"][0]["t_days"], "t_i is not Block-derived"
    block = json.loads((ROOT / "examples" / "block.json").read_text())
    assert s["first_delta_block"] == block["header"]["sealed_at"], \
        "worked example is not anchored to the example Block"
    recompute(w)

    by_label = {c["label"]: recompute(c) for c in r["boundary"]}
    # Requirement: reputation MUST NOT decrease solely because a gate lifted.
    for lo, hi in (("gate-age-below", "gate-age-at"),
                   ("gate-age-at", "gate-age-above"),
                   ("gate-age-below-penalized", "gate-age-at-penalized"),
                   ("gate-c-below", "gate-c-at")):
        assert by_label[lo] <= by_label[hi], \
            f"reputation fell crossing the gate: {lo}={by_label[lo]} > {hi}={by_label[hi]}"
    # The cap is met from below, not jumped past: at A = 0 the ungated formula
    # equals the cap exactly, which is what removes the graduation cliff.
    new = next(c for c in r["boundary"] if c["label"] == "new-domain")
    assert new["formula_u"] == k["provisional_cap_u"] == new["reputation_u"], \
        "a brand-new domain no longer meets the cap exactly"
    assert new["Q"] == 1100, "the new-domain quota is not 1100"
    assert discriminating, "no published row discriminates the two readings of Q"
check("vectors:dc4-reputation", _dc4_reputation)

def _dc4_evaluation_order():
    """§6's parenthesization is normative, so the spec must carry it verbatim.

    A wording of the form "that division is its last operation" is literally
    false for `base_u` and `Q`, both of which add after dividing: read at its
    word it yields base_u = 136 at A = 0 instead of 100 000, which also
    destroys the no-cliff property. This pins both the
    corrected forms and the two counterexample values the spec quotes.
    """
    spec = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    forms = ("(seconds(Y) − seconds(X)) / 86 400",
             "100 000 + ((900 000 × min(A, 730)) / 730)",
             "(base_u × (C + 1) × 1 000 000 000)",
             "100 + ((10 000 × reputation_u) / 1 000 000)")
    for form in forms:
        assert form in spec, f"DC-4 §6 no longer writes {form!r} parenthesized"
    # The stated count and the enumeration must agree, or a reader cannot
    # tell which divisions the parenthesization rule covers.
    assert "exactly **four**" in spec, \
        f"DC-4 §6 no longer states the division count, which is {len(forms)}"
    table_rows = [ln for ln in spec.splitlines()
                  if ln.startswith("| ") and ") / " in ln and "§6" in ln]
    assert len(table_rows) == len(forms), \
        f"the evaluation-order table lists {len(table_rows)} divisions, not {len(forms)}"
    # The spec quotes what the wrong parses produce; verify those numbers are
    # real, so the warning cannot rot into a wrong warning.
    assert (100_000 + 900_000 * 0) // 730 == 136, "quoted mis-parse of base_u is stale"
    assert 100 + 10_000 * (359_236 // 1_000_000) == 100, "quoted mis-parse of Q is stale"
    assert 100_000 + ((900_000 * 0) // 730) == 100_000, "correct base_u parse drifted"
    for n in ("136", "3 692"):
        assert n in spec, f"DC-4 no longer quotes the counterexample value {n}"
check("spec:dc4-evaluation-order", _dc4_evaluation_order)

def _dc4_sealed_at_precision():
    """DC-4 §6.1's day counts are exact only because §6's inputs are exact.

    A Block sealed at `...:00.500Z` or `...+00:00` would make the conversion
    to integer seconds a rounding decision, and one rounded half-second can
    move a whole-day boundary and with it A, t_i, base_u and the score. The
    constraint therefore lives in the Block schema, not in prose downstream.
    """
    import copy
    import re
    schema = json.loads((ROOT / "schemas" / "block.schema.json").read_text())
    pat = schema["properties"]["header"]["properties"]["sealed_at"].get("pattern")
    assert pat == r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", \
        "block.schema.json does not constrain sealed_at to whole seconds + Z"
    block = json.loads((ROOT / "examples" / "block.json").read_text())
    assert re.match(pat, block["header"]["sealed_at"]), \
        "the example Block does not satisfy its own sealed_at pattern"
    v = Draft202012Validator(schema)
    # Positive control. Without it, a pattern that rejects everything would
    # satisfy the negative cases below and look like a passing guard.
    assert v.is_valid(block), "the shipped Block no longer validates against its schema"
    # Negative controls. `is_valid` returns a bool; `iter_errors` returns a
    # generator, which is truthy even when it yields nothing — asserting on it
    # directly would pass for every input, valid ones included.
    for bad in ("2026-08-02T13:00:00.500Z", "2026-08-02T13:00:00+00:00",
                "2026-08-02T13:00:00", "2026-08-02t13:00:00z"):
        candidate = copy.deepcopy(block)
        candidate["header"]["sealed_at"] = bad
        assert not v.is_valid(candidate), f"schema accepts non-exact sealed_at {bad!r}"
        assert list(v.iter_errors(candidate)), \
            f"schema produced no error for non-exact sealed_at {bad!r}"
    dc3 = (ROOT / "specs" / "DC-3-commons-log-distribution.md").read_text()
    assert "whole-second precision" in dc3, "DC-3 §3.1 does not state the constraint"
check("schema:dc4-sealed-at-precision", _dc4_sealed_at_precision)

def _dc4_reputation_figures():
    """DC-4 §6 and Appendix B must quote the vector, not remembered figures."""
    r = json.loads((DC4 / "reputation.json").read_text())
    spec = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    table = json.loads((DC4 / "decay-table.json").read_text())
    def quoted(n):
        # The spec groups long numbers with spaces; short ones it writes plain.
        return str(n) in spec or f"{n:,}".replace(",", " ") in spec
    for n in (table["values"][0], table["values"][-1]):
        assert quoted(n), f"DC-4 does not quote decay value {n}"
    for case in [r["worked_example"]] + r["boundary"]:
        for field in ("base_u", "penalty_n", "reputation_u", "Q"):
            assert quoted(case[field]), \
                f"DC-4 does not quote {case['label']}.{field} = {case[field]}"
    assert quoted(r["worked_example"]["p_1e7"]), "DC-4 does not quote the worked p_1e7"
    assert r["worked_example"]["p_readable"] in spec, \
        "DC-4 does not show what the worked p_1e7 reads as"
check("spec:dc4-reputation-figures", _dc4_reputation_figures)

def _dc4_severity_bands():
    """DC-4 §7's severity table drives `penalty_n` directly (§6.1), so a
    collapsed or unreachable band silently changes every domain's
    reputation rather than merely misdocumenting one. Confirms all three
    severities are reachable from `sim` alone (now an integer, §5), that
    no row rests on a term needing its own definition (e.g. "wholly
    absent"), and that the reachable range tracks §5's own `inconsistent`
    threshold rather than a value copied once and then hardcoded — a
    mutation of §5's threshold that collapses a band must fail here.
    """
    spec = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    section5 = spec.split("## 5. Verdicts")[1].split("## 6.")[0]
    section7 = spec.split("## 7. Sanctions")[1].split("## 8.")[0]
    for row in ("| 150 000 ≤ `sim` < 300 000 | 1 (minor divergence) |",
                "| 50 000 ≤ `sim` < 150 000 | 2 (misleading extract) |",
                "| `sim` < 50 000 | 3 (fabricated content) |"):
        assert row in section7, f"DC-4 §7 no longer carries the severity row {row!r}"
    assert "wholly absent" not in section7, \
        "DC-4 §7's severity table still conditions a band on an undefined term"

    # HIGH is read from §5's own `inconsistent` threshold, not copied and
    # frozen here: a future edit that narrows or widens it must change what
    # this check exercises, or a collapsed band goes undetected again.
    m = re.search(r"\|\s*`inconsistent`\s*\|\s*`similarity`\s*<\s*([\d ]+?)\s*\*\*and\*\*", section5)
    assert m, "DC-4 §5 does not state the `inconsistent` threshold in the expected form"
    HIGH = int(m.group(1).replace(" ", ""))
    LOW, MID = 50_000, 150_000   # exactly the §7 table boundaries pinned above

    def severity(sim):
        assert 0 <= sim < HIGH, f"{sim} is not a valid Confirmed-Inconsistency sim (§5: < {HIGH})"
        if sim >= MID:
            return 1
        if sim >= LOW:
            return 2
        return 3

    # Construct a Confirmed Inconsistency's confirming Audit Records (§5:
    # both `inconsistent`, i.e. similarity < HIGH) at a similarity that
    # lands the CI's `sim` (the highest of the two) in each band.
    cases = [
        ([220_000, 180_000], 1, "minor divergence"),
        ([120_000, 90_000], 2, "misleading extract"),
        ([40_000, 10_000], 3, "fabricated content"),
    ]
    seen = set()
    for sims, expected, label in cases:
        records = [{"similarity": s, "verdict": "inconsistent"} for s in sims]
        assert all(r["verdict"] == "inconsistent" and r["similarity"] < HIGH
                   for r in records), f"{label}: constructed records are not valid confirming Records"
        sim = max(r["similarity"] for r in records)
        got = severity(sim)
        assert got == expected, f"{label}: sim={sim} produced severity {got}, expected {expected}"
        seen.add(got)
    assert seen == {1, 2, 3}, f"the three worked cases do not cover all three severities: {seen}"

    # No reachable similarity value maps to a band the table cannot
    # produce: `similarity` is an integer (§5), so the reachable range is
    # finite and exactly enumerable — every integer in [0, HIGH) is
    # checked, not a sample. A collapsed table (e.g. severity 3 for nearly
    # everything, or band 1 emptied by a narrowed HIGH) would still run
    # without error but never emit a 1.
    reachable = {severity(sim) for sim in range(HIGH)}
    assert reachable == {1, 2, 3}, \
        f"severity table does not produce all three bands across [0, {HIGH}): got {reachable}"

    # Exact boundary behaviour, matching the table's own "≤" / "<" reading.
    # Pinned to literal integers, not to LOW/MID/HIGH: a mutation of those
    # variables must be caught here rather than checked against itself.
    assert severity(150_000) == 1 and severity(149_999) == 2, \
        "the level 1 / level 2 boundary is not at sim = 150 000"
    assert severity(50_000) == 2 and severity(49_999) == 3, \
        "the level 2 / level 3 boundary is not at sim = 50 000"
check("spec:dc4-severity-bands", _dc4_severity_bands)

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

def _no_process_narration():
    """Published files describe what must hold, never how they came to say it.

    A specification is read by people with no access to its drafting history,
    so a comment or sentence that refers to a review round, an internal task
    number, or "an earlier revision" documents nothing a reader can act on and
    dates the artifact. State the invariant and the failure mode it prevents
    instead.
    """
    markers = [
        r"fix[- ]round", r"\bround[- ]\d", r"\bTask \d+\b", r"\bthe reviewer\b",
        r"\breview (?:found|caught)\b", r"XFAIL_UNTIL", r"\bin a later task\b",
        r"\bprior implementer\b", r"\bearlier revision\b",
    ]
    pattern = re.compile("|".join(markers), re.IGNORECASE)
    hits = []
    for folder, glob in (("specs", "*.md"), ("schemas", "*.json"),
                         ("tools", "*.py"), ("decisions", "*.md")):
        for path in sorted((ROOT / folder).glob(glob)):
            if path.name == "validate_examples.py":
                continue          # this check necessarily names the markers
            for n, line in enumerate(path.read_text().splitlines(), 1):
                if pattern.search(line):
                    hits.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()}")
    assert not hits, "process narration in published files:\n  " + "\n  ".join(hits)
check("repo:no-process-narration", _no_process_narration)

sys.exit(1 if failures else 0)
