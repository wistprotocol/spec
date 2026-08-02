#!/usr/bin/env python3
"""Validate examples/ against schemas/ and verify vectors/. Exit 0 = green."""
import base64, calendar, hashlib, json, pathlib, sys, time

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
    assert abs(int.from_bytes(d8, "big") / 2**64 - v["draw"]) < 1e-12, "draw mismatch"
    for row in v["thresholds"]:
        p = min(max(0.02 + 0.30 * (1 - row["reputation"]), 0.02), 0.50)
        assert abs(p - row["p"]) < 1e-9, f"p mismatch at reputation {row['reputation']}"
        assert row["selected"] == (v["draw"] < row["p"]), \
            f"selection mismatch at reputation {row['reputation']}"
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
    assert actions[-1] == "coverage_attestation", "coverage_attestation must be appended, not reordered"
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
    assert f"{v['draw']:.10f}" in flat, "DC-4 does not quote the sampling draw"
    for row in v["thresholds"]:
        assert f"| {row['reputation']:.2f}" in flat or f"{row['reputation']:.2f} " in flat, \
            f"DC-4 does not quote reputation {row['reputation']}"
check("spec:dc4-appendix-figures", _dc4_appendix_figures)

# 5. DC-4 §6: reputation, recomputed from the normative decay table using
# nothing but integers. A float anywhere in this check would defeat its point.
DC4 = ROOT / "vectors" / "dc4"

def _dc4_decay_table():
    raw = (DC4 / "decay-table.json").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    spec = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    assert digest in spec, f"DC-4 §6.1 does not pin the decay table digest {digest}"
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

    def recompute(case):
        A, C = case["A"], case["C"]
        assert C == min(case["distinct_audited_urls"], k["c_cap"]), "C_cap not applied"
        base = k["base_at_age_0"] + (
            (micro - k["base_at_age_0"]) * min(A, k["age_normalization_days"])
        ) // k["age_normalization_days"]
        assert base == case["base_u"], f"base_u mismatch in {case['label']}"
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
        q = k["quota_base"] + k["quota_slope"] * rep // micro
        assert q == case["Q"], f"Q mismatch in {case['label']}"
        p = min(max(200_000 + 3 * (micro - rep), 200_000), 5_000_000)
        assert p == case["p_scaled_1e7"], f"p mismatch in {case['label']}"
        assert case["p"] == "0.%07d" % p, "decimal p does not match its scaled form"
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
check("vectors:dc4-reputation", _dc4_reputation)

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
check("spec:dc4-reputation-figures", _dc4_reputation_figures)

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
