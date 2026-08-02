#!/usr/bin/env python3
"""Generate deterministic DC-1/DC-3 test vectors and signed examples.

Never uses wall-clock or randomness: fixed seed, fixed timestamps.
Re-running always produces byte-identical output.
"""
import base64, calendar, hashlib, json, pathlib, time
from decimal import Decimal, localcontext

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ecvrf
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
    "seq": 0,
    "domain": "example.com",
    "subdomain_scope": ["www.example.com", "blog.example.com"],
    "keys": [
        {"key_id": "test-k1", "alg": "Ed25519", "public_key": b64u(pub_raw),
         "valid_from": "2026-08-02T12:00:00Z"}
    ],
    # Illustrative only: a real recovery key MUST be a distinct keypair,
    # generated independently and held offline, never reused as a signing
    # key. The vector reuses the same test public key purely so the suite
    # ships one deterministic keypair; DC-1 §5.2 normatively requires
    # recovery keys to sign nothing but Declarations.
    "recovery_keys": [
        {"key_id": "test-r1", "alg": "Ed25519", "public_key": b64u(pub_raw),
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

# --------------------------------------------------------------- DC-2: status
# Not a signed Envelope (DC-2 §7.1) — a plain JSON debugging surface.
write_json(EXAMPLES / "status.json", {
    "dc_version": "1.0.0", "domain": "example.com",
    "last_pull_at": "2026-08-02T12:05:00Z", "quota_remaining": 1098,
    "state": "new",
    "rejections": [{"code": "DC1-E07", "at": "2026-08-02T12:05:00Z",
                    "delta_id": "sha256:" + "0" * 64,
                    "detail": "prev chain violation"}],
})
print("dc2 status example written")

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
# The Auditor's VRF proof over the Block Hash (DC-4 §4). alpha is the 32 raw
# octets of the Block Hash — the hex digest decoded, WITHOUT the "sha256:"
# prefix. The VRF key is the Auditor's Ed25519 key (RFC 9381
# ECVRF-EDWARDS25519-SHA512-TAI reuses the RFC 8032 key format).
alpha = bytes.fromhex(block_hash.split(":")[1])
pi = ecvrf.prove(SEED, alpha)
beta = ecvrf.proof_to_hash(pi)

audit_record = {
    "dc_version": "1.0.0",
    "audited_delta": delta_id,
    "auditor_id": "audit.example.org",
    "fetched_at": "2026-08-02T14:00:00Z",
    "response_hash": "sha256:" + sha256_hex(b"response-placeholder"),
    "ref_extract_hash": "sha256:" + sha256_hex(EXTRACT.encode()),
    "similarity": 940000,
    "verdict": "consistent",
    "evidence": "warc:sha256:" + sha256_hex(b"warc-placeholder"),
    "vrf_proof": pi.hex(),
}
write_json(EXAMPLES / "audit-record.json",
           sign_envelope("record", audit_record, "test-aud-k1"))

registry_update = {
    "dc_version": "1.0.0",
    "action": "auditor_admit",
    "subject": "audit.example.org",
    "details": {"key_id": "test-aud-k1", "alg": "Ed25519", "public_key": b64u(pub_raw)},
    "effective_at": "2026-08-02T12:00:00Z",
}
write_json(EXAMPLES / "registry-update.json",
           sign_envelope("update", registry_update, "test-agg-k1"))
print("dc4 audit-record and registry-update examples written")

# ------------------------------------------------------ DC-4: audit sampling
# Worked VRF sampling vector (DC-4 §4), computed the way §4 mandates: in
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
    """DC-4 §4's sampling rate, scaled by 1e7. Exact: no rounding occurs."""
    return min(max(SAMPLING_FLOOR_1E7 + SAMPLING_SLOPE * (10**6 - reputation_u),
                   SAMPLING_FLOOR_1E7), SAMPLING_CEILING_1E7)


def selected(D: int, p_1e7: int) -> bool:
    return D * 10**7 < p_1e7 * TWO_64


def approx4(n: int) -> str:
    """Exact integer -> 4-significant-digit rendering, e.g. 5.350e25.

    DC-4's Appendix A shows these products rounded for reading; computing the
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

DC4 = ROOT / "vectors" / "dc4"
DC4.mkdir(parents=True, exist_ok=True)

# Two real Deltas of the same example Block, drawn against the same beta: the
# first is selected by nobody, the last is selected by a Provisional domain's
# rate. One selected and one not-selected case is what exercises the strict
# inequality in both directions.
selected_delta_id = "sha256:" + sha256_hex(rfc8785.dumps(entries[3]["body"]["delta"]))
draw_bytes, D_primary = draw_D(beta, delta_id)
sel_bytes, D_selected = draw_D(beta, selected_delta_id)

selection_cases = []
for label, did, dbytes, D in (
        ("entry-0", delta_id, draw_bytes, D_primary),
        ("entry-3", selected_delta_id, sel_bytes, D_selected)):
    for rep_label, rep_u in (("provisional", 100_000), ("established", 900_000)):
        p1e7 = sampling_p_1e7(rep_u)
        selection_cases.append({
            "label": f"{label}-{rep_label}",
            "delta_id": did,
            "entry_index": 0 if label == "entry-0" else 3,
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

write_json(DC4 / "sampling.json", {
    "auditor_public_key": b64u(pub_raw),
    "ciphersuite": "ECVRF-EDWARDS25519-SHA512-TAI",
    "block_hash": block_hash,
    "alpha_hex": alpha.hex(), "vrf_proof_hex": pi.hex(), "beta_hex": beta.hex(),
    "delta_id": delta_id, "draw_first8_hex": draw_bytes.hex(), "D": D_primary,
    "test": "select <=> D x 10^7 < p_1e7 x 2^64  (integers only, DC-4 §4)",
    "note": ("D, lhs and rhs exceed 2^53; a consumer whose JSON parser uses "
             "IEEE-754 doubles MUST read D from draw_first8_hex and recompute "
             "lhs/rhs as big integers."),
    "parameters": {"floor_1e7": SAMPLING_FLOOR_1E7, "ceiling_1e7": SAMPLING_CEILING_1E7,
                   "slope_per_micro": SAMPLING_SLOPE},
    "selection": selection_cases,
})
print("dc4 sampling alpha:", alpha.hex())
print("dc4 sampling pi:", pi.hex())
print("dc4 sampling beta:", beta.hex())
print("dc4 sampling draw[:8] hex:", draw_bytes.hex(), "D:", D_primary)
for c in selection_cases:
    print("dc4 sampling %-22s D=%-20d rep_u=%-7d p_1e7=%-8d -> %s" % (
        c["label"], c["D"], c["reputation_u"], c["p_1e7"],
        "AUDIT" if c["selected"] else "no audit"))

# --------------------------------------------------------- DC-4: decay table
# DC-4 §6.1: decay(t) = floor(exp(-t/180) * 1e9) for whole days 0..1825.
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

write_json(DC4 / "decay-table.json", {
    "scale": DECAY_SCALE,
    "max_days": DECAY_MAX_DAYS,
    "note": "decay(t) = floor(exp(-t/180) * 1e9); decay(t) = 0 for t > 1825",
    "values": decay_table,
})
print("dc4 decay table: decay(0)=%d decay(30)=%d decay(1825)=%d" % (
    decay_table[0], decay_table[30], decay_table[DECAY_MAX_DAYS]))

# ------------------------------------------------------- DC-4: reputation
# DC-4 §6, in the integers the spec mandates. Nothing here is a float.
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
    assert delta >= 0, "sealed_at is strictly increasing (DC-3 §3.1)"
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
# values rather than asserted: the first Delta is the one sealed in the DC-3
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
                    "the cap is a ceiling, so the penalty is not laundered away"),
    reputation_case("gate-c-below", 800, 9, [], "aged but under-audited: the cap binds"),
    reputation_case("gate-c-at", 800, 10, [], "the same domain one audited URL later"),
    reputation_case("new-domain", 0, 0, [],
                    "a brand-new domain: base_u equals the cap exactly, so the "
                    "ungated formula already sits at 0.10 and Q = 1100"),
]

write_json(DC4 / "reputation.json", {
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
    "formula": ("reputation_u = base_u x (C+1) x 1e9 / ((C+1) x 1e9 + 5 x penalty_n), "
                "integer division; then min(., 100000) while A < 30 or C < 10"),
    "worked_example": primary,
    "boundary": boundary,
})
for case in [primary] + boundary:
    print("dc4 reputation %-24s A=%-4d C=%-3d penalty=%-12d formula=%-7d rep_u=%-7d Q=%-6d p=%s"
          % (case["label"], case["A"], case["C"], case["penalty_n"],
             case["formula_u"], case["reputation_u"], case["Q"], case["p_readable"]))
assert all(
    boundary[i]["reputation_u"] <= boundary[i + 1]["reputation_u"]
    for i in (0, 1, 3, 5)), "reputation fell when a gate lifted"
