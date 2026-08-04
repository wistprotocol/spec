#!/usr/bin/env python3
"""Generate deterministic WIST-1/WIST-3 test vectors and signed examples.

Never uses wall-clock or randomness: fixed seed, fixed timestamps.
Re-running always produces byte-identical output.
"""
import base64, calendar, hashlib, hmac, json, pathlib, time
from decimal import Decimal, localcontext

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ecvrf
import link_extraction
from merkle import audit_path, leaf_hash, node_hash

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
    # Illustrative only: a real recovery key MUST be a distinct keypair,
    # generated independently and held offline, never reused as a signing
    # key. The vector reuses the same test public key purely so the suite
    # ships one deterministic keypair; WIST-1 §5.2 normatively requires
    # recovery keys to sign nothing but Declarations.
    "recovery_keys": [
        {"key_id": "test-r1", "alg": "Ed25519", "public_key": b64u(pub_raw),
         "valid_from": "2026-08-02T12:00:00Z"}
    ],
    "contact": "mailto:webmaster@example.com",
}
write_json(EXAMPLES / "publisher.json", sign_envelope("publisher", publisher, "test-k1"))
print("wist1 publisher example written")

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
SIM_FIXTURES = []
for label, ref, obs in (
    # Whole-document containment: the committed text embedded in template
    # furniture scores full marks — the case the quotient exists for.
    ("containment-full", REF9, "home about " + REF9 + " contact " + PAD),
    # 9 words -> two 8-word shingles; the observed drops the last word, so
    # exactly one shingle survives: 500000, exercising the denominator |A|.
    ("containment-half", REF9,
     PAD + "one two three four five six seven eight ten"),
    # Below the guard: a bot-interstitial-sized page is not_auditable,
    # never similarity 0.
    ("mass-guard", REF9, "please enable javascript to view this site"),
    # Short reference (2 words): the grapheme branch, contained verbatim.
    ("short-reference-graphemes", "hello world", PAD + "hello world"),
):
    sim = link_extraction.similarity(ref, obs)
    SIM_FIXTURES.append({"label": label, "reference": ref, "observed": obs,
                         "similarity": sim,
                         "verdict_input": "not_auditable" if sim is None else sim})
assert [f["verdict_input"] for f in SIM_FIXTURES] == \
    [1_000_000, 500_000, "not_auditable", 1_000_000], "similarity fixtures drifted"

write_json(WIST2V / "text-extraction.json", {
    "note": ("WIST-2 §12's whole-document text extraction over raw HTML "
             "octets, and WIST-4 §5's reference-containment similarity over "
             "its output. html_hex decodes to the exact input; expected is "
             "the observed text a conforming Auditor produces. similarity "
             "cases carry min_observed_words = 40 (the Registry default); "
             "a null similarity is the mass guard ruling not_auditable."),
    "min_observed_words": 40,
    "extraction": TEXT_FIXTURES,
    "similarity": SIM_FIXTURES,
})
print("wist2 text-extraction vector:",
      [c["label"] for c in TEXT_FIXTURES + SIM_FIXTURES])

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


state_entries = [
    ["aggregator_key", "test-agg-k1", b64u(pub_raw), 0, None],
    ["record", "example.com", DELTA_URL, delta_id],
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
    "auditor_id": "audit.example.net",
    "fetched_at": "2026-08-02T14:00:00Z",
    "response_commitment": audit_commit(RESPONSE_BODY),
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
             "against — here examples/payload.json, the audited Delta's own "
             "Payload (WIST-4 §5). Once that Payload is withdrawn the salt is "
             "gone and none of these commitments can be checked again."),
    "audited_delta": delta_id,
    "salt_source": "examples/payload.json",
    "commitments": {
        "response_commitment": {
            "message_hex": RESPONSE_BODY.hex(),
            "value": audit_record["response_commitment"]},
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
write_json(WIST4 / "link-agreement.json", {
    "note": ("Worked link_agreement cases (WIST-4 §5): "
             "min(subset Jaccard, count agreement), integer micro-units."),
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
    "note": "decay(t) = floor(exp(-t/180) * 1e9); decay(t) = 0 for t > 1825",
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
    return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))


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
                    "the cap is a ceiling, so the penalty is not laundered away"),
    reputation_case("gate-c-below", 800, 9, [], "aged but under-audited: the cap binds"),
    reputation_case("gate-c-at", 800, 10, [], "the same domain one audited URL later"),
    reputation_case("new-domain", 0, 0, [],
                    "a brand-new domain: base_u equals the cap exactly, so the "
                    "ungated formula already sits at 0.10 and Q = 1100"),
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
    "formula": ("reputation_u = base_u x (C+1) x 1e9 / ((C+1) x 1e9 + 5 x penalty_n), "
                "integer division; then min(., 100000) while A < 30 or C < 10"),
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
