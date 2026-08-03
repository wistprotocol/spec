#!/usr/bin/env python3
"""Validate examples/ against schemas/ and verify vectors/. Exit 0 = green."""
import base64, calendar, collections, hashlib, hmac, json, pathlib, re, sys, time

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

import ecvrf
from merkle import audit_path, leaf_hash, merkle_root, node_hash

ROOT = pathlib.Path(__file__).resolve().parents[1]
failures = []

PASSED = set()

# A digest-shaped field, identified by the JSON path it was reached by:
# a property name alone is not an identity (two properties in one file may
# share one), and every exemption and coverage declaration is keyed by path.
_Finding = collections.namedtuple('_Finding', 'schema key pattern path')

def check(label, fn):
    try:
        fn()
        PASSED.add(label)
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
    "snapshot-index.json": "index",
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

def _url_bound():
    """DC-1 §3.2: the subject URL is octet-bounded (url_cap_bytes)."""
    schema = json.loads((ROOT / "schemas" / "delta.schema.json").read_text())
    url_schema = schema["properties"]["delta"]["properties"]["url"]
    assert url_schema.get("maxLength") == 2048, \
        "delta.url carries no maxLength 2048 first-pass bound"
    env = json.loads((ROOT / "examples" / "delta.json").read_text())
    url = env["delta"]["url"]
    assert len(rfc8785.dumps(url)) <= 2048, "example url exceeds url_cap_bytes octets"
    assert len(rfc8785.dumps("https://a.b/")) == 14, "published floor (14) drifted"

check("spec:url-octet-bound", _url_bound)

def _url_bound_twin():
    """Mutation twin: an over-long URL must fail schema validation."""
    schema = json.loads((ROOT / "schemas" / "delta.schema.json").read_text())
    env = json.loads((ROOT / "examples" / "delta.json").read_text())
    env["delta"]["url"] = "https://example.com/" + "a" * 2100
    try:
        Draft202012Validator(schema).validate(env)
    except Exception:
        return
    raise AssertionError("a 2100-char url validated — the bound does not discriminate")

check("negative:url-octet-bound", _url_bound_twin)

def _registry_table_defaults():
    """DC-4 §9's Default column, keyed by identifier, as leading integers."""
    spec = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    section9 = spec.split("## 9. Parameter Registry")[1].split("### 9.1.")[0]
    out = {}
    for line in section9.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 4 or cells[1] == "Identifier":
            continue
        names = re.findall(r"`([a-z0-9_]+)`", cells[1])
        m = re.match(r"([\d ]+)", cells[2])
        if len(names) == 1 and m:
            out[names[0]] = int(m.group(1).replace(" ", ""))
    return out

def _assert_links_valid(payload):
    """DC-1 §3.6 / DC-3 §6.1: structural link rules a validator enforces at ingest.

    Caps are read from the DC-4 §9 registry table (the same source
    `_payload_length` derives from), not hard-coded, so the two checks cannot
    disagree after a `parameter_change` amends either one.

    What is deliberately NOT checked here: whether the declared `urls` prefix
    is the correct one for the page, and whether an omitted remainder would
    have fit `links_cap_bytes`. Both are checkable only against the live page
    (DC-4 §5's link dimension), never from the Payload alone — an ingest
    validator sees only the already-truncated object.
    """
    caps = _registry_table_defaults()
    links = payload["content"]["links"]
    urls, total = links["urls"], links["total"]
    assert len(urls) <= total, "more urls than the declared total"
    assert len(set(urls)) == len(urls), "duplicate link"
    for u in urls:
        assert u.startswith("https://") and "#" not in u, f"non-https or fragment: {u}"
        assert len(rfc8785.dumps(u)) <= caps["link_url_cap_bytes"], \
            f"link exceeds link_url_cap_bytes: {u}"
        host = u.split("/", 3)[2].split(":")[0]
        assert host != "example.com" and not host.endswith(".example.com"), \
            f"internal link declared external: {u}"
    links_octets = len(rfc8785.dumps(links))
    assert links_octets <= caps["links_cap_bytes"], "JCS(links) exceeds links_cap_bytes"

def _payload_links_rules():
    """DC-1 §3.6 / DC-3 §6.1: structural link rules a validator enforces at ingest."""
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    _assert_links_valid(payload)
    # The shipped example is known, by construction, to declare its full set
    # of external links (nothing was truncated) — an editorial fact about
    # this one Payload, not a general ingest rule, so it is asserted here
    # rather than inside the shared helper.
    links = payload["content"]["links"]
    assert len(links["urls"]) == links["total"], \
        "the shipped example's link set is not fully declared (urls != total)"
    content_octets = len(rfc8785.dumps(payload["content"]))
    assert content_octets <= 38944, "JCS(content) exceeds the derived cap"
    delta = json.loads((ROOT / "examples" / "delta.json").read_text())
    assert delta["delta"]["payload"]["bytes"] == content_octets, \
        "declared bytes != JCS(content) octets"
    schema = json.loads((ROOT / "schemas" / "delta.schema.json").read_text())
    assert schema["properties"]["delta"]["properties"]["payload"]["properties"]["bytes"][
        "maximum"] == 38944, "schema bytes maximum is not the derived cap"

check("spec:payload-links-rules", _payload_links_rules)

def _payload_links_twin():
    """Mutation twins: each rule must reject its own target, not merely any rule.

    Every mutation that appends a URL also bumps `total` by one, so the count
    gate (`len(urls) <= total`) still passes and the mutation actually reaches
    the rule it is meant to exercise, rather than being rejected for the wrong
    reason.
    """
    base = json.loads((ROOT / "examples" / "payload.json").read_text())
    def rejected(mutate, expected_substring):
        p = json.loads(json.dumps(base))
        mutate(p)
        try:
            _assert_links_valid(p)          # helper factored from the check above
        except AssertionError as e:
            assert expected_substring in str(e), \
                f"rejected, but not by its target rule: {e}"
            return True
        return False

    def add(p, url):
        p["content"]["links"]["urls"].append(url)
        p["content"]["links"]["total"] += 1

    assert rejected(lambda p: add(p, p["content"]["links"]["urls"][0]),
                     "duplicate link"), "duplicate link passed"
    assert rejected(lambda p: add(p, "https://www.example.com/internal"),
                     "internal link declared external"), "internal link passed"
    assert rejected(lambda p: add(p, "https://spec.example.net/dc-1#frag"),
                     "non-https or fragment"), "fragment link passed"
    assert rejected(lambda p: add(p, "https://x.example.io/" + "a" * 2100),
                     "link exceeds link_url_cap_bytes"), "oversize link passed"
    assert rejected(lambda p: p["content"]["links"].update(total=0),
                     "more urls than the declared total"), "urls > total passed"

check("negative:payload-links-rules", _payload_links_twin)

# Hand-written, independent of tools/link_extraction.py: the vector file is
# generated AND checked by that same module (Step 1's vector reproduction
# below is therefore a round-trip), so this literal is what actually pins
# fixture 1 — a Publisher's own page — to three URLs rather than trusting
# the generator not to have drifted alongside its own check.
_FIXTURE1_EXPECTED = {
    "total": 3,
    "urls": ["https://example.org/reference", "https://spec.example.net/dc-1",
             "https://example.org/~user"],
}

def _link_extraction_vector():
    """DC-2's extraction procedure: the vector's (urls, total) must be
    reproduced from the fixture HTML bytes by the reference implementation."""
    import link_extraction
    vec = json.loads((ROOT / "vectors" / "dc2" / "link-extraction.json").read_text())
    assert vec["links_cap_bytes"] == _registry_table_defaults()["links_cap_bytes"], \
        "the vector's links_cap_bytes has drifted from the Parameter Registry default"
    fixture1 = next(c for c in vec["cases"] if c["label"] == "example-delta-page")
    assert fixture1["expected"] == _FIXTURE1_EXPECTED, \
        "fixture 1's expected member is not the hand-pinned 3-URL set"
    for case in vec["cases"]:
        html = bytes.fromhex(case["html_hex"])
        urls, total = link_extraction.extract_links(
            html, case["base_url"], case["publisher_domain"])
        member = link_extraction.links_member(urls, total, vec["links_cap_bytes"])
        assert member == case["expected"], f"{case['label']}: {member} != {case['expected']}"

check("vectors:dc2-link-extraction", _link_extraction_vector)

def _link_extraction_twin():
    """Mutation twin: a perturbed fixture must not reproduce."""
    import link_extraction
    vec = json.loads((ROOT / "vectors" / "dc2" / "link-extraction.json").read_text())
    case = vec["cases"][0]
    html = bytes.fromhex(case["html_hex"]) + b'<a href="https://mutant.example.io/x">m</a>'
    urls, total = link_extraction.extract_links(
        html, case["base_url"], case["publisher_domain"])
    member = link_extraction.links_member(urls, total, vec["links_cap_bytes"])
    assert member != case["expected"], "an appended link changed nothing — extraction is blind"

check("negative:dc2-link-extraction", _link_extraction_twin)

_BASE = "https://example.com/blog/post-1"

# Independent of the generator: a hand-written table run through
# link_extraction.normalize_url and .extract_links directly, so a bug that
# both derives a vector fixture AND checks it the same wrong way (the
# round-trip `vectors:dc2-link-extraction` above cannot catch that class)
# still gets caught here.
_NORMALIZE_ORACLE = [
    # (label, candidate, base, expected)
    ("absolute dot-segment keeps trailing slash",
     "https://example.com/blog/a/b/..", _BASE, "https://example.com/blog/a/"),
    ("relative dot-segment keeps trailing slash",
     "a/b/..", _BASE, "https://example.com/blog/a/"),
    ("out-of-range port rejected", "https://example.com:99999/x", _BASE, None),
    ("non-numeric port rejected", "https://example.com:abc/x", _BASE, None),
    ("%7e decodes to ~", "https://example.org/%7euser", _BASE, "https://example.org/~user"),
    ("%2f stays encoded, hex uppercased",
     "https://example.com/a%2fb", _BASE, "https://example.com/a%2Fb"),
    ("userinfo rejected", "https://user@example.com/x", _BASE, None),
    ("IPv6 literal host rejected", "https://[::1]/x", _BASE, None),
    ("space in host rejected", "https://exa mple.com/x", _BASE, None),
    ("fragment removed", "https://example.com/x#frag", _BASE, "https://example.com/x"),
    ("default port 443 removed", "https://example.com:443/x", _BASE, "https://example.com/x"),
    ("empty path becomes /", "https://example.com", _BASE, "https://example.com/"),
    ("raw tab in candidate rejected", "https://example.com/\tx", _BASE, None),
]

# (label, tiny literal HTML, expected extracted urls) — exercises the DC-2
# §11 scan itself (comments, raw-text elements, quote-aware attributes,
# data-href vs href, character references), independent of gen_vectors.py's
# fixture 3.
_SCAN_ORACLE = [
    ("data-href is not href",
     b'<a data-href="https://example.org/x">t</a>', []),
    ("comment-wrapped link not extracted",
     b'<!-- <a href="https://example.org/x">t</a> -->', []),
    ("a bare > inside a quoted value does not end the tag",
     b'<a title="a>b" href="https://example.org/x">t</a>', ["https://example.org/x"]),
    ("&amp; decoded in the query",
     b'<a href="https://example.org/x?y=1&amp;z=2">t</a>', ["https://example.org/x?y=1&z=2"]),
    # Regression pins: an out-of-range or surrogate numeric character
    # reference must discard just this candidate — never raise (the old
    # `chr()` call raised ValueError past 0x10FFFF) and never emit a
    # string `rfc8785.dumps` cannot encode (a lone surrogate).
    ("out-of-range numeric reference discards the candidate, not the run",
     b'<a href="https://example.org/x?y=&#99999999999;">t</a>', []),
    ("surrogate numeric reference discards the candidate, not the run",
     b'<a href="https://example.org/x?y=&#xD800;">t</a>', []),
    # A digit run this long (one more than CPython 3.11+'s own 4300-digit
    # int() string-conversion cap) must discard the candidate via the
    # length bound alone, never via int() raising: 4301 digits cannot
    # denote a code point <= 0x10FFFF (7 decimal digits) either way.
    ("over-long decimal reference discards the candidate",
     b'<a href="https://example.org/x?y=&#' + b"9" * 4301 + b';">t</a>', []),
]

def _link_normalization_oracle(normalize_table=_NORMALIZE_ORACLE, scan_table=_SCAN_ORACLE):
    """Independent oracle: hand-written (candidate, expected) pairs, run
    through link_extraction directly rather than through the vector file
    that same module both generates and checks.

    Factored to accept a supplied table so the twin below can run this
    exact comparison over a deliberately perturbed one and prove it is
    live, in the style of `_assert_links_valid`/`negative:payload-links-rules`.
    """
    import link_extraction
    for label, candidate, base, expected in normalize_table:
        got = link_extraction.normalize_url(candidate, base)
        assert got == expected, \
            f"{label}: normalize_url({candidate!r}) = {got!r}, expected {expected!r}"
    for label, html, expected_urls in scan_table:
        urls, total = link_extraction.extract_links(html, _BASE, "example.com")
        assert urls == expected_urls, \
            f"{label}: extract_links = {urls!r}, expected {expected_urls!r}"
        assert total == len(expected_urls), \
            f"{label}: total = {total}, expected {len(expected_urls)}"

check("spec:link-normalization-oracle", _link_normalization_oracle)

def _link_normalization_oracle_twin():
    """Mutation twin: running the oracle over a table with one entry's
    expectation flipped to a wrong literal MUST raise — proving the
    comparison is live rather than vacuously true."""
    perturbed = list(_NORMALIZE_ORACLE)
    label, candidate, base, _expected = perturbed[0]
    perturbed[0] = (label, candidate, base, "https://not-the-right-answer.example/")
    try:
        _link_normalization_oracle(normalize_table=perturbed)
    except AssertionError:
        return
    raise AssertionError(f"{label}: a wrong expected value passed the oracle unnoticed")

check("negative:link-normalization-oracle", _link_normalization_oracle_twin)

DIGEST_NAME = re.compile(r"hash|digest|sha\d|checksum|commitment", re.IGNORECASE)

# Digest lengths in hex: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.
HEX_DIGEST_LENGTHS = (32, 40, 56, 64, 96, 128)
# The same digests base64url-encoded, plus the 16-octet floor a salt sits at.
B64_DIGEST_LENGTHS = (22, 27, 38, 43, 64, 86)

# A pattern is digest-shaped if it accepts a digest. Probing the pattern beats
# pattern-matching the pattern: `^[0-9a-f]{64}$`, `^[0-9A-F]{64}$` and
# `^[a-f0-9]{64}$` are the same constraint written three ways, and a regex over
# the regex catches whichever spelling it was written to catch.
DIGEST_PROBES = [p + c * n
                 for n in HEX_DIGEST_LENGTHS
                 for c in "0a"
                 for p in ("", "sha256:", "sha512:", "warc:sha256:", "hmac-sha256:")]

VALUE_DIGEST = re.compile(
    r"(?:[a-z0-9-]{1,16}:){0,2}(?:"
    + "|".join(f"[0-9a-fA-F]{{{n}}}" for n in HEX_DIGEST_LENGTHS)
    + "|" + "|".join(f"[A-Za-z0-9_-]{{{n}}}" for n in B64_DIGEST_LENGTHS)
    + ")")

def _is_digest_shaped(pattern: str) -> bool:
    if not pattern:
        return False
    try:
        rx = re.compile(pattern)
    except re.error:
        return True          # an unparseable pattern constrains nothing usable
    return any(rx.search(probe) for probe in DIGEST_PROBES)

def _resolve(node, root, seen):
    """Follow a local `$ref` so that `$defs` cannot hide a field from the walk."""
    ref = node.get("$ref") if isinstance(node, dict) else None
    if not isinstance(ref, str) or not ref.startswith("#") or ref in seen:
        return node
    seen = seen | {ref}
    target = root
    for token in ref.lstrip("#/").split("/"):
        if not token:
            continue
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(target, list):
            target = target[int(token)]
        else:
            target = target.get(token, {})
    return target if isinstance(target, dict) else node

def _walk_schema(node, schema_name, findings, key=None, root=None,
                 seen=frozenset(), path=""):
    """Collect every digest-shaped leaf, by property name and by pattern shape.

    Two detectors, because either alone is escapable: a field named
    `withdrawn_content` with pattern `^[0-9a-f]{64}$` carries no telltale name,
    and a field named `extract_hash` with no pattern at all carries no telltale
    pattern. Every applicator JSON Schema offers is followed, including the ones
    that hide a subschema behind indirection (`$ref`/`$defs`), behind a key
    regex (`patternProperties`), or behind a tuple position (`prefixItems`) —
    a field is no less declared for being reached that way.

    Every finding carries the JSON path it was reached by, not only its property
    name. A name is not an identity: two properties in one file may share one,
    and an exemption or a coverage declaration granted to a name would then
    extend to every other occurrence of it for free.

    What neither detector reaches is a field with an innocuous name and no
    pattern at all: an unconstrained string can hold a digest whatever it is
    called. The example and vector scan below covers that for what the suite
    ships, and DC-4 §9.1 covers it normatively for what an implementation adds.
    """
    if root is None:
        root = node
    if not isinstance(node, dict):
        return findings
    node = _resolve(node, root, seen)
    if not isinstance(node, dict):
        return findings
    if node.get("$ref"):
        seen = seen | {node["$ref"]}
    pattern = node.get("pattern", "")
    if key is not None and (DIGEST_NAME.search(key) or _is_digest_shaped(pattern)):
        findings.append(_Finding(schema_name, key, pattern, path))

    def step(sub, sub_key, seg):
        _walk_schema(sub, schema_name, findings, sub_key, root, seen,
                     f"{path}/{seg}" if path else seg)

    for kw in ("properties", "patternProperties", "$defs", "dependentSchemas"):
        # `patternProperties` keys are regexes rather than names; carrying one
        # as the key keeps a `.*_hash` property regex a name match.
        for name, sub in node.get(kw, {}).items():
            step(sub, name, f"{kw}/{name}")
    for kw in ("prefixItems", "items", "allOf", "anyOf", "oneOf"):
        if isinstance(node.get(kw), list):
            for i, sub in enumerate(node[kw]):
                if isinstance(sub, dict):
                    step(sub, key if key is not None else f"<{kw}>", f"{kw}[{i}]")
    for kw in ("items", "then", "else", "not", "contains", "if",
               "additionalProperties", "propertyNames", "unevaluatedProperties",
               "unevaluatedItems"):
        if isinstance(node.get(kw), dict):
            # An applicator at the root of a schema governs fields that have no
            # property name of their own, so the walk must carry a name for it
            # rather than skip a nameless subschema.
            step(node[kw], key if key is not None else f"<{kw}>", kw)
    return findings

def _schema_findings(schema_file):
    return _walk_schema(
        json.loads((ROOT / "schemas" / schema_file).read_text()), schema_file, [])

def _locate_schema_fields(check_name):
    """Every occurrence, by path, of a property name this check is declared for.

    The mirror of `_locate_values`: the occurrences are discovered by walking
    the schema, not read off the declarations, so a second property sharing a
    covered name is found and must be declared in its own right.
    """
    names_by_file = {}
    for (schema_file, path), c in SALTED_COMMITMENTS.items():
        if c == check_name:
            names_by_file.setdefault(schema_file, set()).add(path.rsplit("/", 1)[-1])
    found = set()
    for schema_file, names in names_by_file.items():
        for f in _schema_findings(schema_file):
            if f.key in names:
                found.add((schema_file, f.path))
    return found

def _schema_node_at(schema_file, path):
    """Resolve the subschema a finding path names, following local $refs."""
    root = json.loads((ROOT / "schemas" / schema_file).read_text())
    node = root
    for seg in path.split("/"):
        node = _resolve(node, root, frozenset())
        m = re.fullmatch(r"([A-Za-z$]+)\[(\d+)\]", seg)
        if m:
            node = node[m.group(1)][int(m.group(2))]
        elif seg in node:
            node = node[seg]
        else:
            raise AssertionError(f"{schema_file}: no subschema at {path!r} (stuck at {seg!r})")
    return _resolve(node, root, frozenset())

# ---------------------------------------------------------------- declarations
# Fields and values that ARE content-derived and are salted commitments. Wearing
# the `hmac-sha256:` label earns nothing here, and neither does naming a check
# that happens to pass: each entry names the check that RECOMPUTES this exact
# (file, key) from the Payload salt, and that check asserts — in both
# directions — that the set it recomputed is exactly the set declaring its name.
# A declaration pointing at a check that never reads it is an orphan and fails.
#
# Only a check listed in COVERAGE_ASSERTED may be named, because only those
# make that assertion. Paths are ROOT-relative: `examples/block.json` and
# `vectors/dc3/block.json` are different locations and are declared separately.
COVERAGE_ASSERTED = {"payload:commitment", "audit:commitments"}

SALTED_COMMITMENTS = {          # (schema file, JSON path) -> proving check
    ("delta.schema.json",
     "properties/delta/properties/payload/properties/commitment"): "payload:commitment",
    ("audit-record.schema.json",
     "properties/record/properties/response_commitment"): "audit:commitments",
    ("audit-record.schema.json",
     "properties/record/properties/ref_extract_commitment"): "audit:commitments",
    ("audit-record.schema.json",
     "properties/record/properties/evidence_commitment"): "audit:commitments",
}

SALTED_COMMITMENT_VALUES = {    # (ROOT-relative file, key) -> proving check
    ("examples/delta.json", "commitment"): "payload:commitment",
    ("examples/block.json", "commitment"): "payload:commitment",
    ("vectors/dc1/envelope.json", "commitment"): "payload:commitment",
    ("vectors/dc1/delta.canonical", "commitment"): "payload:commitment",
    ("vectors/dc3/block.json", "commitment"): "payload:commitment",
    ("examples/audit-record.json", "response_commitment"): "audit:commitments",
    ("examples/audit-record.json", "ref_extract_commitment"): "audit:commitments",
    ("examples/audit-record.json", "evidence_commitment"): "audit:commitments",
    ("vectors/dc4/audit-commitments.json", "value"): "audit:commitments",
}

def _declared_values_for(check_name):
    return {p for p, c in SALTED_COMMITMENT_VALUES.items() if c == check_name}

def _declared_schema_for(check_name):
    return {p for p, c in SALTED_COMMITMENTS.items() if c == check_name}

def _values_at(rel_path, key):
    """Every string carried at `key` anywhere in the shipped file at `rel_path`."""
    path = ROOT / rel_path
    if not path.exists():
        return None
    raw = path.read_text()
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return [raw.strip()]
    found = []
    def walk(node, k):
        if isinstance(node, dict):
            for kk, vv in node.items():
                walk(vv, kk)
        elif isinstance(node, list):
            for vv in node:
                walk(vv, k)
        elif isinstance(node, str) and k == key:
            found.append(node)
    walk(doc, None)
    return found

def _shipped_files():
    return (sorted((ROOT / "examples").rglob("*.json"))
            + sorted(p for p in (ROOT / "vectors").rglob("*") if p.is_file()))

def _locate_values(predicate):
    """Every (ROOT-relative file, key) in the shipped tree holding such a value.

    Discovering the locations rather than reading them off the declarations is
    what makes the coverage assertion bidirectional: a copy of a commitment
    sitting at a location nothing declares is then a failure, not an invisible.
    """
    found = set()
    for path in _shipped_files():
        rel = str(path.relative_to(ROOT))
        raw = path.read_text()
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            doc = raw.strip()
        def walk(node, k):
            if isinstance(node, dict):
                for kk, vv in node.items():
                    walk(vv, kk)
            elif isinstance(node, list):
                for vv in node:
                    walk(vv, k)
            elif isinstance(node, str) and predicate(node):
                found.add((rel, k))
        walk(doc, None)
    return found

def _instance_suffix(schema_path, n=2):
    """The trailing property names of a schema path, as an instance-path suffix.

    `properties/delta/properties/payload/properties/commitment` names instances
    reachable at `…/payload/commitment`. Two segments is enough to separate the
    occurrences that matter — `payload/commitment` from `meta/commitment` — while
    staying insensitive to how deeply an envelope nests the object.
    """
    parts = schema_path.split("/")
    names = [parts[i + 1] for i, seg in enumerate(parts)
             if seg == "properties" and i + 1 < len(parts)]
    return names[-n:]

def _instance_values_at(suffix):
    """Every shipped string value reached at an instance path ending in `suffix`."""
    out = set()
    for path in _shipped_files():
        try:
            doc = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        def walk(node, trail):
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(v, trail + [k])
            elif isinstance(node, list):
                for v in node:
                    walk(v, trail)
            elif isinstance(node, str) and trail[-len(suffix):] == suffix:
                out.add(node)
        walk(doc, [])
    return out

def _assert_schema_instances(check_name, recomputed):
    """A declared schema location must have shipped instances, all recomputed.

    Checking that the field's pattern *admits* the recomputed value proves
    nothing — every `^hmac-sha256:` pattern admits it, so any new field patterned
    that way, or any declaration moved between covering checks, would pass. The
    binding requirement is that the values actually shipped at that location are
    ones this check recomputed.
    """
    for schema_file, spath in _declared_schema_for(check_name):
        field = _schema_node_at(schema_file, spath)
        suffix = _instance_suffix(spath)
        assert suffix, f"{schema_file}: {spath} names no property"
        values = _instance_values_at(suffix)
        assert values, (
            f"{schema_file}: {spath} is declared covered by {check_name}, but no "
            f"shipped file carries an instance at .../{'/'.join(suffix)} for it to "
            "have recomputed")
        for got in values:
            assert got in recomputed, (
                f"{schema_file}: {spath} is declared covered by {check_name}, but the "
                f"instance at .../{'/'.join(suffix)} is {got[:28]}…, which "
                f"{check_name} did not recompute")
            assert re.fullmatch(field.get("pattern", ""), got), \
                f"{schema_file}: {spath} does not admit its own shipped instance"

def _assert_coverage(check_name, covered_values, covered_schema):
    """Each proving check proves it covered exactly what declares its name.

    Asserting only that a named check passed would let any declaration launder
    itself by pointing at the name of some unrelated passing check. The proof
    therefore runs the other way: the check reports what it recomputed, and the
    two sets must match exactly — an orphan declaration and an undeclared
    recomputation are both failures.
    """
    for label, covered, declared in (
            ("value", covered_values, _declared_values_for(check_name)),
            ("schema", covered_schema, _declared_schema_for(check_name))):
        orphans = sorted(declared - covered)
        assert not orphans, (
            f"{check_name} does not recompute {label} declaration(s) that name it: "
            f"{orphans} — a declaration may not name a check that never reads it")
        undeclared = sorted(covered - declared)
        assert not undeclared, (
            f"{check_name} recomputes undeclared {label} location(s): {undeclared}")

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
    expected = _commit(payload["salt"], payload["content"])
    assert expected == delta["payload"]["commitment"], \
        "the Payload does not reproduce the Delta's commitment"

    # Every shipped copy of this commitment is recomputed here, not argued for
    # transitively, so that each declaration naming this check is one this check
    # actually verified.
    covered_values = set()
    for rel, key in _declared_values_for("payload:commitment"):
        values = _values_at(rel, key)
        assert values, f"{rel}: no {key!r} to recompute, but it is declared here"
        for got in values:
            assert got == expected, \
                f"{rel}: {key} = {got[:28]}… is not HMAC(salt, JCS(content))"
    # Located, not read off the declarations, so an undeclared copy also fails.
    covered_values = _locate_values(lambda v: v == expected)

    _assert_schema_instances("payload:commitment", {expected})
    covered_schema = _locate_schema_fields("payload:commitment")

    _assert_coverage("payload:commitment", covered_values, covered_schema)
check("payload:commitment", _payload_commitment)

def _payload_length():
    """`bytes`, and every cap it is bounded by, counted in JCS octets.

    DC-1 §3.6 measures every cap as octets of a JCS serialization, never
    as characters and never as code points, because a Consumer uses them to
    bound a fetch. The combined bound is derived rather than independent:
    JCS(content) is `{"extract":<E>,"links":<L>,"summary":<S>}`, so its 32
    octets of structure sit on top of the three field caps. Deriving it here
    rather than hard-coding the total is what keeps the schema's number and
    DC-1 §3.6's arithmetic from drifting apart again.
    """
    payload, delta = _load_payload_and_delta()
    content = payload["content"]
    n = len(rfc8785.dumps(content))
    assert delta["payload"]["bytes"] == n, \
        f"the Delta declares {delta['payload']['bytes']} octets, JCS(content) is {n}"

    caps = _registry_table_defaults()
    e_cap = caps["extract_cap_bytes"]
    lk_cap = caps["links_cap_bytes"]
    s_cap = caps["summary_cap_bytes"]
    wrapper = len(rfc8785.dumps({"extract": "", "links": {}, "summary": {}})) - \
        len(rfc8785.dumps("")) - 2 * len(rfc8785.dumps({}))
    assert wrapper == 32, f"JCS(content) structure is {wrapper} octets, not the 32 DC-1 §3.6 states"
    combined = e_cap + lk_cap + s_cap + wrapper

    e = len(rfc8785.dumps(content["extract"]))
    lk = len(rfc8785.dumps(content["links"]))
    s = len(rfc8785.dumps(content["summary"]))
    assert e <= e_cap, f"JCS(extract) is {e} octets, over the {e_cap}-octet cap (DC-1 §3.6)"
    assert lk <= lk_cap, f"JCS(links) is {lk} octets, over the {lk_cap}-octet cap (DC-1 §3.6)"
    assert s <= s_cap, f"JCS(summary) is {s} octets, over the {s_cap}-octet cap (DC-1 §3.6)"
    assert n <= combined, f"JCS(content) is {n} octets, over the {combined}-octet cap (DC-1 §3.6)"
    assert e + lk + s + wrapper == n, "the JCS lengths do not add up; the derivation is wrong"

    schema = json.loads((ROOT / "schemas" / "delta.schema.json").read_text())
    declared = schema["properties"]["delta"]["properties"]["payload"][
        "properties"]["bytes"]["maximum"]
    assert declared == combined, (
        f"delta.schema.json bounds payload.bytes at {declared}, but "
        f"{e_cap} + {lk_cap} + {s_cap} + {wrapper} = {combined} (DC-1 §3.6)")
    spec = (ROOT / "specs" / "DC-1-delta-format.md").read_text()
    assert str(combined) in spec, f"DC-1 §3.6 does not state the {combined}-octet bound"
    assert "34816" not in spec, "DC-1 still cites the old combined cap, which omitted the JCS wrapper"
    assert "34839" not in spec, "DC-1 still cites the pre-links combined cap"
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

RECORD_FIELDS = ["url", "publisher", "delta_id", "observed_at", "weight"]

def _content_digest(records):
    """DC-3 §7: SHA-256 over the ascending-octet-order concatenation of JCS."""
    return "sha256:" + hashlib.sha256(
        b"".join(sorted(rfc8785.dumps(r) for r in records))).hexdigest()

def _snapshot_content_digest():
    """DC-3 §7's semantic-equivalence digest, recomputed from its own records.

    The point of the digest is that two parties rebuilding the same Log prefix
    agree without producing byte-identical SQLite or Parquet, so the check has
    to hold two properties at once: the digest is a function of the record set
    alone (order-independent, storage-independent), and its preimage contains
    no page content — otherwise a Payload withdrawn after publication would
    make the digest permanently unrecomputable, which is when it matters most.
    """
    v = json.loads((ROOT / "vectors" / "dc3" / "snapshot-records.json").read_text())
    records = v["records"]
    assert v["record_fields"] == RECORD_FIELDS, \
        "the vector's record encoding is not §7's tuple"
    for r in records:
        assert sorted(r) == sorted(RECORD_FIELDS), \
            f"a record carries {sorted(r)}, not §7's tuple"
    digest = _content_digest(records)
    assert digest == v["content_digest"], "the vector's content_digest is not its own records'"

    # Order-independence: the sort is what makes two builders agree, so a digest
    # that moved with insertion order would verify nothing about a rebuild.
    assert _content_digest(list(reversed(records))) == digest, \
        "the digest depends on the order records were fed in"

    manifest = json.loads(
        (ROOT / "examples" / "snapshot-manifest.json").read_text())["manifest"]
    index = json.loads(
        (ROOT / "examples" / "snapshot-index.json").read_text())["index"]
    assert manifest["content_digest"] == digest, \
        "the example manifest does not declare the digest of the published records"

    # The index and the manifest are two independently signed statements about
    # one Snapshot; DC-3 §8 has a Consumer check them against each other.
    assert len(index["snapshots"]) >= 1, "the example index lists no Snapshot"
    entry = index["snapshots"][0]
    for field in ("snapshot_date", "log_position", "content_digest"):
        assert entry[field] == manifest[field], \
            f"the index entry's {field} disagrees with the manifest it names"
    assert entry["manifest_url"] == "/snapshots/%s/manifest.json" % entry["snapshot_date"], \
        "the index entry does not name the §6 layout path for its snapshot_date"
    dates = [s["snapshot_date"] for s in index["snapshots"]]
    assert dates == sorted(dates, reverse=True), "the index is not newest first"

    # `anchor_block_hash` binds the Snapshot to one chain (§7, §8).
    block = json.loads((ROOT / "examples" / "block.json").read_text())
    assert manifest["log_position"] == block["header"]["block_number"], \
        "the example manifest is not positioned at the example Block"
    assert manifest["anchor_block_hash"] == "sha256:" + hashlib.sha256(
        rfc8785.dumps(block["header"])).hexdigest(), \
        "anchor_block_hash is not the Block Hash of Block log_position"

    # No page content in the preimage. Withdrawal destroys the Payload and its
    # salt (§6.2); a digest that needed either could never be recomputed after
    # one, so this asserts the preimage against the actual Payload text rather
    # than against the field names alone.
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    forbidden = [payload["content"]["extract"],
                 payload["content"]["summary"]["title"],
                 payload["content"]["summary"]["abstract"],
                 payload["salt"]]
    preimage = b"".join(sorted(rfc8785.dumps(r) for r in records)).decode()
    for text in forbidden:
        assert text not in preimage, \
            f"content reached the content_digest preimage: {text[:32]!r}"

    # Every field of the tuple must move the digest, or a rebuild could diverge
    # on it undetected. `weight` is the DC-4 §7 level-2 mark and `observed_at`
    # is what an `attest` moves; both are exactly the cases a record-identity-
    # only digest would miss.
    import copy
    for field, other in (("url", "https://example.com/blog/post-9"),
                         ("publisher", "other.example.com"),
                         ("delta_id", "sha256:" + "0" * 64),
                         ("observed_at", "2026-08-02T12:00:01Z"),
                         ("weight", "reduced")):
        mutated = copy.deepcopy(records)
        assert mutated[0][field] != other, f"{field}: the mutation changes nothing"
        mutated[0][field] = other
        assert _content_digest(mutated) != digest, \
            f"the digest does not depend on {field}"
    assert _content_digest(records[:1]) != digest, \
        "dropping a record leaves the digest unchanged"
    assert _content_digest([]) == "sha256:" + hashlib.sha256(b"").hexdigest(), \
        "an empty live set does not digest the empty octet string (§7)"

    # Both `weight` values are exercised, so the level-2 mark is a case the
    # vector actually covers rather than one the format merely admits.
    assert {r["weight"] for r in records} == {"full", "reduced"}, \
        "the vector does not exercise both weight values"

    spec = (ROOT / "specs" / "DC-3-commons-log-distribution.md").read_text()
    assert "semantic equivalence" in spec, "DC-3 §7 no longer states the rebuild rule"
    for field in RECORD_FIELDS:
        assert f'"{field}": r.{field}' in spec, \
            f"DC-3 §7's record tuple no longer names {field}"
    for stale in ("bit-identical", "byte-identical tiers"):
        assert stale not in spec, f"DC-3 still claims byte-reproducible Snapshots: {stale!r}"
check("snapshot:content-digest", _snapshot_content_digest)

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

    # Coverage, proved in this direction rather than assumed: every location
    # declaring this check must be one whose value was just recomputed above.
    recomputed = {e["value"] for e in v["commitments"].values()}
    covered_values = set()
    for rel, key in _declared_values_for("audit:commitments"):
        values = _values_at(rel, key)
        assert values, f"{rel}: no {key!r} to recompute, but it is declared here"
        for got in values:
            assert got in recomputed, \
                f"{rel}: {key} = {got[:28]}… is not one of the recomputed commitments"
    covered_values = _locate_values(lambda v: v in recomputed)

    _assert_schema_instances("audit:commitments", recomputed)
    covered_schema = _locate_schema_fields("audit:commitments")

    _assert_coverage("audit:commitments", covered_values, covered_schema)
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
    ("delta.schema.json", "properties/delta/properties/prev"):
        "a Delta ID: SHA-256 of Canonical Bytes, which carry the salted commitment and no content",
    ("publisher.schema.json", "properties/publisher/properties/prev_declaration"):
        "SHA-256 of a Declaration, which carries keys and no content",
    ("feed.schema.json", "properties/feed/properties/deltas/items"):
        "Delta IDs",
    ("block.schema.json", "properties/header/properties/prev_block_hash"):
        "SHA-256 of a Block header",
    ("block.schema.json", "properties/header/properties/merkle_root"):
        "root over Entries, which carry commitments and no content",
    ("checkpoint.schema.json", "properties/checkpoint/properties/block_hash"):
        "SHA-256 of a Block header",
    ("audit-record.schema.json", "properties/record/properties/audited_delta"):
        "a Delta ID",
    ("registry-update.schema.json",
     "allOf[2]/then/properties/update/properties/evidence/items"):
        "Audit Record IDs: SHA-256 over Records that themselves carry only commitments",
    ("registry-update.schema.json",
     "allOf[6]/then/properties/update/properties/details/properties/delta_id"):
        "a Delta ID",
    ("registry-update.schema.json",
     "allOf[4]/then/properties/update/properties/details/properties/notice"):
        "a Registry Update ID: SHA-256 over a `notice`'s inner object, which carries a kind, a reason, a deadline and Audit Record IDs — no page content",
    ("registry-update.schema.json",
     "allOf[8]/then/properties/update/properties/details/properties/notice"):
        "the same Registry Update ID, named by the `appeal` that answers that notice",
    ("status.schema.json", "properties/rejections/items/properties/delta_id"):
        "a Delta ID",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/files/items/properties/sha256"):
        "a whole tier file, not any one record (DC-3 §7); and a manifest is a static artifact, not a Log Entry",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/anchor_block_hash"):
        "SHA-256 of a Block header",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/content_digest"):
        "a digest over the record tuples of DC-3 §7 — url, publisher, delta_id, observed_at, weight — every one of which the Log already carries in the clear; no page content is in its preimage",
    ("snapshot-index.schema.json",
     "properties/index/properties/snapshots/items/properties/content_digest"):
        "the same DC-3 §7 record-tuple digest the manifest declares, restated by the index",
    ("payload.schema.json", "properties/salt"):
        "the salt itself: drawn from a CSPRNG, never derived from the content it keys (DC-1 §3.6)",
}

NON_CONTENT_VALUES = {
    ("examples/audit-record.json", "audited_delta"): "a Delta ID",
        ("examples/audit-record.json", "value"): "an Ed25519 signature",
        ("examples/block.json", "merkle_root"): "root over Entries, which carry commitments only",
    ("examples/block.json", "prev"): "a Delta ID",
    ("examples/block.json", "value"): "an Ed25519 signature",
    ("examples/checkpoint.json", "block_hash"): "SHA-256 of a Block header",
    ("examples/checkpoint.json", "value"): "an Ed25519 signature",
        ("examples/delta.json", "value"): "an Ed25519 signature",
    ("examples/feed.json", "deltas"): "Delta IDs",
    ("examples/feed.json", "value"): "an Ed25519 signature",
    ("examples/log-anchor.json", "public_key"): "an Ed25519 public key",
    ("examples/log-anchor.json", "value"): "an Ed25519 signature",
    ("examples/payload.json", "salt"): "the salt: from a CSPRNG, never derived from what it keys",
    ("examples/publisher.json", "public_key"): "an Ed25519 public key",
    ("examples/publisher.json", "value"): "an Ed25519 signature",
    ("examples/registry-update.json", "public_key"): "an Ed25519 public key",
    ("examples/registry-update.json", "value"): "an Ed25519 signature",
    ("examples/snapshot-manifest.json", "sha256"): "a whole tier file, not any one record (DC-3 §7)",
    ("examples/snapshot-manifest.json", "anchor_block_hash"): "SHA-256 of a Block header",
    ("examples/snapshot-manifest.json", "content_digest"):
        "DC-3 §7's record-tuple digest: url, publisher, delta_id, observed_at, weight — no content in the preimage",
    ("examples/snapshot-manifest.json", "value"): "an Ed25519 signature",
    ("examples/snapshot-index.json", "content_digest"):
        "the manifest's record-tuple digest, restated by the index (DC-3 §6, §7)",
    ("examples/snapshot-index.json", "value"): "an Ed25519 signature",
    ("vectors/dc3/snapshot-records.json", "delta_id"): "a Delta ID",
    ("vectors/dc3/snapshot-records.json", "content_digest"):
        "DC-3 §7's record-tuple digest, recomputed by `snapshot:content-digest` from the records this file publishes",
    ("examples/status.json", "delta_id"): "a Delta ID",
        ("vectors/dc1/envelope.json", "value"): "an Ed25519 signature",
        ("vectors/dc1/id.txt", None): "the DC-1 vector's Delta ID",
    ("vectors/dc1/keypair.json", "seed_hex"): "the test signing seed",
    ("vectors/dc1/keypair.json", "public_key"): "an Ed25519 public key",
        ("vectors/dc3/block.json", "merkle_root"): "root over Entries, which carry commitments only",
    ("vectors/dc3/block.json", "prev"): "a Delta ID",
    ("vectors/dc3/block.json", "value"): "an Ed25519 signature",
    ("vectors/dc3/inclusion-proof.json", "path"): "Merkle sibling hashes over Entries",
    ("vectors/dc4/sampling.json", "block_hash"): "SHA-256 of a Block header",
    ("vectors/dc4/sampling.json", "alpha_hex"): "the Block Hash's raw octets, the VRF input",
    ("vectors/dc4/sampling.json", "beta_hex"): "the VRF output",
        ("vectors/dc4/sampling.json", "delta_id"): "a Delta ID",
    ("vectors/dc4/sampling.json", "auditor_public_key"): "an Ed25519 public key",
    ("vectors/dc4/audit-commitments.json", "audited_delta"): "a Delta ID",
    ("vectors/dc4/audit-commitments.json", "message_hex"): "a published preimage of this vector's commitments; the vector's content is placeholder text, not page content",
}


def _spec_derived_constants():
    """Digest-shaped figures the specs publish that are not literal in a vector.

    Each is *computed* here from a shipped artifact rather than pasted, so a
    spec figure that drifts from what the suite actually produces stops being a
    published figure and the sweep flags it.
    """
    out = set()
    canonical = (ROOT / "vectors" / "dc1" / "delta.canonical").read_bytes()
    out.add(canonical.hex())                      # DC-1 App A quotes leading chunks
    out.add(hashlib.sha256(b"\x00").hexdigest())  # DC-3 §4's empty-tree constant
    out.add(hashlib.sha256(
        (ROOT / "vectors" / "dc4" / "decay-table.json").read_bytes()).hexdigest())
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    out.add(b64u_decode(payload["salt"]).hex())   # DC-1 App A shows the salt in hex
    # The 160-hex ECVRF proof: longer than any digest, so the value sweep's
    # digest lengths never reach it, but DC-4 App A wraps it into 64-char cells
    # that are digest-shaped on their own.
    out.add(json.loads(
        (ROOT / "vectors" / "dc4" / "sampling.json").read_text())["vrf_proof_hex"])
    dc3 = json.loads((ROOT / "vectors" / "dc3" / "block.json").read_text())
    leaves = [leaf_hash(rfc8785.dumps(e)) for e in dc3["entries"]]
    out.update(h.hex() for h in leaves)           # DC-3 App A's leaf and node figures
    out.add(node_hash(leaves[0], leaves[1]).hex())
    out.add(node_hash(leaves[2], leaves[3]).hex())
    return out

# In prose there are no keys, so base64url detection needs a shape rule that
# does not fire on ordinary identifiers: a digest carries mixed case and digits,
# `deltacommons-test-salt` and `similarity_variance_floor` do not.
def _prose_digest_shaped(token: str) -> bool:
    body = token.split(":")[-1]
    if re.fullmatch(r"[0-9a-fA-F]+", body) and len(body) in HEX_DIGEST_LENGTHS:
        return True
    return (len(body) in B64_DIGEST_LENGTHS
            and re.fullmatch(r"[A-Za-z0-9_-]+", body) is not None
            and any(c.isdigit() for c in body)
            and any(c.islower() for c in body)
            and any(c.isupper() for c in body))

def _no_unsalted_content_digest():
    """No object in the suite carries a bare digest of page content.

    Moving extracts out of the Log achieves nothing if any object keeps an
    unsalted hash of the same text, so this holds the whole suite to the rule
    DC-3 §6.2 states: a content-derived value is committed under the Payload
    salt or it is not carried at all. Three sweeps: every schema, every shipped
    example and vector, and every specification document. In each, a
    digest-shaped thing passes only by being *declared* — as a non-content
    digest, or as a salted commitment with the check that proves it keyed.
    Nothing passes for carrying the `hmac-sha256:` label, because a bare
    SHA-256 of the content can wear that label and a new field can be patterned
    for it without anything keying it to a salt.
    """
    schemas = sorted((ROOT / "schemas").glob("*.schema.json"))
    assert len(schemas) >= 9, f"only {len(schemas)} schemas enumerated; the sweep is not suite-wide"
    # Two conditions, and both are needed. A check must assert its own coverage
    # (or a declaration could point at the name of any unrelated passing check
    # and be laundered by it), and it must have run and passed (or its coverage
    # assertion proves nothing). Together: the check ran, passed, and covered
    # this declaration.
    for where, proving_check in {**SALTED_COMMITMENTS, **SALTED_COMMITMENT_VALUES}.items():
        assert proving_check in COVERAGE_ASSERTED, (
            f"{where} is declared keyed by {proving_check!r}, which does not assert "
            "coverage of what declares it; only these checks may be named: "
            + ", ".join(sorted(COVERAGE_ASSERTED)))
        assert proving_check in PASSED, \
            f"{where} is declared keyed by {proving_check!r}, which did not run or did not pass"
    offenders, present = [], set()
    for path in schemas:
        for f in _schema_findings(path.name):
            present.add((f.schema, f.path))
            # Keyed by JSON path, not by property name: an exemption granted to
            # one occurrence must not extend to a same-named property elsewhere.
            if (f.schema, f.path) in SALTED_COMMITMENTS:
                continue                       # salted, and proven so by a named check
            if (f.schema, f.path) in NON_CONTENT_DIGESTS:
                continue                       # declared to carry no content
            offenders.append(f"{f.schema}: {f.path} (pattern {f.pattern!r})")
    # The other direction: a declaration for a location that no longer exists is
    # stale, and a stale table is one an escape can hide behind. Path drift — an
    # `allOf` branch inserted above a declared one, say — surfaces here too.
    stale = sorted((set(NON_CONTENT_DIGESTS) | set(SALTED_COMMITMENTS)) - present)
    assert not stale, \
        "declarations for schema locations that do not exist:\n  " \
        + "\n  ".join(f"{f}: {pth}" for f, pth in stale)
    assert not offenders, \
        "digest-shaped fields that are neither declared salted commitments nor " \
        "declared content-free:\n  " + "\n  ".join(offenders)

    # Values, not just declarations: `registry-update`'s `details` is
    # `{"type": "object"}` for several actions, so a bare digest there would
    # satisfy every schema in the suite (DC-4 §9.1). Vectors are swept too — a
    # digest parked in vectors/ is as published as one in examples/.
    published, encountered = set(), set()

    def scan(node, key, where, hits):
        if isinstance(node, dict):
            for k, v in node.items():
                scan(v, k, where, hits)
        elif isinstance(node, list):
            for v in node:
                scan(v, key, where, hits)
        elif isinstance(node, str):
            if not VALUE_DIGEST.fullmatch(node):
                return hits
            encountered.add((where, key))
            if (where, key) in SALTED_COMMITMENT_VALUES or (where, key) in NON_CONTENT_VALUES:
                published.add(node)
                published.add(node.split(":")[-1])
                return hits
            hits.append(f"{where}: opaque value at {key!r} = {node[:24]}… — "
                        "commit it under the Payload salt (DC-3 §6.2), or do "
                        "not carry it, or declare it")
        return hits

    hits, scanned = [], 0
    files = _shipped_files()
    for path in files:
        raw = path.read_text()
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            # Not JSON (id.txt): treat the whole file as one value.
            doc = raw.strip()
        scan(doc, None, str(path.relative_to(ROOT)), hits)
        scanned += 1
    assert scanned >= 20, f"only {scanned} shipped files swept; the sweep is not suite-wide"
    assert not hits, "opaque values at undeclared locations:\n  " + "\n  ".join(hits)
    stale_values = sorted(
        (set(NON_CONTENT_VALUES) | set(SALTED_COMMITMENT_VALUES)) - encountered)
    assert not stale_values, \
        "value declarations for locations that carry nothing digest-shaped:\n  " \
        + "\n  ".join(f"{f}: {k}" for f, k in stale_values)

    # The specifications themselves. Appendix A is where digests live in prose,
    # and prose has no keys to scope an allowlist to — so the rule is that every
    # digest-shaped token in specs/ must be a *published figure*: a value the
    # swept examples and vectors already carry at a declared location, or a
    # fragment of one (the appendices wrap long hex across table cells and code
    # blocks), or one of the few constants declared below with what it is.
    published |= {v for v in _spec_derived_constants()}
    corpus = "\n".join(sorted(published))
    spec_hits = []
    for path in sorted((ROOT / "specs").glob("*.md")):
        for token in re.findall(r"[A-Za-z0-9_:.-]{16,}", path.read_text()):
            token = token.strip(".,;:`")
            if not _prose_digest_shaped(token):
                continue
            bare = token.split(":")[-1]
            if bare in corpus or token in corpus:
                continue
            spec_hits.append(f"{path.name}: undeclared digest-shaped token {token}")
    assert not spec_hits, \
        "digest-shaped tokens in specs/ that are not published figures:\n  " \
        + "\n  ".join(spec_hits)
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
            "subject": "audit.example.net",
            "details": {"vrf_proof": v["vrf_proof_hex"]},
            "effective_at": "2026-08-02T16:00:00Z",
        },
        "sig": json.loads(
            (ROOT / "examples" / "registry-update.json").read_text())["sig"],
    }
    Draft202012Validator(schema).validate(attestation)
check("schema:dc4-coverage-attestation", _dc4_coverage_attestation)

def _parameter_registry_enum():
    """DC-4 §9's table and the `parameter_change` enum must correspond exactly.

    The table is what a human reads and the enum is what a validator enforces.
    An identifier in one and not the other means either a parameter nobody can
    amend in-band, or an amendable parameter with no published default and no
    stated owner — both of which turn a governance action into a guess. The
    correspondence is therefore checked in both directions, and a row that is
    deliberately not amendable must say so with an em dash rather than by
    omitting a cell.
    """
    spec = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    section9 = spec.split("## 9. Parameter Registry")[1].split("### 9.1.")[0]
    ids, rows = set(), 0
    for line in section9.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 4 or cells[1] == "Identifier":
            continue
        if set(cells[0]) <= set("-: "):     # the header separator row
            continue
        rows += 1
        found = set(re.findall(r"`([a-z0-9_]+)`", cells[1]))
        assert found or cells[1] == "—", (
            f"§9 row {cells[0]!r} has an Identifier cell that is neither a "
            f"backticked identifier nor an em dash: {cells[1]!r}")
        overlap = ids & found
        assert not overlap, f"§9 lists {sorted(overlap)} in more than one row"
        ids |= found
    assert rows >= 30, f"only {rows} Parameter Registry rows parsed; the sweep is not table-wide"
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    enum = None
    for branch in schema["allOf"]:
        if branch["if"]["properties"]["update"]["properties"]["action"].get("const") \
                == "parameter_change":
            enum = branch["then"]["properties"]["update"]["properties"]["details"][
                "properties"]["parameter"]["enum"]
    assert enum is not None, "registry-update.schema.json has no parameter_change branch"
    assert len(enum) == len(set(enum)), "the parameter enum repeats an identifier"
    missing_from_enum = sorted(ids - set(enum))
    missing_from_table = sorted(set(enum) - ids)
    assert not missing_from_enum, \
        f"§9 publishes identifiers the enum will not accept: {missing_from_enum}"
    assert not missing_from_table, \
        f"the enum accepts identifiers §9 publishes no row for: {missing_from_table}"
check("spec:parameter-registry-enum", _parameter_registry_enum)

def _parameter_change_bounds():
    """The bounds each `parameter_change` branch imposes, by identifier.

    A bound is a (minimum, maximum) pair with `None` for an absent side: some
    parameters are nullified by a value below a floor, some by one above a
    ceiling, and `similarity_consistent` and `similarity_variance_floor` by
    both — read them as one shape rather than assuming every bound is a floor.
    """
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    for branch in schema["allOf"]:
        if branch["if"]["properties"]["update"]["properties"]["action"].get("const") \
                != "parameter_change":
            continue
        details = branch["then"]["properties"]["update"]["properties"]["details"]
        out = {}
        for sub in details["allOf"]:
            value = sub["then"]["properties"]["value"]
            out[sub["if"]["properties"]["parameter"]["const"]] = (
                value.get("minimum"), value.get("maximum"))
        return out
    raise AssertionError("registry-update.schema.json has no parameter_change branch")

def _parameter_bounds():
    """Every bound §9 publishes is the bound the schema enforces, and bites.

    A bound that lives only in prose is an argument, not a constraint: the
    parameters that carry one carry it because a value past it retires a
    mechanism the suite depends on, and nothing but the schema stands between
    a signed `parameter_change` and that outcome. So the two are compared in
    both directions — a published bound the schema does not impose, and a
    schema bound §9 does not publish, are both failures — and each side of each
    bound is then exercised at its own boundary rather than assumed to be
    wired up.

    The table is read out of §9 rather than restated here for the same reason
    every other check in this file reads its thresholds from the document: a
    copy kept here would agree with itself while §9 drifted.
    """
    spec = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    section9 = spec.split("## 9. Parameter Registry")[1].split("### 9.1.")[0]
    # §9's bounds table is the three-column one: | `parameter` | bound | why |.
    # The four-column Parameter Registry table is the defaults table and is
    # parsed elsewhere; keying on the column count keeps the two apart.
    published = {}
    for line in section9.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 3 or set(cells[0]) <= set("-: "):
            continue
        names = re.findall(r"^`([a-z0-9_]+)`$", cells[0])
        if not names:
            continue
        lo = hi = None
        for op, raw in re.findall(r"(≥|>|≤|<)\s*([\d ]+)", cells[1]):
            n = int(raw.replace(" ", ""))
            if op in ("≥", ">"):
                lo = n if op == "≥" else n + 1
            else:
                hi = n if op == "≤" else n - 1
        assert lo is not None or hi is not None, \
            f"§9's bounds table gives {names[0]} no parseable bound: {cells[1]!r}"
        assert cells[2], f"§9's bounds table gives {names[0]} no stated consequence"
        published[names[0]] = (lo, hi)
    assert len(published) >= 20, \
        f"only {len(published)} bounds parsed from §9; the table is not being read"
    enforced = _parameter_change_bounds()
    assert published == enforced, (
        "§9's published bounds and the schema's differ:\n"
        f"  published: {dict(sorted(published.items()))}\n"
        f"  enforced:  {dict(sorted(enforced.items()))}")

    # Bounds may only be placed on parameters that exist: a bound on an
    # identifier the enum does not carry constrains nothing at all.
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    v = Draft202012Validator(schema)
    sig = json.loads((ROOT / "examples" / "registry-update.json").read_text())["sig"]
    def change(parameter, value):
        return {"update": {"dc_version": "1.0.0", "action": "parameter_change",
                           "subject": "log.example.org",
                           "details": {"parameter": parameter, "value": value},
                           "effective_at": "2026-08-12T16:00:00Z"},
                "sig": sig}
    enum = None
    for branch in schema["allOf"]:
        if branch["if"]["properties"]["update"]["properties"]["action"].get("const") \
                == "parameter_change":
            enum = set(branch["then"]["properties"]["update"]["properties"]["details"][
                "properties"]["parameter"]["enum"])
    unknown = sorted(set(enforced) - enum)
    assert not unknown, f"bounds are declared for identifiers the enum lacks: {unknown}"

    # Each side of each bound exercised at its own boundary. A branch wired to
    # the wrong identifier, or a `then` that constrains nothing, passes the
    # comparison above and fails here.
    for name, (lo, hi) in sorted(enforced.items()):
        if lo is not None:
            assert v.is_valid(change(name, lo)), \
                f"a parameter_change setting {name} to its own floor {lo} is rejected"
            assert not v.is_valid(change(name, lo - 1)), \
                f"a parameter_change setting {name} to {lo - 1}, below its floor, validates"
        if hi is not None:
            assert v.is_valid(change(name, hi)), \
                f"a parameter_change setting {name} to its own ceiling {hi} is rejected"
            assert not v.is_valid(change(name, hi + 1)), \
                f"a parameter_change setting {name} to {hi + 1}, above its ceiling, validates"

    # The parameters whose extremes most completely nullify §8 must each be
    # bounded, by name: a generalization that quietly dropped one of them
    # would still satisfy every comparison above.
    for name in ("sampling_floor", "sampling_ceiling", "confirm_window_hours",
                 "coverage_deadline_hours", "confirm_auditors", "penalty_weight"):
        assert enforced.get(name, (None, None))[0], \
            f"{name} carries no floor, so a parameter_change may zero it"
        assert not v.is_valid(change(name, 0)), f"{name} may still be set to zero"

    # `mirror_retention_days` is derived, not chosen: it is the longest span
    # DC-4 §7's own due process can run, so raising any deadline without
    # raising it would leave an appellant unable to fetch the Blocks holding
    # the Audit Records its sanction rests on (DC-3 §6).
    defaults = _registry_table_defaults()
    derived = (defaults["appeal_window_days"] + defaults["appeal_seal_days"]
               + defaults["ruling_deadline_days"])
    assert enforced["mirror_retention_days"][0] == derived, (
        f"the mirror retention floor is {enforced['mirror_retention_days'][0]}, but "
        f"§7's appeal window ({defaults['appeal_window_days']}) plus its sealing "
        f"deadline ({defaults['appeal_seal_days']}) plus its ruling deadline "
        f"({defaults['ruling_deadline_days']}) is {derived} days")
    assert defaults["mirror_retention_days"] >= derived, \
        "the published mirror retention default is below its own floor"
    assert str(derived) in section9, \
        f"§9 does not state the {derived}-day span the floor is derived from"

    # Three of these floors are derived from octet counts this harness can
    # compute, so the published numbers are checked against the artifacts they
    # describe rather than asserted. A cap below any of them is not a small cap
    # but the absence of the thing it bounds.
    assert enforced["extract_cap_bytes"][0] == len(rfc8785.dumps("")), \
        "the extract cap floor is not the octet length of JCS of the empty extract"
    assert enforced["summary_cap_bytes"][0] == len(rfc8785.dumps({"title": ""})), \
        "the summary cap floor is not the octet length of the smallest conforming summary"
    empty_block = json.loads((ROOT / "examples" / "block.json").read_text())
    empty_block["entries"] = []
    empty_block["header"]["entry_count"] = 0
    assert enforced["block_decompressed_cap_bytes"][0] >= len(rfc8785.dumps(empty_block)), (
        "the Block decompressed cap floor is below the size of an empty Block, which "
        "DC-3 §3.2 requires an Aggregator to be able to seal")

    # The catch-all must reach the parameters that exist, not only later ones:
    # a wording scoped to `confirm_auditors`, `penalty_weight` "and any later
    # parameter serving the same role" excludes every present parameter it
    # does not happen to name.
    assert re.search(r"MUST\s*\n?NOT set \*\*any\*\* parameter", section9), \
        "§9's nullification rule no longer reaches every present parameter"
    assert "any later parameter serving the same role" not in section9, \
        "§9's nullification rule is still scoped to parameters a later revision adds"
check("spec:parameter-bounds", _parameter_bounds)

def _parameter_change_integer():
    """`parameter_change.value` is the one field that rewrites a constant.

    DC-4 §6 states that every input to reputation is an integer and §10 that
    "there is no conforming path that uses `double`"; DC-4 §4 says the same of
    the sampling test. Both claims are about the constants as much as the
    variables, and this field is the only way a constant is ever rewritten — so
    a `number` here is the one hole through which a rational reaches §6.2's
    denominator (`penalty_weight`), §4's clamp (`sampling_slope`) or §5's
    thresholds. Every default §9 publishes is already an integer in its own
    unit, so nothing conforming is lost by typing it.
    """
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    branch = next(b for b in schema["allOf"]
                  if b["if"]["properties"]["update"]["properties"]["action"].get("const")
                  == "parameter_change")
    details = branch["then"]["properties"]["update"]["properties"]["details"]
    assert details["properties"]["value"]["type"] == "integer", \
        "parameter_change.value is not typed integer"

    # No other numeric anywhere in the suite may be looser: an `integer` field
    # that a later edit relaxes to `number` would reopen the same hole under a
    # different name, so the whole schema tree is swept rather than this field.
    loose = []
    for path in sorted((ROOT / "schemas").glob("*.schema.json")):
        def walk(node, where):
            if isinstance(node, dict):
                if node.get("type") == "number":
                    loose.append(f"{path.name}: {where}")
                for k, sub in node.items():
                    walk(sub, f"{where}/{k}")
            elif isinstance(node, list):
                for i, sub in enumerate(node):
                    walk(sub, f"{where}[{i}]")
        walk(json.loads(path.read_text()), "")
    assert not loose, \
        "numeric fields typed `number` rather than `integer`:\n  " + "\n  ".join(loose)

    # Mutation proof: the rationals that validated before this field was typed
    # must each be rejected now, and the integer next to each must be accepted,
    # so the check cannot pass by rejecting everything.
    v = Draft202012Validator(schema)
    sig = json.loads((ROOT / "examples" / "registry-update.json").read_text())["sig"]
    def change(parameter, value):
        return {"update": {"dc_version": "1.0.0", "action": "parameter_change",
                           "subject": "log.example.org",
                           "details": {"parameter": parameter, "value": value},
                           "effective_at": "2026-08-12T16:00:00Z"},
                "sig": sig}
    for parameter, rational, whole in (("penalty_weight", 1.5, 2),
                                       ("c_cap", 2.5, 3),
                                       ("provisional_cap_u", 100000.5, 100000),
                                       ("sampling_slope", 0.5, 1),
                                       ("similarity_consistent", 600000.25, 600000),
                                       ("age_norm_days", 730.5, 730)):
        assert not v.is_valid(change(parameter, rational)), \
            f"a parameter_change setting {parameter} to the rational {rational} validates"
        assert v.is_valid(change(parameter, whole)), \
            f"a parameter_change setting {parameter} to the integer {whole} is rejected"
    # JSON has one number type, so a whole-valued float is the same value as
    # the integer beside it; the guard must not turn on the Python literal.
    assert v.is_valid(change("penalty_weight", 5.0)), \
        "5.0 and 5 are one JSON value, and the schema must not distinguish them"

    # DC-4 §9 must say so, or an implementer reading prose alone sees a number.
    section9 = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text() \
        .split("## 9. Parameter Registry")[1]
    assert "**Every value the registry carries is an integer**" in section9, \
        "DC-4 §9 does not state that every registry value is an integer"
    assert "`value` (a number" not in section9, \
        "DC-4 §9.1 still describes `value` as a number"
check("schema:parameter-change-integer", _parameter_change_integer)

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
        # The Selected? cell itself, pinned to its own row via the
        # (lhs_approx, rhs_approx) pair — unique per selection entry — so a
        # hand-edit flipping "yes" to "no" (or vice versa) on the wrong row
        # cannot pass unnoticed. Bold markers (`**yes**`) are tolerated.
        word = "yes" if c["selected"] else "no"
        row = re.escape(f"{c['lhs_approx']} | {c['rhs_approx']} |")
        assert re.search(row + r"\s*\*{0,2}" + word + r"\*{0,2}\s*\|", flat), \
            f"DC-4's Selected? column for {c['label']} does not say {word!r} on its own row"
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

# DC-4 §3: every window and every admission test in the suite reads a Block
# `sealed_at`, and every timestamp compared against one is written in that
# field's own whole-second-plus-literal-Z form. That is a claim about every
# `date-time` in every schema, so the guard below enumerates them all rather
# than any single field.
#
# Each entry is either ANCHORED — the value takes part in a comparison against
# a Block `sealed_at`, so it MUST carry the pattern — or a stated reason why it
# does not. Declaring a field unanchored is the deliberate act of asserting
# that nothing recomputable is decided by comparing it to the Log's own clock.
ANCHORED = "anchored to a Block `sealed_at`"
SEALED_AT_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"

TIMESTAMP_FIELDS = {
    ("block.schema.json", "properties/header/properties/sealed_at"): ANCHORED,
    ("checkpoint.schema.json", "properties/checkpoint/properties/sealed_at"): ANCHORED,
    ("feed.schema.json", "properties/feed/properties/generated_at"): ANCHORED,
    ("audit-record.schema.json", "properties/record/properties/fetched_at"): ANCHORED,
    ("registry-update.schema.json", "properties/update/properties/effective_at"): ANCHORED,
    ("registry-update.schema.json",
     "allOf[3]/then/properties/update/properties/details/properties/appeal_deadline"): ANCHORED,
    ("delta.schema.json", "properties/delta/properties/observed_at"):
        "Publisher-supplied and never compared to a Block: DC-4 §6.1 excludes it from every "
        "derived quantity, and its only comparisons are to the `observed_at` of the Delta named "
        "by `prev` and to the validator's own clock under DC-1 §3.4's 10-minute skew allowance",
    ("publisher.schema.json", "properties/publisher/properties/keys/items/properties/valid_from"):
        "compared only to a Delta's own `observed_at` (DC-1 §5.1), never to a Block",
    ("publisher.schema.json",
     "properties/publisher/properties/recovery_keys/items/properties/valid_from"):
        "compared only to a Delta's own `observed_at` (DC-1 §5.1), never to a Block",
    ("log-anchor.schema.json", "properties/anchor/properties/created_at"):
        "descriptive: the Anchor is authenticated by its own signature and its out-of-band "
        "fingerprint (DC-3 §3.4), and nothing compares this value to anything",
    ("snapshot-index.schema.json", "properties/index/properties/updated_at"):
        "descriptive: when the Aggregator last rewrote a mutable index (DC-3 §6); a Snapshot is "
        "bound to the chain by `log_position` and `anchor_block_hash`, never by this",
    ("status.schema.json", "properties/last_pull_at"):
        "the Publisher's debugging surface (DC-2 §7.1), not a signed Envelope and not an "
        "artifact any party verifies",
    ("status.schema.json", "properties/rejections/items/properties/at"):
        "the same unsigned debugging surface (DC-2 §7.1): when the Aggregator recorded a typed "
        "rejection, reported to the Publisher and compared to nothing",
}

def _walk_timestamps(node, schema_name, found, key=None, root=None,
                     seen=frozenset(), path=""):
    """Every `format: date-time` leaf in a schema, by the JSON path reaching it."""
    if root is None:
        root = node
    if not isinstance(node, dict):
        return found
    node = _resolve(node, root, seen)
    if not isinstance(node, dict):
        return found
    if node.get("$ref"):
        seen = seen | {node["$ref"]}
    if node.get("format") == "date-time":
        found.append((schema_name, path, node.get("pattern")))

    def step(sub, sub_key, seg):
        _walk_timestamps(sub, schema_name, found, sub_key, root, seen,
                         f"{path}/{seg}" if path else seg)

    for kw in ("properties", "patternProperties", "$defs", "dependentSchemas"):
        for name, sub in node.get(kw, {}).items():
            step(sub, name, f"{kw}/{name}")
    for kw in ("prefixItems", "items", "allOf", "anyOf", "oneOf"):
        if isinstance(node.get(kw), list):
            for i, sub in enumerate(node[kw]):
                if isinstance(sub, dict):
                    step(sub, key, f"{kw}[{i}]")
    for kw in ("items", "then", "else", "not", "contains", "if",
               "additionalProperties", "propertyNames", "unevaluatedProperties",
               "unevaluatedItems"):
        if isinstance(node.get(kw), dict):
            step(node[kw], key, kw)
    return found

def _timestamp_anchoring():
    """No window in the suite runs off a timestamp its writer chooses freely.

    DC-4 §3 states that every window and admission test reads a Block
    `sealed_at`. A `date-time` field that takes part in such a comparison and
    is not constrained to that field's own form reopens, one field at a time,
    exactly what block.schema.json's pattern closed: an Aggregator writing
    `effective_at` a month in the past closed an appeal window before the
    notice existed, and every recomputing party agreed. So this enumerates
    every `date-time` in every schema, in both directions, and requires each
    to be declared either anchored — and then patterned — or unanchored with
    the reason it is.
    """
    found, present = [], set()
    schemas = sorted((ROOT / "schemas").glob("*.schema.json"))
    assert len(schemas) >= 9, f"only {len(schemas)} schemas enumerated; the sweep is not suite-wide"
    for path in schemas:
        _walk_timestamps(json.loads(path.read_text()), path.name, found)
    undeclared = []
    for schema_name, spath, pattern in found:
        present.add((schema_name, spath))
        declared = TIMESTAMP_FIELDS.get((schema_name, spath))
        if declared is None:
            undeclared.append(f"{schema_name}: {spath}")
            continue
        if declared is ANCHORED:
            assert pattern == SEALED_AT_PATTERN, (
                f"{schema_name}: {spath} is compared against a Block `sealed_at` but carries "
                f"pattern {pattern!r}, not the whole-second-plus-Z form that field carries")
        else:
            assert pattern is None, (
                f"{schema_name}: {spath} is declared unanchored yet constrained; declare it "
                "anchored or drop the pattern")
            assert len(declared) > 40, \
                f"{schema_name}: {spath} is declared unanchored with no stated reason"
    assert not undeclared, (
        "date-time fields declared neither anchored to a Block nor unanchored:\n  "
        + "\n  ".join(undeclared))
    stale = sorted(set(TIMESTAMP_FIELDS) - present)
    assert not stale, ("declarations for date-time fields that do not exist:\n  "
                       + "\n  ".join(f"{f}: {p}" for f, p in stale))
    anchored = {k for k, v in TIMESTAMP_FIELDS.items() if v is ANCHORED}
    assert len(anchored) >= 6, \
        f"only {len(anchored)} anchored timestamps; the class is wider than that"

    # Mutation proof, on the two fields the appeal and grace-period windows read:
    # the pattern must reject exactly the forms RFC 3339 permits and DC-3 §3.1
    # does not, and must still accept what the suite ships.
    v = Draft202012Validator(
        json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text()))
    import copy
    example = json.loads((ROOT / "examples" / "registry-update.json").read_text())
    assert v.is_valid(example), "the shipped Registry Update no longer validates"
    for bad in ("2026-08-02T12:00:00.500Z", "2026-08-02T12:00:00+00:00",
                "2026-08-02T12:00:00", "2026-08-02t12:00:00z"):
        candidate = copy.deepcopy(example)
        candidate["update"]["effective_at"] = bad
        assert not v.is_valid(candidate), \
            f"registry-update.schema.json accepts non-exact effective_at {bad!r}"
    notice = {"update": {"dc_version": "1.0.0", "action": "notice",
                         "subject": "example.com",
                         "details": {"kind": "sanction", "reason": "see evidence",
                                     "appeal_deadline": "2026-08-16T12:00:00Z"},
                         "evidence": ["sha256:" + "0" * 64],
                         "effective_at": "2026-08-02T12:00:00Z"},
              "sig": example["sig"]}
    assert v.is_valid(notice), "a well-formed sanction notice does not validate"
    for bad in ("2026-08-16T12:00:00.500Z", "2026-08-16T12:00:00+00:00"):
        candidate = copy.deepcopy(notice)
        candidate["update"]["details"]["appeal_deadline"] = bad
        assert not v.is_valid(candidate), \
            f"registry-update.schema.json accepts non-exact appeal_deadline {bad!r}"

    # And the documents must say which value a window reads, or an implementer
    # reading prose alone still runs the appeal window off `effective_at`.
    dc4 = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    section7 = dc4.split("## 7. Sanctions")[1].split("## 8.")[0]
    assert re.search(
        r"appeal window is `appeal_window_days` \(14\) from the `sealed_at` of\s*\n"
        r"\s*the Block sealing the `notice`, never from its `effective_at`", section7), \
        "DC-4 §7 no longer runs the appeal window from the notice's Block `sealed_at`"
    dc1 = (ROOT / "specs" / "DC-1-delta-format.md").read_text()
    assert "opens at the `sealed_at` of the Block" in dc1, \
        "DC-1 §5.2 no longer anchors the recovery window to the Declaration's own Entry"
check("schema:timestamp-anchoring", _timestamp_anchoring)

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

def _dc4_similarity_thresholds():
    """The three §5 verdict bands, read out of the specification's own table.

    Every check below that needs a threshold reads it here rather than
    carrying its own copy, so an edit to §5 moves what the checks exercise
    instead of drifting away from it.
    """
    spec = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    section5 = spec.split("## 5. Verdicts")[1].split("## 6.")[0]
    rows = {
        "consistent_at_or_above": r"\|\s*`consistent`\s*\|\s*effective similarity\s*≥\s*([\d ]+?)\s*\|",
        "variance_at_or_above": r"\|\s*`dynamic_variance`\s*\|\s*([\d ]+?)\s*≤\s*effective similarity",
        "variance_below": r"\|\s*`dynamic_variance`\s*\|.*?effective similarity\s*<\s*([\d ]+?)\s*\|",
        "inconsistent_below": r"\|\s*`inconsistent`\s*\|\s*effective similarity\s*<\s*([\d ]+?)\s*\|",
    }
    out = {}
    for name, pattern in rows.items():
        m = re.search(pattern, section5)
        assert m, f"DC-4 §5 does not state the {name} threshold in the expected form"
        out[name] = int(m.group(1).replace(" ", "").replace(" ", ""))
    assert out["consistent_at_or_above"] == out["variance_below"], \
        "§5's `consistent` floor and `dynamic_variance` ceiling are not the same number"
    assert out["variance_at_or_above"] == out["inconsistent_below"], \
        "§5's `dynamic_variance` floor and `inconsistent` ceiling are not the same number"
    return out


def _dc4_severity_rows():
    """§7's severity table as intervals, parsed out of §7's own text.

    Read rather than restated, so that the totality check below tests §5's
    verdict bands against the severity table the document actually
    publishes. A copy kept here would agree with itself while §5 and §7
    drifted apart, which is the failure the check exists to catch.
    """
    spec = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    section7 = spec.split("## 7. Sanctions")[1].split("## 8.")[0]
    rows = []
    for m in re.finditer(
            r"\|\s*([\d ]+?)\s*≤\s*`sim`\s*<\s*([\d ]+?)\s*\|\s*(\d)\s*\(", section7):
        rows.append((int(m.group(1).replace(" ", "")),
                     int(m.group(2).replace(" ", "")), int(m.group(3))))
    for m in re.finditer(r"\|\s*`sim`\s*<\s*([\d ]+?)\s*\|\s*(\d)\s*\(", section7):
        rows.append((0, int(m.group(1).replace(" ", "")), int(m.group(2))))
    assert len(rows) >= 3, f"DC-4 §7's severity table did not parse: {rows}"
    # §7 must state its input as the *effective* similarity: reverting it to
    # the sealed `similarity` silently un-does the `delete` mirror and leaves
    # a false `delete` deriving severity from a value in the wrong direction.
    assert re.search(r"let `sim` be the highest\s+\*\*effective similarity\*\*\s*\(§5\)",
                     section7), \
        "DC-4 §7 does not derive `sim` from the effective similarity (§5)"
    return rows


def _dc4_verdict_totality():
    """Every permitted pair of texts maps to exactly one verdict (DC-4 §5),
    and every verdict that carries a penalty maps to exactly one severity.

    A verdict table with a gap leaves a conforming Auditor with nothing to
    record, and one with an overlap lets two conforming Auditors record
    different things about the same page; either way the confirmation rule
    and the severity ladder rest on a judgement call the specification did
    not make. `similarity` is an integer in micro-units, so the reachable
    range is finite and exactly enumerable — every value is checked, for
    every change type, against the bands §5 states and the severity rows §7
    states, each parsed from the document rather than restated here. The
    two must meet exactly: §7's rows must cover [0, §5's `inconsistent`
    ceiling) and nothing beyond it, or some reachable Confirmed
    Inconsistency has two severities or none.

    The `delete` direction needs it most: its verdict is read from the
    mirrored value, and a mirror landing outside §7's domain would leave a
    false `delete` as a Confirmed Inconsistency with no severity input.
    """
    spec = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    section5 = spec.split("## 5. Verdicts")[1].split("## 6.")[0]
    t = _dc4_similarity_thresholds()
    CONSISTENT, HIGH = t["consistent_at_or_above"], t["inconsistent_below"]
    assert 0 < HIGH < CONSISTENT <= 1_000_000, \
        f"§5's thresholds are not ordered inside the micro-unit range: {t}"
    rows = _dc4_severity_rows()

    # The severity table's domain, computed from §7's rows, must be exactly
    # the range §5 makes reachable for an `inconsistent` verdict. Widening
    # §5's ceiling without widening §7's table, or narrowing §7's table
    # without narrowing §5, fails here rather than in a deployment.
    top = max(hi for _, hi, _ in rows)
    bottom = min(lo for lo, _, _ in rows)
    assert bottom == 0, f"§7's severity table does not reach 0 (lowest bound {bottom})"
    assert top == HIGH, (
        f"§7's severity table covers [0, {top}) but §5 makes every effective "
        f"similarity in [0, {HIGH}) `inconsistent`: "
        + ("a Confirmed Inconsistency in "
           f"[{top}, {HIGH}) would have no severity" if top < HIGH else
           f"§7 grades values in [{HIGH}, {top}) that no verdict can produce"))

    # The mirror itself must be stated, and stated as a reflection about the
    # full micro-unit range: any other constant would move `delete` verdicts
    # off the bands the direct reading uses.
    assert "effective similarity = similarity" in section5, \
        "§5 does not state the effective similarity for the direct change types"
    assert re.search(r"=\s*1 000 000\s*−\s*similarity\s*\(delete\)", section5), \
        "§5 does not state the `delete` mirror as 1 000 000 − similarity"

    def bands(eff):
        return [name for name, hit in (
            ("consistent", eff >= CONSISTENT),
            ("dynamic_variance", HIGH <= eff < CONSISTENT),
            ("inconsistent", eff < HIGH),
        ) if hit]

    def severities(eff):
        return [s for lo, hi, s in rows if lo <= eff < hi]

    seen, graded = {"new": set(), "delete": set()}, set()
    for sim in range(0, 1_000_001):
        for change_type in ("new", "delete"):
            eff = sim if change_type != "delete" else 1_000_000 - sim
            assert 0 <= eff <= 1_000_000, \
                f"{change_type} at similarity {sim} leaves the micro-unit range"
            hit = bands(eff)
            assert len(hit) == 1, \
                f"{change_type} at similarity {sim} matches {len(hit)} verdicts: {hit}"
            seen[change_type].add(hit[0])
            if hit[0] == "inconsistent":
                got = severities(eff)
                assert len(got) == 1, (
                    f"a {change_type} Confirmed Inconsistency at similarity {sim} "
                    f"(effective {eff}) matches {len(got)} severity rows: {got}")
                graded.add(got[0])
    for change_type, got in seen.items():
        assert got == {"consistent", "dynamic_variance", "inconsistent"}, \
            f"{change_type} audits cannot reach every band: {got}"
    assert graded == {1, 2, 3}, \
        f"the reachable `inconsistent` range does not exercise every severity: {graded}"

    # A `delete` whose URL still serves the committed content is the case
    # the mirror exists for, and it must be `inconsistent` with a severity.
    assert bands(1_000_000 - 1_000_000)[0] == "inconsistent", \
        "a `delete` audit finding the committed content served verbatim is not `inconsistent`"
    assert severities(1_000_000 - 1_000_000) == [max(s for _, _, s in rows)], \
        "a `delete` audit finding the committed content served verbatim is not the gravest severity"
    assert bands(1_000_000 - 0)[0] == "consistent", \
        "a `delete` audit finding none of the committed content is not `consistent`"
check("spec:dc4-verdict-totality", _dc4_verdict_totality)

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
    HIGH = _dc4_similarity_thresholds()["inconsistent_below"]
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

def _withdrawal_binds_every_serving_path():
    """A withdrawal reaches every path the Payload is served from, or none.

    The salt is published in exactly one kind of file, and three parties serve
    it: the Aggregator, every Mirror, and the Publisher's own well-known path
    (DC-2 §3.1, DC-3 §6.1). "After withdrawal the Log itself stops helping"
    (DC-3 §11) and "the salt is destroyed and that Record's commitments can no
    longer be checked by anyone" (DC-4 §5) are false at one fetch if any one of
    the three keeps serving — and DC-2 separately obliges a Publisher to keep
    its anchor Payload retrievable, so leaving it unbound was not an omission
    but a conflict.
    """
    dc2 = (ROOT / "specs" / "DC-2-site-publication.md").read_text()
    dc3 = (ROOT / "specs" / "DC-3-commons-log-distribution.md").read_text()
    dc4 = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    withdrawal = dc3.split("### 6.2. Withdrawal")[1].split("## 7.")[0]
    stop = re.search(r"^- the Aggregator[^\n]*(?:\n(?!- ).*)*", withdrawal, re.M)
    assert stop, "DC-3 §6.2 no longer opens its obligations with the stop-serving rule"
    # The *obligation* must name all three, not the paragraph explaining it: a
    # rule that binds two parties and then discusses the third at length reads
    # as covering it while binding nothing.
    clause = re.split(r"\.\s", stop.group(0))[0]
    assert "MUST stop" in clause, \
        "DC-3 §6.2's first obligation is no longer the stop-serving rule"
    for party in ("Aggregator", "Mirror", "Publisher"):
        assert party in clause, \
            f"DC-3 §6.2's stop-serving obligation does not bind the {party}"
    assert "every party holding the Payload for protocol purposes MUST destroy it" in withdrawal, \
        "DC-3 §6.2 no longer requires holders to destroy the Payload and its salt"

    # The conflicting duty must be reconciled where it is stated, not only
    # overridden from another document.
    retention = dc2.split("**Payload retention.**")[1].split("### 3.2.")[0]
    assert "payload_withdrawal" in retention and "MUST stop serving" in retention, \
        "DC-2 §3.1's retention duty does not say that a withdrawal ends it"
    checklist = dc2.split("## 10. Conformance Checklist")[1].split("**Aggregator")[0]
    assert "payload_withdrawal" in checklist, \
        "DC-2's Publisher checklist has no row for stopping service on a withdrawal"
    assert "appeals/<notice-id>.json" in checklist, \
        "DC-2's Publisher checklist has no row for publishing an appeal"

    # And the claims that rest on it must still be the claims being made, or
    # this check is guarding a guarantee the suite no longer states.
    assert "the Log itself\nstops helping" in dc3, \
        "DC-3 §11 no longer claims the Log stops helping after a withdrawal"
    assert "can no longer be checked by anyone" in dc4, \
        "DC-4 §5 no longer claims a withdrawn Record's commitments are uncheckable"
check("spec:withdrawal-serving-paths", _withdrawal_binds_every_serving_path)

def _rule_ownership():
    """A rule restated in a second document must be the rule, not an older one.

    DC-4 §5 owns the unauditable-URL rule: two `robots_excluded` Records from
    mutually independent Auditors inside the horizon, cleared only by an
    Auditor independent of both, ageing out when they leave the window. The
    pre-Task shape — "no successful audit by an independent Auditor since,
    until one succeeds" — restores exactly the single-permitted-Auditor attack
    the two-Auditor requirement exists to close, so a restatement carrying it
    is not a summary but a second, weaker rule.
    """
    specs = {p.name: p.read_text() for p in sorted((ROOT / "specs").glob("*.md"))}
    stale = re.compile(r"by an independent Auditor since|"
                       r"until an audit succeeds\b|"
                       r"excluded from\s*\n?\s*materialization until one succeeds")
    hits = [f"{name}: {m.group(0)!r}"
            for name, text in specs.items() for m in stale.finditer(text)]
    assert not hits, ("a document restates the unauditable rule in its "
                      "single-Auditor form:\n  " + "\n  ".join(hits))
    # Every site that states the rule states both load-bearing halves.
    for name, marker in (("DC-2-site-publication.md", "two Auditors independent of one another"),
                         ("DC-3-commons-log-distribution.md", "two independent Auditors"),
                         ("DC-4-audit-reputation-governance.md", "signed by Auditors independent of one another")):
        assert marker in specs[name], \
            f"{name} no longer states that two independent Auditors are needed to exclude a URL"
        assert "independent of both" in specs[name], \
            f"{name} no longer states that the clearing audit must come from a third Auditor"
    # DC-2 defers rather than legislating: it owns the robots.txt boundary, not
    # the materialization consequence.
    dc2_section5 = specs["DC-2-site-publication.md"].split("## 5. Aggregator Pull Behavior")[1] \
        .split("## 6.")[0]
    assert "DC-4 §5 owns that rule" in dc2_section5, \
        "DC-2 §5 no longer defers to the document that owns the rule it summarizes"
check("spec:rule-ownership", _rule_ownership)

def _derived_not_discretionary():
    """Consequences the suite derives from the Log may not wait on an Entry.

    Three mechanisms were gated on a discretionary act by the one party the
    design refuses to trust: an appeal nobody was obliged to seal, a recovery
    window that opened only on a `notice`, and a coverage failure whose
    consequence was an `auditor_remove` the Aggregator files. In each the
    Aggregator's entry must now record the consequence rather than cause it,
    and the omission must itself have a derived effect.
    """
    dc1 = (ROOT / "specs" / "DC-1-delta-format.md").read_text()
    dc4 = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    section4 = dc4.split("## 4. Audit Sampling")[1].split("## 5.")[0]
    section7 = dc4.split("## 7. Sanctions")[1].split("## 8.")[0]
    section10 = dc4.split("## 10. Security Considerations")[1].split("## 11.")[0]

    # I1: the appeal has a path, a deadline, and a consequence for the omission.
    assert "/.well-known/deltacommons/appeals/" in section7, \
        "DC-4 §7 gives an appeal no in-band publication path"
    for fragment in ("`appeal_seal_days`",
                     "is void on recomputation from T",
                     '`"unappealed"`'):
        assert fragment in section7, f"DC-4 §7 no longer states {fragment}"
    assert "appeal_seal_days" in json.loads(
        (ROOT / "schemas" / "registry-update.schema.json").read_text())["allOf"][5][
            "then"]["properties"]["update"]["properties"]["details"][
            "properties"]["parameter"]["enum"], \
        "the parameter enum does not carry appeal_seal_days"

    # …and §10 no longer defends appeals with an argument that is false.
    assert "Omission is not equivocation" in section10, \
        "DC-4 §10 no longer corrects the claim that suppression is equivocation"
    assert not re.search(r"suppress a\s*\n?\s*sanction or an appeal: withholding log entries",
                         section10), \
        "DC-4 §10 still answers appeal suppression with the equivocation argument"

    # I3: the recovery window opens on the Declaration's own Entry.
    recovery = dc1.split("**Compromise recovery.**")[1].split("**Historical verification.**")[0]
    assert "opens at the `sealed_at` of the Block" in recovery, \
        "DC-1 §5.2's recovery window is not anchored to the recovery Declaration's Entry"
    assert "does not open it" in recovery, \
        "DC-1 §5.2 does not say the `notice` describes the window rather than opening it"
    assert not re.search(r"MUST record a `notice`[^.]*opening a recovery window", recovery), \
        "DC-1 §5.2 still has the `notice` open the recovery window"

    # I4: coverage failure withdraws the Records itself.
    assert "in coverage failure" in section4, \
        "DC-4 §4 does not define the derived coverage-failure state"
    assert "records\nthe consequence and does not create it" in section4, \
        "DC-4 §4 does not say `auditor_remove` records the consequence rather than creating it"
    section3 = dc4.split("## 3. Auditors")[1].split("## 4.")[0]
    assert "in coverage failure" in section3, \
        "DC-4 §3's rejection list does not reach an Auditor in coverage failure"

    # I5: the personal-data rule is general, not a list of three field names.
    section91 = dc4.split("### 9.1. Registry Update")[1].split("## 10.")[0]
    assert "no `evidence` element, may\ncarry personal data" in section91, \
        "DC-4 §9.1's personal-data rule is not written over the position"
    assert not re.search(r"The same applies to the free-text fields `legal_basis`, `reason` and",
                         section91), \
        "DC-4 §9.1 still enumerates the fields the personal-data rule covers"
    assert "`appeal`'s and a `sanction_lift`'s `details` are the Publisher's" in section91, \
        "DC-4 §9.1 does not reach the Publisher-written details the rule was missing"
check("spec:derived-not-discretionary", _derived_not_discretionary)

def _unappealed_ruling_timing():
    """An `"unappealed"` ruling may not be sealed before the window it reports.

    `"unappealed"` exists so that a Publisher's silence is answered in the Log
    rather than rewarded, and so that an Aggregator burying an appeal must make
    a false, dated, public claim to keep the sanction standing. Both properties
    need the ruling to come *after* the appeal window closes. Unconstrained, it
    can be sealed in the notice's own Block: T is discharged for every process
    the moment it opens, burying an appeal costs one Entry, and the derived
    half of §7's deadline is gone while only the attributable half survives.
    The rule is a comparison of two Block `sealed_at` values against a
    parameter, so it is checked here as arithmetic and not only as prose — no
    schema can express it, the two Blocks being different Entries.
    """
    spec = (ROOT / "specs" / "DC-4-audit-reputation-governance.md").read_text()
    section7 = spec.split("## 7. Sanctions")[1].split("## 8.")[0]
    assert '**An `"unappealed"` ruling cannot precede what it reports.**' in section7, \
        "DC-4 §7 places no timing constraint on an `unappealed` ruling"
    assert re.search(
        r"discharges T only when the Block sealing it has a `sealed_at` at\s*\n"
        r"\s*or after the close of the appeal window", section7), \
        "DC-4 §7 does not require an `unappealed` ruling to follow the window's close"
    assert re.search(r"party recomputing MUST treat it as absent", section7), \
        "DC-4 §7 does not require a recomputing party to ignore an early `unappealed` ruling"
    checklist = spec.split("**Any party recomputing reputation:**")[1]
    assert '`appeal_ruling` of `"unappealed"` whose own Block' in checklist, \
        "DC-4 §12's recompute checklist has no row for the `unappealed` timing rule"

    # The rule as arithmetic, over the parameters §9 publishes rather than
    # numbers restated here: an edit to `appeal_window_days` moves what this
    # exercises instead of leaving it checking a frozen boundary.
    defaults = _registry_table_defaults()
    window, seal = defaults["appeal_window_days"], defaults["appeal_seal_days"]
    day = 86_400

    def discharges(notice_sealed, ruling_sealed):
        """§7: an `unappealed` ruling counts only from the window's close."""
        return ruling_sealed >= notice_sealed + window * day

    def state_void_at_T(notice_sealed, ruling_sealed):
        # T = notice_sealed + (window + seal) days; the state is void there
        # unless something the Log holds discharges it, and an early ruling
        # is not something: §7 has a recomputing party treat it as absent.
        return ruling_sealed is None or not discharges(notice_sealed, ruling_sealed)

    n = 1_000_000
    # The attack the constraint closes: a ruling batched with its own notice.
    assert not discharges(n, n), \
        "a ruling sealed in the notice's own Block discharges T"
    assert not discharges(n, n + day), \
        "a ruling sealed one day after the notice discharges T"
    assert state_void_at_T(n, n + day), \
        "an early `unappealed` ruling leaves the sanction state standing at T"
    # The honest path still works, at the boundary and past it.
    assert discharges(n, n + window * day), \
        "a ruling sealed exactly at the window's close does not discharge T"
    assert not state_void_at_T(n, n + window * day), \
        "a timely `unappealed` ruling does not keep the sanction state in force"
    assert discharges(n, n + (window + seal) * day), \
        "a ruling sealed at T itself does not discharge T"
    assert not discharges(n, n + window * day - 1), \
        "a ruling one second before the window closes discharges T"
    # And doing nothing at all still voids the state, or the rule above would
    # be the only way the deadline ever bites.
    assert state_void_at_T(n, None), "an unanswered notice leaves the state in force at T"
check("spec:unappealed-ruling-timing", _unappealed_ruling_timing)

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

def _single_discovery_channel():
    """No non-HTTPS key-discovery mechanism may reappear (DC-1 §5.1, §8).

    The rule guards a *mechanism*, not a word. Banning the string "DNS"
    outright would forbid DC-1 §8 from naming the fallback it removed, and a
    door whose closing is undocumented is one a later editor reopens in good
    faith; it would also miss a reintroduction under any other name. So the
    guard is written over what an implementation would actually have to
    publish: the well-known record label, and a section heading offering the
    fallback as a defined alternative.
    """
    label = re.compile(r"_deltacommons\.")
    heading = re.compile(r"^#{2,6}\s.*\b(DNS|TXT)\b.*\bfallback\b", re.I | re.M)
    dc1 = (ROOT / "specs" / "DC-1-delta-format.md").read_text()
    security = dc1.split("## 8. Security Considerations")[1].split("## 9.")[0]
    allowed = set(security.splitlines())     # the one place the label may appear
    hits = []
    for path in sorted((ROOT / "specs").glob("*.md")):
        text = path.read_text()
        for n, line in enumerate(text.splitlines(), 1):
            if label.search(line) and line not in allowed:
                hits.append(f"{path.relative_to(ROOT)}:{n}: names the TXT record label "
                            f"outside DC-1 §8, where only its removal is recorded")
        for m in heading.finditer(text):
            hits.append(f"{path.relative_to(ROOT)}: defines a fallback section: {m.group(0).strip()!r}")
    assert not hits, "a non-HTTPS discovery channel has reappeared:\n  " + "\n  ".join(hits)

    # The removal must stay documented, or the guard above protects nothing a
    # reader can see: DC-1 §8 names the mechanism and ADR-0002 records why.
    assert "_deltacommons." in security, \
        "DC-1 §8 no longer names the removed TXT-record mechanism, so the closed door is invisible"
    assert re.search(r"there is no alternative channel", dc1), \
        "DC-1 §5.1 no longer states that HTTPS is the only discovery channel"
    adr = (ROOT / "decisions" / "0002-ed25519-domain-anchored-identity.md").read_text()
    decision = adr.split("## Decision")[1].split("## Consequences")[0]
    assert "fallback" in decision and "_deltacommons." in decision, \
        "ADR-0002's accepted decision no longer records the removed fallback"
    assert "(DNS TXT fallback)" not in adr, \
        "ADR-0002 still lists the fallback as part of the accepted decision"
check("spec:single-discovery-channel", _single_discovery_channel)

sys.exit(1 if failures else 0)
