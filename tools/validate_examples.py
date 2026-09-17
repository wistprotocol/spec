#!/usr/bin/env python3
"""Validate examples/ against schemas/ and verify vectors/. Exit 0 = green."""
import base64, calendar, collections, copy, datetime, hashlib, hmac, itertools, json, pathlib, re, sys, time

from fractions import Fraction

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

import ed25519_curve
import link_extraction
from block_frames import decode_raw_fixture
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

def canonical_b64u_decode(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value) or len(value) % 4 == 1:
        raise ValueError("invalid base64url alphabet or length")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    number = 0
    for char in value:
        number = (number << 6) | alphabet.index(char)
    unused = len(value) * 6 % 8
    if number & ((1 << unused) - 1):
        raise ValueError("nonzero unused base64url bits")
    return (number >> unused).to_bytes(len(value) * 6 // 8, "big")


def log_seconds(value):
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:[0-5][0-9]Z", value, re.ASCII):
        raise ValueError("invalid Log timestamp")
    year = int(value[:4])
    instant = datetime.datetime(
        year if year else 400, int(value[5:7]), int(value[8:10]),
        int(value[11:13]), int(value[14:16]), int(value[17:19]),
        tzinfo=datetime.timezone.utc)
    elapsed = instant - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    return (elapsed.days - (146097 if year == 0 else 0)) * 86400 + elapsed.seconds

def verify_inclusion(block, proof):
    """RFC 6962 audit-path verification (WIST-3 §4).

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
EXAMPLE_SCHEMA = {"label-feed": "feed"}
for example in sorted((ROOT / "examples").glob("*.json")):
    schema_path = ROOT / "schemas" / f"{EXAMPLE_SCHEMA.get(example.stem, example.stem)}.schema.json"
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
    "snapshot-index.json": "index", "snapshot-state.json": "state",
    "registry-update.json": "update", "label.json": "label", "label-feed.json": "feed",
    "label-definition.json": "definition", "dispute.json": "dispute",
    "log-anchor.json": "anchor",
    "mirrors.json": "mirrors",
    "status.json": None,  # not a signed Envelope — plain JSON (WIST-2 §7.1)
    "payload.json": None,  # unsigned: its integrity comes from the Delta's
                           # commitment, not from a signature (WIST-3 §6.1)
}

def load_test_pubkey():
    return b64u_decode(json.loads((ROOT / "vectors" / "wist1" / "keypair.json").read_text())["public_key"])

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

# 2. WIST-1 vectors: recompute ID and verify signature
wist1 = ROOT / "vectors" / "wist1"
if (wist1 / "envelope.json").exists():
    def _dc1():
        env = json.loads((wist1 / "envelope.json").read_text())
        keys = json.loads((wist1 / "keypair.json").read_text())
        canonical = rfc8785.dumps(env["delta"])
        assert canonical == (wist1 / "delta.canonical").read_bytes(), "canonical bytes mismatch"
        delta_id = "sha256:" + hashlib.sha256(canonical).hexdigest()
        assert delta_id == (wist1 / "id.txt").read_text().strip(), "delta ID mismatch"
        pub = Ed25519PublicKey.from_public_bytes(b64u_decode(keys["public_key"]))
        pub.verify(b64u_decode(env["sig"]["value"]), canonical)
    check("vectors:wist1", _dc1)

def _registry_table_defaults():
    """WIST-4 §5's Default column, keyed by identifier, as leading integers.

    A row's Identifier cell names one identifier and its Default cell
    leads with the integer; a row is skipped rather than guessed at when
    that shape does not hold.
    """
    spec = (ROOT / "specs" / "WIST-4-governance.md").read_text()
    section5 = spec.split("## 5. Parameter Registry")[1].split("### 5.1.")[0]
    out = {}
    for line in section5.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 4 or cells[1] == "Identifier":
            continue
        names = re.findall(r"`([a-z0-9_]+)`", cells[1])
        if len(names) == 1:
            m = re.match(r"([\d ]+)", cells[2])
            if m:
                out[names[0]] = int(m.group(1).replace(" ", ""))
        elif len(names) == 2:
            # A "reads as A / B" parenthetical aside may itself contain a
            # "/" (e.g. "600 000 / 300 000 micro-units (reads as 0.60 /
            # 0.30)"); truncating at the first "(" keeps the split to the
            # two primary values the identifiers actually name.
            primary = cells[2].split("(", 1)[0]
            parts = primary.split("/")
            if len(parts) == 2:
                matches = [re.match(r"\s*([\d ]+)", p) for p in parts]
                if all(matches):
                    for name, m in zip(names, matches):
                        out[name] = int(m.group(1).replace(" ", ""))
    return out

def _content_wrapper_octets():
    """The structural octets of `JCS(content)` — the 32 that
    `{"extract":<E>,"links":<L>,"summary":<S>}` puts around its three
    values — measured rather than written down (WIST-1 §3.6)."""
    return len(rfc8785.dumps({"extract": "", "links": {}, "summary": {}})) - \
        len(rfc8785.dumps("")) - 2 * len(rfc8785.dumps({}))

def _combined_content_cap():
    """WIST-1 §3.6's combined `bytes` bound, derived from the three field caps
    in the WIST-4 §5 registry rather than carried as a literal anywhere."""
    caps = _registry_table_defaults()
    return (caps["extract_cap_bytes"] + caps["links_cap_bytes"]
            + caps["summary_cap_bytes"] + _content_wrapper_octets())

def _url_bound():
    """WIST-1 §3.2: the subject URL is octet-bounded (url_cap_bytes).

    The bound is read from the WIST-4 §5 registry rather than written here,
    for the reason `_payload_length` derives its own: a `parameter_change`
    amending `url_cap_bytes` moves the schema's `maxLength` with it, and a
    literal in this file would go on asserting the superseded number.
    """
    cap = _registry_table_defaults()["url_cap_bytes"]
    schema = json.loads((ROOT / "schemas" / "delta.schema.json").read_text())
    url_schema = schema["properties"]["delta"]["properties"]["url"]
    assert url_schema.get("maxLength") == cap, \
        f"delta.url carries no maxLength {cap} first-pass bound"
    env = json.loads((ROOT / "examples" / "delta.json").read_text())
    url = env["delta"]["url"]
    assert len(rfc8785.dumps(url)) <= cap, "example url exceeds url_cap_bytes octets"
    assert len(rfc8785.dumps("https://a.b/")) == 14, "published floor (14) drifted"

check("spec:url-octet-bound", _url_bound)

def _url_bound_twin():
    """Mutation twin: an over-long URL must fail schema validation, and fail
    it *on the length bound* — a rejection by any other keyword would leave
    the octet cap itself unexercised."""
    cap = _registry_table_defaults()["url_cap_bytes"]
    schema = json.loads((ROOT / "schemas" / "delta.schema.json").read_text())
    env = json.loads((ROOT / "examples" / "delta.json").read_text())
    env["delta"]["url"] = "https://example.com/" + "a" * (cap + 52)
    try:
        Draft202012Validator(schema).validate(env)
    except ValidationError as e:
        assert e.validator == "maxLength", \
            f"rejected, but not by the length bound: {e.validator} — {e.message}"
        return
    raise AssertionError(
        f"a {cap + 72}-char url validated — the bound does not discriminate")

check("negative:url-octet-bound", _url_bound_twin)

def _assert_links_valid(payload):
    """WIST-1 §3.6 / WIST-3 §6.1: structural link rules a validator enforces at ingest.

    Caps are read from the WIST-4 §5 registry table (the same source
    `_payload_length` derives from), not hard-coded, so the two checks cannot
    disagree after a `parameter_change` amends either one.

    What is deliberately NOT checked here: whether the declared `urls` prefix
    is the correct one for the page, and whether an omitted remainder would
    have fit `links_cap_bytes`. Both are checkable only against the live page
    never from the Payload alone — an ingest validator sees only the
    already-truncated object.
    """
    import link_extraction
    caps = _registry_table_defaults()
    links = payload["content"]["links"]
    urls, total = links["urls"], links["total"]
    assert len(urls) <= total, "more urls than the declared total"
    assert len(set(urls)) == len(urls), "duplicate link"
    for u in urls:
        assert u.startswith("https://") and "#" not in u, f"non-https or fragment: {u}"
        # WIST-1 §3.6 (WIST1-E12): every entry is a Normalized URL, byte for byte.
        # Byte-wise uniqueness above is not enough on its own — WIST-1 §2 makes
        # sameness byte-identity *of normalizations*, so an unnormalized
        # spelling of a declared link is a second copy of one link that a
        # `set()` sees as two, and it joins against nothing in WIST-3 §7's graph.
        assert link_extraction.normalize_url(u, u) == u, \
            f"entry is not its own Normalized URL: {u}"
        assert len(rfc8785.dumps(u)) <= caps["link_url_cap_bytes"], \
            f"link exceeds link_url_cap_bytes: {u}"
        host = u.split("/", 3)[2].split(":")[0]
        assert host != "example.com" and not host.endswith(".example.com"), \
            f"internal link declared external: {u}"
    links_octets = len(rfc8785.dumps(links))
    assert links_octets <= caps["links_cap_bytes"], "JCS(links) exceeds links_cap_bytes"

def _payload_links_rules():
    """WIST-1 §3.6 / WIST-3 §6.1: structural link rules a validator enforces at ingest."""
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    _assert_links_valid(payload)
    # The shipped example is known, by construction, to declare its full set
    # of external links (nothing was truncated) — an editorial fact about
    # this one Payload, not a general ingest rule, so it is asserted here
    # rather than inside the shared helper.
    links = payload["content"]["links"]
    assert len(links["urls"]) == links["total"], \
        "the shipped example's link set is not fully declared (urls != total)"
    # Derived exactly as `_payload_length` derives it — extract + links +
    # summary caps plus the 32 structural octets of JCS(content) — never
    # written as a literal, so a `parameter_change` to any of the three
    # cannot leave this check asserting a superseded number.
    combined = _combined_content_cap()
    content_octets = len(rfc8785.dumps(payload["content"]))
    assert content_octets <= combined, "JCS(content) exceeds the derived cap"
    delta = json.loads((ROOT / "examples" / "delta.json").read_text())
    assert delta["delta"]["payload"]["bytes"] == content_octets, \
        "declared bytes != JCS(content) octets"
    schema = json.loads((ROOT / "schemas" / "delta.schema.json").read_text())
    assert schema["properties"]["delta"]["properties"]["payload"]["properties"]["bytes"][
        "maximum"] == combined, "schema bytes maximum is not the derived cap"

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
    # The unnormalized spelling of an already-declared link: an uppercased
    # host, so the bytes differ and both `uniqueItems` and the `set()` above
    # pass it, while WIST-1 §2 makes it the same URL as the entry it shadows.
    # It must be rejected by the normalization rule specifically — the
    # duplicate rule cannot see it, which is the whole point of the rule.
    def uppercase_host(u):
        scheme, rest = u.split("://", 1)
        host, _, path = rest.partition("/")
        return f"{scheme}://{host.upper()}/{path}"

    assert rejected(lambda p: add(p, uppercase_host(p["content"]["links"]["urls"][0])),
                     "not its own Normalized URL"), "unnormalized link passed"
    assert rejected(lambda p: add(p, "https://www.example.com/internal"),
                     "internal link declared external"), "internal link passed"
    assert rejected(lambda p: add(p, "https://spec.example.net/wist-1#frag"),
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
    "urls": ["https://example.org/reference", "https://spec.example.net/wist-1",
             "https://example.org/~user"],
}

def _link_extraction_vector():
    """WIST-2's extraction procedure: the vector's (urls, total) must be
    reproduced from the fixture HTML bytes by the reference implementation."""
    import link_extraction
    vec = json.loads((ROOT / "vectors" / "wist2" / "link-extraction.json").read_text())
    assert vec["links_cap_bytes"] == _registry_table_defaults()["links_cap_bytes"], \
        "the vector's links_cap_bytes has drifted from the Parameter Registry default"
    fixture1 = next(c for c in vec["cases"] if c["label"] == "example-delta-page")
    assert fixture1["expected"] == _FIXTURE1_EXPECTED, \
        "fixture 1's expected member is not the hand-pinned 3-URL set"
    cap = vec["links_cap_bytes"]
    # WIST-4 §5's `link_url_cap_bytes` floor: `JCS("https://a.b/")`, the
    # serialization of the shortest Normalized URL that can exist (WIST-1 §2).
    shortest_entry = len(rfc8785.dumps("https://a.b/"))
    assert shortest_entry == 14, "the published shortest-URL floor (14) drifted"
    for case in vec["cases"]:
        html = bytes.fromhex(case["html_hex"])
        urls, total = link_extraction.extract_links(
            html, case["base_url"], case["publisher_domain"])
        member = link_extraction.links_member(urls, total, cap)
        assert member == case["expected"], f"{case['label']}: {member} != {case['expected']}"

        # Two properties of the *published* member, asserted against the
        # budget rather than against the module that produced it — so a
        # generator that truncated wrongly and wrote its own answer down
        # still fails here (WIST-1 §3.6, WIST-2 §11).
        expected = case["expected"]
        octets = len(rfc8785.dumps(expected))
        assert octets <= cap, \
            f"{case['label']}: JCS(expected) is {octets} octets, over the {cap}-octet budget"
        if len(expected["urls"]) < expected["total"]:
            # Maximality, proved without knowing which URL came next:
            # appending any entry at all costs one `,` plus at least the 14
            # octets of the shortest Normalized URL, so a headroom below
            # that admits no longer prefix whatever the survivors are.
            headroom = cap - octets
            assert headroom < 1 + shortest_entry, (
                f"{case['label']}: {headroom} octets of headroom would hold another "
                f"entry ({1 + shortest_entry} at minimum) — the prefix is not maximal")

check("vectors:wist2-link-extraction", _link_extraction_vector)

def _link_extraction_twin():
    """Mutation twin: a perturbed fixture must not reproduce."""
    import link_extraction
    vec = json.loads((ROOT / "vectors" / "wist2" / "link-extraction.json").read_text())
    case = vec["cases"][0]
    html = bytes.fromhex(case["html_hex"]) + b'<a href="https://mutant.example.io/x">m</a>'
    urls, total = link_extraction.extract_links(
        html, case["base_url"], case["publisher_domain"])
    member = link_extraction.links_member(urls, total, vec["links_cap_bytes"])
    assert member != case["expected"], "an appended link changed nothing — extraction is blind"

check("negative:wist2-link-extraction", _link_extraction_twin)

def _text_extraction_vector():
    """WIST-2 §12's text extraction: every fixture must be reproduced from
    its inputs by the recommended derivation."""
    import link_extraction
    vec = json.loads((ROOT / "vectors" / "wist2" / "text-extraction.json").read_text())
    assert len(vec["extraction"]) >= 2
    for case in vec["extraction"]:
        got = link_extraction.extract_text(bytes.fromhex(case["html_hex"]))
        assert got == case["expected"], f"{case['label']}: {got!r} != {case['expected']!r}"

check("vectors:wist2-text-extraction", _text_extraction_vector)

def _page_keyset_vector():
    return json.loads((ROOT / "vectors" / "wist2" / "page-keyset.json").read_text())

def _page_keyset_resolve(declarations, generated_at_s, signer):
    """WIST-2 §3.2: the Declaration with the greatest sealed_at not later
    than generated_at, then the first Block sealed after it that seals one;
    where a Block seals several, the highest seq's, as WIST-1 §5.2 resolves
    it at that height."""
    current, nxt = None, None
    for d in declarations:
        rank = (d["sealed_at_s"], d["seq"])
        if d["sealed_at_s"] <= generated_at_s and (current is None or rank > (current["sealed_at_s"], current["seq"])):
            current = d
        if d["sealed_at_s"] > generated_at_s and (nxt is None or (-d["sealed_at_s"], d["seq"]) > (-nxt["sealed_at_s"], nxt["seq"])):
            nxt = d
    current_keys = current["keys"] if current else []
    next_keys = nxt["keys"] if nxt else []
    under = "current" if signer in current_keys else "next" if signer in next_keys else None
    return current_keys, next_keys, under

def _wist2_page_keyset():
    """WIST-2 §3.2: a sealed Page verifies under the Key Set current at its
    generated_at or under the first Declaration sealed after it."""
    v = _page_keyset_vector()
    saw = set()
    for case in v["cases"]:
        name = case["name"]
        by_page = {pg["page"]: pg for pg in case["pages"]}
        assert [r["page"] for r in case["expected"]] == [pg["page"] for pg in case["pages"]], \
            f"{name}: expected rows out of order"
        for row in case["expected"]:
            pg = by_page[row["page"]]
            current, nxt, under = _page_keyset_resolve(
                case["declarations"], pg["generated_at_s"], pg["signer"])
            assert current == row["current_keys"], f"{name} page {pg['page']}: current Key Set"
            assert nxt == row["next_keys"], f"{name} page {pg['page']}: next Key Set"
            assert under == row["verifies_under"], f"{name} page {pg['page']}: resolution"
            assert row["verifies"] == (under is not None), f"{name} page {pg['page']}: verifies"
            saw.add(under)
            if not current and under == "next":
                saw.add("before first contact")
            if current and pg["signer"] not in current and under == "next":
                saw.add("between rotation and seal")
    assert saw >= {"current", "next", None, "before first contact", "between rotation and seal"}, \
        f"the vector must exercise both resolutions, a WIST2-E04, a Page before first contact and one between a rotation and its seal; saw {saw}"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-2-site-publication.md").read_text())
    for marker in (
            "**first** Block sealed after `generated_at` that seals an applicable Declaration of the domain",
            "the Key Set is the highest `seq`'s, exactly as at a height",
            "A Page that verifies under neither source is `WIST2-E04`"):
        assert marker in prose, f"§3.2 does not state: {marker!r}"
check("vectors:wist2-page-keyset", _wist2_page_keyset)

def _wist2_page_keyset_twin():
    """The check above must notice a Page resolved to a Declaration two seals
    ahead, and one resolved to the current Key Set alone."""
    v = _page_keyset_vector()
    case = next(c for c in v["cases"] if c["name"] == "page cut between a rotation and its sealing")
    two_ahead = next(pg for pg in case["pages"] if pg["signer"] == "k3")
    _, _, under = _page_keyset_resolve(case["declarations"], two_ahead["generated_at_s"], two_ahead["signer"])
    assert under is None, "recomputation admits a key from the second Declaration after generated_at"
    late = next(pg for pg in case["pages"] if pg["signer"] == "k2")
    _, _, under = _page_keyset_resolve(
        [d for d in case["declarations"] if d["sealed_at_s"] <= late["generated_at_s"]],
        late["generated_at_s"], late["signer"])
    assert under is None, "recomputation verified the Page without the Declaration sealed after it"
    same_block = next(c for c in v["cases"] if c["name"] == "two rotations sealed in one block")
    lowest = min((d for d in same_block["declarations"] if d["sealed_at_s"] == 200), key=lambda d: d["seq"])
    for pg in same_block["pages"]:
        _, _, under = _page_keyset_resolve(same_block["declarations"], pg["generated_at_s"], pg["signer"])
        assert (pg["signer"] in lowest["keys"]) == (under is None), \
            "recomputation reads the lowest seq of a Block rather than its Key Set"
check("negative:wist2-page-keyset", _wist2_page_keyset_twin)


def _state_tuple_encoding():
    """WIST-3 §7: the tuple encoding is normative — arity and member types
    pinned per kind in the schema, the digest recomputable from the example,
    and the prose owning the encoding rather than delegating it."""
    schema = json.loads((ROOT / "schemas" / "snapshot-state.schema.json").read_text())
    entries_schema = schema["properties"]["state"]["properties"]["entries"]["items"]
    variants = entries_schema.get("oneOf")
    assert variants, "entries items must be a oneOf of per-kind tuple shapes"
    kinds = set()
    for v in variants:
        assert v.get("items") is False, f"tuple arity unpinned: {v['prefixItems'][0]}"
        kinds.add(v["prefixItems"][0]["const"])
        assert all("type" in m or "const" in m or "oneOf" in m or "enum" in m
                   for m in v["prefixItems"]), f"untyped member in {v['prefixItems'][0]}"
    expected = {"aggregator_key", "declaration", "parameter", "recovery_window",
                "suffix_list", "withdrawal", "label", "dispute", "record"}
    assert kinds == expected, f"kinds mismatch: {kinds ^ expected}"
    state = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())["state"]
    digest = "sha256:" + hashlib.sha256(
        b"".join(sorted(rfc8785.dumps(e) for e in state["entries"]))).hexdigest()
    manifest = json.loads((ROOT / "examples" / "snapshot-manifest.json").read_text())
    assert digest == manifest["manifest"]["state"]["state_digest"], \
        "example state entries do not reproduce the manifest state_digest"
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "Field-level encodings ride with the schema" not in prose, \
        "the encoding must be normative, not delegated to the schema"
    for marker in ("in exactly the order the table gives",
                   "appears exactly once in the digest preimage"):
        assert marker in prose, f"missing normative encoding sentence: {marker!r}"

check("spec:wist3-state-encoding", _state_tuple_encoding)


def _state_tuple_encoding_twin():
    schema = json.loads((ROOT / "schemas" / "snapshot-state.schema.json").read_text())
    validator = Draft202012Validator(schema)
    good = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
    bad = copy.deepcopy(good)
    bad["state"]["entries"][1].append("extra-member")
    try:
        validator.validate(bad)
    except ValidationError:
        pass
    else:
        raise AssertionError("over-arity record tuple validated")
    bad2 = copy.deepcopy(good)
    bad2["state"]["entries"][0][3] = "0"
    try:
        validator.validate(bad2)
    except ValidationError:
        pass
    else:
        raise AssertionError("string height validated where integer is pinned")

check("negative:wist3-state-encoding", _state_tuple_encoding_twin)


def _recovery_queue_disposition():
    """WIST-1 §5.2 / WIST-4 §5: the recovery window and the inclusion
    ceiling were two MUSTs one Aggregator could not both keep, and the
    queue's disposition at window end was unstated."""
    w1 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-delta-format.md").read_text())
    w4 = re.sub(r"\s+", " ",
                (ROOT / "specs" / "WIST-4-governance.md").read_text())
    assert "revalidated against the signing bindings and scope of that chain's newest Declaration" in w1
    assert w1.count("WIST1-E13") >= 2, "E13 must appear in §5.2 and the §7 registry"
    assert "queued under WIST-1 §5.2" in w4, "the §5 ceiling needs the recovery carve-out"

check("spec:recovery-queue-disposition", _recovery_queue_disposition)


def _service_origin():
    """WIST-2/WIST-3: the Ingest and status endpoints must resolve from the
    Log Anchor's log_id, not from an undefined <aggregator> placeholder —
    otherwise the publisher-to-aggregator bootstrap is unspecified."""
    w2 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-2-site-publication.md").read_text())
    w3 = re.sub(r"\s+", " ",
                (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "https://<log_id>/ingest" in w2
    assert "https://<log_id>/status/<domain>" in w2
    assert "<aggregator>/status" not in w2, "undefined <aggregator> placeholder survives"
    assert "POST <ingest endpoint>" not in w2
    assert "Service Origin" in w3 and "https://<log_id>/" in w3

check("spec:service-origin", _service_origin)


def _wist4_error_registry():
    """WIST-4 §7 carries every code the document uses, the retired audit
    codes are gone, and a rejected act never invalidates its Block."""
    w4 = (ROOT / "specs" / "WIST-4-governance.md").read_text()
    assert "## 7. Error Registry" in w4
    assert "## 8. Security Considerations" in w4
    assert "## 9. Privacy Considerations" in w4
    assert "## 10. Conformance Checklist" in w4
    retired = re.search(r"The codes `WIST4-E01`[^.]*were registered by the Auditor[^.]*\.", w4)
    assert retired, "§7 no longer records which codes the Auditor role took with it"
    codes = re.findall(r"WIST4-E(\d{2})", w4.replace(retired.group(0), ""))
    assert sorted(set(codes)) == ["03", "04", "06", "11"], sorted(set(codes))
    registry = w4.split("## 7. Error Registry")[1].split("## 8.")[0]
    assert sorted(set(re.findall(r"\| WIST4-E(\d{2}) ", registry))) == ["03", "04", "06", "11"]
    assert "never invalidates the containing Block" in re.sub(r"\s+", " ", w4)

check("spec:wist4-error-registry", _wist4_error_registry)


def _governance_acts_count():
    """WIST-4 §2's prose count of governance acts must equal the schema's
    action enum, and §3 must name each act the enum carries."""
    w4 = re.sub(r"\s+", " ",
                (ROOT / "specs" / "WIST-4-governance.md").read_text())
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    action_enum = schema["properties"]["update"]["properties"]["action"]["enum"]
    words = {3: "three", 4: "four", 5: "five", 6: "six"}
    assert f"the {words[len(action_enum)]} governance acts" in w4, \
        f"prose count does not match the {len(action_enum)}-action enum"
    acts = w4.split("## 3. Governance Acts")[1].split("## 4.")[0]
    for action in action_enum:
        assert f"`{action}`" in acts, f"§3 does not describe {action}"

check("spec:governance-acts-count", _governance_acts_count)

_BASE = "https://example.com/blog/post-1"

# Independent of the generator: a hand-written table run through
# link_extraction.normalize_url and .extract_links directly, so a bug that
# both derives a vector fixture AND checks it the same wrong way (the
# round-trip `vectors:wist2-link-extraction` above cannot catch that class)
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

# (label, tiny literal HTML, expected extracted urls) — exercises the WIST-2
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
    # WIST-2 §11 step 4 reads "&#NNN;" as decimal — ASCII digits. `_CHAR_REF`
    # scopes `\d` with `re.ASCII`, so a reference spelled with non-ASCII
    # decimal digits (Arabic-Indic "٦٥" = 65 below) matches none of the
    # three alternatives and is left exactly as written, literal `#`
    # included. That surviving `#` then reads as RFC 3986's fragment
    # delimiter, and WIST-1 §2 normalization drops the fragment — truncating
    # the extracted URL's query at the `&` — rather than the link reading
    # `?y=Az` the way a wrongly-decoded `&#٦٥;` (65 = 'A') would produce,
    # with no `#` left over to start a fragment at all.
    ("non-ASCII decimal digits in a numeric reference are not decoded",
     ('<a href="https://example.org/x?y=&#٦٥;z">t</a>'
      .encode("utf-8")), ["https://example.org/x?y=&"]),
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
    ships, and WIST-4 §5.1 covers it normatively for what an implementation adds.
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
# `vectors/wist3/block.json` are different locations and are declared separately.
COVERAGE_ASSERTED = {"payload:commitment"}

SALTED_COMMITMENTS = {          # (schema file, JSON path) -> proving check
    ("delta.schema.json",
     "properties/delta/properties/payload/properties/commitment"): "payload:commitment",
}

SALTED_COMMITMENT_VALUES = {
    ("vectors/wist1/delta-clock-time.json", "commitment"): "payload:commitment",
    ("vectors/wist1/payload-fields.json", "commitment"): "payload:commitment",
    ("vectors/wist1/payload-links.json", "commitment"): "payload:commitment",
    ("vectors/wist1/delta-cap-time.json", "commitment"): "payload:commitment",    # (ROOT-relative file, key) -> proving check
    ("examples/delta.json", "commitment"): "payload:commitment",
    ("examples/block.json", "commitment"): "payload:commitment",
    ("vectors/wist1/envelope.json", "commitment"): "payload:commitment",
    ("vectors/wist1/recovery-settlement.json", "commitment"): "payload:commitment",
    ("vectors/wist1/recovery-bindings.json", "commitment"): "payload:commitment",
    ("vectors/wist1/delta.canonical", "commitment"): "payload:commitment",
    ("vectors/wist3/block.json", "commitment"): "payload:commitment",
    ("vectors/wist3/block-frames.json", "commitment"): "payload:commitment",
    ("vectors/wist1/declaration-fields.json", "commitment"): "payload:commitment",
    ("vectors/wist1/delta-diagnostics.json", "commitment"): "payload:commitment",
    ("vectors/wist1/delta-fields.json", "commitment"): "payload:commitment",
    ("vectors/wist2/declaration-refresh.json", "commitment"): "payload:commitment",
    ("vectors/wist1/delta-attribution.json", "commitment"): "payload:commitment",
    ("vectors/wist1/recovery-scope.json", "commitment"): "payload:commitment",
    ("vectors/wist3/timestamps.json", "commitment"): "payload:commitment",
    ("vectors/multilog/dedup.json", "commitment"): "payload:commitment",
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
    """Source file, instance path and string value for each matching suffix."""
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
                out.add((str(path.relative_to(ROOT)), tuple(trail), node))
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
        for rel, trail, got in values:
            if (schema_file == "delta.schema.json" and rel == "vectors/wist1/delta-fields.json"
                    and trail == ("cases", "envelope", "delta", "payload", "commitment")
                    and got.endswith("\n") and got[:-1] in recomputed):
                assert not re.fullmatch(field["pattern"], got)
                continue
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

def _multilog_commitment():
    """The multi-Log dedup vector carries its own Delta and Payload, so its
    commitment is a second one this check must recompute rather than compare
    against the example's — a vector whose Payload did not reproduce its own
    Delta would otherwise be caught only as an inequality with an unrelated
    Delta's value."""
    v = json.loads((ROOT / "vectors" / "multilog" / "dedup.json").read_text())
    payload, delta = v["payload"], v["delta"]["delta"]
    got = _commit(payload["salt"], payload["content"])
    assert got == delta["payload"]["commitment"], \
        "the multi-Log vector's Payload does not reproduce its Delta's commitment"
    return got

def _payload_commitment():
    payload, delta = _load_payload_and_delta()
    assert delta["payload"]["alg"] == "HMAC-SHA256", "commitment algorithm is not HMAC-SHA256"
    assert len(b64u_decode(payload["salt"])) >= 16, "salt is shorter than 128 bits (WIST-1 §3.6)"
    expected = _commit(payload["salt"], payload["content"])
    assert expected == delta["payload"]["commitment"], \
        "the Payload does not reproduce the Delta's commitment"
    recomputed = {expected, _multilog_commitment()}
    link_vectors = json.loads((ROOT / "vectors/wist1/payload-links.json").read_text())
    for case in link_vectors["cases"]:
        content = case["payload"]
        actual = _commit(content["salt"], content["content"])
        assert actual == case["envelope"]["delta"]["payload"]["commitment"]
        recomputed.add(actual)
    field_vectors = json.loads((ROOT / "vectors/wist1/payload-fields.json").read_text())
    for case in field_vectors["cases"]:
        preimage = case["preimage"]
        actual = _commit(preimage["salt"], preimage["content"])
        assert actual == case["envelope"]["delta"]["payload"]["commitment"]
        recomputed.add(actual)
    cap_vectors = json.loads((ROOT / "vectors/wist1/delta-cap-time.json").read_text())
    for obj in cap_vectors["objects"].values():
        content = obj["payload"]
        actual = _commit(content["salt"], content["content"])
        assert actual == obj["envelope"]["delta"]["payload"]["commitment"]
        recomputed.add(actual)

    # Every shipped copy of this commitment is recomputed here, not argued for
    # transitively, so that each declaration naming this check is one this check
    # actually verified.
    covered_values = set()
    for rel, key in _declared_values_for("payload:commitment"):
        values = _values_at(rel, key)
        assert values, f"{rel}: no {key!r} to recompute, but it is declared here"
        for got in values:
            if rel == "vectors/wist1/delta-fields.json" and got.endswith("\n"):
                assert got[:-1] in recomputed
                continue
            assert got in recomputed, \
                f"{rel}: {key} = {got[:28]}… is not HMAC(salt, JCS(content))"
    # Located, not read off the declarations, so an undeclared copy also fails.
    covered_values = _locate_values(lambda v: v in recomputed)

    _assert_schema_instances("payload:commitment", recomputed)
    covered_schema = _locate_schema_fields("payload:commitment")

    _assert_coverage("payload:commitment", covered_values, covered_schema)
check("payload:commitment", _payload_commitment)

def _payload_length():
    """`bytes`, and every cap it is bounded by, counted in JCS octets.

    WIST-1 §3.6 measures every cap as octets of a JCS serialization, never
    as characters and never as code points, because a Consumer uses them to
    bound a fetch. The combined bound is derived rather than independent:
    JCS(content) is `{"extract":<E>,"links":<L>,"summary":<S>}`, so its 32
    octets of structure sit on top of the three field caps. Deriving it here
    rather than hard-coding the total is what keeps the schema's number and
    WIST-1 §3.6's arithmetic from drifting apart again.
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
    wrapper = _content_wrapper_octets()
    assert wrapper == 32, f"JCS(content) structure is {wrapper} octets, not the 32 WIST-1 §3.6 states"
    combined = _combined_content_cap()
    assert combined == e_cap + lk_cap + s_cap + wrapper, \
        "the combined cap helper no longer derives WIST-1 §3.6's sum"

    e = len(rfc8785.dumps(content["extract"]))
    lk = len(rfc8785.dumps(content["links"]))
    s = len(rfc8785.dumps(content["summary"]))
    assert e <= e_cap, f"JCS(extract) is {e} octets, over the {e_cap}-octet cap (WIST-1 §3.6)"
    assert lk <= lk_cap, f"JCS(links) is {lk} octets, over the {lk_cap}-octet cap (WIST-1 §3.6)"
    assert s <= s_cap, f"JCS(summary) is {s} octets, over the {s_cap}-octet cap (WIST-1 §3.6)"
    assert n <= combined, f"JCS(content) is {n} octets, over the {combined}-octet cap (WIST-1 §3.6)"
    assert e + lk + s + wrapper == n, "the JCS lengths do not add up; the derivation is wrong"

    schema = json.loads((ROOT / "schemas" / "delta.schema.json").read_text())
    declared = schema["properties"]["delta"]["properties"]["payload"][
        "properties"]["bytes"]["maximum"]
    assert declared == combined, (
        f"delta.schema.json bounds payload.bytes at {declared}, but "
        f"{e_cap} + {lk_cap} + {s_cap} + {wrapper} = {combined} (WIST-1 §3.6)")
    spec = (ROOT / "specs" / "WIST-1-delta-format.md").read_text()
    assert str(combined) in spec, f"WIST-1 §3.6 does not state the {combined}-octet bound"
    assert "34816" not in spec, "WIST-1 still cites the old combined cap, which omitted the JCS wrapper"
    assert "34839" not in spec, "WIST-1 still cites the pre-links combined cap"
check("payload:length", _payload_length)

def _payload_tamper():
    """One mutated octet MUST break the commitment (WIST-1 §3.6).

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

    def flip_last_octet(b64u: str) -> str:
        # The salt is base64url, where 22 characters carry 132 bit-slots for the
        # salt's 128 bits: the final character's low 4 bits are padding that
        # decoding discards, so distinct characters there can decode to identical
        # octets. Mutating the octets is what this check claims to do.
        raw = bytearray(b64u_decode(b64u))
        raw[-1] ^= 0x01
        return base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")

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
    m["salt"] = flip_last_octet(m["salt"])
    mutations["salt"] = m

    for label, mutated in mutations.items():
        assert mutated != payload, f"{label}: the mutation did not change the Payload"
        assert _commit(mutated["salt"], mutated["content"]) != committed, \
            f"{label}: a mutated Payload still reproduces the commitment"
check("negative:payload-tamper", _payload_tamper)

# 3. WIST-3 vectors: recompute merkle root and verify inclusion proof
wist3 = ROOT / "vectors" / "wist3"
if (wist3 / "block.json").exists():
    def _dc3():
        block = json.loads((wist3 / "block.json").read_text())
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
        proof = json.loads((wist3 / "inclusion-proof.json").read_text())
        verify_inclusion(block, proof)
    check("vectors:wist3", _dc3)

def _block_checks():
    block = json.loads((ROOT / "examples" / "block.json").read_text())
    cp = json.loads((ROOT / "examples" / "checkpoint.json").read_text())
    assert block["header"]["entry_count"] == len(block["entries"]), "entry_count mismatch"
    # Block Hash definition lives in WIST-3 §3.1: header only.
    signed_bytes = rfc8785.dumps(block["header"])
    block_hash = "sha256:" + hashlib.sha256(signed_bytes).hexdigest()
    assert cp["checkpoint"]["block_hash"] == block_hash, "checkpoint does not bind block"
    assert cp["checkpoint"]["block_number"] == block["header"]["block_number"], "block_number mismatch"
    Ed25519PublicKey.from_public_bytes(load_test_pubkey()).verify(
        b64u_decode(block["sig"]["value"]), signed_bytes)
check("blockhash+binding+entrycount", _block_checks)

RECORD_FIELDS = ["url", "publisher", "delta_id", "observed_at"]

def _content_digest(records):
    """WIST-3 §7: SHA-256 over the ascending-octet-order concatenation of JCS."""
    return "sha256:" + hashlib.sha256(
        b"".join(sorted(rfc8785.dumps(r) for r in records))).hexdigest()

def _snapshot_content_digest():
    """WIST-3 §7's semantic-equivalence digest, recomputed from its own records.

    The point of the digest is that two parties rebuilding the same Log prefix
    agree without producing byte-identical SQLite or Parquet, so the check has
    to hold two properties at once: the digest is a function of the record set
    alone (order-independent, storage-independent), and its preimage contains
    no page content — otherwise a Payload withdrawn after publication would
    make the digest permanently unrecomputable, which is when it matters most.
    """
    v = json.loads((ROOT / "vectors" / "wist3" / "snapshot-records.json").read_text())
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
    # one Snapshot; WIST-3 §8 has a Consumer check them against each other.
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
    # on it undetected. `observed_at` is what an `attest` moves, exactly the
    # case a record-identity-only digest would miss.
    import copy
    for field, other in (("url", "https://example.com/blog/post-9"),
                         ("publisher", "other.example.com"),
                         ("delta_id", "sha256:" + "0" * 64),
                         ("observed_at", "2026-08-02T12:00:01Z")):
        mutated = copy.deepcopy(records)
        assert mutated[0][field] != other, f"{field}: the mutation changes nothing"
        mutated[0][field] = other
        assert _content_digest(mutated) != digest, \
            f"the digest does not depend on {field}"
    assert _content_digest(records[:1]) != digest, \
        "dropping a record leaves the digest unchanged"
    assert _content_digest([]) == "sha256:" + hashlib.sha256(b"").hexdigest(), \
        "an empty live set does not digest the empty octet string (§7)"

    spec = (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text()
    assert "semantic equivalence" in spec, "WIST-3 §7 no longer states the rebuild rule"
    for field in RECORD_FIELDS:
        assert f'"{field}": r.{field}' in spec, \
            f"WIST-3 §7's record tuple no longer names {field}"
    for stale in ("bit-identical", "byte-identical tiers"):
        assert stale not in spec, f"WIST-3 still claims byte-reproducible Snapshots: {stale!r}"
check("snapshot:content-digest", _snapshot_content_digest)

def _assert_links_materialization(vec_links):
    """WIST-3 §7: `tier1/links.parquet` is `(source_url, target_url, position)`
    per declared link, derived from the live record's Payload alone.

    Factored so the twin below runs this exact assertion over a perturbed
    tuple list and proves it raises — the pattern
    `_assert_links_valid`/`negative:payload-links-rules` uses. A twin that
    re-derives `expected` and compares it against the mutation instead is
    vacuous: that comparison is already entailed by the positive check
    passing, and it stays true however weak the positive check becomes.
    """
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    delta = json.loads((ROOT / "examples" / "delta.json").read_text())["delta"]
    expected = [
        {"source_url": delta["url"], "target_url": u, "position": i}
        for i, u in enumerate(payload["content"]["links"]["urls"])]
    assert vec_links == expected, "links materialization != derivation from Payload"

def _snapshot_links_materialization():
    """WIST-3 §7: the links materialization is a pure function of live
    records' Payloads — recompute it from examples/payload.json."""
    vec = json.loads((ROOT / "vectors" / "wist3" / "snapshot-records.json").read_text())
    _assert_links_materialization(vec["links"])
    manifest = json.loads((ROOT / "examples" / "snapshot-manifest.json").read_text())
    paths = {f["path"]: f["tier"] for f in manifest["manifest"]["files"]}
    assert paths.get("tier1/links.parquet") == 1, "links.parquet missing from manifest"
    assert "tier0/embeddings.parquet" not in paths, \
        "embeddings in the manifest: the protocol carries none (ADR-0009)"

check("spec:snapshot-links", _snapshot_links_materialization)

def _snapshot_links_twin():
    """Mutation twin: a shifted `position` must be rejected by the same
    helper the positive check runs, with the same message."""
    vec = json.loads((ROOT / "vectors" / "wist3" / "snapshot-records.json").read_text())
    mutated = json.loads(json.dumps(vec["links"]))
    assert mutated, "vector carries no link tuples to mutate"
    mutated[0]["position"] += 1
    try:
        _assert_links_materialization(mutated)
    except AssertionError as e:
        assert "links materialization != derivation from Payload" in str(e), \
            f"rejected, but not by its target rule: {e}"
        return
    raise AssertionError("a shifted position still matched — the check is blind")

check("negative:snapshot-links", _snapshot_links_twin)

def _chain_vector():
    return json.loads((ROOT / "vectors" / "wist3" / "chain-materialization.json").read_text())

def _chain_replay(deltas):
    """WIST-1 §3.5 / WIST-3 §7, recomputed independently of the generator:
    a Delta is applied only when its prev is the chain tip the state
    carries for (publisher, url) — absent for a chain's first Delta —
    and is otherwise ignored, whether it forks a sealed chain or names a
    prev nothing sealed; an ignored Delta never becomes a tip."""
    tips, ignored = {}, []
    for i, d in enumerate(deltas):
        key = (d["publisher"], d["url"])
        if d.get("eligible", True) is False or d["prev"] != tips.get(key):
            ignored.append(i)
            continue
        tips[key] = d["id"]
    return ignored, [{"publisher": p, "url": u, "delta": t} for (p, u), t in sorted(tips.items())]

def _dc3_chain_materialization():
    """WIST-3 §7: which sealed Deltas a replayer applies, and the chain tips."""
    v = _chain_vector()
    labels = set()
    for case in v["cases"]:
        labels.add(case["label"])
        ignored, tips = _chain_replay(case["deltas"])
        assert ignored == case["ignored_indices"], \
            f"{case['label']}: recomputed ignored {ignored}, vector says {case['ignored_indices']}"
        assert tips == sorted(case["tips"], key=lambda t: (t["publisher"], t["url"])), \
            f"{case['label']}: recomputed tips {tips}, vector says {case['tips']}"
        for i in ignored:
            assert case["deltas"][i]["id"] not in {t["delta"] for t in tips}, \
                f"{case['label']}: an ignored Delta became a tip"
    for needed in ("linear chain", "fork ignored", "unsealed prev ignored",
                   "successor of an ignored delta ignored", "chain continues through delete",
                   "second first delta ignored", "publishers chain separately",
                   "ineligible delta ignored with its successor",
                   "ineligible first delta leaves no tip"):
        assert needed in labels, f"vector lacks the {needed} case"
    ineligible = [c for c in v["cases"] if any(d.get("eligible") is False for d in c["deltas"])]
    assert ineligible and all(
        i in c["ignored_indices"] for c in ineligible
        for i, d in enumerate(c["deltas"]) if d.get("eligible") is False)
    prose3 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    prose1 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-delta-format.md").read_text())
    assert "is not the chain tip the state carries" in prose3, \
        "WIST-3 §7 does not state the tip rule"
    assert "The same disposition covers every other WIST-1 §7 Delta check" in prose3, \
        "WIST-3 §3.3 does not state the ineligible-Delta disposition"
    assert "never sealed ahead of the Delta its `prev` names" in prose1, \
        "WIST-1 §3.5 does not state the sealing order"
check("vectors:wist3-chain-materialization", _dc3_chain_materialization)

def _dc3_chain_materialization_twin():
    """The check above must notice an unsealed prev treated as a tip."""
    v = _chain_vector()
    case = next(c for c in v["cases"] if c["label"] == "unsealed prev ignored")
    deltas = json.loads(json.dumps(case["deltas"]))
    orphan = deltas[case["ignored_indices"][0]]
    orphan["prev"] = deltas[0]["id"]
    ignored, tips = _chain_replay(deltas)
    assert ignored == [] and tips[0]["delta"] == orphan["id"], \
        "recomputation is blind to the prev a Delta names"
    case = next(c for c in v["cases"] if c["label"] == "fork ignored")
    deltas = json.loads(json.dumps(case["deltas"]))
    del deltas[1]
    assert _chain_replay(deltas)[0] == [], "recomputation is blind to which Delta sealed first"
check("negative:wist3-chain-materialization", _dc3_chain_materialization_twin)

def _materialization_preference(host, self_declared, candidates, *, farthest=False, descending=False,
                                raw_suffix=False):
    if self_declared:
        return host if host in candidates else None
    def ancestor(c):
        return host.endswith(c) and host != c if raw_suffix else host.endswith("." + c)
    ancestors = [c for c in candidates if ancestor(c)]
    if ancestors:
        return min(ancestors, key=len) if farthest else max(ancestors, key=len)
    if not candidates:
        return None
    return max(candidates) if descending else min(candidates)

def _dc3_materialization_preference():
    """WIST-3 §7: one record per URL — the self-declared host's own, else the
    nearest ancestor Publisher's, else the least non-ancestor domain."""
    v = json.loads((ROOT / "vectors" / "wist3" / "materialization-preference.json").read_text())
    labels = set()
    for case in v["cases"]:
        labels.add(case["label"])
        assert _materialization_preference(case["host"], case["self_declared"], case["candidates"]) == \
            case["materialized"], case["label"]
        assert case["materialized"] is None or case["materialized"] in case["candidates"], case["label"]
    for needed in ("self declaration prevails", "self declaration excludes parents without an own record",
                   "nearest ancestor", "ancestor over non ancestor", "non ancestors in octet order",
                   "label boundary is not a suffix match"):
        assert needed in labels, f"vector lacks the {needed} case"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "The record materialized is then the **nearest ancestor**'s" in prose
    assert "among such Publishers the least domain in ascending octet order does" in prose
    assert "return when the preferred record leaves" in prose
check("vectors:wist3-materialization-preference", _dc3_materialization_preference)

def _dc3_materialization_preference_twin():
    v = json.loads((ROOT / "vectors" / "wist3" / "materialization-preference.json").read_text())
    by_label = {c["label"]: c for c in v["cases"]}
    for label, flag in (("nearest ancestor", "farthest"), ("non ancestors in octet order", "descending"),
                        ("label boundary is not a suffix match", "raw_suffix")):
        case = by_label[label]
        assert _materialization_preference(case["host"], case["self_declared"], case["candidates"],
                                           **{flag: True}) != case["materialized"], \
            f"the {flag} reading must differ on {label}"
check("negative:wist3-materialization-preference", _dc3_materialization_preference_twin)

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

# Transcribed verbatim from the Certificate Transparency reference
# implementation (transparency-dev/merkle: testonly/constants.go leaf
# inputs and RootHashes, rfc6962/rfc6962_test.go leaf/node cases) — the
# published known answers for RFC 6962's hashing, which WIST-3 §4 adopts.
_CT_LEAF_INPUTS = ["", "00", "10", "2021", "3031", "40414243",
                   "5051525354555657", "606162636465666768696a6b6c6d6e6f"]
_CT_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]

def _merkle_ct_reference():
    """External known-answer anchor for tools/merkle.py: the exhaustive
    property test above proves
    generation and verification agree with *each other*, but two sides of
    one authorship can share one misreading — only answers published by an
    independent implementation prove the hashes themselves are RFC 6962's.
    The empty-tree constant is asserted too, because WIST-3 deviates from
    it deliberately (a heartbeat Block's root is SHA-256(0x00), see
    vectors/wist3/empty-block.json) and the deviation only stays honest
    while the reference value it deviates from is pinned beside it.
    """
    assert leaf_hash(b"").hex() == \
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    assert leaf_hash(b"L123456").hex() == \
        "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56"
    assert node_hash(b"N123", b"N456").hex() == \
        "aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb"
    assert hashlib.sha256(b"").hexdigest() == \
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    leaves = [leaf_hash(bytes.fromhex(h)) for h in _CT_LEAF_INPUTS]
    for n in range(1, 9):
        got = merkle_root(leaves[:n]).hex()
        assert got == _CT_ROOTS[n - 1], \
            f"MTH(D[{n}]) drifted from the CT reference: {got}"
check("merkle:ct-reference-vectors", _merkle_ct_reference)

def _parameter_vector():
    return json.loads((ROOT / "vectors" / "wist4" / "parameter-in-force.json").read_text())

def _value_in_force(default, changes, t_s, inclusive=True):
    """WIST-4 §5: greatest effective_at at or before t_s, Log order breaking
    an equal pair; the default where nothing is in force."""
    best = None
    for i, c in enumerate(changes):
        live = c["effective_at_s"] <= t_s if inclusive else c["effective_at_s"] < t_s
        if not live:
            continue
        key = (c["effective_at_s"], c["block_number"], c["entry_index"])
        if best is None or key > best[0]:
            best = (key, i, c["value"])
    return (default, None) if best is None else (best[2], best[1])

def _dc4_parameter_in_force():
    """WIST-4 §5: which amendment is in force at an instant."""
    v = _parameter_vector()
    labels = set()
    for case in v["cases"]:
        labels.add(case["label"])
        order = [(c["block_number"], c["entry_index"]) for c in case["changes"]]
        assert order == sorted(order), f"{case['label']}: changes not in Log order"
        for c in case["changes"]:
            assert c["effective_at_s"] - c["sealed_at_s"] >= 7 * 86400, \
                f"{case['label']}: an amendment inside the grace period"
        for q in case["queries"]:
            value, source = _value_in_force(case["default"], case["changes"], q["t_s"])
            assert (value, source) == (q["value"], q["from_index"]), \
                f"{case['label']} at {q['t_s']}: recomputed {(value, source)}, vector says {(q['value'], q['from_index'])}"
    for needed in ("effective at is inclusive", "later effective at prevails whatever sealed first",
                   "equal effective at across blocks", "equal effective at in one block"):
        assert needed in labels, f"vector lacks the {needed} case"
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-4-governance.md").read_text())
    for marker in ("in force at every instant T at or after its `effective_at`, the endpoint included",
                   "the one later in Log order (WIST-3 §3.3: ascending Block height, then Entry index) prevails"):
        assert marker in prose, f"§5 does not state: {marker!r}"
check("vectors:wist4-parameter-in-force", _dc4_parameter_in_force)

def _dc4_parameter_in_force_twin():
    """The check above must notice an exclusive endpoint and a tie broken
    the other way."""
    v = _parameter_vector()
    case = next(c for c in v["cases"] if c["label"] == "effective at is inclusive")
    at = next(q for q in case["queries"] if q["from_index"] is not None and
              q["t_s"] == case["changes"][0]["effective_at_s"])
    assert _value_in_force(case["default"], case["changes"], at["t_s"], inclusive=False)[1] is None, \
        "the twin's exclusive endpoint still read the amendment as in force"
    case = next(c for c in v["cases"] if c["label"] == "equal effective at across blocks")
    reversed_changes = list(reversed(case["changes"]))
    for c, b in zip(reversed_changes, [x["block_number"] for x in case["changes"]]):
        c["block_number"] = b
    tied = next(q for q in case["queries"] if q["from_index"] is not None)
    assert _value_in_force(case["default"], reversed_changes, tied["t_s"])[0] != tied["value"], \
        "recomputation is blind to which of an equal pair sealed later"
check("negative:wist4-parameter-in-force", _dc4_parameter_in_force_twin)


def _combinations_hold(values):
    return (values["links_cap_bytes"] >= values["link_url_cap_bytes"] + 21
            and values["mirror_retention_days"] * 6 >= values["payload_window_days"]
            and values["labeler_block_entries_max"] <= values["domain_block_entries_max"])

def _prospective_values(defaults, changes, at_s):
    values = dict(defaults)
    for c in sorted(changes, key=lambda c: (c["effective_at_s"], c["block_height"], c["entry_index"])):
        if c["effective_at_s"] <= at_s:
            values[c["parameter"]] = c["value"]
    return values

def _recovery_parameter_windows():
    vector = json.loads((ROOT / "vectors/wist4/parameter-combinations.json").read_text())
    base = vector["recovery_window_base_s"]
    assert 0 < base <= 253402300799
    limit = 253402300799 - base
    seen = set()
    unsealable = rejected = 0
    for case in vector["recovery_window_cases"]:
        windows = []
        for change in case["accepted_amendments"]:
            assert change["parameter"] == "recovery_window_days"
            assert 1 <= change["value"] <= (1 << 53) - 1
            assert change["effective_at_s"] >= change["sealed_at_s"] + 7 * 86400
            assert change["effective_at_s"] + change["value"] * 86400 <= limit, case["label"]
        for change in case["rejected_amendments"]:
            assert change["parameter"] == "recovery_window_days" and change["code"] == "WIST4-E03"
            assert change["effective_at_s"] + change["value"] * 86400 > limit, case["label"]
            rejected += 1
        for event in case["eligible_recoveries"]:
            at = event["sealed_at_s"]
            active = next((window for window in windows if window[0] <= at < window[1]), None)
            if active is None:
                days = _prospective_values({"recovery_window_days": 7},
                                           case["accepted_amendments"], at)["recovery_window_days"]
                if at + days * 86400 > limit:
                    assert not event["sealable"] and event["window_end_s"] is None, case["label"]
                    unsealable += 1
                    continue
                active = (at, at + days * 86400)
                windows.append(active)
            assert event["sealable"], case["label"]
            assert active == (event["owner_at_s"], int(event["window_end_s"])), case["label"]
            assert int(event["window_end_s"]) <= limit
        for probe in case["probes"]:
            assert probe["open"] == any(start <= probe["at_s"] < end for start, end in windows), case["label"]
        seen.add(case["label"])
    assert len(seen) == 9 and unsealable == 1 and rejected == 1
    assert any(limit - 86400 < int(e["window_end_s"]) <= limit
               for case in vector["recovery_window_cases"] for e in case["eligible_recoveries"]
               if e["sealable"]), "no window end within a day of the Log timestamp range"
    prose = (ROOT / "specs/WIST-4-governance.md").read_text()
    assert "| WIST-1 §5.2 recovery window length | Window owner Declaration's Block;" in prose
    flat = re.sub(r"\s+", " ", prose)
    assert "would end a window opened at that instant after `9999-12-31T23:59:59Z`" in flat
    flat1 = re.sub(r"\s+", " ", (ROOT / "specs/WIST-1-delta-format.md").read_text())
    assert "an Aggregator MUST NOT seal a recovery Declaration whose window would end there" in flat1


check("vectors:wist4-recovery-parameter-windows", _recovery_parameter_windows)


def _dc4_prospective_parameters():
    v = json.loads((ROOT / "vectors" / "wist4" / "parameter-combinations.json").read_text())
    for case in v["prospective_cases"]:
        accepted, rejected = [], []
        order = sorted(range(len(case["changes"])), key=lambda i: (case["changes"][i]["block_height"], case["changes"][i]["entry_index"]))
        for i in order:
            c = case["changes"][i]
            candidate = accepted + [c]
            instants = sorted({c["sealed_at_s"]} | {a["effective_at_s"] for a in candidate if a["effective_at_s"] >= c["sealed_at_s"]})
            maps = [_prospective_values(v["prospective_defaults"], candidate, t) for t in instants]
            if (c["value"] < v["prospective_floors"][c["parameter"]]
                    or c["effective_at_s"] - c["sealed_at_s"] < 7 * 86400
                    or not all(_combinations_hold(m) for m in maps)):
                rejected.append(i)
            else:
                accepted.append(c)
        assert sorted(rejected) == case["rejected_indices"], case["label"]
        for probe in case["maps"]:
            assert _prospective_values(v["prospective_defaults"], accepted, probe["at_s"]) == probe["values"], case["label"]
    labels = {c["label"] for c in v["prospective_cases"]}
    for needed in ("retention below a sixth of the window", "retention exactly a sixth of the window",
                   "aggregate cap exactly the link cap plus its structure", "canonical same Block order"):
        assert needed in labels, needed
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-governance.md").read_text())
    assert "`links_cap_bytes` MUST NOT be below `link_url_cap_bytes` + 21" in prose
    assert "`mirror_retention_days` MUST NOT be below `payload_window_days` divided by 6" in prose
    assert "`labeler_block_entries_max` MUST NOT exceed `domain_block_entries_max`" in prose
check("vectors:wist4-prospective-parameters", _dc4_prospective_parameters)

def _dc4_prospective_parameters_twin():
    v = json.loads((ROOT / "vectors" / "wist4" / "parameter-combinations.json").read_text())
    case = next(c for c in v["prospective_cases"] if c["label"] == "pending link cap then incompatible aggregate cap")
    now = _prospective_values(v["prospective_defaults"], case["changes"], case["changes"][-1]["sealed_at_s"])
    assert _combinations_hold(now)
    assert case["rejected_indices"] == [1]
    future = _prospective_values(v["prospective_defaults"], case["changes"], 11 * 86400)
    assert not _combinations_hold(future)
check("negative:wist4-prospective-parameters", _dc4_prospective_parameters_twin)

def _block_size_maps(default, accepted, instant):
    times = sorted({instant} | {c["effective_at_s"] for c in accepted if c["effective_at_s"] >= instant})
    return [_prospective_values({"block_decompressed_cap_bytes":default},
        [dict(c, parameter="block_decompressed_cap_bytes") for c in accepted], t)["block_decompressed_cap_bytes"] for t in times]


def _replay_block_size(default, blocks, restart_after=()):
    state = {"accepted":[], "maximum":0, "at_s":None}
    probes = []
    for height, block in enumerate(blocks):
        before = default if state["at_s"] is None else max(_block_size_maps(default,state["accepted"],state["at_s"]))
        maximum = max(state["maximum"],block["jcs_bytes"])
        trial = list(state["accepted"])
        rejected = []
        for index, change in enumerate(block["amendments"]):
            candidate = dict(change,block_height=height,entry_index=index)
            proposed = trial+[candidate]
            valid = isinstance(candidate["value"], int) and 1024 <= candidate["value"] <= 9007199254740991 and candidate["effective_at_s"]-block["sealed_at_s"] >= 7*86400
            if valid and all(cap >= maximum for cap in _block_size_maps(default,proposed,block["sealed_at_s"])):
                trial = proposed
            else:
                rejected.append(index)
        cap = min(_block_size_maps(default,trial,block["sealed_at_s"]))
        valid = maximum <= cap
        if valid:
            state = {"accepted":trial,"maximum":maximum,"at_s":block["sealed_at_s"]}
        probes.append({"rejected_indices":rejected,"sealing_cap":cap,"block_valid":valid,
            "largest_bytes":state["maximum"],"transport_bound_before":before})
        if height in restart_after:
            state = json.loads(json.dumps(state))
        if not valid:
            break
    return probes


def _dc4_block_sizes():
    v = json.loads((ROOT / "vectors/wist4/parameter-combinations.json").read_text())
    assert v["block_cap_default"] == 256*1024*1024
    for case in v["block_size_cases"]:
        expected = case["expected"]
        assert _replay_block_size(v["block_cap_default"],case["blocks"]) == expected, case["label"]
        assert _replay_block_size(v["block_cap_default"],case["blocks"],case["restart_after"]) == expected, case["label"]
    for case in v["block_transport_cases"]:
        bound = v["block_cap_default"] if case["prefix_sealed_at_s"] is None else max(_block_size_maps(v["block_cap_default"],case["accepted_caps"],case["prefix_sealed_at_s"]))
        if case.get("snapshot_bootstrap"):
            bound = max([v["block_cap_default"]]+[c["value"] for c in case["accepted_caps"]])
        assert bound == case["transport_bound"], case["label"]
        declared = case["declared_bytes"]
        if declared is None or declared > bound:
            stage = "frame"
        else:
            total = 0
            for chunk in case["decoded_chunk_bytes"]:
                if chunk > bound-total:
                    stage = "stream"
                    break
                total += chunk
            else:
                stage = "decoded" if total == declared else "length"
        assert stage == case["result"], case["label"]
        assert (None if stage == "decoded" else "WIST3-E03") == case["error"], case["label"]
check("vectors:wist4-block-size-schedule", _dc4_block_sizes)


def _dc4_block_sizes_twin():
    v = json.loads((ROOT / "vectors/wist4/parameter-combinations.json").read_text())
    cases = {c["label"]:c for c in v["block_size_cases"]}
    current = cases["reduction includes its complete current Block"]
    smaller = copy.deepcopy(current["blocks"])
    smaller[0]["jcs_bytes"] = 2048
    assert _replay_block_size(v["block_cap_default"],smaller)[0]["rejected_indices"] == []
    assert current["expected"][0]["rejected_indices"] == [0]
    later = cases["later maximum never revalidates old acceptance"]
    final_maximum = max(b["jcs_bytes"] for b in later["blocks"])
    assert later["blocks"][0]["amendments"][0]["value"] < final_maximum
    assert later["expected"][0]["rejected_indices"] == []
    pending = cases["pending reduction constrains an intervening Block"]
    assert pending["blocks"][-1]["jcs_bytes"] < v["block_cap_default"]
    assert not pending["expected"][-1]["block_valid"]
    transport = next(c for c in v["block_transport_cases"] if c["label"] == "future increase enlarges the transport bound")
    assert transport["declared_bytes"] > v["block_cap_default"] and transport["result"] == "decoded"
check("negative:wist4-block-size-schedule", _dc4_block_sizes_twin)

def _dc4_parameter_clocks():
    v = json.loads((ROOT / "vectors/wist4/parameter-combinations.json").read_text())
    def at(parameter, instant, changes):
        value = v["clock_defaults"][parameter]
        for change in sorted(changes, key=lambda c: c["effective_at_s"]):
            if change["effective_at_s"] <= instant and change["parameter"] == parameter:
                value = change["value"]
        return value
    for case in v["clock_cases"]:
        value = at(case["parameter"], case["anchor_s"], case["changes"])
        assert value == case["selected_value"], case["label"]
        assert case["start"] + value * case["unit_scale"] == case["endpoint"], case["label"]
    fixed = next(c for c in v["clock_cases"] if c["label"] == "discovery retains seal count")
    assert at(fixed["parameter"], fixed["query_s"], fixed["changes"]) != fixed["selected_value"]
    included = next(c for c in v["clock_cases"] if c["label"] == "effective at anchor is included")
    assert included["anchor_s"] == included["changes"][0]["effective_at_s"]
    assert included["selected_value"] == included["changes"][0]["value"]
check("vectors:wist4-parameter-clocks", _dc4_parameter_clocks)

def _dc4_parameter_wire_range():
    v = json.loads((ROOT / "vectors/wist4/parameter-combinations.json").read_text())
    validator = Draft202012Validator(json.loads((ROOT / "schemas/registry-update.schema.json").read_text()))
    key = Ed25519PublicKey.from_public_bytes(b64u_decode(v["wire_public_key"]))
    for case in v["wire_cases"]:
        doc = case["envelope"]
        assert validator.is_valid(doc) == case["schema_valid"], case["label"]
        assert case["sealed_disposition"] == ("candidate" if case["schema_valid"] else "ignored"), case["label"]
        if case["canonical_integer"]:
            key.verify(b64u_decode(doc["sig"]["value"]), rfc8785.dumps(doc["update"]))
        else:
            try:
                rfc8785.dumps(doc["update"])
            except rfc8785.IntegerDomainError:
                pass
            else:
                raise AssertionError(case["label"])
        d = doc["update"]["details"]
        assert doc["update"]["subject"] == d["parameter"]
        values = dict(v["prospective_defaults"])
        if d["parameter"] in values and isinstance(d["value"], int):
            values[d["parameter"]] = d["value"]
        assert _combinations_hold(values) == case["combinations_hold_at_defaults"], case["label"]
    floor = next(c for c in v["wire_cases"] if c["envelope"]["update"]["details"] == {"parameter": "payload_window_days", "value": 29})
    assert not floor["schema_valid"] and floor["sealed_disposition"] == "ignored"
    assert next(c for c in v["wire_cases"] if c["envelope"]["update"]["details"] == {"parameter": "payload_window_days", "value": 30})["schema_valid"]
    spellings = [c for c in v["wire_cases"] if c["envelope"]["update"]["details"]["parameter"] == "block_decompressed_cap_bytes"]
    assert [(type(c["envelope"]["update"]["details"]["value"]), c["schema_valid"]) for c in spellings] == [(str, False), (float, True)], \
        "a string value fails the details contract; an integral decimal spelling is the integer it denotes"
    assert spellings[1]["envelope"]["update"]["details"]["value"] == 4096 and spellings[1]["sealed_disposition"] == "candidate"
    fractional = next(c for c in v["wire_cases"] if c["envelope"]["update"]["effective_at"].endswith(".5Z"))
    assert not fractional["schema_valid"] and fractional["sealed_disposition"] == "ignored"
    prose4 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-governance.md").read_text())
    assert "never reaches these checks" in prose4, "WIST-4 §5 does not exclude schema-invalid acts from schedule candidates"
check("vectors:wist4-parameter-wire-range", _dc4_parameter_wire_range)


# WIST-3 §6.2: after a withdrawal the Log retains no unsalted digest of the
# withdrawn content. That sentence is a claim about every object format in the
# suite, so the guard below enumerates every schema and every example rather
# than any single object.
#
# Each entry names a digest-shaped field that is NOT derived from page content,
# with what it actually covers. Anything digest-shaped and not on this list must
# be an `hmac-sha256:` commitment under the Payload salt, or it fails. Adding a
# field here is the deliberate act of asserting it carries no content.
NON_CONTENT_DIGESTS = {
    ('feed.schema.json', 'properties/feed/properties/domain'): "a Canonical Host identifying a Publisher or its declared scope, not a content digest",
    ('delta.schema.json', 'properties/delta/properties/publisher'): 'the signed Canonical Host of the Publisher, not a content digest',
    ('publisher.schema.json', 'properties/publisher/properties/domain'): "a Canonical Host identifying a Publisher or its declared scope, not a content digest",
    ('publisher.schema.json', 'properties/publisher/properties/subdomain_scope/items'): "a Canonical Host identifying a Publisher or its declared scope, not a content digest",
    ('status.schema.json', 'properties/domain'): "a Canonical Host identifying a Publisher or its declared scope, not a content digest",
    ("delta.schema.json", "properties/delta/properties/prev"):
        "a Delta ID: SHA-256 of Canonical Bytes, which carry the salted commitment and no content",
    ("publisher.schema.json", "properties/publisher/properties/prev_declaration"):
        "SHA-256 of a Declaration, which carries keys and no content",
    ("feed.schema.json", "properties/feed/properties/deltas/items"):
        "Delta IDs",
    ("block.schema.json", "properties/header/properties/prev_block_hash"):
        "SHA-256 of a Block header",
    ("log-anchor.schema.json",
     "properties/anchor/properties/predecessor/properties/final_block_hash"):
        "SHA-256 of a Block header (the predecessor Log's final Block, WIST-3 §3.4)",
    ("block.schema.json", "properties/header/properties/merkle_root"):
        "root over Entries, which carry commitments and no content",
    ("checkpoint.schema.json", "properties/checkpoint/properties/block_hash"):
        "SHA-256 of a Block header",
    ("status.schema.json", "properties/rejections/items/properties/delta_id"):
        "a Delta ID",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/files/items/properties/sha256"):
        "a whole tier file, not any one record (WIST-3 §7); and a manifest is a static artifact, not a Log Entry",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/anchor_block_hash"):
        "SHA-256 of a Block header",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/content_digest"):
        "a digest over the record tuples of WIST-3 §7 — url, publisher, delta_id, observed_at — every one of which the Log already carries in the clear; no page content is in its preimage",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/state/properties/sha256"):
        "the whole state file, a Log-derived artifact (WIST-3 §7); transport integrity, same as any files[] sha256",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/state/properties/state_digest"):
        "the content_digest construction over state tuples, every field of which is Log-derived (WIST-3 §7); no page content is in its preimage",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/shards/properties/digests"):
        "an array of per-shard record-tuple digests (WIST-3 §7); the items entry below is the pattern-bearing one, this is the array shell",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/shards/properties/digests/items"):
        "the same WIST-3 §7 record-tuple digest, computed per shard; no page content is in its preimage",
    ("snapshot-index.schema.json",
     "properties/index/properties/snapshots/items/properties/content_digest"):
        "the same WIST-3 §7 record-tuple digest the manifest declares, restated by the index",
    ("payload.schema.json", "properties/salt"):
        "the salt itself: drawn from a CSPRNG, never derived from the content it keys (WIST-1 §3.6)",
    ("label.schema.json", "properties/label/properties/labeler"): "the signed Canonical Host of the Labeler, not a content digest",
    ("label.schema.json", "properties/label/properties/subject"): "a Normalized URL or Canonical Host the Label is about (WIST-2 §3.3), which the Log carries in the clear; no page content",
    ("label.schema.json", "properties/label/properties/name"): "a Label Registry name, `<prefix>:<term>` (WIST-4 §6), not a content digest",
    ("label.schema.json", "properties/label/properties/delta"): "a Delta ID the Label binds to (WIST-2 §3.3): SHA-256 over a Delta that carries only a salted commitment",
    ("dispute.schema.json", "properties/dispute/properties/disputant"): "the signed Canonical Host of the disputant, not a content digest",
    ("dispute.schema.json", "properties/dispute/properties/label"): "the disputed Label's ID (WIST-2 §3.3): SHA-256 over a Label, which carries a subject, a name and an integer, no page content",
    ("dispute.schema.json", "properties/dispute/properties/log"): "a Log's `log_id`, a Canonical Host, not a content digest",
    ("label-definition.schema.json", "properties/definition/properties/labeler"): "the signed Canonical Host of the Labeler, not a content digest",
    ("label-definition.schema.json", "properties/definition/properties/name"): "a Label Registry name, `<prefix>:<term>` (WIST-4 §6), not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[5]/prefixItems[7]/oneOf[0]"): "the Delta ID a Label binds to (WIST-2 §3.3): SHA-256 over a Delta that carries only a salted commitment",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[8]/prefixItems[1]"): "the disputed Label's ID (WIST-2 §3.3): SHA-256 over a Label, no page content",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[8]/prefixItems[2]"): "a Canonical Host identifying the disputant, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[5]/prefixItems[3]"): "a Label Registry name, `<prefix>:<term>` (WIST-4 §6), not a content digest",
    ("registry-update.schema.json", "allOf[3]/then/properties/update/properties/subject"): "a Canonical Host identifying a Publisher, not a content digest",
    ("registry-update.schema.json", "allOf[3]/then/properties/update/properties/details/properties/delta_id"): "a Delta ID: SHA-256 over a Delta that itself carries only a salted commitment (WIST-1 §3.6)",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[1]/prefixItems[1]"): "a Canonical Host identifying a Publisher, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[3]/prefixItems[1]"): "a Canonical Host identifying a Publisher, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[4]/prefixItems[1]"): "a withdrawn Delta's ID: SHA-256 over a Delta that carries only a salted commitment (WIST-3 §6.2)",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[4]/prefixItems[2]"): "a Canonical Host identifying a Publisher, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[5]/prefixItems[1]"): "a Canonical Host identifying a Labeler, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[6]/prefixItems[1]"): "a Canonical Host identifying a Publisher, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[6]/prefixItems[3]"): "a chain-tip Delta ID: SHA-256 over a Delta that carries only a salted commitment (WIST-3 §7)",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[7]/prefixItems[1]"): "a Public Suffix List snapshot identifier: SHA-256 over a list of domain-name rules, no page content (WIST-4 §3.1)",
    ("registry-update.schema.json", "allOf[4]/then/properties/update/properties/subject"): "a Public Suffix List snapshot identifier: SHA-256 over a list of domain-name rules, no page content (WIST-4 §3.1)",
    ("registry-update.schema.json", "allOf[4]/then/properties/update/properties/details/properties/sha256"): "a Public Suffix List snapshot identifier: SHA-256 over a list of domain-name rules, no page content (WIST-4 §3.1)",
}

NON_CONTENT_VALUES = {
    ("vectors/wist1/payload-fields.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/payload-fields.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/payload-fields.json", "salt"): "Payload salts and malformed encoding probes",

    ("vectors/wist4/parameter-combinations.json", "wire_public_key"): "an Ed25519 public key",
    ("vectors/wist4/parameter-combinations.json", "value"): "an Ed25519 signature when opaque",
    ("examples/block.json", "merkle_root"): "root over Entries, which carry commitments only",
    ("examples/block.json", "prev"): "a Delta ID",
    ("examples/block.json", "value"): "an Ed25519 signature",
    ("examples/checkpoint.json", "block_hash"): "SHA-256 of a Block header",
    ("examples/checkpoint.json", "value"): "an Ed25519 signature",
        ("examples/delta.json", "value"): "an Ed25519 signature",
    ("examples/feed.json", "deltas"): "Delta IDs",
    ("examples/feed.json", "value"): "an Ed25519 signature",
    ("examples/log-anchor.json", "public_key"): "an Ed25519 public key",
    ("examples/mirrors.json", "value"): "an Ed25519 signature",
    ("examples/log-anchor.json", "value"): "an Ed25519 signature",
    ("examples/payload.json", "salt"): "the salt: from a CSPRNG, never derived from what it keys",
    ("examples/publisher.json", "public_key"): "an Ed25519 public key",
    ("examples/publisher.json", "value"): "an Ed25519 signature",
    ("examples/registry-update.json", "value"): "an Ed25519 signature",
    ("examples/snapshot-manifest.json", "sha256"): "a whole tier file, not any one record (WIST-3 §7)",
    ("examples/snapshot-manifest.json", "anchor_block_hash"): "SHA-256 of a Block header",
    ("examples/snapshot-manifest.json", "content_digest"):
        "WIST-3 §7's record-tuple digest: url, publisher, delta_id, observed_at — no content in the preimage",
    ("examples/snapshot-manifest.json", "value"): "an Ed25519 signature",
    ("examples/snapshot-manifest.json", "state_digest"):
        "WIST-3 §7's digest construction over state tuples — every field Log-derived, no content in the preimage",
    ("examples/snapshot-state.json", "entries"):
        "state tuples (WIST-3 §7): key IDs, Delta IDs, heights, an Ed25519 public key — Log-derived identifiers, no page content",
    ("examples/snapshot-state.json", "value"): "an Ed25519 signature",
    ("examples/snapshot-index.json", "content_digest"):
        "the manifest's record-tuple digest, restated by the index (WIST-3 §6, §7)",
    ("examples/snapshot-index.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/snapshot-records.json", "delta_id"): "a Delta ID",
    ("vectors/wist3/snapshot-records.json", "content_digest"):
        "WIST-3 §7's record-tuple digest, recomputed by `snapshot:content-digest` from the records this file publishes",
    ("examples/status.json", "delta_id"): "a Delta ID",
        ("vectors/wist1/envelope.json", "value"): "an Ed25519 signature",
        ("vectors/wist1/id.txt", None): "the WIST-1 vector's Delta ID",
    ("vectors/wist1/keypair.json", "seed_hex"): "the test signing seed",
    ("vectors/wist1/keypair.json", "public_key"): "an Ed25519 public key",
        ("vectors/wist3/block.json", "merkle_root"): "root over Entries, which carry commitments only",
    ("vectors/wist3/block.json", "prev"): "a Delta ID",
    ("vectors/wist3/block.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/block-frames.json", "merkle_root"): "root over Entries carrying commitments",
    ("vectors/wist3/block-frames.json", "prev"): "a Delta ID",
    ("vectors/wist3/block-frames.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/timestamps.json", "merkle_root"): "root over Entries carrying commitments",
    ("vectors/wist3/timestamps.json", "prev"): "a Delta ID",
    ("vectors/wist3/timestamps.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/timestamps.json", "block_hash"): "SHA-256 of a Block header",
    ("vectors/wist3/timestamps.json", "deltas"): "Delta IDs in the Feed schema fixture",
    ("vectors/wist3/empty-block.json", "prev_block_hash"): "SHA-256 of a Block header",
    ("vectors/wist3/empty-block.json", "block_hash"): "SHA-256 of a Block header",
    ("vectors/wist3/empty-block.json", "merkle_root"):
        "the empty tree's root, SHA-256(0x00) — no Entry, and therefore no content, in its preimage (WIST-3 §4)",
    ("vectors/wist3/empty-block.json", "rfc6962_empty_root"):
        "the RFC 6962 empty-tree constant this suite deviates from, published so the deviation is checkable (WIST-3 §4)",
    ("vectors/wist3/empty-block.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/inclusion-proof.json", "path"): "Merkle sibling hashes over Entries",
        ("vectors/multilog/dedup.json", "block_hash"): "SHA-256 of a Block header",
    ("vectors/multilog/dedup.json", "prev_block_hash"): "SHA-256 of a Block header",
    ("vectors/multilog/dedup.json", "merkle_root"): "root over Entries, which carry commitments only",
    ("vectors/multilog/dedup.json", "delta_id"): "a Delta ID",
    ("vectors/multilog/dedup.json", "public_key"): "an Ed25519 public key",
    ("vectors/multilog/dedup.json", "value"): "an Ed25519 signature",
    ("vectors/multilog/dedup.json", "salt"): "the salt: from a CSPRNG, never derived from what it keys",
    ("vectors/multilog/dedup.json", "genesis_seed_hex"): "the vector's test signing seed",
    ("vectors/wist1/declaration-hosts.json", 'author_key'): 'the fixture author public key',
    ("vectors/wist1/declaration-hosts.json", 'public_key'): 'an Ed25519 public key',
    ("vectors/wist1/declaration-hosts.json", 'value'): 'an Ed25519 signature',
    ("vectors/wist1/declaration-hosts.json", 'prev_declaration'): 'SHA-256 of the original predecessor publisher object',
    ("vectors/wist1/declaration-hosts.json", 'pinned_head'): 'the authenticated candidate Block header hash',
    ("vectors/wist1/declaration-hosts.json", 'prev_block_hash'): 'the previous Block header hash',
    ("vectors/wist1/declaration-hosts.json", 'merkle_root'): 'the Merkle root of original Declaration Entries',
    ("vectors/wist1/base64url.json", "author_key"): "the fixture author public key",
    ("vectors/wist1/base64url.json", "encoded"): "an encoding or malformed field probe",
    ("vectors/wist1/base64url.json", "public_key"): "a public key or malformed public-key encoding",
    ("vectors/wist1/base64url.json", "value"): "a signature or rejected signature alias",
    ("vectors/wist1/base64url.json", "prev_declaration"): "SHA-256 of the original predecessor publisher object",
    ("vectors/wist1/base64url.json", "pinned_head"): "the authenticated candidate Block header hash",
    ("vectors/wist1/base64url.json", "prev_block_hash"): "the previous Block header hash",
    ("vectors/wist1/base64url.json", "merkle_root"): "the Merkle root of original Declaration Entries",
    ("vectors/wist1/declaration-binding.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/declaration-key-eligibility.json", "public_key"): "an Ed25519 public key or excluded public point encoding",
    ("vectors/wist1/declaration-key-eligibility.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/declaration-key-eligibility.json", "author_key"): "the fixture author public key",
    ("vectors/wist1/declaration-key-eligibility.json", "prev_declaration"): "SHA-256 of the original signed predecessor publisher object",
    ("vectors/wist1/declaration-fields.json", "prev"): "a Delta predecessor ID; relation cases authenticate the supplied predecessor",
    ("vectors/wist2/feed-regression.json", "public_key"): "the supplied Declaration public key",
    ("vectors/wist2/feed-regression.json", "value"): "a valid or deliberately invalid signature",
    ("vectors/wist2/feed-fields.json", "domain"): "supplied Canonical Hosts or deliberately malformed field probes",
    ("vectors/wist2/feed-fields.json", "deltas"): "supplied Delta IDs or deliberately malformed field probes; retrieval is not asserted",
    ("vectors/wist2/feed-fields.json", "public_key"): "the fixture Declaration public key",
    ("vectors/wist2/feed-fields.json", "value"): "valid or deliberately malformed or invalid signatures",
    ("vectors/wist2/feed-next.json", "deltas"): "supplied Delta IDs; retrieval is not asserted",
    ("vectors/wist2/feed-next.json", "seen"): "supplied Delta IDs already seen",
    ("vectors/wist2/feed-next.json", "public_key"): "the fixture Declaration public key",
    ("vectors/wist2/feed-next.json", "value"): "valid or deliberately invalid signatures",
    ("vectors/wist4/withdrawal.json", "delta_id"): "fixture Delta IDs; retrieval is not asserted",
    ("vectors/wist4/withdrawal.json", "public_key"): "the fixture Log public key",
    ("vectors/wist4/registrable-domain.json", "sha256"): "SHA-256 over a Public Suffix List snapshot's octets: a list of domain-name rules, no page content (WIST-4 §3.1)",
    ("vectors/wist4/registrable-domain.json", "public_key"): "the fixture Log public key",
    ("vectors/wist2/declaration-refresh.json", "salt"): "the example Payload salt",
    ("vectors/wist2/declaration-refresh.json", "id"): "SHA-256 of the served Delta",
    ("vectors/wist2/declaration-refresh.json", "prev"): "SHA-256 of the served predecessor",
    ("vectors/wist2/declaration-refresh.json", "prev_declaration"): "SHA-256 of the previous publisher object",
    ("vectors/wist2/declaration-refresh.json", "public_key"): "a usable or deliberately excluded Ed25519 point",
    ("vectors/wist2/declaration-refresh.json", "value"): "a signature or deliberately invalid signature",
    ("vectors/wist2/declaration-refresh.json", "accepted"): "expected accepted Delta IDs",
    ("vectors/wist2/declaration-refresh.json", "rejected"): "expected rejected Delta IDs and diagnostics",
    ("vectors/wist2/declaration-refresh.json", "deltas"): "Feed Delta IDs",
    ("vectors/wist2/page-bindings.json", "prev_declaration"): "SHA-256 of the previous publisher object",
    ("vectors/wist2/page-bindings.json", "public_key"): "a usable or deliberately excluded Ed25519 point",
    ("vectors/wist2/page-bindings.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/payload-links.json", "public_key"): "the Delta signing public key",
    ("vectors/wist1/payload-links.json", "value"): "an Ed25519 Delta signature",
    ("vectors/wist1/payload-links.json", "salt"): "the Payload commitment salt",
    ("vectors/wist1/delta-clock-time.json", "public_key"): "the fixture signing key",
    ("vectors/wist1/delta-clock-time.json", "value"): "signed integer allowance or valid/deliberately invalid signature",
    ("vectors/wist1/delta-cap-time.json", "prev"): "the signed predecessor Delta ID",
    ("vectors/wist1/delta-cap-time.json", "id"): "SHA-256 of a signed Delta",
    ("vectors/wist1/delta-cap-time.json", "pinned_head"): "the trusted final Block header hash",
    ("vectors/wist1/delta-cap-time.json", "prev_block_hash"): "SHA-256 of the previous Block header",
    ("vectors/wist1/delta-cap-time.json", "merkle_root"): "the authenticated Entry Merkle root",
    ("vectors/wist1/delta-cap-time.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/delta-cap-time.json", "value"): "an Ed25519 signature or integer parameter value",
    ("vectors/wist1/delta-cap-time.json", "salt"): "the Payload commitment salt",
    ("vectors/wist1/delta-fields.json", "prev"): "a supplied predecessor ID or malformed spelling; chain eligibility is not asserted",
    ("vectors/wist1/delta-fields.json", "id"): "SHA-256 of the signed Delta",
    ("vectors/wist1/delta-fields.json", "requested_id"): "a supplied matching or mismatching transport ID",
    ("vectors/wist1/delta-fields.json", "author_key"): "the fixture author public key",
    ("vectors/wist1/delta-fields.json", "value"): "a valid or deliberately damaged Ed25519 signature",
    ("vectors/wist1/delta-diagnostics.json", "prev"): "SHA-256 of the supplied signed predecessor Delta",
    ("vectors/wist1/delta-diagnostics.json", "prev_declaration"): "SHA-256 of the authenticated preceding publisher object",
    ("vectors/wist1/delta-diagnostics.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/delta-diagnostics.json", "value"): "an Ed25519 signature or noncanonical signature encoding probe",
    ("vectors/wist1/recovery-scope.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/recovery-admission.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/recovery-admission.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/recovery-admission.json", "prev_declaration"): "SHA-256 of a named predecessor publisher object",
    ("vectors/wist1/recovery-admission.json", "pinned_head"): "the trusted shared Block prefix hash",
    ("vectors/wist1/recovery-admission.json", "last_inside_pin"): "the trusted last pre-deadline Block hash",
    ("vectors/wist1/recovery-admission.json", "deadline_pin"): "the trusted deadline Block hash",
    ("vectors/wist1/recovery-admission.json", "pin"): "the trusted alternate deadline Block hash",
    ("vectors/wist1/recovery-admission.json", "prev_block_hash"): "SHA-256 of the preceding Block header",
    ("vectors/wist1/recovery-admission.json", "merkle_root"): "the Merkle root of Declaration Entries",
    ("vectors/wist1/recovery-scope.json", "value"): "an Ed25519 signature or malformed encoding",
    ("vectors/wist1/recovery-scope.json", "prev_declaration"): "the authenticated predecessor Declaration hash",
    ("vectors/wist1/recovery-scope.json", "pinned_head"): "the trusted final Block header hash",
    ("vectors/wist1/recovery-scope.json", "prev_block_hash"): "the preceding Block header hash",
    ("vectors/wist1/recovery-scope.json", "merkle_root"): "the Declaration Entry Merkle root",
    ("vectors/wist1/delta-attribution.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/delta-attribution.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/delta-attribution.json", "delta_ids"): "SHA-256 of each original signed inner Delta",
    ("vectors/wist1/delta-attribution.json", "prev"): "the authenticated predecessor Delta ID",
    ("vectors/wist1/delta-attribution.json", "prev_declaration"): "the authenticated predecessor Declaration hash",
    ("vectors/wist1/delta-attribution.json", "pinned_head"): "the independently trusted Block head",
    ("vectors/wist1/delta-attribution.json", "prev_block_hash"): "the preceding Block hash",
    ("vectors/wist1/delta-attribution.json", "merkle_root"): "the Block Entry Merkle root",

    ("vectors/wist1/declaration-fields.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/declaration-fields.json", "value"): "an Ed25519 signature or malformed signature-field probe",
    ("vectors/wist1/declaration-fields.json", "author_key"): "the fixture author public key",
    ("vectors/wist1/declaration-fields.json", "prev_declaration"): "SHA-256 of a predecessor publisher object",
    ("vectors/wist1/declaration-fields.json", "pinned_head"): "the trusted candidate Block header hash",
    ("vectors/wist1/declaration-fields.json", "prev_block_hash"): "SHA-256 of a Block header",
    ("vectors/wist1/declaration-fields.json", "merkle_root"): "the Merkle root of Declaration Entries",
    ("vectors/wist1/declaration-conflicts.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/declaration-conflicts.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/declaration-conflicts.json", "prev_declaration"): "SHA-256 of a named predecessor publisher object",
    ("vectors/wist1/declaration-conflicts.json", "pinned_head"): "the trusted final Block header hash",
    ("vectors/wist1/declaration-conflicts.json", "expected_accepted_head"): "the accepted Block header hash after batch validation",
    ("vectors/wist1/declaration-conflicts.json", "prev_block_hash"): "SHA-256 of a Block header",
    ("vectors/wist1/declaration-conflicts.json", "merkle_root"): "the Merkle root of Declaration Entries",
    ("vectors/wist1/declaration-conflicts.json", "current_envelope"): "SHA-256 of the installed Declaration Envelope including signature",
    ("vectors/wist1/declaration-conflicts.json", "recovery_envelope"): "SHA-256 of the recovery-chain Declaration Envelope including signature",
    ("vectors/wist1/declaration-conflicts.json", "first_candidate"): "SHA-256 of a Declaration Envelope used to discriminate leaf order",
    ("vectors/wist1/recovery-settlement.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/recovery-bindings.json", "public_key"): "an Ed25519 public key or excluded point",
    ("vectors/wist1/recovery-bindings.json", "value"): "an Ed25519 signature or malformed signature encoding",
    ("vectors/wist1/recovery-bindings.json", "prev_declaration"): "SHA-256 of the named predecessor publisher object",
    ("vectors/wist1/recovery-bindings.json", "pinned_head"): "the trusted final Block header hash",
    ("vectors/wist1/recovery-bindings.json", "prev_block_hash"): "SHA-256 of a Block header",
    ("vectors/wist1/recovery-bindings.json", "merkle_root"): "the Merkle root of Declaration Entries",
    ("vectors/wist1/recovery-settlement.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/recovery-settlement.json", "prev_declaration"): "SHA-256 of the named predecessor publisher object",
    ("vectors/wist1/recovery-settlement.json", "pinned_head"): "the trusted final Block header hash",
    ("vectors/wist1/recovery-settlement.json", "prev_block_hash"): "SHA-256 of a Block header",
    ("vectors/wist1/recovery-settlement.json", "merkle_root"): "the Merkle root of Declaration Entries",
    ("vectors/wist1/recovery-settlement.json", "label"): "SHA-256 of a publisher object",
    ("vectors/wist1/recovery-settlement.json", "predecessor"): "SHA-256 of a named predecessor publisher object",
    ("vectors/wist1/recovery-settlement.json", "effective_declaration"): "SHA-256 of the effective publisher object",
    ("vectors/wist1/recovery-settlement.json", "superseded"): "SHA-256 identifiers of superseded publisher objects",
    ("vectors/wist1/recovery-settlement.json", "delta_id"): "SHA-256 of a signed Delta object",
    ("vectors/wist1/recovery-settlement.json", "queued"): "SHA-256 identifiers of queued Delta objects",
    ("vectors/wist1/recovery-settlement.json", "not_queued"): "SHA-256 identifiers of nonadmitted Delta objects",
    ("vectors/wist1/recovery-settlement.json", "eligible"): "SHA-256 identifiers of signature-eligible Delta objects",
    ("vectors/wist1/recovery-settlement.json", "rejected"): "SHA-256 identifiers of rejected Delta objects",
    ("vectors/wist1/recovery-heads.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/recovery-heads.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/recovery-heads.json", "prev_declaration"): "SHA-256 of the named predecessor publisher object",
    ("vectors/wist1/recovery-heads.json", "pinned_head"): "the trusted final Block header hash",
    ("vectors/wist1/recovery-heads.json", "prev_block_hash"): "SHA-256 of a Block header",
    ("vectors/wist1/recovery-heads.json", "merkle_root"): "the Merkle root of Declaration Entries",
    ("vectors/wist1/recovery-heads.json", "current_declaration"): "SHA-256 of the current publisher object",
    ("vectors/wist1/recovery-heads.json", "recovery_head"): "SHA-256 of the recovery-chain publisher object",
    ("vectors/wist1/recovery-order.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/recovery-order.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/recovery-order.json", "prev_declaration"):
        "SHA-256 over a Declaration's publisher object (WIST-1 section 5.2)",
    ("vectors/wist1/recovery-order.json", "owner_declaration"):
        "SHA-256 over the recovery owner's publisher object (WIST-1 section 5.2)",
    ("vectors/wist1/recovery-order.json", "pinned_head"):
        "the trusted final Block header hash (WIST-3 section 3.1)",
    ("vectors/wist1/recovery-order.json", "prev_block_hash"):
        "SHA-256 of a Block header (WIST-3 section 3.1)",
    ("vectors/wist1/recovery-order.json", "merkle_root"):
        "the Merkle root of Declaration Entries (WIST-3 section 4)",
    ("vectors/wist1/declaration-binding.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/declaration-binding.json", "prev_declaration"):
        "SHA-256 over a Declaration's publisher object (WIST-1 section 5.2)",
    ("vectors/wist1/declaration-sequence.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist2/labels.json", "public_key"): "the example Declaration's Ed25519 public keys",
    ("vectors/wist2/labels.json", "value"): "an Ed25519 signature over a Label",
    ("vectors/wist2/labels.json", "current"): "the current Label's ID after replay (WIST-2 §3.3)",
    ("vectors/wist4/withdrawal.json", "state_tuples"): "fixture Delta IDs inside WIST-3 §7 withdrawal tuples",
    ("vectors/wist4/withdrawal.json", "record_tuples"): "fixture Delta IDs inside WIST-3 §7 record tuples",
    ("vectors/wist4/withdrawal.json", "materialized"): "fixture Delta IDs whose content materializes",
    ("vectors/wist4/withdrawal.json", "adopted"): "fixture Delta IDs inside adopted withdrawal tuples",
    ("vectors/wist4/registrable-domain.json", "entries"): "Public Suffix List snapshot identifiers inside WIST-3 §7 suffix_list tuples",
    ("vectors/wist3/timestamps.json", "entries"): "a placeholder Label ID inside a WIST-3 §7 dispute tuple whose timestamp position is probed",
    ("examples/dispute.json", "label"): "the disputed Label's ID: SHA-256 over a Label, no page content (WIST-2 §3.3)",
    ("examples/dispute.json", "value"): "an Ed25519 signature over the example dispute",
    ("examples/label-definition.json", "value"): "an Ed25519 signature over the example definition",
    ("vectors/wist2/disputes.json", "label_id"): "a sealed Label's ID: SHA-256 over a Label, no page content (WIST-2 §3.3)",
    ("vectors/wist2/disputes.json", "label"): "the disputed Label's ID: SHA-256 over a Label, no page content (WIST-2 §3.3)",
    ("vectors/wist2/disputes.json", "value"): "an Ed25519 signature over a dispute or Declaration",
    ("vectors/wist2/disputes.json", "public_key"): "the fixture disputant and Labeler public keys",
    ("vectors/wist2/disputes.json", "dispute_id"): "a Dispute ID: SHA-256 over a dispute, which carries a Label ID, hosts and a URL, no page content (WIST-2 §3.3)",
    ("vectors/wist2/disputes.json", "current"): "the current dispute's ID after replay (WIST-2 §3.3)",
    ("vectors/wist2/disputes.json", "state_tuple"): "a Label ID inside a WIST-3 §7 dispute tuple",
    ("vectors/wist2/label-definitions.json", "public_key"): "the example Declaration's Ed25519 public keys",
    ("vectors/wist2/label-definitions.json", "value"): "an Ed25519 signature over a definition",
    ("vectors/wist2/labels.json", "delta"): "the Delta ID a Label binds to: SHA-256 over a Delta that carries only a salted commitment (WIST-2 §3.3)",
    ("vectors/wist2/labels.json", "record_anchor"): "a record's anchor Delta ID (WIST-3 §7): SHA-256 over a Delta that carries only a salted commitment",
    ("vectors/wist2/labels.json", "state_tuple"): "a Label's Delta binding inside a WIST-3 §7 label tuple",
    ("vectors/wist2/labels.json", "label_id"): "a Label ID: SHA-256 over a Label, which carries a subject, a registry name and an integer — no page content (WIST-2 §3.3)",
    ("examples/label.json", "value"): "an Ed25519 signature over the example Label",
    ("examples/label-feed.json", "value"): "an Ed25519 signature over the example Label Feed",
    ("examples/label-feed.json", "deltas"): "the example Label's ID (WIST-2 §3.3): SHA-256 over an object carrying no page content",
    ("vectors/wist1/ed25519-strictness.json", "public_key_hex"):
        "an Ed25519 public key (WIST-1 §4's verification profile), canonical, non-canonical and small-order alike",
    ("vectors/wist1/ed25519-strictness.json", "signature_hex"):
        "an Ed25519 signature over this vector's own published message",
    ("vectors/wist1/declaration-sequence.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/declaration-sequence.json", "prev_declaration"):
        "SHA-256 over a Declaration's publisher object (WIST-1 §5.2) — keys, domain and scope, no page content",
}


def _spec_derived_constants():
    """Digest-shaped figures the specs publish that are not literal in a vector.

    Each is *computed* here from a shipped artifact rather than pasted, so a
    spec figure that drifts from what the suite actually produces stops being a
    published figure and the sweep flags it.
    """
    out = set()
    canonical = (ROOT / "vectors" / "wist1" / "delta.canonical").read_bytes()
    out.add(canonical.hex())                      # WIST-1 App A quotes leading chunks
    out.add(hashlib.sha256(b"\x00").hexdigest())  # WIST-3 §4's empty-tree constant
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    out.add(b64u_decode(payload["salt"]).hex())   # WIST-1 App A shows the salt in hex
    wist3 = json.loads((ROOT / "vectors" / "wist3" / "block.json").read_text())
    leaves = [leaf_hash(rfc8785.dumps(e)) for e in wist3["entries"]]
    out.update(h.hex() for h in leaves)           # WIST-3 App A's leaf and node figures
    out.add(node_hash(leaves[0], leaves[1]).hex())
    out.add(node_hash(leaves[2], leaves[3]).hex())
    return out

# In prose there are no keys, so base64url detection needs a shape rule that
# does not fire on ordinary identifiers: a digest carries mixed case and digits,
# `wist-test-salt` and `similarity_variance_floor` do not.
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
    WIST-3 §6.2 states: a content-derived value is committed under the Payload
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
    # satisfy every schema in the suite (WIST-4 §5.1). Vectors are swept too — a
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
                        "commit it under the Payload salt (WIST-3 §6.2), or do "
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


def _dc3_parameter_tuple_effective_at():
    """WIST-3 §7: a `parameter` tuple's `effective_at` is the instant the
    Registry Update carries, not a height.

    Every window `effective_at` takes part in is compared against a Block
    `sealed_at` (WIST-4 §5.1), so a state artifact restating it as an integer
    would make a resuming Consumer compare a height against an instant — and
    the §5 grace period is exactly such a comparison.
    """
    schema = json.loads((ROOT / "schemas" / "snapshot-state.schema.json").read_text())
    validator = Draft202012Validator(schema)
    envelope = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
    good = copy.deepcopy(envelope)
    good["state"]["entries"].append(
        ["parameter", "block_cadence_seconds", "2026-08-09T13:00:00Z", 7200])
    validator.validate(good)
    for bad_value in (0, 12, "2026-08-09T13:00:00+00:00", "2026-08-09"):
        bad = copy.deepcopy(envelope)
        bad["state"]["entries"].append(
            ["parameter", "block_cadence_seconds", bad_value, 7200])
        try:
            validator.validate(bad)
        except ValidationError:
            continue
        raise AssertionError(f"parameter tuple with effective_at {bad_value!r} validated")
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "a parameter's `effective_at`) are the whole-second" in prose, \
        "§7's instant list does not name the parameter tuple's effective_at"
    assert "One tuple exists per amendment rather than per identifier" in prose, \
        "§7 does not key the parameter tuple on (identifier, effective_at)"
check("schema:wist3-parameter-effective-at", _dc3_parameter_tuple_effective_at)


def _dc2_feed_domain_mismatch_code():
    """WIST-2 §4: the Feed-domain mismatch rejection is typed, and its code is
    the authentication code — the failure is that the Feed does not
    authenticate as this domain's, not that it could not be fetched."""
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-2-site-publication.md").read_text())
    assert ("MUST reject a Feed whose `feed.domain` differs from the host it "
            "was fetched from, with `WIST2-E04`") in prose, \
        "§4 does not type the feed.domain mismatch rejection"
    row = [l for l in (ROOT / "specs" / "WIST-2-site-publication.md")
           .read_text().splitlines() if l.startswith("| WIST2-E04 |")]
    assert row, "no WIST2-E04 registry row"
    assert "`feed.domain` differs from the host it was fetched from" in row[0], \
        "the WIST2-E04 row does not name the mismatch case §4 assigns to it"
    # §4's noise set stays closed at E02/E04, so the mismatch counts as noise
    # by inheritance rather than by a second rule.
    assert "Only pings resolving to `WIST2-E02` or `WIST2-E04` count against it" in prose, \
        "the noise set moved"
check("spec:wist2-feed-domain-mismatch", _dc2_feed_domain_mismatch_code)

def _wist3_empty_block():
    """WIST-3 §4: the empty tree, and the Block that carries it.

    The suite deviates from RFC 6962 here — SHA-256(0x00) rather than
    SHA-256 of the empty string — and an implementation wiring in a CT
    library inherits the other constant without noticing, which is exactly
    the bug that shipped once. Both constants are recomputed here.
    """
    v = json.loads((ROOT / "vectors" / "wist3" / "empty-block.json").read_text())
    block = v["block"]
    assert block["entries"] == [], "the empty-Block vector carries Entries"
    assert block["header"]["entry_count"] == 0
    assert block["header"]["merkle_root"] == \
        "sha256:" + hashlib.sha256(b"\x00").hexdigest(), "empty root is not SHA-256(0x00)"
    assert v["rfc6962_empty_root"] == "sha256:" + hashlib.sha256(b"").hexdigest()
    assert v["rfc6962_empty_root"] != block["header"]["merkle_root"], \
        "the deviation the vector exists to pin has collapsed"
    canonical = rfc8785.dumps(block["header"])
    assert v["block_hash"] == "sha256:" + hashlib.sha256(canonical).hexdigest(), \
        "block_hash is not SHA-256 over the header's JCS bytes"
    Ed25519PublicKey.from_public_bytes(load_test_pubkey()).verify(
        b64u_decode(block["sig"]["value"]), canonical)
    Draft202012Validator(
        json.loads((ROOT / "schemas" / "block.schema.json").read_text())).validate(block)
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "A Block MAY be empty (`entry_count: 0`)" in prose
check("vectors:wist3-empty-block", _wist3_empty_block)

def _keyset_vector():
    return json.loads((ROOT / "vectors" / "wist1" / "keyset-at-height.json").read_text())

def _keyset_at(declarations, height):
    """WIST-1 §5.2, ordinary case: the highest-seq Declaration sealed at a
    height <= N, the Block's own Declarations included."""
    best = None
    for d in declarations:
        if d["height"] <= height and (best is None or d["seq"] > best["seq"]):
            best = d
    return best["keys"] if best else []

def _wist1_keyset_at_height():
    """WIST-1 §5.2: the Key Set a sealed Delta verifies under is resolved at
    its own sealing height, with WIST-3 §3.3's Declarations-first order."""
    v = _keyset_vector()
    saw_beside_rejected = saw_beside_verified = saw_orphan = False
    for case in v["cases"]:
        name = case["name"]
        decls = case["declarations"]
        heights = [d["height"] for d in decls]
        assert heights == sorted(heights), f"{name}: declarations not in Log order"
        for q in case["expected"]["key_set_at"]:
            assert _keyset_at(decls, q["height"]) == q["keys"], \
                f"{name}: Key Set at {q['height']}"
        verifies = [d["delta_id"] for d in case["deltas"]
                    if d["signer"] in _keyset_at(decls, d["height"])]
        rejected = [d["delta_id"] for d in case["deltas"] if d["delta_id"] not in verifies]
        assert verifies == case["expected"]["verifies"], f"{name}: verifies"
        assert rejected == case["expected"]["rejected"], f"{name}: WIST1-E02"
        for d in case["deltas"]:
            beside = [x for x in decls if x["height"] == d["height"]]
            if beside and d["signer"] not in beside[-1]["keys"] and d["delta_id"] in rejected:
                saw_beside_rejected = True
            if beside and d["signer"] in beside[-1]["keys"] and d["delta_id"] in verifies:
                saw_beside_verified = True
            if not any(x["height"] <= d["height"] for x in decls):
                saw_orphan = d["delta_id"] in rejected
    assert saw_beside_rejected and saw_beside_verified and saw_orphan, \
        "the vector must exercise a Delta beside the retiring Declaration, one " \
        "beside the admitting one, and one below every Declaration"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-delta-format.md").read_text())
    for marker in (
            "MUST NOT seal a Delta that does not verify under the Key Set resolved "
            "at its sealing height, the sealing Block's own Declaration Entries included",
            "rejected with `WIST1-E02` at sealing"):
        assert marker in prose, f"§5.2 does not state: {marker!r}"
check("vectors:wist1-keyset-at-height", _wist1_keyset_at_height)

def _wist1_keyset_at_height_twin():
    """The check above must notice a Delta sealed beside the Declaration
    retiring its key: with that Declaration read one Block late, the
    Delta would verify."""
    v = _keyset_vector()
    case = next(c for c in v["cases"] if c["name"] == "rotation retiring the old key")
    late = [dict(d, height=d["height"] + 1) if d["seq"] > 0 else d
            for d in case["declarations"]]
    beside = next(d for d in case["deltas"] if d["delta_id"] == "d-beside-old")
    assert beside["signer"] in _keyset_at(late, beside["height"]), \
        "the twin's late Declaration did not admit the stranded Delta"
    assert beside["signer"] not in _keyset_at(case["declarations"], beside["height"]), \
        "recomputation is blind to a Declaration sealed beside the Delta"
check("negative:wist1-keyset-at-height", _wist1_keyset_at_height_twin)

def _ed25519_profile_verdict(a_bytes: bytes, sig: bytes, msg: bytes):
    """The WIST-1 §4 verification profile, as (accepted, stage).

    `stage` names the first §4 check that fails — "s-range" (s not
    canonically reduced), "decode" (A or R not a canonically-encoded curve
    point), "small-order" (A or R of small order), "equation" (the
    cofactorless equation itself) — or "accept". Both the strictness
    vector's check and the external speccheck corpus below run through
    this one implementation, so they anchor the same profile.
    """
    r_bytes, s_bytes = sig[:32], sig[32:]
    if ed25519_curve.string_to_int(s_bytes) >= ed25519_curve.Q:
        return False, "s-range"
    try:
        a_pt = ed25519_curve.string_to_point(a_bytes)
        r_pt = ed25519_curve.string_to_point(r_bytes)
    except ed25519_curve.InvalidProof:
        return False, "decode"
    if ed25519_curve._is_identity(ed25519_curve._mul(8, a_pt)) or \
            ed25519_curve._is_identity(ed25519_curve._mul(8, r_pt)):
        return False, "small-order"
    k = ed25519_curve.string_to_int(ed25519_curve._sha512(r_bytes, a_bytes, msg)) % ed25519_curve.Q
    lhs = ed25519_curve._mul(ed25519_curve.string_to_int(s_bytes), ed25519_curve.BASE)
    if ed25519_curve._equal(lhs, ed25519_curve._add(r_pt, ed25519_curve._mul(k, a_pt))):
        return True, "accept"
    return False, "equation"

def _wist1_verification_profile():
    """WIST-1 §4: the pinned verification profile, recomputed case by case.

    Each `reject` case is one that some RFC 8032 verifier accepts, so the
    vector is only worth what the recomputation proves: the profile's own
    checks — canonical `s`, canonical and non-small-order `A` and `R`, and
    the cofactorless equation — are what separate them.
    """
    v = json.loads((ROOT / "vectors" / "wist1" / "ed25519-strictness.json").read_text())
    msg = bytes.fromhex(v["message_hex"])

    def cofactored_accepts(a_bytes, sig):
        r_bytes, s_bytes = sig[:32], sig[32:]
        try:
            a_pt = ed25519_curve.string_to_point(a_bytes)
            r_pt = ed25519_curve.string_to_point(r_bytes)
        except ed25519_curve.InvalidProof:
            return False
        k = ed25519_curve.string_to_int(ed25519_curve._sha512(r_bytes, a_bytes, msg)) % ed25519_curve.Q
        lhs = ed25519_curve._mul(8, ed25519_curve._mul(ed25519_curve.string_to_int(s_bytes) % ed25519_curve.Q, ed25519_curve.BASE))
        rhs = ed25519_curve._mul(8, ed25519_curve._add(r_pt, ed25519_curve._mul(k, a_pt)))
        return ed25519_curve._equal(lhs, rhs)

    seen_accept = seen_reject = False
    for case in v["cases"]:
        name = case["name"]
        a_bytes = bytes.fromhex(case["public_key_hex"])
        sig = bytes.fromhex(case["signature_hex"])
        expected = case["expected"] == "accept"
        assert _ed25519_profile_verdict(a_bytes, sig, msg)[0] == expected, \
            f"{name}: the §4 profile disagrees with the vector"
        seen_accept |= expected
        seen_reject |= not expected
        if case.get("cofactored_would_accept"):
            assert cofactored_accepts(a_bytes, sig), \
                f"{name}: claims to separate the two readings but the "\
                "cofactored equation rejects it too"
    assert seen_accept and seen_reject, "the vector exercises only one outcome"

    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-delta-format.md").read_text())
    for marker in ("the **cofactorless** one, `[s]B = R + [k]A`",
                   "`s` MUST be canonically reduced, `0 \u2264 s < L`",
                   "MUST NOT be a point of small order"):
        assert marker in prose, f"§4 does not pin: {marker!r}"
check("vectors:wist1-verification-profile", _wist1_verification_profile)

# Transcribed verbatim from novifinancial/ed25519-speccheck cases.json —
# the published corpus of the paper "Taming the Many EdDSAs", built to
# separate Ed25519 verifier behaviors. Per-case conditions from its
# README table: (s_range, A_order, R_order, note).
_SPECCHECK_CASES = [
    ("8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
     "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
     "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
     "0000000000000000000000000000000000000000000000000000000000000000",
     "small-order", "small A and R"),
    ("9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
     "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
     "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43"
     "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
     "small-order", "small A only"),
    ("aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
     "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
     "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
     "8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
     "small-order", "small R only"),
    ("9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
     "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
     "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f"
     "87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
     "accept", "mixed A and R, succeeds unless full order is checked"),
    ("e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
     "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
     "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed512"
     "5ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
     "equation", "cofactored-only acceptance"),
    ("e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
     "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
     "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7"
     "e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
     "equation", "cofactored-only, (8h) pre-reduction sensitive"),
    ("85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
     "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
     "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e"
     "547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
     "s-range", "S > L"),
    ("85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
     "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
     "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa1942"
     "7e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
     "s-range", "S >> L"),
    ("9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
     "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
     "03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
     "decode", "non-canonical R, reduced for hash"),
    ("9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
     "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
     "ca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
     "decode", "non-canonical R, not reduced for hash"),
    ("e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc"
     "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
     "decode", "non-canonical A, reduced for hash"),
    ("39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc"
     "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
     "decode", "non-canonical A, not reduced for hash"),
]

def _ed25519_speccheck_corpus():
    """External corpus anchor for the §4 profile, an external known-answer corpus.

    The strictness vector's cases were authored alongside this suite; a
    misreading of §4 could shape both. The speccheck corpus was authored
    independently, precisely to separate verifier behaviors, so the §4
    profile must land on a published point of that behavior space: reject
    everything except case 3 (mixed-order A and R, canonical encodings,
    canonical s, cofactorless equation holds — §4 checks small order, not
    full order), and reject each case at the stage its documented
    condition dictates. A profile that quietly grew a full-order check
    (over-strict, breaks case 3) or lost a canonicity check (under-strict,
    shifts a "decode"/"s-range" stage) fails here even though the
    strictness vector, regenerated by the same author, might follow it.
    """
    for i, (msg_hex, pk_hex, sig_hex, want_stage, note) in \
            enumerate(_SPECCHECK_CASES):
        accepted, stage = _ed25519_profile_verdict(
            bytes.fromhex(pk_hex), bytes.fromhex(sig_hex),
            bytes.fromhex(msg_hex))
        assert stage == want_stage, \
            f"speccheck case {i} ({note}): expected {want_stage}, got {stage}"
        assert accepted == (want_stage == "accept")
    assert sum(1 for c in _SPECCHECK_CASES if c[3] == "accept") == 1
check("ed25519:speccheck-corpus", _ed25519_speccheck_corpus)

def _wist1_host_canonicalization():
    """WIST-1 §2: the Canonical Host vector, and the flags it is pinned to.

    UTS #46 is not reimplemented here — the suite carries no IDNA
    dependency, for the reason `tools/requirements.txt` gives about the VRF
    — so what this proves is that the vector's flag block is the one §2
    names, that every accepted case is a well-formed A-label domain, and
    that each non-ASCII case's expected label decodes back through Punycode
    to the mapped form the case cites.
    """
    v = json.loads((ROOT / "vectors" / "wist1" / "host-canonicalization.json").read_text())
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-delta-format.md").read_text())
    for flag, value in v["flags"].items():
        assert f"`{flag}={str(value).lower()}`" in prose, \
            f"§2 does not pin {flag}={value}"
    assert "MUST NOT lowercase the input first" in prose, \
        "§2 does not forbid the pre-mapping lowercase step"
    accepted = [c for c in v["cases"] if c["expected"] is not None]
    rejected = [c for c in v["cases"] if c["expected"] is None]
    assert accepted and rejected, "the vector exercises only one outcome"
    for case in accepted:
        host = case["expected"]
        assert host.isascii() and host == host.lower(), f"{case['name']}: not an A-label host"
        assert not host.endswith("."), f"{case['name']}: trailing dot survived"
        for label in host.split("."):
            assert 0 < len(label) <= 63, f"{case['name']}: label length out of range"
            assert re.fullmatch(r"[a-z0-9-]+", label), f"{case['name']}: non-LDH label"
            if label.startswith("xn--"):
                decoded = label[4:].encode("ascii").decode("punycode")
                assert not decoded.isascii(), f"{case['name']}: A-label decodes to ASCII"
    hyphen_case = [c for c in accepted if c["input"] == "r2---sn-x.example"]
    assert hyphen_case, "no CheckHyphens=false discriminator in the vector"
check("vectors:wist1-host-canonicalization", _wist1_host_canonicalization)

def _dc1_declaration_sequence_vector():
    """WIST-1 §5.2: the sequencing vector's cases are well-formed Declarations,
    and the signature each case turns on is the one it names.

    The outcomes are what an implementation is measured against; what this
    harness proves is that every case's inputs are real — schema-valid
    Declarations whose envelopes verify under the key `sig.key_id` names, so a
    case expecting `WIST1-E08` fails for its sequencing reason and never for an
    accidentally broken signature.
    """
    v = json.loads((ROOT / "vectors" / "wist1" / "declaration-sequence.json").read_text())
    schema = json.loads((ROOT / "schemas" / "publisher.schema.json").read_text())
    validator = Draft202012Validator(schema)
    outcomes = {"idempotent", "ordinary_rotation", "recovery_rotation",
                "fresh_identity", "WIST1-E08"}
    seen = set()
    assert v["cases"], "no cases in the declaration-sequence vector"
    def key_pool(case):
        """A rotation is signed by the *previous* Key Set (§5.2), so a signing
        key need not appear in the Declaration it signs: resolve against both
        sides of the case, the stored Declaration first."""
        pool = {}
        for role in ("fetched", "stored"):
            pub = case[role]["publisher"]
            for k in pub["keys"] + pub.get("recovery_keys", []):
                pool.setdefault(k["key_id"], k["public_key"])
        return pool

    for case in v["cases"]:
        pool = key_pool(case)
        assert case["expected"] in outcomes, f"unknown outcome {case['expected']}"
        seen.add(case["expected"])
        for role in ("stored", "fetched"):
            env = case[role]
            validator.validate(env)
            key_id = env["sig"]["key_id"]
            assert key_id in pool, f"{case['name']}: {role} names undeclared key {key_id}"
            Ed25519PublicKey.from_public_bytes(
                b64u_decode(pool[key_id])).verify(
                    b64u_decode(env["sig"]["value"]), rfc8785.dumps(env["publisher"]))
    assert seen == outcomes, f"outcomes never exercised: {sorted(outcomes - seen)}"
    assert any(c.get("recovery_window_open") for c in v["cases"]), \
        "no case exercises an open recovery window"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-delta-format.md").read_text())
    assert ("MUST NOT name the same `key_id`, or the same `public_key`, in both "
            "`keys` and `recovery_keys`") in prose, \
        "§5.2 does not forbid a key serving as both a signing and a recovery key"
    # The suite's own Declaration must satisfy the rule it states.
    publisher = json.loads((ROOT / "examples" / "publisher.json").read_text())["publisher"]
    signing = {(k["key_id"], k["public_key"]) for k in publisher["keys"]}
    recovery = {(k["key_id"], k["public_key"]) for k in publisher.get("recovery_keys", [])}
    assert not {i for i, _ in signing} & {i for i, _ in recovery}, \
        "the publisher example shares a key_id across its two key sets"
    assert not {k for _, k in signing} & {k for _, k in recovery}, \
        "the publisher example shares a public_key across its two key sets"
    idempotent = [c for c in v["cases"] if c["expected"] == "idempotent"]
    assert idempotent, "no idempotent re-serve case"
    for case in idempotent:
        assert rfc8785.dumps(case["stored"]["publisher"]) == \
            rfc8785.dumps(case["fetched"]["publisher"]), \
            "the idempotent case's publisher objects are not byte-identical"
check("vectors:wist1-declaration-sequence", _dc1_declaration_sequence_vector)

def _declaration_binding_result(stored, incoming, usable_key=None, signature_check=None):
    current = incoming["publisher"]
    keys = current["keys"] + current.get("recovery_keys", [])
    ids = [key["key_id"] for key in keys]
    if len(ids) != len(set(ids)):
        return "WIST1-E08"
    if {k["public_key"] for k in current["keys"]} & {
            k["public_key"] for k in current.get("recovery_keys", [])}:
        return "WIST1-E08"
    previous = stored["publisher"] if stored else None
    if previous:
        if current["seq"] <= previous["seq"] or current.get("prev_declaration") != (
                "sha256:" + hashlib.sha256(rfc8785.dumps(previous)).hexdigest()):
            return "WIST1-E08"
    elif current["seq"] != 0 or "prev_declaration" in current:
        return "WIST1-E08"
    candidates = list(current["keys"])
    if previous:
        candidates += previous["keys"] + previous.get("recovery_keys", [])
    candidates = [key for key in candidates if key["key_id"] == incoming["sig"]["key_id"]]
    if usable_key:
        candidates = [key for key in candidates if usable_key(key)]
    if not candidates:
        return "WIST1-E02"
    verified = set()
    for key in candidates:
        if signature_check and not signature_check(key, incoming):
            continue
        try:
            Ed25519PublicKey.from_public_bytes(b64u_decode(key["public_key"])).verify(
                b64u_decode(incoming["sig"]["value"]), rfc8785.dumps(current))
        except Exception:
            continue
        verified.add(key["public_key"])
    if not verified:
        return "WIST1-E01"
    assert len(verified) == 1
    if not previous:
        return "initial"
    public_key = verified.pop()
    if public_key in {key["public_key"] for key in previous["keys"]
                      if usable_key is None or usable_key(key)}:
        result = "ordinary_rotation"
    elif public_key in {key["public_key"] for key in previous.get("recovery_keys", [])
                        if usable_key is None or usable_key(key)}:
        result = "recovery_rotation"
    else:
        result = "fresh_identity"
    if result != "recovery_rotation" and previous.get("recovery_keys"):
        if rfc8785.dumps(previous["recovery_keys"]) != rfc8785.dumps(current.get("recovery_keys", [])):
            return "WIST1-E08"
    return result


def _declaration_binding_vectors():
    vector = json.loads((ROOT / "vectors/wist1/declaration-binding.json").read_text())
    validator = Draft202012Validator(json.loads((ROOT / "schemas/publisher.schema.json").read_text()))
    for case in vector["cases"]:
        validator.validate(case["fetched"])
        if case["stored"]:
            validator.validate(case["stored"])
        assert _declaration_binding_result(case["stored"], case["fetched"]) == case["expected"], case["name"]
    assert {c["expected"] for c in vector["cases"]} == {
        "initial", "ordinary_rotation", "recovery_rotation", "fresh_identity", "WIST1-E01", "WIST1-E02", "WIST1-E08"}


check("vectors:wist1-declaration-binding", _declaration_binding_vectors)


def _declaration_key_eligibility_vectors():
    vector = json.loads((ROOT / "vectors/wist1/declaration-key-eligibility.json").read_text())
    validator = Draft202012Validator(json.loads(
        (ROOT / "schemas/publisher.schema.json").read_text()))

    def canonical_bytes(value):
        return canonical_b64u_decode(value)

    def usable(key):
        raw = canonical_bytes(key["public_key"])
        try:
            point = ed25519_curve.string_to_point(raw)
        except ed25519_curve.InvalidProof:
            return False
        return not ed25519_curve._is_identity(ed25519_curve._mul(8, point))

    def signature(key, envelope):
        return _ed25519_profile_verdict(canonical_bytes(key["public_key"]),
            canonical_bytes(envelope["sig"]["value"]), rfc8785.dumps(envelope["publisher"]))[0]

    def result(stored, fetched):
        return _declaration_binding_result(stored, fetched, usable, signature)

    outcomes, excluded_public = set(), set()
    retained, immutable_hash = 0, 0
    for case in vector["cases"]:
        old, env = case["stored"], case["fetched"]
        original = copy.deepcopy(case)
        validator.validate(env)
        Ed25519PublicKey.from_public_bytes(canonical_bytes(case["author_key"])).verify(
            canonical_bytes(env["sig"]["value"]), rfc8785.dumps(env["publisher"]))
        if old:
            validator.validate(old)
            assert result(None, old) == "initial", case["name"]
        derived = {field: [key for key in env["publisher"].get(field, []) if usable(key)]
                   for field in ("keys", "recovery_keys")}
        assert derived == case["expected_usable"], case["name"]
        actual = result(old, env)
        assert actual == case["expected"], case["name"]
        assert case == original, "key derivation changed signed entries"
        outcomes.add(actual)
        for field in ("keys", "recovery_keys"):
            excluded_public.update(key["public_key"] for key in env["publisher"].get(field, []) if not usable(key))
        if actual in {"initial", "ordinary_rotation", "recovery_rotation", "fresh_identity"}:
            stripped = copy.deepcopy(env)
            for field in ("keys", "recovery_keys"):
                if field in stripped["publisher"]:
                    stripped["publisher"][field] = derived[field]
            if stripped != env:
                assert rfc8785.dumps(stripped["publisher"]) != rfc8785.dumps(env["publisher"])
                assert not _ed25519_profile_verdict(canonical_bytes(case["author_key"]),
                    canonical_bytes(env["sig"]["value"]), rfc8785.dumps(stripped["publisher"]))[0]
                retained += 1
            if old:
                filtered_old = copy.deepcopy(old)
                for field in ("keys", "recovery_keys"):
                    if field in filtered_old["publisher"]:
                        filtered_old["publisher"][field] = [key for key in old["publisher"][field] if usable(key)]
                if filtered_old != old:
                    assert result(filtered_old, env) == "WIST1-E08", case["name"]
                    immutable_hash += 1
            signature_invalid = copy.deepcopy(env)
            signature_invalid["sig"]["value"] = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()
            assert result(old, signature_invalid) == "WIST1-E01", case["name"]
    assert len(excluded_public) == 5 and retained > 0 and immutable_hash > 0
    assert outcomes == {"initial", "ordinary_rotation", "recovery_rotation", "fresh_identity",
                        "WIST1-E01", "WIST1-E02", "WIST1-E08"}


check("vectors:wist1-declaration-key-eligibility", _declaration_key_eligibility_vectors)

def _recovery_order_vectors():
    vector = json.loads((ROOT / "vectors/wist1/recovery-order.json").read_text())
    schemas = {name: Draft202012Validator(json.loads(
        (ROOT / f"schemas/{name}.schema.json").read_text()))
        for name in ("block", "publisher")}
    log_key = Ed25519PublicKey.from_public_bytes(b64u_decode(vector["log_key"]["public_key"]))
    reversed_same_block = ascending_same_block = later_block = ordinary_prefix = False
    for case in vector["cases"]:
        previous_hash, stored, previous_time = "sha256:genesis", None, None
        sequences, recoveries = [], []
        for height, block in enumerate(case["blocks"]):
            schemas["block"].validate(block)
            header, entries = block["header"], block["entries"]
            assert header["block_number"] == height
            assert header["prev_block_hash"] == previous_hash
            assert header["entry_count"] == len(entries)
            instant = log_seconds(header["sealed_at"])
            assert previous_time is None or instant > previous_time
            previous_time = instant
            encoded = rfc8785.dumps(header)
            assert block["sig"]["key_id"] == vector["log_key"]["key_id"]
            log_key.verify(b64u_decode(block["sig"]["value"]), encoded)
            hashes = [leaf_hash(rfc8785.dumps(entry)) for entry in entries]
            assert hashes == sorted(hashes)
            assert header["merkle_root"] == "sha256:" + merkle_root(hashes).hex()
            previous_hash = "sha256:" + hashlib.sha256(encoded).hexdigest()
            assert all(entry["type"] == "publisher_declaration" for entry in entries)
            candidates = [entry["body"] for entry in entries]
            assert len({env["publisher"]["domain"] for env in candidates}) == 1
            assert len({env["publisher"]["seq"] for env in candidates}) == len(candidates), \
                "ownership fixtures must not settle conflicting-candidate disposition"
            for incoming in sorted(candidates, key=lambda env: env["publisher"]["seq"]):
                schemas["publisher"].validate(incoming)
                assert stored is None or incoming["publisher"]["domain"] == stored["publisher"]["domain"]
                result = _declaration_binding_result(stored, incoming)
                assert result in {"initial", "ordinary_rotation", "recovery_rotation"}, case["name"]
                if result == "recovery_rotation":
                    recoveries.append((height, header["sealed_at"], incoming,
                                       hashes[candidates.index(incoming)]))
                    invalid_signature = copy.deepcopy(incoming)
                    signature = bytearray(b64u_decode(incoming["sig"]["value"]))
                    signature[0] ^= 1
                    invalid_signature["sig"]["value"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
                    assert _declaration_binding_result(stored, invalid_signature) == "WIST1-E01"
                    invalid_predecessor = copy.deepcopy(incoming)
                    invalid_predecessor["publisher"]["prev_declaration"] = "sha256:" + "00" * 32
                    assert _declaration_binding_result(stored, invalid_predecessor) not in {
                        "initial", "ordinary_rotation", "recovery_rotation", "fresh_identity"}
                sequences.append(incoming["publisher"]["seq"])
                stored = incoming
        assert previous_hash == case["pinned_head"]
        assert len(recoveries) == 2
        owner_height, opened_at, owner, first_leaf = recoveries[0]
        next_height, _, successor, next_leaf = recoveries[1]
        assert log_seconds(case["blocks"][-1]["header"]["sealed_at"]) < (
            log_seconds(opened_at) + vector["recovery_window_days"] * 86400)
        initial = case["blocks"][0]["entries"][0]["body"]["publisher"]
        assert successor["sig"]["key_id"] not in {
            key["key_id"] for key in initial["keys"] + initial.get("recovery_keys", [])
            + successor["publisher"]["keys"]}
        derived = {"application_sequences": sequences,
                   "owner_sequence": owner["publisher"]["seq"],
                   "owner_height": owner_height,
                   "owner_declaration": "sha256:" + hashlib.sha256(rfc8785.dumps(owner["publisher"])).hexdigest(),
                   "opened_at": opened_at, "windows_opened": 1}
        assert derived == case["expected"], case["name"]
        assert (next_leaf < first_leaf) == case["recovery_leaves_reversed"]
        reversed_same_block |= owner_height == next_height and next_leaf < first_leaf
        ascending_same_block |= owner_height == next_height and first_leaf < next_leaf
        later_block |= owner_height < next_height
        ordinary_prefix |= owner["publisher"]["seq"] > 1
    assert reversed_same_block and ascending_same_block and later_block and ordinary_prefix


check("vectors:wist1-recovery-order", _recovery_order_vectors)

def _declaration_history_blocks(vector, blocks, pinned, entry_types=("publisher_declaration",)):
    validator = Draft202012Validator(json.loads((ROOT / "schemas/block.schema.json").read_text()))
    previous, previous_time = "sha256:genesis", None
    log_key = Ed25519PublicKey.from_public_bytes(b64u_decode(vector["log_key"]["public_key"]))
    authenticated = []
    for height, block in enumerate(blocks):
        validator.validate(block)
        header, entries = block["header"], block["entries"]
        instant = log_seconds(header["sealed_at"])
        assert previous_time is None or instant == previous_time + 3600
        assert header["block_number"] == height and header["prev_block_hash"] == previous
        assert block["sig"]["key_id"] == vector["log_key"]["key_id"]
        log_key.verify(b64u_decode(block["sig"]["value"]), rfc8785.dumps(header))
        assert header["entry_count"] == len(entries)
        hashes = [leaf_hash(rfc8785.dumps(entry)) for entry in entries]
        ranks = {name: rank for rank, name in enumerate(
            ("publisher_declaration", "registry_update", "publisher_delta", "label"))}
        positions = [(ranks[entry["type"]], hashed) for entry, hashed in zip(entries, hashes)]
        assert positions == sorted(positions)
        root = merkle_root(hashes) if hashes else hashlib.sha256(b"\x00").digest()
        assert header["merkle_root"] == "sha256:" + root.hex()
        assert all(entry["type"] in entry_types for entry in entries)
        authenticated.append((header, [entry["body"] for entry in entries
                                       if entry["type"] == "publisher_declaration"]))
        previous = "sha256:" + hashlib.sha256(rfc8785.dumps(header)).hexdigest()
        previous_time = instant
    assert previous == pinned
    return authenticated


def _recovery_history_reference(vector, field_error=None):
    validators = {name: Draft202012Validator(json.loads(
        (ROOT / f"schemas/{name}.schema.json").read_text()))
        for name in ("publisher", "block")}

    def digest(envelope):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(envelope["publisher"])).hexdigest()

    def settle(state, instant):
        if state["end"] is not None and instant >= log_seconds(state["end"]):
            state["current"] = state["chain"]
            state["chain"], state["end"] = None, None

    def apply(state, incoming, instant, spelling, height):
        if field_error and (error := field_error(incoming)):
            return error
        validators["publisher"].validate(incoming)
        settle(state, instant)
        current = state["current"]
        if current and rfc8785.dumps(current["publisher"]) == rfc8785.dumps(incoming["publisher"]):
            return "idempotent"
        if incoming["publisher"]["seq"] <= state["floor"]:
            return "WIST1-E08"
        previous = None
        if current:
            assert incoming["publisher"]["domain"] == current["publisher"]["domain"]
            previous = next((head for head in (current, state["chain"])
                             if head and digest(head) == incoming["publisher"].get("prev_declaration")), None)
            if previous is None:
                return "WIST1-E08"
        outcome = _declaration_binding_result(previous, incoming)
        if outcome not in {"initial", "ordinary_rotation", "recovery_rotation", "fresh_identity"}:
            return outcome
        if outcome == "fresh_identity" and state["chain"] is None:
            state["reset_height"] = height
        if state["chain"] is not None:
            if previous == state["chain"] and outcome in {"ordinary_rotation", "recovery_rotation"}:
                state["chain"] = incoming
        elif outcome == "recovery_rotation":
            state["chain"] = incoming
            end = datetime.datetime.fromisoformat(spelling.replace("Z", "+00:00")) + datetime.timedelta(
                days=vector["recovery_window_days"])
            state["end"] = end.isoformat().replace("+00:00", "Z")
            state["windows"] += 1
        state["current"], state["floor"] = incoming, incoming["publisher"]["seq"]
        return outcome

    def summary(state):
        return {"current_declaration": digest(state["current"]),
                "recovery_head": digest(state["chain"]) if state["chain"] else None,
                "highest_accepted_seq": state["floor"], "window_end": state["end"],
                "windows_opened": state["windows"]}

    def apply_block(states, header, candidates, reverse_domains=False):
        updated = copy.deepcopy(states)
        instant = log_seconds(header["sealed_at"])
        for state in updated.values():
            settle(state, instant)
        grouped = {}
        for incoming in candidates:
            if field_error and (error := field_error(incoming)):
                return error, states
            validators["publisher"].validate(incoming)
            inner = incoming["publisher"]
            grouped.setdefault(inner["domain"], {}).setdefault(inner["seq"], []).append(incoming)
        for domain in sorted(grouped, reverse=reverse_domains):
            state = updated.setdefault(domain, {"current": None, "chain": None, "floor": -1,
                                                "end": None, "windows": 0, "reset_height": None})
            for seq in sorted(grouped[domain]):
                group = grouped[domain][seq]
                current = state["current"]
                if current and all(rfc8785.dumps(env["publisher"]) == rfc8785.dumps(current["publisher"])
                                   for env in group):
                    continue
                if len({rfc8785.dumps(env) for env in group}) != 1:
                    return "WIST1-E08", states
                result = apply(state, group[0], instant, header["sealed_at"], header["block_number"])
                if result not in {"initial", "ordinary_rotation", "recovery_rotation", "fresh_identity"}:
                    return result, states
        return "accepted", updated

    def replay(blocks, pinned):
        states = {}
        prefix_states = []
        for header, candidates in _declaration_history_blocks(vector, blocks, pinned):
            outcome, states = apply_block(states, header, candidates)
            assert outcome == "accepted"
            assert len(states) == 1
            prefix_states.append(copy.deepcopy(next(iter(states.values()))))
        return prefix_states

    return apply, summary, replay, apply_block


def _declaration_conflict_vectors():
    vector = json.loads((ROOT / "vectors/wist1/declaration-conflicts.json").read_text())
    _, _, _, apply_block = _recovery_history_reference(vector)
    validator = Draft202012Validator(json.loads((ROOT / "schemas/publisher.schema.json").read_text()))

    def digest(obj):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()

    def summaries(states):
        return {domain: {"current_envelope": digest(state["current"]),
                         "recovery_envelope": digest(state["chain"]) if state["chain"] else None,
                         "highest_accepted_seq": state["floor"], "window_end": state["end"],
                         "windows_opened": state["windows"], "reset_height": state["reset_height"]}
                for domain, state in states.items()}

    reversed_leaves = set()
    for case in vector["cases"]:
        blocks = vector["prefixes"][case["prefix"]] + [case["block"]]
        authenticated = _declaration_history_blocks(vector, blocks, case["pinned_head"])
        keys = {}
        for _, candidates in authenticated:
            for env in candidates:
                inner = env["publisher"]
                for key in inner["keys"] + inner.get("recovery_keys", []):
                    keys.setdefault(key["key_id"], set()).add(key["public_key"])
        assert len(case["signature_valid"]) == len(case["block"]["entries"])
        for entry, expected_valid in zip(case["block"]["entries"], case["signature_valid"]):
            env, verified = entry["body"], False
            for public in keys.get(env["sig"]["key_id"], set()):
                try:
                    Ed25519PublicKey.from_public_bytes(b64u_decode(public)).verify(
                        b64u_decode(env["sig"]["value"]), rfc8785.dumps(env["publisher"]))
                    verified = True
                except Exception:
                    pass
            assert verified == expected_valid, case["name"]
        for probe in case["isolated_candidates"]:
            validator.validate(probe["incoming"])
            assert probe["incoming"] in [entry["body"] for entry in case["block"]["entries"]]
            assert _declaration_binding_result(probe["previous"], probe["incoming"]) == probe["expected_result"], case["name"]
        if "sibling_leaves_reversed" in case:
            first = case["block"]["entries"][0]["body"]
            assert (digest(first) != case["first_candidate"]) == case["sibling_leaves_reversed"]
            reversed_leaves.add(case["sibling_leaves_reversed"])
        diagnostics = set()
        for reverse_domains in (False, True):
            states, accepted_head = {}, "sha256:genesis"
            for header, candidates in authenticated:
                before = copy.deepcopy(states)
                result, updated = apply_block(states, header, candidates, reverse_domains)
                assert states == before, "Block evaluation mutated its accepted prefix"
                if header["block_number"] < len(blocks) - 1:
                    assert result == "accepted", case["name"]
                else:
                    assert result in case["expected_results"], case["name"]
                    diagnostics.add(result)
                    reordered_result, reordered = apply_block(states, header, list(reversed(candidates)), reverse_domains)
                    assert (reordered_result, reordered) == (result, updated), case["name"]
                if result == "accepted":
                    states, accepted_head = updated, digest(header)
                else:
                    assert updated == before, "rejected Block changed Declaration or settlement state"
            assert summaries(states) == case["expected_state"], case["name"]
            assert accepted_head == case["expected_accepted_head"], case["name"]
        assert diagnostics == set(case["expected_results"]), case["name"]
    assert reversed_leaves == {False, True}


check("vectors:wist1-declaration-conflicts", _declaration_conflict_vectors)


def _declaration_host_format(value):
    if not isinstance(value, str):
        return True
    if not value.isascii() or len(value) > 253:
        return False
    for label in value.split('.'):
        if not 1 <= len(label) <= 63 or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in label):
            return False
        if label.startswith('xn--'):
            try:
                decoded = label[4:].encode('ascii').decode('punycode')
            except UnicodeError:
                return False
            if decoded.isascii() or decoded.encode('punycode').decode('ascii') != label[4:]:
                return False
            if decoded in {'\x80', 'a\u200cb', 'אa', '\U0001e6c0'}:
                return False
            if decoded not in {'bücher', 'faß', 'ασ', '\u1c8a'}:
                raise NotImplementedError('A-label eligibility outside the Declaration host fixture corpus')
    return True


def _declaration_host_vectors():
    vector = json.loads((ROOT / 'vectors/wist1/declaration-hosts.json').read_text())
    formats = FormatChecker(formats=[])
    formats.checks('wist-canonical-host')(_declaration_host_format)
    schemas = {name: json.loads((ROOT / f'schemas/{name}.schema.json').read_text())
               for name in ('publisher', 'feed', 'status', 'snapshot-state', 'registry-update', 'label',
                            'dispute', 'label-definition')}
    validator = Draft202012Validator(schemas['publisher'], format_checker=formats)
    fields = [schemas['publisher']['properties']['publisher']['properties']['domain'],
              schemas['publisher']['properties']['publisher']['properties']['subdomain_scope']['items'],
              schemas['feed']['properties']['feed']['properties']['domain'],
              schemas['status']['properties']['domain'],
              schemas['label']['properties']['label']['properties']['labeler'],
              schemas['dispute']['properties']['dispute']['properties']['disputant'],
              schemas['dispute']['properties']['dispute']['properties']['log'],
              schemas['label-definition']['properties']['definition']['properties']['labeler']]
    kinds = {'declaration', 'recovery_window', 'withdrawal', 'label', 'dispute', 'record'}
    for branch in schemas['snapshot-state']['properties']['state']['properties']['entries']['items']['oneOf']:
        items = branch['prefixItems']
        if items[0].get('const') in kinds:
            fields.append(items[2 if items[0]['const'] in ('withdrawal', 'dispute') else 1])
    subject_branches = [b for b in schemas['registry-update']['allOf']
                        if b['if']['properties']['update']['properties']['action'].get('const') == 'payload_withdrawal']
    assert len(subject_branches) == 1
    subject_branch = subject_branches[0]
    fields.append(subject_branch['then']['properties']['update']['properties']['subject'])
    assert len(fields) == 15
    for case in vector['hosts']:
        expected = case['expected'] == 'well_formed'
        assert _declaration_host_format(case['input']) == expected, case['name']
        assert expected == (case['input'] == case['canonical']), case['name']
        for field in fields:
            assert field['format'] == 'wist-canonical-host'
            assert Draft202012Validator(field, format_checker=formats).is_valid(case['input']) == expected, case['name']
        if case['canonical'] is not None:
            assert _declaration_host_format(case['canonical']), case['name']
    author = Ed25519PublicKey.from_public_bytes(b64u_decode(vector['author_key']))

    def field_error(env):
        return 'WIST1-E14' if not validator.is_valid(env) else None

    for case in vector['cases']:
        env = case['envelope']
        before = rfc8785.dumps(env)
        author.verify(b64u_decode(env['sig']['value']), rfc8785.dumps(env['publisher']))
        result = field_error(env) or _declaration_binding_result(None, env)
        assert result == case['expected'], case['name']
        assert rfc8785.dumps(env) == before
        host = next(host for host in vector['hosts'] if host['name'] == case['host_case'])
        if host['canonical'] is not None and host['canonical'] != host['input']:
            repaired = copy.deepcopy(env['publisher'])
            repaired[case['field']] = host['canonical'] if case['field'] == 'domain' else [host['canonical']]
            try:
                author.verify(b64u_decode(env['sig']['value']), rfc8785.dumps(repaired))
            except InvalidSignature:
                pass
            else:
                raise AssertionError('normalizing a signed host preserved its signature')
    _, _, _, apply_block = _recovery_history_reference(vector, field_error)
    outcomes, prefixes = set(), set()
    for case in vector['block_cases']:
        history = vector['prefixes'][case['prefix']]
        blocks = _declaration_history_blocks(vector, history + [case['block']], case['pinned_head'])
        for reverse_domains in (False, True):
            states, accepted_head = {}, 'sha256:genesis'
            for header, entries in blocks[:-1]:
                result, states = apply_block(states, header, entries, reverse_domains)
                assert result == 'accepted', case['name']
                accepted_head = 'sha256:' + hashlib.sha256(rfc8785.dumps(header)).hexdigest()
            before = copy.deepcopy(states)
            header, entries = blocks[-1]
            result, updated = apply_block(states, header, entries, reverse_domains)
            assert result == case['expected'], case['name']
            assert states == before
            assert apply_block(states, header, list(reversed(entries)), reverse_domains) == (result, updated)
            if result != 'accepted':
                assert updated == before and accepted_head == header['prev_block_hash']
            else:
                assert sorted(updated) == case['expected_domains'], case['name']
                for state in updated.values():
                    assert state['floor'] == state['current']['publisher']['seq'] or case['prefix'] == 'deadline'
                if case['prefix'] == 'deadline':
                    assert before['example.com']['chain'] is not None
                    assert updated['example.com']['chain'] is None
                    assert updated['example.com']['current'] == before['example.com']['chain']
                    assert updated['example.com']['floor'] == before['example.com']['floor']
            outcomes.add(result)
            prefixes.add(case['prefix'])
        damaged = copy.deepcopy(case['block'])
        damaged['entries'][0]['body']['publisher']['domain'] = 'tampered.example'
        try:
            _declaration_history_blocks(vector, history + [damaged], case['pinned_head'])
        except AssertionError:
            pass
        else:
            raise AssertionError('unauthenticated host Block accepted')
    assert outcomes == {'accepted', 'WIST1-E14', 'WIST1-E08'}
    assert prefixes == {'empty', 'initial', 'open', 'deadline'}


check('vectors:wist1-declaration-hosts', _declaration_host_vectors)

def publisher_instant(value):
    if not isinstance(value, str):
        raise ValueError("Publisher timestamp must be a string")
    match = re.fullmatch(
        r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
        r"(?:\.([0-9]+))?([Zz]|([+-])([0-9]{2}):([0-9]{2}))", value)
    if not match:
        raise ValueError("invalid Publisher timestamp grammar")
    year, month, day, hour, minute, second = map(int, match.groups()[:6])
    civil = datetime.datetime(year or 400, month, day, hour, minute, second)
    elapsed = civil - datetime.datetime(1970, 1, 1)
    seconds = (elapsed.days - (146097 if year == 0 else 0)) * 86400 + elapsed.seconds
    if match[9]:
        offset_hours, offset_minutes = int(match[10]), int(match[11])
        if offset_hours > 23 or offset_minutes > 59:
            raise ValueError("invalid Publisher timestamp offset")
        offset = offset_hours * 3600 + offset_minutes * 60
        seconds -= offset if match[9] == '+' else -offset
    fraction = Fraction(0)
    if match[7]:
        digits, numerator = match[7], 0
        for start in range(0, len(digits), 9):
            chunk = digits[start:start + 9]
            numerator = numerator * 10 ** len(chunk) + int(chunk)
        fraction = Fraction(numerator, 10 ** len(digits))
    return seconds + fraction


def _publisher_timestamp_format(value):
    if not isinstance(value, str):
        return True
    try:
        publisher_instant(value)
        return True
    except ValueError:
        return False


def _declaration_field_vectors():
    vector = json.loads((ROOT / "vectors/wist1/declaration-fields.json").read_text())
    formats = FormatChecker(formats=[])

    formats.checks('wist-canonical-host')(_declaration_host_format)

    formats.checks("wist-publisher-timestamp")(_publisher_timestamp_format)

    validator = Draft202012Validator(json.loads(
        (ROOT / "schemas/publisher.schema.json").read_text()), format_checker=formats)

    def field_error(envelope):
        return "WIST1-E14" if not validator.is_valid(envelope) else None

    author = Ed25519PublicKey.from_public_bytes(b64u_decode(vector["author_key"]))
    for case in vector["cases"]:
        env = case["envelope"]
        try:
            author.verify(b64u_decode(env["sig"]["value"]), rfc8785.dumps(env["publisher"]))
            valid = True
        except (InvalidSignature, ValueError, TypeError):
            valid = False
        assert valid == case["author_signature_valid"], case["name"]
        result = field_error(env) or _declaration_binding_result(vector["stored"], env)
        assert result == case["expected"], case["name"]
    for case in vector["delta_cases"]:
        env = case["envelope"]
        author.verify(b64u_decode(env["sig"]["value"]), rfc8785.dumps(env["delta"]))
        value = env["delta"].get("observed_at")
        result = "well_formed" if isinstance(value, str) and _publisher_timestamp_format(value) else "WIST1-E14"
        assert result == case["expected"], case["name"]
    delta_validator = Draft202012Validator(json.loads(
        (ROOT / "schemas/delta.schema.json").read_text()), format_checker=formats)
    for case in vector["delta_cases"]:
        assert delta_validator.is_valid(case["envelope"]) == (case["expected"] == "well_formed"), case["name"]
    for case in vector["key_time_cases"]:
        declaration, envelope = case["declaration"], case["envelope"]
        for env, inner in ((declaration, "publisher"), (envelope, "delta")):
            author.verify(b64u_decode(env["sig"]["value"]), rfc8785.dumps(env[inner]))
            changed = copy.deepcopy(env[inner])
            if inner == "publisher":
                changed["keys"][0]["valid_from"] += "0"
            else:
                changed["observed_at"] += "0"
            try:
                author.verify(b64u_decode(env["sig"]["value"]), rfc8785.dumps(changed))
            except InvalidSignature:
                pass
            else:
                raise AssertionError("changed timestamp retained its signature")
        result = field_error(declaration)
        if result is None and not delta_validator.is_valid(envelope):
            result = "WIST1-E14"
        if result is None:
            observed = publisher_instant(envelope["delta"]["observed_at"])
            bound = publisher_instant(declaration["publisher"]["keys"][0]["valid_from"])
            result = "key_bound_satisfied" if observed >= bound else "WIST1-E02"
        assert result == case["expected"], case["name"]
    for case in vector["relation_cases"]:
        env = case["envelope"]
        assert delta_validator.is_valid(env), case["name"]
        author.verify(b64u_decode(env["sig"]["value"]), rfc8785.dumps(env["delta"]))
        observed, reference = publisher_instant(env["delta"]["observed_at"]), publisher_instant(case["reference"])
        if case["kind"] == "clock":
            result = "WIST1-E06" if observed - reference > 600 else "relation_satisfied"
        else:
            assert case["kind"] == "predecessor"
            previous = case["predecessor"]
            author.verify(b64u_decode(previous["sig"]["value"]), rfc8785.dumps(previous["delta"]))
            assert previous["delta"]["observed_at"] == case["reference"]
            assert env["delta"]["url"] == previous["delta"]["url"]
            assert env["delta"]["prev"] == "sha256:" + hashlib.sha256(rfc8785.dumps(previous["delta"])).hexdigest()
            result = "WIST1-E07" if observed <= reference else "relation_satisfied"
        assert result == case["expected"], case["name"]
    for case in vector["elapsed_cases"]:
        assert publisher_instant(case["end"]) - publisher_instant(case["start"]) == Fraction(case["seconds"])
    assert publisher_instant("1970-01-01T00:00:00Z") == 0
    assert publisher_instant("0000-01-01T00:00:00+23:59") == -62167305540
    assert publisher_instant("9999-12-31T23:59:59-23:59") == 253402387139
    _, _, _, apply_block = _recovery_history_reference(vector, field_error)
    outcomes, prefixes = set(), set()
    for case in vector["block_cases"]:
        history = vector["prefixes"][case["prefix"]]
        authenticated = _declaration_history_blocks(vector, history + [case["block"]], case["pinned_head"])
        for reverse_domains in (False, True):
            states, accepted_head = {}, "sha256:genesis"
            for header, candidates in authenticated[:-1]:
                result, states = apply_block(states, header, candidates, reverse_domains)
                assert result == "accepted", case["name"]
                accepted_head = "sha256:" + hashlib.sha256(rfc8785.dumps(header)).hexdigest()
            before = copy.deepcopy(states)
            header, candidates = authenticated[-1]
            result, updated = apply_block(states, header, candidates, reverse_domains)
            assert result == case["expected"], case["name"]
            assert states == before, "candidate evaluation changed accepted state"
            assert apply_block(states, header, list(reversed(candidates)), reverse_domains) == (result, updated)
            if result != "accepted":
                assert updated == before, "rejected fields changed state or settled recovery"
                assert accepted_head == case["block"]["header"]["prev_block_hash"]
            else:
                assert set(updated) == {"example.com", "other.example"}
                expected_env = max((env for env in candidates if env["publisher"]["domain"] == "example.com"),
                                   key=lambda env: env["publisher"]["seq"])
                assert updated["example.com"]["current"] == expected_env
                assert updated["example.com"]["floor"] == expected_env["publisher"]["seq"]
            outcomes.add(result)
            prefixes.add(case["prefix"])
        damaged = copy.deepcopy(case["block"])
        damaged["entries"][0]["body"]["publisher"]["contact"] = "changed after signing"
        try:
            _declaration_history_blocks(vector, history + [damaged], case["pinned_head"])
        except AssertionError:
            pass
        else:
            raise AssertionError("field rejection vector did not authenticate its Block")
    assert outcomes == {"accepted", "WIST1-E14", "WIST1-E08", "WIST1-E01"}
    assert prefixes == {"empty", "initial", "open", "deadline"}


check("vectors:wist1-declaration-fields", _declaration_field_vectors)

def _base64url_vectors():
    vector = json.loads((ROOT / "vectors/wist1/base64url.json").read_text())
    for encoded, expected in (("", b""), ("Zg", b"f"), ("Zm8", b"fo"), ("Zm9v", b"foo"),
                              ("Zm9vYg", b"foob"), ("Zm9vYmE", b"fooba"), ("Zm9vYmFy", b"foobar"),
                              ("-_8", bytes((251, 255)))):
        assert canonical_b64u_decode(encoded) == expected
    nodes = collections.defaultdict(list)

    def visit(node, filename):
        if isinstance(node, dict):
            pattern = node.get("pattern", "")
            if "A-Za-z0-9_-" in pattern:
                kind = "public_key" if "{42}" in pattern else "signature" if "{85}" in pattern else "salt"
                nodes[kind].append((filename, Draft202012Validator(node)))
            for child in node.values():
                visit(child, filename)
        elif isinstance(node, list):
            for child in node:
                visit(child, filename)

    for path in (ROOT / "schemas").glob("*.json"):
        visit(json.loads(path.read_text()), path.name)
    assert {kind: len(items) for kind, items in nodes.items()} == {"public_key": 5, "signature": 14, "salt": 1}

    def encoding_result(value, kind):
        try:
            size = len(canonical_b64u_decode(value))
        except (ValueError, TypeError):
            return "WIST1-E14"
        good = size >= 16 if kind == "salt" else size == (32 if kind == "public_key" else 64)
        return "well_formed" if good else "WIST1-E14"

    for case in vector["fields"]:
        actual = encoding_result(case["encoded"], case["kind"])
        assert actual == case["expected"], case["name"]
        for filename, validator in nodes[case["kind"]]:
            assert validator.is_valid(case["encoded"]) == (actual == "well_formed"), (filename, case["name"])
    for size in range(0, 193):
        value = base64.urlsafe_b64encode(bytes(size)).rstrip(b"=").decode()
        assert canonical_b64u_decode(value) == bytes(size)
        for kind, validators in nodes.items():
            good = encoding_result(value, kind) == "well_formed"
            for filename, validator in validators:
                assert validator.is_valid(value) == good, (filename, size)
                assert not validator.is_valid(value + "\n"), (filename, size)
    validator = Draft202012Validator(json.loads((ROOT / "schemas/publisher.schema.json").read_text()))
    author = Ed25519PublicKey.from_public_bytes(canonical_b64u_decode(vector["author_key"]))

    def field_error(envelope):
        values = [(key["public_key"], "public_key") for field in ("keys", "recovery_keys")
                  for key in envelope["publisher"].get(field, [])]
        values.append((envelope["sig"]["value"], "signature"))
        failed = any(encoding_result(value, kind) == "WIST1-E14" for value, kind in values)
        assert validator.is_valid(envelope) != failed
        return "WIST1-E14" if failed else None

    for case in vector["cases"]:
        env = case["envelope"]
        author.verify(b64u_decode(env["sig"]["value"]), rfc8785.dumps(env["publisher"]))
        before = copy.deepcopy(case)
        outcome = field_error(env) or _declaration_binding_result(case["stored"], env)
        assert outcome == case["expected"], case["name"]
        assert case == before
        if "cross set byte alias" in case["name"]:
            signing = env["publisher"]["keys"][0]["public_key"]
            recovery = env["publisher"]["recovery_keys"][0]["public_key"]
            assert signing != recovery and b64u_decode(signing) == b64u_decode(recovery)
        if "signature unused bits" in case["name"]:
            fixed = copy.deepcopy(env)
            fixed["sig"]["value"] = base64.urlsafe_b64encode(b64u_decode(env["sig"]["value"])).rstrip(b"=").decode()
            assert field_error(fixed) is None
            assert leaf_hash(rfc8785.dumps(fixed)) != leaf_hash(rfc8785.dumps(env))
        elif outcome == "WIST1-E14":
            fixed = copy.deepcopy(env)
            for field in ("keys", "recovery_keys"):
                for key in fixed["publisher"].get(field, []):
                    key["public_key"] = base64.urlsafe_b64encode(b64u_decode(key["public_key"])).rstrip(b"=").decode()
            assert rfc8785.dumps(fixed["publisher"]) != rfc8785.dumps(env["publisher"])
            try:
                author.verify(b64u_decode(env["sig"]["value"]), rfc8785.dumps(fixed["publisher"]))
            except InvalidSignature:
                pass
            else:
                raise AssertionError("normalizing signed public keys preserved the signature")
    _, _, _, apply_block = _recovery_history_reference(vector, field_error)
    for case in vector["block_cases"]:
        history = vector["prefixes"][case["prefix"]]
        blocks = _declaration_history_blocks(vector, history + [case["block"]], case["pinned_head"])
        states, accepted_head = {}, "sha256:genesis"
        for header, entries in blocks[:-1]:
            result, states = apply_block(states, header, entries)
            assert result == "accepted", case["name"]
            accepted_head = "sha256:" + hashlib.sha256(rfc8785.dumps(header)).hexdigest()
        before = copy.deepcopy(states)
        header, entries = blocks[-1]
        result, updated = apply_block(states, header, entries)
        assert result == case["expected"], case["name"]
        assert states == before
        assert apply_block(states, header, list(reversed(entries)), True) == (result, updated)
        if result == "WIST1-E14":
            assert updated == before and accepted_head == header["prev_block_hash"]
        else:
            assert "other.example" in updated
            if case["prefix"] == "deadline":
                assert before["example.com"]["chain"] is not None
                assert updated["example.com"]["chain"] is None
                assert updated["example.com"]["floor"] == before["example.com"]["floor"]
                assert updated["example.com"]["current"] == before["example.com"]["chain"]
        damaged = copy.deepcopy(case["block"])
        damaged["entries"][0]["body"]["publisher"]["domain"] = "tampered.example"
        try:
            _declaration_history_blocks(vector, history + [damaged], case["pinned_head"])
        except AssertionError:
            pass
        else:
            raise AssertionError("unauthenticated Block accepted")


check("vectors:wist1-base64url", _base64url_vectors)

def _wist1_recovery_settlement():
    vector = json.loads((ROOT / "vectors/wist1/recovery-settlement.json").read_text())
    apply, _, replay, _ = _recovery_history_reference(vector)
    validator = Draft202012Validator(json.loads((ROOT / "schemas/delta.schema.json").read_text()))
    def digest(inner):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(inner)).hexdigest()
    def fixture_time(value):
        assert re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9]Z", value), \
            "settlement fixtures require whole-second UTC time"
        return log_seconds(value)
    def verifies(env, keys):
        key = next((key for key in keys if key["key_id"] == env["sig"]["key_id"]), None)
        if key is None or fixture_time(env["delta"]["observed_at"]) < fixture_time(key["valid_from"]):
            return False
        try:
            Ed25519PublicKey.from_public_bytes(b64u_decode(key["public_key"])).verify(
                b64u_decode(env["sig"]["value"]), rfc8785.dumps(env["delta"]))
            return True
        except Exception:
            return False
    for case in vector["binding_cases"]:
        env = case["envelope"]
        validator.validate(env)
        assert digest(env["delta"]) == case["delta_id"]
        queued = any(verifies(env, case[field]) for field in ("pre_recovery_keys", "recovery_keys"))
        assert queued == case["expected_queued"], case["name"]
        assert (queued and verifies(env, case["settlement_keys"])) == case["expected_eligible"], case["name"]
        if "re_serve_of" in case:
            earlier = vector["binding_cases"][case["re_serve_of"]]
            assert earlier["envelope"] == env and earlier["delta_id"] == case["delta_id"]
            assert earlier["expected_queued"] and not earlier["expected_eligible"]
            assert case["expected_eligible"]
    saw_named_competitor = False
    for case in vector["cases"]:
        name = case["name"]
        states = replay(case["blocks"], case["pinned_head"])
        projections = [case["initial_declaration"], case["recovery_declaration"]] + case["window_declarations"]
        bindings = {}
        for height, projection in enumerate(projections):
            env = projection["envelope"]
            inner = env["publisher"]
            assert case["blocks"][height]["entries"] == [{"type": "publisher_declaration", "body": env}]
            assert projection["label"] == digest(inner)
            assert projection["predecessor"] == inner.get("prev_declaration")
            assert projection["signer"] == env["sig"]["key_id"]
            for field in ("keys", "recovery_keys"):
                assert projection[field] == [key["key_id"] for key in inner.get(field, [])]
                for key in inner.get(field, []):
                    assert bindings.setdefault(key["key_id"], key) == key
        initial, recovery = projections[:2]
        expected = case["expected"]
        assert case["pre_recovery_keys"] == initial["keys"]
        assert states[1]["windows"] == states[-1]["windows"] == 1
        assert states[168]["chain"] is not None and states[169]["chain"] is None
        assert log_seconds(case["blocks"][169]["header"]["sealed_at"]) == log_seconds(states[1]["end"])
        head = states[-1]["current"]
        assert digest(head["publisher"]) == expected["effective_declaration"], name
        assert [key["key_id"] for key in head["publisher"]["keys"]] == expected["effective_keys"]
        superseded = []
        for height, projection in enumerate(projections[2:], 2):
            env = projection["envelope"]
            if states[height]["chain"] != env:
                superseded.append(projection["label"])
                old_head = states[height - 1]["chain"]["publisher"]
                signer_key = bindings[env["sig"]["key_id"]]["public_key"]
                saw_named_competitor |= signer_key in {key["public_key"] for key in old_head["keys"]}
        assert superseded == expected["superseded"], name
        queued, not_queued, eligible, rejected = [], [], [], []
        for served in case["served"]:
            env = served["envelope"]
            validator.validate(env)
            assert served["delta_id"] == digest(env["delta"])
            assert served["signer"] == env["sig"]["key_id"]
            admitted = any(verifies(env, projection["envelope"]["publisher"]["keys"])
                           for projection in (initial, recovery))
            (queued if admitted else not_queued).append(served["delta_id"])
            if admitted:
                (eligible if verifies(env, head["publisher"]["keys"]) else rejected).append(served["delta_id"])
            mutated = copy.deepcopy(env)
            mutated["delta"]["url"] += "/changed"
            assert not any(verifies(mutated, projection["envelope"]["publisher"]["keys"])
                           for projection in (initial, recovery)), "signature mutation queued"
        assert queued == expected["queued"] and not_queued == expected["not_queued"], name
        assert eligible == expected["eligible"] and rejected == expected["rejected"], name
        for probe in case["probes"]:
            height = probe["prefix_height"] + 1
            state = copy.deepcopy(states[height - 1])
            before = copy.deepcopy(state)
            spelling = case["blocks"][height]["header"]["sealed_at"]
            result = apply(state, probe["candidate"], log_seconds(spelling), spelling, height)
            assert result == probe["expected_result"], (name, probe["name"], result)
            assert state == before, "rejected candidate changed its prefix"
    assert saw_named_competitor, "a shared key must not join the chain via a competitor"
    prose = re.sub(r"\s+", " ", (ROOT / "specs/WIST-1-delta-format.md").read_text())
    for marker in (
            "verifies under **either** the Key Set in effect immediately before the recovery **or** the recovery Declaration's own",
            "revalidated against the signing bindings and scope of that chain's newest Declaration",
            "The rejection is of the queued copy and not of the Delta's identity"):
        assert marker in prose


check("vectors:wist1-recovery-settlement", _wist1_recovery_settlement)

def _recovery_binding_vectors():
    vector = json.loads((ROOT / "vectors/wist1/recovery-bindings.json").read_text())
    original = copy.deepcopy(vector)
    formats = FormatChecker(formats=[])
    formats.checks("wist-canonical-host")(_declaration_host_format)
    formats.checks("wist-publisher-timestamp")(_publisher_timestamp_format)
    validators = {name: Draft202012Validator(json.loads(
        (ROOT / f"schemas/{name}.schema.json").read_text()), format_checker=formats)
        for name in ("publisher", "delta")}

    def usable(key):
        raw = canonical_b64u_decode(key["public_key"])
        assert len(raw) == 32
        try:
            point = ed25519_curve.string_to_point(raw)
        except ed25519_curve.InvalidProof:
            return False
        return not ed25519_curve._is_identity(ed25519_curve._mul(8, point))

    def verifies(key, envelope, inner):
        return _ed25519_profile_verdict(canonical_b64u_decode(key["public_key"]),
            canonical_b64u_decode(envelope["sig"]["value"]),
            rfc8785.dumps(envelope[inner]))[0]

    def declaration_result(previous, envelope):
        validators["publisher"].validate(envelope)
        return _declaration_binding_result(previous, envelope, usable,
            lambda key, env: verifies(key, env, "publisher"))

    def admission(envelope, sources):
        try:
            observed = publisher_instant(envelope["delta"].get("observed_at"))
            signature = canonical_b64u_decode(envelope["sig"]["value"])
            if len(signature) != 64:
                return "WIST1-E14"
        except (KeyError, TypeError, ValueError):
            return "WIST1-E14"
        validators["delta"].validate(envelope)
        candidates = [key for keys in sources for key in keys
                      if key["key_id"] == envelope["sig"]["key_id"] and usable(key)
                      and publisher_instant(key["valid_from"]) <= observed]
        if not candidates:
            return "WIST1-E02"
        return ("accepted" if any(verifies(key, envelope, "delta") for key in candidates)
                else "WIST1-E01")

    prefixes = {}
    for name, history in vector["histories"].items():
        authenticated = _declaration_history_blocks(vector, history["blocks"], history["pinned_head"])
        current, frozen, deadline = None, None, None
        prefixes[name] = {}
        classifications = []
        for header, declarations in authenticated:
            block = history["blocks"][header["block_number"]]
            assert verifies(vector["log_key"], block, "header")
            assert len(declarations) == 1
            envelope = declarations[0]
            result = declaration_result(current, envelope)
            assert result in {"initial", "ordinary_rotation", "recovery_rotation"}, (name, result)
            classifications.append(result)
            if result == "recovery_rotation" and frozen is None:
                assert current is not None
                frozen = [current["publisher"]["keys"], envelope["publisher"]["keys"]]
                deadline = log_seconds(header["sealed_at"]) + vector["recovery_window_days"] * 86400
            if frozen is not None:
                assert log_seconds(header["sealed_at"]) < deadline
                prefixes[name][header["block_number"]] = copy.deepcopy(frozen)
            tampered = copy.deepcopy(envelope)
            tampered["publisher"]["subdomain_scope"] = ["changed.example.com"]
            assert declaration_result(current, tampered) == "WIST1-E01", name
            current = envelope
        assert classifications == ["initial", "recovery_rotation", "ordinary_rotation"], name
        assert prefixes[name][1] == prefixes[name][2]
        damaged = copy.deepcopy(history["blocks"])
        damaged[-1]["entries"][0]["body"]["publisher"]["domain"] = "tampered.example"
        try:
            _declaration_history_blocks(vector, damaged, history["pinned_head"])
        except AssertionError:
            pass
        else:
            raise AssertionError("unauthenticated recovery binding history accepted")
        damaged = copy.deepcopy(history["blocks"][-1])
        damaged["header"]["sealed_at"] = "2026-08-09T00:00:00Z"
        assert not verifies(vector["log_key"], damaged, "header")

    outcomes, exercised_prefixes, seen_names = set(), set(), set()
    for case in vector["cases"]:
        assert case["name"] not in seen_names
        seen_names.add(case["name"])
        sources = prefixes[case["history"]][case["prefix_height"]]
        envelope = case["envelope"]
        result = admission(envelope, sources)
        assert result == case["expected"], (case["name"], result)
        for ordered in (list(reversed(sources)), [list(reversed(keys)) for keys in sources],
                        [list(reversed(keys)) for keys in reversed(sources)]):
            assert admission(envelope, ordered) == result, case["name"]
        if result == "accepted":
            matching = [key for keys in sources for key in keys
                        if key["key_id"] == envelope["sig"]["key_id"] and usable(key)]
            assert any(verifies(key, envelope, "delta") for key in matching), case["name"]
            tampered = copy.deepcopy(envelope)
            tampered["delta"]["url"] += "/changed"
            assert admission(tampered, sources) == "WIST1-E01", case["name"]
        outcomes.add(result)
        exercised_prefixes.add(case["prefix_height"])
    assert outcomes == {"accepted", "WIST1-E01", "WIST1-E02", "WIST1-E14"}
    assert exercised_prefixes == {1, 2}
    assert vector == original, "binding validation mutated signed input"


check("vectors:wist1-recovery-bindings", _recovery_binding_vectors)

def _recovery_state_from_tuples(declaration, window):
    """WIST-3 §7/§8: the reference state a Consumer resumes from the two tuples."""
    state = {"current": declaration[2], "chain": None, "floor": declaration[4], "end": None,
             "windows": 0, "reset_height": None}
    if window is not None:
        state["chain"], state["end"] = window[4], window[3]
    return state

def _recovery_heads_vectors():
    vector = json.loads((ROOT / "vectors/wist1/recovery-heads.json").read_text())
    apply, summary, replay, _ = _recovery_history_reference(vector)
    def digest(envelope):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(envelope["publisher"])).hexdigest()
    states = replay(vector["blocks"], vector["pinned_head"])
    for expected in vector["expected_prefix_states"]:
        assert summary(states[expected["height"]]) == expected["state"], expected["height"]
    branch_states = [replay(branch["blocks"], branch["pinned_head"]) for branch in vector["branches"]]
    for branch, derived in zip(vector["branches"], branch_states):
        assert summary(derived[-1]) == branch["expected_state"]
    outcomes = set()
    for probe in vector["probes"]:
        selected = vector["branches"][probe["branch"]] if "branch" in probe else vector
        selected_states = branch_states[probe["branch"]] if "branch" in probe else states
        state = copy.deepcopy(selected_states[probe["prefix_height"]])
        instant = log_seconds(probe["candidate_sealed_at"])
        assert instant > log_seconds(selected["blocks"][probe["prefix_height"]]["header"]["sealed_at"])
        result = apply(state, probe["candidate"], instant, probe["candidate_sealed_at"],
                       probe["prefix_height"] + 1)
        assert result == probe["expected_result"], probe["name"]
        assert summary(state) == probe["expected_state"], probe["name"]
        outcomes.add(result)
    assert outcomes == {"ordinary_rotation", "recovery_rotation", "fresh_identity", "idempotent",
                        "WIST1-E01", "WIST1-E08"}
    expected_by_height = {row["height"]: row["state"] for row in vector["expected_prefix_states"]}
    compared = ("current_declaration", "recovery_head", "highest_accepted_seq", "window_end")
    resumed = 0
    for row in vector["snapshot_tuples"]:
        declaration, window = row["declaration"], row["recovery_window"]
        assert declaration[0] == "declaration" and len(declaration) == 5
        assert vector["blocks"][declaration[3]]["entries"][0]["body"] == declaration[2]
        if window is not None:
            assert window[0] == "recovery_window" and len(window) == 6
            assert vector["blocks"][window[5]]["entries"][0]["body"] == window[4]
            assert vector["blocks"][window[2]]["entries"], "owner height names an empty Block"
        state = _recovery_state_from_tuples(declaration, window)
        derived = summary(state)
        assert {k: derived[k] for k in compared} == \
            {k: expected_by_height[row["height"]][k] for k in compared}, row["height"]
        for probe in vector["probes"]:
            if "branch" in probe or probe["prefix_height"] != row["height"]:
                continue
            state = _recovery_state_from_tuples(declaration, window)
            result = apply(state, probe["candidate"], log_seconds(probe["candidate_sealed_at"]),
                           probe["candidate_sealed_at"], probe["prefix_height"] + 1)
            assert result == probe["expected_result"], ("resume", probe["name"])
            derived = summary(state)
            assert {k: derived[k] for k in compared} == \
                {k: probe["expected_state"][k] for k in compared}, ("resume", probe["name"])
            resumed += 1
    assert resumed >= 10, "too few probes resumed from Snapshot tuples"
    for case in vector["resume_cases"]:
        state = _recovery_state_from_tuples(case["declaration"], case["recovery_window"])
        result = apply(state, case["candidate"], log_seconds(case["candidate_sealed_at"]),
                       case["candidate_sealed_at"], case["height"])
        assert result == case["expected_result"], case["label"]
    prose3 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "then the highest accepted `seq` — WIST-1 §5.2's sequence floor" in prose3
    assert "then the recovery-chain head's Declaration Envelope verbatim and its sealing height" in prose3
    assert "A `recovery_window` tuple makes its head an eligible predecessor beside the current Declaration" in prose3
    for target in ("author", "header", "predecessor", "head", "omission"):
        blocks = copy.deepcopy(vector["blocks"])
        pinned = vector["pinned_head"]
        if target == "author":
            blocks[3]["entries"][0]["body"]["sig"]["value"] = blocks[2]["entries"][0]["body"]["sig"]["value"]
        elif target == "header":
            blocks[5]["header"]["sealed_at"] = blocks[4]["header"]["sealed_at"]
        elif target == "predecessor":
            blocks[3]["entries"][0]["body"]["publisher"]["prev_declaration"] = digest(
                blocks[2]["entries"][0]["body"])
        elif target == "head":
            pinned = "sha256:" + "00" * 32
        else:
            del blocks[100]
        try:
            replay(blocks, pinned)
        except Exception:
            pass
        else:
            raise AssertionError(f"recovery history accepted tampered {target}")


check("vectors:wist1-recovery-heads", _recovery_heads_vectors)

def _recovery_heads_resume_twin():
    vector = json.loads((ROOT / "vectors/wist1/recovery-heads.json").read_text())
    apply, _, _, _ = _recovery_history_reference(vector)
    for case in vector["resume_cases"]:
        declaration = list(case["declaration"])
        window = case["recovery_window"]
        if case["without"] == "floor":
            declaration[4] = declaration[2]["publisher"]["seq"]
        else:
            window = None
        state = _recovery_state_from_tuples(declaration, window)
        result = apply(state, case["candidate"], log_seconds(case["candidate_sealed_at"]),
                       case["candidate_sealed_at"], case["height"])
        assert result == case["degraded_result"] != case["expected_result"], case["label"]
check("negative:wist1-recovery-heads-resume", _recovery_heads_resume_twin)


def _parameter_registry_enum():
    """WIST-4 §5's table and the `parameter_change` enum must correspond exactly.

    The table is what a human reads and the enum is what a validator enforces.
    An identifier in one and not the other means either a parameter nobody can
    amend in-band, or an amendable parameter with no published default and no
    stated owner — both of which turn a governance action into a guess. The
    correspondence is therefore checked in both directions, and a row that is
    deliberately not amendable must say so with an em dash rather than by
    omitting a cell.
    """
    spec = (ROOT / "specs" / "WIST-4-governance.md").read_text()
    section5 = spec.split("## 5. Parameter Registry")[1].split("### 5.1.")[0]
    ids, rows = set(), 0
    for line in section5.splitlines():
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
            f"§5 row {cells[0]!r} has an Identifier cell that is neither a "
            f"backticked identifier nor an em dash: {cells[1]!r}")
        overlap = ids & found
        assert not overlap, f"§5 lists {sorted(overlap)} in more than one row"
        ids |= found
    assert rows == 21, f"{rows} Parameter Registry rows parsed; the table has twenty-one"
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
        f"§5 publishes identifiers the enum will not accept: {missing_from_enum}"
    assert not missing_from_table, \
        f"the enum accepts identifiers §5 publishes no row for: {missing_from_table}"
check("spec:parameter-registry-enum", _parameter_registry_enum)


def _parameter_change_bounds():
    """The bounds each `parameter_change` branch imposes, by identifier.

    A bound is a (minimum, maximum) pair with `None` for an absent side: some
    parameters are nullified by a value below a floor, some by one above a
    ceiling, and `block_cadence_seconds` by both — read them as one shape
    rather than assuming every bound is a floor.
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
    """Every bound §5 publishes is the bound the schema enforces, and bites.

    A bound that lives only in prose is an argument, not a constraint: the
    parameters that carry one carry it because a value past it retires a
    mechanism the suite depends on, and nothing but the schema stands between
    a signed `parameter_change` and that outcome. So the two are compared in
    both directions — a published bound the schema does not impose, and a
    schema bound §5 does not publish, are both failures — and each side of each
    bound is then exercised at its own boundary rather than assumed to be
    wired up.

    The table is read out of §5 rather than restated here for the same reason
    every other check in this file reads its thresholds from the document: a
    copy kept here would agree with itself while §5 drifted.
    """
    spec = (ROOT / "specs" / "WIST-4-governance.md").read_text()
    section5 = spec.split("## 5. Parameter Registry")[1].split("### 5.1.")[0]
    # §5's bounds table is the three-column one: | `parameter` | bound | why |.
    # The four-column Parameter Registry table is the defaults table and is
    # parsed elsewhere; keying on the column count keeps the two apart.
    published = {}
    for line in section5.splitlines():
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
            f"§5's bounds table gives {names[0]} no parseable bound: {cells[1]!r}"
        assert cells[2], f"§5's bounds table gives {names[0]} no stated consequence"
        published[names[0]] = (lo, hi)
    assert len(published) == 18, \
        f"{len(published)} bounds parsed from §5; the table has seventeen"
    enforced = _parameter_change_bounds()
    assert published == enforced, (
        "§5's published bounds and the schema's differ:\n"
        f"  published: {dict(sorted(published.items()))}\n"
        f"  enforced:  {dict(sorted(enforced.items()))}")

    # Bounds may only be placed on parameters that exist: a bound on an
    # identifier the enum does not carry constrains nothing at all.
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    v = Draft202012Validator(schema)
    sig = json.loads((ROOT / "examples" / "registry-update.json").read_text())["sig"]
    def change(parameter, value):
        return {"update": {"wist_version": "1.0.0", "action": "parameter_change",
                           "subject": parameter,
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

    # The parameters whose extremes most completely nullify a mechanism must
    # each be bounded, by name: a generalization that quietly dropped one of
    # them would still satisfy every comparison above.
    for name in ("block_cadence_seconds", "domain_block_entries_max", "max_inclusion_blocks",
                 "quota_base", "feed_window", "record_seal_blocks", "recovery_window_days"):
        assert enforced.get(name, (None, None))[0], \
            f"{name} carries no floor, so a parameter_change may zero it"
        assert not v.is_valid(change(name, 0)), f"{name} may still be set to zero"
    assert enforced["block_cadence_seconds"][1] == 86400, "the cadence has no ceiling"

    # `mirror_retention_days` is bounded by the availability window: a Consumer
    # resuming from a Snapshot published inside `payload_window_days` must
    # still find the Blocks above it at a Mirror (WIST-3 §6, §8).
    defaults = _registry_table_defaults()
    assert enforced["mirror_retention_days"][0] * 6 == defaults["payload_window_days"], (
        f"the mirror retention floor is {enforced['mirror_retention_days'][0]}, not a sixth of "
        f"the {defaults['payload_window_days']}-day availability window")
    assert "`payload_window_days` divided by 6" in re.sub(r"\s+", " ", section5), \
        "§5 does not state the retention-to-window rule"

    # Three of these floors are derived from octet counts this harness can
    # compute, so the published numbers are checked against the artifacts they
    # describe rather than asserted. A cap below any of them is not a small cap
    # but the absence of the thing it bounds.
    assert enforced["extract_cap_bytes"][0] == len(rfc8785.dumps("")), \
        "the extract cap floor is not the octet length of JCS of the empty extract"
    assert enforced["summary_cap_bytes"][0] == len(rfc8785.dumps({"title": ""})), \
        "the summary cap floor is not the octet length of the smallest conforming summary"
    assert enforced["links_cap_bytes"][0] == len(rfc8785.dumps({"total": 0, "urls": []})), \
        "the links cap floor is not the octet length of the empty links member"
    for name in ("url_cap_bytes", "link_url_cap_bytes"):
        assert enforced[name][0] == len(rfc8785.dumps("https://a.b/")), \
            f"the {name} floor is not the octet length of the shortest two-label Normalized URL"
    empty_block = json.loads((ROOT / "examples" / "block.json").read_text())
    empty_block["entries"] = []
    empty_block["header"]["entry_count"] = 0
    assert enforced["block_decompressed_cap_bytes"][0] >= len(rfc8785.dumps(empty_block)), (
        "the Block decompressed cap floor is below the size of an empty Block, which "
        "WIST-3 §3.2 requires an Aggregator to be able to seal")

    # The catch-all must reach the parameters that exist, not only later ones:
    # a wording scoped to named parameters "and any later parameter serving
    # the same role" excludes every present parameter it does not happen to
    # name.
    assert re.search(r"MUST\s*\n?NOT set \*\*any\*\* parameter", section5), \
        "§5's nullification rule no longer reaches every present parameter"
    assert "any later parameter serving the same role" not in section5, \
        "§5's nullification rule is still scoped to parameters a later revision adds"
check("spec:parameter-bounds", _parameter_bounds)

def _parameter_change_integer():
    """`parameter_change.value` is the one field that rewrites a constant.

    WIST-4 §5 states that every value the registry carries is an integer, and
    every window, cap and cadence in the suite is integer arithmetic over
    those values. This field is the only way a constant is ever rewritten, so
    a `number` here is the one hole through which a rational reaches a Block
    grid or a byte cap. Every default §5 publishes is already an integer in
    its own unit, so nothing conforming is lost by typing it.
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
        return {"update": {"wist_version": "1.0.0", "action": "parameter_change",
                           "subject": parameter,
                           "details": {"parameter": parameter, "value": value},
                           "effective_at": "2026-08-12T16:00:00Z"},
                "sig": sig}
    for parameter, rational, whole in (("quota_base", 1.5, 2),
                                       ("block_cadence_seconds", 3600.5, 3600),
                                       ("payload_window_days", 180.5, 180),
                                       ("feed_window", 0.5, 1),
                                       ("extract_cap_bytes", 32768.25, 32768)):
        assert not v.is_valid(change(parameter, rational)), \
            f"a parameter_change setting {parameter} to the rational {rational} validates"
        assert v.is_valid(change(parameter, whole)), \
            f"a parameter_change setting {parameter} to the integer {whole} is rejected"
    # JSON has one number type, so a whole-valued float is the same value as
    # the integer beside it; the guard must not turn on the Python literal.
    assert v.is_valid(change("quota_base", 5.0)), \
        "5.0 and 5 are one JSON value, and the schema must not distinguish them"

    # WIST-4 §5 must say so, or an implementer reading prose alone sees a number.
    section5 = (ROOT / "specs" / "WIST-4-governance.md").read_text() \
        .split("## 5. Parameter Registry")[1]
    assert "**Every value the registry carries is an integer**" in section5, \
        "WIST-4 §5 does not state that every registry value is an integer"
    assert "`value` (a number" not in section5, \
        "WIST-4 §5.1 still describes `value` as a number"
check("schema:parameter-change-integer", _parameter_change_integer)

def _dc4_payload_withdrawal():
    """A withdrawal is only distinguishable from censorship if it is typed.

    WIST-3 §6.2 rests on the Log carrying, for every withdrawn Payload, an entry
    naming which Delta, on what legal basis, at whose demand. A withdrawal
    missing any of the three would let an operator record an unfalsifiable
    "we removed something", which is what a quiet drop looks like.
    """
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    actions = schema["properties"]["update"]["properties"]["action"]["enum"]
    assert "payload_withdrawal" in actions, "action enum lacks payload_withdrawal"
    delta_id = (ROOT / "vectors" / "wist1" / "id.txt").read_text().strip()
    withdrawal = {
        "update": {
            "wist_version": "1.0.0",
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
check("schema:wist4-payload-withdrawal", _dc4_payload_withdrawal)


def _dc4_suffix_list_update():
    """WIST-4 §3.1: a suffix_list_update pins a snapshot by digest and octet
    count, and `subject` repeats the digest, so two acts naming one file are
    the same act however they were spelled."""
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    assert "suffix_list_update" in schema["properties"]["update"]["properties"]["action"]["enum"]
    snapshot = json.loads((ROOT / "vectors/wist4/registrable-domain.json").read_text(encoding="utf-8"))["lists"][0]
    act = {"update": {"wist_version": "1.0.0", "action": "suffix_list_update", "subject": snapshot["sha256"],
                      "details": {"sha256": snapshot["sha256"], "bytes": snapshot["bytes"]},
                      "effective_at": "2026-08-02T16:00:00Z"},
           "sig": json.loads((ROOT / "examples" / "registry-update.json").read_text())["sig"]}
    v = Draft202012Validator(schema)
    v.validate(act)
    for mutate in (lambda a: a["update"]["details"].pop("bytes"),
                   lambda a: a["update"]["details"].pop("sha256"),
                   lambda a: a["update"]["details"].update(bytes=0),
                   lambda a: a["update"]["details"].update(source="https://publicsuffix.org/"),
                   lambda a: a["update"].update(subject="example.com")):
        bad = copy.deepcopy(act)
        mutate(bad)
        assert not v.is_valid(bad), "a malformed suffix_list_update validates"
check("schema:wist4-suffix-list-update", _dc4_suffix_list_update)


def _dc4_sealed_at_precision():
    """Every window in the suite runs on Block `sealed_at`, in whole seconds.

    A Block sealed at `...:00.500Z` or `...+00:00` would make the conversion
    to integer seconds a rounding decision, and one rounded half-second can
    move a grace period or a recovery window across a Block boundary. The
    constraint therefore lives in the Block schema, not in prose downstream.
    """
    import copy
    import re
    schema = json.loads((ROOT / "schemas" / "block.schema.json").read_text())
    pat = schema["properties"]["header"]["properties"]["sealed_at"].get("pattern")
    assert pat == r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9]Z$", \
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
    wist3 = (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text()
    assert "whole-second precision" in wist3, "WIST-3 §3.1 does not state the constraint"
check("schema:wist4-sealed-at-precision", _dc4_sealed_at_precision)

# WIST-4 §4: every window and every admission test in the suite reads a Block
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
PUBLISHER_TIMESTAMP_PATTERN = '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\\.[0-9]+)?([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$(?![\\s\\S])'
SEALED_AT_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9]Z$"

TIMESTAMP_FIELDS = {
    ("block.schema.json", "properties/header/properties/sealed_at"): ANCHORED,
    ("checkpoint.schema.json", "properties/checkpoint/properties/sealed_at"): ANCHORED,
    ("feed.schema.json", "properties/feed/properties/generated_at"): ANCHORED,
    ("registry-update.schema.json", "properties/update/properties/effective_at"): ANCHORED,
    ("delta.schema.json", "properties/delta/properties/observed_at"):
        "Publisher-supplied and never compared to a Block: its only comparisons are to the "
        "`observed_at` of the Delta named by `prev` and to the validator's own clock under "
        "WIST-1 §3.4's 10-minute skew allowance",
    ("label.schema.json", "properties/label/properties/asserted_at"):
        "Publisher-supplied and read exactly as a Delta's `observed_at` (WIST-2 §3.3): compared "
        "to the same Labeler's other Labels of the subject and name, and to the validator's own "
        "clock under WIST-1 §3.4, never to a Block",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[5]/prefixItems[5]"):
        "the Label's own `asserted_at`, carried verbatim so a resuming Consumer orders a later "
        "Label against it (WIST-3 §7); a Publisher timestamp, never compared to a Block",
    ("label.schema.json", "properties/label/properties/expires_at"):
        "Publisher-supplied: the instant from which the Label applies nothing (WIST-2 §3.3), compared "
        "to `asserted_at` at validation and to a Block's `sealed_at` only when the Label is applied, "
        "as an instant the Publisher chose and the Block does not anchor",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[5]/prefixItems[6]/oneOf[0]"):
        "the Label's own `expires_at`, carried verbatim so a resuming Consumer drops the Label at the "
        "same instant a replaying one does (WIST-3 §7); a Publisher timestamp the Block does not anchor",
    ("dispute.schema.json", "properties/dispute/properties/asserted_at"):
        "Publisher-supplied and read exactly as a Label's `asserted_at` (WIST-2 §3.3): compared to the "
        "same disputant's other disputes of the Label and to the validator's own clock, never to a Block",
    ("label-definition.schema.json", "properties/definition/properties/asserted_at"):
        "Publisher-supplied and read as a Label's `asserted_at` (WIST-2 §3.3): a Consumer keeps the "
        "newest definition that verifies; never compared to a Block",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[8]/prefixItems[4]"):
        "the dispute's own `asserted_at`, carried verbatim so a resuming Consumer orders a later "
        "dispute against it (WIST-3 §7); a Publisher timestamp, never compared to a Block",
    ("publisher.schema.json", "properties/publisher/properties/keys/items/properties/valid_from"):
        "compared only to a Delta's own `observed_at` (WIST-1 §5.1), never to a Block",
    ("publisher.schema.json",
     "properties/publisher/properties/recovery_keys/items/properties/valid_from"):
        "compared only to a Delta's own `observed_at` (WIST-1 §5.1), never to a Block",
    ("log-anchor.schema.json", "properties/anchor/properties/created_at"):
        "descriptive: the Anchor is authenticated by its own signature and its out-of-band "
        "fingerprint (WIST-3 §3.4), and nothing compares this value to anything",
    ("snapshot-index.schema.json", "properties/index/properties/updated_at"):
        "descriptive: when the Aggregator last rewrote a mutable index (WIST-3 §6); a Snapshot is "
        "bound to the chain by `log_position` and `anchor_block_hash`, never by this",
    ("mirrors.schema.json", "properties/mirrors/properties/updated_at"):
        "descriptive: when the Aggregator last rewrote a mutable convenience list (WIST-3 §5), "
        "which no window reads and which a Consumer is told not to trust as its sole source",
    ("status.schema.json", "properties/last_pull_at"):
        "the Publisher's debugging surface (WIST-2 §7.1), not a signed Envelope and not an "
        "artifact any party verifies",
    ("status.schema.json", "properties/rejections/items/properties/at"):
        "the same unsigned debugging surface (WIST-2 §7.1): when the Aggregator recorded a typed "
        "rejection, reported to the Publisher and compared to nothing",
}

def _walk_timestamps(node, schema_name, found, key=None, root=None,
                     seen=frozenset(), path=""):
    """Every timestamp-format leaf in a schema, by the JSON path reaching it."""
    if root is None:
        root = node
    if not isinstance(node, dict):
        return found
    node = _resolve(node, root, seen)
    if not isinstance(node, dict):
        return found
    if node.get("$ref"):
        seen = seen | {node["$ref"]}
    if node.get("format") in ("date-time", "wist-publisher-timestamp"):
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

    WIST-4 §4 states that every window and admission test reads a Block
    `sealed_at`. A `date-time` field that takes part in such a comparison and
    is not constrained to that field's own form reopens, one field at a time,
    exactly what block.schema.json's pattern closed: an Aggregator writing
    `effective_at` a month in the past would put a parameter in force before
    the act existed, and every recomputing party agreed. So this enumerates
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
            assert pattern in (SEALED_AT_PATTERN, SEALED_AT_PATTERN + r"(?![\s\S])"), (
                f"{schema_name}: {spath} is compared against a Block `sealed_at` but carries "
                f"pattern {pattern!r}, not the whole-second-plus-Z form that field carries")
        else:
            publisher_field = (schema_name in ("delta.schema.json", "publisher.schema.json",
                                               "label.schema.json", "dispute.schema.json",
                                               "label-definition.schema.json")
                               or spath.endswith(("oneOf[5]/prefixItems[5]", "oneOf[5]/prefixItems[6]/oneOf[0]",
                                                  "oneOf[8]/prefixItems[4]")))
            assert pattern == (PUBLISHER_TIMESTAMP_PATTERN if publisher_field else None), (
                f"{schema_name}: {spath} has an unexpected unanchored timestamp pattern")
            assert len(declared) > 40, \
                f"{schema_name}: {spath} is declared unanchored with no stated reason"
    assert not undeclared, (
        "date-time fields declared neither anchored to a Block nor unanchored:\n  "
        + "\n  ".join(undeclared))
    stale = sorted(set(TIMESTAMP_FIELDS) - present)
    assert not stale, ("declarations for date-time fields that do not exist:\n  "
                       + "\n  ".join(f"{f}: {p}" for f, p in stale))
    anchored = {k for k, v in TIMESTAMP_FIELDS.items() if v is ANCHORED}
    assert len(anchored) == 4, \
        f"{len(anchored)} anchored timestamps; the class has four members"

    # Mutation proof, on the field the grace-period window reads:
    # the pattern must reject exactly the forms RFC 3339 permits and WIST-3 §3.1
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
    # And the documents must say which value a window reads, or an implementer
    # reading prose alone still runs a window off `effective_at`.
    wist4 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-governance.md").read_text())
    assert "MUST have `effective_at` ≥ 7 days after the Block's `sealed_at`" in wist4, \
        "WIST-4 §5 no longer measures the grace period from the Block's `sealed_at`"
    wist1 = (ROOT / "specs" / "WIST-1-delta-format.md").read_text()
    assert "opens at the `sealed_at` of the Block" in wist1, \
        "WIST-1 §5.2 no longer anchors the recovery window to the Declaration's own Entry"
check("schema:timestamp-anchoring", _timestamp_anchoring)


def _withdrawal_binds_every_serving_path():
    """A withdrawal reaches every path the Payload is served from, or none.

    The salt is published in exactly one kind of file, and three parties serve
    it: the Aggregator, every Mirror, and the Publisher's own well-known path
    (WIST-2 §3.1, WIST-3 §6.1). "After withdrawal the Log itself stops helping"
    (WIST-3 §11) is false at one fetch if any one of
    the three keeps serving — and WIST-2 separately obliges a Publisher to keep
    its anchor Payload retrievable, so leaving it unbound was not an omission
    but a conflict.
    """
    wist2 = (ROOT / "specs" / "WIST-2-site-publication.md").read_text()
    wist3 = (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text()
    withdrawal = wist3.split("### 6.2. Withdrawal")[1].split("## 7.")[0]
    stop = re.search(r"^- the Aggregator[^\n]*(?:\n(?!- ).*)*", withdrawal, re.M)
    assert stop, "WIST-3 §6.2 no longer opens its obligations with the stop-serving rule"
    # The *obligation* must name all three, not the paragraph explaining it: a
    # rule that binds two parties and then discusses the third at length reads
    # as covering it while binding nothing.
    clause = re.split(r"\.\s", stop.group(0))[0]
    assert "MUST stop" in clause, \
        "WIST-3 §6.2's first obligation is no longer the stop-serving rule"
    for party in ("Aggregator", "Mirror", "Publisher"):
        assert party in clause, \
            f"WIST-3 §6.2's stop-serving obligation does not bind the {party}"
    assert "every party holding the Payload for protocol purposes MUST destroy it" in withdrawal, \
        "WIST-3 §6.2 no longer requires holders to destroy the Payload and its salt"

    # The Snapshot artifacts are a fourth serving path, and the link graph is
    # one of their content tiers: a withdrawal that named `extracts.parquet`
    # alone would leave the withdrawn Payload's declared links in
    # distribution (WIST-3 §7), which is the same one-fetch hole the
    # stop-serving rule above exists to close. The bullet parsed above is the
    # *first* of §6.2's obligations, so this clause is not reached by it.
    materialization = re.search(
        r"^- Consumers MUST exclude[^\n]*(?:\n(?!- ).*)*", withdrawal, re.M)
    assert materialization, \
        "WIST-3 §6.2 no longer binds Snapshot artifacts already published"
    assert "tier1/links.parquet" in materialization.group(0), \
        "WIST-3 §6.2's Snapshot-artifact rule does not name tier1/links.parquet"

    # The conflicting duty must be reconciled where it is stated, not only
    # overridden from another document.
    retention = wist2.split("**Payload retention.**")[1].split("### 3.2.")[0]
    assert "payload_withdrawal" in retention and "MUST stop serving" in retention, \
        "WIST-2 §3.1's retention duty does not say that a withdrawal ends it"
    checklist = wist2.split("## 10. Conformance Checklist")[1].split("**Aggregator")[0]
    assert "payload_withdrawal" in checklist, \
        "WIST-2's Publisher checklist has no row for stopping service on a withdrawal"

    # And the claims that rest on it must still be the claims being made, or
    # this check is guarding a guarantee the suite no longer states.
    assert "the Log itself\nstops helping" in wist3, \
        "WIST-3 §11 no longer claims the Log stops helping after a withdrawal"
check("spec:withdrawal-serving-paths", _withdrawal_binds_every_serving_path)


def _negative_index():
    """A proof carrying a falsified index MUST NOT verify (WIST-3 §4)."""
    import copy
    block = copy.deepcopy(json.loads((ROOT / "vectors" / "wist3" / "block.json").read_text()))
    proof = copy.deepcopy(json.loads((ROOT / "vectors" / "wist3" / "inclusion-proof.json").read_text()))
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
    """No non-HTTPS key-discovery mechanism may reappear (WIST-1 §5.1, §8).

    The rule guards a *mechanism*, not a word. Banning the string "DNS"
    outright would forbid WIST-1 §8 from naming the fallback it removed, and a
    door whose closing is undocumented is one a later editor reopens in good
    faith; it would also miss a reintroduction under any other name. So the
    guard is written over what an implementation would actually have to
    publish: the well-known record label, and a section heading offering the
    fallback as a defined alternative.
    """
    label = re.compile(r"_wist\.")
    heading = re.compile(r"^#{2,6}\s.*\b(DNS|TXT)\b.*\bfallback\b", re.I | re.M)
    wist1 = (ROOT / "specs" / "WIST-1-delta-format.md").read_text()
    security = wist1.split("## 8. Security Considerations")[1].split("## 9.")[0]
    allowed = set(security.splitlines())     # the one place the label may appear
    hits = []
    for path in sorted((ROOT / "specs").glob("*.md")):
        text = path.read_text()
        for n, line in enumerate(text.splitlines(), 1):
            if label.search(line) and line not in allowed:
                hits.append(f"{path.relative_to(ROOT)}:{n}: names the TXT record label "
                            f"outside WIST-1 §8, where only its removal is recorded")
        for m in heading.finditer(text):
            hits.append(f"{path.relative_to(ROOT)}: defines a fallback section: {m.group(0).strip()!r}")
    assert not hits, "a non-HTTPS discovery channel has reappeared:\n  " + "\n  ".join(hits)

    # The removal must stay documented, or the guard above protects nothing a
    # reader can see: WIST-1 §8 names the mechanism and ADR-0002 records why.
    assert "_wist." in security, \
        "WIST-1 §8 no longer names the removed TXT-record mechanism, so the closed door is invisible"
    assert re.search(r"there is no alternative channel", wist1), \
        "WIST-1 §5.1 no longer states that HTTPS is the only discovery channel"
    adr = (ROOT / "decisions" / "0002-ed25519-domain-anchored-identity.md").read_text()
    decision = adr.split("## Decision")[1].split("## Consequences")[0]
    assert "fallback" in decision and "_wist." in decision, \
        "ADR-0002's accepted decision no longer records the removed fallback"
    assert "(DNS TXT fallback)" not in adr, \
        "ADR-0002 still lists the fallback as part of the accepted decision"
check("spec:single-discovery-channel", _single_discovery_channel)


def _block_frame_vectors():
    vector = json.loads((ROOT / "vectors/wist3/block-frames.json").read_text())
    assert vector["block"] == json.loads((ROOT / "examples/block.json").read_text())
    canonical = rfc8785.dumps(vector["block"])
    fragments = {name: bytes.fromhex(value) for name, value in vector["fragments_hex"].items()}
    for case in vector["cases"]:
        raw = b"".join(fragments[name] for name in case["parts"])
        try:
            decoded = decode_raw_fixture(raw, case["bound"])
        except ValueError:
            result = "WIST3-E03"
        else:
            assert decoded == canonical, case["label"]
            result = "valid"
        assert result == case["expected"], case["label"]
    for tail in ("empty", "skippable empty", "skippable payload"):
        assert decode_raw_fixture(fragments["block"], len(canonical)) == canonical
        assert any(case["parts"] == ["block", tail] and case["expected"] == "WIST3-E03"
                   for case in vector["cases"]), tail

check("vectors:wist3-block-frames", _block_frame_vectors)

def _log_timestamp_vectors():
    vector = json.loads((ROOT / "vectors/wist3/timestamps.json").read_text())
    for case in vector["cases"]:
        try:
            result = log_seconds(case["value"])
        except ValueError:
            result = None
        assert result == case["epoch_seconds"], case["value"]
    for case in vector["distances"]:
        assert log_seconds(case["to"]) - log_seconds(case["from"]) == case["seconds"]
    exercised = set()
    for case in vector["field_cases"]:
        validator = Draft202012Validator(json.loads((ROOT / "schemas" / case["schema"]).read_text()))
        assert validator.is_valid(case["document"]), case["path"]
        for value, expected in ((vector["field_accept"], True), (vector["field_reject"], False),
                                (vector["field_reject_non_ascii"], False)):
            document = copy.deepcopy(case["document"])
            target = document
            for key in case["path"][:-1]:
                target = target[key]
            target[case["path"][-1]] = value
            assert validator.is_valid(document) == expected, (case["schema"], case["path"], value)
        identity = case["schema"], tuple(case["path"])
        if case["schema"] == "snapshot-state.schema.json":
            identity += (case["document"]["state"]["entries"][0][0],)
        exercised.add(identity)
    assert len(exercised) == 9, "all four fields and five Snapshot timestamp positions required"
    snapshot = json.loads((ROOT / "schemas/snapshot-state.schema.json").read_text())
    def patterns(node):
        if isinstance(node, dict):
            if node.get("pattern") == SEALED_AT_PATTERN:
                yield node
            for child in node.values():
                yield from patterns(child)
        elif isinstance(node, list):
            for child in node:
                yield from patterns(child)
    assert len(list(patterns(snapshot))) == 2, "Snapshot timestamp inventory changed"

check("vectors:wist3-timestamps", _log_timestamp_vectors)

def _delta_diagnostic_vectors():
    vector = json.loads((ROOT / "vectors/wist1/delta-diagnostics.json").read_text())
    original = copy.deepcopy(vector)
    previous_source = vector["previous_declaration"]
    assert _declaration_binding_result(None, previous_source) == "initial"
    formats = FormatChecker(formats=[])
    formats.checks("wist-canonical-host")(_declaration_host_format)
    formats.checks("wist-publisher-timestamp")(_publisher_timestamp_format)
    validators = {name: Draft202012Validator(json.loads(
        (ROOT / f"schemas/{name}.schema.json").read_text()), format_checker=formats)
        for name in ("publisher", "delta")}
    validators["publisher"].validate(previous_source)
    key = previous_source["publisher"]["keys"][0]
    public = canonical_b64u_decode(key["public_key"])

    def signed(envelope, inner):
        return _ed25519_profile_verdict(public, b64u_decode(envelope["sig"]["value"]),
                                       rfc8785.dumps(envelope[inner]))[0]

    def diagnostics(case):
        envelope = case["envelope"]
        rfc8785.dumps(envelope["delta"])
        try:
            observed = publisher_instant(envelope["delta"].get("observed_at"))
            if len(canonical_b64u_decode(envelope["sig"]["value"])) != 64:
                raise ValueError("signature length")
        except ValueError:
            return {"WIST1-E14"}
        validators["delta"].validate(envelope)
        source = case["declaration"]["publisher"]
        bindings = [binding for binding in source["keys"]
                    if binding["key_id"] == envelope["sig"]["key_id"]
                    and publisher_instant(binding["valid_from"]) <= observed]
        errors = set()
        if not bindings:
            errors.add("WIST1-E02")
        elif not signed(envelope, "delta"):
            errors.add("WIST1-E01")
        url = envelope["delta"]["url"]
        assert url == "https://other.example/page"
        if "other.example" not in [source["domain"], *source.get("subdomain_scope", [])]:
            errors.add("WIST1-E03")
        if observed > publisher_instant(case["validator_time"]) + case["clock_skew_seconds"]:
            errors.add("WIST1-E06")
        previous = case["predecessor"]["delta"]
        assert previous["url"] == url
        assert envelope["delta"]["prev"] == "sha256:" + hashlib.sha256(rfc8785.dumps(previous)).hexdigest()
        if observed <= publisher_instant(previous["observed_at"]):
            errors.add("WIST1-E07")
        return errors

    sets, fields, signatures = set(), set(), set()
    for case in vector["cases"]:
        source, predecessor, envelope = case["declaration"], case["predecessor"], case["envelope"]
        validators["publisher"].validate(source)
        validators["delta"].validate(predecessor)
        assert _declaration_binding_result(previous_source, source) == "ordinary_rotation"
        assert source["publisher"]["keys"][0]["public_key"] == key["public_key"]
        assert signed(predecessor, "delta")
        assert predecessor["sig"]["key_id"] == key["key_id"]
        assert publisher_instant(predecessor["delta"]["observed_at"]) >= publisher_instant(key["valid_from"])
        assert "other.example" in previous_source["publisher"]["subdomain_scope"]
        got = diagnostics(case)
        assert got == set(case["allowed"]), case["name"]
        sets.add(frozenset(got))
        fields.add(case["field"])
        signatures.add(signed(envelope, "delta"))
        if case["field"] == "signature encoding":
            decoded = b64u_decode(envelope["sig"]["value"])
            repaired = copy.deepcopy(case)
            repaired["envelope"]["sig"]["value"] = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode()
            assert "WIST1-E14" not in diagnostics(repaired)
        damaged = copy.deepcopy(predecessor)
        damaged["delta"]["observed_at"] = "2026-08-01T01:00:00Z"
        assert not signed(damaged, "delta")
    expected_sets = {frozenset(subset) for size in range(5)
                     for subset in itertools.combinations(
                         ("WIST1-E01", "WIST1-E02", "WIST1-E03", "WIST1-E06", "WIST1-E07"), size)
                     if not {"WIST1-E01", "WIST1-E02"} <= set(subset)}
    assert sets == expected_sets | {frozenset({"WIST1-E14"})}
    assert len(vector["cases"]) == 96
    assert fields == {"valid", "timestamp", "signature encoding"}
    assert signatures == {True, False}
    assert vector == original


check("vectors:wist1-delta-diagnostics", _delta_diagnostic_vectors)


def _delta_field_vectors():
    vector = json.loads((ROOT / "vectors/wist1/delta-fields.json").read_text())
    original = copy.deepcopy(vector)
    schema = json.loads((ROOT / "schemas/delta.schema.json").read_text())
    fields = copy.deepcopy(schema)
    fields["allOf"] = [fields["allOf"][1]]
    properties = fields["properties"]["delta"]["properties"]
    properties["url"] = {"type": "string"}
    properties["payload"]["properties"]["bytes"]["maximum"] = 9007199254740991
    formats = FormatChecker(formats=[])
    formats.checks("wist-canonical-host")(_declaration_host_format)
    formats.checks("wist-publisher-timestamp")(_publisher_timestamp_format)
    validator = Draft202012Validator(fields, format_checker=formats)
    complete = Draft202012Validator(schema, format_checker=formats)
    public = canonical_b64u_decode(vector["author_key"])

    def diagnostics(doc, url_cap=2048, commitment_cap=38944):
        rfc8785.dumps(doc)
        if not validator.is_valid(doc):
            return {"WIST1-E14"}
        body = doc["delta"]
        errors = set()
        if body["wist_version"].partition(".")[0] != "1":
            errors.add("WIST1-E15")
        if not _ed25519_profile_verdict(public, canonical_b64u_decode(doc["sig"]["value"]),
                                       rfc8785.dumps(body))[0]:
            errors.add("WIST1-E01")
        if body["change_type"] != "new" and "prev" not in body:
            errors.add("WIST1-E07")
        if body["change_type"] in ("new", "update") and "payload" not in body:
            errors.add("WIST1-E09")
        if body.get("payload", {}).get("bytes", 0) > commitment_cap:
            errors.add("WIST1-E04")
        if len(rfc8785.dumps(body["url"])) > url_cap:
            errors.add("WIST1-E11")
        assert re.fullmatch(r"https?://example\.com/[a-z]*", body["url"])
        if not body["url"].startswith("https:"):
            errors.add("WIST1-E03")
        return errors

    errors_seen = set()
    for case in vector["cases"]:
        doc = case["envelope"]
        assert case["id"] == "sha256:" + hashlib.sha256(rfc8785.dumps(doc["delta"])).hexdigest()
        actual = diagnostics(doc, case.get("url_cap_bytes", 2048), case.get("commitment_cap_bytes", 38944))
        assert actual == set(case["allowed"]), (case["name"], actual)
        errors_seen |= actual
        if not actual - {"WIST1-E01", "WIST1-E11"} and "commitment_cap_bytes" not in case and "url_cap_bytes" not in case:
            complete.validate(doc)
        if isinstance(doc.get("sig"), dict) and "value" in doc["sig"]:
            verified = _ed25519_profile_verdict(public, canonical_b64u_decode(doc["sig"]["value"]),
                                               rfc8785.dumps(doc["delta"]))[0]
            assert verified == (not case["name"].endswith(" with invalid signature")), case["name"]
    assert errors_seen == {"WIST1-E01", "WIST1-E03", "WIST1-E04", "WIST1-E07", "WIST1-E09", "WIST1-E11", "WIST1-E14", "WIST1-E15"}
    assert len(vector["cases"]) == 200
    for case in vector["transport_cases"]:
        doc = case["envelope"]
        assert _ed25519_profile_verdict(public, canonical_b64u_decode(doc["sig"]["value"]),
                                       rfc8785.dumps(doc["delta"]))[0]
        actual_id = "sha256:" + hashlib.sha256(rfc8785.dumps(doc["delta"])).hexdigest()
        got = "WIST1-E14" if not validator.is_valid(doc) else (
            "WIST2-E03" if actual_id != case["requested_id"] or doc["delta"]["publisher"] != case["feed_domain"]
            else "association_satisfied")
        assert got == case["expected"]
    assert len(vector["transport_cases"]) == 8
    assert vector == original


check("vectors:wist1-delta-fields", _delta_field_vectors)


def _delta_attribution_vectors():
    vector = json.loads((ROOT / "vectors/wist1/delta-attribution.json").read_text())
    original = copy.deepcopy(vector)
    formats = FormatChecker(formats=[])
    formats.checks("wist-canonical-host")(_declaration_host_format)
    formats.checks("wist-publisher-timestamp")(_publisher_timestamp_format)
    validators = {name: Draft202012Validator(json.loads(
        (ROOT / f"schemas/{name}.schema.json").read_text()), format_checker=formats)
        for name in ("publisher", "delta")}

    def digest(inner):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(inner)).hexdigest()

    def result(env, sources, scopes, feed=None, tips=None, sealed=None, seen=None):
        inner = env["delta"]
        try:
            if not isinstance(inner.get("publisher"), str) or not _declaration_host_format(inner["publisher"]):
                return "WIST1-E14"
            observed = publisher_instant(inner.get("observed_at"))
            signature = canonical_b64u_decode(env["sig"]["value"])
            if len(signature) != 64:
                return "WIST1-E14"
        except (ValueError, TypeError):
            return "WIST1-E14"
        validators["delta"].validate(env)
        domain = inner["publisher"]
        if feed is not None and domain != feed:
            return "WIST2-E03"
        if feed is not None and seen is not None and digest(inner) in seen.get(feed, set()):
            return "accepted"
        candidates = []
        for source in sources.get(domain, []):
            for key in source["publisher"]["keys"]:
                if key["key_id"] != env["sig"]["key_id"]:
                    continue
                public = canonical_b64u_decode(key["public_key"])
                try:
                    point = ed25519_curve.string_to_point(public)
                except ValueError:
                    continue
                if ed25519_curve._is_identity(ed25519_curve._mul(8, point)):
                    continue
                if publisher_instant(key["valid_from"]) <= observed:
                    candidates.append(public)
        if not candidates:
            return "WIST1-E02"
        if not any(_ed25519_profile_verdict(public, signature, rfc8785.dumps(inner))[0]
                   for public in candidates):
            return "WIST1-E01"
        host = inner["url"].split("/", 3)[2]
        if host not in scopes[domain]:
            return "WIST1-E03"
        if tips is not None:
            key = domain, inner["url"]
            previous = inner.get("prev")
            if previous != tips.get(key):
                return "WIST1-E07"
            if previous is not None:
                old = sealed[previous]["delta"]
                if (old["publisher"], old["url"]) != key:
                    return "WIST1-E07"
                if observed <= publisher_instant(old["observed_at"]):
                    return "WIST1-E07"
        return "accepted"

    for case in vector["cases"]:
        declarations = case["declarations"]
        for env in declarations:
            validators["publisher"].validate(env)
            assert _declaration_binding_result(None, env) == "initial", case["name"]
        assert len(case["envelopes"]) == len(case["expected"]) == len(case["delta_ids"])
        for order in (declarations, list(reversed(declarations))):
            sources = {env["publisher"]["domain"]: [env] for env in order}
            scopes = {domain: [domain, *envs[0]["publisher"].get("subdomain_scope", [])]
                      for domain, envs in sources.items()}
            for env, expected, id_ in zip(case["envelopes"], case["expected"], case["delta_ids"]):
                assert digest(env["delta"]) == id_
                seen = {env["delta"].get("publisher", "example.com"): {id_}} if case.get("already_seen") else {}
                if "serving_host" in case:
                    assert case["serving_host"] in scopes[case["feed_domain"]]
                assert result(env, sources, scopes, case.get("feed_domain"), seen=seen) == expected, case["name"]
                if expected == "accepted":
                    damaged = copy.deepcopy(env)
                    damaged["delta"]["observed_at"] = "2026-08-02T12:00:01Z"
                    assert result(damaged, sources, scopes, case.get("feed_domain")) == "WIST1-E01"
        if len(case["envelopes"]) == 2:
            left, right = case["envelopes"]
            assert len(set(case["delta_ids"])) == 2
            assert {k: v for k, v in left["delta"].items() if k != "publisher"} == {
                    k: v for k, v in right["delta"].items() if k != "publisher"}
            assert left["sig"]["value"] != right["sig"]["value"]
    cases = {case["name"]: case for case in vector["cases"]}
    assert len(cases) == 30
    assert cases["author tampering requires a new signature even with shared keys"]["delta_ids"][0] == cases[
        "shared keys retain separate authors and IDs"]["delta_ids"][1]
    assert cases["unsigned alias cannot borrow another domain's key"]["delta_ids"][0] == cases[
        "shared keys retain separate authors and IDs"]["delta_ids"][0]
    for name in ("Feed association child.example.com seen", "Feed association child.example.com new"):
        assert cases[name]["expected"] == ["WIST2-E03"]

    authenticated = _declaration_history_blocks(vector, vector["blocks"], vector["pinned_head"],
                                                 ("publisher_declaration", "publisher_delta"))
    _, _, _, apply_block = _recovery_history_reference(vector)
    states, frozen, tips, sealed, snapshots, accepted_at = {}, {}, {}, {}, {}, {}
    for header, declarations in authenticated:
        height = header["block_number"]
        before = copy.deepcopy(states)
        outcome, states = apply_block(states, header, declarations)
        assert outcome == "accepted"
        for domain, state in states.items():
            if state["chain"] is None:
                frozen.pop(domain, None)
            elif domain not in frozen:
                owner = state["chain"]
                previous = before[domain]["current"]
                assert owner["publisher"]["prev_declaration"] == digest(previous["publisher"])
                frozen[domain] = [previous, owner]
        current = {domain: [state["chain"] or state["current"]] for domain, state in states.items()}
        scopes = {domain: [domain, *envs[0]["publisher"].get("subdomain_scope", [])]
                  for domain, envs in current.items()}
        for entry in vector["blocks"][height]["entries"]:
            if entry["type"] != "publisher_delta":
                continue
            env = entry["body"]; domain = env["delta"]["publisher"]
            assert states[domain]["chain"] is None, "open recovery cannot seal Deltas"
            assert result(env, current, scopes, tips=tips, sealed=sealed) == "accepted", height
            id_ = digest(env["delta"])
            assert id_ not in sealed
            sealed[id_] = env
            tips[(domain, env["delta"]["url"])] = id_
            accepted_at[(height, domain)] = env
        snapshots[height] = copy.deepcopy((states, frozen, tips, sealed, scopes))
    assert len(sealed) == 6 and len(tips) == 2
    assert snapshots[170][0]["example.com"]["floor"] == 4
    assert snapshots[171][0]["example.com"]["reset_height"] == 171
    assert snapshots[4][0]["example.com"]["reset_height"] is None
    for probe in vector["probes"]:
        states, frozen, tips, sealed, scopes = snapshots[probe["height"]]
        sources = {domain: [state["chain"] or state["current"]] for domain, state in states.items()}
        if probe["stage"] == "admission":
            sources.update(frozen)
        actual = result(probe["envelope"], sources, scopes, tips=tips, sealed=sealed)
        assert actual == probe["expected"], (probe["name"], actual, probe["expected"])
    for case in vector["projection_cases"]:
        states = snapshots[case["at_height"]][0]
        env = accepted_at[(case["reference_height"], case["publisher"])]
        domain = env["delta"]["publisher"]
        assert domain == case["publisher"]
        reset = states[domain]["reset_height"]
        counted = reset is None or case["reference_height"] >= reset
        assert counted == case["expected_current_identity"]
        eligible_subjects = {subject for subject in states if counted and subject == domain}
        assert eligible_subjects == ({case["publisher"]} if case["expected_current_identity"] else set())
        assert ("child.example.com" in eligible_subjects) == (
            case["publisher"] == "child.example.com" and case["expected_current_identity"])
    for case in vector["version_cases"]:
        env = case["envelope"]
        if not validators["delta"].is_valid(env):
            actual = "WIST1-E14"
        elif env["delta"]["wist_version"].partition(".")[0] != "1":
            actual = "WIST1-E15"
        else:
            source = vector["cases"][0]["declarations"][0]
            actual = result(env, {"example.com": [source]},
                            {"example.com": ["example.com", "child.example.com"]})
        assert actual == case["expected"]
    assert vector == original


check("vectors:wist1-delta-attribution", _delta_attribution_vectors)

def _signed_delta_appendices():
    envelope = json.loads((ROOT / "vectors/wist1/envelope.json").read_text())
    canonical = rfc8785.dumps(envelope["delta"])
    delta_id = "sha256:" + hashlib.sha256(canonical).hexdigest()
    prose = (ROOT / "specs/WIST-1-delta-format.md").read_text().split("## Appendix A.")[1]
    inner = prose.split("**Delta (inner object):**")[1].split("```json\n")[1].split("\n```")[0]
    assert json.loads(inner) == envelope["delta"]
    payload = prose.split("**Payload (")[1].split("```json\n")[1].split("\n```")[0]
    assert json.loads(payload) == json.loads((ROOT / "examples/payload.json").read_text())
    size = len(rfc8785.dumps(json.loads(payload)["content"]))
    assert size == envelope["delta"]["payload"]["bytes"]
    assert f"`JCS(content)` is {size} octets" in prose
    assert delta_id in prose and envelope["sig"]["value"] in prose
    assert canonical[:32].hex() in prose and canonical[32:64].hex() in prose
    block = json.loads((ROOT / "vectors/wist3/block.json").read_text())
    prose = (ROOT / "specs/WIST-3-logbook-distribution.md").read_text().split("## Appendix A.")[1]
    leaves = [leaf_hash(rfc8785.dumps(entry)) for entry in block["entries"]]
    for index, value in enumerate(leaves):
        assert f"leaf{index} = {value.hex()}" in prose
    assert block["header"]["merkle_root"] in prose
    assert "sha256:" + hashlib.sha256(rfc8785.dumps(block["header"])).hexdigest() in prose
    for index in (0, 2):
        assert hashlib.sha256(b"\x01" + leaves[index] + leaves[index + 1]).hexdigest() in prose
    assert f"/payloads/{delta_id[7:]}.json" in prose


check("spec:signed-delta-appendices", _signed_delta_appendices)

def _recovery_scope_vectors():
    vector = json.loads((ROOT / "vectors/wist1/recovery-scope.json").read_text())
    original = copy.deepcopy(vector)
    formats = FormatChecker(formats=[])
    formats.checks("wist-canonical-host")(_declaration_host_format)
    formats.checks("wist-publisher-timestamp")(_publisher_timestamp_format)
    validators = {name: Draft202012Validator(json.loads(
        (ROOT / f"schemas/{name}.schema.json").read_text()), format_checker=formats)
        for name in ("publisher", "delta")}
    _, _, _, apply_block = _recovery_history_reference(vector)
    snapshots, settlements = {}, {}

    def digest(inner):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(inner)).hexdigest()

    for name, history in vector["histories"].items():
        authenticated = _declaration_history_blocks(vector, history["blocks"], history["pinned_head"])
        states, frozen = {}, {}
        accepted = {}
        for header, declarations in authenticated:
            height = header["block_number"]
            for domain, state in states.items():
                if state["end"] and log_seconds(header["sealed_at"]) >= log_seconds(state["end"]):
                    settlements[name, height, domain] = state["chain"]
                    frozen.pop(domain)
            for env in declarations:
                validators["publisher"].validate(env)
            outcome, updated = apply_block(states, header, declarations)
            assert outcome == "accepted", (name, height, outcome)
            by_domain = {}
            for env in declarations:
                by_domain.setdefault(env["publisher"]["domain"], []).append(env)
            for domain, envelopes in by_domain.items():
                state = states.get(domain)
                chain = state["chain"] if state and state["end"] and (
                    log_seconds(header["sealed_at"]) < log_seconds(state["end"])) else None
                for env in sorted(envelopes, key=lambda item: item["publisher"]["seq"]):
                    predecessor = accepted.get(env["publisher"].get("prev_declaration"))
                    classification = _declaration_binding_result(predecessor, env)
                    assert classification in {"initial", "ordinary_rotation", "recovery_rotation", "fresh_identity"}
                    if chain is None and classification == "recovery_rotation":
                        frozen[domain] = [predecessor, env]
                        chain = env
                    accepted[digest(env["publisher"])] = env
            states = updated
            sources = {domain: frozen.get(domain, [state["current"]]) for domain, state in states.items()}
            snapshots[name, height] = copy.deepcopy((states, sources))
        assert len(authenticated) == 171
        state, sources = snapshots[name, 1]
        assert [env["publisher"]["seq"] for env in sources["example.com"]] == [1, 2]
        assert snapshots[name, 168][0]["example.com"]["current"]["publisher"]["seq"] == 5
        assert settlements[name, 169, "example.com"]["publisher"]["seq"] == 4
        assert snapshots[name, 169][0]["example.com"]["current"]["publisher"]["seq"] == 6

    def authority(env, sources, stage):
        inner = env["delta"]
        try:
            observed = publisher_instant(inner["observed_at"])
            signature = canonical_b64u_decode(env["sig"]["value"])
            if len(signature) != 64 or not _declaration_host_format(inner["publisher"]):
                return "WIST1-E14"
        except (ValueError, TypeError):
            return "WIST1-E14"
        validators["delta"].validate(env)
        eligible, verified, covering = [], [], []
        for source in sources:
            declaration = source["publisher"]
            if declaration["domain"] != inner["publisher"]:
                continue
            for binding in declaration["keys"]:
                if binding["key_id"] != env["sig"]["key_id"]:
                    continue
                raw = canonical_b64u_decode(binding["public_key"])
                try:
                    point = ed25519_curve.string_to_point(raw)
                except ValueError:
                    continue
                if ed25519_curve._is_identity(ed25519_curve._mul(8, point)) or publisher_instant(binding["valid_from"]) > observed:
                    continue
                eligible.append(binding)
                if _ed25519_profile_verdict(raw, signature, rfc8785.dumps(inner))[0]:
                    verified.append(binding)
                    if inner["url"].split("/", 3)[2] in {
                            declaration["domain"], *declaration.get("subdomain_scope", [])}:
                        covering.append(binding)
        result = ("WIST1-E02" if not eligible else "WIST1-E01" if not verified else
                  "WIST1-E03" if not covering else "accepted")
        if stage == "settlement" and result != "accepted":
            return "WIST1-E13"
        return result

    outcomes, settlement_copies = set(), set()
    for probe in vector["probes"]:
        name, height, stage, env = (probe[key] for key in ("history", "height", "stage", "envelope"))
        domain = env["delta"]["publisher"]
        states, admission = snapshots[name, height]
        if stage == "settlement":
            sources = [settlements[name, height, domain]]
        elif stage == "admission":
            sources = admission[domain]
        else:
            assert stage == "sealing" and states[domain]["chain"] is None
            sources = [states[domain]["current"]]
        for ordering in (sources, list(reversed(sources))):
            actual = authority(env, ordering, stage)
            assert actual == probe["expected"], (name, probe["name"], actual, probe["expected"])
        outcomes.add(actual)
        if stage == "settlement" and "queued copy" in probe["name"]:
            assert authority(env, snapshots[name, 1][1][domain], "admission") == "accepted"
            settlement_copies.add((name, digest(env["delta"])))
            if probe["expected"] == "WIST1-E13" and "owner queued" in probe["name"]:
                assert authority(env, snapshots[name, 170][1][domain], "admission") == "accepted"
        if actual == "accepted":
            damaged = copy.deepcopy(env)
            damaged["sig"]["value"] = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()
            assert authority(damaged, sources, stage) == ("WIST1-E13" if stage == "settlement" else "WIST1-E01")
        if probe["name"] == "historical pre recovery scope":
            assert authority(env, snapshots[name, 169][1][domain], "sealing") != "accepted"
    assert outcomes == {"accepted", "WIST1-E01", "WIST1-E02", "WIST1-E03", "WIST1-E13", "WIST1-E14"}
    assert len(settlement_copies) == 8
    assert vector == original


check("vectors:wist1-recovery-scope", _recovery_scope_vectors)

def _recovery_admission_vectors():
    vector = json.loads((ROOT / "vectors/wist1/recovery-admission.json").read_text())
    original = copy.deepcopy(vector)
    apply, _, replay, _ = _recovery_history_reference(vector)
    prefix_states = replay(vector["blocks"], vector["pinned_head"])
    prefix = prefix_states[-1]
    declarations = vector["declarations"]
    deadline = log_seconds(vector["deadline"])
    assert log_seconds(prefix["end"]) == deadline
    def identity(envelope):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(envelope["publisher"])).hexdigest()
    names = {identity(envelope): name for name, envelope in declarations.items()}
    def name(envelope):
        return names[identity(envelope)]
    def compact(state):
        return {"current": name(state["current"]), "floor": state["floor"]}

    classifications, removed_kinds, revival_count = set(), set(), 0
    for case in vector["cases"]:
        admitted_at = log_seconds(case["admitted_at"])
        assert log_seconds(vector["blocks"][1]["header"]["sealed_at"]) < admitted_at < deadline
        preceding = max(index for index, block in enumerate(vector["blocks"])
                        if log_seconds(block["header"]["sealed_at"]) < admitted_at)
        admission = copy.deepcopy(prefix_states[preceding])
        accepted_chain, kinds = {identity(prefix["chain"])}, {}
        for label in case["admitted"]:
            envelope = declarations[label]
            previous_chain = identity(admission["chain"])
            result = apply(admission, envelope, admitted_at, case["admitted_at"], len(vector["blocks"]))
            assert result in {"ordinary_rotation", "recovery_rotation", "fresh_identity"}, (case["name"], label, result)
            classifications.add(result)
            kinds[label] = result
            if identity(admission["chain"]) != previous_chain:
                accepted_chain.add(identity(envelope))
            damaged = copy.deepcopy(envelope)
            damaged["sig"]["value"] = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()
            assert _declaration_binding_result(
                next(env for env in declarations.values()
                     if identity(env) == envelope["publisher"]["prev_declaration"]), damaged
            ) == "WIST1-E01"

        inside = case["last_inside_block"]
        sealed_names = {name(entry["body"]) for entry in inside["entries"]}
        assert sealed_names <= set(case["admitted"])
        if sealed_names:
            assert admitted_at < log_seconds(inside["header"]["sealed_at"])
        sealed_prefix = vector["blocks"] + [inside]
        sealed = replay(sealed_prefix, case["last_inside_pin"])[-1]
        queue_source = name(sealed["chain"])
        pending = [label for label in case["admitted"] if label not in sealed_names]
        retained = [label for label in pending if identity(declarations[label]) in accepted_chain]
        removed = [label for label in pending if label not in retained]
        removed_kinds.update(kinds[label] for label in removed)
        admission["current"] = admission["chain"]
        admission["chain"], admission["end"] = None, None
        expected = case["expected_settlement"]
        actual = dict(compact(admission), queue_source=queue_source, retained=retained, removed=removed)
        assert actual == expected, (case["name"], actual, expected)
        assert admission["reset_height"] == prefix["reset_height"]
        elapsed_blocks = sum(log_seconds(block["header"]["sealed_at"]) > admitted_at
                             for block in sealed_prefix)
        assert elapsed_blocks in {0, 1, 166}
        overdue = elapsed_blocks > 24 and any(kinds[label] == "recovery_rotation" for label in removed)
        assert overdue == case["removed_recovery_sealing_violation"]

        included = list(retained)
        for probe in case["at_deadline"]:
            envelope = declarations[probe["declaration"]]
            before = copy.deepcopy(admission)
            result = apply(admission, envelope, deadline, vector["deadline"], len(sealed_prefix))
            assert result == probe["expected"], case["name"]
            if result == "WIST1-E08":
                assert admission == before
            else:
                included.append(probe["declaration"])
                if result == "fresh_identity":
                    assert admission["reset_height"] == len(sealed_prefix)
        assert compact(admission) == case["expected_after_repeat"]
        resumed = json.loads(json.dumps(admission))
        result = apply(resumed, resumed["current"], deadline + 1, vector["deadline"], len(sealed_prefix))
        assert result == "idempotent" and resumed == admission
        assert compact(resumed) == case["expected_after_repeat"]

        sealed_block = case["deadline_block"]
        actual_members = {name(entry["body"]) for entry in sealed_block["entries"]}
        assert actual_members == set(included) and not actual_members.intersection(removed)
        final = replay(sealed_prefix + [sealed_block], case["deadline_pin"])[-1]
        assert dict(compact(final), window_end=final["end"], reset_height=final["reset_height"]) == case["expected_log"], case["name"]
        if "expected_window_owner" in case:
            projected = copy.deepcopy(sealed)
            owner = None
            for label in sorted(included, key=lambda label: declarations[label]["publisher"]["seq"]):
                windows = projected["windows"]
                result = apply(projected, declarations[label], deadline, vector["deadline"], len(sealed_prefix))
                assert result in {"ordinary_rotation", "recovery_rotation", "fresh_identity"}
                if projected["windows"] > windows:
                    assert owner is None
                    owner = label
            assert owner == case["expected_window_owner"]
            assert projected == final
        if "forbidden_revival" in case:
            revival = case["forbidden_revival"]
            revived = replay(sealed_prefix + [revival["block"]], revival["pin"])[-1]
            assert name(revived["current"]) == revival["log_current"]
            assert revived["reset_height"] == revival["log_reset_height"]
            assert actual_members != {name(entry["body"]) for entry in revival["block"]["entries"]}
            revival_count += 1
    assert classifications == removed_kinds == {"ordinary_rotation", "recovery_rotation", "fresh_identity"}
    assert revival_count >= 2
    assert len(vector["cases"]) == 11 and vector == original


check("vectors:wist1-recovery-admission", _recovery_admission_vectors)


def _declaration_refresh_vectors():
    vector = json.loads((ROOT / "vectors/wist2/declaration-refresh.json").read_text())
    formats = FormatChecker(formats=[])
    formats.checks("wist-canonical-host")(_declaration_host_format)
    formats.checks("wist-publisher-timestamp")(_publisher_timestamp_format)
    schemas = {kind: Draft202012Validator(json.loads(
        (ROOT / f"schemas/{kind}.schema.json").read_text()), format_checker=formats)
        for kind in ("publisher", "delta", "feed")}

    def verifies(key, doc, kind):
        return _ed25519_profile_verdict(canonical_b64u_decode(key["public_key"]),
            canonical_b64u_decode(doc["sig"]["value"]), rfc8785.dumps(doc[kind]))[0]

    def usable(encoded):
        try:
            point = ed25519_curve.string_to_point(canonical_b64u_decode(encoded))
            return not ed25519_curve._is_identity(ed25519_curve._mul(8, point))
        except ed25519_curve.InvalidProof:
            return False

    def diagnostic(source, doc, kind):
        if not schemas[kind].is_valid(doc):
            return "WIST1-E14" if kind == "delta" else "WIST2-E01"
        if kind == "delta" and doc[kind]["publisher"] != vector["domain"]:
            return "WIST2-E03"
        keys = [k for k in source["publisher"]["keys"] if k["key_id"] == doc["sig"]["key_id"]]
        if kind == "delta":
            keys = [k for k in keys if usable(k["public_key"])
                    and publisher_instant(k["valid_from"]) <= publisher_instant(doc[kind]["observed_at"])]
        if not keys:
            return "WIST1-E02" if kind == "delta" else "WIST2-E04"
        if any(verifies(k, doc, kind) for k in keys):
            return None
        return "WIST1-E01" if kind == "delta" else "WIST2-E04"

    for case in vector["cases"]:
        source = case["initial"]
        schemas["publisher"].validate(source)
        sealed = case.get("sealed", [])
        previous = None
        for entry in sealed:
            incoming = entry["envelope"]
            schemas["publisher"].validate(incoming)
            assert _declaration_binding_result(previous, incoming) == (
                "initial" if previous is None else "ordinary_rotation")
            previous = incoming
        if previous is None:
            assert _declaration_binding_result(None, source) == "initial"
        else:
            assert source == previous
        responses = iter(case["responses"])
        requests = 1
        def refresh():
            nonlocal source, requests
            incoming = next(responses)
            requests += 1
            if incoming is None or not schemas["publisher"].is_valid(incoming):
                return
            if incoming["publisher"] == source["publisher"]:
                assert any(verifies(k, incoming, "publisher") for k in source["publisher"]["keys"])
                return
            if _declaration_binding_result(source, incoming) == "ordinary_rotation":
                source = incoming

        objects = {entry["id"]: entry["envelope"] for entry in case["deltas"]}
        for id, doc in objects.items():
            assert id == "sha256:" + hashlib.sha256(rfc8785.dumps(doc["delta"])).hexdigest()
        budget = case["content_budget"]
        if isinstance(budget, str):
            budget = len(rfc8785.dumps(case["feed"])) + (
                sum(len(rfc8785.dumps(doc)) for doc in objects.values()) if budget == "feed and deltas"
                else len(rfc8785.dumps(case["page"])) if budget == "feed and page" else 0)
        if budget is None:
            budget = 10**9
        spent = 0
        suspended = False
        noise = None
        accepted, rejected, fetched, attempts = [], [], set(), set()
        def fetch(doc):
            nonlocal spent, suspended
            if spent >= budget:
                suspended = True
                return False
            spent += len(rfc8785.dumps(doc))
            return True

        if fetch(case["feed"]):
            feed_attempt = diagnostic(source, case["feed"], "feed") is not None
            if feed_attempt:
                refresh()
            assert diagnostic(source, case["feed"], "feed") is None, (case["name"], diagnostic(source, case["feed"], "feed"))
            if "page" in case and fetch(case["page"]):
                page = case["page"]
                schemas["feed"].validate(page)
                ordered = sorted(sealed, key=lambda entry: entry["at"])
                before = [entry for entry in ordered if entry["at"] <= page["feed"]["generated_at"]]
                after = [entry for entry in ordered if entry["at"] > page["feed"]["generated_at"]]
                eligible = before[-1:] + after[:1]
                if not any(diagnostic(entry["envelope"], page, "feed") is None for entry in eligible):
                    if not feed_attempt:
                        refresh()
                    assert not any(diagnostic(entry["envelope"], page, "feed") is None for entry in eligible)
                    noise = "WIST2-E04"
            def process(id):
                if id in accepted:
                    return
                doc = objects[id]
                if id not in fetched:
                    if not fetch(doc):
                        return
                    fetched.add(id)
                error = diagnostic(source, doc, "delta")
                if error in ("WIST1-E01", "WIST1-E02") and id not in attempts:
                    attempts.add(id)
                    refresh()
                    error = diagnostic(source, doc, "delta")
                if error:
                    rejected.append([id, error])
                    return
                prev = doc["delta"].get("prev")
                if prev and prev not in accepted:
                    process(prev)
                    if suspended:
                        return
                    assert prev in accepted
                    assert publisher_instant(objects[prev]["delta"]["observed_at"]) < publisher_instant(doc["delta"]["observed_at"])
                    assert objects[prev]["delta"]["url"] == doc["delta"]["url"]
                    error = diagnostic(source, doc, "delta")
                    if error:
                        assert id in attempts
                        rejected.append([id, error])
                        return
                if not fetch(vector["payload"]):
                    return
                accepted.append(id)
            for id in case["feed"]["feed"]["deltas"]:
                if noise or suspended:
                    break
                process(id)
                if suspended:
                    break
        actual = dict(accepted=accepted, rejected=rejected, suspended=suspended,
                      declaration_requests=requests)
        if "page" in case:
            actual["noise"] = noise
        assert actual == case["expected"], case["name"]
        assert next(responses, "exhausted") == "exhausted", case["name"]
    assert len(vector["cases"]) == 30


check("vectors:wist2-declaration-refresh", _declaration_refresh_vectors)

def _page_binding_vectors():
    vector = json.loads((ROOT / "vectors/wist2/page-bindings.json").read_text())
    original = copy.deepcopy(vector)
    schemas = {name: Draft202012Validator(json.loads(
        (ROOT / f"schemas/{name}.schema.json").read_text())) for name in ("publisher", "feed")}

    def usable(key):
        try:
            point = ed25519_curve.string_to_point(canonical_b64u_decode(key["public_key"]))
        except ed25519_curve.InvalidProof:
            return False
        return not ed25519_curve._is_identity(ed25519_curve._mul(8, point))

    def verifies(key, doc, inner):
        return _ed25519_profile_verdict(canonical_b64u_decode(key["public_key"]),
            canonical_b64u_decode(doc["sig"]["value"]), rfc8785.dumps(doc[inner]))[0]

    for sources in vector["histories"].values():
        previous = None
        last = None
        for source in sources:
            doc = source["envelope"]
            schemas["publisher"].validate(doc)
            assert _declaration_binding_result(previous, doc, usable,
                lambda key, env: verifies(key, env, "publisher")) == (
                    "initial" if previous is None else "ordinary_rotation")
            at = log_seconds(source["sealed_at"])
            assert last is None or last < at
            previous, last = doc, at

    def resolve(sources, doc):
        cut = log_seconds(doc["feed"]["generated_at"])
        ordered = sorted(sources, key=lambda source: (
            log_seconds(source["sealed_at"]), source["envelope"]["publisher"]["seq"]))
        before = [source for source in ordered if log_seconds(source["sealed_at"]) <= cut]
        after = [source for source in ordered if log_seconds(source["sealed_at"]) > cut]
        current = before[-1:] if before else []
        following = ([source for source in after if source["sealed_at"] == after[0]["sealed_at"]][-1:]
                     if after else [])
        for role, selected in (("current", current), ("next", following)):
            for source in selected:
                for key in source["envelope"]["publisher"]["keys"]:
                    if key["key_id"] == doc["sig"]["key_id"] and usable(key) and verifies(key, doc, "feed"):
                        return role
        return "WIST2-E04"

    for probe in vector["probes"]:
        doc = probe["envelope"]
        schemas["feed"].validate(doc)
        sources = vector["histories"][probe["history"]]
        assert resolve(sources, doc) == probe["expected"], probe["name"]
        assert resolve(list(reversed(sources)), doc) == probe["expected"], probe["name"]
        damaged = copy.deepcopy(doc)
        damaged["feed"]["domain"] = "tampered.example"
        assert resolve(sources, damaged) == "WIST2-E04", probe["name"]
    renamed = vector["probes"][0]
    current = vector["histories"]["renamed"][0]["envelope"]["publisher"]["keys"]
    assert renamed["expected"] == "next"
    assert any(verifies(key, renamed["envelope"], "feed") for key in current if usable(key))
    assert all(key["key_id"] != renamed["envelope"]["sig"]["key_id"] for key in current)
    assert len(vector["probes"]) == 16
    assert vector == original


check("vectors:wist2-page-bindings", _page_binding_vectors)


def _feed_field_vectors():
    vector = json.loads((ROOT / "vectors/wist2/feed-fields.json").read_text())
    original = copy.deepcopy(vector)
    formats = FormatChecker(formats=[])
    formats.checks("wist-canonical-host")(_declaration_host_format)

    def timestamp(value):
        if not isinstance(value, str):
            return True
        try:
            log_seconds(value)
            return True
        except ValueError:
            return False

    formats.checks("date-time")(timestamp)
    validator = Draft202012Validator(json.loads(
        (ROOT / "schemas/feed.schema.json").read_text()), format_checker=formats)
    source = vector["declaration"]
    key = source["publisher"]["keys"][0]
    public = canonical_b64u_decode(key["public_key"])
    assert _ed25519_profile_verdict(public, canonical_b64u_decode(source["sig"]["value"]),
                                  rfc8785.dumps(source["publisher"]))[0]
    observed = set()
    for case in vector["cases"]:
        doc = case["envelope"]
        try:
            signature = base64.urlsafe_b64decode(doc["sig"]["value"] + "==")
            author_signature = _ed25519_profile_verdict(public, signature, rfc8785.dumps(doc["feed"]))[0]
        except (KeyError, TypeError, ValueError):
            author_signature = False
        assert author_signature == case["author_signature"], case["name"]
        if not validator.is_valid(doc):
            phase = "fields"
        else:
            rfc8785.dumps(doc)
            if doc["feed"]["domain"] != vector["host"]:
                phase = "domain"
            elif (doc["sig"]["key_id"] != key["key_id"] or
                  not _ed25519_profile_verdict(public, canonical_b64u_decode(doc["sig"]["value"]),
                                              rfc8785.dumps(doc["feed"]))[0]):
                phase = "signature"
            else:
                phase = "accepted"
        assert phase == case["expected"], case["name"]
        assert case["code"] == {"fields": "WIST2-E01", "domain": "WIST2-E04",
                                "signature": "WIST2-E04", "accepted": None}[phase]
        assert case["rejection_noise"] == (phase in ("domain", "signature"))
        assert case["declaration_retries"] == int(phase == "signature")
        observed.add(phase)
    assert observed == {"fields", "domain", "signature", "accepted"}
    assert vector == original


check("vectors:wist2-feed-fields", _feed_field_vectors)

def _feed_next_vectors():
    vector = json.loads((ROOT / "vectors/wist2/feed-next.json").read_text())
    original = copy.deepcopy(vector)
    formats = FormatChecker(formats=[])
    formats.checks("wist-canonical-host")(_declaration_host_format)
    formats.checks("date-time")(lambda value: not isinstance(value, str) or
                               isinstance(log_seconds(value), int))
    validator = Draft202012Validator(json.loads(
        (ROOT / "schemas/feed.schema.json").read_text()), format_checker=formats)
    source = vector["declaration"]
    key = source["publisher"]["keys"][0]
    public = canonical_b64u_decode(key["public_key"])
    assert _ed25519_profile_verdict(public, canonical_b64u_decode(source["sig"]["value"]),
                                  rfc8785.dumps(source["publisher"]))[0]
    host = vector["host"]
    assert source["publisher"]["domain"] == host
    assert "www." + host in source["publisher"]["subdomain_scope"]
    prefix = f"https://{host}/.well-known/wist/"
    retained = log_seconds(vector["retained_generated_at"])
    w2 = (ROOT / "specs/WIST-2-site-publication.md").read_text()
    assert "MUST be byte-identical to its own Normalized URL (WIST-1 §2)\nand MUST begin with `https://`, the requested Canonical Host and\n`/.well-known/wist/`" in w2
    assert "An unread `next` is checked against nothing." in w2
    assert "the Deltas of the Feed and Pages\nalready fetched proceed under §5" in w2
    codes = {"fields": "WIST2-E01", "domain": "WIST2-E04", "signature": "WIST2-E04",
             "regression": "WIST2-E05", "unread": None, "end": None, "target": "WIST2-E01",
             "followed": None}
    observed = set()
    for case in vector["cases"]:
        doc = case["envelope"]
        if not validator.is_valid(doc):
            phase = "fields"
        else:
            rfc8785.dumps(doc)
            feed = doc["feed"]
            if feed["domain"] != host:
                phase = "domain"
            elif (doc["sig"]["key_id"] != key["key_id"] or
                  not _ed25519_profile_verdict(public, canonical_b64u_decode(doc["sig"]["value"]),
                                              rfc8785.dumps(feed))[0]):
                phase = "signature"
            elif case["live"] and log_seconds(feed["generated_at"]) < retained:
                phase = "regression"
            elif all(delta in case["seen"] for delta in feed["deltas"]):
                phase = "unread"
            elif feed["next"] is None:
                phase = "end"
            else:
                target = feed["next"]
                normalized = link_extraction.normalize_url(target, prefix + "feed.json")
                phase = "followed" if normalized == target and target.startswith(prefix) else "target"
        assert phase == case["expected"], case["name"]
        assert case["code"] == codes[phase], case["name"]
        assert case["next_read"] == (phase in ("end", "target", "followed")), case["name"]
        assert case["fetch"] == (doc["feed"]["next"] if phase == "followed" else None), case["name"]
        assert case["deltas_admitted"] == (phase in ("unread", "end", "target", "followed")), case["name"]
        assert case["declaration_retries"] == int(phase == "signature"), case["name"]
        observed.add(phase)
    assert observed == set(codes)
    by_name = {case["name"]: case for case in vector["cases"]}
    assert by_name["scope host"]["expected"] == "target"
    assert by_name["explicit default port"]["expected"] == "target"
    assert by_name["encoded dot segment"]["expected"] == "target"
    assert by_name["encoded separator in prefix"]["expected"] == "target"
    assert by_name["encoded separator inside the layout"]["expected"] == "followed"
    assert by_name["query preserved"]["fetch"].endswith("?v=2&x=%2F")
    assert by_name["regressed Page with bad target"]["expected"] == "target"
    assert by_name["regressed live Feed with bad target"]["expected"] == "regression"
    assert not by_name["ingested Feed with bad target"]["next_read"]
    assert vector == original


check("vectors:wist2-feed-next", _feed_next_vectors)

def _feed_regression_vectors():
    vector = json.loads((ROOT / "vectors/wist2/feed-regression.json").read_text())
    formats = FormatChecker(formats=[])
    formats.checks("wist-canonical-host")(_declaration_host_format)
    formats.checks("date-time")(lambda value: not isinstance(value, str) or
                               isinstance(log_seconds(value), int))
    validator = Draft202012Validator(json.loads(
        (ROOT / "schemas/feed.schema.json").read_text()), format_checker=formats)
    source = vector["declaration"]
    key = source["publisher"]["keys"][0]
    public = canonical_b64u_decode(key["public_key"])
    assert _ed25519_profile_verdict(public, canonical_b64u_decode(source["sig"]["value"]),
                                  rfc8785.dumps(source["publisher"]))[0]
    for case in vector["cases"]:
        retained = None
        for event in case["observations"]:
            doc = event["envelope"]
            retries = 0
            if not validator.is_valid(doc):
                code = "WIST2-E01"
            elif doc["feed"]["domain"] != vector["host"]:
                code = "WIST2-E04"
            elif (doc["sig"]["key_id"] != key["key_id"] or
                  not _ed25519_profile_verdict(public, canonical_b64u_decode(doc["sig"]["value"]),
                                              rfc8785.dumps(doc["feed"]))[0]):
                code, retries = "WIST2-E04", 1
            elif retained is not None and log_seconds(doc["feed"]["generated_at"]) < log_seconds(retained):
                code = "WIST2-E05"
            else:
                code = None
                retained = doc["feed"]["generated_at"]
            assert code == event["code"], event["name"]
            assert retained == event["retained"], event["name"]
            assert event["retained_s"] == (None if retained is None else log_seconds(retained))
            assert retries == event["declaration_retries"], event["name"]
            assert event["noise"] == ("WIST2-E04" if code == "WIST2-E04" else
                                      "WIST2-E02" if code is None else None)


check("vectors:wist2-feed-regression", _feed_regression_vectors)


def _delta_cap_time_vectors():
    vector = json.loads((ROOT / 'vectors/wist1/delta-cap-time.json').read_text())
    original = copy.deepcopy(vector)
    blocks = vector['blocks']
    permitted = ('publisher_declaration', 'registry_update', 'publisher_delta')
    _declaration_history_blocks(vector, blocks, vector['pinned_head'], permitted)
    public = Ed25519PublicKey.from_public_bytes(b64u_decode(vector['log_key']['public_key']))
    schemas = {name: Draft202012Validator(json.loads((ROOT / f'schemas/{name}.schema.json').read_text()))
               for name in ('publisher', 'registry-update', 'delta', 'payload')}
    defaults = dict(url_cap_bytes=2048, extract_cap_bytes=32768, links_cap_bytes=4096,
                    link_url_cap_bytes=2048, summary_cap_bytes=2048)
    assert vector['defaults'] == defaults
    amendments, inclusion = [], {}
    for height, block in enumerate(blocks):
        for index, entry in enumerate(block['entries']):
            doc = entry['body']
            inner = {'publisher_declaration': 'publisher', 'registry_update': 'update', 'publisher_delta': 'delta'}[entry['type']]
            schemas['registry-update' if inner == 'update' else inner].validate(doc)
            public.verify(b64u_decode(doc['sig']['value']), rfc8785.dumps(doc[inner]))
            if inner == 'publisher':
                assert height == 0 and doc['publisher']['domain'] == 'example.com'
                assert doc['publisher']['keys'][0]['public_key'] == vector['log_key']['public_key']
                assert doc['publisher']['keys'][0]['key_id'] == 'test-k1'
            elif inner == 'update':
                update = doc['update']
                assert doc['sig']['key_id'] == vector['log_key']['key_id']
                assert update['action'] == 'parameter_change'
                assert log_seconds(update['effective_at']) >= log_seconds(block['header']['sealed_at']) + 7 * 86400
                amendments.append((height, index, update))
            else:
                ident = 'sha256:' + hashlib.sha256(rfc8785.dumps(doc['delta'])).hexdigest()
                assert ident not in inclusion
                inclusion[ident] = height

    def parameters(at, prefix):
        result, selected = defaults.copy(), {}
        for height, index, update in amendments:
            effective = log_seconds(update['effective_at'])
            if height > prefix or effective > at:
                continue
            key = update['details']['parameter']
            position = (effective, height, index)
            if key not in selected or position > selected[key]:
                result[key] = update['details']['value']
                selected[key] = position
        return result

    for height, _, update in amendments:
        for at in {log_seconds(blocks[height]['header']['sealed_at'])} | {
                log_seconds(candidate['effective_at']) for sealed, _, candidate in amendments if sealed <= height}:
            caps = parameters(at, height)
            assert caps['links_cap_bytes'] >= caps['link_url_cap_bytes'] + 21
            assert caps['extract_cap_bytes'] >= 2 and caps['summary_cap_bytes'] >= 12
            assert caps['url_cap_bytes'] >= 14 and caps['link_url_cap_bytes'] >= 14
            assert sum(caps[k] for k in ('extract_cap_bytes', 'links_cap_bytes', 'summary_cap_bytes')) + 32 + 8 * 1024 * 1024 <= 1024 * 1024 * 1024

    def diagnose(obj, caps, with_payload=True):
        body, payload = obj['envelope']['delta'], obj['payload']
        content = payload['content']
        checks = [(len(rfc8785.dumps(body['url'])), caps['url_cap_bytes'], 'WIST1-E11')]
        if with_payload:
            checks += [(len(rfc8785.dumps(value)), caps[key + '_cap_bytes'], 'WIST1-E04')
                       for key, value in content.items()]
            checks += [(len(rfc8785.dumps(link)), caps['link_url_cap_bytes'], 'WIST1-E04')
                       for link in content['links']['urls']]
        checks.append((body['payload']['bytes'], caps['extract_cap_bytes'] + caps['summary_cap_bytes'] + caps['links_cap_bytes'] + 32, 'WIST1-E04'))
        errors = {code for size, limit, code in checks if size > limit}
        assert len(errors) <= 1
        return next(iter(errors), None)

    for name, obj in vector['objects'].items():
        schemas['delta'].validate(obj['envelope'])
        schemas['payload'].validate(obj['payload'])
        body = obj['envelope']['delta']
        assert obj['envelope']['sig']['key_id'] == 'test-k1'
        public.verify(b64u_decode(obj['envelope']['sig']['value']), rfc8785.dumps(body))
        assert obj['id'] == 'sha256:' + hashlib.sha256(rfc8785.dumps(body)).hexdigest()
        assert body['publisher'] == 'example.com' and body['url'].startswith('https://example.com/')
        assert publisher_instant(body['observed_at']) <= log_seconds(blocks[obj['sealed_height']]['header']['sealed_at'])
        assert body['payload']['commitment'] == _commit(obj['payload']['salt'], obj['payload']['content'])
        assert body['payload']['bytes'] == len(rfc8785.dumps(obj['payload']['content']))
        assert inclusion[obj['id']] == obj['sealed_height']
        instant = log_seconds(blocks[obj['sealed_height']]['header']['sealed_at'])
        assert diagnose(obj, parameters(instant, obj['sealed_height'])) is None, name

    stages, outcomes = collections.Counter(), collections.Counter()
    for probe in vector['probes']:
        obj = vector['objects'][probe['object']]
        if probe['stage'] == 'admission':
            at, prefix = log_seconds(probe['started_at']), probe['prefix_height']
            assert log_seconds(probe['completed_at']) >= at
        elif probe['stage'] == 'sealing':
            prefix = probe['candidate_height']
            at = log_seconds(blocks[prefix]['header']['sealed_at'])
            admission = log_seconds(probe['admitted_at'])
            assert admission < at
            assert diagnose(obj, parameters(admission, 168)) is None
        else:
            assert probe['stage'] == 'historical'
            prefix = inclusion[obj['id']]
            at = log_seconds(blocks[prefix]['header']['sealed_at'])
            assert probe['prefix_height'] >= prefix and log_seconds(probe['checked_at']) >= at
        caps = parameters(at, prefix)
        assert caps == probe['expected_profile'], probe['name']
        result = diagnose(obj, caps)
        assert result == probe['expected'], probe['name']
        assert diagnose(obj, caps, False) == probe['expected_delta'], probe['name']
        assert probe['restart'] and parameters(at, prefix) == caps
        stages[probe['stage']] += 1
        outcomes[result] += 1
    assert stages == dict(admission=144, sealing=72, historical=48)
    assert set(outcomes) == {None, 'WIST1-E04', 'WIST1-E11'}
    for case in vector['invalid_blocks']:
        candidate = case['block']
        _declaration_history_blocks(vector, blocks[:169] + [candidate], case['pinned_head'], permitted)
        doc = candidate['entries'][0]['body']
        public.verify(b64u_decode(doc['sig']['value']), rfc8785.dumps(doc['delta']))
        obj = dict(envelope=doc, payload=case['payload'])
        assert doc['delta']['payload']['commitment'] == _commit(case['payload']['salt'], case['payload']['content'])
        assert doc['delta']['change_type'] == 'new' and 'prev' not in doc['delta']
        assert publisher_instant(doc['delta']['observed_at']) <= log_seconds(candidate['header']['sealed_at'])
        assert all(entry['body']['delta']['url'] != doc['delta']['url']
                   for block in blocks[:169] for entry in block['entries'] if entry['type'] == 'publisher_delta')
        cap = parameters(log_seconds(candidate['header']['sealed_at']), 168)
        assert diagnose(obj, cap) == case['expected'] and case['expected'] is not None
    deltas = {obj['id']: obj['envelope']['delta'] for obj in vector['objects'].values()}
    for entry in blocks[169]['entries']:
        if entry['type'] == 'publisher_delta':
            body = entry['body']['delta']
            deltas['sha256:' + hashlib.sha256(rfc8785.dumps(body)).hexdigest()] = body
    damaged = copy.deepcopy(blocks)
    damaged[0]['entries'][-1]['body']['update']['details']['value'] += 1
    try:
        _declaration_history_blocks(vector, damaged, vector['pinned_head'], permitted)
    except AssertionError:
        pass
    else:
        raise AssertionError('unauthenticated cap amendment accepted')
    assert vector == original


check('vectors:wist1-delta-cap-time', _delta_cap_time_vectors)


def _payload_link_vectors():
    import copy
    import hmac
    import urllib.parse
    import link_extraction
    vector = json.loads((ROOT / 'vectors/wist1/payload-links.json').read_text())
    original = copy.deepcopy(vector)
    names = set()
    for case in vector['cases']:
        assert case['name'] not in names
        names.add(case['name'])
        verify_envelope(case['envelope'], 'delta', b64u_decode(vector['public_key']))
        body, payload = case['envelope']['delta'], case['payload']
        content = rfc8785.dumps(payload['content'])
        assert len(content) == body['payload']['bytes']
        assert 'hmac-sha256:' + hmac.new(b64u_decode(payload['salt']), content, hashlib.sha256).hexdigest() == body['payload']['commitment']
        links = payload['content']['links']
        urls = links['urls']
        invalid = len(urls) > links['total'] or len(set(urls)) != len(urls)
        for url in urls:
            normalized = link_extraction.normalize_url(url, url)
            if normalized != url:
                invalid = True
                continue
            host = urllib.parse.urlsplit(url).hostname
            invalid |= host == body['publisher'] or host.endswith('.' + body['publisher'])
        assert ('WIST1-E12' if invalid else None) == case['expected'], case['name']
    assert len(names) == 31
    assert vector == original


check('vectors:wist1-payload-links', _payload_link_vectors)

def _payload_field_vectors():
    import urllib.parse
    import link_extraction
    vector = json.loads((ROOT / 'vectors/wist1/payload-fields.json').read_text())
    original = copy.deepcopy(vector)
    schema = json.loads((ROOT / 'schemas/payload.schema.json').read_text())
    fields = copy.deepcopy(schema)
    props = fields['properties']['content']['properties']
    del props['extract']['maxLength']
    del props['links']['properties']['urls']['uniqueItems']
    props['links']['properties']['urls']['items'] = dict(type='string')
    validator = Draft202012Validator(fields)
    seen = set()
    names = set()

    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError('duplicate JSON member')
            obj[key] = value
        return obj

    for case in vector['cases']:
        assert case['name'] not in names
        names.add(case['name'])
        verify_envelope(case['envelope'], 'delta', b64u_decode(vector['public_key']))
        try:
            payload = json.loads(case['payload_json'], object_pairs_hook=unique) if 'payload_json' in case else case['payload']
            rfc8785.dumps(payload)
        except (ValueError, rfc8785.CanonicalizationError):
            assert case['allowed'] == ['WIST1-E05'], case['name']
            seen.add('WIST1-E05')
            continue
        assert payload == case['payload']
        body = case['envelope']['delta']
        errors = set()
        if not validator.is_valid(payload):
            errors.add('WIST1-E14')
        else:
            salt = canonical_b64u_decode(payload['salt'])
            assert len(salt) >= 16
            if payload['wist_version'].partition('.')[0] != '1':
                errors.add('WIST1-E15')
            content = payload['content']
            encoded = rfc8785.dumps(content)
            if body['payload']['bytes'] != len(encoded):
                errors.add('WIST1-E10')
            if body['payload']['commitment'] != 'hmac-sha256:' + hmac.new(salt, encoded, hashlib.sha256).hexdigest():
                errors.add('WIST1-E10')
            caps = dict(extract_cap_bytes=32768, links_cap_bytes=4096,
                        summary_cap_bytes=2048, link_url_cap_bytes=2048)
            caps.update(case.get('caps', {}))
            if any(len(rfc8785.dumps(content[name])) > caps[name + '_cap_bytes']
                   for name in ('extract', 'links', 'summary')):
                errors.add('WIST1-E04')
            if len(encoded) > sum(caps[name + '_cap_bytes'] for name in ('extract', 'links', 'summary')) + 32:
                errors.add('WIST1-E04')
            links = content['links']
            if len(set(links['urls'])) != len(links['urls']) or len(links['urls']) > links['total']:
                errors.add('WIST1-E12')
            for url in links['urls']:
                if len(rfc8785.dumps(url)) > caps['link_url_cap_bytes']:
                    errors.add('WIST1-E04')
                if link_extraction.normalize_url(url, url) != url:
                    errors.add('WIST1-E12')
                    continue
                host = urllib.parse.urlsplit(url).hostname
                if host == body['publisher'] or host.endswith('.' + body['publisher']):
                    errors.add('WIST1-E12')
        assert errors == set(case['allowed']), (case['name'], errors)
        seen |= errors
    assert seen == {'WIST1-E04', 'WIST1-E05', 'WIST1-E10', 'WIST1-E12', 'WIST1-E14', 'WIST1-E15'}
    assert vector == original


check('vectors:wist1-payload-fields', _payload_field_vectors)


def _delta_clock_time_vectors():
    vector = json.loads((ROOT / 'vectors/wist1/delta-clock-time.json').read_text())
    original = copy.deepcopy(vector)
    public = b64u_decode(vector['public_key'])
    schemas = {name: Draft202012Validator(json.loads((ROOT / f'schemas/{name}.schema.json').read_text()))
               for name in ('delta', 'registry-update')}
    accepted = []
    for index, candidate in enumerate(vector['amendments']):
        doc = candidate['envelope']
        schemas['registry-update'].validate(doc)
        update = doc['update']
        assert update['action'] == 'parameter_change'
        assert update['details']['parameter'] == 'clock_skew_seconds'
        value = update['details']['value']
        assert isinstance(value, int) and abs(value) <= 9007199254740991
        try:
            verify_envelope(doc, 'update', public)
            valid = True
        except InvalidSignature:
            valid = False
        sealed = log_seconds(candidate['sealed_at'])
        effective = log_seconds(update['effective_at'])
        valid = valid and effective >= sealed + 7 * 86400
        assert valid == candidate['accepted']
        if valid:
            accepted.append((effective, index, value))

    def allowance(at):
        applicable = [change for change in accepted if change[0] <= at]
        return max(applicable)[2] if applicable else vector['default']

    names = set()
    alternatives = collections.Counter()
    for probe in vector['probes']:
        assert probe['name'] not in names
        names.add(probe['name'])
        doc = probe['envelope']
        schemas['delta'].validate(doc)
        verify_envelope(doc, 'delta', public)
        observed = publisher_instant(doc['delta']['observed_at'])
        clock_field = {'admission': 'started_at', 'sealing': 'candidate_sealed_at',
                       'historical': 'sealed_at'}[probe['stage']]
        clock = publisher_instant(probe[clock_field])
        skew = allowance(clock)
        assert probe['expected_clock'] == probe[clock_field]
        assert probe['expected_allowance'] == skew
        expected = None if observed <= clock + skew else 'WIST1-E06'
        assert expected == probe['expected'], probe['name']
        later_field = {'admission': 'completed_at', 'sealing': 'admitted_at',
                       'historical': 'checked_at'}[probe['stage']]
        later = publisher_instant(probe[later_field])
        for label, bound in [('clock', later + skew), ('allowance', clock + allowance(later)),
                             ('both', later + allowance(later))]:
            alternative = None if observed <= bound else 'WIST1-E06'
            alternatives[probe['stage'], label] += alternative != expected
    assert len(names) == 96
    for stage in ('admission', 'sealing', 'historical'):
        for changed in ('clock', 'allowance', 'both'):
            assert alternatives[stage, changed], (stage, changed)
    assert vector == original


check('vectors:wist1-delta-clock-time', _delta_clock_time_vectors)


def _withdrawal_vector():
    return json.loads((ROOT / "vectors/wist4/withdrawal.json").read_text())

def _strict_json(raw):
    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate member")
        return dict(pairs)
    return json.loads(raw, object_pairs_hook=no_duplicates)

def _registry_update_eligibility(raw, validator):
    """WIST-4 §5.1: JSON/JCS eligibility (WIST1-E05), then the schema, where a
    failure inside an action's branch is the details contract (WIST4-E04) and
    any other field failure, the version check included, is WIST4-E11."""
    try:
        doc = _strict_json(raw)
        rfc8785.dumps(doc)
    except (ValueError, TypeError):
        return "WIST1-E05", None
    errors = list(validator.iter_errors(doc))
    if any("allOf" not in e.absolute_schema_path for e in errors):
        return "WIST4-E11", None
    if errors:
        return "WIST4-E04", None
    if doc["update"]["wist_version"].partition(".")[0] != "1":
        return "WIST4-E11", None
    return None, doc

def _dc4_withdrawal():
    """WIST-4 §5.1: payload_withdrawal acts under the Log key naming a sealed
    Delta of the subject; the earliest accepted withdrawal's Block governs
    and the state carries one withdrawal tuple per withdrawn Delta."""
    v = _withdrawal_vector()
    validator = Draft202012Validator(json.loads((ROOT / "schemas/registry-update.schema.json").read_text()))
    log_key = Ed25519PublicKey.from_public_bytes(b64u_decode(v["log_key"]["public_key"]))
    sealed = {d["delta_id"]: d for d in v["sealed_deltas"]}
    withdrawn = {}
    seen = set()
    for case in v["act_cases"]:
        code, doc = _registry_update_eligibility(case["envelope_json"], validator)
        if doc is not None:
            try:
                assert doc["sig"]["key_id"] == v["log_key"]["key_id"]
                log_key.verify(b64u_decode(doc["sig"]["value"]), rfc8785.dumps(doc["update"]))
            except (AssertionError, InvalidSignature):
                code = "WIST4-E11"
            else:
                update = doc["update"]
                fact = sealed.get(update["details"]["delta_id"])
                if fact is None or fact["height"] > case["height"] or fact["publisher"] != update["subject"]:
                    code = "WIST4-E04"
        assert code == case["code"], (case["label"], code)
        if code is None:
            delta_id = doc["update"]["details"]["delta_id"]
            withdrawn.setdefault(delta_id, (case["height"], doc["update"]["subject"]))
            assert withdrawn[delta_id][0] == case["withdrawn_height"], case["label"]
        else:
            assert case["withdrawn_height"] is None, case["label"]
        seen.add(code)
    assert seen == {None, "WIST4-E11", "WIST4-E04"}
    assert any(c["code"] is None and c["height"] > c["withdrawn_height"] for c in v["act_cases"]), \
        "no repeated withdrawal keeps the first height"
    tuples = sorted(["withdrawal", d, p, h] for d, (h, p) in withdrawn.items())
    assert tuples == sorted(v["state_tuples"]), "the replay does not leave the vector's withdrawal tuples"
    state = Draft202012Validator(json.loads((ROOT / "schemas/snapshot-state.schema.json").read_text()))
    envelope = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
    envelope["state"]["entries"] = v["state_tuples"]
    state.validate(envelope)
    # WIST-3 §3.3 and §6.2: every sealed Delta moves its chain tip, the one
    # withdrawn in its own Block included; only an unwithdrawn one materializes.
    records = sorted(["record", d["publisher"], d["url"], d["delta_id"]] for d in v["sealed_deltas"])
    assert records == sorted(v["record_tuples"]), "a withdrawn Delta moved no chain tip"
    materialized = sorted(d["delta_id"] for d in v["sealed_deltas"] if d["delta_id"] not in withdrawn)
    assert materialized == sorted(v["materialized"]) and materialized, "withdrawn content materialized"
    assert any(withdrawn[d["delta_id"]][0] == d["height"] for d in v["sealed_deltas"] if d["delta_id"] in withdrawn), \
        "no Delta withdrawn in its own Block"
    envelope["state"]["entries"] = v["state_tuples"] + v["record_tuples"]
    state.validate(envelope)
    # WIST-3 §7: a resuming Consumer checks the contract only for a Delta it walked.
    resume = v["resume"]
    walked = {d["delta_id"]: d for d in resume["walked_deltas"]}
    assert all(d["height"] > resume["log_position"] for d in walked.values())
    resumed = {t[1]: (t[3], t[2]) for t in resume["adopted"]}
    assert all(h <= resume["log_position"] for h, _ in resumed.values())
    unverified = 0
    for case in resume["act_cases"]:
        code, doc = _registry_update_eligibility(case["envelope_json"], validator)
        assert code is None, case["label"]
        log_key.verify(b64u_decode(doc["sig"]["value"]), rfc8785.dumps(doc["update"]))
        update = doc["update"]
        fact = walked.get(update["details"]["delta_id"])
        if fact is not None and (fact["height"] > case["height"] or fact["publisher"] != update["subject"]):
            code = "WIST4-E04"
        assert code == case["code"], (case["label"], code)
        if code is None:
            delta_id = update["details"]["delta_id"]
            unverified += fact is None and delta_id not in resumed
            resumed.setdefault(delta_id, (case["height"], update["subject"]))
            assert resumed[delta_id][0] == case["withdrawn_height"], case["label"]
    assert unverified, "no act names a Delta below the Snapshot"
    assert sorted(["withdrawal", d, p, h] for d, (h, p) in resumed.items()) == sorted(resume["state_tuples"])
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-governance.md").read_text())
    assert "`delta_id` MUST name a Delta sealed at or below the act's Block whose signed `publisher` is `subject`" in prose
    assert "the earliest accepted withdrawal's Block is the height every rule reads" in prose
    assert "E11 takes precedence over E04" in prose
    assert "the Delta's content never materializes, its chain tip moves as any Delta's does" in prose
    assert "checks the contract only for an act naming a Delta sealed above `log_position`" in prose
    prose3 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "takes effect on that Delta as the Delta applies below" in prose3
    assert "a resuming Consumer accepts a later act naming one of them as consistent" in prose3
check("vectors:wist4-withdrawal", _dc4_withdrawal)

def _dc4_withdrawal_twin():
    v = _withdrawal_vector()
    validator = Draft202012Validator(json.loads((ROOT / "schemas/registry-update.schema.json").read_text()))
    valid = next(c for c in v["act_cases"] if c["code"] is None)
    doc = json.loads(valid["envelope_json"])
    doc["update"]["details"]["legal_basis"] = 7
    assert _registry_update_eligibility(json.dumps(doc), validator)[0] == "WIST4-E04"
    doc = json.loads(valid["envelope_json"])
    doc["update"]["extra"] = 1
    assert _registry_update_eligibility(json.dumps(doc), validator)[0] == "WIST4-E11"
    doc = json.loads(valid["envelope_json"])
    doc["update"]["subject"] = "Not A Host"
    doc["update"]["details"] = {}
    assert _registry_update_eligibility(json.dumps(doc), validator)[0] == "WIST4-E04"
    del doc["update"]["subject"]
    assert _registry_update_eligibility(json.dumps(doc), validator)[0] == "WIST4-E11"
    raw = valid["envelope_json"].replace('"legal_basis"', '"legal_basis": "x", "legal_basis"', 1)
    assert _registry_update_eligibility(raw, validator)[0] == "WIST1-E05"
check("negative:wist4-withdrawal", _dc4_withdrawal_twin)


def _registrable_domain_vector():
    return json.loads((ROOT / "vectors/wist4/registrable-domain.json").read_text(encoding="utf-8"))

def _psl_host_label(label):
    if label == "*":
        return label
    label = label.lower()
    return label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii")

def _psl_canonical_host(name):
    labels = name.split(".")
    return None if any(not l for l in labels) else ".".join(_psl_host_label(l) for l in labels)

def _psl_rules(text):
    """WIST-4 §3.1: the rule lines of both sections as {rule: is_exception}, labels
    in Canonical Host form; a second copy of the reading, structured as a map."""
    rules = {}
    for line in text.splitlines():
        body = line.strip()
        if not body or body.startswith("//"):
            continue
        token = body.split()[0]
        exception = token[:1] == "!"
        rule = ".".join(_psl_host_label(l) for l in token.lstrip("!").split("."))
        rules[rule] = exception
    return rules

def _psl_registrable(host, rules):
    """The Public Suffix List algorithm as WIST-4 §3.1 states it, returning the
    Registrable Domain and whether the host is itself a public suffix."""
    if rules is None:
        return host, False
    labels = host.split(".")
    best = None
    for rule, exception in rules.items():
        parts = rule.split(".")
        if len(parts) > len(labels):
            continue
        if all(a == "*" or a == b for a, b in zip(parts[::-1], labels[::-1])):
            candidate = (exception, len(parts), rule)
            if best is None or candidate[:2] > best[:2]:
                best = candidate
    suffix = 1 if best is None else (best[1] - 1 if best[0] else best[1])
    if suffix >= len(labels):
        return host, True
    return ".".join(labels[len(labels) - suffix - 1:]), False

def _dc4_registrable_domain():
    """WIST-4 §3.1, WIST-2 §4 and WIST-3 §3.2: the Registrable Domain under a
    pinned Public Suffix List snapshot, checked against the Public Suffix
    List project's own test cases, the act replay, the in-force rule, the
    per-Registrable-Domain capacity and quota, and the suffix_list tuple."""
    v = _registrable_domain_vector()
    lists = {l["name"]: l for l in v["lists"]}
    for l in v["lists"]:
        octets = l["text"].encode("utf-8")
        assert l["sha256"] == "sha256:" + hashlib.sha256(octets).hexdigest() and l["bytes"] == len(octets), l["name"]
        assert "// ===BEGIN ICANN DOMAINS===" in l["text"] and "// ===BEGIN PRIVATE DOMAINS===" in l["text"]
    rules = {name: _psl_rules(l["text"]) for name, l in lists.items()}
    rules[None] = None
    by_id = {l["sha256"]: l for l in v["lists"]}
    # External anchor: the project's checkPublicSuffix cases, read from the file,
    # over the fixture snapshot, which carries every rule those inputs reach.
    official = {}
    for line in (ROOT / "tools/psl_test_cases.txt").read_text(encoding="utf-8").splitlines():
        m = re.fullmatch(r"checkPublicSuffix\((null|'([^']*)'), (null|'([^']*)')\);", line.strip())
        if m and m.group(1) != "null":
            official[m.group(2)] = m.group(4)
    assert len(official) >= 75 and {c["input"] for c in v["official_cases"]} == set(official)
    for case in v["official_cases"]:
        expected = official[case["input"]]
        assert case["expected"] == expected, case["input"]
        host = _psl_canonical_host(case["input"])
        assert case["host"] == host, case["input"]
        if host is None:
            assert case["registrable"] is None and case["public_suffix"] is None
            continue
        registrable, own = _psl_registrable(host, rules["first"])
        assert registrable == (host if expected is None else _psl_canonical_host(expected)), case["input"]
        assert (case["registrable"], case["public_suffix"]) == (registrable, own), case["input"]
    assert any(c["host"] and c["input"] != c["host"] for c in v["official_cases"]), "no case exercises canonicalization"
    for case in v["domain_cases"]:
        assert (case["registrable"], case["public_suffix"]) == _psl_registrable(case["host"], rules[case["list"]]), case["label"]
    shared = [c for c in v["domain_cases"] if c["list"] == "first" and c["registrable"] == "example.com"]
    assert len({c["host"] for c in shared}) >= 3, "no shared-quota hosts"
    private = [c for c in v["domain_cases"] if c["host"].endswith(".github.io")]
    assert len({c["registrable"] for c in private}) == len(private) >= 2, "private section hosts merge"
    split = {c["list"]: c["registrable"] for c in v["domain_cases"] if c["host"] == "a.hosts.sample.net"}
    assert split == {"first": "sample.net", "second": "a.hosts.sample.net"}, "the snapshot advance splits nothing"
    assert all(c["registrable"] == c["host"] for c in v["domain_cases"] if c["list"] is None)

    validator = Draft202012Validator(json.loads((ROOT / "schemas/registry-update.schema.json").read_text()))
    log_key = Ed25519PublicKey.from_public_bytes(b64u_decode(v["log_key"]["public_key"]))
    accepted = []
    seen = set()
    heights = [c["height"] for c in v["act_cases"]]
    assert heights == sorted(heights)
    for case in v["act_cases"]:
        code, doc = _registry_update_eligibility(case["envelope_json"], validator)
        if doc is not None:
            try:
                assert doc["sig"]["key_id"] == v["log_key"]["key_id"]
                log_key.verify(b64u_decode(doc["sig"]["value"]), rfc8785.dumps(doc["update"]))
            except (AssertionError, InvalidSignature):
                code = "WIST4-E11"
            else:
                update = doc["update"]
                named = by_id.get(update["details"]["sha256"])
                if update["subject"] != update["details"]["sha256"] or named is None \
                        or named["bytes"] != update["details"]["bytes"]:
                    code = "WIST4-E04"
        assert code == case["code"], (case["label"], code)
        unheld = doc is not None and by_id.get(doc["update"]["details"]["sha256"]) is None
        assert case.get("consumer") == ("WIST3-E01" if unheld else None), case["label"]
        if code is None:
            accepted.append((case["height"], by_id[json.loads(case["envelope_json"])["update"]["details"]["sha256"]]["name"]))
        in_force = next((n for h, n in reversed(accepted) if h <= case["height"]), None)
        assert in_force == case["in_force_after"], case["label"]
        seen.add(code)
    assert seen == {None, "WIST4-E11", "WIST4-E04"}
    assert any(c.get("consumer") for c in v["act_cases"]), "no act names an unobtainable file"

    def force_at(height):
        return next((n for h, n in reversed(accepted) if h < height), None)
    for row in v["in_force"]:
        assert force_at(row["height"]) == row["list"], row
    assert {row["list"] for row in v["in_force"]} == {None, "first", "second"}
    for case in v["capacity_cases"]:
        counts = collections.Counter(_psl_registrable(e["domain"], rules[force_at(case["height"])])[0]
                                     for e in case["entries"])
        assert all(e["type"] in ("publisher_delta", "label") for e in case["entries"])
        expected = "WIST3-E03" if max(counts.values()) > case["domain_block_entries_max"] else None
        assert expected == case["expected"], case["label"]
    assert {c["expected"] for c in v["capacity_cases"]} == {None, "WIST3-E03"}
    changed = 0
    for case in v["quota_cases"]:
        noise = collections.Counter()
        for ping in case["pings"]:
            unit = _psl_registrable(ping["host"], rules[force_at(ping.get("height", case["height"]))])[0]
            if noise[unit] >= case["quota_base"]:
                assert ping["expected"] == 429, (case["label"], ping)
                continue
            if ping["noise"]:
                noise[unit] += 1
            assert ping["expected"] == 202, (case["label"], ping)
        assert 429 in {p["expected"] for p in case["pings"]} or case["height"] == 0, case["label"]
        changed += len({force_at(p.get("height", case["height"])) for p in case["pings"]}) > 1
    assert changed, "no quota case crosses a snapshot change"
    for state in v["state_tuples"]:
        pinned = None
        for h, n in accepted:
            if h <= state["log_position"] and (pinned is None or pinned[1] != n):
                pinned = (h, n)
        assert state["entries"] == [["suffix_list", lists[pinned[1]]["sha256"], pinned[0]]], state
    assert any(h > s["entries"][0][2] for h, _ in accepted for s in v["state_tuples"]
               if h <= s["log_position"]), "no repeated pin leaves the tuple's height alone"
    schema = Draft202012Validator(json.loads((ROOT / "schemas/snapshot-state.schema.json").read_text()))
    envelope = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
    envelope["state"]["entries"] = v["state_tuples"][0]["entries"]
    schema.validate(envelope)
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-governance.md").read_text())
    for marker in ("in force from the Block after its sealing Block",
                   "the Registrable Domain is the host itself",
                   "every Canonical Host is its own Registrable Domain",
                   "An Aggregator MUST NOT seal an act naming a file it does not hold",
                   "it stops at the act's Block (`WIST3-E01`)"):
        assert marker in prose, marker
    w2 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-2-site-publication.md").read_text())
    assert "Ping quota Q is `quota_base` Pings per UTC day per Registrable Domain" in w2
    assert "the Pings already counted stay under the unit they were counted against" in w2
    w3 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "whose Publisher's or Labeler's Canonical Host has one Registrable Domain" in w3
check("vectors:wist4-registrable-domain", _dc4_registrable_domain)

def _dc4_registrable_domain_twin():
    v = _registrable_domain_vector()
    rules = _psl_rules(v["lists"][0]["text"])
    assert _psl_registrable("www.ck", rules) == ("www.ck", False)
    no_exception = {r: e for r, e in rules.items() if r != "www.ck"}
    assert _psl_registrable("www.ck", no_exception) == ("www.ck", True), "the exception rule is inert"
    icann_only = _psl_rules(v["lists"][0]["text"].split("// ===BEGIN PRIVATE DOMAINS===")[0])
    assert _psl_registrable("alice.github.io", icann_only) == ("github.io", False), "the private section is inert"
    assert _psl_registrable("alice.github.io", rules) == ("alice.github.io", False)
    assert _psl_registrable("a.b.example.example", rules) == ("example.example", False)
    validator = Draft202012Validator(json.loads((ROOT / "schemas/registry-update.schema.json").read_text()))
    valid = next(c for c in v["act_cases"] if c["code"] is None)
    doc = json.loads(valid["envelope_json"])
    doc["update"]["details"]["bytes"] = "496"
    assert _registry_update_eligibility(json.dumps(doc), validator)[0] == "WIST4-E04"
    doc = json.loads(valid["envelope_json"])
    doc["update"]["subject"] = "example.com"
    assert _registry_update_eligibility(json.dumps(doc), validator)[0] == "WIST4-E04"
    doc = json.loads(valid["envelope_json"])
    del doc["update"]["effective_at"]
    assert _registry_update_eligibility(json.dumps(doc), validator)[0] == "WIST4-E11"
    schema = Draft202012Validator(json.loads((ROOT / "schemas/snapshot-state.schema.json").read_text()))
    envelope = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
    envelope["state"]["entries"] = [["suffix_list", v["lists"][0]["sha256"], "0"]]
    assert not schema.is_valid(envelope), "a string height validated in a suffix_list tuple"
    envelope["state"]["entries"] = [["suffix_list", v["lists"][0]["sha256"]]]
    assert not schema.is_valid(envelope), "an under-arity suffix_list tuple validated"
check("negative:wist4-registrable-domain", _dc4_registrable_domain_twin)


def _fetch_bounds_vector():
    return json.loads((ROOT / "vectors/wist2/fetch-bounds.json").read_text())

_REFUSED_V4 = [("loopback", "127.0.0.0/8"), ("unspecified", "0.0.0.0/32"), ("private", "10.0.0.0/8"),
               ("private", "172.16.0.0/12"), ("private", "192.168.0.0/16"), ("link-local", "169.254.0.0/16"),
               ("shared address space", "100.64.0.0/10"), ("broadcast", "255.255.255.255/32"),
               ("multicast", "224.0.0.0/4"), ("documentation", "192.0.2.0/24"), ("documentation", "198.51.100.0/24"),
               ("documentation", "203.0.113.0/24"), ("benchmarking", "198.18.0.0/15"), ("reserved", "240.0.0.0/4")]
_REFUSED_V6 = [("loopback", "::1/128"), ("unspecified", "::/128"), ("unique local", "fc00::/7"),
               ("link-local", "fe80::/10"), ("multicast", "ff00::/8"), ("documentation", "2001:db8::/32")]

def _address_class(text, loopback_opt_in):
    """WIST-2 §8: the refused class of one address, None for a public unicast
    destination; the interpreter's ipaddress module does the prefix arithmetic."""
    import ipaddress
    address = ipaddress.ip_address(text)
    if address.version == 6:
        embedded = address.ipv4_mapped
        if embedded is None and address in ipaddress.ip_network("2002::/16"):
            embedded = ipaddress.ip_address(int(address) >> 80 & 0xffffffff)
        if embedded is None and address in ipaddress.ip_network("64:ff9b::/96"):
            embedded = ipaddress.ip_address(int(address) & 0xffffffff)
        if embedded is not None:
            return _address_class(str(embedded), loopback_opt_in)
        table = _REFUSED_V6
    else:
        table = _REFUSED_V4
    for cls, prefix in table:
        if address in ipaddress.ip_network(prefix):
            return None if cls == "loopback" and loopback_opt_in else cls
    return None

def _dc2_fetch_bounds():
    """WIST-2 §8 and §5 (ADR-0044): destination classes, name refusal, response
    bounds under the caps, pull-work dispositions and per-request scope."""
    v = _fetch_bounds_vector()
    classes = set()
    for case in v["destinations"]:
        cls = _address_class(case["address"], case["loopback_opt_in"])
        assert cls == case["class"] and case["allowed"] == (cls is None), (case["label"], cls)
        classes.add(cls)
    assert classes >= {None, "loopback", "unspecified", "private", "link-local", "shared address space",
                       "broadcast", "multicast", "documentation", "benchmarking", "reserved", "unique local"}
    assert any(c["loopback_opt_in"] and c["allowed"] for c in v["destinations"])
    assert any(c["address"].startswith("::ffff:") and c["class"] for c in v["destinations"])
    assert any(c["address"].startswith("2002:") and c["class"] for c in v["destinations"])
    assert any(c["address"].startswith("64:ff9b:") and c["class"] for c in v["destinations"])
    for case in v["resolutions"]:
        allowed = bool(case["addresses"]) and all(_address_class(a, False) is None for a in case["addresses"])
        assert allowed == case["allowed"], case["label"]
    assert {c["allowed"] for c in v["resolutions"]} == {True, False}
    for case in v["object_bounds"]:
        p = case["parameters"]
        if case["object"] in ("declaration", "feed", "page", "mirrors"):
            expected = 1048576
        elif case["object"] == "delta":
            expected = 16384 + 2 * p["url_cap_bytes"]
        else:
            assert case["object"] == "payload"
            expected = p["extract_cap_bytes"] + p["links_cap_bytes"] + p["summary_cap_bytes"] + 4096
        assert case["bound"] == expected, case["label"]
    assert len({c["bound"] for c in v["object_bounds"] if c["object"] == "delta"}) == 2, "one parameter map only"
    outcomes = set()
    for case in v["work_cases"]:
        budget, work_bytes, objects = case["budget_remaining"], case["work_bytes_remaining"], case["work_objects_remaining"]
        size, own = case["object_bytes"], case["object_bound"]
        if budget == 0 or work_bytes == 0 or objects == 0:
            expected = ("suspended", 0)
        else:
            limit = min(own, budget, work_bytes)
            if size <= limit:
                expected = ("fetched", size)
            elif limit < own:
                expected = ("suspended", limit)
            else:
                expected = ("failed", 0)
        assert (case["outcome"], case["debited"]) == expected, (case["label"], expected)
        outcomes.add(case["outcome"])
    assert outcomes == {"fetched", "suspended", "failed"}
    from urllib.parse import urlsplit
    for case in v["redirect_cases"]:
        host = case["requested_host"]
        scope = None
        grants = removals = 0
        for step in case["steps"]:
            if "declaration" in step:
                new = set(step["declaration"]["subdomain_scope"])
                grants += bool(new - (scope or set()))
                removals += bool((scope or set()) - new)
                scope = new
                continue
            target = urlsplit(step["redirect_to"])
            allowed = target.scheme == "https" and (target.hostname == host or (scope is not None and target.hostname in scope))
            assert allowed == step["allowed"], (case["label"], step)
        assert grants and removals, "no mid-pull scope grant and removal"
        assert any("redirect_to" in s and not s["allowed"] for s in case["steps"][:next(i for i, s in enumerate(case["steps"]) if "declaration" in s)]), \
            "no off-host redirect before the first Declaration"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-2-site-publication.md").read_text())
    for marker in ("An Aggregator MUST connect only to a public unicast address",
                   "refuses a name whole when any address it resolves to is refused",
                   "An Aggregator MUST NOT read more than 1 048 576 octets",
                   "16 384 + 2 × `url_cap_bytes` octets of a Delta file",
                   "the Declaration accepted at the instant the request is issued",
                   "a redirect MUST stay on the requested Canonical Host",
                   "An Aggregator MAY suspend a walk below the budget under a per-pull limit of its own",
                   "the octets read are debited and the walk suspends there"):
        assert marker in prose, marker
check("vectors:wist2-fetch-bounds", _dc2_fetch_bounds)

def _dc2_fetch_bounds_twin():
    assert _address_class("127.0.0.1", False) == "loopback" and _address_class("127.0.0.1", True) is None
    assert _address_class("::ffff:169.254.169.254", False) == "link-local"
    assert _address_class("2001:db9::1", False) is None and _address_class("2001:db8:ffff::1", False) == "documentation"
    assert _address_class("fe80::1", True) == "link-local", "the opt-in admits loopback alone"
    v = _fetch_bounds_vector()
    case = next(c for c in v["work_cases"] if c["outcome"] == "failed")
    assert case["object_bytes"] > case["object_bound"] <= min(case["budget_remaining"], case["work_bytes_remaining"])
check("negative:wist2-fetch-bounds", _dc2_fetch_bounds_twin)


def _label_vector():
    return json.loads((ROOT / "vectors/wist2/labels.json").read_text())

def _wist_label_terms():
    w4 = (ROOT / "specs" / "WIST-4-governance.md").read_text()
    registry = w4.split("## 6. Label Registry")[1].split("## 7.")[0]
    terms = re.findall(r"^\| `(wist:[a-z0-9-]+)` \|", registry, re.M)
    assert len(terms) >= 7 and len(terms) == len(set(terms))
    return set(terms)

def _label_disposition(doc, declaration, validator, url_cap_bytes, terms):
    """WIST-2 §3.3 over one Label Envelope: accepted, fields, self, signature
    or binding, in the order WIST-2 §3.3 and WIST-1 §7 apply them."""
    import link_extraction
    if not validator.is_valid(doc):
        return "fields"
    label = doc["label"]
    if label["wist_version"].partition(".")[0] != "1":
        return "fields"
    publisher = declaration["publisher"]
    if label["labeler"] != publisher["domain"]:
        return "fields"
    subject = label["subject"]
    if subject.startswith("https://"):
        if link_extraction.normalize_url(subject, subject) != subject:
            return "fields"
        host = subject[len("https://"):].split("/", 1)[0]
    else:
        if not _declaration_host_format(subject):
            return "fields"
        host = subject
    if len(rfc8785.dumps(subject)) > url_cap_bytes:
        return "fields"
    m = re.fullmatch(r"([a-z0-9.-]+):([a-z0-9-]+)", label["name"])
    if not m or len(label["name"]) > 64:
        return "fields"
    prefix = m.group(1)
    if prefix == "wist":
        if label["name"] not in terms:
            return "fields"
    elif not _declaration_host_format(prefix):
        return "fields"
    try:
        asserted = publisher_instant(label["asserted_at"])
        if "expires_at" in label and publisher_instant(label["expires_at"]) <= asserted:
            return "fields"
    except ValueError:
        return "fields"
    if "delta" in label and not subject.startswith("https://"):
        return "fields"
    if host == publisher["domain"] or host in publisher.get("subdomain_scope", []):
        return "self"
    key = next((k for k in publisher["keys"] if k["key_id"] == doc["sig"]["key_id"]), None)
    if key is None:
        return "binding"
    if not _ed25519_profile_verdict(canonical_b64u_decode(key["public_key"]),
                                    canonical_b64u_decode(doc["sig"]["value"]),
                                    rfc8785.dumps(label))[0]:
        return "signature"
    return "accepted"

def _label_vectors():
    """WIST-2 §3.3 and WIST-4 §6: every case's disposition is recomputed over
    the example Declaration, the accepted Label IDs reproduce, and the
    current-Label rule leaves the state tuples the vector names."""
    v = _label_vector()
    validator = Draft202012Validator(json.loads((ROOT / "schemas/label.schema.json").read_text()))
    terms = _wist_label_terms()
    codes = {"accepted": None, "fields": "WIST2-E06", "self": "WIST2-E06",
             "signature": "WIST1-E01", "binding": "WIST1-E02"}
    outcomes = set()
    for case in v["cases"]:
        got = _label_disposition(case["envelope"], v["declaration"], validator, v["url_cap_bytes"], terms)
        assert got == case["expected"], (case["name"], got, case["expected"])
        assert case["code"] == codes[case["expected"]], case["name"]
        label_id = "sha256:" + hashlib.sha256(rfc8785.dumps(case["envelope"]["label"])).hexdigest()
        assert case["label_id"] == (label_id if case["expected"] == "accepted" else None), case["name"]
        outcomes.add(case["expected"])
    assert outcomes == set(codes)
    example = json.loads((ROOT / "examples" / "label.json").read_text())
    assert _label_disposition(example, v["declaration"], validator, v["url_cap_bytes"], terms) == "accepted"
    feed = json.loads((ROOT / "examples" / "label-feed.json").read_text())
    assert feed["feed"]["deltas"] == ["sha256:" + hashlib.sha256(rfc8785.dumps(example["label"])).hexdigest()]
    Draft202012Validator(json.loads((ROOT / "schemas/feed.schema.json").read_text())).validate(feed)
    state = Draft202012Validator(json.loads((ROOT / "schemas/snapshot-state.schema.json").read_text()))
    envelope = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
    for case in v["current_cases"]:
        ranked = max(case["sealed"], key=lambda s: (publisher_instant(s["label"]["asserted_at"]),
                                                     s["height"], s["entry_index"]))
        assert ranked["label_id"] == case["current"], case["name"]
        inner = ranked["label"]
        expired = "expires_at" in inner and publisher_instant(inner["expires_at"]) <= log_seconds(case["sealed_at"])
        expected = None if inner.get("retracted") or expired else [
            "label", inner["labeler"], inner["subject"], inner["name"], inner.get("value"),
            inner["asserted_at"], inner.get("expires_at"), inner.get("delta"), ranked["height"]]
        assert case["state_tuple"] == expected, case["name"]
        if expected is not None:
            envelope["state"]["entries"] = [expected]
            state.validate(envelope)
    assert any(c["state_tuple"] is None and not c["sealed"][0]["label"].get("retracted")
               and "expires_at" in c["sealed"][0]["label"] for c in v["current_cases"]), "no expiry drops a tuple"
    assert any(c["state_tuple"] is not None and c["state_tuple"][7] is not None for c in v["current_cases"])
    for case in v["binding_cases"]:
        applies = case["record_anchor"] is not None and (case["delta"] is None or case["delta"] == case["record_anchor"])
        assert applies == case["applies"], case["name"]
    assert {c["applies"] for c in v["binding_cases"]} == {True, False}
    outcomes_expiry = {c["expected"] for c in v["cases"] if "expires_at" in c["envelope"]["label"]}
    assert outcomes_expiry == {"accepted", "fields"}, "expiry cases do not cover both dispositions"
    assert {c["expected"] for c in v["cases"] if "delta" in c["envelope"]["label"]} == {"accepted", "fields"}
    assert any(c["state_tuple"] is None for c in v["current_cases"])
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-2-site-publication.md").read_text())
    assert "the sealed Label with the greatest `asserted_at`, and among equal instants the one later in Log order" in prose
    assert "it is rejected under `WIST2-E06` and never sealed" in prose
    assert "applies nothing at a Block whose `sealed_at` is at or after that instant" in prose
    assert "the Label applies only while the subject URL's record stands on that anchor Delta" in prose
check("vectors:wist2-labels", _label_vectors)

def _label_vectors_twin():
    """The check above must notice a self-label accepted, a foreign-prefix
    name rejected and the tie broken the other way."""
    v = _label_vector()
    validator = Draft202012Validator(json.loads((ROOT / "schemas/label.schema.json").read_text()))
    terms = _wist_label_terms()
    self_case = next(c for c in v["cases"] if c["expected"] == "self")
    widened = copy.deepcopy(v["declaration"])
    widened["publisher"]["domain"] = "elsewhere.example"
    widened["publisher"]["subdomain_scope"] = []
    doc = copy.deepcopy(self_case["envelope"])
    doc["label"]["labeler"] = "elsewhere.example"
    assert _label_disposition(doc, widened, validator, v["url_cap_bytes"], terms) == "signature"
    foreign = next(c for c in v["cases"] if c["name"] == "name under a Canonical Host prefix")
    assert _label_disposition(foreign["envelope"], v["declaration"], validator, v["url_cap_bytes"], set()) == "accepted"
    assert _label_disposition(foreign["envelope"], v["declaration"], validator, 20, terms) == "fields"
    tie = next(c for c in v["current_cases"] if c["name"] == "equal instants break by Block height")
    reversed_order = min(tie["sealed"], key=lambda s: (s["height"], s["entry_index"]))
    assert reversed_order["label_id"] != tie["current"]
check("negative:wist2-labels", _label_vectors_twin)


def _dispute_vector():
    return json.loads((ROOT / "vectors/wist2/disputes.json").read_text())

def _dispute_disposition(doc, declaration, validator, sealed):
    """WIST-2 §3.3 over one Dispute Envelope: accepted, fields, unsealed,
    authority, signature or binding, in the order the section applies them."""
    import link_extraction
    if not validator.is_valid(doc):
        return "fields"
    dispute = doc["dispute"]
    if dispute["wist_version"].partition(".")[0] != "1":
        return "fields"
    publisher = declaration["publisher"]
    if dispute["disputant"] != publisher["domain"]:
        return "fields"
    if not _declaration_host_format(dispute["log"]):
        return "fields"
    if "reason" in dispute and link_extraction.normalize_url(dispute["reason"], dispute["reason"]) != dispute["reason"]:
        return "fields"
    try:
        publisher_instant(dispute["asserted_at"])
    except ValueError:
        return "fields"
    label = sealed.get(dispute["label"])
    if label is None:
        return "unsealed"
    subject = label["subject"]
    host = subject[len("https://"):].split("/", 1)[0] if subject.startswith("https://") else subject
    if host != publisher["domain"] and host not in publisher.get("subdomain_scope", []):
        return "authority"
    key = next((k for k in publisher["keys"] if k["key_id"] == doc["sig"]["key_id"]), None)
    if key is None:
        return "binding"
    if not _ed25519_profile_verdict(canonical_b64u_decode(key["public_key"]),
                                    canonical_b64u_decode(doc["sig"]["value"]),
                                    rfc8785.dumps(dispute))[0]:
        return "signature"
    return "accepted"

def _dispute_vectors():
    """WIST-2 §3.3 disputes: every disposition recomputed under the disputant's
    Declaration against the supplied sealed Labels, the Dispute IDs, the
    current-dispute rule and the WIST-3 §7 dispute tuple."""
    v = _dispute_vector()
    validator = Draft202012Validator(json.loads((ROOT / "schemas/dispute.schema.json").read_text()))
    sealed = {l["label_id"]: l for l in v["sealed_labels"]}
    codes = {"accepted": None, "fields": "WIST2-E06", "unsealed": "WIST2-E06", "authority": "WIST2-E06",
             "signature": "WIST1-E01", "binding": "WIST1-E02"}
    outcomes = set()
    for case in v["cases"]:
        got = _dispute_disposition(case["envelope"], case["declaration"], validator, sealed)
        assert got == case["expected"], (case["name"], got, case["expected"])
        assert case["code"] == codes[case["expected"]], case["name"]
        dispute_id = "sha256:" + hashlib.sha256(rfc8785.dumps(case["envelope"]["dispute"])).hexdigest()
        assert case["dispute_id"] == (dispute_id if case["expected"] == "accepted" else None), case["name"]
        outcomes.add(case["expected"])
    assert outcomes == set(codes)
    assert any(c["expected"] == "accepted" and c["envelope"]["dispute"]["log"] != "log.example" for c in v["cases"]), \
        "no accepted dispute cites another Log"
    example = json.loads((ROOT / "examples" / "dispute.json").read_text())
    example_sealed = {example["dispute"]["label"]: {"subject": "https://example.com/blog/post-1"}}
    publisher = json.loads((ROOT / "examples" / "publisher.json").read_text())
    assert _dispute_disposition(example, publisher, validator, example_sealed) == "accepted"
    state = Draft202012Validator(json.loads((ROOT / "schemas/snapshot-state.schema.json").read_text()))
    envelope = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
    for case in v["current_cases"]:
        ranked = max(case["sealed"], key=lambda s: (publisher_instant(s["dispute"]["asserted_at"]),
                                                     s["height"], s["entry_index"]))
        assert ranked["dispute_id"] == case["current"], case["name"]
        inner = ranked["dispute"]
        expected = ["dispute", inner["label"], inner["disputant"], inner.get("reason"), inner["asserted_at"],
                    ranked["height"]]
        assert case["state_tuple"] == expected, case["name"]
        envelope["state"]["entries"] = [expected]
        state.validate(envelope)
    block = json.loads((ROOT / "schemas/block.schema.json").read_text())
    assert "dispute" in block["properties"]["entries"]["items"]["properties"]["type"]["enum"]
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-2-site-publication.md").read_text())
    assert "the disputed Label's `subject` MUST lie under the disputant's authority" in prose
    assert "an Aggregator MUST NOT reject a dispute for naming another Log" in prose
    assert "A dispute is never applied by the Aggregator or a Snapshot builder" in prose
    w3 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "`publisher_delta`, `label`, `dispute`, and within each group" in w3
check("vectors:wist2-disputes", _dispute_vectors)

def _dispute_vectors_twin():
    v = _dispute_vector()
    validator = Draft202012Validator(json.loads((ROOT / "schemas/dispute.schema.json").read_text()))
    sealed = {l["label_id"]: l for l in v["sealed_labels"]}
    valid = next(c for c in v["cases"] if c["expected"] == "accepted")
    widened = copy.deepcopy(valid["declaration"])
    widened["publisher"]["domain"] = "elsewhere.example"
    doc = copy.deepcopy(valid["envelope"])
    doc["dispute"]["disputant"] = "elsewhere.example"
    assert _dispute_disposition(doc, widened, validator, sealed) == "authority"
    assert _dispute_disposition(valid["envelope"], valid["declaration"], validator, {}) == "unsealed"
    tie = next(c for c in v["current_cases"] if c["name"] == "equal instants break by Log order")
    assert min(tie["sealed"], key=lambda s: s["entry_index"])["dispute_id"] != tie["current"]
check("negative:wist2-disputes", _dispute_vectors_twin)


def _definition_vector():
    return json.loads((ROOT / "vectors/wist2/label-definitions.json").read_text())

def _definition_accepted(doc, declaration, validator, terms):
    import link_extraction
    if not validator.is_valid(doc):
        return False
    definition = doc["definition"]
    publisher = declaration["publisher"]
    if definition["wist_version"].partition(".")[0] != "1" or definition["labeler"] != publisher["domain"]:
        return False
    m = re.fullmatch(r"([a-z0-9.-]+):([a-z0-9-]+)", definition["name"])
    if not m or (m.group(1) == "wist" and definition["name"] not in terms) \
            or (m.group(1) != "wist" and not _declaration_host_format(m.group(1))):
        return False
    if link_extraction.normalize_url(definition["description"], definition["description"]) != definition["description"]:
        return False
    try:
        publisher_instant(definition["asserted_at"])
    except ValueError:
        return False
    key = next((k for k in publisher["keys"] if k["key_id"] == doc["sig"]["key_id"]), None)
    return key is not None and _ed25519_profile_verdict(
        canonical_b64u_decode(key["public_key"]), canonical_b64u_decode(doc["sig"]["value"]),
        rfc8785.dumps(definition))[0]

def _definition_vectors():
    """WIST-2 §3.3 label definitions: each case's acceptance recomputed over the
    example Declaration and the served path derived from the name."""
    v = _definition_vector()
    validator = Draft202012Validator(json.loads((ROOT / "schemas/label-definition.schema.json").read_text()))
    terms = _wist_label_terms()
    for case in v["cases"]:
        accepted = _definition_accepted(case["envelope"], v["declaration"], validator, terms)
        assert accepted == (case["expected"] == "accepted"), case["name"]
        path = ("labels/definitions/" + hashlib.sha256(case["envelope"]["definition"]["name"].encode("utf-8")).hexdigest()
                + ".json") if accepted else None
        assert case["path"] == path, case["name"]
    assert {c["envelope"]["definition"]["treatment"] for c in v["cases"] if c["expected"] == "accepted"} == {"hide", "warn", "inform"}
    example = json.loads((ROOT / "examples" / "label-definition.json").read_text())
    assert _definition_accepted(example, v["declaration"], validator, terms)
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-2-site-publication.md").read_text())
    assert "treats a name with no verifiable definition as `inform`" in prose
    assert "`<hex>` is the lowercase hex SHA-256 of the name's UTF-8 octets" in prose
    w4 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-governance.md").read_text())
    assert "`hide` (the subject is not presented), `warn` (presented with the Label shown) or `inform`" in w4
check("vectors:wist2-label-definitions", _definition_vectors)

def _definition_vectors_twin():
    v = _definition_vector()
    validator = Draft202012Validator(json.loads((ROOT / "schemas/label-definition.schema.json").read_text()))
    valid = next(c for c in v["cases"] if c["name"] == "valid definition")
    assert not _definition_accepted(valid["envelope"], v["declaration"], validator, set())
    doc = copy.deepcopy(valid["envelope"])
    doc["definition"]["treatment"] = "inform"
    assert not _definition_accepted(doc, v["declaration"], validator, _wist_label_terms())
check("negative:wist2-label-definitions", _definition_vectors_twin)


def _label_table_vector():
    return json.loads((ROOT / "vectors/wist3/label-tables.json").read_text())

def _label_table_vectors():
    """WIST-3 §7 labeler statistics, WIST-3 §3.2 per-Labeler cap and WIST-4 §6's
    recommended persistence and inactivity rules, each recomputed."""
    v = _label_table_vector()
    for case in v["statistics_cases"]:
        rows = {}
        for e in sorted(case["sealed"], key=lambda e: e["height"]):
            row = rows.setdefault(e["labeler"], [0, 0, set(), e["height"]])
            row[0] += 1
            row[1] += e["retracted"]
            row[2].add(e["subject"])
        expected = [{"labeler": k, "label_count": r[0], "retraction_count": r[1], "distinct_subjects": len(r[2]),
                     "first_seen_height": r[3]} for k, r in sorted(rows.items())]
        assert case["rows"] == expected, case["label"]
        assert len(expected) >= 2 and any(r["retraction_count"] for r in expected)
    seen = set()
    for case in v["cap_cases"]:
        domain = collections.Counter(e["domain"] for e in case["entries"])
        labeler = collections.Counter(e["domain"] for e in case["entries"] if e["type"] in ("label", "dispute"))
        over = max(domain.values()) > case["domain_block_entries_max"] or \
            (labeler and max(labeler.values()) > case["labeler_block_entries_max"])
        assert case["expected"] == ("WIST3-E03" if over else None), case["label"]
        assert case["labeler_block_entries_max"] <= case["domain_block_entries_max"]
        seen.add(case["expected"])
    assert seen == {None, "WIST3-E03"}
    assert any(e["type"] == "dispute" for c in v["cap_cases"] for e in c["entries"])
    for case in v["persistence_cases"]:
        def live(h):
            current = max((ev for ev in case["events"] if ev["height"] <= h),
                          key=lambda ev: publisher_instant(ev["asserted_at"]), default=None)
            if current is None or current["retracted"]:
                return False
            return case["expires_at_height"] is None or h < case["expires_at_height"]
        for probe in case["probes"]:
            assert probe["counted"] == (live(probe["height"]) and live(probe["height"] - 1)), (case["label"], probe)
        assert {p["counted"] for p in case["probes"]} == {True, False}, case["label"]
    for case in v["inactivity_cases"]:
        assert case["applies"] == (case["height"] - case["last_sealed_height"] <= case["inactivity_blocks"]), case["label"]
    assert {c["applies"] for c in v["inactivity_cases"]} == {True, False}
    w3 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "`(labeler, label_count, retraction_count, distinct_subjects, first_seen_height)`" in w3
    assert "a Block MUST NOT carry more than `labeler_block_entries_max`" in w3
    w4 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-governance.md").read_text())
    assert "only once it has persisted across two consecutive Blocks" in w4
    assert "Ignore a Labeler with no sealed Entry of any type within a configured number of Blocks, 720 by default" in w4
check("vectors:wist3-label-tables", _label_table_vectors)

def _label_table_vectors_twin():
    v = _label_table_vector()
    case = next(c for c in v["persistence_cases"] if c["label"] == "counted from the second consecutive Block")
    first = min(p["height"] for p in case["probes"] if p["counted"])
    assert not next(p for p in case["probes"] if p["height"] == first - 1)["counted"], "a Label counts in its sealing Block"
    cap = next(c for c in v["cap_cases"] if c["label"] == "labels over the labeler cap")
    assert len(cap["entries"]) <= cap["domain_block_entries_max"], "the labeler cap case is really a domain cap case"
check("negative:wist3-label-tables", _label_table_vectors_twin)


sys.exit(1 if failures else 0)
