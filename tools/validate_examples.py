#!/usr/bin/env python3
"""Validate examples/ against schemas/ and verify vectors/. Exit 0 = green."""
import base64, calendar, collections, copy, hashlib, hmac, itertools, json, pathlib, re, sys, time

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

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
    "snapshot-index.json": "index", "snapshot-state.json": "state",
    "audit-record.json": "record", "registry-update.json": "update",
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
    """WIST-4 §9's Default column, keyed by identifier, as leading integers.

    A row's Identifier cell may name one identifier or a "`a` / `b`" pair
    sharing one Default cell (e.g. `similarity_consistent` /
    `similarity_variance_floor`, or `link_agreement_consistent` /
    `link_variance_floor`): the Default cell then reads with the same
    "/"-separated shape, one leading integer per identifier, in the same
    order. A row is skipped rather than guessed at when that shape does
    not hold. Compound rules without identifiers are not numeric defaults.
    """
    spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    section9 = spec.split("## 9. Parameter Registry")[1].split("### 9.1.")[0]
    out = {}
    for line in section9.splitlines():
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
    in the WIST-4 §9 registry rather than carried as a literal anywhere."""
    caps = _registry_table_defaults()
    return (caps["extract_cap_bytes"] + caps["links_cap_bytes"]
            + caps["summary_cap_bytes"] + _content_wrapper_octets())

def _url_bound():
    """WIST-1 §3.2: the subject URL is octet-bounded (url_cap_bytes).

    The bound is read from the WIST-4 §9 registry rather than written here,
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

    Caps are read from the WIST-4 §9 registry table (the same source
    `_payload_length` derives from), not hard-coded, so the two checks cannot
    disagree after a `parameter_change` amends either one.

    What is deliberately NOT checked here: whether the declared `urls` prefix
    is the correct one for the page, and whether an omitted remainder would
    have fit `links_cap_bytes`. Both are checkable only against the live page
    (WIST-4 §5's link dimension), never from the Payload alone — an ingest
    validator sees only the already-truncated object.
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
    # WIST-4 §9's `link_url_cap_bytes` floor: `JCS("https://a.b/")`, the
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
    """WIST-2 §12's text extraction and WIST-4 §5's containment similarity:
    every fixture must be reproduced from its inputs by the reference
    implementation, and the guard default must match the Registry."""
    import link_extraction
    vec = json.loads((ROOT / "vectors" / "wist2" / "text-extraction.json").read_text())
    assert vec["min_observed_words"] == _registry_table_defaults()["min_observed_words"], \
        "the vector's min_observed_words has drifted from the Parameter Registry default"
    for case in vec["extraction"]:
        got = link_extraction.extract_text(bytes.fromhex(case["html_hex"]))
        assert got == case["expected"], f"{case['label']}: {got!r} != {case['expected']!r}"
    default_shingle = _registry_table_defaults()["shingle_size"]
    for case in vec["similarity"]:
        got = link_extraction.similarity(
            case["reference"], case["observed"], vec["min_observed_words"],
            case["shingle_size"])
        assert got == case["similarity"], \
            f"{case['label']}: {got!r} != {case['similarity']!r}"
    # §5: one parameter governs the shingle length and the branch
    # threshold, so an amended value must be able to move a pair across
    # the branch and change its score.
    amended = [c for c in vec["similarity"] if c["shingle_size"] != default_shingle]
    assert amended, "no case amends shingle_size"
    for case in amended:
        at_default = link_extraction.similarity(
            case["reference"], case["observed"], vec["min_observed_words"],
            default_shingle)
        assert at_default != case["similarity"], \
            f"{case['label']}: the amendment changes nothing"
    # The guard and the branch structure, pinned by shape rather than trust:
    # one null (mass guard), one short-reference case, one non-trivial
    # containment strictly between the bands' endpoints.
    sims = [c["similarity"] for c in vec["similarity"]]
    assert None in sims, "no mass-guard case in the vector"
    assert any(s is not None and 0 < s < 1_000_000 for s in sims), \
        "no partial-containment case in the vector"

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
            "against the Key Set of the first Block after `generated_at` sealing an applicable Declaration of the domain",
            "the Key Set is the highest `seq`'s, exactly as at a height",
            "A page that verifies under neither Key Set is `WIST2-E04`"):
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

def _text_extraction_twin():
    """Mutation twin: appended visible text must change the extraction, and
    removing the committed text from the observed side must sink the score."""
    import link_extraction
    vec = json.loads((ROOT / "vectors" / "wist2" / "text-extraction.json").read_text())
    case = vec["extraction"][0]
    got = link_extraction.extract_text(
        bytes.fromhex(case["html_hex"]) + b"<p>mutant words</p>")
    assert got != case["expected"], "appended text changed nothing — extraction is blind"
    full = next(c for c in vec["similarity"] if c["label"] == "containment-full")
    sunk = link_extraction.similarity(
        full["reference"], full["observed"].replace(full["reference"], ""),
        vec["min_observed_words"], full["shingle_size"])
    assert sunk == 0, f"removing the committed text left similarity {sunk!r}"

check("negative:wist2-text-extraction", _text_extraction_twin)

def _uax29_conformance():
    """External known-answer test: the Unicode Consortium's own
    WordBreakTest.txt and GraphemeBreakTest.txt for the release ADR-0017
    pins, run in full against tools/segmentation.py. The annex is
    implemented from its text, so this is what keeps that reading honest."""
    import segmentation
    assert segmentation.UNICODE_VERSION == "16.0.0", \
        f"the tables carry Unicode {segmentation.UNICODE_VERSION}, not the pinned release"
    ucd = ROOT / "tools" / "ucd"

    def cases(path):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#")[0].strip()
            if not line:
                continue
            text, expected, current = "", [], ""
            for token in line.split():
                if token == "\u00f7":
                    if current:
                        expected.append(current)
                        current = ""
                elif token != "\u00d7":
                    ch = chr(int(token, 16))
                    text += ch
                    current += ch
            if current:
                expected.append(current)
            yield text, expected

    for name, fn in (("WordBreakTest.txt", segmentation.split_word_bounds),
                     ("GraphemeBreakTest.txt", segmentation.grapheme_clusters)):
        total = 0
        for text, expected in cases(ucd / name):
            total += 1
            got = fn(text)
            assert got == expected, f"{name}: {text!r}: {got!r} != {expected!r}"
        assert total > 1000, f"{name}: only {total} cases parsed"

check("unicode:uax29-conformance", _uax29_conformance)

def _normalization_twin():
    """Mutation twin: each normalization case must come out differently under
    the one reading it exists to rule out, so a fixture that every
    implementation passes cannot sit in the vector unnoticed."""
    import unicodedata
    import segmentation
    import link_extraction
    vec = json.loads((ROOT / "vectors" / "wist2" / "text-extraction.json").read_text())

    def scored(reference, observed, guard, shingle, nfc, fold, split, unit):
        def words(text):
            text = unicodedata.normalize("NFC", text) if nfc else text
            text = text.casefold() if fold == "casefold" else text.lower()
            if split == "whitespace":
                return text.split(), text
            kept = [seg for seg in segmentation.split_word_bounds(text)
                    if any(unicodedata.category(c)[0] in ("L", "N") for c in seg)]
            return kept, " ".join(kept)

        ref_words, ref_form = words(reference)
        obs_words, obs_form = words(observed)
        if not ref_words or len(obs_words) < guard:
            return None
        if len(ref_words) >= shingle and len(obs_words) >= shingle:
            a = link_extraction._shingles(ref_words, shingle)
            b = link_extraction._shingles(obs_words, shingle)
        else:
            units = (list if unit == "codepoint" else segmentation.grapheme_clusters)
            ref_units, obs_units = units(ref_form), units(obs_form)
            n = min(shingle, len(ref_units), len(obs_units))
            a = link_extraction._shingles(ref_units, n)
            b = link_extraction._shingles(obs_units, n)
        return (len(a & b) * 1_000_000) // len(a) if a else None

    NORMATIVE = dict(nfc=True, fold="casefold", split="uax29", unit="cluster")
    # Each case names the single step it rules out, and the reading that
    # skips that step must score it differently.
    ruled_out = {
        "full-case-folding-folds-sharp-s": {"fold": "lower"},
        "nfc-precomposes-before-comparison": {"nfc": False},
        "han-segments-per-character": {"split": "whitespace"},
        "punctuation-segments-are-discarded": {"split": "whitespace"},
        "short-branch-counts-grapheme-clusters": {"unit": "codepoint"},
    }
    by_label = {c["label"]: c for c in vec["similarity"]}
    for label, difference in ruled_out.items():
        case = by_label[label]
        got = scored(case["reference"], case["observed"], vec["min_observed_words"],
                     case["shingle_size"], **{**NORMATIVE, **difference})
        assert got != case["similarity"], \
            f"{label}: {difference} also yields {got!r} — the case discriminates nothing"

check("negative:wist2-normalization", _normalization_twin)

def _snapshot_state_counted_urls():
    """WIST-3 §7: reputation_inputs carries counted-URL *digests*, never URLs.

    The state artifact is mandatory and unshardable-by-default, so carrying
    up to c_cap Normalized URLs per domain would make it outgrow the
    laptop-sized tier it ships beside. The encoding is what bounds it, so
    the encoding is pinned here rather than left to prose.
    """
    state = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())["state"]
    rows = [e for e in state["entries"] if e[0] == "reputation_inputs"]
    assert rows, "no reputation_inputs tuple in the state artifact"
    nonempty = 0
    for row in rows:
        counted = row[5]
        assert isinstance(counted, list), "the counted-URL set is not a list"
        for d in counted:
            nonempty += 1
            assert re.fullmatch(r"[0-9a-f]{32}", d), \
                f"counted-URL member {d!r} is not a 16-octet digest — a URL here is the size bug"
        # 16 KiB is the §7 bound at the default c_cap; a tuple already over
        # it in a two-record vector would mean the encoding drifted.
        assert len(rfc8785.dumps(counted)) <= 16384, "counted-URL set exceeds the §7 bound"
    assert nonempty, "no counted URL in any tuple — the digest encoding is untested"
    # The digest is domain-bound: the same URL under another domain differs.
    url = "https://example.com/blog/post-1"
    a = hashlib.sha256(rfc8785.dumps("example.com") + rfc8785.dumps(url)).hexdigest()[:32]
    b = hashlib.sha256(rfc8785.dumps("other.example") + rfc8785.dumps(url)).hexdigest()[:32]
    assert a != b, "the counted-URL digest does not bind the Publisher domain"

check("spec:wist3-counted-url-digests", _snapshot_state_counted_urls)


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
    expected = {"aggregator_key", "auditor", "declaration", "parameter",
                "sanction_state", "recovery_window", "exclusion",
                "coverage_failure", "escalation", "reputation_inputs", "record",
                "observer", "canary_commitment"}
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
    """WIST-1 §5.2 / WIST-4 §6.4: the recovery window and the inclusion
    ceiling were two MUSTs one Aggregator could not both keep, and the
    queue's disposition at window end was unstated."""
    w1 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-delta-format.md").read_text())
    w4 = re.sub(r"\s+", " ",
                (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    assert "revalidated against the Key Set of that chain's newest Declaration" in w1
    assert w1.count("WIST1-E13") >= 2, "E13 must appear in §5.2 and the §7 registry"
    assert "queued under WIST-1 §5.2" in w4, "§6.4 ceiling needs the recovery carve-out"

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
    """WIST-4 was the one document without an Error Registry, leaving ~15
    normative rejection conditions with no codes and the replay effect of a
    rejected Registry Update unstated."""
    w4 = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    assert "## 10. Error Registry" in w4
    assert "## 11. Security Considerations" in w4
    assert "## 12. Privacy Considerations" in w4
    assert "## 13. Conformance Checklist" in w4
    assert "## 10. Security Considerations" not in w4
    codes = re.findall(r"WIST4-E(\d{2})", w4)
    assert sorted(set(codes)) == ["01", "02", "03", "04", "05", "06", "07", "08"], sorted(set(codes))
    assert "never invalidates the containing Block" in re.sub(r"\s+", " ", w4)

check("spec:wist4-error-registry", _wist4_error_registry)


def _governance_acts_count():
    """WIST-4 §2's prose count of governance acts must equal the schema's
    action enum, and §5's field enumeration must carry prev_record — the
    schema requires it, so a §5 reader producing Records without it ships
    objects that never validate."""
    w4 = re.sub(r"\s+", " ",
                (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    action_enum = schema["properties"]["update"]["properties"]["action"]["enum"]
    words = {11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen",
             15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen"}
    assert f"the {words[len(action_enum)]} governance acts" in w4, \
        f"prose count does not match the {len(action_enum)}-action enum"
    fields = w4.split("## 5. Verdicts")[1][:2400]
    assert "prev_record" in fields, "§5's field enumeration omits prev_record"

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
    ships, and WIST-4 §9.1 covers it normatively for what an implementation adds.
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
COVERAGE_ASSERTED = {"payload:commitment", "audit:commitments", "vectors:wist4-canary"}

SALTED_COMMITMENTS = {          # (schema file, JSON path) -> proving check
    ("delta.schema.json",
     "properties/delta/properties/payload/properties/commitment"): "payload:commitment",
    ("audit-record.schema.json",
     "properties/record/properties/response_commitment"): "audit:commitments",
    ("audit-record.schema.json",
     "properties/record/properties/ref_extract_commitment"): "audit:commitments",
    ("audit-record.schema.json",
     "properties/record/properties/evidence_commitment"): "audit:commitments",
    ("audit-record.schema.json",
     "properties/record/properties/credit_commitment"): "audit:commitments",
}

SALTED_COMMITMENT_VALUES = {    # (ROOT-relative file, key) -> proving check
    ("examples/delta.json", "commitment"): "payload:commitment",
    ("examples/block.json", "commitment"): "payload:commitment",
    ("vectors/wist1/envelope.json", "commitment"): "payload:commitment",
    ("vectors/wist1/delta.canonical", "commitment"): "payload:commitment",
    ("vectors/wist3/block.json", "commitment"): "payload:commitment",
    ("vectors/multilog/dedup.json", "commitment"): "payload:commitment",
    ("examples/audit-record.json", "response_commitment"): "audit:commitments",
    ("examples/audit-record.json", "ref_extract_commitment"): "audit:commitments",
    ("examples/audit-record.json", "evidence_commitment"): "audit:commitments",
    ("examples/audit-record.json", "credit_commitment"): "audit:commitments",
    ("vectors/wist4/audit-commitments.json", "value"): "audit:commitments",
    ("vectors/wist4/canary.json", "credit_commitment"): "vectors:wist4-canary",
    ("vectors/wist4/canary.json", "response_commitment"): "vectors:wist4-canary",
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

    # Every shipped copy of this commitment is recomputed here, not argued for
    # transitively, so that each declaration naming this check is one this check
    # actually verified.
    covered_values = set()
    for rel, key in _declared_values_for("payload:commitment"):
        values = _values_at(rel, key)
        assert values, f"{rel}: no {key!r} to recompute, but it is declared here"
        for got in values:
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

RECORD_FIELDS = ["url", "publisher", "delta_id", "observed_at", "weight"]

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
    # on it undetected. `weight` is the WIST-4 §7 level-2 mark and `observed_at`
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
        if d["prev"] != tips.get(key):
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
                   "second first delta ignored", "publishers chain separately"):
        assert needed in labels, f"vector lacks the {needed} case"
    prose3 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    prose1 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-delta-format.md").read_text())
    assert "is not the chain tip the state carries" in prose3, \
        "WIST-3 §7 does not state the tip rule"
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
    """External known-answer anchor for tools/merkle.py, in the mold of
    ecvrf's RFC 9381 B.3 replay: the exhaustive property test above proves
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

# 4. WIST-4 §4: the ECVRF primitive itself, then the sampling vector built on it.
# The RFC 9381 Appendix B.3 vectors are the acceptance criterion for ecvrf.py:
# a VRF that is subtly wrong still *looks* verifiable, so the primitive is
# re-proved against the RFC on every harness run, not just at authoring time.
check("ecvrf:rfc9381-b3-vectors", ecvrf.self_test)

def _dc4_sampling():
    v = json.loads((ROOT / "vectors" / "wist4" / "sampling.json").read_text())
    pk = b64u_decode(v["auditor_public_key"])
    alpha, pi = bytes.fromhex(v["alpha_hex"]), bytes.fromhex(v["vrf_proof_hex"])
    # alpha is the 32 raw octets of the Block Hash: the hex digest decoded,
    # with the "sha256:" prefix NOT part of alpha (WIST-4 §4).
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
    # §4 displaces the formula to sampling_ceiling under a level-1 rung or an
    # escalation and under nothing else; §6.3's account of what a reset buys
    # names the formula's value at the Provisional cap, not the ceiling.
    labels = set()
    for c in v["rate_cases"]:
        labels.add(c["label"])
        formula = min(max(par["floor_1e7"] + par["slope_per_micro"] * (1_000_000 - c["reputation_u"]),
                          par["floor_1e7"]), par["ceiling_1e7"])
        expect = par["ceiling_1e7"] if c["level1_or_escalation"] else formula
        assert c["p_1e7"] == expect, f"{c['label']}: p_1e7"
        assert c["is_ceiling"] == (c["p_1e7"] == par["ceiling_1e7"]), f"{c['label']}: is_ceiling"
    assert "provisional cap under no rung" in labels, "vector lacks the Provisional-cap rate"
    cap = next(c for c in v["rate_cases"] if c["label"] == "provisional cap under no rung")
    assert not cap["is_ceiling"], "the Provisional cap's rate is the formula's, not the ceiling"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    assert "`p_1e7` 2 900 000 at the cap, below the `sampling_ceiling`" in prose, \
        "§6.3 does not name the formula's value at the Provisional cap"
check("vectors:wist4-sampling", _dc4_sampling)

def _dc4_sampling_rate_twin():
    """A harness reading the ceiling at the Provisional cap — the sentence
    §6.3 used to carry — must disagree with the vector."""
    v = json.loads((ROOT / "vectors" / "wist4" / "sampling.json").read_text())
    cap = next(c for c in v["rate_cases"] if c["label"] == "provisional cap under no rung")
    assert v["parameters"]["ceiling_1e7"] != cap["p_1e7"], \
        "the vector cannot tell the ceiling from the formula at the cap"
    displaced = next(c for c in v["rate_cases"] if c["label"] == "provisional cap under a level 1 rung")
    assert displaced["p_1e7"] == v["parameters"]["ceiling_1e7"] and displaced["reputation_u"] == cap["reputation_u"], \
        "the same reputation under a rung must read the ceiling"
check("negative:wist4-sampling-rate", _dc4_sampling_rate_twin)

def _dc4_link_agreement_optional():
    """WIST-4 §5, §13: a measured Record SHOULD carry `link_agreement` where
    the dimension applies, so the schema admits one without it; a link
    verdict asserts a reading and cannot omit it; the neutral verdicts
    cannot carry it."""
    schema = json.loads((ROOT / "schemas" / "audit-record.schema.json").read_text())
    validator = Draft202012Validator(schema)
    example = json.loads((ROOT / "examples" / "audit-record.json").read_text())
    assert "link_agreement" in example["record"], "the example Record should carry the field"
    without = copy.deepcopy(example)
    del without["record"]["link_agreement"]
    validator.validate(without)
    for verdict in ("link_variance", "link_inconsistent"):
        link = copy.deepcopy(without)
        link["record"]["verdict"] = verdict
        link["record"]["similarity"] = 1_000_000
        try:
            validator.validate(link)
        except ValidationError:
            pass
        else:
            raise AssertionError(f"a {verdict} Record without link_agreement validated")
    neutral = copy.deepcopy(example)
    neutral["record"]["verdict"] = "not_auditable"
    for field in ("response_commitment", "credit_commitment", "ref_extract_commitment",
                  "similarity", "evidence_commitment"):
        neutral["record"].pop(field, None)
    try:
        validator.validate(neutral)
    except ValidationError:
        pass
    else:
        raise AssertionError("a not_auditable Record carrying link_agreement validated")
    checklist = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    assert "seals the field on the Record as §5 says it SHOULD" in checklist, \
        "§13's link checklist line does not defer to §5's SHOULD"
check("schema:wist4-link-agreement-optional", _dc4_link_agreement_optional)

def _dc4_audit_record_proof():
    """The published Record's vrf_proof must verify for the Block it audits."""
    rec = json.loads((ROOT / "examples" / "audit-record.json").read_text())["record"]
    v = json.loads((ROOT / "vectors" / "wist4" / "sampling.json").read_text())
    alpha = bytes.fromhex(v["alpha_hex"])
    assert ecvrf.verify(load_test_pubkey(), alpha, bytes.fromhex(rec["vrf_proof"])), \
        "audit record vrf_proof does not verify"
    assert rec["vrf_proof"] == v["vrf_proof_hex"], "record proof differs from vector proof"
check("vectors:wist4-audit-record-proof", _dc4_audit_record_proof)

def _extension_proof_vector():
    return json.loads((ROOT / "vectors" / "wist4" / "extension-proof.json").read_text())

def _proof_standing(v, case):
    """WIST-4 §3/§4: the Block a Record's proof gives it standing for.

    A proof over the audited Block gives standing through the draw it
    determines; a proof over B₁, the Block that sealed the triggering
    Record, gives standing through the extension rule; any other proof
    gives none (WIST4-E01).
    """
    pk_audited = b64u_decode(case["admitted_at"]["audited_block"])
    pk_trigger = b64u_decode(case["admitted_at"]["trigger_block"])
    pi = bytes.fromhex(case["vrf_proof_hex"])
    audited = bytes.fromhex(v["audited_block"]["alpha_hex"])
    trigger = bytes.fromhex(v["trigger_block"]["alpha_hex"])
    if ecvrf.verify(pk_audited, audited, pi):
        beta = ecvrf.proof_to_hash(pi)
        D = int.from_bytes(
            hashlib.sha256(beta + v["audited_delta"].encode()).digest()[:8], "big")
        p_1e7 = min(max(200_000 + 3 * (1_000_000 - v["reputation_u"]), 200_000), 5_000_000)
        return ("audited", "selection" if D * 10**7 < p_1e7 * 2**64 else "WIST4-E01")
    if ecvrf.verify(pk_trigger, trigger, pi):
        return ("trigger", "extension" if case["named_by_extension"] else "WIST4-E01")
    return (None, "WIST4-E01")

def _dc4_extension_proof():
    """WIST-4 §4: an extension Record's vrf_proof is over B₁, not the audited Block."""
    v = _extension_proof_vector()
    block = json.loads((ROOT / "examples" / "block.json").read_text())
    empty = json.loads((ROOT / "vectors" / "wist3" / "empty-block.json").read_text())
    audited_hash = "sha256:" + hashlib.sha256(rfc8785.dumps(block["header"])).hexdigest()
    assert v["audited_block"]["block_hash"] == audited_hash, "audited Block is not the example Block"
    assert v["trigger_block"]["block_hash"] == empty["block_hash"], "B₁ is not the empty Block"
    for key in ("audited_block", "trigger_block"):
        assert v[key]["alpha_hex"] == v[key]["block_hash"].split(":")[1], f"{key}: alpha"
    assert empty["block"]["header"]["block_number"] > block["header"]["block_number"], \
        "B₁ must be sealed after the audited Block"
    assert any("sha256:" + hashlib.sha256(rfc8785.dumps(e["body"]["delta"])).hexdigest()
               == v["audited_delta"] for e in block["entries"]), \
        "audited_delta is not an Entry of the audited Block"
    labels = set()
    standings = set()
    for case in v["cases"]:
        labels.add(case["label"])
        got = _proof_standing(v, case)
        assert got == (case["proof_block"], case["standing"]), \
            f"{case['label']}: recomputed {got}, vector says {(case['proof_block'], case['standing'])}"
        standings.add(case["standing"])
    for needed in ("extension proof over trigger block", "audited block proof unselected",
                   "proof over neither block", "trigger proof but not summoned",
                   "rotated between the blocks proof under the key held at b1",
                   "rotated between the blocks b1 proof under the audited blocks key",
                   "rotated between the blocks audited proof under the key held at b1"):
        assert needed in labels, f"vector lacks the {needed} case"
    assert standings == {"extension", "WIST4-E01"}, standings
    assert v["rotated_public_key"] != v["auditor_public_key"], "the rotation admits the same key"
    assert any(c["admitted_at"]["audited_block"] != c["admitted_at"]["trigger_block"]
               for c in v["cases"]), "no case rotates between the audited Block and B₁"
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    assert "in whose selection set the Auditor holds `audited_delta`" in prose, \
        "§5 does not state which Block an extension Record's proof is over"
check("vectors:wist4-extension-proof", _dc4_extension_proof)

def _dc4_extension_proof_twin():
    """The check above must notice a proof over the wrong Block."""
    v = _extension_proof_vector()
    ext = next(c for c in v["cases"] if c["label"] == "extension proof over trigger block")
    aud = next(c for c in v["cases"] if c["label"] == "audited block proof unselected")
    assert _proof_standing(v, dict(ext, vrf_proof_hex=aud["vrf_proof_hex"]))[1] == "WIST4-E01", \
        "recomputation is blind to an extension Record carrying the audited Block's proof"
    assert _proof_standing(v, dict(ext, named_by_extension=False))[1] == "WIST4-E01", \
        "recomputation is blind to a proof over B₁ from an Auditor B₁ did not summon"
    old_key = next(c for c in v["cases"]
                   if c["label"] == "rotated between the blocks b1 proof under the audited blocks key")
    steady = dict(old_key, admitted_at={"audited_block": v["auditor_public_key"],
                                        "trigger_block": v["auditor_public_key"]})
    assert _proof_standing(v, steady)[1] == "extension", \
        "recomputation is blind to which key the Auditor held at B₁"
check("negative:wist4-extension-proof", _dc4_extension_proof_twin)

def _roster_vector():
    return json.loads((ROOT / "vectors" / "wist4" / "roster.json").read_text())

def _roster_independent(a, b):
    sa, sb = a.split(".")[-2:], b.split(".")[-2:]
    return len(sa) < 2 or len(sb) < 2 or sa != sb

def _roster_replay(log_id, entries):
    """WIST-4 §3/§4 roster derivation, recomputed independently of the
    generator: at most one admitted key per auditor_id at any height;
    removes at an instant apply before admits at it; a retired key_id,
    a subject barred for cause, an overlapping admit, a subject dependent
    on log_id, and a remove of a key its subject does not hold are all
    rejected (WIST4-E07)."""
    holding, retired, barred, rejected = {}, set(), set(), []
    by_instant = {}
    for i, e in enumerate(entries):
        by_instant.setdefault(e["sealed_at_s"], []).append((i, e))
    for t in sorted(by_instant):
        acts = by_instant[t]
        for i, e in [x for x in acts if x[1]["action"] == "auditor_remove"]:
            if holding.get(e["auditor_id"], (None,))[0] != e["key_id"]:
                rejected.append(i)
                continue
            retired.add(e["key_id"])
            retired.add(holding[e["auditor_id"]][2])
            holding[e["auditor_id"]] = (None, t, None)
            if e.get("evidence"):
                barred.add(e["auditor_id"])
        admits = [x for x in acts if x[1]["action"] == "auditor_admit"]
        for i, e in admits:
            held = holding.get(e["auditor_id"], (None, None, None))[0]
            live = {x for k, _, pk in holding.values() if k is not None for x in (k, pk)}
            twice = sum(1 for _, o in admits if o["auditor_id"] == e["auditor_id"]) > 1
            if (e["key_id"] in retired or e["public_key"] in retired
                    or e["key_id"] in live or e["public_key"] in live
                    or e["auditor_id"] in barred or held is not None
                    or twice or not _roster_independent(e["auditor_id"], log_id)):
                rejected.append(i)
                continue
            holding[e["auditor_id"]] = (e["key_id"], t, e["public_key"])
    return sorted(rejected)

def _observer_batch(case, log_id):
    initial, acts = case["initial_after_removals"], case["acts"]
    groups = collections.defaultdict(list)
    for i, a in enumerate(acts):
        groups[a["action"], a["subject"]].append(i)
    live = set(range(len(acts))) - {i for g in groups.values() if len(g) > 1 for i in g}
    for i in list(live):
        a = acts[i]
        occupied = any(subject != a["subject"] and any(key[field] == a[field] for field in ("key_id", "public_key"))
                       for mapping in (initial["auditors"], initial["observers"]) for subject, key in mapping.items())
        if (occupied or a["subject"] in initial["auditors"]
                or not _roster_independent(a["subject"], log_id)
                or a["action"] == "auditor_admit" and a["subject"] in initial["barred"]
                or a["key_id"] in initial["retired_key_ids"] or a["public_key"] in initial["retired_public_keys"]):
            live.remove(i)
    admits = {acts[i]["subject"] for i in live if acts[i]["action"] == "auditor_admit"}
    live -= {i for i in live if acts[i]["action"] == "observer_register" and acts[i]["subject"] in admits}
    by_key = collections.defaultdict(list)
    for i in live:
        for field in ("key_id", "public_key"):
            by_key[field, acts[i][field]].append(i)
    conflicts = {i for group in by_key.values() if len({acts[j]["subject"] for j in group}) > 1 for i in group}
    live -= conflicts
    state = {role: copy.deepcopy(initial[role]) for role in ("auditors", "observers")}
    for i in live:
        a = acts[i]
        role = "auditors" if a["action"] == "auditor_admit" else "observers"
        state[role][a["subject"]] = {k: a[k] for k in ("key_id", "public_key")}
        if role == "auditors":
            state["observers"].pop(a["subject"], None)
    return state | {"rejected_indices": sorted(set(range(len(acts))) - live)}

def _dc4_observer_batches():
    v = _roster_vector()
    for case in v["batch_cases"]:
        assert _observer_batch(case, "log.example.org") == case["expected"], case["label"]
check("vectors:wist4-observer-batches", _dc4_observer_batches)

def _dc4_observer_batches_twin():
    for case in _roster_vector()["batch_cases"]:
        for permutation in itertools.permutations(range(len(case["acts"]))):
            shuffled = case | {"acts": [case["acts"][i] for i in permutation]}
            result = _observer_batch(shuffled, "log.example.org")
            result["rejected_indices"] = sorted(permutation[i] for i in result["rejected_indices"])
            assert result == case["expected"], case["label"]
    collision = next(c for c in _roster_vector()["batch_cases"] if c["label"] == "registrations share key id")
    assert collision["expected"]["rejected_indices"] == [0, 1]
check("negative:wist4-observer-batches", _dc4_observer_batches_twin)

def _roster_admitted_at(log_id, entries, auditor_id, t):
    rejected = set(_roster_replay(log_id, entries))
    key = None
    for i, e in enumerate(entries):
        if i in rejected or e["auditor_id"] != auditor_id or e["sealed_at_s"] > t:
            continue
        key = e["key_id"] if e["action"] == "auditor_admit" else None
    return key

def _dc4_roster():
    """WIST-4 §3, §4: one admitted key per auditor_id per height, and the
    roster acts a replayer rejects."""
    v = _roster_vector()
    labels = set()
    for case in v["cases"]:
        labels.add(case["label"])
        seals = [e["sealed_at_s"] for e in case["entries"]]
        assert seals == sorted(seals), f"{case['label']}: entries not in Log order"
        got = _roster_replay(case["log_id"], case["entries"])
        assert got == case["rejected_indices"], \
            f"{case['label']}: recomputed rejections {got}, vector says {case['rejected_indices']}"
        for q in case["admitted_key_at"]:
            key = _roster_admitted_at(case["log_id"], case["entries"], q["auditor_id"], q["sealed_at_s"])
            assert key == q["key_id"], \
                f"{case['label']}: at {q['sealed_at_s']} recomputed {key}, vector says {q['key_id']}"
    for needed in ("rotation in one block", "overlapping admit rejected",
                   "retired key id rejected", "barred subject rejected",
                   "exit then re entry allowed", "removal ends admission at its instant",
                   "dependent on the log id rejected", "remove of a key not held rejected",
                   "two admits for one subject in one block both rejected",
                   "same public key under a fresh key id after exit rejected",
                   "public key held by another auditor rejected",
                   "key id held by another auditor rejected",
                   "retired key id re admitted by another auditor rejected",
                   "rejected for cause remove bars nothing",
                   "same block for cause remove and admit rejected"):
        assert needed in labels, f"vector lacks the {needed} case"
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    assert "at most one admitted key at any height" in prose, "§3 does not pin one key per height"
    assert "| WIST4-E07 |" in prose, "§10 has no roster row"
check("vectors:wist4-roster", _dc4_roster)

def _dc4_roster_twin():
    """The check above must notice a rotation whose removal went missing."""
    v = _roster_vector()
    case = next(c for c in v["cases"] if c["label"] == "rotation in one block")
    entries = [e for e in case["entries"] if e["action"] != "auditor_remove"]
    assert _roster_replay(case["log_id"], entries) == [1], \
        "recomputation is blind to a second key admitted beside a live one"
    case = next(c for c in v["cases"] if c["label"] == "removal ends admission at its instant")
    remove = next(e for e in case["entries"] if e["action"] == "auditor_remove")
    assert _roster_admitted_at(case["log_id"], case["entries"], remove["auditor_id"],
                               remove["sealed_at_s"] - 1) == remove["key_id"], \
        "recomputation is blind to the instant before a removal"
    case = next(c for c in v["cases"] if c["label"] == "two admits for one subject in one block both rejected")
    assert _roster_replay(case["log_id"], case["entries"][:1]) == [], \
        "recomputation rejects a lone admit as if a second stood beside it"
    case = next(c for c in v["cases"] if c["label"] == "same public key under a fresh key id after exit rejected")
    fresh = copy.deepcopy(case["entries"])
    fresh[2]["public_key"] = "pk-fresh"
    assert _roster_replay(case["log_id"], fresh) == [3], \
        "recomputation is blind to the public_key a re-admission names"
check("negative:wist4-roster", _dc4_roster_twin)

def _selection_domain_vector():
    return json.loads((ROOT / "vectors" / "wist4" / "selection-domain.json").read_text())

def _selection_domain_excluded(case):
    """WIST-4 §4 / WIST-3 §7, recomputed independently of the generator: a
    Delta is outside the Block's selection domain when its URL host has its
    own seq-0 Declaration sealed at or below the Block and the Delta's
    Publisher is not that host."""
    declared = {d["domain"]: d["seq0_height"] for d in case["declarations"]}
    return [i for i, e in enumerate(case["entries"])
            if e["url_host"] != e["publisher"]
            and declared.get(e["url_host"], case["block_height"] + 1) <= case["block_height"]]

def _dc4_selection_domain():
    """WIST-4 §4: which Deltas of a Block any Auditor's draw can select."""
    v = _selection_domain_vector()
    labels = set()
    outcomes = set()
    for case in v["cases"]:
        labels.add(case["label"])
        got = _selection_domain_excluded(case)
        assert got == case["excluded_indices"], \
            f"{case['label']}: recomputed {got}, vector says {case['excluded_indices']}"
        outcomes.add(bool(got))
    for needed in ("own host always selectable", "parent delta before the declaration",
                   "parent delta at the declaration height", "parent delta after the declaration",
                   "subdomain own delta selectable", "unrelated declaration excludes nothing",
                   "mixed block"):
        assert needed in labels, f"vector lacks the {needed} case"
    assert outcomes == {True, False}
    barred = set()
    for case in v["self_audit_cases"]:
        got = not _roster_independent(case["auditor_id"], case["publisher"])
        assert got == case["barred"], \
            f"{case['label']}: recomputed barred={got}, vector says {case['barred']}"
        barred.add(got)
    assert barred == {True, False}, "self_audit_cases must exercise both outcomes"
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    assert "inside *B*'s **selection domain**" in prose, "§4 does not define the selection domain"
    assert "A Delta §3 bars an Auditor from is in none of *that* Auditor's selection sets by either path" in prose, \
        "§4 does not take a barred Delta out of the Auditor's selection set"
check("vectors:wist4-selection-domain", _dc4_selection_domain)

def _dc4_selection_domain_twin():
    """The check above must notice a Declaration moved past the Block."""
    v = _selection_domain_vector()
    case = next(c for c in v["cases"] if c["label"] == "parent delta at the declaration height")
    mutated = json.loads(json.dumps(case))
    mutated["declarations"][0]["seq0_height"] += 1
    assert _selection_domain_excluded(mutated) == [], \
        "recomputation is blind to the Declaration's height"
    mutated = json.loads(json.dumps(case))
    mutated["entries"][0]["publisher"] = mutated["entries"][0]["url_host"]
    assert _selection_domain_excluded(mutated) == [], \
        "recomputation is blind to whose Delta it is"
    kin = next(c for c in v["self_audit_cases"] if c["label"] == "publisher under the auditors suffix")
    assert _roster_independent(kin["auditor_id"], "shop.example.org"), \
        "recomputation is blind to the Publisher's suffix"
check("negative:wist4-selection-domain", _dc4_selection_domain_twin)

def _parameter_vector():
    return json.loads((ROOT / "vectors" / "wist4" / "parameter-in-force.json").read_text())

def _value_in_force(default, changes, t_s, inclusive=True):
    """WIST-4 §9: greatest effective_at at or before t_s, Log order breaking
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
    """WIST-4 §9: which amendment is in force at an instant."""
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
                   (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    for marker in ("in force at every instant T at or after its `effective_at`, the endpoint included",
                   "the one later in Log order (WIST-3 §3.3: ascending Block height, then Entry index) prevails"):
        assert marker in prose, f"§9 does not state: {marker!r}"
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

def _countability_vector():
    return json.loads((ROOT / "vectors" / "wist4" / "parameter-combinations.json").read_text())

def _wist4_section9():
    spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    return spec.split("## 9. Parameter Registry")[1].split("### 9.1.")[0]

def _coverage_failures_max_default():
    """The row carries no identifier, so `_registry_table_defaults()` skips
    it; the rule below needs the published number all the same."""
    for line in _wist4_section9().splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 4 and "`coverage_failures_max`" in cells[0]:
            return int(re.match(r"(\d+)", cells[2]).group(1))
    raise AssertionError("§9 publishes no coverage_failures_max default")

def _cadence_upper_bound():
    for line in _wist4_section9().splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 3 and cells[0] == "`block_cadence_seconds`":
            return int(re.search(r"\u2264 ([\d ]+)", cells[1]).group(1).replace(" ", ""))
    raise AssertionError("§9 publishes no block_cadence_seconds ceiling")

def _counts_at_some_height(cadence_s, lag_s, failures_max, window_days=30):
    """The fact the §9 sum stands for: an Auditor failing every Block on a
    fully sealed grid, counted at every height, ever passing the tolerance."""
    window_s = window_days * 86400
    best = 0
    for n in range(lag_s // cadence_s + window_s // cadence_s + 3):
        heights = {h for h in range(n + 1)
                   if h * cadence_s + lag_s <= n * cadence_s
                   and (n - h) * cadence_s < window_s}
        best = max(best, len(heights))
    return best, best > failures_max

def _countability_sum(case, participants=("record_seal_blocks", "coverage_failures_max")):
    return (case["coverage_deadline_hours"] * 3600
            + sum(case[p] for p in participants) * case["block_cadence_seconds"])

def _dc4_coverage_countability():
    """WIST-4 §9: the sum that keeps a coverage failure countable."""
    v = _countability_vector()
    window_s = v["window_days"] * 86400
    published = _coverage_failures_max_default()
    labels = set()
    for case in v["cases"]:
        labels.add(case["label"])
        assert case["coverage_failures_max"] == published, \
            f"{case['label']}: coverage_failures_max is not §9's published default"
        total = _countability_sum(case)
        assert total == case["sum_s"], \
            f"{case['label']}: recomputed sum {total}, vector says {case['sum_s']}"
        assert (total < window_s) == case["rule_holds"], \
            f"{case['label']}: the rule's verdict disagrees with the vector"
        on_grid = (case["coverage_deadline_hours"] * 3600) % case["block_cadence_seconds"] == 0
        assert on_grid == case["deadline_on_grid"], f"{case['label']}: grid flag wrong"
        for side, seal_blocks in (("unattested", case["record_seal_blocks"]),
                                  ("attested_next_block", 1)):
            lag = ((case["coverage_deadline_hours"] * 3600) // case["block_cadence_seconds"]
                   + seal_blocks) * case["block_cadence_seconds"]
            assert lag == case[side]["establishing_lag_s"], \
                f"{case['label']} {side}: recomputed lag {lag}"
            reached, fires = _counts_at_some_height(case["block_cadence_seconds"], lag,
                                                    case["coverage_failures_max"],
                                                    v["window_days"])
            assert reached == case[side]["max_counted_at_any_height"], \
                f"{case['label']} {side}: recomputed {reached} counted, vector says {case[side]['max_counted_at_any_height']}"
            assert fires == case[side]["predicate_reachable"], \
                f"{case['label']} {side}: reachability disagrees with the count"
        if case["deadline_on_grid"]:
            assert case["rule_holds"] == case["unattested"]["predicate_reachable"], \
                f"{case['label']}: the rule and the predicate part on the grid"
        else:
            assert not case["rule_holds"] or case["unattested"]["predicate_reachable"], \
                f"{case['label']}: the rule admits an unreachable predicate"
    maxed = next(c for c in v["cases"]
                 if c["block_cadence_seconds"] == _cadence_upper_bound()
                 and c["record_seal_blocks"] == 24 and c["coverage_deadline_hours"] == 72)
    assert not maxed["rule_holds"] and not maxed["unattested"]["predicate_reachable"] \
        and maxed["attested_next_block"]["predicate_reachable"], \
        "the vector no longer shows the ceiling the per-parameter table permits"
    for needed in ("registry defaults", "one block past it", "a deadline between two blocks"):
        assert needed in labels, f"vector lacks the {needed} case"
    prose = re.sub(r"\s+", " ", _wist4_section9())
    for marker in ("`coverage_deadline_hours` \u00d7 3600 + (`record_seal_blocks` + "
                   "`coverage_failures_max`) \u00d7 `block_cadence_seconds` MUST be shorter "
                   "than 30 whole days (2 592 000 seconds)",
                   "a party replaying the Log MUST reject a `parameter_change` that leaves it otherwise"):
        assert marker in prose, f"§9 does not state: {marker!r}"
check("vectors:wist4-coverage-countability", _dc4_coverage_countability)

def _dc4_coverage_countability_twin():
    """The check above must notice a sum bounded at the endpoint instead of
    below it, and one that leaves `coverage_failures_max` out."""
    v = _countability_vector()
    window_s = v["window_days"] * 86400
    boundary = next(c for c in v["cases"] if c["sum_s"] == window_s)
    assert not boundary["unattested"]["predicate_reachable"], \
        "the boundary case no longer sits where the two readings part"
    assert (boundary["sum_s"] <= window_s) != boundary["rule_holds"], \
        "an endpoint-inclusive bound admits a parameter set no history satisfies"
    dead = next(c for c in v["cases"] if not c["unattested"]["predicate_reachable"]
                and c["block_cadence_seconds"] == _cadence_upper_bound())
    assert _countability_sum(dead, ("record_seal_blocks",)) < window_s, \
        "the twin's failure span no longer changes the verdict"
check("negative:wist4-coverage-countability", _dc4_coverage_countability_twin)

def _unauditable_vector():
    return json.loads((ROOT / "vectors" / "wist4" / "unauditable.json").read_text())

def _record_blocks(record, every_not_auditable=False):
    """WIST-4 §5: a robots_excluded Record, or a not_auditable Record whose
    `unmeasured` side is the observed one. `every_not_auditable` is the
    ruled-out reading that lets a missing reference block."""
    if record["verdict"] == "unreachable":
        return bool(record.get("robots_excluded"))
    if record["verdict"] != "not_auditable":
        return False
    return True if every_not_auditable else record.get("unmeasured") == "observed"

def _unauditable_at(v, case, end_inclusive_start_exclusive=True):
    """WIST-4 §5: two independent blocking Records inside the horizon
    ending at N, uncleared by an independent third Record sealed after the
    later of them and at or below N."""
    horizon_s = v["unauditable_horizon_days"] * 86400
    n_s = case["n_sealed_at_s"]
    def in_window(t):
        if end_inclusive_start_exclusive:
            return t <= n_s and n_s - t < horizon_s
        return t <= n_s and n_s - t <= horizon_s
    live = [b for b in case["blocking"] if _record_blocks(b) and in_window(b["sealed_at_s"])]
    for i, b1 in enumerate(live):
        for b2 in live[i + 1:]:
            if not _roster_independent(b1["auditor"], b2["auditor"]):
                continue
            later = max(b1["sealed_at_s"], b2["sealed_at_s"])
            if not any(later < c["sealed_at_s"] <= n_s
                       and c["verdict"] in v["clearing_verdicts"]
                       and _roster_independent(c["auditor"], b1["auditor"])
                       and _roster_independent(c["auditor"], b2["auditor"])
                       for c in case["other_records"]):
                return True
    return False

def _dc4_unauditable():
    """WIST-4 §5: the unauditable predicate, with its horizon measured like
    every other window."""
    v = _unauditable_vector()
    labels = set()
    for case in v["cases"]:
        labels.add(case["label"])
        for b in case["blocking"]:
            assert _record_blocks(b) == b["blocks"], f"{case['label']}: blocks"
        got = _unauditable_at(v, case)
        assert got == case["unauditable"], \
            f"{case['label']}: recomputed {got}, vector says {case['unauditable']}"
    for needed in ("two reference side not auditable records block nothing",
                   "an observed side not auditable record beside a robots exclusion blocks",
                   "a reference side record beside a robots exclusion blocks nothing",
                   "two observed side not auditable records block",
                   "second blocking exactly thirty days before n",
                   "second blocking one second inside the horizon",
                   "cleared by a third independent auditor",
                   "clearing auditor dependent on a blocker",
                   "clearing record at the later blocking instant",
                   "clearing record exactly at n",
                   "three blockers one pair uncleared"):
        assert needed in labels, f"vector lacks the {needed} case"
    assert set(v["clearing_verdicts"]) == {"consistent", "inconsistent", "dynamic_variance",
                                           "link_variance", "link_inconsistent"}
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    assert ("sealed inside the 30 whole days (Parameter Registry: `unauditable_horizon_days`) "
            "ending at Block N's `sealed_at`") in prose, "§5 does not measure the horizon as a window ending at N"
check("vectors:wist4-unauditable", _dc4_unauditable)

def _dc4_unauditable_twin():
    """The check above must notice a horizon read end-inclusive at 30."""
    v = _unauditable_vector()
    case = next(c for c in v["cases"] if c["label"] == "second blocking exactly thirty days before n")
    assert _unauditable_at(v, case, end_inclusive_start_exclusive=False) is True, \
        "the twin's closed horizon did not admit the thirtieth-day Record"
    assert _unauditable_at(v, case) is False, \
        "recomputation is blind to the horizon's start"
    reference = next(c for c in v["cases"]
                     if c["label"] == "two reference side not auditable records block nothing")
    assert all(_record_blocks(b, every_not_auditable=True) for b in reference["blocking"]) \
        and not any(_record_blocks(b) for b in reference["blocking"]), \
        "recomputation is blind to which side left nothing to measure"
check("negative:wist4-unauditable", _dc4_unauditable_twin)

def _dc4_unmeasured_field():
    """WIST-4 §5, audit-record schema: a not_auditable Record names the side
    that left nothing to measure, and no other verdict carries the field."""
    schema = json.loads((ROOT / "schemas" / "audit-record.schema.json").read_text())
    validator = Draft202012Validator(schema)
    example = json.loads((ROOT / "examples" / "audit-record.json").read_text())
    neutral = copy.deepcopy(example)
    neutral["record"]["verdict"] = "not_auditable"
    for field in ("response_commitment", "credit_commitment", "ref_extract_commitment",
                  "similarity", "evidence_commitment", "link_agreement"):
        neutral["record"].pop(field, None)
    assert list(validator.iter_errors(neutral)), "a not_auditable Record without unmeasured validated"
    for side in ("observed", "reference"):
        sided = copy.deepcopy(neutral)
        sided["record"]["unmeasured"] = side
        validator.validate(sided)
    bad = copy.deepcopy(neutral); bad["record"]["unmeasured"] = "mirror"
    assert list(validator.iter_errors(bad)), "an unknown side validated"
    measured = copy.deepcopy(example); measured["record"]["unmeasured"] = "observed"
    assert list(validator.iter_errors(measured)), "a measured Record carrying unmeasured validated"
    unreachable = copy.deepcopy(neutral); unreachable["record"]["verdict"] = "unreachable"
    unreachable["record"]["unmeasured"] = "observed"
    assert list(validator.iter_errors(unreachable)), "an unreachable Record carrying unmeasured validated"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    for marker in ("every `not_auditable` Record carries `unmeasured`",
                   "a `not_auditable` Record without `unmeasured`, or any other Record carrying it (§5)"):
        assert marker in prose, f"WIST-4 does not state: {marker!r}"
check("schema:wist4-unmeasured", _dc4_unmeasured_field)

def _coverage_vector():
    return json.loads((ROOT / "vectors" / "wist4" / "coverage.json").read_text())

def _establishing_height(case, attestation_overrides=False):
    """WIST-4 §4: the earlier of the two evidence heights the Log carries —
    the attestation's Block, or the record_seal_blocks-th Block sealed after
    the deadline; `attestation_overrides` is the ruled-out reading under
    which an attestation sealed later moves the height it establishes at."""
    after = [b["height"] for b in case["blocks"] if b["sealed_at_s"] > case["coverage_deadline_s"]]
    unattested = after[case["record_seal_blocks"] - 1] if len(after) >= case["record_seal_blocks"] else None
    attested = case["attestation_height"]
    if attestation_overrides and attested is not None:
        return attested
    evidence = [h for h in (attested, unattested) if h is not None]
    return min(evidence) if evidence else None

def _dc4_coverage_establishing():
    """WIST-4 §4: a failed duty enters the count from its establishing height,
    read from the Log up to N, and counts only while the audited Block is
    inside the 30 whole days ending at N."""
    v = _coverage_vector()
    window_s = v["window_days"] * 86400
    labels = set()
    for case in v["establishing_cases"]:
        labels.add(case["label"])
        establishing = _establishing_height(case)
        assert establishing == case["establishing_height"], f"{case['label']}: establishing height"
        audited_s = case["audited_block"]["sealed_at_s"]
        for probe in case["counts_at"]:
            expect = (establishing is not None and establishing <= probe["height"]
                      and audited_s <= probe["sealed_at_s"] < audited_s + window_s)
            assert probe["counts"] == expect, f"{case['label']} at {probe['height']}"
    for needed in ("a later attestation confirms the unattested failure and moves nothing",
                   "evidence outside the window counts at no height"):
        assert needed in labels, f"vector lacks the {needed} case"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    assert "whichever of the two the Log carries first where it carries both" in prose, \
        "§4 does not say which evidence establishes where the Log carries both"
check("vectors:wist4-coverage-establishing", _dc4_coverage_establishing)

def _signature_void(case, duty_key_governs=False):
    """WIST-4 §3, §4: the signature reads the key held at the Record's own
    Block, the proof the key admitted at the duty's Block. `duty_key_governs`
    is the ruled-out reading under which the signature too must verify
    against the duty Block's key."""
    signed, at_record, duty = case["signed_under"], case["record_block_key"], case["duty_block_key"]
    if duty_key_governs:
        return None if signed == duty else "never admitted at anchor block"
    if signed == at_record:
        return None
    return "removed after anchor block" if signed == duty else "never admitted at anchor block"

def _dc4_coverage_signature():
    """WIST-4 §3, §4: which key a rotated Record signs under, which its proof
    is under, and what each mismatch does to standing and discharge."""
    v = _coverage_vector()
    labels = set()
    discharging = {"removed after anchor block", "coverage failure at sealing", "malformed as evidence"}
    for case in v["signature_cases"]:
        labels.add(case["label"])
        void = _signature_void(case)
        assert void == case["void"], f"{case['label']}: void"
        assert case["proof_under"] == case["duty_block_key"], f"{case['label']}: the proof reads the duty key"
        assert case["counts"] == (void is None), f"{case['label']}: counts"
        assert case["discharges"] == (void is None or void in discharging), f"{case['label']}: discharges"
    for needed in ("rotated record signed under the new key with the old proof",
                   "rotated record signed under the removed duty key",
                   "exited auditor signs under the removed duty key"):
        assert needed in labels, f"vector lacks the {needed} case"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    for marker in ("carries its `vrf_proof` under the key admitted then",
                   "The signature is §3's: under the key the Auditor holds at the Record's own Block"):
        assert marker in prose, f"§4 does not state: {marker!r}"
check("vectors:wist4-coverage-signature", _dc4_coverage_signature)

def _dc4_coverage_signature_twin():
    """The check above must notice a signature read against the duty key."""
    v = _coverage_vector()
    rotated = next(c for c in v["signature_cases"]
                   if c["label"] == "rotated record signed under the new key with the old proof")
    assert _signature_void(rotated, duty_key_governs=True) is not None and rotated["void"] is None, \
        "recomputation is blind to which Block's key the signature reads"
check("negative:wist4-coverage-signature", _dc4_coverage_signature_twin)

def _dc4_coverage_establishing_twin():
    """The check above must notice a future attestation read as suppressing
    the unattested failure it arrives after."""
    v = _coverage_vector()
    case = next(c for c in v["establishing_cases"]
                if c["label"] == "a later attestation confirms the unattested failure and moves nothing")
    overriding = _establishing_height(case, attestation_overrides=True)
    assert overriding == case["attestation_height"] and overriding > case["establishing_height"], \
        "the twin's reading did not move the establishing height"
    between = next(p for p in case["counts_at"]
                   if case["establishing_height"] <= p["height"] < case["attestation_height"])
    assert between["counts"] and not (overriding <= between["height"]), \
        "recomputation is blind to an attestation read from above N"
check("negative:wist4-coverage-establishing", _dc4_coverage_establishing_twin)

def _confirmation_quorum_index(records, window_hours, quorum):
    for i, candidate in enumerate(records):
        suffixes = {tuple(r["auditor"].split(".")[-2:]) for r in records[:i + 1]
                    if 0 <= candidate["sealed_at_s"] - r["sealed_at_s"] <= window_hours * 3600}
        if len(suffixes) >= quorum:
            return i
    return None

def _dc4_confirmation_quorums():
    v = json.loads((ROOT / "vectors" / "wist4" / "confirmation.json").read_text())
    for case in v["cases"] + v["quorum_cases"]:
        got = _confirmation_quorum_index(case["records"], v["confirm_window_hours"],
                                         case.get("confirm_auditors", 2))
        assert got == case["confirming_index"], case["label"]
        severity = None
        if got is not None:
            sim = max(r["effective_similarity"] for r in case["records"][:got + 1])
            severity = 1 if case.get("verdict") == "link_inconsistent" or sim >= 150_000 else 2 if sim >= 50_000 else 3
        assert severity == case["severity"], case["label"]
    for case in v["quorum_contradiction_cases"]:
        trigger = case["trigger"]
        held = [r for r in case["records"] if trigger["sealed_at_s"] <= r["sealed_at_s"] <=
                trigger["sealed_at_s"] + v["confirm_window_hours"] * 3600]
        agreeing = [trigger] + [r for r in held if r["verdict"] == trigger["verdict"]]
        confirmed = len({tuple(r["auditor"].split(".")[-2:]) for r in agreeing}) >= case["confirm_auditors"]
        consistent = len({tuple(r["auditor"].split(".")[-2:]) for r in held
                          if r["verdict"] == "consistent"}) >= case["confirm_auditors"]
        closed = case["closing_sealed_at_s"] > trigger["sealed_at_s"] + v["confirm_window_hours"] * 3600
        assert confirmed == case["confirmed"], case["label"]
        assert (closed and not confirmed and consistent) == case["contradicted"], case["label"]
check("vectors:wist4-confirmation-quorums", _dc4_confirmation_quorums)

def _dc4_confirmation_quorums_twin():
    v = json.loads((ROOT / "vectors" / "wist4" / "confirmation.json").read_text())
    stale = next(c for c in v["quorum_cases"] if c["label"] == "stale member beside fresh pair inconsistent")
    assert _confirmation_quorum_index(stale["records"], 72, 2) is not None
    assert stale["confirming_index"] is None
    assert len({r["auditor"] for r in stale["records"]}) == stale["confirm_auditors"]
    pair = next(c for c in v["quorum_contradiction_cases"] if c["label"] == "consistent pair is insufficient inconsistent")
    assert len(pair["records"]) == 2 and not pair["contradicted"]
check("negative:wist4-confirmation-quorums", _dc4_confirmation_quorums_twin)

def _dc4_late_discharge():
    v = json.loads((ROOT / "vectors" / "wist4" / "coverage.json").read_text())
    for case in v["late_discharge_cases"]:
        for probe in case["probes"]:
            n = probe["height"]
            covered = [r["delta"] for r in case["records"] if r["sealed_height"] <= n and not r["void"]]
            attested = case["coverage_attestation_height"]
            complete = all(d in covered for d in case["selected"]) if case["selected"] else attested is not None and attested <= n
            established = n >= case["deadline_height"] + case["record_seal_blocks"] or case["pull_height"] is not None and case["pull_height"] <= n
            assert complete == probe["complete"], case["label"]
            assert (established and not complete) == probe["counts"], case["label"]
check("vectors:wist4-late-discharge", _dc4_late_discharge)

def _dc4_late_discharge_twin():
    v = json.loads((ROOT / "vectors" / "wist4" / "coverage.json").read_text())
    case = v["late_discharge_cases"][0]
    before = next(p for p in case["probes"] if p["height"] == 99)
    after = next(p for p in case["probes"] if p["height"] == 100)
    assert before["counts"] and not after["counts"]
    assert case["pull_height"] < after["height"] and after["complete"]
check("negative:wist4-late-discharge", _dc4_late_discharge_twin)

def _dc4_suppression_attribution():
    v = json.loads((ROOT / "vectors" / "wist4" / "coverage.json").read_text())
    for case in v["attribution_cases"]:
        pull, successor = case["pull"], case["successor"]
        n, arrived = case["n_height"], case["predecessor_sealed_height"]
        proof = all((pull["height"] <= successor["height"] <= n,
                     successor["auditor"] == case["auditor"], successor["log"] == case["log"],
                     successor["prev_record"] in pull["found"],
                     arrived is None or arrived > n))
        assert proof == case["chain_contradicts"], case["label"]
check("vectors:wist4-suppression-attribution", _dc4_suppression_attribution)

def _dc4_suppression_attribution_twin():
    v = json.loads((ROOT / "vectors" / "wist4" / "coverage.json").read_text())
    unrelated = next(c for c in v["attribution_cases"] if c["label"] == "unrelated missing predecessor")
    assert unrelated["predecessor_sealed_height"] is None and not unrelated["chain_contradicts"]
    related = next(c for c in v["attribution_cases"] if c["label"] == "related missing predecessor")
    assert related["successor"] == unrelated["successor"] and related["chain_contradicts"]
check("negative:wist4-suppression-attribution", _dc4_suppression_attribution_twin)

def _prospective_values(defaults, changes, at_s):
    values = dict(defaults)
    for c in sorted(changes, key=lambda c: (c["effective_at_s"], c["block_height"], c["entry_index"])):
        if c["effective_at_s"] <= at_s:
            values[c["parameter"]] = c["value"]
    return values

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
            if (c["value"] < 1 or c["effective_at_s"] - c["sealed_at_s"] < 7 * 86400
                    or any(m["sampling_floor"] > m["sampling_ceiling"] for m in maps)):
                rejected.append(i)
            else:
                accepted.append(c)
        assert sorted(rejected) == case["rejected_indices"], case["label"]
        for probe in case["maps"]:
            assert _prospective_values(v["prospective_defaults"], accepted, probe["at_s"]) == probe["values"], case["label"]
check("vectors:wist4-prospective-parameters", _dc4_prospective_parameters)

def _dc4_prospective_parameters_twin():
    v = json.loads((ROOT / "vectors" / "wist4" / "parameter-combinations.json").read_text())
    case = next(c for c in v["prospective_cases"] if c["label"] == "pending floor then incompatible ceiling")
    now = _prospective_values(v["prospective_defaults"], case["changes"], case["changes"][-1]["sealed_at_s"])
    assert now["sampling_floor"] <= now["sampling_ceiling"]
    assert case["rejected_indices"] == [1]
    future = _prospective_values(v["prospective_defaults"], case["changes"], 11 * 86400)
    assert future["sampling_floor"] > future["sampling_ceiling"]
check("negative:wist4-prospective-parameters", _dc4_prospective_parameters_twin)

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
    for case in v["confirmation_clock_cases"]:
        successes = []
        for i, t in enumerate(case["record_times_s"]):
            window = at("confirm_window_hours", t, case["changes"]) * 3600
            quorum = at("confirm_auditors", t, case["changes"])
            members = [u for u in case["record_times_s"][:i + 1] if u >= t - window]
            if len(members) >= quorum:
                successes.append(i)
        assert (min(successes) if successes else None) == case["confirming_index"], case["label"]
    fixed = next(c for c in v["clock_cases"] if c["label"] == "coverage retains deadline")
    assert at(fixed["parameter"], fixed["query_s"], fixed["changes"]) != fixed["selected_value"]
    raised = v["confirmation_clock_cases"][0]
    assert raised["confirming_index"] == 2 and v["clock_defaults"]["confirm_auditors"] == 2
check("vectors:wist4-parameter-clocks", _dc4_parameter_clocks)

def _dc4_parameter_wire_range():
    v = json.loads((ROOT / "vectors/wist4/parameter-combinations.json").read_text())
    validator = Draft202012Validator(json.loads((ROOT / "schemas/registry-update.schema.json").read_text()))
    key = Ed25519PublicKey.from_public_bytes(b64u_decode(v["wire_public_key"]))
    for case in v["wire_cases"]:
        doc = case["envelope"]
        assert validator.is_valid(doc) == case["schema_valid"], case["label"]
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
        cadence = d["value"] if d["parameter"] == "block_cadence_seconds" else 3600
        holds = (36 * 3600 + 24 * cadence <= 72 * 3600
            and 168 * cadence >= 72 * 3600 + 72 * cadence
            and 72 * 3600 + 48 * cadence < 30 * 86400)
        assert holds == case["combinations_hold_at_defaults"], case["label"]
    cap = next(c for c in v["wire_cases"] if c["envelope"]["update"]["details"] == {"parameter": "provisional_cap_u", "value": -1})
    assert min(100000, cap["envelope"]["update"]["details"]["value"]) < 0 and not cap["schema_valid"]
check("vectors:wist4-parameter-wire-range", _dc4_parameter_wire_range)

def _extension_vector():
    return json.loads((ROOT / "vectors" / "wist4" / "extension.json").read_text())

def _extension_order(case, reverse=False):
    records = sorted(case["records"], key=lambda r: (r["block_height"], r["entry_index"]), reverse=reverse)
    history = list(case["prior_triggers"])
    seen, eligible, summons, peers = {}, [], [], []
    for r in records:
        prior = seen.get(r["delta"], [])
        candidate = not any(0 <= r["sealed_at_s"] - e["sealed_at_s"] <= 72 * 3600 for e in prior)
        used = sum(a == r["auditor"] and 0 <= r["sealed_at_s"] - t < 30 * 86400 for a, t in history)
        fires = candidate and used < 3
        eligible.append(candidate)
        summons.append(fires)
        peers.append([a for a in case["roster"] if fires
                      and _roster_independent(a, case["publisher_domain"])
                      and all(_roster_independent(a, e["auditor"]) for e in prior + [r])])
        if fires:
            history.append((r["auditor"], r["sealed_at_s"]))
        seen.setdefault(r["delta"], []).append(r)
    return eligible, summons, peers

def _dc4_extension_order():
    for case in _extension_vector()["order_cases"]:
        assert _extension_order(case) == (case["eligible"], case["summons"], case["summoned_auditors"]), case["label"]
check("vectors:wist4-extension-order", _dc4_extension_order)

def _dc4_extension_order_twin():
    cases = _extension_vector()["order_cases"]
    first = cases[0]
    reversed_result = _extension_order(first, reverse=True)
    assert list(reversed(reversed_result[1])) != first["summons"]
    peer = next(c for c in cases if c["label"] == "later peer does not cancel summons")
    assert peer["records"][1]["auditor"] in peer["summoned_auditors"][0]
    assert peer["eligible"] == [True, False]
check("negative:wist4-extension-order", _dc4_extension_order_twin)

def _contradiction_outcome(v, case, endpoint_inclusive=True):
    """WIST-4 §4: a summoning Record is contradicted when its extension closes
    — the first Block sealed more than confirm_window_hours after B₁ — with
    no confirmation and an independent consistent pair sealed inside the
    window, the endpoint included."""
    window_s = v["confirm_window_hours"] * 3600
    trigger = case["trigger"]
    b1_s = trigger["sealed_at_s"]
    def inside(t):
        return b1_s <= t <= b1_s + window_s if endpoint_inclusive else b1_s <= t < b1_s + window_s
    held = [r for r in case["records"] if inside(r["sealed_at_s"])]
    confirmed = any(r["verdict"] == trigger["verdict"]
                    and _roster_independent(r["auditor"], trigger["auditor"]) for r in held)
    consistent = [r for r in held if r["verdict"] == "consistent"]
    pair = any(_roster_independent(a["auditor"], b["auditor"])
               for i, a in enumerate(consistent) for b in consistent[i + 1:])
    closes = next((b["height"] for b in v["contradiction_blocks"]
                   if b["sealed_at_s"] > b1_s + window_s), None)
    contradicted = case["summoned"] and not confirmed and pair and closes is not None
    return closes, confirmed, pair, contradicted

def _dc4_contradiction():
    """WIST-4 §4: the instant an extension closes, the contradiction it
    settles, and the escalated sampling that follows for the domain."""
    v = _extension_vector()
    assert "contradictions_max" not in v, "the vector still carries the retired divergence threshold"
    window_s = v["escalation_window_days"] * 86400
    labels = set()
    for case in v["contradiction_cases"]:
        labels.add(case["label"])
        got = _contradiction_outcome(v, case)
        want = (case["closes_at_height"], case["confirmed"],
                case["independent_consistent_pair"], case["contradicted"])
        assert got == want, f"{case['label']}: recomputed {got}, vector says {want}"
        establishing = case["establishing_height"]
        assert establishing == (case["closes_at_height"] if case["contradicted"] else None), \
            f"{case['label']}: a contradiction is dated where the extension closes"
        est_s = None if establishing is None else next(
            b["sealed_at_s"] for b in v["contradiction_blocks"] if b["height"] == establishing)
        for probe in case["escalation_at"]:
            expect = (establishing is not None and establishing <= probe["height"]
                      and probe["sealed_at_s"] - est_s < window_s)
            assert expect == probe["in_force"], \
                f"{case['label']} at {probe['height']}: recomputed {expect}, vector says {probe['in_force']}"
    for needed in ("two independent consistent inside the window", "confirmed inside the window",
                   "consistent pair not independent", "second consistent after the window",
                   "consistent exactly at the window end",
                   "confirming record exactly at the window end",
                   "confirming record one block past the window",
                   "rationed out trigger cannot be contradicted", "consistent sealed in b1 counts"):
        assert needed in labels, f"vector lacks the {needed} case"
    contradicted = [c for c in v["contradiction_cases"] if c["contradicted"]]
    assert contradicted and any(p["in_force"] for c in contradicted for p in c["escalation_at"]) \
        and any(not p["in_force"] for c in contradicted for p in c["escalation_at"]), \
        "no case shows escalation both in force and aged out"
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    for marker in ("The extension closes at the first Block whose `sealed_at` is more than "
                   "its fixed window after *B₁*.",
                   "`domain(d)` is under **escalated sampling**",
                   "no mark on the filer"):
        assert marker in prose, f"§4 does not state: {marker!r}"
    assert "contradictions_max" not in prose, "§4 or §9 still names the retired divergence threshold"
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    assert "contradictions_max" not in json.dumps(schema), "the schema still lists contradictions_max"
check("vectors:wist4-contradiction", _dc4_contradiction)

def _dc4_contradiction_twin():
    """The check above must notice a window read endpoint-exclusive, in both
    directions: a consistent Record at the endpoint stops counting, and a
    confirming Record at the endpoint stops confirming."""
    v = _extension_vector()
    at_end = next(c for c in v["contradiction_cases"]
                  if c["label"] == "consistent exactly at the window end")
    assert _contradiction_outcome(v, at_end, endpoint_inclusive=False)[3] is False \
        and at_end["contradicted"] is True, "recomputation is blind to the window's endpoint"
    confirming = next(c for c in v["contradiction_cases"]
                      if c["label"] == "confirming record exactly at the window end")
    assert _contradiction_outcome(v, confirming, endpoint_inclusive=False)[3] is True \
        and confirming["contradicted"] is False, "recomputation is blind to a confirmation at the endpoint"
    rationed = next(c for c in v["contradiction_cases"]
                    if c["label"] == "rationed out trigger cannot be contradicted")
    assert _contradiction_outcome(v, dict(rationed, summoned=True))[3] is True, \
        "recomputation is blind to whether the trigger summoned"
check("negative:wist4-contradiction", _dc4_contradiction_twin)

def _extension_window_sum(case):
    return ((case["confirm_window_hours"] // 2) * 3600
            + case["record_seal_blocks"] * case["block_cadence_seconds"])

def _latest_extension_seal(case):
    """The fact the §9 sum stands for: on a fully sealed grid, the Record
    published at the extension deadline seals at the record_seal_blocks-th
    Block after the pull, the next Block being the first."""
    cadence = case["block_cadence_seconds"]
    deadline = (case["confirm_window_hours"] // 2) * 3600
    return (deadline // cadence + 1) * cadence + (case["record_seal_blocks"] - 1) * cadence

def _dc4_extension_window():
    """WIST-4 §9: the sum that keeps an extension Record sealable inside the
    confirmation window it serves."""
    v = _countability_vector()
    labels = set()
    for case in v["extension_window_cases"]:
        labels.add(case["label"])
        total = _extension_window_sum(case)
        assert total == case["sum_s"], f"{case['label']}: recomputed sum {total}"
        assert case["window_s"] == case["confirm_window_hours"] * 3600
        assert (total <= case["window_s"]) == case["rule_holds"], \
            f"{case['label']}: the rule's verdict disagrees with the vector"
        latest = _latest_extension_seal(case)
        assert latest == case["latest_seal_s"], f"{case['label']}: recomputed latest seal {latest}"
        assert (latest <= case["window_s"]) == case["seals_inside_window"]
        if case["extension_deadline_s"] % case["block_cadence_seconds"] == 0:
            assert case["rule_holds"] == case["seals_inside_window"], \
                f"{case['label']}: the rule and the seal part on the grid"
        else:
            assert not case["rule_holds"] or case["seals_inside_window"], \
                f"{case['label']}: the rule admits a Record that seals late"
    for needed in ("registry defaults", "cadence at the tables maximum",
                   "the last seal deadline the rule admits", "one block past it",
                   "a deadline between two blocks"):
        assert needed in labels, f"vector lacks the {needed} case"
    maxed = next(c for c in v["extension_window_cases"]
                 if c["block_cadence_seconds"] == _cadence_upper_bound())
    assert not maxed["rule_holds"] and not maxed["seals_inside_window"], \
        "the vector no longer shows the cadence ceiling defeating the extension rule"
    prose = re.sub(r"\s+", " ", _wist4_section9())
    for marker in ("`confirm_window_hours / 2` × 3600 + `record_seal_blocks` × "
                   "`block_cadence_seconds` MUST NOT exceed `confirm_window_hours` × 3600",):
        assert marker in prose, f"§9 does not state: {marker!r}"
    w4 = re.sub(r"\s+", " ",
                (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    assert "MUST also fetch that path once the extension deadline passes and before it seals its next Block" in w4, \
        "§4 does not require the extension pull"
check("vectors:wist4-extension-window", _dc4_extension_window)

def _dc4_extension_window_twin():
    """The check above must notice a bound written strictly instead of at
    the endpoint, and one that leaves record_seal_blocks out."""
    v = _countability_vector()
    boundary = next(c for c in v["extension_window_cases"] if c["sum_s"] == c["window_s"])
    assert boundary["rule_holds"] and boundary["seals_inside_window"], \
        "the boundary case no longer sits where the two readings part"
    assert (boundary["sum_s"] < boundary["window_s"]) != boundary["rule_holds"], \
        "a strict bound rejects a parameter set under which the Record seals in time"
    late = next(c for c in v["extension_window_cases"] if c["label"] == "one block past it")
    assert (late["confirm_window_hours"] // 2) * 3600 <= late["window_s"] and not late["rule_holds"], \
        "the twin's missing term no longer changes the verdict"
check("negative:wist4-extension-window", _dc4_extension_window_twin)

def _sanctions_vector():
    return json.loads((ROOT / "vectors" / "wist4" / "sanctions.json").read_text())

def _sanction_void_at(v, case, service_inside_window=None):
    """WIST-4 §7: when a level-3/4 state voids on recomputation — nothing by
    T, a ruling deadline lapsing, an overturned ruling — read from Block
    sealed_at values alone. `service_inside_window` is the ruled-out
    reading under which an appeal sealed by T discharges it only if the
    file was served inside the window, an instant no Log carries."""
    day = 86400
    notice = case["notice_sealed_at_s"]
    if notice is None:
        return None
    window_close = notice + v["appeal_window_days"] * day
    t = window_close + v["appeal_seal_days"] * day
    appeal = case["appeal_sealed_at_s"]
    appeal_by_t = appeal if appeal is not None and appeal <= t else None
    if service_inside_window is not None and appeal_by_t is not None and not service_inside_window:
        appeal_by_t = None
    ruling = case["ruling"]
    valid_unappealed = ruling is not None and ruling[0] == "unappealed" and window_close <= ruling[1] <= t
    if appeal_by_t is None and not valid_unappealed:
        return t
    if appeal_by_t is None:
        return None
    due = appeal_by_t + v["ruling_deadline_days"] * day
    if ruling is not None and ruling[1] <= due:
        if ruling[0] == "overturned":
            return ruling[1]
        if ruling[0] == "upheld":
            return None
    return due

def _process_prefix(process, case, n_s, reverse=False):
    notice = case.get("notice", process["notice"])["update"]
    if notice["details"]["kind"] != "sanction":
        return {"appeal_index": None, "merits_index": None, "unappealed_index": None, "void_at_s": None}
    notice_id = "sha256:" + hashlib.sha256(rfc8785.dumps(notice)).hexdigest()
    start = process["notice_sealed_at_s"]
    t = start + 21 * 86400
    slots, seen = {}, set()
    groups = collections.defaultdict(list)
    for i, act in enumerate(case["acts"]):
        if start <= act["sealed_at_s"] <= n_s:
            groups[act["sealed_at_s"]].append((i, act["envelope"]["update"]))
    for instant in sorted(groups):
        unseen = []
        for i, inner in sorted(groups[instant], reverse=reverse):
            rid = hashlib.sha256(rfc8785.dumps(inner)).digest()
            if rid in seen:
                continue
            seen.add(rid)
            if (notice["details"]["kind"] == "sanction" and inner["subject"] == notice["subject"]
                    and inner["details"]["notice"] == notice_id):
                unseen.append((i, inner))
        proposals = [e for e in unseen if e[1]["action"] == "appeal"]
        if "appeal" not in slots and len(proposals) == 1:
            slots["appeal"] = (proposals[0][0], instant, proposals[0][1])
        appeal = slots.get("appeal")
        timely = appeal is not None and appeal[1] <= t
        for slot in ("merits", "unappealed"):
            if slot in slots:
                continue
            candidates = []
            for i, inner in unseen:
                if inner["action"] != "appeal_ruling":
                    continue
                outcome = inner["details"]["outcome"]
                eligible = (outcome in ("upheld", "overturned") and timely
                            and instant <= appeal[1] + 30 * 86400) if slot == "merits" else (
                            outcome == "unappealed" and start + 14 * 86400 <= instant <= t and not timely)
                if eligible:
                    candidates.append((i, instant, inner))
            if len(candidates) == 1:
                slots[slot] = candidates[0]
    appeal = slots.get("appeal")
    merits = slots.get("merits")
    void = None
    if appeal is None or appeal[1] > t:
        if "unappealed" not in slots and n_s >= t:
            void = t
    elif merits is not None:
        if merits[2]["details"]["outcome"] == "overturned":
            void = merits[1]
    elif n_s >= appeal[1] + 30 * 86400:
        void = appeal[1] + 30 * 86400
    return {name + "_index": slots[name][0] if name in slots else None
            for name in ("appeal", "merits", "unappealed")} | {"void_at_s": void}

def _dc4_appeal_process():
    process = _sanctions_vector()["process"]
    pub = Ed25519PublicKey.from_public_bytes(b64u_decode(process["public_key"]))
    validator = Draft202012Validator(json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text()))
    for envelope in [process["notice"]] + [c["notice"] for c in process["cases"] if "notice" in c] + [a["envelope"] for c in process["cases"] for a in c["acts"]]:
        validator.validate(envelope)
        pub.verify(b64u_decode(envelope["sig"]["value"]), rfc8785.dumps(envelope["update"]))
    for case in process["cases"]:
        for probe in case["probes"]:
            assert _process_prefix(process, case, probe["n_s"]) == probe["expected"], case["label"]
check("vectors:wist4-appeal-process", _dc4_appeal_process)

def _dc4_appeal_process_twin():
    process = _sanctions_vector()["process"]
    for case in process["cases"]:
        for probe in case["probes"]:
            reversed_result = _process_prefix(process, case, probe["n_s"], reverse=True)
            for slot in ("appeal", "merits", "unappealed"):
                key = slot + "_index"
                actual, expected = reversed_result[key], probe["expected"][key]
                if actual != expected:
                    assert actual is not None and expected is not None
                    assert case["acts"][actual]["envelope"]["update"] == case["acts"][expected]["envelope"]["update"]
            assert reversed_result["void_at_s"] == probe["expected"]["void_at_s"]
    conflict = next(c for c in process["cases"] if c["label"] == "same Block conflicting rulings both rejected")
    assert conflict["probes"][-1]["expected"]["merits_index"] is None
    assert conflict["probes"][-1]["expected"]["void_at_s"] == 31 * 86400
check("negative:wist4-appeal-process", _dc4_appeal_process_twin)

def _dc4_sanction_voids():
    """WIST-4 §7: the void instants of a level-3/4 state, recomputed from the
    notice, the appeal's Block and the ruling."""
    v = _sanctions_vector()
    labels = set()
    for case in v["void_cases"]:
        labels.add(case["label"])
        assert _sanction_void_at(v, case) == case["void_at_s"], f"{case['label']}: void instant"
    for needed in ("appeal sealed at t discharges", "appeal sealed after the window by t discharges",
                   "appeal after t does not discharge", "early unappealed is absent"):
        assert needed in labels, f"vector lacks the {needed} case"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    for marker in ("**Recomputation reads the Block, never the service.**",
                   "An `appeal` sealed in a Block whose `sealed_at` is at or before T discharges T"):
        assert marker in prose, f"§7 does not state: {marker!r}"
check("vectors:wist4-sanction-voids", _dc4_sanction_voids)

def _dc4_sanction_voids_twin():
    """The check above must notice a discharge conditioned on the service
    instant, which the Log does not carry."""
    v = _sanctions_vector()
    late = next(c for c in v["void_cases"] if c["label"] == "appeal sealed after the window by t discharges")
    day = 86400
    t = late["notice_sealed_at_s"] + (v["appeal_window_days"] + v["appeal_seal_days"]) * day
    assert _sanction_void_at(v, late, service_inside_window=False) == t != late["void_at_s"], \
        "recomputation is blind to a service-time condition"
check("negative:wist4-sanction-voids", _dc4_sanction_voids_twin)

def _ladder_levels_from_findings(v, findings, lifts, lift_erases_findings=False):
    """WIST-4 §7 rung derivation from findings and lifts, recomputed
    independently of the generator: count criteria over whole-day windows
    ending at each finding, level 3 on any severity 3, level 4 by the
    three-severity-3 count or by accrual on a level-3 domain, and a lift
    clearing every rung at its instant while leaving every finding counted."""
    esc = v["escalation"]
    def met(count, span_days, min_sev):
        out = []
        for k, f in enumerate(findings):
            if f["severity"] < min_sev:
                continue
            earlier = [g for g in findings[:k + 1] if g["severity"] >= min_sev
                       and (span_days is None
                            or (f["sealed_at_s"] - g["sealed_at_s"]) // 86400 < span_days)]
            if lift_erases_findings:
                last_lift = max((l for l in lifts if l <= f["sealed_at_s"]), default=None)
                if last_lift is not None:
                    earlier = [g for g in earlier if g["sealed_at_s"] > last_lift]
            if len(earlier) >= count:
                out.append(f["sealed_at_s"])
        return out
    def in_force_before(times, t):
        last_met = max((m for m in times if m < t), default=None)
        last_clear = max((c for c in lifts if c < t), default=None)
        return last_met is not None and (last_clear is None or last_clear < last_met)
    l1 = met(1, None, 0)
    l2 = met(esc["l2"]["count"], esc["l2"]["days"], 0)
    l3 = sorted(set(met(esc["l3_count"]["count"], esc["l3_count"]["days"], 0)
                    + met(1, None, esc["l3_severity"])))
    l4_count = met(esc["l4_sev3"]["count"], esc["l4_sev3"]["days"], esc["l3_severity"])
    l4_accrual = [f["sealed_at_s"] for f in findings if in_force_before(l3, f["sealed_at_s"])]
    levels = [l1, l2, l3, sorted(set(l4_count + l4_accrual))]
    def level_at(n_s):
        for i in range(3, -1, -1):
            last_met = max((m for m in levels[i] if m <= n_s), default=None)
            last_clear = max((c for c in lifts if c <= n_s), default=None)
            if last_met is not None and (last_clear is None or last_clear < last_met):
                return i + 1
        return 0
    return levels, l4_count, l4_accrual, level_at

def _transition_rungs(case, expiry=False, lift_after=False):
    raised, cleared, findings, outputs = {}, {}, [], []
    for block in case["blocks"]:
        clear = (block["height"], -1)
        for level in range(1, 5):
            if block["lift"] and not lift_after or level in block["void_levels"]:
                cleared[level] = clear
        for f in sorted(block["findings"], key=lambda f: f["entry_index"]):
            pos = (block["height"], f["entry_index"])
            had_three = raised.get(3, (-1, -1)) > cleared.get(3, (-1, -1))
            findings.append((block["sealed_at_s"], f["severity"]))
            total = sum(0 <= block["sealed_at_s"] - t < 90 * 86400 for t, severity in findings)
            severe = sum(severity == 3 and 0 <= block["sealed_at_s"] - t < 180 * 86400 for t, severity in findings)
            predicates = (True, total >= 3, total >= 10 or f["severity"] == 3,
                          had_three or f["severity"] == 3 and severe >= 3)
            for level, met in enumerate(predicates, 1):
                if met:
                    raised[level] = pos
        if block["lift"] and lift_after:
            for level in range(1, 5):
                cleared[level] = (block["height"], 10**9)
        active = [level for level in range(1, 5)
                  if raised.get(level, (-1, -1)) > cleared.get(level, (-1, -1))]
        if expiry and sum(0 <= block["sealed_at_s"] - t < 90 * 86400 for t, severity in findings) < 3:
            active = [level for level in active if level != 2]
        outputs.append(active)
    return outputs

def _dc4_sanction_transitions():
    for case in _sanctions_vector()["transition_cases"]:
        active = _transition_rungs(case)
        assert active == case["active_rungs"], case["label"]
        assert [max(a, default=0) for a in active] == case["levels"], case["label"]
check("vectors:wist4-sanction-transitions", _dc4_sanction_transitions)

def _dc4_retired_escalations():
    v = _sanctions_vector()
    schema = json.loads((ROOT / "schemas/registry-update.schema.json").read_text())
    validator = Draft202012Validator(schema)
    key = Ed25519PublicKey.from_public_bytes(b64u_decode(v["process"]["public_key"]))
    for case in v["retired_escalation_cases"]:
        doc = case["envelope"]
        key.verify(b64u_decode(doc["sig"]["value"]), rfc8785.dumps(doc["update"]))
        assert list(validator.iter_errors(doc)) and case["error"] == "WIST4-E03"
        assert _transition_rungs(case) == case["active_rungs"], case["label"]
        valid = copy.deepcopy(doc)
        valid["update"]["details"] = {"parameter": "confirm_auditors", "value": 2}
        validator.validate(valid)
    assert v["retired_escalation_cases"][0]["levels"] == [1, 1, 2]
check("vectors:wist4-retired-escalations", _dc4_retired_escalations)

def _dc4_sanction_transitions_twin():
    cases = _sanctions_vector()["transition_cases"]
    aging = next(c for c in cases if c["label"] == "level two survives evidence aging")
    same = next(c for c in cases if c["label"] == "lift precedes same Block finding")
    assert _transition_rungs(aging, expiry=True) != aging["active_rungs"]
    assert _transition_rungs(same, lift_after=True) != same["active_rungs"]
check("negative:wist4-sanction-transitions", _dc4_sanction_transitions_twin)

def _dc4_ladder_reversals():
    """WIST-4 §7: a lift clears rungs and never findings, and level 4's
    three-severity-3 branch is first to fire only across reversals."""
    v = _sanctions_vector()
    labels = set()
    for case in v["reversal_cases"]:
        labels.add(case["label"])
        levels, l4_count, l4_accrual, level_at = _ladder_levels_from_findings(
            v, case["findings"], case["lift_times_s"])
        assert levels == case["met_times_s"], f"{case['label']}: recomputed met times {levels}"
        assert l4_count == case["l4_count_branch_times_s"]
        assert l4_accrual == case["l4_accrual_branch_times_s"]
        for probe in case["probes"]:
            got = level_at(probe["n_s"])
            assert got == probe["level"], \
                f"{case['label']} at {probe['n_s']}: recomputed level {got}, vector says {probe['level']}"
    for needed in ("three severity 3 across two lifts reach level 4 by the count branch",
                   "without the lifts the second finding reaches level 4 by accrual",
                   "a lift clears rungs not findings"):
        assert needed in labels, f"vector lacks the {needed} case"
    across = next(c for c in v["reversal_cases"] if "across two lifts" in c["label"])
    assert across["l4_accrual_branch_times_s"] == [] and across["l4_count_branch_times_s"], \
        "the count branch is no longer the only path to level 4 in the reversal case"
    assert any(p["level"] == 4 for p in across["probes"])
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    for marker in ("A lift clears rungs, never findings",
                   "a third severity-3 finding is the first to meet that branch only where "
                   "the level-3 state was cleared in between"):
        assert marker in prose, f"§7 does not state: {marker!r}"
check("vectors:wist4-ladder-reversals", _dc4_ladder_reversals)

def _dc4_ladder_reversals_twin():
    """The check above must notice a lift read as erasing the findings
    before it, and a ladder without the count branch."""
    v = _sanctions_vector()
    case = next(c for c in v["reversal_cases"] if c["label"] == "a lift clears rungs not findings")
    _, _, _, level_at = _ladder_levels_from_findings(
        v, case["findings"], case["lift_times_s"], lift_erases_findings=True)
    last = case["probes"][-1]
    assert level_at(last["n_s"]) != last["level"], \
        "recomputation is blind to whether a lift erases findings"
    across = next(c for c in v["reversal_cases"] if "across two lifts" in c["label"])
    levels, _, l4_accrual, _ = _ladder_levels_from_findings(
        v, across["findings"], across["lift_times_s"])
    without_count = [levels[0], levels[1], levels[2], sorted(l4_accrual)]
    def level_without_count(n_s):
        for i in range(3, -1, -1):
            last_met = max((m for m in without_count[i] if m <= n_s), default=None)
            last_clear = max((c for c in across["lift_times_s"] if c <= n_s), default=None)
            if last_met is not None and (last_clear is None or last_clear < last_met):
                return i + 1
        return 0
    final = across["probes"][-1]
    assert level_without_count(final["n_s"]) != final["level"], \
        "recomputation is blind to the three-severity-3 branch"
check("negative:wist4-ladder-reversals", _dc4_ladder_reversals_twin)

def _canary_vector():
    return json.loads((ROOT / "vectors" / "wist4" / "canary.json").read_text())

def _canary_credit(key, body, auditor_id, append_signer=True):
    msg = body + (auditor_id.encode() if append_signer else b"")
    return "hmac-sha256:" + hmac.new(key, msg, hashlib.sha256).hexdigest()

def _canary_root_from_path(leaf, index, size, path):
    """WIST-3 §4's fn/sn walk over a canary leaf's Inclusion Proof — the
    verifier's algorithm, not the generator's PATH construction."""
    h = leaf
    fn, sn, k = index, size - 1, 0
    while sn > 0:
        if fn % 2 == 1:
            h = hashlib.sha256(b"\x01" + path[k] + h).digest(); k += 1
        elif fn < sn:
            h = hashlib.sha256(b"\x01" + h + path[k]).digest(); k += 1
        fn //= 2; sn //= 2
    assert k == len(path), "path elements left unconsumed"
    return h

def _canary_membership(commitment, envelope):
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    if list(Draft202012Validator(schema).iter_errors(envelope)):
        return False
    details = envelope["update"]["details"]
    expected_id = "sha256:" + hashlib.sha256(rfc8785.dumps(commitment["update"])).hexdigest()
    if details["commitment"] != expected_id:
        return False
    tree = commitment["update"]["details"]
    seen = set()
    for leaf in details["leaves"]:
        index = leaf["index"]
        if not 0 <= index < tree["leaves"] or index in seen:
            return False
        seen.add(index)
        try:
            root = _canary_root_from_path(bytes.fromhex(leaf["leaf_hash"][7:]),
                                         index, tree["leaves"],
                                         [bytes.fromhex(h[7:]) for h in leaf["path"]])
        except (AssertionError, IndexError):
            return False
        if "sha256:" + root.hex() != tree["root"]:
            return False
    return True

def _dc4_canary_membership():
    v = _canary_vector()["membership"]
    pub = Ed25519PublicKey.from_public_bytes(b64u_decode(v["public_key"]))
    commitment = v["commitment_envelope"]
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    Draft202012Validator(schema).validate(commitment)
    for envelope in [commitment] + [c["envelope"] for c in v["cases"]]:
        pub.verify(b64u_decode(envelope["sig"]["value"]), rfc8785.dumps(envelope["update"]))
    for case in v["cases"]:
        valid = _canary_membership(commitment, case["envelope"])
        assert valid == case["membership_valid"], case["label"]
        assert case["error"] == (None if valid else "WIST4-E08"), case["label"]
check("vectors:wist4-canary-membership", _dc4_canary_membership)

def _dc4_canary_membership_twin():
    v = _canary_vector()["membership"]
    good = next(c["envelope"] for c in v["cases"] if c["membership_valid"])
    bad = copy.deepcopy(good)
    for leaf in bad["update"]["details"]["leaves"]:
        leaf["leaf_hash"] = v["commitment_envelope"]["update"]["details"]["root"]
    assert not _canary_membership(v["commitment_envelope"], bad)
    assert any(not c["membership_valid"] and
               not list(Draft202012Validator(json.loads((ROOT / "schemas" /
                   "registry-update.schema.json").read_text())).iter_errors(c["envelope"]))
               for c in v["cases"])
check("negative:wist4-canary-membership", _dc4_canary_membership_twin)

def _canary_band(v, similarity):
    p = v["parameters"]
    if similarity >= p["similarity_consistent"]:
        return "consistent"
    if similarity >= p["similarity_variance_floor"]:
        return "dynamic_variance"
    return "inconsistent"

def _canary_hard_hit(v, reproduces, verdict, derived, bands_apart=2):
    p = v["parameters"]
    if not reproduces or derived is None:
        return False
    if bands_apart == 2:
        return ((verdict == "consistent" and derived < p["similarity_variance_floor"])
                or (verdict == "inconsistent" and derived >= p["similarity_consistent"]))
    return verdict != _canary_band(v, derived) and verdict in ("consistent", "inconsistent")

def _canary_timing(v, case, literal_rotation=False):
    p = v["parameters"]
    turns = -(-case["suffixes_registered"] // p["observer_checkpoint_budget"])
    rotation = ((turns if literal_rotation else max(turns, 1)) - 1) * p["epoch_blocks"]
    earliest = max(case["delta_heights"]) + p["canary_reveal_min_blocks"] + rotation
    latest = case["commitment_height"] + p["canary_lifetime_blocks"]
    lead_ok = all(h >= case["commitment_height"] + p["canary_lead_blocks"] for h in case["delta_heights"])
    return earliest, latest, lead_ok, lead_ok and earliest <= case["reveal_height"] <= latest

def _canary_window_open(case, end_inclusive_start_exclusive=True):
    """WIST-4 §5.1: the scoring window is open at N while the whole days from
    the reveal's Block to N are fewer than payload_window_days."""
    span = case["n_sealed_at_s"] - case["reveal_sealed_at_s"]
    if span < 0:
        return False
    whole = span // 86400
    return whole < case["payload_window_days"] if end_inclusive_start_exclusive \
        else whole <= case["payload_window_days"]

def _dc4_canary():
    import link_extraction
    """WIST-4 §5.1, §5.2: leaves hash to the committed root under their
    nonces, credit is byte possession bound to the signer, the hard hit is a
    verdict two bands from the bytes, the reveal timing composes with the
    checkpoint budget, and the scoreboard counts per tier."""
    v = _canary_vector()
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    salt = b64u_decode(payload["salt"])
    assert v["reference_extract"] == payload["content"]["extract"], "the leaves are not measured against the example Payload"
    size = v["commitment"]["leaves"]
    root = bytes.fromhex(v["commitment"]["root"].split(":")[1])
    bodies, nonces = {}, set()
    for leaf in v["leaves"]:
        body = bytes.fromhex(leaf["served_bytes_hex"])
        bodies[leaf["index"]] = body
        nonce = bytes.fromhex(leaf["nonce_hex"])
        assert len(nonce) >= 16 and nonce not in nonces and nonce.hex().encode() in body, \
            f"leaf {leaf['index']}: nonce absent, short or reused"
        nonces.add(nonce)
        lh = hashlib.sha256(b"\x00" + body).digest()
        assert "sha256:" + lh.hex() == leaf["leaf_hash"], f"leaf {leaf['index']}: leaf hash"
        if not leaf["revealed"]:
            assert "path" not in leaf and "delta_id" not in leaf
            continue
        path = [bytes.fromhex(p.split(":")[1]) for p in leaf["path"]]
        assert _canary_root_from_path(lh, leaf["index"], size, path) == root, \
            f"leaf {leaf['index']}: inclusion proof does not reach the root"
        observed = link_extraction.extract_text(body)
        sim = link_extraction.similarity(v["reference_extract"], observed,
                                         v["parameters"]["min_observed_words"])
        assert sim == leaf["derived_similarity"], f"leaf {leaf['index']}: recomputed similarity {sim}"
        if sim is None:
            assert leaf["derived_verdict"] == "not_auditable", f"leaf {leaf['index']}: no band, no verdict but not_auditable"
        else:
            assert _canary_band(v, sim) == leaf["derived_verdict"]
        if leaf["class"] == "watermark":
            assert sim == 1_000_000 and link_extraction.extract_text(body) == \
                link_extraction.extract_text(bytes.fromhex(v["payload_page_hex"])), \
                "a watermark must leave the extracted text untouched"
        tier = ("provisional" if leaf["domain_provisional"] else
                "mature" if leaf["domain_reputation_u"] >= v["parameters"]["latency_threshold_u"]
                else "standing")
        assert tier == leaf["tier"], f"leaf {leaf['index']}: tier"
    assert {l["class"] for l in v["leaves"]} == {"watermark", "fraud", "dynamic", "unrevealed", "thin"}
    bound = [l["delta_id"] for l in v["leaves"] if l["revealed"]]
    assert len(bound) == len(set(bound)), "a Delta is bound to two leaves"
    recomputed, labels = set(), set()
    other_salt = bytes(b ^ 0x01 for b in salt)
    for case in v["credit_cases"]:
        labels.add(case["label"])
        leaf = next(l for l in v["leaves"] if l["index"] == case["leaf_index"])
        held = {"leaf": bodies[case["leaf_index"]],
                "payload_page": bytes.fromhex(v["payload_page_hex"])}.get(case["held"])
        key = salt if case["salt"] == "reference" else other_salt
        if case["held"] is None:
            # §5: a not_auditable Record carries no commitment — an encounter
            # without credit, and nothing for a hit to read.
            assert case["verdict"] == "not_auditable" and case["credit_commitment"] is None \
                and case["response_commitment"] is None, f"{case['label']}: a neutral Record commits to nothing"
            assert case["reproduces"] is False and case["hard_hit"] is False
            assert leaf["derived_similarity"] is None, f"{case['label']}: the honest verdict below the guard"
            continue
        if case["held"] == "other_nonce":
            # Bytes the vector does not carry: the sealed value must simply
            # fail to reproduce over the leaf and must not equal any leaf value.
            assert case["credit_commitment"] != _canary_credit(salt, bodies[case["leaf_index"]], case["auditor_id"])
            assert case["reproduces"] is False and case["hard_hit"] is False
            continue
        signer = case["copied_from"] or case["auditor_id"]
        sealed = _canary_credit(key, held, signer)
        assert sealed == case["credit_commitment"], f"{case['label']}: sealed credit"
        assert "hmac-sha256:" + hmac.new(key, held, hashlib.sha256).hexdigest() == case["response_commitment"]
        recomputed.update({sealed, case["response_commitment"]})
        reproduces = sealed == _canary_credit(salt, bodies[case["leaf_index"]], case["auditor_id"])
        assert reproduces == case["reproduces"], f"{case['label']}: reproduces"
        assert _canary_hard_hit(v, reproduces, case["verdict"], leaf["derived_similarity"]) == case["hard_hit"], \
            f"{case['label']}: hard hit"
    for needed in ("fetcher credits the watermark", "payload bytes earn no credit",
                   "a copied credit value is worthless", "consistent on the fraud leaf is a hard hit",
                   "inconsistent on the fraud leaf credits", "inconsistent on the watermark is a hard hit",
                   "consistent in the buffer band is no hit", "inconsistent in the buffer band is no hit",
                   "a cloaked fetch misses", "the wrong salt reproduces nothing",
                   "a measured verdict on a thin leaf credits and is no hit",
                   "the honest record on a thin leaf is not auditable without credit"):
        assert needed in labels, f"vector lacks the {needed} case"
    thin = next(c for c in v["credit_cases"] if c["label"] == "a measured verdict on a thin leaf credits and is no hit")
    assert thin["reproduces"] and not thin["hard_hit"] and thin["verdict"] == "consistent", \
        "the thin leaf's measured verdict must credit and never hit"
    for case in v["scoring_window_cases"]:
        labels.add(case["label"])
        whole = (case["n_sealed_at_s"] - case["reveal_sealed_at_s"]) // 86400
        assert whole == case["whole_days"], f"{case['label']}: whole days"
        assert case["payload_window_days"] == v["parameters"]["payload_window_days"]
        assert _canary_window_open(case) == case["open"], f"{case['label']}: open"
    for needed in ("open at the reveals own block", "open at the last block inside the window",
                   "lapsed at the first block a whole window later"):
        assert needed in labels, f"vector lacks the {needed} case"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    assert ("it is **open** at a Block N when the whole days (§6.1) from the reveal's Block "
            "`sealed_at` to N's are fewer than `payload_window_days`") in prose, \
        "§5.1 does not fix the scoring window's endpoints"
    for case in v["timing_cases"]:
        got = _canary_timing(v, case)
        want = (case["earliest_reveal_height"], case["latest_reveal_height"],
                case["lead_respected"], case["valid"])
        assert got == want, f"{case['label']}: recomputed {got}, vector says {want}"
    assert any(c["suffixes_registered"] > v["parameters"]["observer_checkpoint_budget"] and c["valid"]
               for c in v["timing_cases"]), "no case shows the rotation term absorbed"
    none = [c for c in v["timing_cases"] if c["suffixes_registered"] == 0]
    one = next(c for c in v["timing_cases"] if c["suffixes_registered"] == 1)
    assert none and all(c["earliest_reveal_height"] == one["earliest_reveal_height"] for c in none), \
        "an empty Observer roster must leave the minimum where one suffix leaves it"
    assert "`(max(⌈S / observer_checkpoint_budget⌉, 1) − 1) × epoch_blocks`" in prose, \
        "§5.1 does not clamp the rotation term at no registered suffix"
    for record in v["scoreboard_records"]:
        if record["held"] is None:
            assert record["credit_commitment"] is None and record["verdict"] in ("unreachable", "not_auditable")
            continue
        held = {"leaf": bodies[record["leaf_index"]], "payload_page": bytes.fromhex(v["payload_page_hex"])}[record["held"]]
        sealed = _canary_credit(salt, held, record["auditor_id"])
        assert sealed == record["credit_commitment"]
        recomputed.add(sealed)
    for auditor_id, board in v["scoreboards"].items():
        mine = {t: [0, 0, 0] for t in ("provisional", "standing", "mature")}
        for record in v["scoreboard_records"]:
            if record["auditor_id"] != auditor_id or not record["fixed_before_reveal"]:
                continue
            leaf = next(l for l in v["leaves"] if l["index"] == record["leaf_index"])
            row = mine[leaf["tier"]]
            reproduces = record["credit_commitment"] is not None and \
                record["credit_commitment"] == _canary_credit(salt, bodies[leaf["index"]], auditor_id)
            row[0] += 1; row[1] += reproduces
            row[2] += _canary_hard_hit(v, reproduces, record["verdict"], leaf["derived_similarity"])
        assert mine == board, f"{auditor_id}: recomputed scoreboard {mine}, vector says {board}"
    # The example Record's credit commitment is the same construction.
    rec = json.loads((ROOT / "examples" / "audit-record.json").read_text())["record"]
    ac = json.loads((ROOT / "vectors" / "wist4" / "audit-commitments.json").read_text())["commitments"]
    body = bytes.fromhex(ac["response_commitment"]["message_hex"])
    assert rec["credit_commitment"] == _canary_credit(salt, body, rec["auditor_id"]), \
        "the example Record's credit_commitment is not salt over body || auditor_id"
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    for marker in ("message = <raw response body> ‖ <auditor_id as UTF-8>",
                   "a hard hit is a verdict two bands from the bytes its signer proved it held",
                   "there is no hard hit on any verdict",
                   "a party recomputing the scoreboard MUST NOT infer one",
                   "`leaf = SHA-256(0x00 ‖ served bytes)`",
                   "https://<domain>/.well-known/wist/canary/<commitment-id-hex>/<index>"):
        assert marker in prose, f"§5.1/§5.2 does not state: {marker!r}"
    covered_values = _locate_values(lambda x: x in recomputed)
    _assert_coverage("vectors:wist4-canary", covered_values, _locate_schema_fields("vectors:wist4-canary"))
check("vectors:wist4-canary", _dc4_canary)

def _dc4_canary_twin():
    """The check above must notice a credit that omits the signer, a hard hit
    read one band away, and a proof under the wrong index."""
    v = _canary_vector()
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    salt = b64u_decode(payload["salt"])
    copier = next(c for c in v["credit_cases"] if c["label"] == "a copied credit value is worthless")
    body = bytes.fromhex(v["leaves"][copier["leaf_index"]]["served_bytes_hex"])
    assert _canary_credit(salt, body, copier["copied_from"], append_signer=False) == \
        _canary_credit(salt, body, copier["auditor_id"], append_signer=False), \
        "without the signer in the message, the twin cannot show the copier being caught"
    assert copier["reproduces"] is False
    buffer = next(c for c in v["credit_cases"] if c["label"] == "consistent in the buffer band is no hit")
    leaf = v["leaves"][buffer["leaf_index"]]
    assert _canary_hard_hit(v, True, buffer["verdict"], leaf["derived_similarity"], bands_apart=1) is True \
        and buffer["hard_hit"] is False, "recomputation is blind to the buffer band"
    size = v["commitment"]["leaves"]
    root = bytes.fromhex(v["commitment"]["root"].split(":")[1])
    revealed = [l for l in v["leaves"] if l["revealed"]]
    a, b = revealed[0], revealed[1]
    lh = bytes.fromhex(a["leaf_hash"].split(":")[1])
    path = [bytes.fromhex(p.split(":")[1]) for p in a["path"]]
    assert _canary_root_from_path(lh, b["index"], size, path) != root, \
        "recomputation is blind to the leaf's index"
    early = next(c for c in v["timing_cases"] if c["label"] == "reveal one block early")
    assert _canary_timing(v, dict(early, reveal_height=early["reveal_height"] + 1))[3] is True
    lapsed = next(c for c in v["scoring_window_cases"]
                  if c["label"] == "lapsed at the first block a whole window later")
    assert _canary_window_open(lapsed, end_inclusive_start_exclusive=False) is True \
        and _canary_window_open(lapsed) is False, \
        "recomputation is blind to the window's closing endpoint"
    empty = next(c for c in v["timing_cases"]
                 if c["label"] == "no observer registered reveal one block early")
    assert _canary_timing(v, empty, literal_rotation=True)[3] is True and _canary_timing(v, empty)[3] is False, \
        "recomputation is blind to the literal minus-one-rotation at no suffix"
    thin = next(l for l in v["leaves"] if l["class"] == "thin")
    assert thin["derived_similarity"] is None and \
        _canary_hard_hit(v, True, "consistent", 0) is True and \
        _canary_hard_hit(v, True, "consistent", thin["derived_similarity"]) is False, \
        "recomputation reads a missing band as the inconsistent band"
check("negative:wist4-canary", _dc4_canary_twin)

def _observer_vector():
    return json.loads((ROOT / "vectors" / "wist4" / "observer-checkpoints.json").read_text())

def _epoch_priority(epoch, name):
    return hashlib.sha256(epoch.to_bytes(8, "big") + name.encode()).hexdigest()

def _suffix_groups(observers):
    groups = {}
    for o in observers:
        groups.setdefault(".".join(o.split(".")[-2:]), []).append(o)
    return groups

def _epoch_budget(observers, epoch, budget, walk=True):
    """WIST-4 §3.1: suffixes in a fixed order by SHA-256(suffix); the epoch's
    window of one budget starts at position epoch × budget mod S; within a
    suffix, the Observer least by SHA-256(be64(epoch) ‖ observer_id).
    `walk=False` is a static queue that never advances, the starving
    reading the section rules out."""
    groups = _suffix_groups(observers)
    order = sorted(groups, key=lambda s: hashlib.sha256(s.encode()).hexdigest())
    size = len(order)
    start = (epoch * budget) % size if (walk and size) else 0
    positions = [(start + k) % size for k in range(min(budget, size))] if size else []
    pick = lambda sfx: min(groups[sfx], key=lambda o: _epoch_priority(epoch, o))
    return order, positions, [pick(order[p]) for p in positions]

def _epoch_budget_rehashed(observers, epoch, budget):
    """The ruled-out reading: an order drawn afresh each epoch."""
    groups = _suffix_groups(observers)
    order = sorted(groups, key=lambda s: _epoch_priority(epoch, s))
    return [min(groups[sfx], key=lambda o: _epoch_priority(epoch, o)) for sfx in order[:budget]]

def _epoch_of_block(v, block, per_first_block=True):
    changes = v["epoch_changes"]
    def in_force(t_s):
        live = [c for c in changes if c["effective_at_s"] <= t_s]
        return max(live, key=lambda c: c["effective_at_s"])["value"] if live else v["epoch_blocks_default"]
    if not per_first_block:
        length = in_force(block * 3600)
        return block // length
    start, index = 0, 0
    while True:
        length = in_force(start * 3600)
        if block < start + length:
            return index
        start += length
        index += 1

def _covered_before(v, item, reveal_height):
    for cp in v["checkpoints"]:
        if cp["height"] >= reveal_height:
            continue
        cursor = cp["head"]
        while cursor is not None:
            if cursor == item:
                return True
            cursor = v["prev_record"][cursor]
    return False

def _dc4_observer_checkpoints():
    """WIST-4 §3.1: the epoch budget's derivable allocation, the epoch a Block
    belongs to, and what a sealed checkpoint fixes before a reveal."""
    v = _observer_vector()
    labels = set()
    for case in v["budget_cases"]:
        labels.add(case["label"])
        suffixes = len(_suffix_groups(case["registered"]))
        assert case["suffixes"] == suffixes
        bound = -(-suffixes // case["budget"]) if suffixes else 0
        assert case["bound_epochs"] == bound, f"{case['label']}: bound"
        for e in case["epochs"]:
            order, positions, chosen = _epoch_budget(case["registered"], e["epoch"], case["budget"])
            assert order == e["suffix_order"], f"{case['label']} epoch {e['epoch']}: suffix order"
            assert positions == e["positions"], f"{case['label']} epoch {e['epoch']}: positions"
            assert chosen == e["budgeted"], f"{case['label']} epoch {e['epoch']}: recomputed {chosen}"
            assert len(chosen) == min(case["budget"], len(order))
            if "budgeted_under_per_epoch_rehash" in e:
                assert _epoch_budget_rehashed(case["registered"], e["epoch"], case["budget"]) == \
                    e["budgeted_under_per_epoch_rehash"], f"{case['label']} epoch {e['epoch']}: rehash reading"
        # The bound: every suffix inside any bound_epochs consecutive epochs.
        first = case["epochs"][0]["epoch"]
        for start in range(first, first + bound):
            seen = set()
            for e in range(start, start + bound):
                seen.update(".".join(o.split(".")[-2:])
                            for o in _epoch_budget(case["registered"], e, case["budget"])[2])
            assert len(seen) == suffixes, f"{case['label']}: a suffix waits past the bound from epoch {start}"
    for needed in ("under budget every suffix budgeted", "over budget rotates across epochs",
                   "a crowd under one suffix shares one slot", "two suffixes and one slot alternate"):
        assert needed in labels, f"vector lacks the {needed} case"
    for case in v["epoch_cases"]:
        got = _epoch_of_block(v, case["block"])
        assert got == case["epoch"], f"block {case['block']}: recomputed epoch {got}"
        assert case["epoch_first_block"] <= case["block"] < case["epoch_first_block"] + case["epoch_length"]
    for case in v["coverage_cases"]:
        for item, fixed in case["fixed_before_reveal"].items():
            assert _covered_before(v, item, case["reveal_height"]) == fixed, \
                f"{case['label']}: {item}"
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    for marker in ("order the S suffixes by ascending octet order of `SHA-256(suffix)`",
                   "`(epoch number × observer_checkpoint_budget + k) mod S`",
                   "across any `⌈S / observer_checkpoint_budget⌉` consecutive epochs at whose first Blocks "
                   "the same S suffixes are registered, every one of them is budgeted at least once",
                   "spans the `epoch_blocks` (Parameter Registry; default 24) in force at its first Block's `sealed_at`",
                   "only if a checkpoint covering it was sealed in a Block below the reveal's"):
        assert marker in prose, f"§3.1 does not state: {marker!r}"
check("vectors:wist4-observer-checkpoints", _dc4_observer_checkpoints)

def _dc4_observer_checkpoints_twin():
    """The check above must notice a static queue and an epoch read from the
    value in force at the Block rather than at the epoch's first Block."""
    v = _observer_vector()
    rotating = next(c for c in v["budget_cases"] if c["label"] == "over budget rotates across epochs")
    suffixes_of = lambda chosen: tuple(".".join(o.split(".")[-2:]) for o in chosen)
    static = {suffixes_of(_epoch_budget(rotating["registered"], e["epoch"], rotating["budget"], walk=False)[2])
              for e in rotating["epochs"]}
    assert len(static) == 1 and len({suffixes_of(e["budgeted"]) for e in rotating["epochs"]}) > 1, \
        "a static order would starve the same suffixes every epoch, and the twin cannot see it"
    alternate = next(c for c in v["budget_cases"] if c["label"] == "two suffixes and one slot alternate")
    rehashed = [e["budgeted_under_per_epoch_rehash"] for e in alternate["epochs"]]
    walked = [e["budgeted"] for e in alternate["epochs"]]
    assert rehashed != walked and len({tuple(r) for r in rehashed[:3]}) == 1, \
        "the ruled-out fresh draw must repeat a winner where the walk alternates"
    assert any(_epoch_of_block(v, c["block"], per_first_block=False) != c["epoch"] for c in v["epoch_cases"]), \
        "recomputation is blind to which Block's value governs an epoch"
    at_height = next(c for c in v["coverage_cases"] if c["label"] == "reveal at the first checkpoints height")
    assert not any(at_height["fixed_before_reveal"].values()), \
        "a checkpoint sealed at the reveal's own height must fix nothing"
check("negative:wist4-observer-checkpoints", _dc4_observer_checkpoints_twin)

def _dc4_observer_and_canary_acts():
    """WIST-4 §3.1, §5.1, §9.1: the four self-signed acts and the admission
    track record validate with their REQUIRED members and fail without them."""
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    validator = Draft202012Validator(schema)
    actions = schema["properties"]["update"]["properties"]["action"]["enum"]
    for a in ("observer_register", "observer_checkpoint", "canary_commitment", "canary_reveal"):
        assert a in actions, f"action enum lacks {a}"
    sig = json.loads((ROOT / "examples" / "registry-update.json").read_text())["sig"]
    canary = _canary_vector()
    leaf = next(l for l in canary["leaves"] if l["revealed"])
    pub = json.loads((ROOT / "examples" / "registry-update.json").read_text())["update"]["details"]["public_key"]
    acts = {
        "observer_register": ("watch.sample.net", {"key_id": "test-obs-k1", "alg": "Ed25519", "public_key": pub}),
        "observer_checkpoint": ("watch.sample.net", {"head": "sha256:" + "0" * 64}),
        "canary_commitment": (canary["planter"], {"root": canary["commitment"]["root"],
                                                  "leaves": canary["commitment"]["leaves"]}),
        "canary_reveal": (canary["canary_domain"], {"commitment": "sha256:" + "1" * 64,
                                                    "leaves": [{"index": leaf["index"], "delta_id": leaf["delta_id"],
                                                                "leaf_hash": leaf["leaf_hash"], "path": leaf["path"]}]}),
    }
    for action, (subject, details) in acts.items():
        doc = {"update": {"wist_version": "1.0.0", "action": action, "subject": subject,
                          "details": details, "effective_at": "2026-08-02T16:00:00Z"}, "sig": sig}
        validator.validate(doc)
        for missing in details:
            bad = copy.deepcopy(doc)
            del bad["update"]["details"][missing]
            assert list(validator.iter_errors(bad)), f"{action} without {missing} validated"
        bad = copy.deepcopy(doc)
        bad["update"]["subject"] = "not a hostname"
        assert list(validator.iter_errors(bad)), f"{action} under a non-hostname subject validated"
    bad = copy.deepcopy(acts["canary_reveal"][1]); bad["leaves"] = []
    doc = {"update": {"wist_version": "1.0.0", "action": "canary_reveal", "subject": canary["canary_domain"],
                      "details": bad, "effective_at": "2026-08-02T16:00:00Z"}, "sig": sig}
    assert list(validator.iter_errors(doc)), "a reveal of no leaves validated"
    admit = json.loads((ROOT / "examples" / "registry-update.json").read_text())
    validator.validate(admit)
    with_record = copy.deepcopy(admit)
    with_record["update"]["details"]["track_record"] = {
        "checkpoint": "sha256:" + "2" * 64,
        "scoreboard": {"provisional": [1, 1, 0], "standing": [1, 1, 1], "mature": [1, 1, 0]}}
    validator.validate(with_record)
    for mutate in (lambda d: d["scoreboard"].pop("mature"),
                   lambda d: d["scoreboard"]["mature"].append(0),
                   lambda d: d.pop("checkpoint"),
                   lambda d: d["scoreboard"].update({"provisional": [1, -1, 0]})):
        bad = copy.deepcopy(with_record)
        mutate(bad["update"]["details"]["track_record"])
        assert list(validator.iter_errors(bad)), "a malformed track_record validated"
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    assert "https://<domain>/.well-known/wist/registry.json" in prose, "§9.1 fixes no submissions path"
    w2 = (ROOT / "specs" / "WIST-2-site-publication.md").read_text()
    assert "/.well-known/wist/registry.json" in w2 and "/.well-known/wist/canary/<c>/<i>" in w2, \
        "WIST-2 §3's layout omits the new paths"
check("schema:wist4-observer-and-canary-acts", _dc4_observer_and_canary_acts)

def _dc4_audit_commitments():
    """Every content-derived value in an Audit Record is salted (WIST-4 §5).

    Moving extracts out of the Log achieves nothing if the Log keeps bare
    digests of the same text: a party holding a copy could recompute one and
    confirm the text was there, which is precisely the confirmability the
    Payload salt exists to destroy. So the Auditor's three content-derived
    values are committed under that same salt, and this recomputes all three
    from their preimages.
    """
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    rec = json.loads((ROOT / "examples" / "audit-record.json").read_text())["record"]
    v = json.loads((ROOT / "vectors" / "wist4" / "audit-commitments.json").read_text())
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
    v = json.loads((ROOT / "vectors" / "wist4" / "audit-commitments.json").read_text())
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

def _reference_vector():
    return json.loads((ROOT / "vectors" / "wist4" / "superseded-audit.json").read_text())

def _reference_recompute(chain, other, case):
    """Independent recomputation of WIST-4 §5's reference_delta rules."""
    ids = [d["id"] for d in chain]
    def sealed(i): return chain[i]["sealed_at_s"]
    tip = None
    for d in chain:
        if d["sealed_at_s"] <= case["fetched_at_s"]:
            tip = d["id"]
    ref, aud = case["reference"], case["audited"]
    if ref not in ids:
        return ("WIST4-E02", tip, None, None, None, None)
    ri, ai = ids.index(ref), ids.index(aud)
    if ri < ai or sealed(ri) > case["fetched_at_s"]:
        return ("WIST4-E02", tip, None, None, None, None)
    change = chain[ri]["change"]
    anchor = next((chain[j]["payload"] for j in range(ri, -1, -1)
                   if chain[j]["change"] in ("new", "update")), None)
    if "similarity" not in case:
        return (True, tip, anchor, change, None, None)
    eff = 1_000_000 - case["similarity"] if change == "delete" else case["similarity"]
    verdict = ("consistent" if eff >= 600_000 else
               "dynamic_variance" if eff >= 300_000 else "inconsistent")
    return (True, tip, anchor, change, verdict,
            verdict == "consistent" and change in ("new", "update"))

def _dc4_superseded_audit():
    """WIST-4 §5: reference_delta, the anchor as of it, and §3's rejections."""
    v = _reference_vector()
    assert v["similarity_consistent"] == 600_000 and v["similarity_variance_floor"] == 300_000
    heights = [d["height"] for d in v["chain"]]
    assert heights == sorted(heights), "chain not in Log order"
    labels = set()
    for case in v["cases"]:
        labels.add(case["label"])
        assert case["record_sealed_at_s"] >= case["fetched_at_s"], case["label"]
        audited_delta = next(d for d in v["chain"] if d["id"] == case["audited"])
        assert case["fetched_at_s"] >= audited_delta["sealed_at_s"], case["label"]
        got = _reference_recompute(v["chain"], v["other_chain"], case)
        exp = (case["valid"], case["expected_reference"], case["resolved_payload"],
               case["reading_change"], case.get("verdict"), case.get("counts_toward_c"))
        assert got == exp, f"{case['label']}: recomputed {got}, vector says {exp}"
        if case["valid"] is True and "similarity" in case:
            assert case["effective_similarity"] == (
                1_000_000 - case["similarity"] if case["reading_change"] == "delete"
                else case["similarity"]), case["label"]
    for needed in ("honest-rewrite", "reactive-truth-after-fetch",
                   "stale-reference-not-decidable", "reference-before-audited",
                   "reference-from-another-chain", "attest-after-rewrite",
                   "boundary-sealed-at-equals-fetched-at"):
        assert needed in labels, f"vector lacks the {needed} case"
    assert len(heights) > len(set(heights)), \
        "the chain shares no Block, so §5's intra-Block tiebreak is unexercised"
    rec = json.loads((ROOT / "examples" / "audit-record.json").read_text())["record"]
    assert rec["reference_delta"] == rec["audited_delta"], \
        "the example chain has one Delta, so its tip is the audited Delta"
    schema = json.loads((ROOT / "schemas" / "audit-record.schema.json").read_text())
    assert "reference_delta" in schema["properties"]["record"]["required"]
check("vectors:wist4-superseded-audit", _dc4_superseded_audit)

def _dc4_superseded_audit_twin():
    """The check above must notice a reference moved one Delta later."""
    v = _reference_vector()
    case = next(c for c in v["cases"] if c["label"] == "honest-rewrite")
    mutated = dict(case, reference="d1")
    got = _reference_recompute(v["chain"], v["other_chain"], mutated)
    assert got[2] == "P1" and got[2] != case["resolved_payload"], \
        "recomputation is blind to the reference"
    mutated = dict(case, fetched_at_s=3_600)
    assert _reference_recompute(v["chain"], v["other_chain"], mutated)[0] == "WIST4-E02", \
        "recomputation is blind to a reference sealed after the fetch"
    delete_case = next(c for c in v["cases"] if c["label"] == "audited-attest-tip-delete")
    mutated = dict(delete_case, similarity=1_000_000)
    got = _reference_recompute(v["chain"], v["other_chain"], mutated)
    assert got[4] == "inconsistent" and got[5] is False, \
        "recomputation is blind to the delete mirror"
check("negative:wist4-superseded-audit", _dc4_superseded_audit_twin)

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
    ("registry-update.schema.json",
     "allOf[15]/then/properties/update/properties/details/properties/leaves/items/properties/leaf_hash"):
        "SHA-256 over served bytes carrying a fresh secret nonce (WIST-4 §5.1)",
    ("registry-update.schema.json",
     "allOf[13]/then/properties/update/properties/details/properties/head"):
        "an Audit Record or coverage_attestation ID — the Observer's chain head (WIST-4 §3.1); objects that carry only commitments",
    ("registry-update.schema.json",
     "allOf[14]/then/properties/update/properties/details/properties/root"):
        "a Merkle root over canary leaves, each SHA-256 over served bytes carrying a fresh nonce no Payload carries — a keyed commitment under the nonce (WIST-4 §5.1, §9.1)",
    ("registry-update.schema.json",
     "allOf[15]/then/properties/update/properties/details/properties/commitment"):
        "a Registry Update ID: SHA-256 over a canary_commitment's inner object, which carries a root and a count (WIST-4 §5.1)",
    ("registry-update.schema.json",
     "allOf[15]/then/properties/update/properties/details/properties/leaves/items/properties/delta_id"):
        "a Delta ID",
    ("registry-update.schema.json",
     "allOf[15]/then/properties/update/properties/details/properties/leaves/items/properties/path/items"):
        "Merkle siblings over canary leaves, each keyed by its leaf's nonce (WIST-4 §5.1, §9.1)",
    ("registry-update.schema.json",
     "allOf[16]/then/properties/update/properties/details/properties/track_record/properties/checkpoint"):
        "a Registry Update ID: SHA-256 over an observer_checkpoint's inner object, which carries a chain-head ID (WIST-4 §3.1)",
    ("snapshot-state.schema.json",
     "properties/state/properties/entries/items/oneOf[12]/prefixItems[1]"):
        "a Registry Update ID (a live canary_commitment's, WIST-3 §7)",
    ("snapshot-state.schema.json",
     "properties/state/properties/entries/items/oneOf[12]/prefixItems[3]"):
        "the canary_commitment's Merkle root over nonce-keyed leaves (WIST-4 §5.1)",
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
    ("audit-record.schema.json", "properties/record/properties/audited_delta"):
        "a Delta ID",
    ("audit-record.schema.json", "properties/record/properties/reference_delta"):
        "a Delta ID",
    ("audit-record.schema.json", "properties/record/properties/prev_record/oneOf[0]"):
        "an Audit Record or coverage_attestation ID: SHA-256 over an object that carries only commitments (WIST-4 §4's per-auditor chain)",
    ("registry-update.schema.json",
     "allOf[9]/then/properties/update/properties/details/properties/block"):
        "SHA-256 of a Block header (the audited Block a pull_attestation names, WIST-4 §4)",
    ("registry-update.schema.json",
     "allOf[9]/then/properties/update/properties/details/properties/found/items"):
        "Audit Record and coverage_attestation IDs a pull returned (WIST-4 §4) — objects that carry only commitments",
    ("registry-update.schema.json",
     "allOf[10]/then/properties/update/properties/details/properties/block"):
        "SHA-256 of a Block header (the Block whose selection was empty, WIST-4 §4)",
    ("registry-update.schema.json",
     "allOf[10]/then/properties/update/properties/details/properties/prev_record/oneOf[0]"):
        "the same per-auditor chain ID an Audit Record's prev_record carries (WIST-4 §4)",
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
    ("snapshot-state.schema.json",
     "properties/state/properties/entries/items/oneOf[4]/prefixItems[3]/items"):
        "Registry Update IDs establishing a sanction_state tuple (WIST-3 §7) — objects that carry only commitments",
    ("snapshot-state.schema.json",
     "properties/state/properties/entries/items/oneOf[8]/prefixItems[5]/items"):
        "counted-URL digests (WIST-3 §7): domain and Normalized URL, both of which the Log carries in the clear; no page content",
    ("snapshot-state.schema.json",
     "properties/state/properties/entries/items/oneOf[9]/prefixItems[3]"):
        "a Delta ID (a record tuple's chain tip, WIST-3 §7)",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/files/items/properties/sha256"):
        "a whole tier file, not any one record (WIST-3 §7); and a manifest is a static artifact, not a Log Entry",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/anchor_block_hash"):
        "SHA-256 of a Block header",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/content_digest"):
        "a digest over the record tuples of WIST-3 §7 — url, publisher, delta_id, observed_at, weight — every one of which the Log already carries in the clear; no page content is in its preimage",
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
}

NON_CONTENT_VALUES = {
    ("vectors/wist4/parameter-combinations.json", "wire_public_key"): "an Ed25519 public key",
    ("vectors/wist4/parameter-combinations.json", "value"): "an Ed25519 signature when opaque",
    ("vectors/wist4/parameter-combinations.json", "parameter"): "a Parameter Registry identifier",
    ("vectors/wist4/sanctions.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist4/sanctions.json", "value"): "an Ed25519 signature",
    ("vectors/wist4/sanctions.json", "notice"): "a Registry Update ID",
    ("vectors/wist4/sanctions.json", "evidence"): "an Audit Record ID",
    ("vectors/wist4/canary.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist4/canary.json", "value"): "an Ed25519 signature",
    ("vectors/wist4/canary.json", "commitment"): "a Registry Update ID over a root and leaf count",
    ("vectors/wist4/canary.json", "root"): "a Merkle root over nonce-keyed canary leaves (WIST-4 §5.1)",
    ("vectors/wist4/canary.json", "leaf_hash"): "SHA-256 over served bytes carrying a fresh nonce (WIST-4 §5.1)",
    ("vectors/wist4/canary.json", "path"): "Merkle siblings over nonce-keyed canary leaves (WIST-4 §5.1)",
    ("vectors/wist4/canary.json", "delta_id"): "a Delta ID",
    ("vectors/wist4/canary.json", "nonce_hex"): "the nonce: from a CSPRNG in production, the unguessable part of a leaf's served bytes (WIST-4 §5.1)",
    ("examples/audit-record.json", "audited_delta"): "a Delta ID",
    ("examples/audit-record.json", "reference_delta"): "a Delta ID",
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
    ("examples/mirrors.json", "value"): "an Ed25519 signature",
    ("examples/log-anchor.json", "value"): "an Ed25519 signature",
    ("examples/payload.json", "salt"): "the salt: from a CSPRNG, never derived from what it keys",
    ("examples/publisher.json", "public_key"): "an Ed25519 public key",
    ("examples/publisher.json", "value"): "an Ed25519 signature",
    ("examples/registry-update.json", "public_key"): "an Ed25519 public key",
    ("examples/registry-update.json", "value"): "an Ed25519 signature",
    ("examples/snapshot-manifest.json", "sha256"): "a whole tier file, not any one record (WIST-3 §7)",
    ("examples/snapshot-manifest.json", "anchor_block_hash"): "SHA-256 of a Block header",
    ("examples/snapshot-manifest.json", "content_digest"):
        "WIST-3 §7's record-tuple digest: url, publisher, delta_id, observed_at, weight — no content in the preimage",
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
    ("vectors/wist3/empty-block.json", "prev_block_hash"): "SHA-256 of a Block header",
    ("vectors/wist3/empty-block.json", "block_hash"): "SHA-256 of a Block header",
    ("vectors/wist3/empty-block.json", "merkle_root"):
        "the empty tree's root, SHA-256(0x00) — no Entry, and therefore no content, in its preimage (WIST-3 §4)",
    ("vectors/wist3/empty-block.json", "rfc6962_empty_root"):
        "the RFC 6962 empty-tree constant this suite deviates from, published so the deviation is checkable (WIST-3 §4)",
    ("vectors/wist3/empty-block.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/inclusion-proof.json", "path"): "Merkle sibling hashes over Entries",
    ("vectors/wist4/sampling.json", "block_hash"): "SHA-256 of a Block header",
    ("vectors/wist4/sampling.json", "alpha_hex"): "the Block Hash's raw octets, the VRF input",
    ("vectors/wist4/sampling.json", "beta_hex"): "the VRF output",
        ("vectors/wist4/sampling.json", "delta_id"): "a Delta ID",
    ("vectors/wist4/sampling.json", "auditor_public_key"): "an Ed25519 public key",
    ("vectors/wist4/extension-proof.json", "block_hash"): "SHA-256 of a Block header",
    ("vectors/wist4/extension-proof.json", "alpha_hex"): "the Block Hash's raw octets, the VRF input",
    ("vectors/wist4/extension-proof.json", "audited_delta"): "a Delta ID",
    ("vectors/wist4/extension-proof.json", "auditor_public_key"): "an Ed25519 public key",
    ("vectors/wist4/extension-proof.json", "rotated_public_key"): "an Ed25519 public key",
    ("vectors/wist4/extension-proof.json", "audited_block"): "the Ed25519 public key the Auditor held at the audited Block",
    ("vectors/wist4/extension-proof.json", "trigger_block"): "the Ed25519 public key the Auditor held at B₁",
    ("vectors/multilog/dedup.json", "block_hash"): "SHA-256 of a Block header",
    ("vectors/multilog/dedup.json", "prev_block_hash"): "SHA-256 of a Block header",
    ("vectors/multilog/dedup.json", "merkle_root"): "root over Entries, which carry commitments only",
    ("vectors/multilog/dedup.json", "delta_id"): "a Delta ID",
    ("vectors/multilog/dedup.json", "public_key"): "an Ed25519 public key",
    ("vectors/multilog/dedup.json", "value"): "an Ed25519 signature",
    ("vectors/multilog/dedup.json", "salt"): "the salt: from a CSPRNG, never derived from what it keys",
    ("vectors/multilog/dedup.json", "genesis_seed_hex"): "the vector's test signing seed",
    ("vectors/wist1/declaration-sequence.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/ed25519-strictness.json", "public_key_hex"):
        "an Ed25519 public key (WIST-1 §4's verification profile), canonical, non-canonical and small-order alike",
    ("vectors/wist1/ed25519-strictness.json", "signature_hex"):
        "an Ed25519 signature over this vector's own published message",
    ("vectors/wist1/declaration-sequence.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/declaration-sequence.json", "prev_declaration"):
        "SHA-256 over a Declaration's publisher object (WIST-1 §5.2) — keys, domain and scope, no page content",
    ("vectors/wist4/audit-commitments.json", "audited_delta"): "a Delta ID",
    ("vectors/wist4/audit-commitments.json", "reference_delta"): "a Delta ID",
    ("vectors/wist4/audit-commitments.json", "message_hex"): "a published preimage of this vector's commitments; the vector's content is placeholder text, not page content",
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
    out.add(hashlib.sha256(
        (ROOT / "vectors" / "wist4" / "decay-table.json").read_bytes()).hexdigest())
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    out.add(b64u_decode(payload["salt"]).hex())   # WIST-1 App A shows the salt in hex
    # The 160-hex ECVRF proof: longer than any digest, so the value sweep's
    # digest lengths never reach it, but WIST-4 App A wraps it into 64-char cells
    # that are digest-shaped on their own.
    out.add(json.loads(
        (ROOT / "vectors" / "wist4" / "sampling.json").read_text())["vrf_proof_hex"])
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
    # satisfy every schema in the suite (WIST-4 §9.1). Vectors are swept too — a
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
    v = json.loads((ROOT / "vectors" / "wist4" / "sampling.json").read_text())
    attestation = {
        "update": {
            "wist_version": "1.0.0",
            "action": "coverage_attestation",
            "subject": "audit.example.net",
            "details": {"block": v["block_hash"], "vrf_proof": v["vrf_proof_hex"],
                        "prev_record": None},
            "effective_at": "2026-08-02T16:00:00Z",
        },
        "sig": json.loads(
            (ROOT / "examples" / "registry-update.json").read_text())["sig"],
    }
    Draft202012Validator(schema).validate(attestation)
    # §4 requires the proof, and the whole coverage duty is derived from it:
    # an attestation without one claims an empty draw and proves nothing.
    for missing in ("block", "vrf_proof", "prev_record"):
        bad = copy.deepcopy(attestation)
        del bad["update"]["details"][missing]
        try:
            Draft202012Validator(schema).validate(bad)
        except ValidationError:
            continue
        raise AssertionError(f"coverage_attestation without {missing} validated")
check("schema:wist4-coverage-attestation", _dc4_coverage_attestation)

def _dc4_auditor_remove_evidence():
    """WIST-4 §4, §9.1: an auditor_remove is for cause exactly when it carries
    evidence, so an empty `evidence` array — a removal neither for cause nor
    an exit — is not a valid Registry Update."""
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    sig = json.loads((ROOT / "examples" / "registry-update.json").read_text())["sig"]
    def remove(**over):
        update = {"wist_version": "1.0.0", "action": "auditor_remove",
                  "subject": "audit.example.net", "details": {"key_id": "test-aud-k1"},
                  "effective_at": "2026-08-02T16:00:00Z"}
        update.update(over)
        return {"update": update, "sig": sig}
    Draft202012Validator(schema).validate(remove())
    Draft202012Validator(schema).validate(remove(evidence=["sha256:" + "0" * 64]))
    try:
        Draft202012Validator(schema).validate(remove(evidence=[]))
    except ValidationError:
        pass
    else:
        raise AssertionError("an auditor_remove with an empty evidence array validated")
    v = _roster_vector()
    removes = [e for c in v["cases"] for e in c["entries"] if e["action"] == "auditor_remove"]
    assert all(e["evidence"] for e in removes if "evidence" in e), \
        "a roster vector remove carries an empty evidence array"
    assert any("evidence" in e for e in removes) and any("evidence" not in e for e in removes), \
        "the roster vector must carry both a removal for cause and an exit"
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text())
    assert "an `evidence` member naming at least one ID" in prose, "§4 does not pin what carrying evidence means"
check("schema:wist4-auditor-remove-evidence", _dc4_auditor_remove_evidence)

def _dc3_parameter_tuple_effective_at():
    """WIST-3 §7: a `parameter` tuple's `effective_at` is the instant the
    Registry Update carries, not a height.

    Every window `effective_at` takes part in is compared against a Block
    `sealed_at` (WIST-4 §9.1), so a state artifact restating it as an integer
    would make a resuming Consumer compare a height against an instant — and
    the §9 grace period is exactly such a comparison.
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
    assert ("Only pings resolving to `WIST2-E02` or `WIST2-E04` count against "
            "the domain's daily quota Q") in prose, "the noise set moved"
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

def _wist1_recovery_settlement():
    """WIST-1 §5.2: the window's admission and settlement derivations.

    Recomputed here from the case inputs rather than read off `expected`, so
    the vector states the rule and this check proves the file agrees with it.
    """
    v = json.loads((ROOT / "vectors" / "wist1" / "recovery-settlement.json").read_text())
    saw_supersession = saw_chain_extension = saw_rejection = False
    for case in v["cases"]:
        name = case["name"]
        recovery = case["recovery_declaration"]
        admitted_keys = set(case["pre_recovery_keys"]) | set(recovery["keys"])
        queued = [d for d in case["served"] if d["signer"] in admitted_keys]
        not_queued = [d for d in case["served"] if d["signer"] not in admitted_keys]
        assert [d["delta_id"] for d in queued] == case["expected"]["queued"], \
            f"{name}: queue admission"
        assert [d["delta_id"] for d in not_queued] == case["expected"]["not_queued"], \
            f"{name}: non-admission"

        head, superseded = recovery, []
        for decl in case["window_declarations"]:
            if decl["signer"] in set(head["keys"]) | set(head.get("recovery_keys", [])):
                head = decl
                saw_chain_extension = True
            else:
                superseded.append(decl["label"])
        assert superseded == case["expected"]["superseded"], f"{name}: supersession"
        assert head["keys"] == case["expected"]["effective_keys"], f"{name}: effective keys"
        sealed = [d["delta_id"] for d in queued if d["signer"] in head["keys"]]
        rejected = [d["delta_id"] for d in queued if d["signer"] not in head["keys"]]
        assert sealed == case["expected"]["sealed"], f"{name}: sealed"
        assert rejected == case["expected"]["rejected"], f"{name}: WIST1-E13"
        saw_supersession |= bool(superseded)
        saw_rejection |= bool(rejected)
    assert saw_supersession and saw_chain_extension and saw_rejection, \
        "the vector must exercise supersession, a chain extension and an E13 drop"

    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-delta-format.md").read_text())
    for marker in (
            "verifies under **either** the Key Set in effect immediately before the "
            "recovery **or** the recovery Declaration's own",
            "an ordinary rotation and a fresh identity alike",
            "revalidated against the Key Set of that chain's newest Declaration",
            "The rejection is of the queued copy and not of the Delta's identity"):
        assert marker in prose, f"§5.2 does not state: {marker!r}"
check("vectors:wist1-recovery-settlement", _wist1_recovery_settlement)

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
    if ecvrf.string_to_int(s_bytes) >= ecvrf.Q:
        return False, "s-range"
    try:
        a_pt = ecvrf.string_to_point(a_bytes)
        r_pt = ecvrf.string_to_point(r_bytes)
    except ecvrf.InvalidProof:
        return False, "decode"
    if ecvrf._is_identity(ecvrf._mul(8, a_pt)) or \
            ecvrf._is_identity(ecvrf._mul(8, r_pt)):
        return False, "small-order"
    k = ecvrf.string_to_int(ecvrf._sha512(r_bytes, a_bytes, msg)) % ecvrf.Q
    lhs = ecvrf._mul(ecvrf.string_to_int(s_bytes), ecvrf.BASE)
    if ecvrf._equal(lhs, ecvrf._add(r_pt, ecvrf._mul(k, a_pt))):
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
            a_pt = ecvrf.string_to_point(a_bytes)
            r_pt = ecvrf.string_to_point(r_bytes)
        except ecvrf.InvalidProof:
            return False
        k = ecvrf.string_to_int(ecvrf._sha512(r_bytes, a_bytes, msg)) % ecvrf.Q
        lhs = ecvrf._mul(8, ecvrf._mul(ecvrf.string_to_int(s_bytes) % ecvrf.Q, ecvrf.BASE))
        rhs = ecvrf._mul(8, ecvrf._add(r_pt, ecvrf._mul(k, a_pt)))
        return ecvrf._equal(lhs, rhs)

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
    """External corpus anchor for the §4 profile, in the ecvrf B.3 mold.

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

def _parameter_registry_enum():
    """WIST-4 §9's table and the `parameter_change` enum must correspond exactly.

    The table is what a human reads and the enum is what a validator enforces.
    An identifier in one and not the other means either a parameter nobody can
    amend in-band, or an amendable parameter with no published default and no
    stated owner — both of which turn a governance action into a guess. The
    correspondence is therefore checked in both directions, and a row that is
    deliberately not amendable must say so with an em dash rather than by
    omitting a cell.
    """
    spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
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

def _decay_parameters_twin():
    """WIST-4 §6.1, §9: the decay constant is fixed by the table's bytes and
    carries no identifier; the horizon is amendable only down to the table."""
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    validator = Draft202012Validator(schema)
    example = json.loads((ROOT / "examples" / "registry-update.json").read_text())
    def change(parameter, value):
        doc = copy.deepcopy(example)
        doc["update"]["action"] = "parameter_change"
        doc["update"]["details"] = {"parameter": parameter, "value": value}
        doc["update"]["effective_at"] = "2026-08-12T12:00:00Z"
        return doc
    rejected = lambda doc: bool(list(validator.iter_errors(doc)))
    assert rejected(change("decay_constant_days", 90)), \
        "the schema still accepts a parameter_change to the decay constant"
    assert rejected(change("decay_horizon_days", 1826)), \
        "the schema accepts a horizon past the table's last index"
    assert not rejected(change("decay_horizon_days", 1825)), \
        "the schema rejects the table's own horizon"
    assert not rejected(change("decay_horizon_days", 365)), \
        "the schema rejects a horizon inside the table"
    table = json.loads((ROOT / "vectors" / "wist4" / "decay-table.json").read_text())
    assert table["max_days"] == 1825 and len(table["values"]) == 1826, \
        "the horizon bound and the table's length disagree"
check("negative:wist4-decay-parameters", _decay_parameters_twin)

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
    spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
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
        return {"update": {"wist_version": "1.0.0", "action": "parameter_change",
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
    # WIST-4 §7's own due process can run, so raising any deadline without
    # raising it would leave an appellant unable to fetch the Blocks holding
    # the Audit Records its sanction rests on (WIST-3 §6).
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
        "WIST-3 §3.2 requires an Aggregator to be able to seal")

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

    WIST-4 §6 states that every input to reputation is an integer and §11 that
    "there is no conforming path that uses `double`"; WIST-4 §4 says the same of
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
        return {"update": {"wist_version": "1.0.0", "action": "parameter_change",
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

    # WIST-4 §9 must say so, or an implementer reading prose alone sees a number.
    section9 = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text() \
        .split("## 9. Parameter Registry")[1]
    assert "**Every value the registry carries is an integer**" in section9, \
        "WIST-4 §9 does not state that every registry value is an integer"
    assert "`value` (a number" not in section9, \
        "WIST-4 §9.1 still describes `value` as a number"
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

def _dc4_appendix_figures():
    """WIST-4's worked example must quote the vector, not a remembered figure.

    Figures transcribed into prose drift silently from the vectors that
    produced them. This pins every published figure to
    vectors/wist4/sampling.json.
    """
    v = json.loads((ROOT / "vectors" / "wist4" / "sampling.json").read_text())
    spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    flat = spec.replace("`<br>`", "")   # long hex is wrapped inside table cells
    for field in ("block_hash", "alpha_hex", "vrf_proof_hex", "beta_hex",
                  "delta_id", "draw_first8_hex", "auditor_public_key"):
        assert v[field] in flat, f"WIST-4 does not quote sampling.json {field}"
    for c in v["selection"]:
        for field in ("delta_id", "draw_first8_hex", "lhs_approx", "rhs_approx"):
            assert c[field] in flat, \
                f"WIST-4 does not quote {c['label']} {field} = {c[field]}"
        for n in (c["D"], c["p_1e7"], c["reputation_u"]):
            assert str(n) in flat or f"{n:,}".replace(",", " ") in flat, \
                f"WIST-4 does not quote {c['label']} value {n}"
        # The Selected? cell itself, pinned to its own row via the
        # (lhs_approx, rhs_approx) pair — unique per selection entry — so a
        # hand-edit flipping "yes" to "no" (or vice versa) on the wrong row
        # cannot pass unnoticed. Bold markers (`**yes**`) are tolerated.
        word = "yes" if c["selected"] else "no"
        row = re.escape(f"{c['lhs_approx']} | {c['rhs_approx']} |")
        assert re.search(row + r"\s*\*{0,2}" + word + r"\*{0,2}\s*\|", flat), \
            f"WIST-4's Selected? column for {c['label']} does not say {word!r} on its own row"
    # No floating-point rendering of the sampling rate may survive in §4's
    # normative text: the integers are the definition, decimals only a reading.
    section4 = flat.split("## 4. Audit Sampling")[1].split("## 5.")[0]
    for stale in ("draw(d) <", "0.30 x (1 - reputation)", "clamp(0.02"):
        assert stale not in section4, f"§4 still specifies sampling in floats: {stale!r}"
check("spec:wist4-appendix-figures", _dc4_appendix_figures)

# 5. WIST-4 §6: reputation, recomputed from the normative decay table using
# nothing but integers. A float anywhere in this check would defeat its point.
WIST4 = ROOT / "vectors" / "wist4"

def _dc4_decay_table():
    raw = (WIST4 / "decay-table.json").read_bytes()
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
    spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    assert digest in spec, f"WIST-4 §6.1 does not pin the decay table digest {digest}"
check("vectors:wist4-decay-table", _dc4_decay_table)

def _dc4_reputation():
    """Recompute every published intermediate from §6, in integers only."""
    r = json.loads((WIST4 / "reputation.json").read_text())
    table = json.loads((WIST4 / "decay-table.json").read_text())
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
check("vectors:wist4-reputation", _dc4_reputation)

def _dc4_evaluation_order():
    """§6's parenthesization is normative, so the spec must carry it verbatim.

    A wording of the form "that division is its last operation" is literally
    false for `base_u` and `Q`, both of which add after dividing: read at its
    word it yields base_u = 136 at A = 0 instead of 100 000, which also
    destroys the no-cliff property. This pins both the
    corrected forms and the two counterexample values the spec quotes.
    """
    spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    forms = ("(seconds(Y) − seconds(X)) / 86 400",
             "100 000 + ((900 000 × min(A, 730)) / 730)",
             "(base_u × (C + 1) × 1 000 000 000)",
             "100 + ((10 000 × reputation_u) / 1 000 000)")
    for form in forms:
        assert form in spec, f"WIST-4 §6 no longer writes {form!r} parenthesized"
    # The stated count and the enumeration must agree, or a reader cannot
    # tell which divisions the parenthesization rule covers; the divisions
    # outside §6 are named there too, so the count is not read as exhaustive.
    assert "The **four** that reputation and\nits consumers perform are tabulated here" in spec, \
        f"WIST-4 §6 no longer states the division count, which is {len(forms)}"
    for elsewhere in ("`confirm_window_hours / 2` in §4's extension deadline",
                      "the two\nlink-agreement quotients in §5"):
        assert elsewhere in spec, f"WIST-4 §6 no longer names the division {elsewhere!r}"
    assert "`confirm_window_hours / 2` hours (integer division)" in spec, \
        "§4 no longer writes the extension deadline's division out"
    assert "floor(|D ∩ O| × 1 000 000 / |D ∪ O|)" in spec, \
        "§5 no longer writes the link subset quotient out"
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
        assert n in spec, f"WIST-4 no longer quotes the counterexample value {n}"
check("spec:wist4-evaluation-order", _dc4_evaluation_order)

def _dc4_sealed_at_precision():
    """WIST-4 §6.1's day counts are exact only because §6's inputs are exact.

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
    wist3 = (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text()
    assert "whole-second precision" in wist3, "WIST-3 §3.1 does not state the constraint"
check("schema:wist4-sealed-at-precision", _dc4_sealed_at_precision)

# WIST-4 §3: every window and every admission test in the suite reads a Block
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
        "Publisher-supplied and never compared to a Block: WIST-4 §6.1 excludes it from every "
        "derived quantity, and its only comparisons are to the `observed_at` of the Delta named "
        "by `prev` and to the validator's own clock under WIST-1 §3.4's 10-minute skew allowance",
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

    WIST-4 §3 states that every window and admission test reads a Block
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
    notice = {"update": {"wist_version": "1.0.0", "action": "notice",
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
    wist4 = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    section7 = wist4.split("## 7. Sanctions")[1].split("## 8.")[0]
    assert re.search(
        r"appeal window is `appeal_window_days` \(14\) from the `sealed_at` of\s*\n"
        r"\s*the Block sealing the `notice`, never from its `effective_at`", section7), \
        "WIST-4 §7 no longer runs the appeal window from the notice's Block `sealed_at`"
    wist1 = (ROOT / "specs" / "WIST-1-delta-format.md").read_text()
    assert "opens at the `sealed_at` of the Block" in wist1, \
        "WIST-1 §5.2 no longer anchors the recovery window to the Declaration's own Entry"
check("schema:timestamp-anchoring", _timestamp_anchoring)

def _dc4_reputation_figures():
    """WIST-4 §6 and Appendix B must quote the vector, not remembered figures."""
    r = json.loads((WIST4 / "reputation.json").read_text())
    spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    table = json.loads((WIST4 / "decay-table.json").read_text())
    def quoted(n):
        # The spec groups long numbers with spaces; short ones it writes plain.
        return str(n) in spec or f"{n:,}".replace(",", " ") in spec
    for n in (table["values"][0], table["values"][-1]):
        assert quoted(n), f"WIST-4 does not quote decay value {n}"
    for case in [r["worked_example"]] + r["boundary"]:
        for field in ("base_u", "penalty_n", "reputation_u", "Q"):
            assert quoted(case[field]), \
                f"WIST-4 does not quote {case['label']}.{field} = {case[field]}"
    assert quoted(r["worked_example"]["p_1e7"]), "WIST-4 does not quote the worked p_1e7"
    assert r["worked_example"]["p_readable"] in spec, \
        "WIST-4 does not show what the worked p_1e7 reads as"
check("spec:wist4-reputation-figures", _dc4_reputation_figures)

def _dc4_similarity_thresholds(section5=None):
    """The three extract §5 verdict bands and the two nested link bands,
    read out of the specification's own table.

    Every check below that needs a threshold reads it here rather than
    carrying its own copy, so an edit to §5 moves what the checks exercise
    instead of drifting away from it.

    `section5` is the already-sliced §5 text to parse; the default (None)
    reads and slices it from the real spec file. A caller may instead pass
    a perturbed copy — `negative:wist4-link-thresholds` below does, to prove
    the link-threshold regexes and the registry cross-check actually bind
    to the table's content rather than passing regardless of it.
    """
    if section5 is None:
        spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
        section5 = spec.split("## 5. Verdicts")[1].split("## 6.")[0]
    rows = {
        # Unlike the other two extract rows, `consistent`'s condition cell
        # carries a second, trailing clause (WIST-4 §5: the link-dimension
        # qualifier), so this pattern reads the number off the front of the
        # cell rather than requiring the cell to end right after it.
        "consistent_at_or_above": r"\|\s*`consistent`\s*\|\s*effective similarity\s*≥\s*([\d ]+)",
        "variance_at_or_above": r"\|\s*`dynamic_variance`\s*\|\s*([\d ]+?)\s*≤\s*effective similarity",
        "variance_below": r"\|\s*`dynamic_variance`\s*\|.*?effective similarity\s*<\s*([\d ]+?)\s*\|",
        "inconsistent_below": r"\|\s*`inconsistent`\s*\|\s*effective similarity\s*<\s*([\d ]+?)\s*\|",
        # The link dimension's own thresholds: the trailing clause on the
        # `consistent` row, and the two link-verdict rows nested inside it.
        # Parsed independently of the extract thresholds above, so a
        # hand-edit that moves a link number without moving the qualifier
        # (or vice versa) is caught rather than silently accepted.
        "link_consistent_at_or_above": r"\|\s*`consistent`\s*\|.*?`link_agreement`\s*≥\s*([\d ]+?)\s*\|",
        "link_variance_floor_at_or_above": r"\|\s*`link_variance`\s*\|.*?([\d ]+?)\s*≤\s*`link_agreement`",
        "link_variance_below": r"\|\s*`link_variance`\s*\|.*?`link_agreement`\s*<\s*([\d ]+?)\s*\(",
        "link_inconsistent_below": r"\|\s*`link_inconsistent`\s*\|.*?`link_agreement`\s*<\s*([\d ]+?)\s*\|",
    }
    out = {}
    for name, pattern in rows.items():
        m = re.search(pattern, section5)
        assert m, f"WIST-4 §5 does not state the {name} threshold in the expected form"
        out[name] = int(m.group(1).replace(" ", "").replace(" ", ""))
    assert out["consistent_at_or_above"] == out["variance_below"], \
        "§5's `consistent` floor and `dynamic_variance` ceiling are not the same number"
    assert out["variance_at_or_above"] == out["inconsistent_below"], \
        "§5's `dynamic_variance` floor and `inconsistent` ceiling are not the same number"
    assert out["link_consistent_at_or_above"] == out["link_variance_below"], \
        "§5's `consistent` link floor and `link_variance` ceiling are not the same number"
    assert out["link_variance_floor_at_or_above"] == out["link_inconsistent_below"], \
        "§5's `link_variance` floor and `link_inconsistent` ceiling are not the same number"

    # The two link thresholds are also registered constants (§9): a table
    # that agrees with itself but not with the Parameter Registry is still
    # wrong, and a `parameter_change` reads the registry value, never §5's
    # own prose copy of it.
    registered = _registry_table_defaults()
    assert out["link_consistent_at_or_above"] == registered["link_agreement_consistent"], (
        f"§5's verdict table reads the link consistent floor as "
        f"{out['link_consistent_at_or_above']}, but §9 registers "
        f"link_agreement_consistent as {registered['link_agreement_consistent']}")
    assert out["link_variance_floor_at_or_above"] == registered["link_variance_floor"], (
        f"§5's verdict table reads the link variance floor as "
        f"{out['link_variance_floor_at_or_above']}, but §9 registers "
        f"link_variance_floor as {registered['link_variance_floor']}")
    return out

def _link_threshold_parser_twin():
    """A hand-edited link threshold in a *copy* of §5's table must break
    `_dc4_similarity_thresholds`'s own registry cross-check — proof the
    link-threshold regexes added above bind to the table's real numbers
    rather than passing regardless of its content. Both link rows are
    perturbed to the same wrong value (300 000 → 250 000) so the table
    still agrees with itself and the failure is specifically the registry
    comparison, not the self-consistency assert a single-row edit would
    trip instead; the disk copy is untouched throughout.
    """
    spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    section5 = spec.split("## 5. Verdicts")[1].split("## 6.")[0]
    variance_row = re.compile(r"(`link_variance`\s*\|.*?)300 000(\s*≤\s*`link_agreement`)")
    inconsistent_row = re.compile(r"(`link_inconsistent`\s*\|.*?`link_agreement`\s*<\s*)300 000")
    assert variance_row.search(section5) and inconsistent_row.search(section5), \
        "the link threshold rows did not match for the twin to perturb"
    mutated = variance_row.sub(r"\g<1>250 000\g<2>", section5, count=1)
    mutated = inconsistent_row.sub(r"\g<1>250 000", mutated, count=1)
    assert mutated != section5, "the substitution changed nothing"

    try:
        _dc4_similarity_thresholds(mutated)
    except AssertionError as e:
        assert str(e) == (
            "§5's verdict table reads the link variance floor as 250000, "
            "but §9 registers link_variance_floor as 300000"), \
            f"raised for the wrong reason: {e!r}"
    else:
        raise AssertionError(
            "perturbing both link thresholds in a copied table still "
            "passed _dc4_similarity_thresholds")

check("negative:wist4-link-thresholds", _link_threshold_parser_twin)


def _dc4_severity_rows():
    """§7's severity table as intervals, parsed out of §7's own text.

    Read rather than restated, so that the totality check below tests §5's
    verdict bands against the severity table the document actually
    publishes. A copy kept here would agree with itself while §5 and §7
    drifted apart, which is the failure the check exists to catch.
    """
    spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    section7 = spec.split("## 7. Sanctions")[1].split("## 8.")[0]
    rows = []
    for m in re.finditer(
            r"\|\s*([\d ]+?)\s*≤\s*`sim`\s*<\s*([\d ]+?)\s*\|\s*(\d)\s*\(", section7):
        rows.append((int(m.group(1).replace(" ", "")),
                     int(m.group(2).replace(" ", "")), int(m.group(3))))
    for m in re.finditer(r"\|\s*`sim`\s*<\s*([\d ]+?)\s*\|\s*(\d)\s*\(", section7):
        rows.append((0, int(m.group(1).replace(" ", "")), int(m.group(2))))
    assert len(rows) >= 3, f"WIST-4 §7's severity table did not parse: {rows}"
    # §7 must state its input as the *effective* similarity: reverting it to
    # the sealed `similarity` silently un-does the `delete` mirror and leaves
    # a false `delete` deriving severity from a value in the wrong direction.
    assert re.search(r"let `sim` be the highest\s+\*\*effective similarity\*\*\s*\(§5\)",
                     section7), \
        "WIST-4 §7 does not derive `sim` from the effective similarity (§5)"
    return rows


def _dc4_verdict_totality():
    """Every permitted pair of texts maps to exactly one verdict (WIST-4 §5),
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
    spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    section5 = spec.split("## 5. Verdicts")[1].split("## 6.")[0]
    t = _dc4_similarity_thresholds()
    CONSISTENT, HIGH = t["consistent_at_or_above"], t["inconsistent_below"]
    assert 0 < HIGH < CONSISTENT <= 1_000_000, \
        f"§5's thresholds are not ordered inside the micro-unit range: {t}"
    LINK_CONSISTENT = t["link_consistent_at_or_above"]
    LINK_VARIANCE_FLOOR = t["link_variance_floor_at_or_above"]
    assert 0 < LINK_VARIANCE_FLOOR < LINK_CONSISTENT <= 1_000_000, \
        f"§5's link thresholds are not ordered inside the micro-unit range: {t}"
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

    def bands(eff, link_agreement=None):
        """WIST-4 §5's full seven-row model: the three extract bands, with a
        second partition over `link_agreement` nested inside the extract-
        `consistent` band alone. `link_agreement=None` models the link
        dimension being neutral for this audit — a `delete`, a non-HTML
        representation, or an `unreachable`/`not_auditable` verdict — in
        which case the result depends on `eff` only, exactly as before
        this function grew a second parameter.
        """
        extract_hit = [name for name, hit in (
            ("consistent", eff >= CONSISTENT),
            ("dynamic_variance", HIGH <= eff < CONSISTENT),
            ("inconsistent", eff < HIGH),
        ) if hit]
        if len(extract_hit) != 1 or extract_hit[0] != "consistent" or link_agreement is None:
            return extract_hit
        return [name for name, hit in (
            ("consistent", link_agreement >= LINK_CONSISTENT),
            ("link_variance", LINK_VARIANCE_FLOOR <= link_agreement < LINK_CONSISTENT),
            ("link_inconsistent", link_agreement < LINK_VARIANCE_FLOOR),
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

    # The link dimension's own partition (WIST-4 §5), nested inside the
    # extract-`consistent` band alone: every `link_agreement` value is
    # checked at two representative extract-consistent readings — the
    # boundary itself and the top of the range — since which consistent-
    # band `eff` it sits inside cannot move the link partition.
    seen_link = set()
    for eff_probe in (CONSISTENT, 1_000_000):
        for link_agreement in range(0, 1_000_001):
            hit = bands(eff_probe, link_agreement)
            assert len(hit) == 1, (
                f"eff={eff_probe}, link_agreement={link_agreement} matches "
                f"{len(hit)} link-dimension verdicts: {hit}")
            seen_link.add(hit[0])
    assert seen_link == {"consistent", "link_variance", "link_inconsistent"}, \
        f"the link dimension cannot reach every band: {seen_link}"

    # Exact boundary behaviour at the two link thresholds, the shape §5's
    # table states ("≥" / "≤ … <" / "<").
    assert bands(CONSISTENT, LINK_CONSISTENT) == ["consistent"], \
        "link_agreement at its own consistent floor is not `consistent`"
    assert bands(CONSISTENT, LINK_CONSISTENT - 1) == ["link_variance"], \
        "link_agreement one below the consistent floor is not `link_variance`"
    assert bands(CONSISTENT, LINK_VARIANCE_FLOOR) == ["link_variance"], \
        "link_agreement at its own variance floor is not `link_variance`"
    assert bands(CONSISTENT, LINK_VARIANCE_FLOOR - 1) == ["link_inconsistent"], \
        "link_agreement one below the variance floor is not `link_inconsistent`"

    # The qualifier is vacuous outside the extract-`consistent` band, and
    # when the dimension does not apply at all (`link_agreement=None`):
    # neither moves the verdict away from the extract-only reading — the
    # nested partition can only ever narrow the one band it sits inside.
    for eff_probe in (0, HIGH - 1, HIGH, CONSISTENT - 1):
        extract_only = bands(eff_probe)
        assert bands(eff_probe, None) == extract_only, \
            f"eff={eff_probe} with no link dimension applied is not the extract-only band"
        for link_agreement in (0, LINK_VARIANCE_FLOOR, LINK_CONSISTENT, 1_000_000):
            assert bands(eff_probe, link_agreement) == extract_only, (
                f"eff={eff_probe} (outside the extract-consistent band) is "
                f"moved by link_agreement={link_agreement}, but the link "
                f"dimension must be vacuous there")
check("spec:wist4-verdict-totality", _dc4_verdict_totality)

def _dc4_severity_bands():
    """WIST-4 §7's severity table drives `penalty_n` directly (§6.1), so a
    collapsed or unreachable band silently changes every domain's
    reputation rather than merely misdocumenting one. Confirms all three
    severities are reachable from `sim` alone (now an integer, §5), that
    no row rests on a term needing its own definition (e.g. "wholly
    absent"), and that the reachable range tracks §5's own `inconsistent`
    threshold rather than a value copied once and then hardcoded — a
    mutation of §5's threshold that collapses a band must fail here.
    """
    spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    section5 = spec.split("## 5. Verdicts")[1].split("## 6.")[0]
    section7 = spec.split("## 7. Sanctions")[1].split("## 8.")[0]
    for row in ("| 150 000 ≤ `sim` < 300 000 | 1 (minor divergence) |",
                "| 50 000 ≤ `sim` < 150 000 | 2 (misleading extract) |",
                "| `sim` < 50 000 | 3 (fabricated content) |"):
        assert row in section7, f"WIST-4 §7 no longer carries the severity row {row!r}"
    assert "wholly absent" not in section7, \
        "WIST-4 §7's severity table still conditions a band on an undefined term"

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
check("spec:wist4-severity-bands", _dc4_severity_bands)

def _withdrawal_binds_every_serving_path():
    """A withdrawal reaches every path the Payload is served from, or none.

    The salt is published in exactly one kind of file, and three parties serve
    it: the Aggregator, every Mirror, and the Publisher's own well-known path
    (WIST-2 §3.1, WIST-3 §6.1). "After withdrawal the Log itself stops helping"
    (WIST-3 §11) and "the salt is destroyed and that Record's commitments can no
    longer be checked by anyone" (WIST-4 §5) are false at one fetch if any one of
    the three keeps serving — and WIST-2 separately obliges a Publisher to keep
    its anchor Payload retrievable, so leaving it unbound was not an omission
    but a conflict.
    """
    wist2 = (ROOT / "specs" / "WIST-2-site-publication.md").read_text()
    wist3 = (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text()
    wist4 = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
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
    assert "appeals/<notice-id>.json" in checklist, \
        "WIST-2's Publisher checklist has no row for publishing an appeal"

    # And the claims that rest on it must still be the claims being made, or
    # this check is guarding a guarantee the suite no longer states.
    assert "the Log itself\nstops helping" in wist3, \
        "WIST-3 §11 no longer claims the Log stops helping after a withdrawal"
    assert "can no longer be checked by anyone" in wist4, \
        "WIST-4 §5 no longer claims a withdrawn Record's commitments are uncheckable"
check("spec:withdrawal-serving-paths", _withdrawal_binds_every_serving_path)

def _rule_ownership():
    """A rule restated in a second document must be the rule, not an older one.

    WIST-4 §5 owns the unauditable-URL rule: two `robots_excluded` Records from
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
    for name, marker in (("WIST-2-site-publication.md", "two Auditors independent of one another"),
                         ("WIST-3-logbook-distribution.md", "two independent Auditors"),
                         ("WIST-4-audit-reputation-governance.md", "signed by Auditors independent of one another")):
        assert marker in specs[name], \
            f"{name} no longer states that two independent Auditors are needed to exclude a URL"
        assert "independent of both" in specs[name], \
            f"{name} no longer states that the clearing audit must come from a third Auditor"
    # WIST-2 defers rather than legislating: it owns the robots.txt boundary, not
    # the materialization consequence.
    dc2_section5 = specs["WIST-2-site-publication.md"].split("## 5. Aggregator Pull Behavior")[1] \
        .split("## 6.")[0]
    assert "WIST-4 §5 owns that rule" in dc2_section5, \
        "WIST-2 §5 no longer defers to the document that owns the rule it summarizes"
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
    wist1 = (ROOT / "specs" / "WIST-1-delta-format.md").read_text()
    wist4 = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    section4 = wist4.split("## 4. Audit Sampling")[1].split("## 5.")[0]
    section7 = wist4.split("## 7. Sanctions")[1].split("## 8.")[0]
    section10 = wist4.split("## 11. Security Considerations")[1].split("## 12.")[0]

    # I1: the appeal has a path, a deadline, and a consequence for the omission.
    assert "/.well-known/wist/appeals/" in section7, \
        "WIST-4 §7 gives an appeal no in-band publication path"
    for fragment in ("`appeal_seal_days`",
                     "is void on recomputation from T",
                     '`"unappealed"`'):
        assert fragment in section7, f"WIST-4 §7 no longer states {fragment}"
    assert "appeal_seal_days" in json.loads(
        (ROOT / "schemas" / "registry-update.schema.json").read_text())["allOf"][5][
            "then"]["properties"]["update"]["properties"]["details"][
            "properties"]["parameter"]["enum"], \
        "the parameter enum does not carry appeal_seal_days"

    # …and §10 no longer defends appeals with an argument that is false.
    assert "Omission is not equivocation" in section10, \
        "WIST-4 §11 no longer corrects the claim that suppression is equivocation"
    assert not re.search(r"suppress a\s*\n?\s*sanction or an appeal: withholding log entries",
                         section10), \
        "WIST-4 §11 still answers appeal suppression with the equivocation argument"

    # I3: the recovery window opens on the Declaration's own Entry.
    recovery = wist1.split("**Compromise recovery.**")[1].split("**Historical verification.**")[0]
    assert "opens at the `sealed_at` of the Block" in recovery, \
        "WIST-1 §5.2's recovery window is not anchored to the recovery Declaration's Entry"
    assert "does not open it" in recovery, \
        "WIST-1 §5.2 does not say the `notice` describes the window rather than opening it"
    assert not re.search(r"MUST record a `notice`[^.]*opening a recovery window", recovery), \
        "WIST-1 §5.2 still has the `notice` open the recovery window"

    # I4: coverage failure withdraws the Records itself.
    assert "in coverage failure" in section4, \
        "WIST-4 §4 does not define the derived coverage-failure state"
    assert "records\nthe consequence and does not create it" in section4, \
        "WIST-4 §4 does not say `auditor_remove` records the consequence rather than creating it"
    section3 = wist4.split("## 3. Auditors")[1].split("## 4.")[0]
    assert "in coverage failure" in section3, \
        "WIST-4 §3's rejection list does not reach an Auditor in coverage failure"

    # I5: the personal-data rule is general, not a list of three field names.
    section91 = wist4.split("### 9.1. Registry Update")[1].split("## 10.")[0]
    assert "no `evidence` element, may\ncarry personal data" in section91, \
        "WIST-4 §9.1's personal-data rule is not written over the position"
    assert not re.search(r"The same applies to the free-text fields `legal_basis`, `reason` and",
                         section91), \
        "WIST-4 §9.1 still enumerates the fields the personal-data rule covers"
    # The rule reaches the Publisher-written details, and the authorship it
    # states matches who seals what: `appeal` is the Publisher's, while
    # `sanction_lift` is an Aggregator-sealed Registry Update (§7) — text
    # bracketing the two as both-Publisher would contradict §7.
    assert "an `appeal`'s `details` are the\nPublisher's" in section91, \
        "WIST-4 §9.1 does not reach the Publisher-written details the rule was missing"
    assert "`sanction_lift`'s\n`details` are the Aggregator's" in section91, \
        "WIST-4 §9.1 misattributes a `sanction_lift`'s `details` (an Aggregator-sealed entry, §7)"
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
    spec = (ROOT / "specs" / "WIST-4-audit-reputation-governance.md").read_text()
    section7 = spec.split("## 7. Sanctions")[1].split("## 8.")[0]
    assert '**An `"unappealed"` ruling cannot precede what it reports.**' in section7, \
        "WIST-4 §7 places no timing constraint on an `unappealed` ruling"
    assert re.search(
        r"discharges T only when the Block sealing it has a `sealed_at` at\s*\n"
        r"\s*or after the close of the appeal window", section7), \
        "WIST-4 §7 does not require an `unappealed` ruling to follow the window's close"
    assert re.search(r"party recomputing MUST treat it as absent", section7), \
        "WIST-4 §7 does not require a recomputing party to ignore an early `unappealed` ruling"
    checklist = spec.split("**Any party recomputing reputation:**")[1]
    assert '`appeal_ruling` of `"unappealed"` whose own Block' in checklist, \
        "WIST-4 §13's recompute checklist has no row for the `unappealed` timing rule"

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

def _link_agreement_vector():
    """WIST-4 §5: recompute every published link_agreement case."""
    import link_extraction
    vec = json.loads((ROOT / "vectors" / "wist4" / "link-agreement.json").read_text())
    for case in vec["cases"]:
        got = link_extraction.link_agreement(
            case["declared_urls"], case["declared_total"],
            case["observed_urls"], case["observed_total"])
        assert got == case["link_agreement"], f"{case['label']}: {got}"

check("vectors:wist4-link-agreement", _link_agreement_vector)

def _link_agreement_twin():
    import link_extraction
    vec = json.loads((ROOT / "vectors" / "wist4" / "link-agreement.json").read_text())
    case = next(c for c in vec["cases"] if c["observed_urls"])
    got = link_extraction.link_agreement(
        case["declared_urls"], case["declared_total"],
        case["observed_urls"][:-1], case["observed_total"] - 1)
    assert got != case["link_agreement"], "dropping an observed link moved nothing"

check("negative:wist4-link-agreement", _link_agreement_twin)

def _verdict_pair_ok(record, effective_similarity=None):
    """WIST-4 §5: raise AssertionError when `record`'s (effective similarity,
    link_agreement, verdict) triple does not satisfy §5's condition for
    its own verdict — the real predicate behind WIST-4 §3's malformed-
    evidence rejection, not a copy of it, so both the positive check below
    and its twin exercise one function rather than one each agreeing with
    itself. Thresholds are read from the Parameter Registry's own
    published defaults (`_registry_table_defaults()`), never as literals,
    so a `parameter_change` to either threshold moves what this checks.

    `effective_similarity` is §5's mirror applied to `record["similarity"]`
    — the sealed value itself for `new`/`update`/`attest`, `1_000_000 -
    similarity` for `delete` — and resolving it is the CALLER's job: a
    Record carries `audited_delta`, not its change type, so this function
    cannot look the mirror up itself. The default (`None`) falls back to
    the sealed `similarity` unmirrored, which is correct only for a
    non-`delete` audit; a caller checking a `delete` Record MUST resolve
    the change type and pass the mirrored value explicitly, or a
    perfectly conforming `delete` (similarity 0, effective 1 000 000) is
    flagged malformed in exactly the direction §5's mirror exists to
    prevent.

    Only the three verdicts whose condition involves the link dimension
    are covered — `dynamic_variance`, `inconsistent`, `unreachable` and
    `not_auditable` are outside this pair-condition's scope and are left
    unchecked here (WIST-4 §5's full verdict totality is `spec:wist4-verdict-
    totality`'s job, not this one's).
    """
    if effective_similarity is None:
        effective_similarity = record["similarity"]
    defaults = _registry_table_defaults()
    sim_floor = defaults["similarity_consistent"]
    link_floor = defaults["link_agreement_consistent"]
    link_variance_floor = defaults["link_variance_floor"]
    verdict = record["verdict"]
    if verdict == "consistent":
        assert effective_similarity >= sim_floor, \
            "consistent verdict below the extract band"
        if "link_agreement" in record:
            assert record["link_agreement"] >= link_floor, \
                "consistent verdict below the link band"
    elif verdict == "link_variance":
        assert effective_similarity >= sim_floor, \
            "link_variance verdict below the extract band"
        assert link_variance_floor <= record["link_agreement"] < link_floor, \
            "link_variance verdict outside the link variance band"
    elif verdict == "link_inconsistent":
        assert effective_similarity >= sim_floor, \
            "link_inconsistent verdict below the extract band"
        assert record["link_agreement"] < link_variance_floor, \
            "link_inconsistent verdict at or above the link variance floor"

def _verdict_pair_condition():
    """WIST-4 §3/§5: the example Record's (similarity, link_agreement) pair
    satisfies §5's condition for its own verdict. The example Record's
    audited Delta is change type `new` (`vectors/wist1/id.txt`'s Delta, WIST-1
    §3.3), so `similarity` needs no §5 mirror and `_verdict_pair_ok` is
    called with none — a `delete` Record would have to pass one (below)."""
    rec = json.loads((ROOT / "examples" / "audit-record.json").read_text())["record"]
    assert rec["verdict"] == "consistent"
    _verdict_pair_ok(rec)

check("spec:audit-verdict-pair", _verdict_pair_condition)

def _verdict_pair_twin():
    """A link_agreement below the floor must not still read as `consistent`
    (WIST-4 §5). The mutation runs through `_verdict_pair_ok` itself — the
    same function the positive check calls — rather than re-deriving the
    boolean inline, and the failure is message-matched to the specific
    link-band assertion, so a defect in the wrong branch of the checker
    (or one that stops raising at all) cannot pass this by accident."""
    rec = json.loads((ROOT / "examples" / "audit-record.json").read_text())["record"]
    mutated = copy.deepcopy(rec)
    mutated["verdict"] = "consistent"
    mutated["link_agreement"] = 299_999
    try:
        _verdict_pair_ok(mutated)
    except AssertionError as e:
        assert str(e) == "consistent verdict below the link band", \
            f"raised for the wrong reason: {e!r}"
    else:
        raise AssertionError("a link_agreement below the floor still reads as consistent")

check("negative:audit-verdict-pair", _verdict_pair_twin)

def _verdict_pair_delete_mirror():
    """WIST-4 §5: a `delete` audit's `similarity` is mirrored before any
    verdict condition ever reads it (`1_000_000 − similarity`), so a
    conforming `delete` Record scoring `similarity` 0 — full agreement
    that the committed content is gone — is `consistent` at effective
    similarity 1 000 000, not malformed evidence. `_verdict_pair_ok`
    cannot resolve that mirror itself (a Record carries `audited_delta`,
    not a change type), so the caller passes it explicitly. The Record
    seals no `link_agreement`: §5 makes the link dimension neutral for a
    `delete` audit, and §3 rejects a Record carrying one where it is."""
    rec = {"verdict": "consistent", "similarity": 0}
    _verdict_pair_ok(rec, effective_similarity=1_000_000)

check("spec:audit-verdict-pair-delete-mirror", _verdict_pair_delete_mirror)

def _verdict_pair_delete_mirror_twin():
    """The same Record read through the sealed `similarity` unmirrored —
    `_verdict_pair_ok`'s default, correct only for a non-`delete` audit —
    must be flagged malformed: proof the mirror argument is load-bearing
    and not merely accepted and ignored. This is the bug IMPORTANT-5
    named: before the `effective_similarity` parameter existed, this
    exact conforming `delete` Record was rejected as below the extract
    band."""
    rec = {"verdict": "consistent", "similarity": 0}
    try:
        _verdict_pair_ok(rec)
    except AssertionError as e:
        assert str(e) == "consistent verdict below the extract band", \
            f"raised for the wrong reason: {e!r}"
    else:
        raise AssertionError(
            "a delete Record read without the effective-similarity mirror "
            "still passed as consistent")

check("negative:audit-verdict-pair-delete-mirror", _verdict_pair_delete_mirror_twin)

sys.exit(1 if failures else 0)
