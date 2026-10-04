#!/usr/bin/env python3
"""Validate examples/ against schemas/ and verify vectors/. Exit 0 = green."""
import base64, calendar, collections, copy, datetime, hashlib, hmac, itertools, json, pathlib, re, sys, time

from fractions import Fraction

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

import catalogs
import ed25519_curve
import items as item_rules
import link_extraction
from merkle import audit_path, consistency_proof, leaf_hash, merkle_root, node_hash

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


SEALED_AT_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9]Z$"

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

def note_key_id(name: str, raw_pub: bytes) -> bytes:
    """[signed-note] note key ID (WIST-3 §3.4), computed independently of
    tools/gen_vectors.py's identical formula."""
    return hashlib.sha256(name.encode() + b"\x0a\x01" + raw_pub).digest()[:4]


CHECKPOINT_SIGNATURE_LINES_MAX = 16

# The Unicode White_Space property (WIST-3 §5), enumerated rather than read
# from the interpreter's character tables, which follow whichever Unicode
# version the interpreter ships.
UNICODE_WHITE_SPACE = frozenset(
    "\t\n\v\f\r \x85\xa0     　"
    + "".join(chr(c) for c in range(0x2000, 0x200B)))


def parse_checkpoint(text: str) -> dict:
    """Parse a Checkpoint note per WIST-3 §5 / [signed-note] / [tlog-checkpoint],
    independently of gen_vectors.py's signing helper. Raises ValueError
    ("WIST3-E03: ...") on any structural defect. §5 fixes four points the
    two formats leave open: the root hash line is the base64 of exactly 32
    octets and re-encodes to itself, every signature line — the last
    included — ends in a newline, a key name is non-empty and carries no
    plus and no character with the Unicode White_Space property, and a note
    carries at most 16 signature
    lines. A signature line's blob need only decode to at least a 4-octet
    key ID plus a signature: §5 "ignores every other signature line as
    [signed-note] requires", so the 68-octet Aggregator shape (and the
    76-octet Witness cosignature shape) are enforced only for a line naming
    a known key, in `verify_checkpoint`. Does not authenticate a signature —
    see `verify_checkpoint`."""
    if "\n\n" not in text:
        raise ValueError("WIST3-E03: no blank line between note text and signatures")
    if not text.endswith("\n"):
        raise ValueError("WIST3-E03: the last signature line does not end in a newline")
    header, sigblock = text.split("\n\n", 1)
    lines = header.split("\n")
    if len(lines) != 5:
        raise ValueError(f"WIST3-E03: note text has {len(lines)} lines, not 5")
    origin, size_line, root_line, bn_line, sealed_line = lines
    if not re.fullmatch(r"0|[1-9][0-9]*", size_line):
        raise ValueError("WIST3-E03: tree size is not a canonical decimal")
    tree_size = int(size_line)
    try:
        root = base64.b64decode(root_line, validate=True)
    except Exception as e:
        raise ValueError(f"WIST3-E03: root hash does not parse as base64: {e}")
    if base64.b64encode(root).decode() != root_line:
        raise ValueError("WIST3-E03: root hash is not canonical base64")
    if len(root) != 32:
        raise ValueError(f"WIST3-E03: root hash decodes to {len(root)} octets, not 32")
    m = re.fullmatch(r"epoch_number (0|[1-9][0-9]*)", bn_line)
    if not m:
        raise ValueError("WIST3-E03: malformed epoch_number line")
    epoch_number = int(m.group(1))
    m = re.fullmatch(r"sealed_at (.+)", sealed_line)
    if not m or not re.fullmatch(SEALED_AT_PATTERN.strip("^$"), m.group(1)):
        raise ValueError("WIST3-E03: sealed_at line outside the §3.1 profile")
    sealed_at = m.group(1)

    sig_lines = sigblock.split("\n")
    if sig_lines and sig_lines[-1] == "":
        sig_lines.pop()
    if not sig_lines:
        raise ValueError("WIST3-E03: no signature line")
    if len(sig_lines) > CHECKPOINT_SIGNATURE_LINES_MAX:
        raise ValueError(
            f"WIST3-E03: note carries {len(sig_lines)} signature lines, over the "
            f"{CHECKPOINT_SIGNATURE_LINES_MAX} §5 admits")
    signatures = []
    for line in sig_lines:
        if not line.startswith("— "):
            raise ValueError("WIST3-E03: signature line missing the em-dash-space prefix")
        rest = line[2:]
        if " " not in rest:
            raise ValueError("WIST3-E03: malformed signature line")
        name, sig_b64 = rest.rsplit(" ", 1)
        if not name:
            raise ValueError("WIST3-E03: signature line with an empty key name")
        if "+" in name or any(ch in UNICODE_WHITE_SPACE for ch in name):
            raise ValueError(
                "WIST3-E03: key name carries a plus or a White_Space character")
        try:
            blob = base64.b64decode(sig_b64, validate=True)
        except Exception as e:
            raise ValueError(f"WIST3-E03: signature does not parse as base64: {e}")
        if base64.b64encode(blob).decode() != sig_b64:
            raise ValueError("WIST3-E03: signature blob is not canonical base64")
        if len(blob) < 5:
            raise ValueError("WIST3-E03: signature blob shorter than a 4-octet key ID plus a signature")
        signatures.append((name, blob[:4], blob[4:]))

    return {
        "origin": origin, "tree_size": tree_size, "root": root,
        "epoch_number": epoch_number, "sealed_at": sealed_at,
        "signed_bytes": (header + "\n").encode(), "signatures": signatures,
    }


def witness_key_id(name: str, raw_pub: bytes) -> bytes:
    """[tlog-cosignature]'s note key ID for a Witness key: the [signed-note]
    formula (WIST-3 §3.4) with type byte 0x04, not the Aggregator's 0x01 —
    computed independently of gen_vectors.py's identical formula."""
    return hashlib.sha256(name.encode() + b"\x0a\x04" + raw_pub).digest()[:4]


def verify_cosignature(raw_pub: bytes, note_text: bytes, blob: bytes) -> int:
    """[tlog-cosignature] cosignature/v1: verify a Witness cosignature line
    value against the Checkpoint's bare note text (WIST-3 §5's five lines,
    no signature block). Raises ValueError/InvalidSignature on any defect;
    returns the signed Unix timestamp on success."""
    if len(blob) != 76:
        raise ValueError("cosignature blob is not a canonical 4+8+64-octet key_id||time||signature")
    timestamp = int.from_bytes(blob[4:12], "big")
    message = b"cosignature/v1\ntime %d\n" % timestamp + note_text
    Ed25519PublicKey.from_public_bytes(raw_pub).verify(blob[12:], message)
    return timestamp


def verify_checkpoint(text: str, log_id: str, keys: dict, witness_keys: dict = None) -> dict:
    """WIST-3 §5: parse and authenticate a Checkpoint. `keys` maps a signer
    name to its raw Ed25519 Aggregator public key; `witness_keys`, if given,
    maps a trusted Witness name to its raw Ed25519 public key. A Checkpoint
    MUST carry a verifying signature under a known Aggregator key, keyed by
    the note key ID [signed-note] derives. A line naming a known key —
    Aggregator or trusted Witness — that fails to verify also rejects the
    whole Checkpoint ("WIST3-E03: ..."); every other line is ignored, as
    [signed-note] requires. Returns the parsed note plus `"cosigners"`, the
    names of every trusted Witness whose cosignature verified — the caller's
    own concern (quorum, WIST-4 §5 `checkpoint_witness_quorum`) is not
    decided here."""
    parsed = parse_checkpoint(text)
    if parsed["origin"] != log_id:
        raise ValueError("WIST3-E03: origin does not match the Log's log_id")
    verified = False
    cosigners = []
    for name, kid, rest in parsed["signatures"]:
        raw_pub = keys.get(name)
        if raw_pub is not None and note_key_id(name, raw_pub) == kid:
            if len(rest) != 64:
                raise ValueError("WIST3-E03: signature blob is not a canonical 4+64-octet key_id||signature")
            try:
                Ed25519PublicKey.from_public_bytes(raw_pub).verify(rest, parsed["signed_bytes"])
                verified = True
            except InvalidSignature:
                raise ValueError("WIST3-E03: signature under a known key does not verify")
            continue
        wraw = (witness_keys or {}).get(name)
        if wraw is not None and witness_key_id(name, wraw) == kid:
            try:
                verify_cosignature(wraw, parsed["signed_bytes"], kid + rest)
                cosigners.append(name)
            except (ValueError, InvalidSignature):
                raise ValueError("WIST3-E03: cosignature under a known Witness key does not verify")
    if not verified:
        raise ValueError("WIST3-E03: no verifying signature under a known key")
    parsed["cosigners"] = cosigners
    return parsed


def verify_consistency(m: int, n: int, m_root: bytes, n_root: bytes, path: list):
    """RFC 9162 §2.1.4.2 consistency-proof verification: reconstruct both
    `m_root` and `n_root` from `path`, independently of
    merkle.consistency_proof (which only *generates* a proof — used solely
    by the exhaustive gen-vs-verify property test below). Raises ValueError
    on a proof that does not reconstruct both roots. `m == 0` (the empty
    tree is a prefix of every tree) and `m == n` both require an empty
    `path` (WIST-3 §4). An empty proof exempts no root from comparison: the
    root reconstructed at size 0 is SHA-256("") (§4), so a stated size-0 root
    that is anything else fails here as any root mismatch does."""
    if not (0 <= m <= n):
        raise ValueError("require 0 <= m <= n")
    if m == 0 and m_root != hashlib.sha256(b"").digest():
        raise ValueError("the root reconstructed at size 0 is SHA-256(\"\")")
    if n == 0 and n_root != hashlib.sha256(b"").digest():
        raise ValueError("the root reconstructed at size 0 is SHA-256(\"\")")
    if m == 0 or m == n:
        if path:
            raise ValueError("a proof at m == 0 or m == n carries no nodes")
        if m == n and m_root != n_root:
            raise ValueError("equal sizes must share one root")
        return
    proof = list(path)
    node, last_node = m - 1, n - 1
    while node % 2 == 1:
        node //= 2
        last_node //= 2
    if node:
        if not proof:
            raise ValueError("consistency path exhausted")
        new_hash = old_hash = proof.pop(0)
    else:
        new_hash = old_hash = m_root
    while last_node:
        if node % 2 == 1:
            if not proof:
                raise ValueError("consistency path exhausted")
            nxt = proof.pop(0)
            old_hash = node_hash(nxt, old_hash)
            new_hash = node_hash(nxt, new_hash)
        elif node < last_node:
            if not proof:
                raise ValueError("consistency path exhausted")
            nxt = proof.pop(0)
            new_hash = node_hash(new_hash, nxt)
        node //= 2
        last_node //= 2
    if old_hash != m_root:
        raise ValueError("old root does not reconstruct")
    if new_hash != n_root:
        raise ValueError("new root does not reconstruct")
    if proof:
        raise ValueError("trailing consistency-path nodes")


def epoch_sealed_at(epoch: dict) -> str:
    """An Epoch's `sealed_at`, read from its Checkpoint's extension line
    (WIST-3 §3.1) rather than a per-Epoch header field, which no longer
    exists. Structural parse only (`parse_checkpoint`) - callers that need
    the Checkpoint's signature authenticated call `verify_checkpoint`."""
    return parse_checkpoint(epoch["checkpoint"])["sealed_at"]


def epoch_number(epoch: dict) -> int:
    """An Epoch's `epoch_number`, read from its Checkpoint (WIST-3 §3.1)."""
    return parse_checkpoint(epoch["checkpoint"])["epoch_number"]


def verify_inclusion(epoch, proof):
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

    `epoch` carries `tree_size` and `root` directly (as `vectors/wist3/epoch.json`
    does, and as the exhaustive property test below constructs synthetically)
    rather than a Checkpoint note - a caller that must authenticate a
    Checkpoint first calls `verify_checkpoint` and checks its `tree_size`/
    `root` against `epoch`'s before calling this.
    """
    idx, n, path = proof["index"], proof["tree_size"], proof["path"]
    assert 0 <= idx < n, "index out of range"
    assert n == epoch["tree_size"], "tree_size mismatch"
    h = leaf_hash(rfc8785.dumps(epoch["entries"][idx]))
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
    assert "sha256:" + h.hex() == epoch["root"], "root mismatch"

# 1. Schema validation: examples/<stem>.json <-> schemas/<stem>.schema.json
SCHEMA_REGISTRY = Registry().with_resources(
    (s["$id"], Resource.from_contents(s))
    for s in (json.loads(p.read_text()) for p in sorted((ROOT / "schemas").glob("*.schema.json"))))
EXAMPLE_SCHEMA = {"label-feed": "feed"}
for example in sorted((ROOT / "examples").glob("*.json")):
    schema_path = ROOT / "schemas" / f"{EXAMPLE_SCHEMA.get(example.stem, example.stem)}.schema.json"
    def _v(example=example, schema_path=schema_path):
        if not schema_path.exists():
            raise FileNotFoundError(f"no schema for {example.name}")
        schema = json.loads(schema_path.read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, registry=SCHEMA_REGISTRY).validate(json.loads(example.read_text()))
    check(f"schema:{example.name}", _v)

INNER_KEY = {
    "catalog.json": "catalog", "publisher.json": "publisher",
    "snapshot-manifest.json": "manifest",
    "snapshot-index.json": "index", "snapshot-state.json": "state",
    "registry-update.json": "update", "label.json": "label", "label-feed.json": "feed",
    "label-definition.json": "definition", "dispute.json": "dispute",
    "log-anchor.json": "anchor",
    "mirrors.json": "mirrors",
    "status.json": None,  # not a signed Envelope — plain JSON (WIST-2 §7.1)
    "payload.json": None,  # unsigned: its integrity comes from the Item's
                           # commitment, not from a signature (WIST-3 §6.1)
    "item.json": None,  # unsigned: the Catalog's root commits to it (WIST-1 §4)
    "publisher-item.json": None,  # unsigned: the Entry body a Checkpoint commits to (WIST-3 §3.3)
    "tree-file.json": None,  # unsigned JCS octets, named by their SHA-256 (WIST-1 §4)
    "emission.json": None,  # unsigned: a stream line never leaves the Publisher (WIST-5 §1)
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

# 2. WIST-1 vectors: recompute the Catalog's ID and signature and the Item's
# ID, key, leaf and root against the worked example
wist1 = ROOT / "vectors" / "wist1"
if (wist1 / "envelope.json").exists():
    def _dc1():
        env = json.loads((wist1 / "envelope.json").read_text())
        assert env == json.loads((ROOT / "examples" / "catalog.json").read_text()), \
            "the vector Envelope differs from examples/catalog.json"
        keys = json.loads((wist1 / "keypair.json").read_text())
        catalog = env["catalog"]
        canonical = rfc8785.dumps(catalog)
        assert canonical == (wist1 / "catalog.canonical").read_bytes(), "canonical bytes mismatch"
        catalog_id = "sha256:" + hashlib.sha256(canonical).hexdigest()
        assert catalog_id == (wist1 / "id.txt").read_text().strip(), "Catalog ID mismatch"
        assert env["sig"]["key_id"] == keys["kid"], "the Envelope is not signed under the vector key"
        pub = Ed25519PublicKey.from_public_bytes(b64u_decode(keys["public_key"]))
        pub.verify(b64u_decode(env["sig"]["value"]), canonical)

        item = json.loads((ROOT / "examples" / "item.json").read_text())
        item_octets = rfc8785.dumps(item)
        assert item_rules.item_id(item) == "sha256:" + hashlib.sha256(item_octets).hexdigest()
        key = hashlib.sha256(rfc8785.dumps(["page", item["url"]])).digest()
        assert key == item_rules.item_key(item["url"]), "Item key mismatch"
        leaf = hashlib.sha256(b"\x00" + key + hashlib.sha256(item_octets).digest()).digest()
        assert leaf == item_rules.leaf(item), "Item leaf mismatch"
        assert catalog["size"] == 1 and catalog["root"] == "sha256:" + leaf.hex(), \
            "a one-Item root is not that Item's leaf"
        assert catalog["root"] == item_rules.root_string([item])

        tree_octets = (ROOT / "examples" / "tree-file.json").read_bytes()
        assert catalog["tree"] == "sha256:" + hashlib.sha256(tree_octets).hexdigest(), \
            "tree does not name the root tree file"
        assert tree_octets == rfc8785.dumps({"items": [item]}), \
            "the root tree file is not the JCS octets of the bucket listing the Item"
        payload = json.loads((ROOT / "examples" / "payload.json").read_text())
        content = rfc8785.dumps(payload["content"])
        assert len(content) == item["payload"]["bytes"]
        assert item["payload"]["commitment"] == "hmac-sha256:" + hmac.new(
            b64u_decode(payload["salt"]), content, hashlib.sha256).hexdigest()
        assert catalogs.catalog_disposition(
            env, json.loads((ROOT / "examples" / "publisher.json").read_text())["publisher"],
            catalog["generated_at"]) == "accepted"
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
    schema = json.loads((ROOT / "schemas" / "item.schema.json").read_text())
    url_schema = schema["oneOf"][0]["properties"]["url"]
    assert url_schema.get("maxLength") == cap, \
        f"a page Item's url carries no maxLength {cap} first-pass bound"
    url = json.loads((ROOT / "examples" / "item.json").read_text())["url"]
    assert len(rfc8785.dumps(url)) <= cap, "example url exceeds url_cap_bytes octets"
    assert len(rfc8785.dumps("https://a.b/")) == 14, "published floor (14) drifted"

check("spec:url-octet-bound", _url_bound)

def _url_bound_twin():
    """Mutation twin: an over-long URL must fail schema validation, and fail
    it *on the length bound* — a rejection by any other keyword would leave
    the octet cap itself unexercised."""
    cap = _registry_table_defaults()["url_cap_bytes"]
    schema = json.loads((ROOT / "schemas" / "item.schema.json").read_text())
    item = json.loads((ROOT / "examples" / "item.json").read_text())
    item["url"] = "https://example.com/" + "a" * (cap + 52)
    try:
        Draft202012Validator(schema["oneOf"][0] | {"$defs": schema["$defs"]}).validate(item)
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
    item = json.loads((ROOT / "examples" / "item.json").read_text())
    assert item["payload"]["bytes"] == content_octets, \
        "declared bytes != JCS(content) octets"
    schema = json.loads((ROOT / "schemas" / "item.schema.json").read_text())
    assert schema["oneOf"][0]["properties"]["payload"]["properties"]["bytes"][
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
    fixture1 = next(c for c in vec["cases"] if c["label"] == "example-item-page-links")
    assert fixture1["expected"] == _FIXTURE1_EXPECTED, \
        "fixture 1's expected member is not the hand-pinned 3-URL set"
    cap = vec["links_cap_bytes"]
    # The shortest Normalized URL that can exist (WIST-1 §2).
    shortest_entry = len(rfc8785.dumps("https://a.b/"))
    assert shortest_entry == 14, "JCS of the shortest Normalized URL is not 14 octets"
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
    its inputs by the section's procedure."""
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
    than generated_at, then the first Epoch sealed after it that seals one;
    where an Epoch seals several, the highest seq's, as WIST-1 §5.2 resolves
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
            "**first** Epoch sealed after `generated_at` that seals an applicable Declaration of the domain",
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
    same_epoch = next(c for c in v["cases"] if c["name"] == "two rotations sealed in one epoch")
    lowest = min((d for d in same_epoch["declarations"] if d["sealed_at_s"] == 200), key=lambda d: d["seq"])
    for pg in same_epoch["pages"]:
        _, _, under = _page_keyset_resolve(same_epoch["declarations"], pg["generated_at_s"], pg["signer"])
        assert (pg["signer"] in lowest["keys"]) == (under is None), \
            "recomputation reads the lowest seq of an Epoch rather than its Key Set"
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
    expected = {"aggregator_key", "declaration", "pending_declaration", "parameter",
                "recovery_window", "suffix_list", "withdrawal", "label", "dispute", "record",
                "collection", "removal", "registry_update"}
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
    validator.validate(good)
    kinds = [t[0] for t in good["state"]["entries"]]
    record = kinds.index("record")
    for label, mutate in (
            ("over-arity record tuple", lambda e: e[record].append("extra-member")),
            ("record tuple carrying an Item ID in place of the Item",
             lambda e: e.__setitem__(record, e[record][:3] + ["sha256:" + "0" * 64])),
            ("record tuple without the Catalog's generated_at", lambda e: e[record].pop()),
            ("collection tuple without its sealing height", lambda e: e[kinds.index("collection")].pop()),
            ("removal tuple carrying the removed Item in place of its ID",
             lambda e: e[kinds.index("removal")].__setitem__(3, {"removed": True}))):
        bad = copy.deepcopy(good)
        mutate(bad["state"]["entries"])
        try:
            validator.validate(bad)
        except ValidationError:
            continue
        raise AssertionError(f"{label} validated")
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
    w1 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-item-format.md").read_text())
    w3 = re.sub(r"\s+", " ",
                (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    w4 = re.sub(r"\s+", " ",
                (ROOT / "specs" / "WIST-4-governance.md").read_text())
    assert "Every queued Catalog is judged again by C1 (WIST-3 §3.3) under the settlement source" in w1
    assert w1.count("WIST1-E13") >= 2, "E13 must appear in §5.2 and the §7 registry"
    assert ("`recovery_window`: for a Catalog or an Item, a recovery window of the "
            "Publisher open at the Epoch") in w3, "WIST-3 §3.3 needs the recovery deferral"
    assert "the deferrals that move it and the ceiling with it" in w4, \
        "the §5 ceiling needs to move with WIST-3 §3.3's deferrals"

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
    codes are gone, and a rejected act never invalidates its Epoch."""
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
    assert "never invalidates the containing Epoch" in re.sub(r"\s+", " ", w4)

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
    ("a numeric reference in non-ASCII decimal digits is not decoded, and the fragment its # opens holds non-ASCII digits, so the candidate has no Normalized URL",
     ('<a href="https://example.org/x?y=&#٦٥;z">t</a>'
      .encode("utf-8")), []),
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
# make that assertion. Paths are ROOT-relative: `examples/item.json` and
# `vectors/wist3/epoch.json` are different locations and are declared separately.
COVERAGE_ASSERTED = {"payload:commitment"}

SALTED_COMMITMENTS = {          # (schema file, JSON path) -> proving check
    ("item.schema.json",
     "oneOf[0]/properties/payload/properties/commitment"): "payload:commitment",
}

SALTED_COMMITMENT_VALUES = {
    # (ROOT-relative file, key) -> proving check
    ("examples/item.json", "commitment"): "payload:commitment",
    ("examples/tree-file.json", "commitment"): "payload:commitment",
    ("vectors/wist1/payload-fields.json", "commitment"): "payload:commitment",
    ("vectors/wist1/payload-links.json", "commitment"): "payload:commitment",
    ("vectors/wist3/epoch.json", "commitment"): "payload:commitment",
    ("vectors/wist3/checkpoints.json", "commitment"): "payload:commitment",
    ("vectors/wist1/declaration-fields.json", "commitment"): "payload:commitment",
    ("vectors/multilog/dedup.json", "commitment"): "payload:commitment",
    ("vectors/wist1/item-fields.json", "commitment"): "payload:commitment",
    ("vectors/wist1/item-roots.json", "commitment"): "payload:commitment",
    ("vectors/wist2/item-lists.json", "commitment"): "payload:commitment",
    ("vectors/wist3/catalog-sealing.json", "commitment"): "payload:commitment",
    ("vectors/multilog/catalog-order.json", "commitment"): "payload:commitment",
    ("vectors/wist3/catalog-waiting.json", "commitment"): "payload:commitment",
    ("vectors/wist1/catalog-recovery.json", "commitment"): "payload:commitment",
    ("vectors/wist2/collection-pull.json", "commitment"): "payload:commitment",
    ("vectors/wist2/change-lists.json", "commitment"): "payload:commitment",
    ("vectors/wist2/change-list-serving.json", "commitment"): "payload:commitment",
    ("vectors/wist2/change-chains.json", "commitment"): "payload:commitment",
    ("examples/snapshot-state.json", "commitment"): "payload:commitment",
    ("examples/publisher-item.json", "commitment"): "payload:commitment",
    ("vectors/wist3/snapshot-records.json", "commitment"): "payload:commitment",
    ("vectors/wist3/record-materialization.json", "commitment"): "payload:commitment",
    ("vectors/wist3/timestamps.json", "commitment"): "payload:commitment",
    ("vectors/wist4/withdrawal.json", "commitment"): "payload:commitment",
}

CATALOG_COMMITMENT_FILES = ("vectors/wist1/item-fields.json", "vectors/wist1/item-roots.json",
                            "vectors/wist2/item-lists.json", "vectors/wist3/catalog-sealing.json",
                            "vectors/multilog/catalog-order.json", "vectors/wist3/catalog-waiting.json",
                            "vectors/wist1/catalog-recovery.json", "vectors/wist2/collection-pull.json",
                            "vectors/wist2/change-lists.json", "vectors/wist2/change-list-serving.json",
                            "vectors/wist2/change-chains.json", "vectors/wist3/epoch.json",
                            "vectors/wist3/checkpoints.json", "vectors/wist3/snapshot-records.json",
                            "vectors/wist3/record-materialization.json", "vectors/wist4/withdrawal.json")

def _carried_payload_commitments(node):
    found = set()
    if isinstance(node, dict):
        if isinstance(node.get("salt"), str) and isinstance(node.get("content"), dict):
            found.add(_commit(node["salt"], node["content"]))
        for value in node.values():
            found |= _carried_payload_commitments(value)
    elif isinstance(node, list):
        for value in node:
            found |= _carried_payload_commitments(value)
    return found

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

    `properties/item/properties/payload/properties/commitment` names instances
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

# 2b. The payload commitment: the only thing binding an Item to content that
# the Log does not carry. Everything downstream — the audit metric, snapshot
# materialization, the withdrawal guarantee — rests on this recomputation.
def _load_payload_and_item():
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    item = json.loads((ROOT / "examples" / "item.json").read_text())
    return payload, item

def _commit(salt_b64: str, content: dict) -> str:
    return "hmac-sha256:" + hmac.new(
        b64u_decode(salt_b64), rfc8785.dumps(content), hashlib.sha256).hexdigest()

def _multilog_commitment():
    v = json.loads((ROOT / "vectors" / "multilog" / "dedup.json").read_text())
    got = _commit(v["payload"]["salt"], v["payload"]["content"])
    assert got == v["item"]["payload"]["commitment"], \
        "the multi-Log vector's Payload does not reproduce its Item's commitment"
    return got

def _payload_commitment():
    payload, item = _load_payload_and_item()
    assert item["payload"]["alg"] == "HMAC-SHA256", "commitment algorithm is not HMAC-SHA256"
    assert len(b64u_decode(payload["salt"])) >= 16, "salt is shorter than 128 bits (WIST-1 §3.6)"
    expected = _commit(payload["salt"], payload["content"])
    assert expected == item["payload"]["commitment"], \
        "the Payload does not reproduce the Item's commitment"
    recomputed = {expected, _multilog_commitment()}
    link_vectors = json.loads((ROOT / "vectors/wist1/payload-links.json").read_text())
    for case in link_vectors["cases"]:
        content = case["payload"]
        actual = _commit(content["salt"], content["content"])
        assert actual == case["item"]["payload"]["commitment"]
        recomputed.add(actual)
    field_vectors = json.loads((ROOT / "vectors/wist1/payload-fields.json").read_text())
    for case in field_vectors["cases"]:
        preimage = case["preimage"]
        actual = _commit(preimage["salt"], preimage["content"])
        assert actual == case["item"]["payload"]["commitment"]
        recomputed.add(actual)
    for rel in CATALOG_COMMITMENT_FILES:
        recomputed |= _carried_payload_commitments(json.loads((ROOT / rel).read_text()))

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
    payload, item = _load_payload_and_item()
    content = payload["content"]
    n = len(rfc8785.dumps(content))
    assert item["payload"]["bytes"] == n, \
        f"the Item declares {item['payload']['bytes']} octets, JCS(content) is {n}"

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

    schema = json.loads((ROOT / "schemas" / "item.schema.json").read_text())
    declared = schema["oneOf"][0]["properties"]["payload"][
        "properties"]["bytes"]["maximum"]
    assert declared == combined, (
        f"item.schema.json bounds payload.bytes at {declared}, but "
        f"{e_cap} + {lk_cap} + {s_cap} + {wrapper} = {combined} (WIST-1 §3.6)")
    spec = (ROOT / "specs" / "WIST-1-item-format.md").read_text()
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
    payload, item = _load_payload_and_item()
    committed = item["payload"]["commitment"]
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
if (wist3 / "epoch.json").exists():
    def _dc3():
        epoch = json.loads((wist3 / "epoch.json").read_text())
        leaves = [leaf_hash(rfc8785.dumps(e)) for e in epoch["entries"]]
        level = leaves[:]
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    nxt.append(node_hash(level[i], level[i + 1]))
                else:
                    nxt.append(level[i])
            level = nxt
        root = level[0] if level else hashlib.sha256(b"").digest()
        assert "sha256:" + root.hex() == epoch["root"], "merkle root mismatch"
        assert epoch["leaf_hashes"] == [h.hex() for h in leaves], "leaf_hashes are not the Entries' leaf hashes"
        cp = verify_checkpoint(epoch["checkpoint"], epoch["log_id"],
                               {epoch["log_id"]: load_test_pubkey()})
        assert cp["root"] == root, "checkpoint root does not match the recomputed tree"
        assert cp["tree_size"] == epoch["tree_size"] == len(leaves), "tree_size mismatch"
        proof = json.loads((wist3 / "inclusion-proof.json").read_text())
        verify_inclusion(epoch, proof)
    check("vectors:wist3", _dc3)

def _epoch_checks():
    """WIST-3 §5: the example Checkpoint is bound to the example Epoch and
    verifies under the Anchor's genesis key."""
    checkpoint_text = (ROOT / "examples" / "checkpoint.txt").read_text()
    anchor_env = json.loads((ROOT / "examples" / "log-anchor.json").read_text())
    anchor = anchor_env["anchor"]
    log_id = anchor["log_id"]
    genesis_pub = b64u_decode(anchor["genesis_key"]["public_key"])
    Ed25519PublicKey.from_public_bytes(genesis_pub).verify(
        b64u_decode(anchor_env["sig"]["value"]), rfc8785.dumps(anchor))
    cp = verify_checkpoint(checkpoint_text, log_id, {log_id: genesis_pub})
    epoch = json.loads((ROOT / "vectors" / "wist3" / "epoch.json").read_text())
    assert epoch["log_id"] == log_id, "the example Epoch is not this Anchor's Log"
    assert checkpoint_text == epoch["checkpoint"], \
        "examples/checkpoint.txt is not the example Epoch's Checkpoint"
    assert cp["tree_size"] == len(epoch["entries"]) == epoch["tree_size"], "tree_size mismatch"
    assert cp["epoch_number"] == 0, "the example Checkpoint is not Epoch 0's"
check("checkpoint+binding+treesize", _epoch_checks)

def _snapshot_directory(manifest_inner):
    """WIST-3 §6: /snapshots/<snapshot_date>/<epoch_number>/, the Epoch zero-padded to nine digits."""
    return "/snapshots/%s/%09d/" % (manifest_inner["snapshot_date"], manifest_inner["epoch_number"])


def _shard_of(domain, count):
    """WIST-3 §7: first 8 octets of SHA-256(UTF-8 of the domain), big-endian, mod count."""
    return int.from_bytes(hashlib.sha256(domain.encode()).digest()[:8], "big") % count


RECORD_FIELDS = ["url", "publisher", "item_id", "observed_at", "attested_at"]

def _content_digest(records):
    """WIST-3 §7: SHA-256 over the ascending-octet-order concatenation of JCS."""
    return "sha256:" + hashlib.sha256(
        b"".join(sorted(rfc8785.dumps(r) for r in records))).hexdigest()

def _content_tuples_from_state(v):
    example_state = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
    state = example_state["state"]["entries"]
    declarations = {"example.com": json.loads((ROOT / "examples" / "publisher.json").read_text())}
    declarations.update(v["declarations"])
    collections_held = {(t[1], t[2]): t for t in v["tuples"] if t[0] == "collection"}
    validator = Draft202012Validator(json.loads((ROOT / "schemas" / "snapshot-state.schema.json").read_text()))
    validator.validate(dict(example_state, state=dict(example_state["state"], entries=v["tuples"])))
    manifest = json.loads((ROOT / "examples" / "snapshot-manifest.json").read_text())["manifest"]
    for t in v["tuples"]:
        if t[1] == "example.com":
            assert t in state, "example.com's tuples are not those of examples/snapshot-state.json"
        if t[0] == "collection":
            assert t[4] <= manifest["epoch_number"], "a latest Catalog sealed above the Snapshot's Epoch"
    out = []
    for t in v["tuples"]:
        if t[0] != "record":
            continue
        _, publisher, url, item, collection, catalog_id, attested_at = t
        held = collections_held[(publisher, collection)][3]
        catalog = held["catalog"]
        assert "sha256:" + hashlib.sha256(rfc8785.dumps(catalog)).hexdigest() == catalog_id, \
            "the record's Catalog ID is not the collection tuple's Catalog"
        assert catalog["generated_at"] == attested_at and catalog["publisher"] == publisher
        keys = {e["kid"]: e for e in declarations[publisher]["publisher"]["keys"]}
        Ed25519PublicKey.from_public_bytes(b64u_decode(keys[held["sig"]["key_id"]]["x"])).verify(
            b64u_decode(held["sig"]["value"]), rfc8785.dumps(catalog))
        item_octets = rfc8785.dumps(item)
        key = hashlib.sha256(rfc8785.dumps(["page", item["url"]])).digest()
        leaf = hashlib.sha256(b"\x00" + key + hashlib.sha256(item_octets).digest()).digest()
        assert catalog["size"] == 1 and catalog["root"] == "sha256:" + leaf.hex(), \
            "the record's Item is not the one Item of its Catalog"
        item_id = "sha256:" + hashlib.sha256(item_octets).hexdigest()
        payload = v["payloads"][item_id]
        assert _commit(payload["salt"], payload["content"]) == item["payload"]["commitment"]
        assert len(rfc8785.dumps(payload["content"])) == item["payload"]["bytes"]
        assert item["url"] == url and item["publisher"] == publisher
        out.append({"url": url, "publisher": publisher, "item_id": item_id,
                    "observed_at": item["observed_at"], "attested_at": attested_at})
    return out

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
    assert records == _content_tuples_from_state(v), \
        "the content tuples are not those §7 derives from the record and collection tuples"
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
    for field in ("snapshot_date", "tree_size", "content_digest"):
        assert entry[field] == manifest[field], \
            f"the index entry's {field} disagrees with the manifest it names"
    assert entry["manifest_url"] == _snapshot_directory(manifest) + "manifest.json", \
        "the index entry does not name the §6 directory of its Snapshot's date and Epoch"
    dates = [s["snapshot_date"] for s in index["snapshots"]]
    assert dates == sorted(dates, reverse=True), "the index is not newest first"

    # `root_hash` binds the Snapshot to one chain (§7, §8): it is the
    # root hash of the tree at `tree_size` (WIST-3 §3.1), independently
    # of the `epoch_number`/`tree_size` distinction §7's schema draws.
    epoch = json.loads((ROOT / "vectors" / "wist3" / "epoch.json").read_text())
    assert manifest["tree_size"] == epoch["tree_size"], \
        "the example manifest is not positioned at the example Epoch's tree size"
    assert manifest["root_hash"] == epoch["root"], \
        "root_hash is not the root hash at tree_size"

    # No page content in the preimage. Withdrawal destroys the Payload and its
    # salt (§6.2); a digest that needed either could never be recomputed after
    # one, so this asserts the preimage against the actual Payload text rather
    # than against the field names alone.
    forbidden = [text for payload in v["payloads"].values()
                 for text in (payload["content"]["extract"], payload["content"]["summary"]["title"],
                              payload["content"]["summary"]["abstract"], payload["salt"])]
    preimage = b"".join(sorted(rfc8785.dumps(r) for r in records)).decode()
    for text in forbidden:
        assert text not in preimage, \
            f"content reached the content_digest preimage: {text[:32]!r}"

    for field, other in (("url", "https://example.com/blog/post-9"),
                         ("publisher", "other.example.com"),
                         ("item_id", "sha256:" + "0" * 64),
                         ("observed_at", "2026-08-02T12:00:01Z"),
                         ("attested_at", "2026-08-02T12:00:01Z")):
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
    item = json.loads((ROOT / "examples" / "item.json").read_text())
    expected = [
        {"source_url": item["url"], "target_url": u, "position": i}
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


SHARD_TIER_FILES = ["tier0/index.sqlite", "tier1/extracts.parquet", "tier1/links.parquet",
                    "tier1/labels.parquet", "tier1/disputes.parquet", "tier1/labelers.parquet"]


def _assert_sharded_section(vec):
    sharded, records = vec["sharded"], vec["records"]
    count = sharded["count"]
    assert count >= 2 and len(sharded["digests"]) == count, "digests is not one per shard"
    for domain, index in sharded["shard_of"].items():
        assert index == _shard_of(domain, count), f"{domain}: shard_of != §7's domain rule"
    for i in range(count):
        held = [r for r in records if _shard_of(r["publisher"], count) == i]
        assert _content_digest(held) == sharded["digests"][i], \
            f"shard {i}: digest != content_digest over its records"
    assert _content_digest(records) == vec["content_digest"], "the whole-set digest changed"
    expected_files = [{"path": f"shard-{i}/{path}", "tier": 0 if path.startswith("tier0/") else 1,
                       "shard": i} for i in range(count) for path in SHARD_TIER_FILES]
    assert sharded["files"] == expected_files, "files != shard-<i>/ paths of the six tier files"
    for row in sharded["label_rows"] + sharded["labeler_rows"]:
        assert row["shard"] == _shard_of(row["labeler"], count), \
            f"a label or labeler row of {row['labeler']} is not in the Labeler's shard"
    for row in sharded["dispute_rows"]:
        assert row["shard"] == _shard_of(row["disputant"], count), \
            f"a dispute row of {row['disputant']} is not in the disputant's shard"
    subject_hosts = {re.sub(r"^https?://([^/]+).*$", r"\1", row["subject"]) for row in sharded["label_rows"]}
    assert any(_shard_of(h, count) != _shard_of(r["labeler"], count)
               for h in subject_hosts for r in sharded["label_rows"]
               if re.sub(r"^https?://([^/]+).*$", r"\1", r["subject"]) == h), \
        "no Label row separates the Labeler's shard from the subject Publisher's"


def _snapshot_sharding():
    """WIST-3 §7 sharding: the per-shard digests, the shard-<i>/ file layout and
    the shard each Label, labeler and dispute row is filed under, recomputed from
    the records and the domain rule."""
    vec = json.loads((ROOT / "vectors" / "wist3" / "snapshot-records.json").read_text())
    _assert_sharded_section(vec)

check("spec:snapshot-sharding", _snapshot_sharding)


def _snapshot_sharding_twin():
    """Mutation twin: a Label row moved to its subject's Publisher's shard must
    fail on the Labeler rule; a record moved across shards must fail its digest."""
    vec = json.loads((ROOT / "vectors" / "wist3" / "snapshot-records.json").read_text())
    count = vec["sharded"]["count"]
    moved = json.loads(json.dumps(vec))
    row = next(r for r in moved["sharded"]["label_rows"] if r["labeler"] == "example.com")
    row["shard"] = _shard_of("reduced.example.org", count)
    assert row["shard"] != _shard_of("example.com", count), "the twin's move is a no-op"
    try:
        _assert_sharded_section(moved)
    except AssertionError as e:
        assert "not in the Labeler's shard" in str(e), f"rejected, but not by its target rule: {e}"
    else:
        raise AssertionError("a Label row in its subject's shard passed — the check is blind")
    swapped = json.loads(json.dumps(vec))
    swapped["sharded"]["digests"] = swapped["sharded"]["digests"][::-1]
    try:
        _assert_sharded_section(swapped)
    except AssertionError as e:
        assert "digest != content_digest over its records" in str(e), \
            f"rejected, but not by its target rule: {e}"
        return
    raise AssertionError("reversed per-shard digests passed — the check is blind")

check("negative:snapshot-sharding", _snapshot_sharding_twin)



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

def _record_vector():
    return json.loads((ROOT / "vectors" / "wist3" / "record-materialization.json").read_text())

_RECORD_PAYLOADS = {}

def _record_payloads():
    if not _RECORD_PAYLOADS:
        _RECORD_PAYLOADS.update(_record_vector()["payloads"])
    return _RECORD_PAYLOADS

def _url_host(url):
    return re.match(r"https://([^/:?#]+)", url).group(1)

def _item_id(item):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(item)).hexdigest()

def _record_empty():
    return {"records": {}, "removals": {}, "withdrawn": {}, "declared": set()}

def _record_apply(state, epoch, **variant):
    for e in epoch["events"]:
        kind = e["event"]
        if kind == "declaration":
            state["declared"].add(e["domain"])
        elif kind == "narrowing":
            for url in e["urls"]:
                held = state["records"].pop((e["publisher"], url))
                if variant.get("narrowing_leaves_removal"):
                    state["removals"][(e["publisher"], url)] = {
                        "item": held["item_id"], "catalog": held["catalog"], "generated_at": held["generated_at"]}
        elif kind == "withdrawal":
            state["withdrawn"].setdefault(e["item"], epoch["height"])
            if variant.get("withdrawal_removes"):
                for slot in [k for k, r in state["records"].items() if r["item_id"] == e["item"]]:
                    del state["records"][slot]
        elif kind == "base":
            for slot in [k for k, r in state["records"].items()
                         if k[0] == e["publisher"] and r["collection"] == e["collection"]]:
                del state["records"][slot]
            if variant.get("base_clears_removals"):
                for slot in [k for k in state["removals"] if k[0] == e["publisher"]]:
                    del state["removals"][slot]
        elif kind == "record":
            item = e["item"]
            assert item["publisher"] == e["publisher"], "a record of another Publisher's Item"
            slot = (e["publisher"], item["url"])
            state["records"][slot] = {"item": item, "item_id": _item_id(item), "collection": e["collection"],
                                      "catalog": e["catalog"], "generated_at": e["generated_at"]}
            if not variant.get("removal_survives_record"):
                state["removals"].pop(slot, None)
        else:
            assert kind == "removal", kind
            slot = (e["publisher"], e["url"])
            assert slot in state["records"], "an Item of kind removed with no record (I7)"
            del state["records"][slot]
            state["removals"][slot] = {"item": e["item"], "catalog": e["catalog"], "generated_at": e["generated_at"]}

def _record_outcome(state, height, **variant):
    by_url = {}
    for (publisher, url), held in state["records"].items():
        if variant.get("ignore_withdrawals") or held["item_id"] not in state["withdrawn"]:
            by_url.setdefault(url, {})[publisher] = held
    materialized = []
    for url, held in by_url.items():
        host = _url_host(url)
        declared = host in state["declared"] and not variant.get("ignore_self_declaration")
        chosen = _materialization_preference(host, declared, list(held))
        if chosen is not None:
            r = held[chosen]
            materialized.append({"url": url, "publisher": chosen, "item_id": r["item_id"],
                                 "observed_at": r["item"]["observed_at"], "attested_at": r["generated_at"]})
    order = lambda row: (row["publisher"].encode(), row["url"].encode())
    records = [{"publisher": p, "url": u, "item": r["item_id"], "collection": r["collection"],
                "catalog": r["catalog"], "generated_at": r["generated_at"]} for (p, u), r in state["records"].items()]
    removals = [{"publisher": p, "url": u, **r} for (p, u), r in state["removals"].items()]
    if variant.get("url_first_order"):
        materialized.sort(key=lambda row: (row["url"].encode(), row["publisher"].encode()))
    else:
        materialized.sort(key=order)
    links = [{"source_url": row["url"], "target_url": target, "position": position}
             for row in materialized
             for position, target in enumerate(_record_payloads()[row["item_id"]]["content"]["links"]["urls"])]
    if variant.get("links_by_target"):
        links.sort(key=lambda row: (row["source_url"].encode(), row["target_url"].encode()))
    return {"height": height, "records": sorted(records, key=order), "removals": sorted(removals, key=order),
            "materialized": materialized, "links": links, "content_digest": _content_digest(materialized)}

def _record_resumed(tuples, **variant):
    state = _record_empty()
    for t in tuples:
        if t[0] == "declaration":
            assert t[2]["publisher"]["domain"] == t[1]
            state["declared"].add(t[1])
        elif t[0] == "collection":
            assert (t[3]["catalog"]["publisher"], t[3]["catalog"]["collection"]) == (t[1], t[2])
        elif t[0] == "record":
            assert t[3]["publisher"] == t[1] and t[3]["url"] == t[2] and "payload" in t[3]
            state["records"][(t[1], t[2])] = {"item": t[3], "item_id": _item_id(t[3]), "collection": t[4],
                                              "catalog": t[5], "generated_at": t[6]}
        elif t[0] == "removal":
            state["removals"][(t[1], t[2])] = {"item": t[3], "catalog": t[4], "generated_at": t[5]}
        elif t[0] == "withdrawal" and not variant.get("resume_without_withdrawals"):
            state["withdrawn"][t[1]] = t[3]
    if variant.get("resume_from_content_tuples"):
        kept = {(r["publisher"], r["url"]) for r in _record_outcome(state, 0)["materialized"]}
        state["records"] = {k: r for k, r in state["records"].items() if k in kept}
    return state

def _record_case_outcomes(case, **variant):
    state, outcomes = _record_empty(), []
    for epoch in case["epochs"]:
        _record_apply(state, epoch, **variant)
        outcomes.append(_record_outcome(state, epoch["height"], **variant))
    resumed = None
    if "snapshot" in case:
        height = case["snapshot"]["height"]
        live = _record_resumed(case["snapshot"]["tuples"], **variant)
        resumed = [_record_outcome(live, height, **variant)]
        for epoch in case["epochs"][height + 1:]:
            _record_apply(live, epoch, **variant)
            resumed.append(_record_outcome(live, epoch["height"], **variant))
    return outcomes, resumed

def _record_snapshot_tuples(case):
    height = case["snapshot"]["height"]
    state = _record_empty()
    publishers = {}
    for epoch in case["epochs"][:height + 1]:
        _record_apply(state, epoch)
        for e in epoch["events"]:
            if e["event"] == "record":
                publishers[_item_id(e["item"])] = e["publisher"]
    tuples = case["snapshot"]["tuples"]
    validator = Draft202012Validator(json.loads((ROOT / "schemas" / "snapshot-state.schema.json").read_text()))
    example = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
    validator.validate(dict(example, state=dict(example["state"], entries=tuples)))
    records = sorted(rfc8785.dumps(["record", p, u, r["item"], r["collection"], r["catalog"], r["generated_at"]])
                     for (p, u), r in state["records"].items())
    assert records == sorted(rfc8785.dumps(t) for t in tuples if t[0] == "record"), \
        "the Snapshot's record tuples are not every record the Log holds"
    removals = sorted(rfc8785.dumps(["removal", p, u, r["item"], r["catalog"], r["generated_at"]])
                      for (p, u), r in state["removals"].items())
    assert removals == sorted(rfc8785.dumps(t) for t in tuples if t[0] == "removal")
    withdrawals = sorted(rfc8785.dumps(["withdrawal", i, publishers[i], h]) for i, h in state["withdrawn"].items())
    assert withdrawals == sorted(rfc8785.dumps(t) for t in tuples if t[0] == "withdrawal")
    accepted = {}
    for epoch in case["epochs"][:height + 1]:
        for e in epoch["events"]:
            if e["event"] == "withdrawal":
                accepted.setdefault(e["update"], epoch["height"])
    assert sorted(rfc8785.dumps(["registry_update", i, h]) for i, h in accepted.items()) == \
        sorted(rfc8785.dumps(t) for t in tuples if t[0] == "registry_update"), \
        "the Snapshot's registry_update tuples are not one per accepted Registry Update"
    assert {t[1] for t in tuples if t[0] == "declaration"} == state["declared"]
    return state

def _dc3_record_materialization():
    v = _record_vector()
    seen = collections.Counter()
    for case in v["cases"]:
        outcomes, resumed = _record_case_outcomes(case)
        assert outcomes == case["expected"], f"{case['name']}: recomputed state differs from the vector's"
        for epoch in case["epochs"]:
            kinds = [e["event"] for e in epoch["events"]]
            seen.update(set(kinds))
            same_epoch = {e["item"] for e in epoch["events"] if e["event"] == "withdrawal"} & \
                {_item_id(e["item"]) for e in epoch["events"] if e["event"] == "record"}
            seen["withdrawal in the Item's own Epoch"] += bool(same_epoch)
        if "snapshot" in case:
            height = case["snapshot"]["height"]
            at_snapshot = _record_snapshot_tuples(case)
            assert resumed == case["expected"][height:], f"{case['name']}: the resumed Consumer diverges"
            shown = {(r["publisher"], r["url"]) for r in case["expected"][height]["materialized"]}
            later = {(r["publisher"], r["url"]) for e in case["expected"][height + 1:] for r in e["materialized"]}
            seen["an unmaterialized record materialized after the resume"] += bool(
                (set(at_snapshot["records"]) - shown) & later)
    for needed in ("record", "removal", "narrowing", "base", "withdrawal", "declaration",
                   "withdrawal in the Item's own Epoch", "an unmaterialized record materialized after the resume"):
        assert seen[needed], f"no case carries {needed}"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    for marker in ("a record that narrowing or a base removed leaves no removal state",
                   "A removal state stays through narrowing and through a base, and ends when a valid Item of kind `page` becomes the URL's record",
                   "A withdrawal (§6.2) removes no record",
                   "a record the one-URL rule does not materialize and one whose Item a withdrawal names included",
                   "Of the records of one URL whose Item no withdrawal sealed at or below the height names, one is **materialized**"):
        assert marker in prose, f"WIST-3 §7 no longer states: {marker}"
check("vectors:wist3-record-materialization", _dc3_record_materialization)

def _dc3_record_materialization_twin():
    v = _record_vector()
    for variant in ("narrowing_leaves_removal", "withdrawal_removes", "base_clears_removals",
                    "removal_survives_record", "ignore_withdrawals", "ignore_self_declaration",
                    "resume_without_withdrawals", "resume_from_content_tuples", "url_first_order",
                    "links_by_target"):
        moved = False
        for case in v["cases"]:
            try:
                outcomes, resumed = _record_case_outcomes(case, **{variant: True})
            except (AssertionError, KeyError):
                moved = True
                continue
            height = case.get("snapshot", {}).get("height")
            moved |= outcomes != case["expected"] or (
                resumed is not None and resumed != case["expected"][height:])
        assert moved, f"the {variant} reading reproduces every expected value"
check("negative:wist3-record-materialization", _dc3_record_materialization_twin)


def _sealing_duties(history, window_from_removal=False):
    ends, info, withdrawn, out, previous, held_before = {}, {}, set(), [], [], set()
    for epoch, expected in zip(history["epochs"], history["expected"]):
        if expected["status"] != "accepted":
            out.append(previous)
            continue
        now = log_seconds(epoch["sealed_at"])
        window = epoch["parameters"]["payload_window_days"] * 86400
        verdicts = {d["name"]: d["disposition"] for d in expected["entries"]}
        records = {_item_id(r["item"]) for r in expected["state"]["records"]}
        for named in epoch["entries"]:
            entry = named.get("entry")
            if verdicts.get(named["name"]) != "valid" or entry is None:
                continue
            if entry["type"] == "registry_update":
                withdrawn.add(entry["body"]["update"]["details"]["delta_id"])
            elif entry["type"] == "publisher_item" and "payload" in entry["body"]["item"]:
                item = entry["body"]["item"]
                ends.setdefault(_item_id(item), []).append(now + window)
                info[_item_id(item)] = (item["publisher"], item["url"])
        if window_from_removal:
            for identifier in held_before - records:
                ends[identifier].append(now + window)
        held_before = records
        duties = []
        for identifier, sealed_ends in ends.items():
            if identifier in withdrawn:
                continue
            until = None if identifier in records else max(sealed_ends)
            if until is None or until > now:
                duties.append({"publisher": info[identifier][0], "url": info[identifier][1], "item": identifier,
                               "until": None if until is None else time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                                 time.gmtime(until))})
        duties.sort(key=lambda d: (d["publisher"].encode(), d["url"].encode(), d["item"].encode()))
        out.append(duties)
        previous = duties
    return out

def _dc3_sealing_duties():
    v = json.loads((ROOT / "vectors" / "wist3" / "catalog-sealing.json").read_text())
    carried = 0
    for history in v["histories"]:
        for expected in history["expected"]:
            for record in expected.get("state", {}).get("records", []):
                assert isinstance(record["item"], dict) and record["item"]["url"] == record["url"] \
                    and record["item"]["publisher"] == record["publisher"], \
                    f"{history['name']}: a record does not carry its Item (WIST-3 §7)"
        if "payload_duties" not in history["expected"][0]:
            continue
        carried += 1
        assert _sealing_duties(history) == [e["payload_duties"] for e in history["expected"]], \
            f"{history['name']}: the Payload duties are not those WIST-3 §6.1 gives"
    assert carried >= 4
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert ("its Item's Payload keeps only the availability window of each Epoch that sealed the Item: a "
            "superseded Payload gets no further window at the Aggregator") in prose
check("vectors:wist3-sealing-duties", _dc3_sealing_duties)

def _dc3_sealing_duties_twin():
    v = json.loads((ROOT / "vectors" / "wist3" / "catalog-sealing.json").read_text())
    moved = [h["name"] for h in v["histories"] if "payload_duties" in h["expected"][0]
             and _sealing_duties(h, window_from_removal=True) != [e["payload_duties"] for e in h["expected"]]]
    assert "a superseded Payload keeps only the window of the Epoch that sealed its Item" in moved, \
        "a further window from the Epoch that replaced the record reproduces the superseded case"
check("negative:wist3-sealing-duties", _dc3_sealing_duties_twin)


def _example_log_epochs():
    v = json.loads((ROOT / "vectors" / "wist3" / "checkpoints.json").read_text())
    assert v["epochs"][0]["entries"] == json.loads((ROOT / "vectors" / "wist3" / "epoch.json").read_text())["entries"]
    order = ("publisher_declaration", "registry_update", "publisher_catalog", "publisher_item", "label", "dispute")
    declaration, latest, records, verdicts = None, {}, {}, []
    for epoch in v["epochs"]:
        sealed_at = parse_checkpoint(epoch["checkpoint"])["sealed_at"]
        entries = epoch["entries"]
        ranks = [(order.index(e["type"]), leaf_hash(rfc8785.dumps(e))) for e in entries]
        assert ranks == sorted(ranks), "the example Epoch is out of canonical Entry order"
        for entry in entries:
            if entry["type"] == "publisher_declaration":
                assert _declaration_binding_result(None, entry["body"]) == "initial"
                declaration = entry["body"]["publisher"]
        for entry in entries:
            if entry["type"] != "publisher_catalog":
                continue
            envelope, catalog = entry["body"], entry["body"]["catalog"]
            signer = next(k for k in declaration["keys"] if k["kid"] == envelope["sig"]["key_id"])
            Ed25519PublicKey.from_public_bytes(b64u_decode(signer["x"])).verify(
                b64u_decode(envelope["sig"]["value"]), rfc8785.dumps(catalog))
            instant = log_seconds(catalog["generated_at"])
            assert signer["nbf"] <= instant and ("exp" not in signer or instant < signer["exp"])
            assert catalog["publisher"] == declaration["domain"] and catalog["collection"] == "default"
            assert instant <= log_seconds(sealed_at) + 600, "C1: generated_at beyond the clock allowance"
            held = latest.get((catalog["publisher"], catalog["collection"]))
            assert held is None or instant > log_seconds(held["generated_at"]), "C3"
            latest[(catalog["publisher"], catalog["collection"])] = catalog
            verdicts.append("valid")
        for entry in entries:
            if entry["type"] != "publisher_item":
                continue
            body, item = entry["body"], entry["body"]["item"]
            catalog = next(c for c in latest.values()
                           if "sha256:" + hashlib.sha256(rfc8785.dumps(c)).hexdigest() == body["catalog"])
            assert body["collection"] == catalog["collection"] and item["publisher"] == catalog["publisher"]
            assert _url_host(item["url"]) in {declaration["domain"], *declaration.get("subdomain_scope", [])}
            assert publisher_instant(item["observed_at"]) <= publisher_instant(catalog["generated_at"])
            _item_proved(item, body["proof"], catalog)
            slot = (catalog["publisher"], item["url"])
            assert records.get(slot) != _item_id(item), "I7: the Item is its URL's record"
            records[slot] = _item_id(item)
            verdicts.append("valid")
    return verdicts, records

def _dc3_example_log():
    verdicts, records = _example_log_epochs()
    assert len(verdicts) == 6 and len(records) == 4
    w3 = (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text()
    assert "Epoch 0 of the example Log contains four Entries" in w3

def _preference_candidates(case, ignore_withdrawals=False):
    return [r["publisher"] for r in case["records"] if ignore_withdrawals or not r["withdrawn"]]

def _dc3_materialization_preference():
    v = json.loads((ROOT / "vectors" / "wist3" / "materialization-preference.json").read_text())
    labels = set()
    for case in v["cases"]:
        labels.add(case["label"])
        candidates = _preference_candidates(case)
        assert _materialization_preference(case["host"], case["self_declared"], candidates) == \
            case["materialized"], case["label"]
        assert case["materialized"] is None or case["materialized"] in candidates, case["label"]
    for needed in ("self declaration prevails", "self declaration excludes parents without an own record",
                   "nearest ancestor", "ancestor over non ancestor", "non ancestors in octet order",
                   "label boundary is not a suffix match", "a withdrawn nearest ancestor",
                   "a self declared host whose own record is withdrawn"):
        assert needed in labels, f"vector lacks the {needed} case"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "The record materialized is then the **nearest ancestor**'s" in prose
    assert "among such Publishers the least domain in ascending octet order does" in prose
    assert "return when the preferred record leaves" in prose
    assert ("From the height of the first accepted Epoch (§3.3) that seals a `publisher_declaration` Entry "
            "whose `domain` is the host") in prose
check("vectors:wist3-materialization-preference", _dc3_materialization_preference)

def _dc3_materialization_preference_twin():
    v = json.loads((ROOT / "vectors" / "wist3" / "materialization-preference.json").read_text())
    by_label = {c["label"]: c for c in v["cases"]}
    for label, flag in (("nearest ancestor", "farthest"), ("non ancestors in octet order", "descending"),
                        ("label boundary is not a suffix match", "raw_suffix")):
        case = by_label[label]
        assert _materialization_preference(case["host"], case["self_declared"], _preference_candidates(case),
                                           **{flag: True}) != case["materialized"], \
            f"the {flag} reading must differ on {label}"
    for label in ("a withdrawn nearest ancestor", "a withdrawn ancestor beside a non ancestor",
                  "a self declared host whose own record is withdrawn"):
        case = by_label[label]
        assert _materialization_preference(case["host"], case["self_declared"],
                                           _preference_candidates(case, ignore_withdrawals=True)) != \
            case["materialized"], f"a reading that ignores withdrawals must differ on {label}"
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
    `index`/`tree_size`, not read off the proof).
    """
    def _expect_reject(epoch, proof):
        try:
            verify_inclusion(epoch, proof)
        except Exception:
            return
        raise AssertionError(
            f"expected rejection, got acceptance: tree_size={proof['tree_size']} "
            f"claimed_index={proof['index']} path_len={len(proof['path'])}")

    exercised = 0
    for n in range(1, 65):
        entries = [{"i": j} for j in range(n)]
        leaves = [leaf_hash(rfc8785.dumps(e)) for e in entries]
        root = "sha256:" + merkle_root(leaves).hex()
        epoch = {"tree_size": n, "root": root, "entries": entries}
        for idx in range(n):
            path_hex = [h.hex() for h in audit_path(idx, leaves)]
            proof = {"index": idx, "tree_size": n, "path": path_hex}
            verify_inclusion(epoch, proof)                    # (a) correct proof verifies
            exercised += 1
            for other in range(n):                            # (b) position authentication
                if other != idx:
                    _expect_reject(epoch, {**proof, "index": other})
            if path_hex:                                      # (c) path too short
                _expect_reject(epoch, {**proof, "path": path_hex[:-1]})
            filler = path_hex[0] if path_hex else leaves[0].hex()
            _expect_reject(epoch, {**proof, "path": path_hex + [filler]})  # path too long
    assert exercised == sum(range(1, 65)), "did not exercise every (n, index) pair"
check("merkle-exhaustive", _merkle_exhaustive)

def _merkle_consistency_exhaustive():
    """Property test for verify_consistency (RFC 9162 §2.1.4.2), the one
    place this file uses merkle.consistency_proof: that function only
    *generates* a proof, so pairing it with an independently implemented
    verifier here — for every (m, n) with 0 <= m <= n <= 64 — is what lets
    this test catch a bug in either side without both sharing one mistake.
    Every valid proof must verify, and removing or appending one node, or
    reconstructing against a wrong root, must not.
    """
    exercised = 0
    for n in range(0, 65):
        entries = [{"i": j} for j in range(n)]
        leaves = [leaf_hash(rfc8785.dumps(e)) for e in entries]
        roots = [merkle_root(leaves[:k]) if k else hashlib.sha256(b"").digest()
                 for k in range(n + 1)]
        for m in range(0, n + 1):
            proof = [h.hex() for h in consistency_proof(m, n, leaves)]
            path = [bytes.fromhex(h) for h in proof]
            verify_consistency(m, n, roots[m], roots[n], path)          # (a) valid proof verifies
            exercised += 1
            if path:
                try:
                    verify_consistency(m, n, roots[m], roots[n], path[:-1])
                    raise AssertionError(f"m={m} n={n}: truncated proof still verified")
                except ValueError:
                    pass
                try:
                    verify_consistency(m, n, roots[m], roots[n], path + [path[0]])
                    raise AssertionError(f"m={m} n={n}: padded proof still verified")
                except ValueError:
                    pass
            if m > 0 and roots[m] != roots[n]:
                try:
                    verify_consistency(m, n, roots[n], roots[n], path)
                    raise AssertionError(f"m={m} n={n}: wrong old root still verified")
                except ValueError:
                    pass
            # WIST-3 §4: the empty proof still compares the size-0 root.
            if m == 0 and n > 0:
                try:
                    verify_consistency(m, n, roots[n], roots[n], path)
                    raise AssertionError(f"n={n}: a size-0 root other than SHA-256(\"\") still verified")
                except ValueError:
                    pass
    assert exercised == sum(range(1, 66)), "did not exercise every (m, n) pair"
check("merkle-consistency-exhaustive", _merkle_consistency_exhaustive)

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
    property test above proves generation and verification agree with
    *each other*, but two sides of one authorship can share one
    misreading — only answers published by an independent implementation
    prove the hashes themselves are RFC 6962's. The empty-tree constant
    (`SHA-256("")`, WIST-3 §4) is asserted too: every tree size in this
    suite, the empty tree before Epoch 0 included, is exactly RFC 6962's
    (see vectors/wist3/empty-epoch.json).
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
        key = (c["effective_at_s"], c["epoch_number"], c["entry_index"])
        if best is None or key > best[0]:
            best = (key, i, c["value"])
    return (default, None) if best is None else (best[2], best[1])

def _dc4_parameter_in_force():
    """WIST-4 §5: which amendment is in force at an instant."""
    v = _parameter_vector()
    labels = set()
    for case in v["cases"]:
        labels.add(case["label"])
        order = [(c["epoch_number"], c["entry_index"]) for c in case["changes"]]
        assert order == sorted(order), f"{case['label']}: changes not in Log order"
        for c in case["changes"]:
            assert c["effective_at_s"] - c["sealed_at_s"] >= 7 * 86400, \
                f"{case['label']}: an amendment inside the grace period"
        for q in case["queries"]:
            value, source = _value_in_force(case["default"], case["changes"], q["t_s"])
            assert (value, source) == (q["value"], q["from_index"]), \
                f"{case['label']} at {q['t_s']}: recomputed {(value, source)}, vector says {(q['value'], q['from_index'])}"
    for needed in ("effective at is inclusive", "later effective at prevails whatever sealed first",
                   "equal effective at across epochs", "equal effective at in one epoch"):
        assert needed in labels, f"vector lacks the {needed} case"
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-4-governance.md").read_text())
    for marker in ("in force at every instant T at or after its `effective_at`, the endpoint included",
                   "the one later in Log order (WIST-3 §3.3: ascending Epoch number, then Entry index) prevails"):
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
    case = next(c for c in v["cases"] if c["label"] == "equal effective at across epochs")
    reversed_changes = list(reversed(case["changes"]))
    for c, b in zip(reversed_changes, [x["epoch_number"] for x in case["changes"]]):
        c["epoch_number"] = b
    tied = next(q for q in case["queries"] if q["from_index"] is not None)
    assert _value_in_force(case["default"], reversed_changes, tied["t_s"])[0] != tied["value"], \
        "recomputation is blind to which of an equal pair sealed later"
check("negative:wist4-parameter-in-force", _dc4_parameter_in_force_twin)


def _combinations_hold(values):
    return (values["links_cap_bytes"] >= values["link_url_cap_bytes"] + 21
            and values["mirror_retention_days"] * 6 >= values["payload_window_days"]
            and values["labeler_epoch_entries_max"] <= values["domain_epoch_entries_max"])

def _prospective_values(defaults, changes, at_s):
    values = dict(defaults)
    for c in sorted(changes, key=lambda c: (c["effective_at_s"], c["epoch_height"], c["entry_index"])):
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
    assert "| WIST-1 §5.2 recovery window length | Window owner Declaration's Epoch;" in prose
    flat = re.sub(r"\s+", " ", prose)
    assert "would end a window opened at that instant after `9999-12-31T23:59:59Z`" in flat
    flat1 = re.sub(r"\s+", " ", (ROOT / "specs/WIST-1-item-format.md").read_text())
    assert "an Aggregator MUST NOT seal a recovery Declaration whose window would end there" in flat1


check("vectors:wist4-recovery-parameter-windows", _recovery_parameter_windows)


def _dc4_prospective_parameters():
    v = json.loads((ROOT / "vectors" / "wist4" / "parameter-combinations.json").read_text())
    for case in v["prospective_cases"]:
        accepted, rejected = [], []
        order = sorted(range(len(case["changes"])), key=lambda i: (case["changes"][i]["epoch_height"], case["changes"][i]["entry_index"]))
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
                   "aggregate cap exactly the link cap plus its structure", "canonical same Epoch order"):
        assert needed in labels, needed
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-governance.md").read_text())
    assert "`links_cap_bytes` MUST NOT be below `link_url_cap_bytes` + 21" in prose
    assert "`mirror_retention_days` MUST NOT be below `payload_window_days` divided by 6" in prose
    assert "`labeler_epoch_entries_max` MUST NOT exceed `domain_epoch_entries_max`" in prose
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

def _epoch_size_maps(default, accepted, instant):
    times = sorted({instant} | {c["effective_at_s"] for c in accepted if c["effective_at_s"] >= instant})
    return [_prospective_values({"epoch_cap_bytes":default},
        [dict(c, parameter="epoch_cap_bytes") for c in accepted], t)["epoch_cap_bytes"] for t in times]


def _replay_epoch_size(default, epochs, restart_after=()):
    state = {"accepted":[], "maximum":0, "at_s":None}
    probes = []
    for height, epoch in enumerate(epochs):
        before = default if state["at_s"] is None else max(_epoch_size_maps(default,state["accepted"],state["at_s"]))
        maximum = max(state["maximum"],epoch["jcs_bytes"])
        trial = list(state["accepted"])
        rejected = []
        for index, change in enumerate(epoch["amendments"]):
            candidate = dict(change,epoch_height=height,entry_index=index)
            proposed = trial+[candidate]
            valid = isinstance(candidate["value"], int) and 65537 <= candidate["value"] <= 9007199254740991 and candidate["effective_at_s"]-epoch["sealed_at_s"] >= 7*86400
            if valid and all(cap >= maximum for cap in _epoch_size_maps(default,proposed,epoch["sealed_at_s"])):
                trial = proposed
            else:
                rejected.append(index)
        cap = min(_epoch_size_maps(default,trial,epoch["sealed_at_s"]))
        valid = maximum <= cap
        if valid:
            state = {"accepted":trial,"maximum":maximum,"at_s":epoch["sealed_at_s"]}
        probes.append({"rejected_indices":rejected,"sealing_cap":cap,"epoch_valid":valid,
            "largest_bytes":state["maximum"],"transport_bound_before":before})
        if height in restart_after:
            state = json.loads(json.dumps(state))
        if not valid:
            break
    return probes


def _dc4_epoch_sizes():
    v = json.loads((ROOT / "vectors/wist4/parameter-combinations.json").read_text())
    assert v["epoch_cap_default"] == 256*1024*1024
    for case in v["epoch_size_cases"]:
        expected = case["expected"]
        assert _replay_epoch_size(v["epoch_cap_default"],case["epochs"]) == expected, case["label"]
        assert _replay_epoch_size(v["epoch_cap_default"],case["epochs"],case["restart_after"]) == expected, case["label"]
    for case in v["epoch_transport_cases"]:
        bound = v["epoch_cap_default"] if case["prefix_sealed_at_s"] is None else max(_epoch_size_maps(v["epoch_cap_default"],case["accepted_caps"],case["prefix_sealed_at_s"]))
        if case.get("snapshot_bootstrap"):
            bound = max([v["epoch_cap_default"]]+[c["value"] for c in case["accepted_caps"]])
        assert bound == case["transport_bound"], case["label"]
        valid = case["entries_bytes"] <= bound
        assert valid == case["valid"], case["label"]
        assert (None if valid else "WIST3-E03") == case["error"], case["label"]
check("vectors:wist4-epoch-size-schedule", _dc4_epoch_sizes)


def _dc4_epoch_sizes_twin():
    v = json.loads((ROOT / "vectors/wist4/parameter-combinations.json").read_text())
    cases = {c["label"]:c for c in v["epoch_size_cases"]}
    current = cases["reduction includes its complete current Epoch"]
    smaller = copy.deepcopy(current["epochs"])
    smaller[0]["jcs_bytes"] = 2048
    assert _replay_epoch_size(v["epoch_cap_default"],smaller)[0]["rejected_indices"] == []
    assert current["expected"][0]["rejected_indices"] == [0]
    later = cases["later maximum never revalidates old acceptance"]
    final_maximum = max(b["jcs_bytes"] for b in later["epochs"])
    assert later["epochs"][0]["amendments"][0]["value"] < final_maximum
    assert later["expected"][0]["rejected_indices"] == []
    pending = cases["pending reduction constrains an intervening Epoch"]
    assert pending["epochs"][-1]["jcs_bytes"] < v["epoch_cap_default"]
    assert not pending["expected"][-1]["epoch_valid"]
    transport = next(c for c in v["epoch_transport_cases"] if c["label"] == "an accepted future effective_at raises the bound before it takes effect")
    assert transport["entries_bytes"] > v["epoch_cap_default"] and transport["valid"]
    excluded = next(c for c in v["epoch_transport_cases"] if c["label"] == "a rejected candidate does not raise the bound")
    assert not excluded["valid"]
    with_rejected = max(_epoch_size_maps(v["epoch_cap_default"],
        excluded["accepted_caps"] + excluded["rejected_caps"], excluded["prefix_sealed_at_s"]))
    assert with_rejected > excluded["transport_bound"] and excluded["entries_bytes"] <= with_rejected
check("negative:wist4-epoch-size-schedule", _dc4_epoch_sizes_twin)

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

def _strict_json(raw):
    return item_rules.strict_loads(raw.encode("utf-8") if isinstance(raw, str) else raw)

def _registry_update_eligibility(raw, validator):
    """WIST-4 §5.1: JSON/JCS eligibility (WIST1-E05), then the schema, where a
    failure inside an action's branch is the details contract (WIST4-E04) and
    any other field failure, the version check included, is WIST4-E11."""
    try:
        doc = _strict_json(raw)
        rfc8785.dumps(doc)
    except (ValueError, TypeError, item_rules.NotJcsInput):
        return "WIST1-E05", None
    errors = list(validator.iter_errors(doc))
    if any("allOf" not in e.absolute_schema_path for e in errors):
        return "WIST4-E11", None
    if errors and not _parameter_rejection(doc, errors):
        return "WIST4-E04", None
    if doc["update"]["wist_version"].partition(".")[0] != "1":
        return "WIST4-E11", None
    return ("WIST4-E03" if errors else None), doc

def _parameter_rejection(doc, errors):
    """WIST-4 §5.1: a string `parameter` naming no identifier, with the same
    `subject`, and an integer `value` past its bound pass to authentication
    and are rejected as WIST4-E03; the caller authenticates first."""
    update = doc["update"]
    details = update.get("details")
    if update.get("action") != "parameter_change" or not isinstance(details, dict):
        return False
    parameter, value = details.get("parameter"), details.get("value")
    if not isinstance(parameter, str) or update.get("subject") != parameter:
        return False
    integral = (isinstance(value, int) and not isinstance(value, bool)) or \
        (isinstance(value, float) and value.is_integer())
    for e in errors:
        where = list(e.absolute_path)
        if e.validator == "enum" and where in (["update", "details", "parameter"], ["update", "subject"]):
            continue
        if integral and e.validator in ("minimum", "maximum") and where == ["update", "details", "value"]:
            continue
        return False
    return True

def _dc4_parameter_wire_range():
    v = json.loads((ROOT / "vectors/wist4/parameter-combinations.json").read_text())
    validator = Draft202012Validator(json.loads((ROOT / "schemas/registry-update.schema.json").read_text()))
    key = Ed25519PublicKey.from_public_bytes(b64u_decode(v["wire_public_key"]))
    for case in v["wire_cases"]:
        doc = case["envelope"]
        assert validator.is_valid(doc) == case["schema_valid"], case["label"]
        code, parsed = ("WIST1-E05", None) if not case["canonical_integer"] else \
            _registry_update_eligibility(json.dumps(doc), validator)
        if parsed is not None:
            try:
                key.verify(b64u_decode(doc["sig"]["value"]), rfc8785.dumps(doc["update"]))
            except InvalidSignature:
                code = "WIST4-E11"
        assert code == case["code"], (case["label"], code)
        assert case["sealed_disposition"] == ("candidate" if case["schema_valid"] else "ignored"), case["label"]
        if case["canonical_integer"]:
            if case["code"] != "WIST4-E11" or doc["update"]["effective_at"].endswith(".5Z"):
                key.verify(b64u_decode(doc["sig"]["value"]), rfc8785.dumps(doc["update"]))
        else:
            try:
                rfc8785.dumps(doc["update"])
            except rfc8785.IntegerDomainError:
                pass
            else:
                raise AssertionError(case["label"])
        d = doc["update"]["details"]
        values = dict(v["prospective_defaults"])
        if d["parameter"] in values and isinstance(d["value"], int):
            values[d["parameter"]] = d["value"]
        assert _combinations_hold(values) == case["combinations_hold_at_defaults"], case["label"]
    floor = next(c for c in v["wire_cases"] if c["envelope"]["update"]["details"] == {"parameter": "payload_window_days", "value": 29})
    assert not floor["schema_valid"] and floor["sealed_disposition"] == "ignored"
    assert next(c for c in v["wire_cases"] if c["envelope"]["update"]["details"] == {"parameter": "payload_window_days", "value": 30})["schema_valid"]
    spellings = [c for c in v["wire_cases"] if c["envelope"]["update"]["details"]["parameter"] == "epoch_cap_bytes"]
    assert [(type(c["envelope"]["update"]["details"]["value"]), c["schema_valid"]) for c in spellings] == [(str, False), (float, True)], \
        "a string value fails the details contract; an integral decimal spelling is the integer it denotes"
    assert spellings[1]["envelope"]["update"]["details"]["value"] == 65537 and spellings[1]["sealed_disposition"] == "candidate"
    fractional = next(c for c in v["wire_cases"] if c["envelope"]["update"]["effective_at"].endswith(".5Z"))
    assert not fractional["schema_valid"] and fractional["sealed_disposition"] == "ignored"
    probed = {(c["envelope"]["update"]["details"]["parameter"], c["envelope"]["update"]["details"]["value"]):
              c["schema_valid"] for c in v["wire_cases"]}
    defaults = _registry_table_defaults()
    for name in ("url_cap_bytes", "extract_cap_bytes", "summary_cap_bytes", "links_cap_bytes",
                 "link_url_cap_bytes", "collections_max", "scope_entries_max", "catalog_items_max",
                 "tree_file_cap_bytes", "tree_depth_max"):
        assert probed.get((name, defaults[name])) is True and probed.get((name, defaults[name] - 1)) is False, \
            f"{name} lacks a case at its floor, the default, and one below it"
    for name, edges in (("url_cap_bytes", ((32768, True), (32769, False))),
                        ("catalog_refresh_seconds", ((0, False), (1, True), (7776000, True), (7776001, False)))):
        for value, valid in edges:
            assert probed.get((name, value)) is valid, f"{name} lacks the bound case {value}"
    codes = {c["label"]: c["code"] for c in v["wire_cases"]}
    for label, code in (("value below its bound under a signature that fails", "WIST4-E11"),
                        ("identifier the Parameter Registry does not list with the same subject", "WIST4-E03"),
                        ("identifier the Parameter Registry does not list under a signature that fails", "WIST4-E11"),
                        ("identifier the Parameter Registry does not list with another subject", "WIST4-E04"),
                        ("non string parameter", "WIST4-E04")):
        assert codes.get(label) == code, label
    assert codes["url_cap_bytes value 2047"] == "WIST4-E03"
    prose4 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-governance.md").read_text())
    assert ("a string `details.parameter` that names no §5 identifier, with a `subject` that is the same string, "
            "and an integer `details.value` outside its §5 bound") in prose4
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
    ("catalog.schema.json", "properties/catalog/properties/publisher"): "the signed Canonical Host of the Publisher, not a content digest",
    ("catalog.schema.json", "properties/catalog/properties/collection"): "a Collection name chosen by the Publisher (WIST-1 §3.5), not a content digest",
    ("publisher.schema.json", "properties/publisher/properties/collections/items/properties/name"): "a Collection name chosen by the Publisher (WIST-1 §3.5), not a content digest",
    ("catalog.schema.json", "properties/catalog/properties/root"): "an Item list root (WIST-1 §4): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("catalog.schema.json", "properties/catalog/properties/tree"): "a tree file name (WIST-1 §4): SHA-256 over a file of Items that carry only a salted commitment",
    **{("item.schema.json", path): "the Canonical Host of the Publisher, not a content digest"
       for path in ("$defs/publisher", "oneOf[0]/properties/publisher", "oneOf[1]/properties/publisher")},
    ("tree-file.schema.json", "oneOf[1]/properties/children/items/properties/prefix"): "leading hexadecimal digits of Item keys (WIST-1 §4): SHA-256 over a URL, which the Log carries in the clear",
    ("tree-file.schema.json", "oneOf[1]/properties/children/items/properties/file"): "a tree file name (WIST-1 §4): SHA-256 over a file of Items that carry only a salted commitment",
    ('feed.schema.json', 'properties/feed/properties/domain'): "a Canonical Host identifying a Publisher or its declared scope, not a content digest",
    ('publisher.schema.json', 'properties/publisher/properties/domain'): "a Canonical Host identifying a Publisher or its declared scope, not a content digest",
    ('publisher.schema.json', 'properties/publisher/properties/subdomain_scope/items'): "a Canonical Host identifying a Publisher or its declared scope, not a content digest",
    ('status.schema.json', 'properties/domain'): "a Canonical Host identifying a Publisher or its declared scope, not a content digest",
    ("publisher.schema.json", "properties/publisher/properties/prev_declaration"):
        "SHA-256 of a Declaration, which carries keys and no content",
    ("publisher.schema.json", "properties/publisher/properties/next_keys"):
        "a Key Set fingerprint (WIST-1 §5.1): SHA-256 over a JSON array of JWK thumbprints, no content",
    ("feed.schema.json", "properties/feed/properties/deltas/items"):
        "Label and Dispute IDs (WIST-2 §3.2): SHA-256 over Labels and disputes, no page content",
    ("log-anchor.schema.json",
     "properties/anchor/properties/predecessor/properties/final_root_hash"):
        "SHA-256 of an Epoch header (the predecessor Log's final Epoch, WIST-3 §3.4)",
    ("status.schema.json", "properties/collections/items/properties/name"):
        "a Collection name chosen by the Publisher (WIST-1 §3.5), not a content digest",
    ("status.schema.json", "properties/collections/items/properties/latest"):
        "a Catalog ID (WIST-2 §7.1): SHA-256 over a Catalog that carries no page content",
    ("status.schema.json", "properties/collections/items/properties/accepted"):
        "a Catalog ID (WIST-2 §7.1): SHA-256 over a Catalog that carries no page content",
    ("status.schema.json", "properties/collections/items/properties/waiting/items/properties/id"):
        "a Catalog ID or an Item ID (WIST-2 §7.1): SHA-256 over a Catalog or an Item that carries only a salted commitment",
    ("status.schema.json", "properties/rejections/items/properties/id"):
        "the ID of a Declaration, Catalog, Item, Label or dispute (WIST-2 §7.1): SHA-256 over an object that carries at most a salted commitment",
    ("status.schema.json", "properties/rejections/items/properties/collection"):
        "a Collection name chosen by the Publisher (WIST-1 §3.5), not a content digest",
    ("status.schema.json", "properties/rejections/items/properties/change_list"):
        "a Catalog ID naming a change list (WIST-2 §5.3): SHA-256 over a Catalog that carries no page content",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/files/items/properties/sha256"):
        "a whole tier file, not any one record (WIST-3 §7); and a manifest is a static artifact, not a Log Entry",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/root_hash"):
        "SHA-256 of an Epoch header",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/content_digest"):
        "a digest over the content tuples of WIST-3 §7 — url, publisher, item_id, observed_at, attested_at — every one of which the Log already carries in the clear; no page content is in its preimage",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/state/properties/sha256"):
        "the whole state file, a Log-derived artifact (WIST-3 §7); transport integrity, same as any files[] sha256",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/state/properties/state_digest"):
        "the content_digest construction over state tuples, every field of which is Log-derived (WIST-3 §7); no page content is in its preimage",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/shards/properties/digests"):
        "an array of per-shard content-tuple digests (WIST-3 §7); the items entry below is the pattern-bearing one, this is the array shell",
    ("snapshot-manifest.schema.json",
     "properties/manifest/properties/shards/properties/digests/items"):
        "the same WIST-3 §7 content-tuple digest, computed per shard; no page content is in its preimage",
    ("snapshot-index.schema.json",
     "properties/index/properties/snapshots/items/properties/content_digest"):
        "the same WIST-3 §7 content-tuple digest the manifest declares, restated by the index",
    ("payload.schema.json", "properties/salt"):
        "the salt itself: drawn from a CSPRNG, never derived from the content it keys (WIST-1 §3.6)",
    ("label.schema.json", "properties/label/properties/labeler"): "the signed Canonical Host of the Labeler, not a content digest",
    ("label.schema.json", "properties/label/properties/subject"): "a Normalized URL or Canonical Host the Label is about (WIST-2 §3.3), which the Log carries in the clear; no page content",
    ("label.schema.json", "properties/label/properties/name"): "a Label Registry name, `<prefix>:<term>` (WIST-4 §6), not a content digest",
    ("label.schema.json", "properties/label/properties/delta"): "an Item ID the Label binds to (WIST-2 §3.3): SHA-256 over an Item that carries only a salted commitment",
    ("dispute.schema.json", "properties/dispute/properties/disputant"): "the signed Canonical Host of the disputant, not a content digest",
    ("dispute.schema.json", "properties/dispute/properties/label"): "the disputed Label's ID (WIST-2 §3.3): SHA-256 over a Label, which carries a subject, a name and an integer, no page content",
    ("dispute.schema.json", "properties/dispute/properties/log"): "a Log's `log_id`, a Canonical Host, not a content digest",
    ("label-definition.schema.json", "properties/definition/properties/labeler"): "the signed Canonical Host of the Labeler, not a content digest",
    ("label-definition.schema.json", "properties/definition/properties/name"): "a Label Registry name, `<prefix>:<term>` (WIST-4 §6), not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[6]/prefixItems[7]/oneOf[0]"): "the Item ID a Label binds to (WIST-2 §3.3): SHA-256 over an Item that carries only a salted commitment",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[6]/prefixItems[8]"): "the current Label's ID (WIST-2 §3.3): SHA-256 over a Label, which carries a subject, a name and an integer, no page content",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[9]/prefixItems[1]"): "the disputed Label's ID (WIST-2 §3.3): SHA-256 over a Label, no page content",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[9]/prefixItems[2]"): "a Canonical Host identifying the disputant, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[6]/prefixItems[3]"): "a Label Registry name, `<prefix>:<term>` (WIST-4 §6), not a content digest",
    ("registry-update.schema.json", "allOf[3]/then/properties/update/properties/subject"): "a Canonical Host identifying a Publisher, not a content digest",
    ("registry-update.schema.json", "allOf[3]/then/properties/update/properties/details/properties/delta_id"): "the Item ID a withdrawal names (WIST-3 §6.2): SHA-256 over an Item that carries only a salted commitment (WIST-1 §3.6)",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[1]/prefixItems[1]"): "a Canonical Host identifying a Publisher, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[4]/prefixItems[1]"): "a Canonical Host identifying a Publisher, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[2]/prefixItems[1]"): "a Canonical Host identifying a Publisher whose fresh identity is pending, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[5]/prefixItems[1]"): "a withdrawn Item's ID: SHA-256 over an Item that carries only a salted commitment (WIST-3 §6.2)",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[5]/prefixItems[2]"): "a Canonical Host identifying a Publisher, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[6]/prefixItems[1]"): "a Canonical Host identifying a Labeler, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[7]/prefixItems[1]"): "a Canonical Host identifying a Publisher, not a content digest",
    ("publisher-item.schema.json", "properties/collection"): "a Collection name chosen by the Publisher (WIST-1 §3.5), not a content digest",
    ("publisher-item.schema.json", "properties/catalog"): "a Catalog ID (WIST-3 §3.3): SHA-256 over a Catalog that carries no page content",
    ("publisher-item.schema.json", "properties/proof/properties/path/items"): "sibling hashes of an Item list's Merkle tree (WIST-1 §4.3), over leaves that carry only a URL hash and an Item hash",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[7]/prefixItems[4]"): "a Collection name chosen by the Publisher (WIST-1 §3.5), not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[7]/prefixItems[5]"): "the Catalog ID a record's Item was proved against (WIST-3 §7): SHA-256 over a Catalog that carries no page content",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[10]/prefixItems[1]"): "a Canonical Host identifying a Publisher, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[10]/prefixItems[2]"): "a Collection name chosen by the Publisher (WIST-1 §3.5), not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[11]/prefixItems[1]"): "a Canonical Host identifying a Publisher, not a content digest",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[11]/prefixItems[3]"): "the Item ID of an Item of kind removed (WIST-3 §7): SHA-256 over an Item that carries a URL and an instant, no page content",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[11]/prefixItems[4]"): "the Catalog ID the Item of kind removed was proved against (WIST-3 §7): SHA-256 over a Catalog that carries no page content",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[8]/prefixItems[1]"): "a Public Suffix List snapshot identifier: SHA-256 over a list of domain-name rules, no page content (WIST-4 §3.1)",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[12]/prefixItems[1]"): "a Registry Update ID (WIST-4 §2): SHA-256 over an update, which carries no page content",
    ("registry-update.schema.json", "allOf[4]/then/properties/update/properties/subject"): "a Public Suffix List snapshot identifier: SHA-256 over a list of domain-name rules, no page content (WIST-4 §3.1)",
    ("registry-update.schema.json", "allOf[4]/then/properties/update/properties/details/properties/sha256"): "a Public Suffix List snapshot identifier: SHA-256 over a list of domain-name rules, no page content (WIST-4 §3.1)",
}

NON_CONTENT_VALUES = {
    ("vectors/wist1/payload-fields.json", "salt"): "Payload salts and malformed encoding probes",

    ("vectors/wist4/parameter-combinations.json", "wire_public_key"): "an Ed25519 public key",
    ("vectors/wist4/parameter-combinations.json", "value"): "an Ed25519 signature when opaque",
    ("examples/catalog.json", "value"): "an Ed25519 signature",
    ("examples/catalog.json", "root"): "an Item list root (WIST-1 §4): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("examples/catalog.json", "tree"): "a tree file name (WIST-1 §4): SHA-256 over a file of Items that carry only a salted commitment",
    ("examples/log-anchor.json", "public_key"): "an Ed25519 public key",
    ("examples/mirrors.json", "value"): "an Ed25519 signature",
    ("examples/log-anchor.json", "value"): "an Ed25519 signature",
    ("examples/payload.json", "salt"): "the salt: from a CSPRNG, never derived from what it keys",
    ("examples/publisher.json", "x"): "an Ed25519 public key",
    ("examples/publisher.json", "value"): "an Ed25519 signature",
    ("examples/registry-update.json", "value"): "an Ed25519 signature",
    ("examples/snapshot-manifest.json", "sha256"): "a whole tier file, not any one record (WIST-3 §7)",
    ("examples/snapshot-manifest.json", "root_hash"): "SHA-256 of an Epoch header",
    ("examples/snapshot-manifest.json", "content_digest"):
        "WIST-3 §7's content-tuple digest: url, publisher, item_id, observed_at, attested_at — no content in the preimage",
    ("examples/snapshot-manifest.json", "value"): "an Ed25519 signature",
    ("examples/snapshot-manifest.json", "state_digest"):
        "WIST-3 §7's digest construction over state tuples — every field Log-derived, no content in the preimage",
    ("examples/snapshot-state.json", "entries"):
        "state tuples (WIST-3 §7): key IDs, Catalog IDs, Item IDs, heights, an Ed25519 public key — Log-derived identifiers, no page content",
    ("examples/snapshot-state.json", "value"): "an Ed25519 signature",
    ("examples/snapshot-index.json", "content_digest"):
        "the manifest's content-tuple digest, restated by the index (WIST-3 §6, §7)",
    ("examples/snapshot-index.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/snapshot-records.json", "digests"):
        "WIST-3 §7's content-tuple digest per shard, recomputed by `snapshot-sharding` from the records this file publishes",
    ("vectors/wist3/snapshot-index.json", "content_digest"):
        "the example manifest's content-tuple digest, restated by each index entry (WIST-3 §6, §7)",
    ("vectors/wist3/snapshot-index.json", "sha256"): "a whole tier or state file, not any one record (WIST-3 §7)",
    ("vectors/wist3/snapshot-index.json", "root_hash"): "SHA-256 of an Epoch header",
    ("vectors/wist3/snapshot-index.json", "state_digest"):
        "WIST-3 §7's digest construction over state tuples — every field Log-derived, no content in the preimage",
    ("vectors/wist3/snapshot-index.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/snapshot-records.json", "content_digest"):
        "WIST-3 §7's content-tuple digest, recomputed by `snapshot:content-digest` from the records this file publishes",
    ("examples/status.json", "id"): "a Catalog ID or an Item ID (WIST-2 §7.1): SHA-256 over a Catalog or an Item that carries only a salted commitment",
    ("examples/status.json", "accepted"): "a Catalog ID (WIST-2 §7.1): SHA-256 over a Catalog that carries no page content",
    ("examples/status.json", "change_list"): "a Catalog ID naming a change list (WIST-2 §5.3): SHA-256 over a Catalog that carries no page content",
    ("vectors/wist1/envelope.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/envelope.json", "root"): "an Item list root (WIST-1 §4): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("vectors/wist1/envelope.json", "tree"): "a tree file name (WIST-1 §4): SHA-256 over a file of Items that carry only a salted commitment",
    ("vectors/wist1/catalog.canonical", "root"): "an Item list root (WIST-1 §4): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("vectors/wist1/catalog.canonical", "tree"): "a tree file name (WIST-1 §4): SHA-256 over a file of Items that carry only a salted commitment",
    ("vectors/wist1/id.txt", None): "the WIST-1 vector's Catalog ID: SHA-256 over a Catalog that carries a root, a tree hash and no page content",
    ("vectors/wist1/key-directory.json", "root"): "the root of an empty Item list (WIST-1 §4): SHA-256 of the empty string",
    ("vectors/wist1/key-directory.json", "tree"): "a tree file name (WIST-1 §4): SHA-256 over the empty bucket",
    ("vectors/wist1/keypair.json", "seed_hex"): "the test signing seed",
    ("vectors/wist1/keypair.json", "public_key"): "an Ed25519 public key",
        ("vectors/wist3/epoch.json", "root"): "root over Entries, which carry commitments only",
    ("vectors/wist3/epoch.json", "leaf_hashes"): "leaf hashes over Entries, which carry commitments only",
    ("vectors/wist3/checkpoints.json", "leaf_hashes"): "leaf hashes over Entries, which carry commitments only",
    ("vectors/wist3/checkpoints.json", "m_root"): "root over Entries, which carry commitments only",
    ("vectors/wist3/checkpoints.json", "n_root"): "root over Entries, which carry commitments only",
    ("vectors/wist3/checkpoints.json", "path"): "Merkle sibling hashes over Entries",
    ("vectors/wist3/checkpoints.json", "leaf_hashes_2"): "leaf hashes over Entries, which carry commitments only",
    ("vectors/wist3/checkpoints.json", "larger_tree_leaf_hashes"): "leaf hashes over Entries, which carry commitments only",
    ("vectors/wist3/tile-bounds.json", "octets_hex"): "the octets a tile or entry bundle is served as, carrying no page content",
    ("vectors/wist3/checkpoints.json", "witness-a.example"): "an Ed25519 public key",
    ("vectors/wist3/checkpoints.json", "witness-b.example"): "an Ed25519 public key",
    ("vectors/wist3/checkpoints.json", "root_hash"): "root over Entries, which carry commitments only",
    ("vectors/wist3/aggregator-keys.json", "public_key"):
        "an Ed25519 Aggregator key, in a Log Anchor or an aggregator_key_add (WIST-3 §3.4)",
    ("vectors/wist3/aggregator-keys.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/aggregator-keys.json", "final_root_hash"):
        "the final root a successor Anchor names, over Entries that carry no page content",
    ("vectors/wist3/aggregator-keys.json", "leaf_hashes"):
        "leaf hashes over Entries, which carry governance acts and no page content",
    ("vectors/wist3/aggregator-keys.json", "expected_state"):
        "WIST-3 §7 aggregator_key tuples: a key_id, an Ed25519 public key, two heights and "
        "the key acts, which carry governance acts and no page content",
    ("vectors/wist3/aggregator-keys.json", "entries"):
        "WIST-3 §7 aggregator_key tuples in the Snapshot state cases, as above",
    ("vectors/wist3/aggregator-keys.json", "expected_registry_state"):
        "WIST-3 §7 registry_update tuples: Registry Update IDs, which hash governance acts "
        "carrying no page content",
    ("vectors/wist3/aggregator-keys.json", "sha256"):
        "a Public Suffix List snapshot identifier (WIST-4 §3.1), naming no page content",
    ("vectors/wist3/aggregator-keys.json", "subject"):
        "a Public Suffix List snapshot identifier, the subject of a suffix_list_update",
    ("vectors/wist3/snapshot-keys.json", "public_key"):
        "an Ed25519 Aggregator key, in a Log Anchor, an aggregator_key_add or a §7 "
        "aggregator_key tuple (WIST-3 §3.4)",
    ("vectors/wist3/snapshot-keys.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/snapshot-keys.json", "seed_hex"): "a test-only Ed25519 seed, no page content",
    ("vectors/wist3/snapshot-keys.json", "leaf_hashes"):
        "leaf hashes over Entries, which carry governance acts and no page content",
    ("vectors/wist3/snapshot-keys.json", "root_hash"):
        "root over Entries, which carry governance acts and no page content",
    ("vectors/wist3/snapshot-keys.json", "expected_state"):
        "WIST-3 §7 aggregator_key tuples: a key_id, an Ed25519 public key, two heights and "
        "the key acts, which carry governance acts and no page content",
    ("vectors/wist3/snapshot-keys.json", "entries"):
        "WIST-3 §7 aggregator_key tuples in the Snapshot state files and the Consumer "
        "registries, as above",
    ("vectors/wist3/snapshot-keys.json", "content_digest"):
        "WIST-3 §7's digest over the live record set, empty in a Log whose Entries are key "
        "acts alone: Log-derived identifiers only, never page content",
    ("vectors/wist3/snapshot-keys.json", "sha256"):
        "SHA-256 over a Snapshot state file's octets and over a placeholder tier file "
        "(WIST-3 §7); neither carries page content",
    ("vectors/wist3/snapshot-keys.json", "state_digest"):
        "WIST-3 §7's digest over the state tuples, which carry key registry state only",
    ("vectors/wist3/snapshot-keys.json", "accepted_state_digest"):
        "WIST-3 §7's digest over the state tuples, as above",
    ("vectors/wist3/snapshot-keys.json", "alternate_state_digest"):
        "WIST-3 §7's digest over the state tuples, as above",
    ("vectors/wist3/epoch.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/checkpoints.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/timestamps.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/timestamps.json", "deltas"): "Label IDs in the Label Feed example fixture",
    ("vectors/wist3/empty-epoch.json", "empty_tree_root"):
        "the empty tree's root (WIST-3 §4): SHA-256(\"\"), the RFC 6962 empty-tree constant",
    ("vectors/wist3/empty-epoch.json", "epoch_0_root"): "root over Entries, which carry commitments only",
    ("vectors/wist3/inclusion-proof.json", "path"): "Merkle sibling hashes over Entries",
    ("vectors/multilog/dedup.json", "root"): "root over Entries, which carry commitments only",
    ("vectors/multilog/dedup.json", "public_key"): "an Ed25519 public key (the Log genesis key)",
    ("vectors/multilog/dedup.json", "value"): "an Ed25519 signature",
    ("vectors/multilog/dedup.json", "salt"): "the salt: from a CSPRNG, never derived from what it keys",
    ("vectors/multilog/dedup.json", "genesis_seed_hex"): "the vector's test signing seed",
    ("vectors/multilog/dedup.json", "x"): "an Ed25519 public key",
    ("vectors/multilog/dedup.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/multilog/dedup.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/declaration-hosts.json", 'author_key'): 'the fixture author public key',
    ("vectors/wist1/declaration-hosts.json", 'public_key'): 'an Ed25519 public key',
    ("vectors/wist1/declaration-hosts.json", 'value'): 'an Ed25519 signature',
    ("vectors/wist1/declaration-hosts.json", 'prev_declaration'): 'SHA-256 of the original predecessor publisher object',
    ("vectors/wist1/declaration-hosts.json", 'pinned_head'): 'the authenticated candidate Epoch header hash',
    ("vectors/wist1/base64url.json", "author_key"): "the fixture author public key",
    ("vectors/wist1/base64url.json", "encoded"): "an encoding or malformed field probe",
    ("vectors/wist1/base64url.json", "public_key"): "a public key or malformed public-key encoding",
    ("vectors/wist1/base64url.json", "value"): "a signature or rejected signature alias",
    ("vectors/wist1/base64url.json", "prev_declaration"): "SHA-256 of the original predecessor publisher object",
    ("vectors/wist1/base64url.json", "pinned_head"): "the authenticated candidate Epoch header hash",
    ("vectors/wist1/declaration-binding.json", "x"): "an Ed25519 public key",
    ("vectors/wist1/declaration-key-eligibility.json", "x"): "an Ed25519 public key or excluded public point encoding",
    ("vectors/wist1/declaration-key-eligibility.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/declaration-key-eligibility.json", "author_key"): "the fixture author public key",
    ("vectors/wist1/declaration-key-eligibility.json", "prev_declaration"): "SHA-256 of the original signed predecessor publisher object",
    ("vectors/wist2/feed-regression.json", "x"): "the supplied Declaration public key",
    ("vectors/wist2/feed-regression.json", "value"): "a valid or deliberately invalid signature",
    ("vectors/wist2/feed-fields.json", "domain"): "supplied Canonical Hosts or deliberately malformed field probes",
    ("vectors/wist2/feed-fields.json", "deltas"): "supplied Label or Dispute IDs or deliberately malformed field probes; retrieval is not asserted",
    ("vectors/wist2/feed-fields.json", "x"): "the fixture Declaration public key",
    ("vectors/wist2/feed-fields.json", "value"): "valid or deliberately malformed or invalid signatures",
    ("vectors/wist2/feed-next.json", "deltas"): "supplied Label or Dispute IDs; retrieval is not asserted",
    ("vectors/wist2/feed-next.json", "seen"): "supplied Label or Dispute IDs already seen",
    ("vectors/wist2/feed-next.json", "x"): "the fixture Declaration public key",
    ("vectors/wist2/feed-next.json", "value"): "valid or deliberately invalid signatures",
    ("vectors/wist4/withdrawal.json", "public_key"): "the fixture Log public key",
    ("vectors/wist4/registrable-domain.json", "sha256"): "SHA-256 over a Public Suffix List snapshot's octets: a list of domain-name rules, no page content (WIST-4 §3.1)",
    ("vectors/wist4/registrable-domain.json", "public_key"): "the fixture Log public key",
    ("vectors/wist2/declaration-refresh.json", "prev_declaration"): "SHA-256 of the previous publisher object",
    ("vectors/wist2/declaration-refresh.json", "x"): "a usable or deliberately excluded Ed25519 point",
    ("vectors/wist2/declaration-refresh.json", "value"): "a signature or deliberately invalid signature",
    ("vectors/wist2/declaration-refresh.json", "root"): "the root of an empty Item list (WIST-1 §4): SHA-256 of no octets",
    ("vectors/wist2/declaration-refresh.json", "tree"): "a tree file name (WIST-1 §4.2): SHA-256 over a file listing no Item",
    ("vectors/wist2/declaration-refresh.json", "labels_accepted"): "Label IDs: SHA-256 over Labels, which carry a subject and a registry name, no page content (WIST-2 §3.3)",
    ("vectors/wist2/declaration-refresh.json", "deltas"): "Label IDs listed by a Label Feed: SHA-256 over Labels, no page content (WIST-2 §3.2)",
    ("vectors/wist2/page-bindings.json", "prev_declaration"): "SHA-256 of the previous publisher object",
    ("vectors/wist2/page-bindings.json", "x"): "a usable or deliberately excluded Ed25519 point",
    ("vectors/wist2/page-bindings.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/payload-links.json", "salt"): "the Payload commitment salt",
    ("vectors/wist1/recovery-admission.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/recovery-admission.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/recovery-admission.json", "prev_declaration"): "SHA-256 of a named predecessor publisher object",
    ("vectors/wist1/recovery-admission.json", "pinned_head"): "the trusted shared Epoch prefix hash",
    ("vectors/wist1/recovery-admission.json", "last_inside_pin"): "the trusted last pre-deadline Epoch hash",
    ("vectors/wist1/recovery-admission.json", "deadline_pin"): "the trusted deadline Epoch hash",
    ("vectors/wist1/recovery-admission.json", "pin"): "the trusted alternate deadline Epoch hash",

    ("vectors/wist1/declaration-fields.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/declaration-fields.json", "value"): "an Ed25519 signature or malformed signature-field probe",
    ("vectors/wist1/declaration-fields.json", "author_key"): "the fixture author public key",
    ("vectors/wist1/declaration-fields.json", "prev_declaration"): "SHA-256 of a predecessor publisher object",
    ("vectors/wist1/declaration-fields.json", "pinned_head"): "the trusted candidate Epoch header hash",
    ("vectors/wist1/declaration-conflicts.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/declaration-conflicts.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/declaration-conflicts.json", "prev_declaration"): "SHA-256 of a named predecessor publisher object",
    ("vectors/wist1/declaration-conflicts.json", "pinned_head"): "the trusted final Epoch header hash",
    ("vectors/wist1/declaration-conflicts.json", "expected_accepted_head"): "the accepted Epoch header hash after batch validation",
    ("vectors/wist1/declaration-conflicts.json", "current_envelope"): "SHA-256 of the installed Declaration Envelope including signature",
    ("vectors/wist1/declaration-conflicts.json", "recovery_envelope"): "SHA-256 of the recovery-chain Declaration Envelope including signature",
    ("vectors/wist1/declaration-conflicts.json", "first_candidate"): "SHA-256 of a Declaration Envelope used to discriminate leaf order",
    ("vectors/wist1/recovery-settlement.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/recovery-settlement.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/recovery-settlement.json", "prev_declaration"): "SHA-256 of the named predecessor publisher object",
    ("vectors/wist1/recovery-settlement.json", "pinned_head"): "the trusted final Epoch header hash",
    ("vectors/wist1/recovery-settlement.json", "label"): "SHA-256 of a publisher object",
    ("vectors/wist1/recovery-settlement.json", "predecessor"): "SHA-256 of a named predecessor publisher object",
    ("vectors/wist1/recovery-settlement.json", "effective_declaration"): "SHA-256 of the effective publisher object",
    ("vectors/wist1/recovery-settlement.json", "superseded"): "SHA-256 identifiers of superseded publisher objects",
    ("vectors/wist1/recovery-heads.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/recovery-heads.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/recovery-heads.json", "prev_declaration"): "SHA-256 of the named predecessor publisher object",
    ("vectors/wist1/recovery-heads.json", "pinned_head"): "the trusted final Epoch header hash",
    ("vectors/wist1/recovery-heads.json", "current_declaration"): "SHA-256 of the current publisher object",
    ("vectors/wist1/recovery-heads.json", "recovery_head"): "SHA-256 of the recovery-chain publisher object",
    ("vectors/wist1/recovery-order.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/recovery-order.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/recovery-order.json", "prev_declaration"):
        "SHA-256 over a Declaration's publisher object (WIST-1 section 5.2)",
    ("vectors/wist1/recovery-order.json", "owner_declaration"):
        "SHA-256 over the recovery owner's publisher object (WIST-1 section 5.2)",
    ("vectors/wist1/recovery-order.json", "pinned_head"):
        "the trusted final Epoch header hash (WIST-3 section 3.1)",
    ("vectors/wist1/declaration-binding.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/declaration-binding.json", "prev_declaration"):
        "SHA-256 over a Declaration's publisher object (WIST-1 section 5.2)",
    ("vectors/wist1/declaration-sequence.json", "x"): "an Ed25519 public key",
    ("vectors/wist2/labels.json", "x"): "the example Declaration's Ed25519 public keys",
    ("vectors/wist2/labels.json", "value"): "an Ed25519 signature over a Label",
    ("vectors/wist2/labels.json", "current"): "the current Label's ID after replay (WIST-2 §3.3)",
    ("vectors/wist2/labels.json", "state_tuple"): "the current Label's ID inside a WIST-3 §7 label tuple",
    ("vectors/wist4/withdrawal.json", "state_tuples"): "fixture Item IDs inside WIST-3 §7 withdrawal tuples",
    ("vectors/wist4/withdrawal.json", "record_tuples"): "fixture Catalog IDs inside WIST-3 §7 record tuples",
    ("vectors/wist4/withdrawal.json", "materialized"): "fixture Item IDs whose content materializes",
    ("vectors/wist4/withdrawal.json", "adopted"): "fixture Item IDs inside adopted withdrawal tuples",
    ("vectors/wist4/withdrawal.json", "replay_state_tuples"): "fixture Item IDs inside WIST-3 §7 withdrawal tuples",
    ("vectors/wist4/withdrawal.json", "removal_tuples"):
        "fixture Item IDs of Items of kind removed and Catalog IDs inside WIST-3 §7 removal tuples",
    ("vectors/wist4/registrable-domain.json", "entries"): "Public Suffix List snapshot identifiers and Registry Update IDs inside WIST-3 §7 suffix_list and registry_update tuples",
    ("vectors/wist3/timestamps.json", "entries"): "a placeholder Label ID inside a WIST-3 §7 label or dispute tuple whose timestamp position is probed",
    ("examples/dispute.json", "label"): "the disputed Label's ID: SHA-256 over a Label, no page content (WIST-2 §3.3)",
    ("examples/dispute.json", "value"): "an Ed25519 signature over the example dispute",
    ("examples/label-definition.json", "value"): "an Ed25519 signature over the example definition",
    ("vectors/wist2/disputes.json", "label_id"): "a sealed Label's ID: SHA-256 over a Label, no page content (WIST-2 §3.3)",
    ("vectors/wist2/disputes.json", "label"): "the disputed Label's ID: SHA-256 over a Label, no page content (WIST-2 §3.3)",
    ("vectors/wist2/disputes.json", "value"): "an Ed25519 signature over a dispute or Declaration",
    ("vectors/wist2/disputes.json", "x"): "the fixture disputant and Labeler public keys",
    ("vectors/wist2/disputes.json", "dispute_id"): "a Dispute ID: SHA-256 over a dispute, which carries a Label ID, hosts and a URL, no page content (WIST-2 §3.3)",
    ("vectors/wist2/disputes.json", "current"): "the current dispute's ID after replay (WIST-2 §3.3)",
    ("vectors/wist2/disputes.json", "state_tuple"): "a Label ID inside a WIST-3 §7 dispute tuple",
    ("vectors/wist2/label-definitions.json", "x"): "the example Declaration's Ed25519 public keys",
    ("vectors/wist2/label-definitions.json", "value"): "an Ed25519 signature over a definition",
    ("vectors/wist2/labels.json", "delta"): "the Item ID a Label binds to: SHA-256 over an Item that carries only a salted commitment (WIST-2 §3.3)",
    ("vectors/wist2/labels.json", "record_item"): "the Item ID a record carries (WIST-3 §7): SHA-256 over an Item that carries only a salted commitment",
    ("vectors/wist2/labels.json", "state_tuple"): "a Label's Item binding inside a WIST-3 §7 label tuple",
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
    ("examples/catalog.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("examples/dispute.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("examples/label-definition.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("examples/label-feed.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("examples/label.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("examples/publisher.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/base64url.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/declaration-binding.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/declaration-conflicts.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/declaration-fields.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/declaration-hosts.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/declaration-key-eligibility.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/declaration-sequence.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/envelope.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/recovery-admission.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/recovery-heads.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/recovery-order.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/recovery-settlement.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/declaration-refresh.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/disputes.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/feed-fields.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/feed-next.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/feed-regression.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/label-definitions.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/labels.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/page-bindings.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist3/epoch.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist3/checkpoints.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist3/timestamps.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("examples/publisher.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/base64url.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/base64url.json", "x"): "an Ed25519 public key or a deliberately excluded or malformed point encoding",
    ("vectors/wist1/declaration-binding.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/declaration-conflicts.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/declaration-conflicts.json", "x"): "an Ed25519 public key or a deliberately excluded or malformed point encoding",
    ("vectors/wist1/declaration-fields.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/declaration-fields.json", "x"): "an Ed25519 public key or a deliberately excluded or malformed point encoding",
    ("vectors/wist1/declaration-hosts.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/declaration-hosts.json", "x"): "an Ed25519 public key or a deliberately excluded or malformed point encoding",
    ("vectors/wist1/declaration-key-eligibility.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/declaration-sequence.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/recovery-admission.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/recovery-admission.json", "x"): "an Ed25519 public key or a deliberately excluded or malformed point encoding",
    ("vectors/wist1/recovery-heads.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/key-directory.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/key-directory.json", "kids"): "JWK thumbprints in byte order, the Key Set fingerprint's input (WIST-1 §5.1)",
    ("vectors/wist1/key-directory.json", "x"): "an Ed25519 public key",
    ("vectors/wist1/key-directory.json", "public_key"): "an Ed25519 public key",
    ("vectors/wist1/key-directory.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/key-directory.json", "fingerprint"): "a Key Set fingerprint (WIST-1 §5.1): SHA-256 over the JCS array of thumbprints, no page content",
    ("vectors/wist1/key-directory.json", "next_keys"): "a Key Set fingerprint committing to the next signing set (WIST-1 §5.2), no page content",
    ("vectors/wist1/key-directory.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/key-directory.json", "prev_declaration"): "SHA-256 of the named predecessor publisher object",
    ("vectors/wist1/key-directory.json", "pinned_head"): "the trusted final Epoch header hash",
    ("vectors/wist1/key-directory.json", "current_declaration"): "SHA-256 of the current publisher object",
    ("vectors/wist1/key-directory.json", "pending_head"): "SHA-256 of the pending head publisher object",
    ("vectors/wist1/recovery-heads.json", "x"): "an Ed25519 public key or a deliberately excluded or malformed point encoding",
    ("vectors/wist1/recovery-order.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/recovery-order.json", "x"): "an Ed25519 public key or a deliberately excluded or malformed point encoding",
    ("vectors/wist1/recovery-settlement.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/recovery-settlement.json", "x"): "an Ed25519 public key or a deliberately excluded or malformed point encoding",
    ("vectors/wist2/declaration-refresh.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/disputes.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/feed-fields.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/feed-next.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/feed-regression.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/label-definitions.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/labels.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/page-bindings.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/recovery-settlement.json", "effective_keys"): "thumbprints of a projected Declaration's entries (WIST-1 §5.1), no page content",
    ("vectors/wist1/recovery-settlement.json", "keys"): "thumbprints of a projected Declaration's entries (WIST-1 §5.1), no page content",
    ("vectors/wist1/recovery-settlement.json", "pre_recovery_keys"): "thumbprints of a projected Declaration's entries (WIST-1 §5.1), no page content",
    ("vectors/wist1/recovery-settlement.json", "recovery_keys"): "thumbprints of a projected Declaration's entries (WIST-1 §5.1), no page content",
    ("vectors/wist1/recovery-settlement.json", "signer"): "thumbprints of a projected Declaration's entries (WIST-1 §5.1), no page content",
    ("vectors/wist1/keypair.json", "kid"): "the test key's JWK thumbprint (WIST-1 §5.1)",
    ("vectors/wist1/collection-fields.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/collection-fields.json", "x"): "an Ed25519 public key",
    ("vectors/wist1/collection-fields.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/collection-fields.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/collection-fields.json", "seed_hex"): "a test-only Ed25519 seed, no page content",
    ("vectors/wist1/collection-scope.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/collection-scope.json", "x"): "an Ed25519 public key",
    ("vectors/wist1/collection-scope.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/collection-scope.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/collection-scope.json", "seed_hex"): "a test-only Ed25519 seed, no page content",
    ("vectors/wist1/collection-keys.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/collection-keys.json", "x"): "an Ed25519 public key",
    ("vectors/wist1/collection-keys.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/collection-keys.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/collection-keys.json", "seed_hex"): "a test-only Ed25519 seed, no page content",
    ("vectors/wist1/collection-keys.json", "prev_declaration"): "SHA-256 of the named predecessor publisher object",
    ("vectors/wist1/collection-keys.json", "next_keys"): "a Key Set fingerprint committing to the next signing set (WIST-1 §5.2), no page content",
    ("vectors/wist1/collection-keys.json", "fingerprint"): "a Key Set fingerprint (WIST-1 §5.1): SHA-256 over the JCS array of thumbprints, no page content",
    ("vectors/wist1/collection-narrowing.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/collection-narrowing.json", "x"): "an Ed25519 public key",
    ("vectors/wist1/collection-narrowing.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/collection-narrowing.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/collection-narrowing.json", "seed_hex"): "a test-only Ed25519 seed, no page content",
    ("vectors/wist1/collection-narrowing.json", "prev_declaration"): "SHA-256 of the named predecessor publisher object",
    ("vectors/wist1/collection-narrowing.json", "kind"): "a narrowing transition name, no page content",
    ("vectors/wist2/declaration-pull.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/declaration-pull.json", "x"): "an Ed25519 public key",
    ("vectors/wist2/declaration-pull.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/declaration-pull.json", "value"): "an Ed25519 signature",
    ("vectors/wist2/declaration-pull.json", "seed_hex"): "a test-only Ed25519 seed, no page content",
    ("vectors/wist2/declaration-pull.json", "prev_declaration"): "SHA-256 of the named predecessor publisher object",
    ("vectors/wist2/declaration-pull.json", "acceptance"): "a Declaration acceptance class of WIST-1 §5.2, no page content",
    ("vectors/wist1/item-fields.json", "x"): "an Ed25519 public key",
    ("vectors/wist1/item-fields.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/item-fields.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/item-fields.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/item-fields.json", "seed_hex"): "a test-only Ed25519 seed, no page content",
    ("vectors/wist1/item-fields.json", "item_id"): "an Item ID (ADR-0052): SHA-256 over an Item that carries only a salted commitment",
    ("vectors/wist1/item-fields.json", "key"): "an Item key (ADR-0052): SHA-256 over a URL the Item carries in the clear",
    ("vectors/wist1/item-fields.json", "leaf"): "an Item leaf (ADR-0052): SHA-256 over an Item key and an Item hash, no page content",
    ("vectors/wist1/item-fields.json", "root"): "an Item list root (ADR-0052): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("vectors/wist1/item-fields.json", "tree"): "a tree file name (ADR-0052): SHA-256 over a file of Items that carry only a salted commitment",
    ("vectors/wist1/item-fields.json", "salt"): "Payload salts",
    ("vectors/wist1/item-fields.json", "license"): "a license string of 64 letters at its field bound, no page content",
    ("vectors/wist1/item-fields.json", "prev"): "a member an Item may not carry, all zero digits, no page content",
    ("vectors/wist1/item-roots.json", "keys"): "Item keys (ADR-0052): SHA-256 over URLs the Items carry in the clear",
    ("vectors/wist1/item-roots.json", "leaves"): "Item leaves (ADR-0052): SHA-256 over an Item key and an Item hash, no page content",
    ("vectors/wist1/item-roots.json", "root"): "an Item list root (ADR-0052): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("vectors/wist1/item-roots.json", "tree"): "a tree file name (ADR-0052): SHA-256 over a file of Items that carry only a salted commitment",
    ("vectors/wist1/item-roots.json", "path"): "Inclusion Proof sibling hashes over Item leaves, no page content",
    ("vectors/wist1/item-roots.json", "proof"): "Inclusion Proof sibling hashes in a malformed proof, no page content",
    ("vectors/wist1/item-roots.json", "catalog"): "a Catalog ID (ADR-0052): SHA-256 over a Catalog that carries a root, a tree hash and no page content",
    ("vectors/wist1/item-roots.json", "salt"): "Payload salts",
    ("vectors/wist1/catalog-fields.json", "x"): "an Ed25519 public key",
    ("vectors/wist1/catalog-fields.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/catalog-fields.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist1/catalog-fields.json", "value"): "an Ed25519 signature",
    ("vectors/wist1/catalog-fields.json", "seed_hex"): "a test-only Ed25519 seed, no page content",
    ("vectors/wist1/catalog-fields.json", "root"): "an Item list root (ADR-0052): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("vectors/wist1/catalog-fields.json", "tree"): "a tree file name (ADR-0052): SHA-256 over a file of Items that carry only a salted commitment",
    ("vectors/wist1/catalog-fields.json", "catalog_id"): "a Catalog ID (ADR-0052): SHA-256 over a Catalog that carries a root, a tree hash and no page content",
    ("vectors/wist2/catalog-order.json", "root"): "an Item list root (ADR-0052): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("vectors/wist2/catalog-order.json", "tree"): "a tree file name (ADR-0052): SHA-256 over a file of Items that carry only a salted commitment",
    ("vectors/wist2/catalog-tree.json", "root"): "an Item list root (ADR-0052): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("vectors/wist2/catalog-tree.json", "tree"): "a tree file name (ADR-0052): SHA-256 over a file of Items that carry only a salted commitment",
    ("vectors/wist2/catalog-tree.json", "list"): "Item IDs (ADR-0052): SHA-256 over Items that carry only a salted commitment",
    ("vectors/wist2/catalog-tree.json", "fetched"): "tree file names (ADR-0052): SHA-256 over files of Items that carry only a salted commitment",
    ("vectors/wist2/catalog-items.json", "x"): "an Ed25519 public key",
    ("vectors/wist2/catalog-items.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/catalog-items.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/catalog-items.json", "value"): "an Ed25519 signature",
    ("vectors/wist2/catalog-items.json", "seed_hex"): "a test-only Ed25519 seed, no page content",
    ("vectors/wist2/catalog-items.json", "root"): "an Item list root (ADR-0052): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("vectors/wist2/catalog-items.json", "tree"): "a tree file name (ADR-0052): SHA-256 over a file of Items that carry only a salted commitment",
    ("vectors/wist2/catalog-items.json", "item_id"): "an Item ID (ADR-0052): SHA-256 over an Item that carries only a salted commitment",
    ("vectors/wist2/item-lists.json", "x"): "an Ed25519 public key",
    ("vectors/wist2/item-lists.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/item-lists.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist2/item-lists.json", "value"): "an Ed25519 signature",
    ("vectors/wist2/item-lists.json", "seed_hex"): "a test-only Ed25519 seed, no page content",
    ("vectors/wist2/item-lists.json", "salt"): "Payload salts",
    ("vectors/wist2/change-lists.json", "file"): "a change list name (ADR-0053): the digits of a Catalog ID, SHA-256 over a Catalog that carries no page content",
    ("vectors/wist2/change-lists.json", "list"): "Item IDs (ADR-0052): SHA-256 over Items that carry only a salted commitment",
    ("vectors/wist2/change-lists.json", "root"): "an Item list root (ADR-0052): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("vectors/wist2/change-lists.json", "salt"): "Payload salts",
    ("vectors/wist2/change-list-serving.json", "root"): "an Item list root (ADR-0052): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("vectors/wist2/change-list-serving.json", "tree"): "a tree file name (ADR-0052): SHA-256 over a file of Items that carry only a salted commitment",
    ("vectors/wist2/change-list-serving.json", "name"): "a change list name (ADR-0053): the digits of a Catalog ID, SHA-256 over a Catalog that carries no page content",
    ("vectors/wist2/change-list-serving.json", "sha256"): "the SHA-256 of a change list file (ADR-0053), whose Items carry only a salted commitment",
    ("vectors/wist2/change-list-serving.json", "written"): "a change list name (ADR-0053): the digits of a Catalog ID, SHA-256 over a Catalog that carries no page content",
    ("vectors/wist2/change-list-serving.json", "must_serve"): "change list names (ADR-0053): the digits of Catalog IDs, SHA-256 over Catalogs that carry no page content",
    ("vectors/wist2/change-list-serving.json", "may_serve"): "change list names (ADR-0053): the digits of Catalog IDs, SHA-256 over Catalogs that carry no page content",
    ("vectors/wist2/change-list-serving.json", "must_not_serve"): "change list names (ADR-0053): the digits of Catalog IDs, SHA-256 over Catalogs that carry no page content",
    ("vectors/wist2/change-list-serving.json", "change_list"): "a change list name (ADR-0053): the digits of a Catalog ID, SHA-256 over a Catalog that carries no page content",
    ("vectors/wist2/change-list-serving.json", "salt"): "Payload salts",
    ("vectors/wist2/change-chains.json", "root"): "an Item list root (ADR-0052): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("vectors/wist2/change-chains.json", "tree"): "a tree file name (ADR-0052): SHA-256 over a file of Items that carry only a salted commitment",
    ("vectors/wist2/change-chains.json", "list"): "Item IDs (ADR-0052): SHA-256 over Items that carry only a salted commitment",
    ("vectors/wist2/change-chains.json", "previous"): "the Catalog ID of a previous Catalog (ADR-0053): SHA-256 over a Catalog that carries a root, a tree hash and no page content",
    ("vectors/wist2/change-chains.json", "held_after"): "Catalog IDs whose lists an Aggregator holds (ADR-0053): SHA-256 over Catalogs that carry no page content",
    ("vectors/wist2/change-chains.json", "catalog"): "a Catalog ID (ADR-0052): SHA-256 over a Catalog that carries a root, a tree hash and no page content",
    ("vectors/wist2/change-chains.json", "change_list"): "a Catalog ID (ADR-0052): SHA-256 over a Catalog that carries a root, a tree hash and no page content",
    ("vectors/wist2/change-chains.json", "lists_read"): "Catalog IDs naming the change lists read (ADR-0053): SHA-256 over Catalogs that carry no page content",
    ("vectors/wist2/change-chains.json", "tree_files_fetched"): "tree file names (ADR-0052): SHA-256 over files of Items that carry only a salted commitment",
    ("vectors/wist2/change-chains.json", "salt"): "Payload salts",
    ("vectors/wist3/catalog-sealing.json", "x"): "an Ed25519 public key",
    ("vectors/wist3/catalog-sealing.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist3/catalog-sealing.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/wist3/catalog-sealing.json", "value"): "an Ed25519 signature",
    ("vectors/wist3/catalog-sealing.json", "seed_hex"): "a test-only Ed25519 seed, no page content",
    ("vectors/wist3/catalog-sealing.json", "prev_declaration"): "SHA-256 of the named predecessor publisher object",
    ("vectors/wist3/catalog-sealing.json", "root"): "an Item list root (ADR-0052): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("vectors/wist3/catalog-sealing.json", "tree"): "a tree file name (ADR-0052): SHA-256 over a file of Items that carry only a salted commitment",
    ("vectors/wist3/catalog-sealing.json", "catalog"): "a Catalog ID (ADR-0052): SHA-256 over a Catalog that carries a root, a tree hash and no page content",
    ("vectors/wist3/catalog-sealing.json", "item"): "an Item ID (ADR-0052): SHA-256 over an Item that carries only a salted commitment",
    ("vectors/wist3/catalog-sealing.json", "path"): "Inclusion Proof sibling hashes over Item leaves, no page content",
    ("vectors/multilog/catalog-order.json", "x"): "an Ed25519 public key",
    ("vectors/multilog/catalog-order.json", "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/multilog/catalog-order.json", "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    ("vectors/multilog/catalog-order.json", "value"): "an Ed25519 signature",
    ("vectors/multilog/catalog-order.json", "seed_hex"): "a test-only Ed25519 seed, no page content",
    ("vectors/multilog/catalog-order.json", "prev_declaration"): "SHA-256 of the named predecessor publisher object",
    ("vectors/multilog/catalog-order.json", "root"): "an Item list root (ADR-0052): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    ("vectors/multilog/catalog-order.json", "tree"): "a tree file name (ADR-0052): SHA-256 over a file of Items that carry only a salted commitment",
    ("vectors/multilog/catalog-order.json", "catalog"): "a Catalog ID (ADR-0052): SHA-256 over a Catalog that carries a root, a tree hash and no page content",
    ("vectors/multilog/catalog-order.json", "expected"): "Catalog IDs (ADR-0052): SHA-256 over Catalogs that carry a root, a tree hash and no page content",
    ("vectors/multilog/catalog-order.json", "item"): "an Item ID (ADR-0052): SHA-256 over an Item that carries only a salted commitment",
    ("vectors/multilog/catalog-order.json", "path"): "Inclusion Proof sibling hashes over Item leaves, no page content",
    ("vectors/wist2/served-files.json", "catalog"): "a Catalog ID (ADR-0052) naming a served Catalog the file does not carry, no page content",
    ("vectors/wist2/served-files.json", "withdrawn"): "Item IDs a payload_withdrawal names (WIST-2 §3.1): SHA-256 over Items that carry only a salted commitment",
    ("vectors/wist3/catalog-sealing.json", "salt"): "Payload salts",
    ("vectors/wist2/labels.json", "item"):
        "an Item ID (WIST-1 §4.1) a record carries: SHA-256 over an Item that carries only a salted commitment",
    ("vectors/wist3/record-materialization.json", "update"):
        "a Registry Update ID (WIST-4 §2): SHA-256 over an update, which carries no page content",
    ("vectors/wist4/parameter-in-force.json", "public_key"): "the fixture Log public key",
    ("vectors/wist4/parameter-in-force.json", "value"): "an Ed25519 signature",
    ("vectors/wist4/parameter-in-force.json", "snapshot_tuples"):
        "Registry Update IDs inside WIST-3 §7 registry_update tuples: SHA-256 over an update, no page content",
    ("vectors/wist4/withdrawal.json", "registry_update_tuples"):
        "Registry Update IDs inside WIST-3 §7 registry_update tuples: SHA-256 over an update, no page content",
    ("vectors/wist3/catalog-sealing.json", "label"):
        "a Label ID (WIST-2 §3.3): SHA-256 over a Label, which carries a subject, a name and an integer, no page content",
    ("vectors/wist3/catalog-sealing.json", "dispute"):
        "a Dispute ID (WIST-2 §3.3): SHA-256 over a dispute, which carries a Label ID and a reason URL, no page content",
    ("vectors/wist3/catalog-sealing.json", "item_id"):
        "an Item ID (WIST-1 §4.1) in a content tuple (WIST-3 §7): SHA-256 over an Item that carries only a salted commitment",
    ("vectors/multilog/catalog-order.json", "salt"): "Payload salts",
}

PULL_FIXTURE_CATALOG_NAMES = {
    "vectors/wist3/catalog-waiting.json": (
        "B1", "J1", "J1b", "J1c", "J1m", "J2", "J2x", "J2y", "J3", "J4", "S1", "S2", "S3",
        "J1 a.example.com", "J1 b.example.com", "J2 a.example.com", "J2 b.example.com",
        "S1 a.example.com", "S1 b.example.com", "S2 a.example.com", "S2 b.example.com",
        "J2 under J1's signature"),
    "vectors/wist1/catalog-recovery.json": (
        "D1", "J0", "J0b", "J1", "J1r", "J2", "J2b", "J2e", "J3", "J4", "J4j", "S0", "S1", "S1b", "S2", "So", "W1"),
    "vectors/wist2/collection-pull.json": ("Da", "Db", "J0", "J1", "J1j", "J2", "J3", "K1", "S1"),
}

for _rel, _names in PULL_FIXTURE_CATALOG_NAMES.items():
    NON_CONTENT_VALUES.update({
        (_rel, "x"): "an Ed25519 public key",
        (_rel, "kid"): "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
        (_rel, "key_id"): "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
        (_rel, "value"): "an Ed25519 signature",
        (_rel, "seed_hex"): "a test-only Ed25519 seed, no page content",
        (_rel, "prev_declaration"): "SHA-256 of the named predecessor publisher object",
        (_rel, "root"): "an Item list root (ADR-0052): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
        (_rel, "tree"): "a tree file name (ADR-0052): SHA-256 over a file of Items that carry only a salted commitment",
        (_rel, "tree_files"): "tree file names (ADR-0052): SHA-256 over files of Items that carry only a salted commitment",
        (_rel, "tree_files_fetched"): "tree file names (ADR-0052): SHA-256 over files of Items that carry only a salted commitment",
        (_rel, "catalog"): "a Catalog ID (ADR-0052): SHA-256 over a Catalog that carries a root, a tree hash and no page content",
        (_rel, "last_accepted"): "a Catalog ID (ADR-0052): SHA-256 over a Catalog that carries a root, a tree hash and no page content",
        (_rel, "latest"): "a Catalog ID (ADR-0052): SHA-256 over a Catalog that carries a root, a tree hash and no page content",
        (_rel, "item"): "an Item ID (ADR-0052): SHA-256 over an Item that carries only a salted commitment",
        (_rel, "path"): "Inclusion Proof sibling hashes over Item leaves, no page content",
        (_rel, "salt"): "Payload salts",
    })
    NON_CONTENT_VALUES.update({
        (_rel, name): "a Catalog ID (ADR-0052) under the fixture's name for its Catalog, no page content"
        for name in _names})
_CATALOG_VALUE_MEANINGS = {
    "x": "an Ed25519 public key",
    "kid": "a JWK thumbprint (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    "key_id": "the thumbprint naming a signing entry (WIST-1 §5.1): SHA-256 over an Ed25519 public key, no page content",
    "value": "an Ed25519 signature",
    "seed_hex": "a test-only Ed25519 seed, no page content",
    "root": "an Item list root (WIST-1 §4): a Merkle Tree Hash over leaves that carry only a URL hash and an Item hash",
    "tree": "a tree file name (WIST-1 §4): SHA-256 over a file of Items that carry only a salted commitment",
    "catalog": "a Catalog ID (WIST-1 §3.5): SHA-256 over a Catalog that carries a root, a tree hash and no page content",
    "catalog_id": "a Catalog ID (WIST-1 §3.5): SHA-256 over a Catalog that carries a root, a tree hash and no page content",
    "item": "an Item ID (WIST-1 §4.1): SHA-256 over an Item that carries only a salted commitment",
    "item_id": "an Item ID (WIST-1 §4.1): SHA-256 over an Item that carries only a salted commitment",
    "path": "Inclusion Proof sibling hashes over Item leaves (WIST-1 §4.3), no page content",
    "salt": "Payload salts: from a CSPRNG, never derived from what they key",
    "content_digest": "WIST-3 §7's digest over content tuples, every field Log-derived, no content in the preimage",
    "tuples": "WIST-3 §7 state tuples: Item IDs, Catalog IDs and heights inside them, Log-derived, no page content",
}
for _rel, _keys in (
        ("examples/snapshot-state.json", ("key_id", "root", "tree")),
        ("examples/publisher-item.json", ("catalog",)),
        ("vectors/multilog/dedup.json", ("catalog", "catalog_id", "item", "item_id", "tree")),
        ("vectors/wist3/checkpoints.json", ("catalog", "kid", "root", "salt", "tree", "x")),
        ("vectors/wist3/epoch.json", ("catalog", "kid", "path", "salt", "tree", "x")),
        ("vectors/wist3/record-materialization.json",
         ("catalog", "content_digest", "item", "item_id", "key_id", "kid", "root", "salt", "seed_hex", "tree",
          "tuples", "value", "x")),
        ("vectors/wist3/snapshot-records.json", ("item_id", "key_id", "kid", "root", "salt", "tree", "tuples",
                                                 "value", "x")),
        ("vectors/wist4/withdrawal.json", ("catalog", "item_id", "salt")),
        ("vectors/wist1/declaration-fields.json", ("root", "tree"))):
    NON_CONTENT_VALUES.update({(_rel, key): _CATALOG_VALUE_MEANINGS[key] for key in _keys})
for _rel in ("vectors/wist3/catalog-waiting.json", "vectors/wist2/collection-pull.json"):
    NON_CONTENT_VALUES[(_rel, "outcome")] = "a Declaration outcome name, no page content"
NON_CONTENT_VALUES[("vectors/wist3/catalog-waiting.json", "id")] = (
    "the Label or Dispute ID a rejection reports (WIST-2 §7.1): SHA-256 over a Label or a dispute, no page content")
NON_CONTENT_VALUES[("vectors/wist3/catalog-waiting.json", "label")] = (
    "a Label or Dispute ID (WIST-2 §3.3): SHA-256 over a Label or a dispute, which carries no page content")
for _rel in ("vectors/wist3/catalog-sealing.json", "vectors/wist2/collection-pull.json"):
    NON_CONTENT_VALUES[(_rel, "delta_id")] = ("the Item ID a payload_withdrawal names (ADR-0052): SHA-256 over an Item "
                                              "that carries only a salted commitment")


def _spec_derived_constants():
    """Digest-shaped figures the specs publish that are not literal in a vector.

    Each is *computed* here from a shipped artifact rather than pasted, so a
    spec figure that drifts from what the suite actually produces stops being a
    published figure and the sweep flags it.
    """
    out = set()
    canonical = (ROOT / "vectors" / "wist1" / "catalog.canonical").read_bytes()
    out.add(canonical.hex())                      # WIST-1 App A quotes leading chunks
    item = json.loads((ROOT / "examples" / "item.json").read_text())
    out.add(item_rules.item_id(item)[len("sha256:"):])  # WIST-1 App A's Payload path
    out.add(item_rules.item_key(item["url"]).hex())      # WIST-1 App A's key and leaf
    out.add(item_rules.leaf(item).hex())
    out.add(hashlib.sha256(b"\x00").hexdigest())  # WIST-3 §4's empty-tree constant
    payload = json.loads((ROOT / "examples" / "payload.json").read_text())
    out.add(b64u_decode(payload["salt"]).hex())   # WIST-1 App A shows the salt in hex
    wist3 = json.loads((ROOT / "vectors" / "wist3" / "epoch.json").read_text())
    leaves = [leaf_hash(rfc8785.dumps(e)) for e in wist3["entries"]]
    out.update(h.hex() for h in leaves)           # WIST-3 App A's leaf and node figures
    out.add(node_hash(leaves[0], leaves[1]).hex())
    out.add(node_hash(leaves[2], leaves[3]).hex())
    root = node_hash(node_hash(leaves[0], leaves[1]), node_hash(leaves[2], leaves[3]))
    out.add(root.hex())                            # WIST-3 App A's Checkpoint root line
    out.add(base64.b64encode(root).decode())        # same root, base64 as the Checkpoint carries it
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
    # epochs), or one of the few constants declared below with what it is.
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

    Every window `effective_at` takes part in is compared against an Epoch
    `sealed_at` (WIST-4 §5.1), so a state artifact restating it as an integer
    would make a resuming Consumer compare a height against an instant — and
    the §5 grace period is exactly such a comparison.
    """
    schema = json.loads((ROOT / "schemas" / "snapshot-state.schema.json").read_text())
    validator = Draft202012Validator(schema)
    envelope = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
    good = copy.deepcopy(envelope)
    good["state"]["entries"].append(
        ["parameter", "epoch_cadence_seconds", "2026-08-09T13:00:00Z", 7200])
    validator.validate(good)
    for bad_value in (0, 12, "2026-08-09T13:00:00+00:00", "2026-08-09"):
        bad = copy.deepcopy(envelope)
        bad["state"]["entries"].append(
            ["parameter", "epoch_cadence_seconds", bad_value, 7200])
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


def _dc2_catalog_address_mismatch_code():
    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-2-site-publication.md").read_text())
    assert ("MUST reject a Catalog that names another Publisher or Collection "
            "than the one it was fetched for, with `WIST2-E04`") in prose, \
        "§4 does not type the misaddressed Catalog rejection"
    row = [l for l in (ROOT / "specs" / "WIST-2-site-publication.md")
           .read_text().splitlines() if l.startswith("| WIST2-E04 |")]
    assert row, "no WIST2-E04 registry row"
    assert ("a Catalog that names another Publisher or Collection than the one "
            "it was fetched for") in row[0], \
        "the WIST2-E04 row does not name the case §4 assigns to it"
    assert "a refused Catalog leaves the pull to §5.4" in row[0], \
        "the WIST2-E04 row does not leave a refused Catalog's pull to §5.4"
    assert "Only pings resolving to `WIST2-E02` or `WIST2-E04` count against it" in prose, \
        "the noise set moved"
check("spec:wist2-catalog-address-mismatch", _dc2_catalog_address_mismatch_code)


def _status_from_vectors():
    chains = json.loads((ROOT / "vectors/wist2/change-chains.json").read_text())
    pulls = json.loads((ROOT / "vectors/wist2/collection-pull.json").read_text())
    reports = {}
    for case in chains["cases"]:
        for outcome in case["expected"]:
            if outcome.get("chain") == "discarded":
                reports.setdefault(outcome["report"]["condition"], outcome["report"])
    assert set(reports) == {"fetch", "size", "form", "chain", "result"}, sorted(reports)
    at = "2026-10-01T12:00:00Z"
    rejections = [{"code": r["code"], "at": at, "id": r["catalog"], "collection": "journal",
                   "condition": r["condition"], "change_list": r["change_list"], "detail": "chain discarded"}
                  for r in reports.values()]
    waiting = json.loads((ROOT / "vectors/wist3/catalog-waiting.json").read_text())
    dropped = next(c for history in pulls["histories"] + waiting["histories"] for event in history["expected"]
                   for c in event.get("catalogs", []) if c.get("dropped"))
    rejections.append({"code": "WIST2-E07", "at": at, "id": dropped["catalog"], "collection": dropped["collection"],
                       "urls": dropped["dropped"], "detail": "the list drops the URL of a held record"})
    item = next(i for history in pulls["histories"] for event in history["expected"]
                for c in event.get("catalogs", []) for i in c.get("items", []) if i["outcome"] == "not_admitted")
    rejections.append({"code": "WIST2-E03", "at": at, "id": item["item"], "collection": "journal",
                       "urls": [item["url"]], "detail": "Payload unavailable"})
    rejections.append({"code": "WIST2-E01", "at": at, "collection": "store", "detail": "catalog.json not fetched"})
    waiting = [{"id": reports["fetch"]["catalog"], "deferrals": ["capacity"], "held": False},
               {"id": item["item"], "url": item["url"], "deferrals": [], "held": True},
               {"id": item["item"], "url": item["url"],
                "deferrals": ["recovery_window", "capacity", "catalog_waiting", "latest_fails_i4"], "held": False}]
    status = {"wist_version": "1.0.0", "domain": "example.com", "last_pull_at": at, "quota_remaining": 3,
              "state": "active",
              "collections": [{"name": "journal", "latest": None, "accepted": reports["fetch"]["catalog"],
                               "waiting": waiting},
                              {"name": "store", "latest": dropped["catalog"], "accepted": None, "waiting": []}],
              "rejections": rejections}
    return status


def _status_members():
    validator = Draft202012Validator(json.loads((ROOT / "schemas/status.schema.json").read_text()))
    status = _status_from_vectors()
    validator.validate(status)
    members = {k for r in status["rejections"] for k in r}
    assert members == {"code", "at", "detail", "id", "collection", "urls", "condition", "change_list"}
    prose = re.sub(r"\s+", " ", (ROOT / "specs/WIST-2-site-publication.md").read_text())
    for marker in ("and for `WIST2-E08`, `condition`, one of `fetch`, `size`, `form`, `chain` and `result`, beside "
                   "`id`, the fetched Catalog's ID, and `change_list`, the Catalog ID that names the change list at "
                   "which the condition was met (§5.3)",
                   "`latest`, the Catalog ID of its latest Catalog (WIST-3 §7), or `null`; `accepted`, the Catalog "
                   "ID of its last accepted Catalog (WIST-3 §3.3), or `null`",
                   "named `recovery_window`, `capacity`, `catalog_waiting` and `latest_fails_i4`"):
        assert marker in prose, marker
check("schema:wist2-status-members", _status_members)


def _status_members_twin():
    validator = Draft202012Validator(json.loads((ROOT / "schemas/status.schema.json").read_text()))
    base = _status_from_vectors()
    e08 = next(i for i, r in enumerate(base["rejections"]) if r["code"] == "WIST2-E08")
    e07 = next(i for i, r in enumerate(base["rejections"]) if r["code"] == "WIST2-E07")

    def altered(change):
        doc = copy.deepcopy(base)
        change(doc)
        return doc

    negatives = {
        "condition outside WIST2-E08": lambda d: d["rejections"][e07].update(condition="fetch"),
        "change_list outside WIST2-E08": lambda d: d["rejections"][e07].update(
            change_list=d["rejections"][e08]["change_list"]),
        "WIST2-E08 without condition": lambda d: d["rejections"][e08].pop("condition"),
        "WIST2-E08 without change_list": lambda d: d["rejections"][e08].pop("change_list"),
        "WIST2-E08 without id": lambda d: d["rejections"][e08].pop("id"),
        "WIST2-E08 without collection": lambda d: d["rejections"][e08].pop("collection"),
        "condition outside the five": lambda d: d["rejections"][e08].update(condition="budget"),
        "no collections": lambda d: d.pop("collections"),
        "a waiting entry without held": lambda d: d["collections"][0]["waiting"][0].pop("held"),
        "an unknown deferral": lambda d: d["collections"][0]["waiting"][0].update(deferrals=["quota"]),
        "an empty urls": lambda d: d["rejections"][e07].update(urls=[]),
        "a Catalog ID in uppercase": lambda d: d["collections"][0].update(
            accepted=d["collections"][0]["accepted"].upper().replace("SHA256", "sha256")),
        "a delta_id member": lambda d: d["rejections"][e07].update(delta_id=d["rejections"][e07]["id"]),
        "a WIST3 code": lambda d: d["rejections"][e07].update(code="WIST3-E01"),
    }
    for name, change in negatives.items():
        assert not validator.is_valid(altered(change)), name
check("negative:wist2-status-members", _status_members_twin)


def _tree_file_bucket_members():
    validator = Draft202012Validator(json.loads((ROOT / "schemas/tree-file.schema.json").read_text()))
    bucket = json.loads((ROOT / "examples/tree-file.json").read_text())
    validator.validate(bucket)
    widened = copy.deepcopy(bucket)
    widened["items"][0]["extra"] = True
    validator.validate(widened)
    for name, change in (("no url", lambda item: item.pop("url")),
                         ("a url that is not a string", lambda item: item.update(url=7))):
        broken = copy.deepcopy(bucket)
        change(broken["items"][0])
        assert not validator.is_valid(broken), name
check("schema:wist2-tree-file-bucket-members", _tree_file_bucket_members)


def _publisher_item_validator():
    return Draft202012Validator(json.loads((ROOT / "schemas/publisher-item.schema.json").read_text()),
                                registry=SCHEMA_REGISTRY, format_checker=FormatChecker(formats=[]))

def _sealed_publisher_item_bodies():
    bodies, refused = [], []
    example = json.loads((ROOT / "examples/publisher-item.json").read_text())
    assert example["item"] == json.loads((ROOT / "examples/item.json").read_text())
    assert example["catalog"] == (ROOT / "vectors/wist1/id.txt").read_text().strip()
    assert example["proof"] == {"index": 0, "tree_size": 1, "path": []}
    bodies.append(example)
    for rel in ("vectors/wist3/epoch.json", "vectors/wist3/checkpoints.json", "vectors/multilog/dedup.json"):
        doc = json.loads((ROOT / rel).read_text())
        epochs = [doc] if "entries" in doc else doc.get("epochs") or [ep for log in doc["logs"] for ep in log["epochs"]]
        bodies += [e["body"] for ep in epochs for e in ep["entries"] if e["type"] == "publisher_item"]
    sealing_doc = json.loads((ROOT / "vectors/wist3/catalog-sealing.json").read_text())
    for history in sealing_doc["histories"]:
        verdicts = {d["name"]: d for ex in history["expected"] for d in ex.get("entries", [])}
        for epoch in history["epochs"]:
            for named in epoch["entries"]:
                entry = named.get("entry")
                if not isinstance(entry, dict) or set(entry) != {"type", "body"} or entry["type"] != "publisher_item":
                    continue
                verdict = verdicts.get(named["name"], {})
                (refused if "I1" in verdict.get("failed", []) else bodies).append(entry["body"])
    return bodies, refused

def _publisher_item_bodies():
    validator = _publisher_item_validator()
    bodies, refused = _sealed_publisher_item_bodies()
    assert len(bodies) >= 10, "too few sealed publisher_item bodies to judge the schema by"
    for body in bodies:
        validator.validate(body)
    for body in refused:
        assert not validator.is_valid(body), "a body WIST-3 §3.3 refuses under I1 passes the schema"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert ("`publisher_item` — an object with exactly the members `item`, an Item (WIST-1 §3.3); `collection`, the "
            "name of its Collection in the form of WIST-1 §5.1; `catalog`, the Catalog ID of the Catalog it is proved "
            "against; and `proof`, its Inclusion Proof against that Catalog (WIST-1 §4.3)") in prose
    assert "schemas/publisher-item.schema.json" in prose
check("schema:wist3-publisher-item", _publisher_item_bodies)


def _publisher_item_bodies_twin():
    validator = _publisher_item_validator()
    good = json.loads((ROOT / "vectors/wist3/epoch.json").read_text())
    good = next(e["body"] for e in good["entries"] if e["type"] == "publisher_item")
    validator.validate(good)
    for label, mutate in (
            ("a missing proof", lambda b: b.pop("proof")),
            ("an extra member", lambda b: b.update(delta_id=b["catalog"])),
            ("a catalog that is not a Catalog ID", lambda b: b.update(catalog=b["catalog"][7:])),
            ("a Collection name with an uppercase letter", lambda b: b.update(collection="Default")),
            ("a negative index", lambda b: b["proof"].update(index=-1)),
            ("a path element of 63 digits", lambda b: b["proof"].update(path=["0" * 63])),
            ("an Item without its meta", lambda b: b["item"].pop("meta"))):
        bad = copy.deepcopy(good)
        mutate(bad)
        assert not validator.is_valid(bad), f"{label} passed schemas/publisher-item.schema.json"
check("negative:wist3-publisher-item", _publisher_item_bodies_twin)

def _wist3_empty_epoch():
    """WIST-3 §3.2, §4: the empty tree before Epoch 0, and Epoch 1 of the
    Appendix A Log (WIST-3 §4's `size(N) == size(N-1)` empty Epoch), which
    restates Epoch 0's tree size and root a cadence later."""
    v = json.loads((ROOT / "vectors" / "wist3" / "empty-epoch.json").read_text())
    assert v["empty_tree_size"] == 0
    assert v["empty_tree_root"] == "sha256:" + hashlib.sha256(b"").hexdigest(), \
        "the empty tree's root is not RFC 6962's MTH of the empty sequence"
    epoch0 = json.loads((ROOT / "vectors" / "wist3" / "epoch.json").read_text())
    assert v["epoch_0_root"] == epoch0["root"], "epoch_0_root does not match epoch.json's root"

    anchor_env = json.loads((ROOT / "examples" / "log-anchor.json").read_text())
    log_id = anchor_env["anchor"]["log_id"]
    genesis_pub = b64u_decode(anchor_env["anchor"]["genesis_key"]["public_key"])
    epoch1 = v["epoch_1"]
    assert epoch1["entries"] == [], "Epoch 1 of the empty-Epoch vector carries Entries"
    cp0 = verify_checkpoint(epoch0["checkpoint"], log_id, {log_id: genesis_pub})
    cp1 = verify_checkpoint(epoch1["checkpoint"], log_id, {log_id: genesis_pub})
    assert cp1["tree_size"] == cp0["tree_size"] == epoch0["tree_size"], \
        "Epoch 1 does not restate Epoch 0's tree size"
    assert cp1["root"] == cp0["root"] and "sha256:" + cp1["root"].hex() == v["epoch_0_root"], \
        "Epoch 1 does not restate Epoch 0's root"
    assert cp1["epoch_number"] == cp0["epoch_number"] + 1
    assert cp1["sealed_at"] > cp0["sealed_at"], "Epoch 1 is not sealed strictly later"

    assert v["consistency_proof_4_to_4"] == [], \
        "a Consistency Proof between equal tree sizes carries no nodes (WIST-3 §4)"
    verify_consistency(cp0["tree_size"], cp1["tree_size"], cp0["root"], cp1["root"],
                       [bytes.fromhex(h) for h in v["consistency_proof_4_to_4"]])

    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "equality is an empty Epoch" in prose
check("vectors:wist3-empty-epoch", _wist3_empty_epoch)

def _checkpoint_vector():
    return json.loads((ROOT / "vectors" / "wist3" / "checkpoints.json").read_text())

def _cp_keys(v):
    anchor_env = json.loads((ROOT / "examples" / "log-anchor.json").read_text())
    log_id = anchor_env["anchor"]["log_id"]
    genesis_pub = b64u_decode(anchor_env["anchor"]["genesis_key"]["public_key"])
    assert log_id == v["log_id"], "checkpoints.json's log_id does not match the example Log"
    return log_id, {log_id: genesis_pub}

def _cp_witness_keys(v):
    return {name: b64u_decode(pub) for name, pub in v["witness_roster"].items()}

def _wist3_checkpoints():
    """WIST-3 §§4-6, 8-10: Checkpoint note form, Consistency Proofs,
    rollback, the three Equivocation forms (§5), the archive path rule
    (§6), Witness quorum (§5, WIST-4 §5 `checkpoint_witness_quorum`), and
    the §8 step 5 Snapshot cold-start match — over one cumulative tree of
    7 leaves."""
    v = _checkpoint_vector()
    log_id, keys = _cp_keys(v)
    witness_keys = _cp_witness_keys(v)

    for case in v["note_form_cases"]:
        try:
            cp = verify_checkpoint(case["checkpoint"], log_id, keys, witness_keys)
            result = "valid"
        except ValueError as e:
            assert "WIST3-E03" in str(e), f"{case['name']}: wrong code: {e}"
            result = "WIST3-E03"
        assert result == case["expected"], f"{case['name']}: got {result}, want {case['expected']}"
        if result == "valid":
            assert cp["cosigners"] == [], \
                f"{case['name']}: a line from an untrusted signer was counted as a cosigner"

    epochs = {b["epoch_number"]: b for b in v["epochs"]}
    cumulative = []
    for bn in sorted(epochs):
        b = epochs[bn]
        cp = verify_checkpoint(b["checkpoint"], log_id, keys)
        assert cp["epoch_number"] == bn, f"epoch {bn}: epoch_number mismatch"
        cumulative += [leaf_hash(rfc8785.dumps(e)) for e in b["entries"]]
        assert cp["tree_size"] == len(cumulative) == len(b["leaf_hashes"]), \
            f"epoch {bn}: tree_size does not match the cumulative Entry count"
        assert [h.hex() for h in cumulative] == b["leaf_hashes"], \
            f"epoch {bn}: leaf_hashes does not match the cumulative Entries"
        assert cp["root"] == merkle_root(cumulative), f"epoch {bn}: root does not match the cumulative tree"
    assert len(cumulative) == 7, "the vector's cumulative tree is not 7 leaves"

    for case in v["consistency_cases"]:
        m_root = bytes.fromhex(case["m_root"].split(":", 1)[1])
        n_root = bytes.fromhex(case["n_root"].split(":", 1)[1])
        path = [bytes.fromhex(h) for h in case["path"]]
        try:
            verify_consistency(case["m"], case["n"], m_root, n_root, path)
            result = "valid"
        except ValueError:
            result = "WIST3-E02"
        assert result == case["expected"], case["name"]

    for case in v["rollback_cases"]:
        offered = verify_checkpoint(case["offered_checkpoint"], log_id, keys)
        assert offered["epoch_number"] < case["verified_head_epoch_number"], case["name"]
        result = "not_adopted"
        if case["verified_checkpoint"] is not None:
            held = verify_checkpoint(case["verified_checkpoint"], log_id, keys)
            assert held["epoch_number"] == offered["epoch_number"], case["name"]
            if case["verified_checkpoint"].split("\n\n", 1)[0] != case["offered_checkpoint"].split("\n\n", 1)[0]:
                result = "WIST3-E02"
        assert result == case["expected"], case["name"]

    # WIST-3 §3.1's sequence failures. A Checkpoint stating a tree size
    # below the head's has no Entries to walk, so the key set valid at N is
    # the one valid at N-1; it is §5's third Equivocation form only when its
    # signature verifies under that set and its root is not the head tree's
    # root at the smaller size. Equivocation decides a Checkpoint failing
    # more than one rule; every other failure, alone or combined, is
    # `WIST3-E03`, and `WIST3-E01` is the unobtainable Checkpoint below an
    # offered one that breaks no rule itself.
    cadence = v["epoch_cadence_seconds"]
    for case in v["sequence_cases"]:
        held = verify_checkpoint(case["verified_checkpoint"], log_id, keys)
        assert held["epoch_number"] == case["verified_head_epoch_number"], case["name"]
        try:
            offered = verify_checkpoint(case["offered_checkpoint"], log_id, keys)
            signed = True
        except ValueError as e:
            assert "WIST3-E03" in str(e), f"{case['name']}: wrong code: {e}"
            offered = parse_checkpoint(case["offered_checkpoint"])
            signed = False
        assert signed == case["signature_verifies"], case["name"]
        assert offered["epoch_number"] > held["epoch_number"], case["name"]
        sealed = log_seconds(offered["sealed_at"])
        below = offered["tree_size"] < held["tree_size"]
        assert ("larger_tree_leaf_hashes" in case) == below, case["name"]
        equivocates = False
        if below:
            larger = [bytes.fromhex(h) for h in case["larger_tree_leaf_hashes"]]
            assert merkle_root(larger) == held["root"], \
                f"{case['name']}: the stated hashes do not reproduce the larger tree's root"
            equivocates = signed and merkle_root(larger[:offered["tree_size"]]) != offered["root"]
        if equivocates:
            result = "WIST3-E02"
        elif below or not signed or sealed <= log_seconds(held["sealed_at"]) or sealed % cadence:
            result = "WIST3-E03"
        elif "unobtainable_epoch_number" in case:
            result = "WIST3-E01"
        else:
            result = "valid"
        if "unobtainable_epoch_number" in case:
            assert held["epoch_number"] < case["unobtainable_epoch_number"] < \
                offered["epoch_number"], case["name"]
        assert result == case["expected"], f"{case['name']}: got {result}"
        head = offered["epoch_number"] if result == "valid" else held["epoch_number"]
        assert head == case["expected_head_epoch_number"], case["name"]
        assert ("evidence" in case) == (result == "WIST3-E02"), case["name"]
        if result == "WIST3-E02":
            assert case["evidence"] == ["verified_checkpoint", "offered_checkpoint",
                                        "larger_tree_leaf_hashes"], case["name"]
    assert {c["expected"] for c in v["sequence_cases"]} == \
        {"valid", "WIST3-E01", "WIST3-E02", "WIST3-E03"}, \
        "the sequence cases must exercise acceptance and all three codes"
    combined = next(c for c in v["sequence_cases"]
                    if c["name"].startswith("off-grid sealed_at and a tree size below"))
    combined_cp = verify_checkpoint(combined["offered_checkpoint"], log_id, keys)
    assert log_seconds(combined_cp["sealed_at"]) % cadence \
        and combined_cp["tree_size"] < held["tree_size"] \
        and combined["expected"] == "WIST3-E02", \
        "the multi-failure case must break the grid rule and the size rule and still be E02"

    for case in v["equivocation_cases"]:
        cp1 = verify_checkpoint(case["checkpoint_1"], log_id, keys)
        cp2 = verify_checkpoint(case["checkpoint_2"], log_id, keys)
        if case["form"].startswith("same tree size"):
            assert cp1["tree_size"] == cp2["tree_size"] and cp1["root"] != cp2["root"], case["form"]
        elif case["form"].startswith("same epoch_number"):
            assert cp1["epoch_number"] == cp2["epoch_number"], case["form"]
            assert cp1["tree_size"] == cp2["tree_size"] and cp1["root"] == cp2["root"], case["form"]
            assert cp1["sealed_at"] != cp2["sealed_at"], case["form"]
        else:
            leaves2 = [bytes.fromhex(h) for h in case["leaf_hashes_2"]]
            assert merkle_root(leaves2) == cp2["root"], \
                "leaf_hashes_2 does not reproduce checkpoint_2's root"
            assert merkle_root(leaves2[:cp1["tree_size"]]) != cp1["root"], \
                "checkpoint_1's root is a valid prefix of checkpoint_2's tree: not equivocation"
        assert case["expected"] == "WIST3-E02"

    for case in v["archive_cases"]:
        cp = verify_checkpoint(case["checkpoint"], log_id, keys)
        m = re.fullmatch(r"/log/checkpoints/(\d{9})", case["path"])
        assert m, f"{case['name']}: path does not match §6's archive form"
        result = "valid" if int(m.group(1)) == cp["epoch_number"] else "WIST3-E03"
        assert result == case["expected"], case["name"]

    for case in v["quorum_cases"]:
        try:
            cp = verify_checkpoint(case["checkpoint"], log_id, keys, witness_keys)
        except ValueError as e:
            assert "WIST3-E03" in str(e), f"{case['name']}: wrong code: {e}"
            assert case["expected"] == "WIST3-E03", case["name"]
            continue
        adopted = len(set(cp["cosigners"])) >= case["quorum"]
        result = "valid" if adopted else "not_adopted"
        assert result == case["expected"], f"{case['name']}: got {result}, want {case['expected']}"
        if "unwitnessed" in case:
            assert (len(cp["cosigners"]) == 0) == case["unwitnessed"], case["name"]

    # WIST-3 §8 steps 4-5: the state artifact's `tree_size` against the
    # manifest's first (`WIST3-E04`), then the Checkpoint the manifest's
    # `epoch_number` selects. A file at that path stating another
    # `epoch_number` is the source's fault (`WIST3-E03`) and never
    # divergence, whatever else it states.
    for case in v["cold_start_cases"]:
        m = case["manifest"]
        cp = verify_checkpoint(case["checkpoint"], log_id, keys)
        if case["state_tree_size"] != m["tree_size"]:
            result = "WIST3-E04"
        elif cp["epoch_number"] != m["epoch_number"]:
            result = "WIST3-E03"
        elif (m["tree_size"] != cp["tree_size"]
              or m["root_hash"] != "sha256:" + cp["root"].hex()):
            result = "WIST3-E02"
        else:
            result = "valid"
        assert result == case["expected"], f"{case['name']}: got {result}"
        head = m["epoch_number"] if result == "valid" else None
        assert head == case["expected_head_epoch_number"], case["name"]
    assert {c["expected"] for c in v["cold_start_cases"]} == \
        {"valid", "WIST3-E02", "WIST3-E03", "WIST3-E04"}, \
        "the cold-start cases must exercise acceptance, divergence, a source fault and E04"
    off_path = next(c for c in v["cold_start_cases"] if c["expected"] == "WIST3-E03")
    off_cp = verify_checkpoint(off_path["checkpoint"], log_id, keys)
    assert off_cp["tree_size"] != off_path["manifest"]["tree_size"], \
        "the source-fault case must also disagree on tree size, or it does not " \
        "separate WIST3-E03 from WIST3-E02"

    # WIST-3 §4, §5: a validly signed Checkpoint stating tree size 0 is judged
    # by the Consistency Proof from the empty tree to itself, which compares
    # the size-0 root rather than skipping the empty proof.
    for case in v["size_zero_cases"]:
        cp = verify_checkpoint(case["checkpoint"], log_id, keys)
        assert cp["tree_size"] == 0, case["name"]
        try:
            verify_consistency(0, cp["tree_size"], cp["root"], cp["root"], [])
            result = "valid"
        except ValueError:
            result = "WIST3-E02"
        assert result == case["expected"], case["name"]
    assert {c["expected"] for c in v["size_zero_cases"]} == {"valid", "WIST3-E02"}, \
        "the size-0 cases must exercise both outcomes"

    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    for marker in (
            "The root hash line is the RFC 4648 §4 base64 encoding, padding "
            "included, of exactly 32 octets, and re-encoding the decoded octets "
            "reproduces the line.",
            "Every signature line, the last included, ends in a newline (U+000A).",
            "a key name that is non-empty and contains no plus (U+002B) and no "
            "character with the Unicode White_Space property",
            "A note carries at most 16 signature lines: a Consumer MUST accept 16 "
            "and MUST reject 17 or more",
            "or is off the grid, is `WIST3-E03`, whether or not its signature verifies",
            "unless its signature verifies under that set and its root is not the "
            "root of Checkpoint N−1's tree at the smaller size: that is §5's third "
            "form of Equivocation (`WIST3-E02`)",
            "A Checkpoint failing more than one of these rules is `WIST3-E02` when "
            "that form applies and `WIST3-E03` otherwise.",
            "an archived Checkpoint no source serves is `WIST3-E01`",
            "The manifest's `epoch_number` selects the Checkpoint and is never "
            "itself compared for divergence",
            "a state file whose `tree_size` is not the manifest's"):
        assert marker in prose, f"WIST-3 does not state: {marker!r}"
check("vectors:wist3-checkpoints", _wist3_checkpoints)

def _wist3_checkpoints_twin():
    """Mutation twin: the checker above must notice a genuinely broken
    Consistency Proof node, and must count a Witness's cosignature only
    under the trusted roster it is actually given."""
    v = _checkpoint_vector()
    log_id, keys = _cp_keys(v)
    witness_keys = _cp_witness_keys(v)

    good = next(c for c in v["consistency_cases"] if c["name"] == "4 to 7")
    m_root = bytes.fromhex(good["m_root"].split(":", 1)[1])
    n_root = bytes.fromhex(good["n_root"].split(":", 1)[1])
    path = [bytes.fromhex(h) for h in good["path"]]
    verify_consistency(good["m"], good["n"], m_root, n_root, path)  # positive control
    broken = list(path)
    broken[0] = bytes([broken[0][0] ^ 1]) + broken[0][1:]
    try:
        verify_consistency(good["m"], good["n"], m_root, n_root, broken)
    except ValueError:
        pass
    else:
        raise AssertionError("a corrupted Consistency Proof node still verified")

    adopted_case = next(c for c in v["quorum_cases"]
                        if c["name"] == "quorum 2, two distinct trusted cosignatures: adopted")
    cp = verify_checkpoint(adopted_case["checkpoint"], log_id, keys, witness_keys)
    assert len(set(cp["cosigners"])) >= adopted_case["quorum"], "positive control: expected adoption"
    shrunk_roster = {n: p for n, p in witness_keys.items() if n != "witness-b.example"}
    cp_shrunk = verify_checkpoint(adopted_case["checkpoint"], log_id, keys, shrunk_roster)
    assert len(set(cp_shrunk["cosigners"])) < adopted_case["quorum"], \
        "dropping a trusted Witness from the roster did not lower the count below quorum"

    # The size-0 rejection is the root comparison, not a signature failure:
    # the Checkpoint verifies, and the same size and signature check pass once
    # the stated root is the empty tree's.
    diverging = next(c for c in v["size_zero_cases"] if c["expected"] == "WIST3-E02")
    cp = verify_checkpoint(diverging["checkpoint"], log_id, keys)
    assert cp["root"] != hashlib.sha256(b"").digest(), "the case states the empty-tree root"
    verify_consistency(0, 0, hashlib.sha256(b"").digest(), hashlib.sha256(b"").digest(), [])

    # The §3.1 sequence rejections are not signature failures and not each
    # other: the off-grid and tree-size-below Checkpoints verify as objects,
    # and the accepted control breaks under each rule in turn.
    cadence = v["epoch_cadence_seconds"]
    for name in ("sealed_at off the epoch_cadence_seconds grid",
                 "tree size below the previous Checkpoint's, validly signed"):
        case = next(c for c in v["sequence_cases"] if c["name"] == name)
        verify_checkpoint(case["offered_checkpoint"], log_id, keys)
    control = next(c for c in v["sequence_cases"] if c["expected"] == "valid")
    held = verify_checkpoint(control["verified_checkpoint"], log_id, keys)
    offered = verify_checkpoint(control["offered_checkpoint"], log_id, keys)
    assert log_seconds(offered["sealed_at"]) % cadence == 0 \
        and log_seconds(offered["sealed_at"]) > log_seconds(held["sealed_at"]) \
        and offered["tree_size"] >= held["tree_size"] \
        and offered["epoch_number"] == held["epoch_number"] + 1, \
        "the accepted control does not satisfy every §3.1 sequence rule"
    for broken in v["sequence_cases"]:
        if broken["expected"] == "valid":
            continue
        assert broken["offered_checkpoint"] != control["offered_checkpoint"], \
            f"{broken['name']}: the rejected candidate is the accepted control"

    # A note one signature line over the limit is rejected for that line
    # alone: the same note without it is accepted.
    sixteen = next(c for c in v["note_form_cases"] if c["name"] == "note carrying 16 signature lines")
    seventeen = next(c for c in v["note_form_cases"] if c["name"] == "note carrying 17 signature lines")
    parse_checkpoint(sixteen["checkpoint"])
    assert seventeen["checkpoint"].startswith(sixteen["checkpoint"]), \
        "the 17-line note is not the 16-line note plus one line"
    try:
        parse_checkpoint(seventeen["checkpoint"])
    except ValueError as e:
        assert "WIST3-E03" in str(e)
    else:
        raise AssertionError("a 17-line note parsed")
check("negative:wist3-checkpoints", _wist3_checkpoints_twin)

def _keyset_vector():
    return json.loads((ROOT / "vectors" / "wist1" / "keyset-at-height.json").read_text())

def _keyset_at(declarations, height):
    """WIST-1 §5.2, ordinary case: the highest-seq Declaration sealed at a
    height <= N, the Epoch's own Declarations included."""
    best = None
    for d in declarations:
        if d["height"] <= height and (best is None or d["seq"] > best["seq"]):
            best = d
    return best["keys"] if best else []

def _wist1_keyset_at_height():
    """WIST-1 §5.2: the Key Set a sealed Catalog verifies under is resolved at
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
        verifies = [c["catalog_id"] for c in case["catalogs"]
                    if c["signer"] in _keyset_at(decls, c["height"])]
        rejected = [c["catalog_id"] for c in case["catalogs"] if c["catalog_id"] not in verifies]
        assert verifies == case["expected"]["verifies"], f"{name}: verifies"
        assert rejected == case["expected"]["rejected"], f"{name}: WIST1-E02"
        for c in case["catalogs"]:
            beside = [x for x in decls if x["height"] == c["height"]]
            if beside and c["signer"] not in beside[-1]["keys"] and c["catalog_id"] in rejected:
                saw_beside_rejected = True
            if beside and c["signer"] in beside[-1]["keys"] and c["catalog_id"] in verifies:
                saw_beside_verified = True
            if not any(x["height"] <= c["height"] for x in decls):
                saw_orphan = c["catalog_id"] in rejected
    assert saw_beside_rejected and saw_beside_verified and saw_orphan, \
        "the vector must exercise a Catalog beside the retiring Declaration, one " \
        "beside the admitting one, and one below every Declaration"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-item-format.md").read_text())
    for marker in (
            "The Declaration in force for a Publisher at Epoch N, which judges its "
            "`publisher_catalog` and `publisher_item` Entries sealed in Epoch N",
            "settlements and activations have applied under this section"):
        assert marker in prose, f"§5.2 does not state: {marker!r}"
check("vectors:wist1-keyset-at-height", _wist1_keyset_at_height)

def _wist1_keyset_at_height_twin():
    """The check above must notice a Catalog sealed beside the Declaration
    retiring its key: with that Declaration read one Epoch late, the
    Catalog would verify."""
    v = _keyset_vector()
    case = next(c for c in v["cases"] if c["name"] == "rotation retiring the old key")
    late = [dict(d, height=d["height"] + 1) if d["seq"] > 0 else d
            for d in case["declarations"]]
    beside = next(c for c in case["catalogs"] if c["catalog_id"] == "c-beside-old")
    assert beside["signer"] in _keyset_at(late, beside["height"]), \
        "the twin's late Declaration did not admit the stranded Catalog"
    assert beside["signer"] not in _keyset_at(case["declarations"], beside["height"]), \
        "recomputation is blind to a Declaration sealed beside the Catalog"
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

    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-item-format.md").read_text())
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
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-item-format.md").read_text())
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
                pool.setdefault(k["kid"], k["x"])
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
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-item-format.md").read_text())
    assert ("MUST NOT list the same public key (`x`, equivalently `kid`) in both "
            "`keys` and `recovery_keys`") in prose, \
        "§5.2 does not forbid a key serving as both a signing and a recovery key"
    # The suite's own Declaration must satisfy the rule it states.
    publisher = json.loads((ROOT / "examples" / "publisher.json").read_text())["publisher"]
    signing = {(k["kid"], k["x"]) for k in publisher["keys"]}
    recovery = {(k["kid"], k["x"]) for k in publisher.get("recovery_keys", [])}
    assert not {i for i, _ in signing} & {i for i, _ in recovery}, \
        "the publisher example shares a kid across its two key sets"
    assert not {k for _, k in signing} & {k for _, k in recovery}, \
        "the publisher example shares a public key across its two key sets"
    idempotent = [c for c in v["cases"] if c["expected"] == "idempotent"]
    assert idempotent, "no idempotent re-serve case"
    for case in idempotent:
        assert rfc8785.dumps(case["stored"]["publisher"]) == \
            rfc8785.dumps(case["fetched"]["publisher"]), \
            "the idempotent case's publisher objects are not byte-identical"
check("vectors:wist1-declaration-sequence", _dc1_declaration_sequence_vector)

def _jwk_thumbprint(x):
    """RFC 7638 over the three required OKP members, in JCS order (WIST-1 §5.1)."""
    return base64.urlsafe_b64encode(hashlib.sha256(rfc8785.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": x})).digest()).rstrip(b"=").decode()


def _keyset_fingerprint(entries):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(sorted(e["kid"] for e in entries))).hexdigest()


def _key_entry_error(publisher):
    for field in ("keys", "recovery_keys"):
        for entry in publisher.get(field, []):
            if entry["kid"] != _jwk_thumbprint(entry["x"]):
                return "WIST1-E14"
            if "exp" in entry and entry["exp"] <= entry["nbf"]:
                return "WIST1-E14"
    return None


def _declaration_binding_result(stored, incoming, usable_key=None, signature_check=None):
    current = incoming["publisher"]
    if error := _key_entry_error(current):
        return error
    keys = current["keys"] + current.get("recovery_keys", [])
    public = [key["x"] for key in keys]
    if len(public) != len(set(public)):
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
    candidates = [key for key in candidates if key["kid"] == incoming["sig"]["key_id"]]
    if usable_key:
        candidates = [key for key in candidates if usable_key(key)]
    if not candidates:
        return "WIST1-E02"
    verified = set()
    for key in candidates:
        if signature_check and not signature_check(key, incoming):
            continue
        try:
            Ed25519PublicKey.from_public_bytes(b64u_decode(key["x"])).verify(
                b64u_decode(incoming["sig"]["value"]), rfc8785.dumps(current))
        except Exception:
            continue
        verified.add(key["x"])
    if not verified:
        return "WIST1-E01"
    assert len(verified) == 1
    if not previous:
        return "initial"
    public_key = verified.pop()
    if public_key in {key["x"] for key in previous["keys"]
                      if usable_key is None or usable_key(key)}:
        result = "ordinary_rotation"
    elif public_key in {key["x"] for key in previous.get("recovery_keys", [])
                        if usable_key is None or usable_key(key)}:
        result = "recovery_rotation"
    else:
        result = "fresh_identity"
    if result != "recovery_rotation" and previous.get("recovery_keys"):
        if rfc8785.dumps(previous["recovery_keys"]) != rfc8785.dumps(current.get("recovery_keys", [])):
            return "WIST1-E08"
    if result == "ordinary_rotation" and "next_keys" in previous:
        kept = ({k["kid"] for k in previous["keys"]} == {k["kid"] for k in current["keys"]}
                and current.get("next_keys") == previous["next_keys"])
        if not kept and _keyset_fingerprint(current["keys"]) != previous["next_keys"]:
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
        "initial", "ordinary_rotation", "recovery_rotation", "fresh_identity",
        "WIST1-E01", "WIST1-E02", "WIST1-E08", "WIST1-E14"}


check("vectors:wist1-declaration-binding", _declaration_binding_vectors)


def _declaration_key_eligibility_vectors():
    vector = json.loads((ROOT / "vectors/wist1/declaration-key-eligibility.json").read_text())
    validator = Draft202012Validator(json.loads(
        (ROOT / "schemas/publisher.schema.json").read_text()))

    def canonical_bytes(value):
        return canonical_b64u_decode(value)

    def usable(key):
        raw = canonical_bytes(key["x"])
        try:
            point = ed25519_curve.string_to_point(raw)
        except ed25519_curve.InvalidProof:
            return False
        return not ed25519_curve._is_identity(ed25519_curve._mul(8, point))

    def signature(key, envelope):
        return _ed25519_profile_verdict(canonical_bytes(key["x"]),
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
            excluded_public.update(key["x"] for key in env["publisher"].get(field, []) if not usable(key))
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
    publisher_schema = Draft202012Validator(json.loads(
        (ROOT / "schemas/publisher.schema.json").read_text()))
    log_id = vector["log_key"]["key_id"]
    keys = {log_id: b64u_decode(vector["log_key"]["public_key"])}
    reversed_same_epoch = ascending_same_epoch = later_epoch = ordinary_prefix = False
    for case in vector["cases"]:
        stored, previous_time = None, None
        leaves = []
        sequences, recoveries = [], []
        for height, epoch in enumerate(case["epochs"]):
            cp = verify_checkpoint(epoch["checkpoint"], log_id, keys)
            entries = epoch["entries"]
            assert cp["epoch_number"] == height
            instant = log_seconds(cp["sealed_at"])
            assert previous_time is None or instant > previous_time
            previous_time = instant
            hashes = [leaf_hash(rfc8785.dumps(entry)) for entry in entries]
            assert hashes == sorted(hashes)
            leaves.extend(hashes)
            assert cp["tree_size"] == len(leaves)
            root = merkle_root(leaves) if leaves else hashlib.sha256(b"").digest()
            assert cp["root"] == root
            assert all(entry["type"] == "publisher_declaration" for entry in entries)
            candidates = [entry["body"] for entry in entries]
            assert len({env["publisher"]["domain"] for env in candidates}) == 1
            assert len({env["publisher"]["seq"] for env in candidates}) == len(candidates), \
                "ownership fixtures must not settle conflicting-candidate disposition"
            for incoming in sorted(candidates, key=lambda env: env["publisher"]["seq"]):
                publisher_schema.validate(incoming)
                assert stored is None or incoming["publisher"]["domain"] == stored["publisher"]["domain"]
                result = _declaration_binding_result(stored, incoming)
                assert result in {"initial", "ordinary_rotation", "recovery_rotation"}, case["name"]
                if result == "recovery_rotation":
                    recoveries.append((height, cp["sealed_at"], incoming,
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
        final_root = merkle_root(leaves) if leaves else hashlib.sha256(b"").digest()
        assert "sha256:" + final_root.hex() == case["pinned_head"]
        assert len(recoveries) == 2
        owner_height, opened_at, owner, first_leaf = recoveries[0]
        next_height, _, successor, next_leaf = recoveries[1]
        assert log_seconds(cp["sealed_at"]) < (
            log_seconds(opened_at) + vector["recovery_window_days"] * 86400)
        initial = case["epochs"][0]["entries"][0]["body"]["publisher"]
        assert successor["sig"]["key_id"] not in {
            key["kid"] for key in initial["keys"] + initial.get("recovery_keys", [])
            + successor["publisher"]["keys"]}
        derived = {"application_sequences": sequences,
                   "owner_sequence": owner["publisher"]["seq"],
                   "owner_height": owner_height,
                   "owner_declaration": "sha256:" + hashlib.sha256(rfc8785.dumps(owner["publisher"])).hexdigest(),
                   "opened_at": opened_at, "windows_opened": 1}
        assert derived == case["expected"], case["name"]
        assert (next_leaf < first_leaf) == case["recovery_leaves_reversed"]
        reversed_same_epoch |= owner_height == next_height and next_leaf < first_leaf
        ascending_same_epoch |= owner_height == next_height and first_leaf < next_leaf
        later_epoch |= owner_height < next_height
        ordinary_prefix |= owner["publisher"]["seq"] > 1
    assert reversed_same_epoch and ascending_same_epoch and later_epoch and ordinary_prefix


check("vectors:wist1-recovery-order", _recovery_order_vectors)

def _declaration_history_epochs(vector, epochs, pinned, entry_types=("publisher_declaration",)):
    """Replays a Log's Epochs (WIST-3 §§3-5): each Epoch's Checkpoint is
    authenticated under `vector["log_key"]`; tree size and root are
    recomputed from the cumulative leaf sequence, since no Epoch object
    carries them (WIST-3 §3 - "No object represents an Epoch"); Entries
    within an Epoch are position-checked against the canonical type order.
    Returns `(checkpoint, publisher_declaration bodies)` per Epoch, where
    `checkpoint` is `parse_checkpoint`'s dict (its `sealed_at`/`epoch_number`
    keys read the same as the old per-Epoch header did)."""
    log_id = vector["log_key"]["key_id"]
    keys = {log_id: b64u_decode(vector["log_key"]["public_key"])}
    ranks = {name: rank for rank, name in enumerate(
        ("publisher_declaration", "registry_update", "publisher_catalog", "publisher_item", "label",
         "dispute"))}
    previous_time = None
    leaves = []
    authenticated = []
    for height, epoch in enumerate(epochs):
        cp = verify_checkpoint(epoch["checkpoint"], log_id, keys)
        entries = epoch["entries"]
        instant = log_seconds(cp["sealed_at"])
        assert previous_time is None or instant == previous_time + 3600
        assert cp["epoch_number"] == height
        hashes = [leaf_hash(rfc8785.dumps(entry)) for entry in entries]
        positions = [(ranks[entry["type"]], hashed) for entry, hashed in zip(entries, hashes)]
        assert positions == sorted(positions)
        leaves.extend(hashes)
        assert cp["tree_size"] == len(leaves)
        root = merkle_root(leaves) if leaves else hashlib.sha256(b"").digest()
        assert cp["root"] == root
        assert all(entry["type"] in entry_types for entry in entries)
        authenticated.append((cp, [entry["body"] for entry in entries
                                   if entry["type"] == "publisher_declaration"]))
        previous_time = instant
    final_root = merkle_root(leaves) if leaves else hashlib.sha256(b"").digest()
    assert "sha256:" + final_root.hex() == pinned
    return authenticated


def _recovery_history_reference(vector, field_error=None, activation_epochs=None):
    validators = {name: Draft202012Validator(json.loads(
        (ROOT / f"schemas/{name}.schema.json").read_text()))
        for name in ("publisher",)}
    delay = vector.get("declaration_activation_epochs", 24) if activation_epochs is None else activation_epochs

    def digest(envelope):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(envelope["publisher"])).hexdigest()

    def settle(state, instant):
        if state["end"] is not None and instant >= log_seconds(state["end"]):
            state["current"] = state["chain"]
            state["chain"], state["end"] = None, None

    def activate(state, height):
        """WIST-1 §5.2: the pending head becomes current at its activation height."""
        if state["pending"] is not None and height >= state["activation"]:
            state["current"], state["reset_height"] = state["pending"], height
            state["pending"], state["activation"] = None, None

    def apply(state, incoming, instant, spelling, height):
        if field_error and (error := field_error(incoming)):
            return error
        validators["publisher"].validate(incoming)
        settle(state, instant)
        activate(state, height)
        current = state["current"]
        if current and rfc8785.dumps(current["publisher"]) == rfc8785.dumps(incoming["publisher"]):
            return "idempotent"
        if state["pending"] is not None and rfc8785.dumps(
                state["pending"]["publisher"]) == rfc8785.dumps(incoming["publisher"]):
            return "idempotent"
        if incoming["publisher"]["seq"] <= state["floor"]:
            return "WIST1-E08"
        previous = None
        if current:
            assert incoming["publisher"]["domain"] == current["publisher"]["domain"]
            previous = next((head for head in (current, state["chain"], state["pending"])
                             if head and digest(head) == incoming["publisher"].get("prev_declaration")), None)
            if previous is None:
                return "WIST1-E08"
        outcome = _declaration_binding_result(previous, incoming)
        if outcome not in {"initial", "ordinary_rotation", "recovery_rotation", "fresh_identity"}:
            return outcome
        if state["pending"] is not None and previous == state["pending"]:
            state["pending"], state["floor"] = incoming, incoming["publisher"]["seq"]
            return outcome
        if outcome == "fresh_identity" and state["chain"] is None:
            if state["pending"] is not None:
                return "WIST1-E08"
            state["floor"] = incoming["publisher"]["seq"]
            if delay > 0:
                state["pending"], state["activation"] = incoming, height + delay
            else:
                state["current"], state["reset_height"] = incoming, height
            return outcome
        state["pending"], state["activation"] = None, None
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

    def apply_epoch(states, header, candidates, reverse_domains=False):
        updated = copy.deepcopy(states)
        instant = log_seconds(header["sealed_at"])
        for state in updated.values():
            settle(state, instant)
            activate(state, header["epoch_number"])
        grouped = {}
        for incoming in candidates:
            if field_error and (error := field_error(incoming)):
                return error, states
            validators["publisher"].validate(incoming)
            inner = incoming["publisher"]
            grouped.setdefault(inner["domain"], {}).setdefault(inner["seq"], []).append(incoming)
        for domain in sorted(grouped, reverse=reverse_domains):
            state = updated.setdefault(domain, {"current": None, "chain": None, "floor": -1,
                                                "end": None, "windows": 0, "reset_height": None,
                                                "pending": None, "activation": None})
            for seq in sorted(grouped[domain]):
                group = grouped[domain][seq]
                current = state["current"]
                if current and all(rfc8785.dumps(env["publisher"]) == rfc8785.dumps(current["publisher"])
                                   for env in group):
                    continue
                if len({rfc8785.dumps(env) for env in group}) != 1:
                    return "WIST1-E08", states
                result = apply(state, group[0], instant, header["sealed_at"], header["epoch_number"])
                if result not in {"initial", "ordinary_rotation", "recovery_rotation", "fresh_identity"}:
                    return result, states
        return "accepted", updated

    def replay(epochs, pinned):
        states = {}
        prefix_states = []
        for header, candidates in _declaration_history_epochs(vector, epochs, pinned):
            outcome, states = apply_epoch(states, header, candidates)
            assert outcome == "accepted"
            assert len(states) == 1
            prefix_states.append(copy.deepcopy(next(iter(states.values()))))
        return prefix_states

    return apply, summary, replay, apply_epoch


def _declaration_conflict_vectors():
    vector = json.loads((ROOT / "vectors/wist1/declaration-conflicts.json").read_text())
    _, _, _, apply_epoch = _recovery_history_reference(vector)
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
        epochs = vector["prefixes"][case["prefix"]] + [case["epoch"]]
        authenticated = _declaration_history_epochs(vector, epochs, case["pinned_head"])
        keys = {}
        for _, candidates in authenticated:
            for env in candidates:
                inner = env["publisher"]
                for key in inner["keys"] + inner.get("recovery_keys", []):
                    keys.setdefault(key["kid"], set()).add(key["x"])
        assert len(case["signature_valid"]) == len(case["epoch"]["entries"])
        for entry, expected_valid in zip(case["epoch"]["entries"], case["signature_valid"]):
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
            assert probe["incoming"] in [entry["body"] for entry in case["epoch"]["entries"]]
            assert _declaration_binding_result(probe["previous"], probe["incoming"]) == probe["expected_result"], case["name"]
        if "sibling_leaves_reversed" in case:
            first = case["epoch"]["entries"][0]["body"]
            assert (digest(first) != case["first_candidate"]) == case["sibling_leaves_reversed"]
            reversed_leaves.add(case["sibling_leaves_reversed"])
        diagnostics = set()
        for reverse_domains in (False, True):
            states = {}
            accepted_head = "sha256:" + hashlib.sha256(b"").hexdigest()
            for header, candidates in authenticated:
                before = copy.deepcopy(states)
                result, updated = apply_epoch(states, header, candidates, reverse_domains)
                assert states == before, "Epoch evaluation mutated its accepted prefix"
                if header["epoch_number"] < len(epochs) - 1:
                    assert result == "accepted", case["name"]
                else:
                    assert result in case["expected_results"], case["name"]
                    diagnostics.add(result)
                    reordered_result, reordered = apply_epoch(states, header, list(reversed(candidates)), reverse_domains)
                    assert (reordered_result, reordered) == (result, updated), case["name"]
                if result == "accepted":
                    states, accepted_head = updated, "sha256:" + header["root"].hex()
                else:
                    assert updated == before, "rejected Epoch changed Declaration or settlement state"
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
    _, _, _, apply_epoch = _recovery_history_reference(vector, field_error)
    outcomes, prefixes = set(), set()
    for case in vector['epoch_cases']:
        history = vector['prefixes'][case['prefix']]
        epochs = _declaration_history_epochs(vector, history + [case['epoch']], case['pinned_head'])
        for reverse_domains in (False, True):
            states = {}
            for header, entries in epochs[:-1]:
                result, states = apply_epoch(states, header, entries, reverse_domains)
                assert result == 'accepted', case['name']
            before = copy.deepcopy(states)
            header, entries = epochs[-1]
            result, updated = apply_epoch(states, header, entries, reverse_domains)
            assert result == case['expected'], case['name']
            assert states == before
            assert apply_epoch(states, header, list(reversed(entries)), reverse_domains) == (result, updated)
            if result != 'accepted':
                assert updated == before
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
        damaged = copy.deepcopy(case['epoch'])
        damaged['entries'][0]['body']['publisher']['domain'] = 'tampered.example'
        try:
            _declaration_history_epochs(vector, history + [damaged], case['pinned_head'])
        except AssertionError:
            pass
        else:
            raise AssertionError('unauthenticated host Epoch accepted')
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


def _in_window(entry, instant):
    """WIST-1 §5.1: a signing binding is eligible when nbf <= generated_at < exp."""
    return entry["nbf"] <= instant and ("exp" not in entry or instant < entry["exp"])


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
        if not validator.is_valid(envelope):
            return "WIST1-E14"
        if envelope["publisher"]["wist_version"].partition(".")[0] != "1":
            return "WIST1-E15"
        return None

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
    def generated_seconds(envelope):
        value = envelope["catalog"].get("generated_at")
        try:
            return log_seconds(value) if isinstance(value, str) else None
        except ValueError:
            return None
    for case in vector["key_time_cases"]:
        declaration, envelope = case["declaration"], case["envelope"]
        for env, inner in ((declaration, "publisher"), (envelope, "catalog")):
            author.verify(b64u_decode(env["sig"]["value"]), rfc8785.dumps(env[inner]))
            changed = copy.deepcopy(env[inner])
            if inner == "publisher":
                changed["keys"][0]["nbf"] += 1
            else:
                changed["generated_at"] += "0"
            try:
                author.verify(b64u_decode(env["sig"]["value"]), rfc8785.dumps(changed))
            except InvalidSignature:
                pass
            else:
                raise AssertionError("changed timestamp retained its signature")
        result = field_error(declaration)
        generated = generated_seconds(envelope)
        if result is None and generated is None:
            result = "WIST1-E14"
        if result is None:
            entry = declaration["publisher"]["keys"][0]
            result = "key_bound_satisfied" if _in_window(entry, generated) else "WIST1-E02"
        assert result == case["expected"], case["name"]
    for case in vector["relation_cases"]:
        env = case["envelope"]
        author.verify(b64u_decode(env["sig"]["value"]), rfc8785.dumps(env["catalog"]))
        generated = generated_seconds(env)
        assert generated is not None, case["name"]
        if case["kind"] == "clock":
            result = ("WIST1-E06" if generated - publisher_instant(case["reference"]) > 600
                      else "relation_satisfied")
        else:
            assert case["kind"] == "item"
            item = case["item"]
            assert env["catalog"]["generated_at"] == case["reference"]
            assert item["publisher"] == env["catalog"]["publisher"]
            assert _publisher_timestamp_format(item["observed_at"]), case["name"]
            result = ("WIST1-E06" if publisher_instant(item["observed_at"]) > generated
                      else "relation_satisfied")
        assert result == case["expected"], case["name"]
    assert {c["kind"] for c in vector["relation_cases"]} == {"clock", "item"}
    for case in vector["elapsed_cases"]:
        assert publisher_instant(case["end"]) - publisher_instant(case["start"]) == Fraction(case["seconds"])
    assert publisher_instant("1970-01-01T00:00:00Z") == 0
    assert publisher_instant("0000-01-01T00:00:00+23:59") == -62167305540
    assert publisher_instant("9999-12-31T23:59:59-23:59") == 253402387139
    _, _, _, apply_epoch = _recovery_history_reference(vector, field_error)
    outcomes, prefixes = set(), set()
    for case in vector["epoch_cases"]:
        history = vector["prefixes"][case["prefix"]]
        authenticated = _declaration_history_epochs(vector, history + [case["epoch"]], case["pinned_head"])
        for reverse_domains in (False, True):
            states = {}
            for header, candidates in authenticated[:-1]:
                result, states = apply_epoch(states, header, candidates, reverse_domains)
                assert result == "accepted", case["name"]
            before = copy.deepcopy(states)
            header, candidates = authenticated[-1]
            result, updated = apply_epoch(states, header, candidates, reverse_domains)
            assert result == case["expected"], case["name"]
            assert states == before, "candidate evaluation changed accepted state"
            assert apply_epoch(states, header, list(reversed(candidates)), reverse_domains) == (result, updated)
            if result != "accepted":
                assert updated == before, "rejected fields changed state or settled recovery"
            else:
                assert set(updated) == {"example.com", "other.example"}
                expected_env = max((env for env in candidates if env["publisher"]["domain"] == "example.com"),
                                   key=lambda env: env["publisher"]["seq"])
                assert updated["example.com"]["current"] == expected_env
                assert updated["example.com"]["floor"] == expected_env["publisher"]["seq"]
            outcomes.add(result)
            prefixes.add(case["prefix"])
        damaged = copy.deepcopy(case["epoch"])
        damaged["entries"][0]["body"]["publisher"]["contact"] = "changed after signing"
        try:
            _declaration_history_epochs(vector, history + [damaged], case["pinned_head"])
        except AssertionError:
            pass
        else:
            raise AssertionError("field rejection vector did not authenticate its Epoch")
    assert outcomes == {"accepted", "WIST1-E14", "WIST1-E15", "WIST1-E08", "WIST1-E01"}
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
                kind = "x" if "{42}" in pattern else "signature" if "{85}" in pattern else "salt"
                nodes[kind].append((filename, Draft202012Validator(node)))
            for child in node.values():
                visit(child, filename)
        elif isinstance(node, list):
            for child in node:
                visit(child, filename)

    for path in (ROOT / "schemas").glob("*.json"):
        visit(json.loads(path.read_text()), path.name)
    assert {kind: len(items) for kind, items in nodes.items()} == {"x": 7, "signature": 12, "salt": 1}

    def encoding_result(value, kind):
        try:
            size = len(canonical_b64u_decode(value))
        except (ValueError, TypeError):
            return "WIST1-E14"
        good = size >= 16 if kind == "salt" else size == (32 if kind == "x" else 64)
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
        values = [(key["x"], "x") for field in ("keys", "recovery_keys")
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
        if "cross set noncanonical spelling" in case["name"]:
            signing = env["publisher"]["keys"][0]["x"]
            recovery = env["publisher"]["recovery_keys"][0]["x"]
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
                    key["x"] = base64.urlsafe_b64encode(b64u_decode(key["x"])).rstrip(b"=").decode()
            assert rfc8785.dumps(fixed["publisher"]) != rfc8785.dumps(env["publisher"])
            try:
                author.verify(b64u_decode(env["sig"]["value"]), rfc8785.dumps(fixed["publisher"]))
            except InvalidSignature:
                pass
            else:
                raise AssertionError("normalizing signed public keys preserved the signature")
    _, _, _, apply_epoch = _recovery_history_reference(vector, field_error)
    for case in vector["epoch_cases"]:
        history = vector["prefixes"][case["prefix"]]
        epochs = _declaration_history_epochs(vector, history + [case["epoch"]], case["pinned_head"])
        states = {}
        for header, entries in epochs[:-1]:
            result, states = apply_epoch(states, header, entries)
            assert result == "accepted", case["name"]
        before = copy.deepcopy(states)
        header, entries = epochs[-1]
        result, updated = apply_epoch(states, header, entries)
        assert result == case["expected"], case["name"]
        assert states == before
        assert apply_epoch(states, header, list(reversed(entries)), True) == (result, updated)
        if result == "WIST1-E14":
            assert updated == before
        else:
            assert "other.example" in updated
            if case["prefix"] == "deadline":
                assert before["example.com"]["chain"] is not None
                assert updated["example.com"]["chain"] is None
                assert updated["example.com"]["floor"] == before["example.com"]["floor"]
                assert updated["example.com"]["current"] == before["example.com"]["chain"]
        damaged = copy.deepcopy(case["epoch"])
        damaged["entries"][0]["body"]["publisher"]["domain"] = "tampered.example"
        try:
            _declaration_history_epochs(vector, history + [damaged], case["pinned_head"])
        except AssertionError:
            pass
        else:
            raise AssertionError("unauthenticated Epoch accepted")


check("vectors:wist1-base64url", _base64url_vectors)

def _wist1_recovery_settlement():
    vector = json.loads((ROOT / "vectors/wist1/recovery-settlement.json").read_text())
    apply, _, replay, _ = _recovery_history_reference(vector)
    def digest(inner):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(inner)).hexdigest()
    saw_named_competitor = False
    for case in vector["cases"]:
        name = case["name"]
        states = replay(case["epochs"], case["pinned_head"])
        projections = [case["initial_declaration"], case["recovery_declaration"]] + case["window_declarations"]
        bindings = {}
        for height, projection in enumerate(projections):
            env = projection["envelope"]
            inner = env["publisher"]
            assert case["epochs"][height]["entries"] == [{"type": "publisher_declaration", "body": env}]
            assert projection["label"] == digest(inner)
            assert projection["predecessor"] == inner.get("prev_declaration")
            assert projection["signer"] == env["sig"]["key_id"]
            for field in ("keys", "recovery_keys"):
                assert projection[field] == [key["kid"] for key in inner.get(field, [])]
                for key in inner.get(field, []):
                    assert bindings.setdefault(key["kid"], key) == key
        initial, recovery = projections[:2]
        expected = case["expected"]
        assert case["pre_recovery_keys"] == initial["keys"]
        assert states[1]["windows"] == states[-1]["windows"] == 1
        assert states[168]["chain"] is not None and states[169]["chain"] is None
        assert log_seconds(epoch_sealed_at(case["epochs"][169])) == log_seconds(states[1]["end"])
        head = states[-1]["current"]
        assert digest(head["publisher"]) == expected["effective_declaration"], name
        assert [key["kid"] for key in head["publisher"]["keys"]] == expected["effective_keys"]
        superseded = []
        for height, projection in enumerate(projections[2:], 2):
            env = projection["envelope"]
            if states[height]["chain"] != env:
                superseded.append(projection["label"])
                old_head = states[height - 1]["chain"]["publisher"]
                signer_key = bindings[env["sig"]["key_id"]]["x"]
                saw_named_competitor |= signer_key in {key["x"] for key in old_head["keys"]}
        assert superseded == expected["superseded"], name
        for probe in case["probes"]:
            height = probe["prefix_height"] + 1
            state = copy.deepcopy(states[height - 1])
            before = copy.deepcopy(state)
            spelling = epoch_sealed_at(case["epochs"][height])
            result = apply(state, probe["candidate"], log_seconds(spelling), spelling, height)
            assert result == probe["expected_result"], (name, probe["name"], result)
            assert state == before, "rejected candidate changed its prefix"
    assert saw_named_competitor, "a shared key must not join the chain via a competitor"
    prose = re.sub(r"\s+", " ", (ROOT / "specs/WIST-1-item-format.md").read_text())
    for marker in (
            "each source is read alone, with its own Collections, Scopes and keys",
            "Every queued Catalog is judged again by C1 (WIST-3 §3.3) under the settlement source",
            "The rejection is of the queued copy and not of the Catalog's identity"):
        assert marker in prose


check("vectors:wist1-recovery-settlement", _wist1_recovery_settlement)

def _recovery_state_from_tuples(declaration, window, pending=None):
    """WIST-3 §7/§8: the reference state a Consumer resumes from the tuples."""
    state = {"current": declaration[2], "chain": None, "floor": declaration[4], "end": None,
             "windows": 0, "reset_height": None, "pending": None, "activation": None}
    if window is not None:
        state["chain"], state["end"] = window[4], window[3]
    if pending is not None:
        state["pending"], state["activation"] = pending[2], pending[4]
    return state

def _recovery_heads_vectors():
    vector = json.loads((ROOT / "vectors/wist1/recovery-heads.json").read_text())
    apply, summary, replay, _ = _recovery_history_reference(vector)
    def digest(envelope):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(envelope["publisher"])).hexdigest()
    states = replay(vector["epochs"], vector["pinned_head"])
    for expected in vector["expected_prefix_states"]:
        assert summary(states[expected["height"]]) == expected["state"], expected["height"]
    branch_states = [replay(branch["epochs"], branch["pinned_head"]) for branch in vector["branches"]]
    for branch, derived in zip(vector["branches"], branch_states):
        assert summary(derived[-1]) == branch["expected_state"]
    outcomes = set()
    for probe in vector["probes"]:
        selected = vector["branches"][probe["branch"]] if "branch" in probe else vector
        selected_states = branch_states[probe["branch"]] if "branch" in probe else states
        state = copy.deepcopy(selected_states[probe["prefix_height"]])
        instant = log_seconds(probe["candidate_sealed_at"])
        assert instant > log_seconds(epoch_sealed_at(selected["epochs"][probe["prefix_height"]]))
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
        assert vector["epochs"][declaration[3]]["entries"][0]["body"] == declaration[2]
        if window is not None:
            assert window[0] == "recovery_window" and len(window) == 6
            assert vector["epochs"][window[5]]["entries"][0]["body"] == window[4]
            assert vector["epochs"][window[2]]["entries"], "owner height names an empty Epoch"
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
        epochs = copy.deepcopy(vector["epochs"])
        pinned = vector["pinned_head"]
        if target == "author":
            epochs[3]["entries"][0]["body"]["sig"]["value"] = epochs[2]["entries"][0]["body"]["sig"]["value"]
        elif target == "header":
            lines5, lines4 = epochs[5]["checkpoint"].split("\n"), epochs[4]["checkpoint"].split("\n")
            lines5[4] = lines4[4]
            epochs[5]["checkpoint"] = "\n".join(lines5)
        elif target == "predecessor":
            epochs[3]["entries"][0]["body"]["publisher"]["prev_declaration"] = digest(
                epochs[2]["entries"][0]["body"])
        elif target == "head":
            pinned = "sha256:" + "00" * 32
        else:
            del epochs[100]
        try:
            replay(epochs, pinned)
        except Exception:
            pass
        else:
            raise AssertionError(f"recovery history accepted tampered {target}")


check("vectors:wist1-recovery-heads", _recovery_heads_vectors)

def _catalog_key_check(declaration_inner, envelope):
    """WIST-1 §5.1 key check of a Catalog of the default Collection against one
    Declaration's signing set, the window read at generated_at."""
    catalog = envelope["catalog"]
    Draft202012Validator(json.loads((ROOT / "schemas/catalog.schema.json").read_text())).validate(envelope)
    assert catalog["collection"] == "default" and catalog["size"] == 0
    assert catalog["root"] == "sha256:" + hashlib.sha256(b"").hexdigest()
    assert catalog["tree"] == "sha256:" + hashlib.sha256(rfc8785.dumps({"items": []})).hexdigest()
    generated = log_seconds(catalog["generated_at"])
    named = [k for k in declaration_inner["keys"] if k["kid"] == envelope["sig"]["key_id"]]
    eligible = [k for k in named if k["nbf"] <= generated and ("exp" not in k or generated < k["exp"])]
    if not eligible:
        result = "WIST1-E02"
    else:
        result = "WIST1-E01"
        for key in eligible:
            try:
                Ed25519PublicKey.from_public_bytes(b64u_decode(key["x"])).verify(
                    b64u_decode(envelope["sig"]["value"]), rfc8785.dumps(catalog))
                result = "accepted"
                break
            except Exception:
                continue
    assert catalogs.catalog_disposition(envelope, declaration_inner, catalog["generated_at"]) == result
    return result


def _key_directory_vectors():
    vector = json.loads((ROOT / "vectors/wist1/key-directory.json").read_text())
    validator = Draft202012Validator(json.loads((ROOT / "schemas/publisher.schema.json").read_text()))
    kat = vector["thumbprints"][0]
    assert kat["x"] == "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    assert kat["kid"] == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    for row in vector["thumbprints"]:
        assert _jwk_thumbprint(row["x"]) == row["kid"], row["name"]
    for row in vector["fingerprints"]:
        assert _keyset_fingerprint([{"kid": k} for k in row["kids"]]) == row["fingerprint"], row["name"]
    example = json.loads((ROOT / "examples/publisher.json").read_text())["publisher"]
    record = vector["dns_record"]
    assert record["name"] == "_wist." + example["domain"] and record["domain"] == example["domain"]
    assert record["txt"] == "v=wist1; keys=" + _keyset_fingerprint(example["keys"])
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-1-item-format.md").read_text())
    assert "`v=wist1; keys=<fingerprint>`" in prose
    assert "MUST NOT let the result change whether a Declaration or a Catalog is accepted" in prose

    def initial_result(envelope):
        if not validator.is_valid(envelope):
            return "WIST1-E14"
        return _key_entry_error(envelope["publisher"]) or _declaration_binding_result(None, envelope)

    seen = set()
    for case in vector["entry_cases"]:
        assert initial_result(case["envelope"]) == case["expected"], case["name"]
        seen.add(case["expected"])
    assert seen == {"initial", "WIST1-E14", "WIST1-E08"}

    seen = set()
    for case in vector["window_cases"]:
        declaration = case["declaration"]
        assert initial_result(declaration) == "initial", case["name"]
        assert _catalog_key_check(declaration["publisher"], case["envelope"]) == case["expected"], case["name"]
        seen.add(case["expected"])
    assert seen == {"accepted", "WIST1-E02", "WIST1-E01"}

    seen = set()
    for case in vector["commitment_cases"]:
        validator.validate(case["stored"]); validator.validate(case["fetched"])
        assert _declaration_binding_result(case["stored"], case["fetched"]) == case["expected"], case["name"]
        seen.add(case["expected"])
    assert seen == {"ordinary_rotation", "recovery_rotation", "fresh_identity", "WIST1-E08"}

    def digest(envelope):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(envelope["publisher"])).hexdigest()

    def summary(state):
        return {"current_declaration": digest(state["current"]),
                "pending_head": digest(state["pending"]) if state["pending"] else None,
                "activation_height": state["activation"], "highest_accepted_seq": state["floor"],
                "reset_height": state["reset_height"], "window_end": state["end"]}

    replayed, engines = {}, {}
    for name, history in vector["histories"].items():
        epochs_param = history.get("declaration_activation_epochs", vector["declaration_activation_epochs"])
        apply, _, replay, _ = _recovery_history_reference(vector, activation_epochs=epochs_param)
        states = replay(history["epochs"], history["pinned_head"])
        replayed[name], engines[name] = states, apply
        for row in history["expected_states"]:
            assert summary(states[row["height"]]) == row["state"], (name, row["height"])
    assert any(s["pending"] is not None for s in replayed["activated"])
    assert replayed["activated"][-1]["reset_height"] == 26 and replayed["activated"][-1]["pending"] is None
    assert replayed["reversed by a signing key"][-1]["reset_height"] is None
    assert replayed["reversed by a recovery key"][-1]["end"] is not None
    assert replayed["activation delay zero"][2]["reset_height"] == 2

    outcomes = set()
    for case in vector["rejections"]:
        history = vector["histories"][case["history"]]
        state = copy.deepcopy(replayed[case["history"]][case["prefix_height"]])
        before = copy.deepcopy(state)
        instant = log_seconds(case["candidate_sealed_at"])
        assert instant == log_seconds(epoch_sealed_at(history["epochs"][case["prefix_height"]])) + 3600
        result = engines[case["history"]](state, case["candidate"], instant, case["candidate_sealed_at"],
                                          case["prefix_height"] + 1)
        assert result == case["expected"], case["name"]
        if result == "fresh_identity":
            assert state["pending"] == case["candidate"], case["name"]
        else:
            assert state == before, case["name"]
        outcomes.add(result)
    assert outcomes == {"WIST1-E08", "fresh_identity", "idempotent"}

    resumed = 0
    for row in vector["snapshot_tuples"]:
        history = vector["histories"][row["history"]]
        declaration, pending = row["declaration"], row["pending_declaration"]
        assert declaration[0] == "declaration" and len(declaration) == 5
        assert history["epochs"][declaration[3]]["entries"][0]["body"] == declaration[2]
        if pending is not None:
            assert pending[0] == "pending_declaration" and len(pending) == 5
            assert history["epochs"][pending[3]]["entries"][0]["body"] == pending[2]
        state = _recovery_state_from_tuples(declaration, None, pending)
        derived = replayed[row["history"]][row["height"]]
        resumed_view = {k: v for k, v in summary(state).items() if k != "reset_height"}
        assert resumed_view == {k: v for k, v in summary(derived).items() if k != "reset_height"}, \
            (row["history"], row["height"])
        for case in vector["rejections"]:
            if case["history"] != row["history"] or case["prefix_height"] != row["height"]:
                continue
            state = _recovery_state_from_tuples(declaration, None, pending)
            result = engines[case["history"]](state, case["candidate"], log_seconds(case["candidate_sealed_at"]),
                                              case["candidate_sealed_at"], case["prefix_height"] + 1)
            assert result == case["expected"], ("resume", case["name"])
            resumed += 1
    assert resumed >= 3
    prose3 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "| `pending_declaration` | domain | the pending head Envelope, its sealing height, the activation height |" in prose3

    seen = set()
    for case in vector["catalog_probes"]:
        state = replayed[case["history"]][case["prefix_height"]]
        assert _catalog_key_check(state["current"]["publisher"], case["envelope"]) == case["expected"], case["name"]
        seen.add(case["expected"])
    assert seen == {"accepted", "WIST1-E02"}
    for target in ("author", "header", "omission"):
        history = copy.deepcopy(vector["histories"]["activated"])
        epochs, pinned = history["epochs"], history["pinned_head"]
        if target == "author":
            epochs[2]["entries"][0]["body"]["sig"]["value"] = epochs[0]["entries"][0]["body"]["sig"]["value"]
        elif target == "header":
            lines5, lines4 = epochs[5]["checkpoint"].split("\n"), epochs[4]["checkpoint"].split("\n")
            lines5[4] = lines4[4]
            epochs[5]["checkpoint"] = "\n".join(lines5)
        else:
            del epochs[10]
        _, _, replay, _ = _recovery_history_reference(vector, activation_epochs=24)
        try:
            replay(epochs, pinned)
        except Exception:
            pass
        else:
            raise AssertionError(f"activation history accepted tampered {target}")


check("vectors:wist1-key-directory", _key_directory_vectors)


def _item_proved(item, proof, catalog):
    key = hashlib.sha256(rfc8785.dumps(["page", item["url"]])).digest()
    leaf = hashlib.sha256(b"\x00" + key + hashlib.sha256(rfc8785.dumps(item)).digest()).digest()
    index, size, path = proof["index"], proof["tree_size"], [bytes.fromhex(h) for h in proof["path"]]
    assert size == catalog["size"] and 0 <= index < size, "proof shape"
    h, fn, sn = leaf, index, size - 1
    while sn > 0:
        if fn % 2 == 1:
            h = node_hash(path.pop(0), h)
        elif fn < sn:
            h = node_hash(h, path.pop(0))
        fn, sn = fn // 2, sn // 2
    assert not path and "sha256:" + h.hex() == catalog["root"], "the Inclusion Proof does not reach the root"

def _multilog_dedup(v, schemas=None):
    formats = FormatChecker(formats=[])
    validators = {name: Draft202012Validator(json.loads((ROOT / f"schemas/{name}.schema.json").read_text()),
                                             registry=SCHEMA_REGISTRY, format_checker=formats)
                  for name in ("publisher", "catalog", "publisher-item")}
    declaration = v["publisher_declaration"]
    validators["publisher"].validate(declaration)
    inner = declaration["publisher"]
    assert _key_entry_error(inner) is None, "declaration key entries fail §5.1 checks"
    assert _declaration_binding_result(None, declaration) == "initial", \
        "declaration is not an accepted first (seq 0) self-signed Declaration"
    keys = {e["kid"]: e for e in inner["keys"]}
    order = ("publisher_declaration", "registry_update", "publisher_catalog", "publisher_item", "label", "dispute")
    catalog_envelopes, item_entries, states = {}, {}, {}
    for log in v["logs"]:
        anchor = log["anchor"]
        genesis = b64u_decode(anchor["anchor"]["genesis_key"]["public_key"])
        Ed25519PublicKey.from_public_bytes(genesis).verify(b64u_decode(anchor["sig"]["value"]),
                                                          rfc8785.dumps(anchor["anchor"]))
        leaves, record = [], None
        for epoch in log["epochs"]:
            entries = epoch["entries"]
            ranks = [(order.index(e["type"]), leaf_hash(rfc8785.dumps(e))) for e in entries]
            assert ranks == sorted(ranks), f"{log['log_id']}: Entries out of canonical order"
            leaves += [leaf_hash(rfc8785.dumps(e)) for e in entries]
            cp = verify_checkpoint(epoch["checkpoint"], log["log_id"], {log["log_id"]: genesis})
            assert cp["tree_size"] == len(leaves) and cp["root"] == merkle_root(leaves), \
                f"{log['log_id']}: a Checkpoint does not state the tree of its Entries"
            held = {}
            for entry in entries:
                if entry["type"] == "publisher_declaration":
                    assert entry["body"] == declaration
                elif entry["type"] == "publisher_catalog":
                    envelope = entry["body"]
                    validators["catalog"].validate(envelope)
                    signer = keys[envelope["sig"]["key_id"]]
                    Ed25519PublicKey.from_public_bytes(b64u_decode(signer["x"])).verify(
                        b64u_decode(envelope["sig"]["value"]), rfc8785.dumps(envelope["catalog"]))
                    assert envelope["catalog"]["publisher"] == inner["domain"]
                    catalog_id = "sha256:" + hashlib.sha256(rfc8785.dumps(envelope["catalog"])).hexdigest()
                    held[catalog_id] = envelope["catalog"]
                    catalog_envelopes[log["log_id"]] = (catalog_id, envelope)
                elif entry["type"] == "publisher_item":
                    body = entry["body"]
                    validators["publisher-item"].validate(body)
                    catalog = held[body["catalog"]]
                    assert body["collection"] == catalog["collection"]
                    assert body["item"]["publisher"] == catalog["publisher"]
                    _item_proved(body["item"], body["proof"], catalog)
                    item_entries[log["log_id"]] = entry
                    record = {"state": "record", "item": _item_id(body["item"]), "collection": body["collection"],
                              "catalog": body["catalog"], "generated_at": catalog["generated_at"]}
        assert log["tree_size"] == len(leaves) and log["root"] == "sha256:" + merkle_root(leaves).hex()
        states[log["log_id"]] = record
    ids = {catalog_id for catalog_id, _ in catalog_envelopes.values()}
    assert ids == {v["catalog_id"]}, "the Logs do not seal one Catalog ID"
    assert len({rfc8785.dumps(e) for _, e in catalog_envelopes.values()}) == len(v["logs"]), \
        "the Catalog's Envelope does not carry another signature in each Log"
    assert len({rfc8785.dumps(e) for e in item_entries.values()}) == 1, "the publisher_item Entry differs"
    assert _item_id(v["item"]) == v["item_id"] and all(
        e["body"]["item"] == v["item"] for e in item_entries.values())
    heights = [next(i for i, ep in enumerate(log["epochs"]) if any(e["type"] == "publisher_item"
                                                                    for e in ep["entries"])) for log in v["logs"]]
    assert len(set(heights)) == len(heights), "the Logs seal the Item at one height"
    assert states == v["expected"]["log_states"], "a Log's state for the URL is not its record"
    latest = max(states.values(), key=lambda st: (log_seconds(st["generated_at"]), st["catalog"].encode(),
                                                  st["item"].encode()))
    holders = sorted(name for name, st in states.items() if st == latest)
    assert v["expected"]["combined"] == {"state": latest, "logs": holders}, "the combined state differs"
    assert holders == sorted(states), "a Consumer of both Logs does not take one state held by both"

def _multilog_declaration_and_item_signatures():
    _multilog_dedup(json.loads((ROOT / "vectors" / "multilog" / "dedup.json").read_text()))
check("vectors:multilog-dedup", _multilog_declaration_and_item_signatures)


def _multilog_dedup_twin():
    v = json.loads((ROOT / "vectors" / "multilog" / "dedup.json").read_text())
    for label, mutate in (
            ("a proof sibling flipped", lambda w: w["logs"][1]["epochs"][-1]["entries"][-1]["body"]["proof"].update(
                path=["0" * 64])),
            ("a publisher_item body with an extra member",
             lambda w: w["logs"][0]["epochs"][-1]["entries"][-1]["body"].update(note="x")),
            ("one Log's state for another Catalog",
             lambda w: w["expected"]["log_states"]["log-b"].update(catalog="sha256:" + "1" * 64))):
        w = copy.deepcopy(v)
        mutate(w)
        try:
            _multilog_dedup(w)
        except (AssertionError, ValidationError, KeyError, ValueError, IndexError):
            continue
        raise AssertionError(f"{label} passed the multi-Log check")
check("negative:multilog-dedup", _multilog_dedup_twin)
check("vectors:wist3-example-log", _dc3_example_log)


def _multilog_declaration_signature_twin():
    """A tampered Declaration signature must fail verification: the check
    above is not vacuously true because every signature in the fixture
    happens to verify."""
    v = json.loads((ROOT / "vectors" / "multilog" / "dedup.json").read_text())
    tampered = copy.deepcopy(v["publisher_declaration"])
    tampered["publisher"]["seq"] = 1
    try:
        Ed25519PublicKey.from_public_bytes(
            b64u_decode(tampered["publisher"]["keys"][0]["x"])).verify(
                b64u_decode(tampered["sig"]["value"]), rfc8785.dumps(tampered["publisher"]))
    except InvalidSignature:
        pass
    else:
        raise AssertionError("a mutated Declaration verified unchanged")
check("negative:multilog-declaration-signature", _multilog_declaration_signature_twin)


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
    assert rows == 28, f"{rows} Parameter Registry rows parsed; the table has twenty-eight"
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
    ceiling, and `epoch_cadence_seconds` by both — read them as one shape
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
    assert len(published) == 26, \
        f"{len(published)} bounds parsed from §5; the table has twenty-six"
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
    for name in ("epoch_cadence_seconds", "domain_epoch_entries_max", "max_inclusion_epochs",
                 "quota_base", "feed_window", "record_seal_epochs", "recovery_window_days"):
        assert enforced.get(name, (None, None))[0], \
            f"{name} carries no floor, so a parameter_change may zero it"
        assert not v.is_valid(change(name, 0)), f"{name} may still be set to zero"
    assert enforced["epoch_cadence_seconds"][1] == 86400, "the cadence has no ceiling"

    # `mirror_retention_days` is bounded by the availability window: a Consumer
    # resuming from a Snapshot published inside `payload_window_days` must
    # still find the Epochs above it at a Mirror (WIST-3 §6, §8).
    defaults = _registry_table_defaults()
    assert enforced["mirror_retention_days"][0] * 6 == defaults["payload_window_days"], (
        f"the mirror retention floor is {enforced['mirror_retention_days'][0]}, not a sixth of "
        f"the {defaults['payload_window_days']}-day availability window")
    assert "`payload_window_days` divided by 6" in re.sub(r"\s+", " ", section5), \
        "§5 does not state the retention-to-window rule"

    assert "**Values a Publisher builds to.**" in section5, \
        "§5 does not state why the publication caps are not amended below their defaults"
    for name in ("extract_cap_bytes", "links_cap_bytes", "link_url_cap_bytes",
                 "summary_cap_bytes", "url_cap_bytes", "collections_max",
                 "scope_entries_max", "catalog_items_max", "tree_file_cap_bytes",
                 "tree_depth_max"):
        assert enforced[name][0] == defaults[name], (
            f"the {name} floor {enforced[name][0]} is not its Registry default "
            f"{defaults[name]}, the value a Publisher builds to")
    assert enforced["url_cap_bytes"][1] == 32768, "the url cap has no 32 768 ceiling"
    assert enforced["catalog_refresh_seconds"] == (1, 7776000), \
        "the Catalog refresh interval is not bounded to 1 through 7 776 000 seconds"
    empty_epoch = json.loads((ROOT / "vectors/wist3/empty-epoch.json").read_text())["epoch_1"]
    assert enforced["epoch_cap_bytes"][0] >= len(rfc8785.dumps(empty_epoch)), (
        "the Epoch cap floor is below the size of an empty Epoch, which "
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
    a `number` here is the one hole through which a rational reaches an Epoch
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
                                       ("epoch_cadence_seconds", 3600.5, 3600),
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
    naming which Item, on what legal basis, at whose demand. A withdrawal
    missing any of the three would let an operator record an unfalsifiable
    "we removed something", which is what a quiet drop looks like.
    """
    schema = json.loads((ROOT / "schemas" / "registry-update.schema.json").read_text())
    actions = schema["properties"]["update"]["properties"]["action"]["enum"]
    assert "payload_withdrawal" in actions, "action enum lacks payload_withdrawal"
    item_id = _item_id(json.loads((ROOT / "examples" / "item.json").read_text()))
    withdrawal = {
        "update": {
            "wist_version": "1.0.0",
            "action": "payload_withdrawal",
            "subject": "example.com",
            "details": {"delta_id": item_id,
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
    bad["update"]["details"]["delta_id"] = "not-an-item-id"
    assert not v.is_valid(bad), "a withdrawal naming no well-formed Item ID validates"
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
    """Every window in the suite runs on Checkpoint `sealed_at`, in whole
    seconds.

    A Checkpoint sealed at `...:00.500Z` or `...+00:00` would make the
    conversion to integer seconds a rounding decision, and one rounded
    half-second can move a grace period or a recovery window across an Epoch
    boundary. WIST-3 §5 fixes the `sealed_at` extension line to this exact
    form, checked here independently of `parse_checkpoint`'s own use of
    `SEALED_AT_PATTERN` (a pattern that rejected everything would satisfy the
    negative cases below and look like a passing guard).
    """
    text = (ROOT / "examples" / "checkpoint.txt").read_text()
    lines = text.split("\n\n", 1)[0].split("\n")
    assert len(lines) == 5, "the example Checkpoint's note text is not 5 lines"
    sealed_line = lines[4]
    m = re.fullmatch(r"sealed_at (.+)", sealed_line)
    assert m, "the example Checkpoint has no sealed_at extension line"
    assert re.fullmatch(SEALED_AT_PATTERN.strip("^$"), m.group(1)), \
        "the example Checkpoint's sealed_at does not satisfy its own §3.1 pattern"
    for bad in ("2026-08-02T13:00:00.500Z", "2026-08-02T13:00:00+00:00",
                "2026-08-02T13:00:00", "2026-08-02t13:00:00z"):
        candidate = "\n".join(lines[:4] + ["sealed_at " + bad]) + text[text.index("\n\n"):]
        try:
            parse_checkpoint(candidate)
        except ValueError as e:
            assert "WIST3-E03" in str(e), f"non-exact sealed_at {bad!r} rejected for the wrong reason"
        else:
            raise AssertionError(f"parse_checkpoint accepts non-exact sealed_at {bad!r}")
    wist3 = (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text()
    assert "whole-second precision" in wist3, "WIST-3 §3.1 does not state the constraint"
check("schema:wist4-sealed-at-precision", _dc4_sealed_at_precision)

# WIST-4 §4: every window and every admission test in the suite reads an Epoch
# `sealed_at`, and every timestamp compared against one is written in that
# field's own whole-second-plus-literal-Z form. That is a claim about every
# `date-time` in every schema, so the guard below enumerates them all rather
# than any single field.
#
# Each entry is either ANCHORED — the value takes part in a comparison against
# an Epoch `sealed_at`, so it MUST carry the pattern — or a stated reason why it
# does not. Declaring a field unanchored is the deliberate act of asserting
# that nothing recomputable is decided by comparing it to the Log's own clock.
ANCHORED = "anchored to an Epoch `sealed_at`"
PUBLISHER_TIMESTAMP_PATTERN = '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\\.[0-9]+)?([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$(?![\\s\\S])'

TIMESTAMP_FIELDS = {
    ("feed.schema.json", "properties/feed/properties/generated_at"): ANCHORED,
    ("registry-update.schema.json", "properties/update/properties/effective_at"): ANCHORED,
    **{("item.schema.json", path):
        "Publisher-supplied and never compared to an Epoch: compared to the `generated_at` of the "
        "Catalog that lists the Item (WIST1-E06), and a removed Item's to later `generated_at` "
        "values under `removal_retention_days`"
       for path in ("$defs/observed_at", "oneOf[0]/properties/observed_at", "oneOf[1]/properties/observed_at")},
    ("emission.schema.json", "oneOf[1]/properties/modified"):
        "Publisher-supplied and never compared to an Epoch: it becomes a new Item's `observed_at` "
        "(WIST-5 §6.2), which the part that signs compares to the Catalog's `generated_at`",
    ("label.schema.json", "properties/label/properties/asserted_at"):
        "Publisher-supplied and read exactly as an Item's `observed_at` (WIST-2 §3.3): compared "
        "to the same Labeler's other Labels of the subject and name, and to the validator's own "
        "clock under WIST-1 §3.4, never to an Epoch",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[6]/prefixItems[5]"):
        "the Label's own `asserted_at`, carried verbatim so a resuming Consumer orders a later "
        "Label against it (WIST-3 §7); a Publisher timestamp, never compared to an Epoch",
    ("label.schema.json", "properties/label/properties/expires_at"):
        "Publisher-supplied: the instant from which the Label applies nothing (WIST-2 §3.3), compared "
        "to `asserted_at` at validation and to an Epoch's `sealed_at` only when the Label is applied, "
        "as an instant the Publisher chose and the Epoch does not anchor",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[6]/prefixItems[6]/oneOf[0]"):
        "the Label's own `expires_at`, carried verbatim so a resuming Consumer drops the Label at the "
        "same instant a replaying one does (WIST-3 §7); a Publisher timestamp the Epoch does not anchor",
    ("dispute.schema.json", "properties/dispute/properties/asserted_at"):
        "Publisher-supplied and read exactly as a Label's `asserted_at` (WIST-2 §3.3): compared to the "
        "same disputant's other disputes of the Label and to the validator's own clock, never to an Epoch",
    ("label-definition.schema.json", "properties/definition/properties/asserted_at"):
        "Publisher-supplied and read as a Label's `asserted_at` (WIST-2 §3.3): a Consumer keeps the "
        "newest definition that verifies; never compared to an Epoch",
    ("snapshot-state.schema.json", "properties/state/properties/entries/items/oneOf[9]/prefixItems[4]"):
        "the dispute's own `asserted_at`, carried verbatim so a resuming Consumer orders a later "
        "dispute against it (WIST-3 §7); a Publisher timestamp, never compared to an Epoch",
    ("log-anchor.schema.json", "properties/anchor/properties/created_at"):
        "descriptive: the Anchor is authenticated by its own signature and its out-of-band "
        "fingerprint (WIST-3 §3.4), and nothing compares this value to anything",
    ("snapshot-index.schema.json", "properties/index/properties/updated_at"):
        "descriptive: when the Aggregator last rewrote a mutable index (WIST-3 §6); a Snapshot is "
        "bound to the chain by `tree_size` and `root_hash`, never by this",
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

    WIST-4 §4 states that every window and admission test reads an Epoch
    `sealed_at`. A `date-time` field that takes part in such a comparison and
    is not constrained to that field's own form reopens, one field at a time,
    exactly what the Checkpoint `sealed_at` pattern closed: an Aggregator writing
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
                f"{schema_name}: {spath} is compared against an Epoch `sealed_at` but carries "
                f"pattern {pattern!r}, not the whole-second-plus-Z form that field carries")
        else:
            publisher_field = (schema_name in ("item.schema.json", "emission.schema.json", "publisher.schema.json",
                                               "label.schema.json", "dispute.schema.json",
                                               "label-definition.schema.json")
                               or spath.endswith(("oneOf[6]/prefixItems[5]", "oneOf[6]/prefixItems[6]/oneOf[0]",
                                                  "oneOf[9]/prefixItems[4]")))
            assert pattern == (PUBLISHER_TIMESTAMP_PATTERN if publisher_field else None), (
                f"{schema_name}: {spath} has an unexpected unanchored timestamp pattern")
            assert len(declared) > 40, \
                f"{schema_name}: {spath} is declared unanchored with no stated reason"
    assert not undeclared, (
        "date-time fields declared neither anchored to an Epoch nor unanchored:\n  "
        + "\n  ".join(undeclared))
    stale = sorted(set(TIMESTAMP_FIELDS) - present)
    assert not stale, ("declarations for date-time fields that do not exist:\n  "
                       + "\n  ".join(f"{f}: {p}" for f, p in stale))
    anchored = {k for k, v in TIMESTAMP_FIELDS.items() if v is ANCHORED}
    assert len(anchored) == 2, \
        f"{len(anchored)} anchored timestamps; the class has two members"

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
    assert "MUST have `effective_at` ≥ 7 days after the Epoch's `sealed_at`" in wist4, \
        "WIST-4 §5 no longer measures the grace period from the Epoch's `sealed_at`"
    wist1 = (ROOT / "specs" / "WIST-1-item-format.md").read_text()
    assert "opens at the `sealed_at` of the Epoch" in wist1, \
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
    epoch = copy.deepcopy(json.loads((ROOT / "vectors" / "wist3" / "epoch.json").read_text()))
    proof = copy.deepcopy(json.loads((ROOT / "vectors" / "wist3" / "inclusion-proof.json").read_text()))
    # verify_inclusion(epoch, proof) fetches its leaf via epoch["entries"][proof["index"]],
    # so merely relabeling proof["index"] (leaving epoch untouched) makes it fetch a
    # genuinely different, distinct Entry — which fails on leaf-content grounds alone and
    # would mask the defect under test regardless of how "side" is handled. A mirror
    # colluding in this attack controls what it serves at each position, so simulate that:
    # keep entry 0's real (leaf, path) pair — the one this proof actually authenticates —
    # but relabel it as occupying position 3.
    epoch["entries"][3] = epoch["entries"][proof["index"]]
    proof["index"] = 3
    try:
        verify_inclusion(epoch, proof)
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
    wist1 = (ROOT / "specs" / "WIST-1-item-format.md").read_text()
    security = wist1.split("## 8. Security Considerations")[1].split("## 9.")[0]
    fingerprint = wist1.split("**DNS fingerprint record.**")[1].split("\n\n")[0]
    assert "carries no key" in fingerprint and "MUST NOT let the result change" in fingerprint, \
        "WIST-1 §5.1's fingerprint record no longer disclaims key discovery and acceptance effects"
    allowed = set(security.splitlines()) | set(fingerprint.splitlines())
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


def tile_path_width(path: str) -> int:
    """The number of hashes or Entries a [tlog-tiles] path states (WIST-3
    §6): `W` for `.p/<W>`, `W` being 1 through 255, and 256 for a full tile
    or bundle. A path stating a width outside that range states no width a
    file can hold, so anything served at it is `WIST3-E03`."""
    m = re.fullmatch(
        r"/tile/(?:entries|[0-9]+)/(?:x[0-9]{3}/)*[0-9]{3}(?:\.p/(0|[1-9][0-9]{0,2}))?", path)
    if not m:
        raise ValueError(f"not a [tlog-tiles] path: {path}")
    if m.group(1) is None:
        return 256
    width = int(m.group(1))
    if not 1 <= width <= 255:
        raise ValueError(f"WIST3-E03: partial width {width} is outside 1 through 255")
    return width


def parse_tile(octets: bytes, width: int) -> list:
    """WIST-3 §6 / [tlog-tiles]: a tile's hashes, 32 octets each, as many as
    the path states. Raises ValueError ("WIST3-E03: ...") on a form §6
    excludes from reproducing any root. Implemented independently of
    merkle.tile_bytes, which only builds one."""
    if not octets:
        raise ValueError("WIST3-E03: empty tile")
    if len(octets) % 32:
        raise ValueError("WIST3-E03: tile length is not a multiple of 32 octets")
    hashes = [octets[i:i + 32] for i in range(0, len(octets), 32)]
    if len(hashes) != width:
        raise ValueError(
            f"WIST3-E03: tile holds {len(hashes)} hashes, not the {width} its path states")
    return hashes


def parse_entry_bundle(octets: bytes, count: int) -> list:
    """WIST-3 §6 / [tlog-tiles]: an entry bundle's leaf data — each Entry's
    JCS serialization behind its big-endian uint16 length — as many Entries
    as the path states, and no octet after the last. Raises ValueError
    ("WIST3-E03: ...") otherwise. Implemented independently of
    merkle.entry_bundle_bytes, which only builds one."""
    entries = []
    pos = 0
    while len(entries) < count:
        if pos + 2 > len(octets):
            raise ValueError("WIST3-E03: entry bundle ends inside a length prefix")
        length = int.from_bytes(octets[pos:pos + 2], "big")
        pos += 2
        if pos + length > len(octets):
            raise ValueError("WIST3-E03: entry bundle ends inside leaf data")
        entries.append(octets[pos:pos + length])
        pos += length
    if pos != len(octets):
        raise ValueError("WIST3-E03: octets after the bundle's last Entry")
    return entries


def _tile_form_vectors():
    """WIST-3 §6: the tile, entry-bundle and Epoch-leaf-range forms that
    already exclude reproducing the root a Checkpoint states, each
    `WIST3-E03`, beside the forms that admit it."""
    vector = json.loads((ROOT / "vectors/wist3/tile-bounds.json").read_text())
    assert vector["tile_hash_octets"] == 32 and vector["full_tile_hashes"] == 256

    for case in vector["tile_form_cases"]:
        try:
            width = tile_path_width(case["path"])
            hashes = parse_tile(bytes.fromhex(case["octets_hex"]), width)
            assert len(hashes) == width, case["name"]
            result = "valid"
        except ValueError as e:
            assert "WIST3-E03" in str(e), f"{case['name']}: wrong code: {e}"
            result = "WIST3-E03"
        assert result == case["expected"], f"{case['name']}: got {result}"

    for case in vector["bundle_form_cases"]:
        octets = bytes.fromhex(case["octets_hex"])
        try:
            count = tile_path_width(case["path"])
            entries = parse_entry_bundle(octets, count)
            assert len(entries) == count, case["name"]
            for data in entries:
                assert len(data) <= 65535, f"{case['name']}: leaf data over §3.3's bound"
                json.loads(data)
            result = "valid"
        except ValueError as e:
            assert "WIST3-E03" in str(e), f"{case['name']}: wrong code: {e}"
            result = "WIST3-E03"
        assert result == case["expected"], f"{case['name']}: got {result}"

    for case in vector["epoch_range_cases"]:
        wanted = list(range(case["size_previous"], case["size"]))
        result = "valid" if case["entry_leaf_indexes"] == wanted else "WIST3-E03"
        assert result == case["expected"], f"{case['name']}: got {result}"

    for family in ("tile_form_cases", "bundle_form_cases", "epoch_range_cases"):
        assert {c["expected"] for c in vector[family]} == {"valid", "WIST3-E03"}, \
            f"{family} must exercise both outcomes"

    prose = re.sub(r"\s+", " ",
                   (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    for marker in (
            "a tile that is empty, whose length is not a multiple of 32 octets, "
            "or that holds a number of hashes other than the one its path states "
            "— 256 for a full tile, `W` for `.p/<W>`, `W` being 1 through 255",
            "an entry bundle whose last length prefix or leaf data is cut short, "
            "that carries octets after its last Entry, or that holds a number of "
            "Entries other than the one its path states",
            "an Epoch's Entries that do not fill the leaf range `size(N-1)` "
            "through `size(N) - 1`"):
        assert marker in prose, f"WIST-3 §6 does not state: {marker!r}"
check("vectors:wist3-tile-forms", _tile_form_vectors)


def _tile_form_twin():
    """The form parsers are not blind: an accepted tile loses one octet and
    an accepted bundle gains one, and each is then rejected at the width its
    path states."""
    vector = json.loads((ROOT / "vectors/wist3/tile-bounds.json").read_text())
    tile = next(c for c in vector["tile_form_cases"] if c["expected"] == "valid")
    octets = bytes.fromhex(tile["octets_hex"])
    parse_tile(octets, tile_path_width(tile["path"]))
    for mutated in (octets[:-1], octets[:-32]):
        try:
            parse_tile(mutated, tile_path_width(tile["path"]))
        except ValueError:
            continue
        raise AssertionError("a mutated tile still parsed")

    bundle = next(c for c in vector["bundle_form_cases"] if c["expected"] == "valid")
    octets = bytes.fromhex(bundle["octets_hex"])
    count = tile_path_width(bundle["path"])
    parse_entry_bundle(octets, count)
    for mutated, at in ((octets + b"\x00", count), (octets, count + 1), (octets, count - 1)):
        try:
            parse_entry_bundle(mutated, at)
        except ValueError:
            continue
        raise AssertionError("a mutated entry bundle still parsed")
check("negative:wist3-tile-forms", _tile_form_twin)


def _tile_bound_vectors():
    """WIST-3 §6, §3.3: a Consumer stops reading before buffering past a tile,
    entry bundle, or Entry JCS bound; equality with a bound is permitted."""
    vector = json.loads((ROOT / "vectors/wist3/tile-bounds.json").read_text())
    tile = vector["tile"]
    assert len(bytes.fromhex(tile["at_bound_hex"])) == tile["bound_bytes"]
    assert tile["at_bound_expected"] == "valid"
    assert len(bytes.fromhex(tile["over_bound_hex"])) == tile["bound_bytes"] + 1
    assert tile["over_bound_expected"] == "WIST3-E03"
    bundle = vector["entry_bundle"]
    assert bundle["bound_bytes"] == 256 * 65537
    assert bundle["at_bound_declared_bytes"] == bundle["bound_bytes"]
    assert bundle["at_bound_expected"] == "valid"
    assert bundle["over_bound_declared_bytes"] == bundle["bound_bytes"] + 1
    assert bundle["over_bound_expected"] == "WIST3-E03"
    entry_jcs = vector["entry_jcs"]
    assert entry_jcs["bound_bytes"] == 65535
    assert len(rfc8785.dumps(entry_jcs["at_bound_entry"])) == entry_jcs["bound_bytes"]
    assert entry_jcs["at_bound_expected"] == "valid"
    assert len(rfc8785.dumps(entry_jcs["over_bound_entry"])) == entry_jcs["bound_bytes"] + 1
    assert entry_jcs["over_bound_expected"] == "WIST3-E03"

check("vectors:wist3-tile-bounds", _tile_bound_vectors)

def _log_timestamp_vectors():
    vector = json.loads((ROOT / "vectors/wist3/timestamps.json").read_text())
    for case in vector["cases"]:
        try:
            result = log_seconds(case["value"])
        except ValueError:
            result = None
        assert result == case["unix_seconds"], case["value"]
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
    assert len(exercised) == 9, "both remaining schema fields and seven Snapshot timestamp positions required"

    cp = vector["checkpoint_field_case"]
    idx = cp["sealed_at_line_index"]
    base_lines = cp["note_lines"]
    sig_block = cp["sig_block"]
    parse_checkpoint("\n".join(base_lines) + "\n\n" + sig_block)  # positive control
    for value, expected in ((vector["field_accept"], True), (vector["field_reject"], False),
                            (vector["field_reject_non_ascii"], False)):
        lines = list(base_lines)
        lines[idx] = "sealed_at " + value
        candidate = "\n".join(lines) + "\n\n" + sig_block
        try:
            parse_checkpoint(candidate)
            accepted = True
        except ValueError as e:
            assert "WIST3-E03" in str(e), f"sealed_at {value!r} rejected for the wrong reason"
            accepted = False
        assert accepted == expected, ("checkpoint sealed_at", value)

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
    assert len(list(patterns(snapshot))) == 4, "Snapshot timestamp inventory changed"

check("vectors:wist3-timestamps", _log_timestamp_vectors)

def _signed_catalog_appendices():
    envelope = json.loads((ROOT / "vectors/wist1/envelope.json").read_text())
    canonical = rfc8785.dumps(envelope["catalog"])
    catalog_id = "sha256:" + hashlib.sha256(canonical).hexdigest()
    assert catalog_id == (ROOT / "vectors/wist1/id.txt").read_text().strip()
    assert canonical == (ROOT / "vectors/wist1/catalog.canonical").read_bytes()
    prose = (ROOT / "specs/WIST-1-item-format.md").read_text().split("## Appendix A.")[1]
    inner = prose.split("**Catalog (inner object):**")[1].split("```json\n")[1].split("\n```")[0]
    assert json.loads(inner) == envelope["catalog"]
    item = json.loads(prose.split("**Item of kind `page` (")[1].split("```json\n")[1].split("\n```")[0])
    assert item == json.loads((ROOT / "examples/item.json").read_text())
    payload = prose.split("**Payload (")[1].split("```json\n")[1].split("\n```")[0]
    assert json.loads(payload) == json.loads((ROOT / "examples/payload.json").read_text())
    size = len(rfc8785.dumps(json.loads(payload)["content"]))
    assert size == item["payload"]["bytes"]
    assert f"`JCS(content)` is {size} octets" in prose
    item_canonical = rfc8785.dumps(item)
    item_id = "sha256:" + hashlib.sha256(item_canonical).hexdigest()
    key = hashlib.sha256(rfc8785.dumps(["page", item["url"]])).digest()
    leaf = hashlib.sha256(b"\x00" + key + hashlib.sha256(item_canonical).digest()).digest()
    assert item_id in prose and key.hex() in prose and leaf.hex() in prose
    assert envelope["catalog"]["root"] == "sha256:" + leaf.hex()
    tree_octets = (ROOT / "examples/tree-file.json").read_bytes()
    assert tree_octets == rfc8785.dumps({"items": [item]})
    assert envelope["catalog"]["tree"] == "sha256:" + hashlib.sha256(tree_octets).hexdigest()
    assert tree_octets.decode() in prose and hashlib.sha256(tree_octets).hexdigest() in prose
    assert catalog_id in prose and envelope["sig"]["value"] in prose
    assert canonical[:32].hex() in prose and canonical[32:64].hex() in prose
    assert f"/payloads/{item_id[7:]}.json" in prose
    epoch = json.loads((ROOT / "vectors/wist3/epoch.json").read_text())
    prose = (ROOT / "specs/WIST-3-logbook-distribution.md").read_text().split("## Appendix A.")[1]
    leaves = [leaf_hash(rfc8785.dumps(entry)) for entry in epoch["entries"]]
    for index, value in enumerate(leaves):
        assert f"leaf{index} = {value.hex()}" in prose
    cp = parse_checkpoint(epoch["checkpoint"])
    assert "sha256:" + cp["root"].hex() in prose
    assert base64.b64encode(cp["root"]).decode() in prose
    for index in (0, 2):
        assert hashlib.sha256(b"\x01" + leaves[index] + leaves[index + 1]).hexdigest() in prose


check("spec:signed-catalog-appendices", _signed_catalog_appendices)

def _recovery_admission_vectors():
    vector = json.loads((ROOT / "vectors/wist1/recovery-admission.json").read_text())
    original = copy.deepcopy(vector)
    apply, _, replay, _ = _recovery_history_reference(vector)
    prefix_states = replay(vector["epochs"], vector["pinned_head"])
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
        assert log_seconds(epoch_sealed_at(vector["epochs"][1])) < admitted_at < deadline
        preceding = max(index for index, epoch in enumerate(vector["epochs"])
                        if log_seconds(epoch_sealed_at(epoch)) < admitted_at)
        admission = copy.deepcopy(prefix_states[preceding])
        accepted_chain, kinds = {identity(prefix["chain"])}, {}
        for label in case["admitted"]:
            envelope = declarations[label]
            previous_chain = identity(admission["chain"])
            result = apply(admission, envelope, admitted_at, case["admitted_at"], len(vector["epochs"]))
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

        inside = case["last_inside_epoch"]
        sealed_names = {name(entry["body"]) for entry in inside["entries"]}
        assert sealed_names <= set(case["admitted"])
        if sealed_names:
            assert admitted_at < log_seconds(epoch_sealed_at(inside))
        sealed_prefix = vector["epochs"] + [inside]
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
        elapsed_epochs = sum(log_seconds(epoch_sealed_at(epoch)) > admitted_at
                             for epoch in sealed_prefix)
        assert elapsed_epochs in {0, 1, 166}
        overdue = elapsed_epochs > 24 and any(kinds[label] == "recovery_rotation" for label in removed)
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

        sealed_epoch = case["deadline_epoch"]
        actual_members = {name(entry["body"]) for entry in sealed_epoch["entries"]}
        assert actual_members == set(included) and not actual_members.intersection(removed)
        final = replay(sealed_prefix + [sealed_epoch], case["deadline_pin"])[-1]
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
            revived = replay(sealed_prefix + [revival["epoch"]], revival["pin"])[-1]
            assert name(revived["current"]) == revival["log_current"]
            assert revived["reset_height"] == revival["log_reset_height"]
            assert actual_members != {name(entry["body"]) for entry in revival["epoch"]["entries"]}
            revival_count += 1
    assert classifications == removed_kinds == {"ordinary_rotation", "recovery_rotation", "fresh_identity"}
    assert revival_count >= 2
    assert len(vector["cases"]) == 11 and vector == original


check("vectors:wist1-recovery-admission", _recovery_admission_vectors)


def _declaration_refresh_vectors():
    vector = json.loads((ROOT / "vectors/wist2/declaration-refresh.json").read_text())
    original = copy.deepcopy(vector)
    formats = FormatChecker(formats=[])
    formats.checks("wist-canonical-host")(_declaration_host_format)
    formats.checks("wist-publisher-timestamp")(_publisher_timestamp_format)
    schemas = {kind: Draft202012Validator(json.loads(
        (ROOT / f"schemas/{kind}.schema.json").read_text()), format_checker=formats)
        for kind in ("publisher", "feed", "catalog", "label")}
    defaults = _registry_table_defaults()
    terms = _wist_label_terms()
    domain, clock = vector["domain"], vector["clock"]
    empty_tree = rfc8785.dumps({"items": []})

    def verifies(key, doc, kind):
        return _ed25519_profile_verdict(canonical_b64u_decode(key["x"]),
            canonical_b64u_decode(doc["sig"]["value"]), rfc8785.dumps(doc[kind]))[0]

    def accept(stored, incoming):
        if incoming is None or not schemas["publisher"].is_valid(incoming):
            return None
        if stored is not None and incoming == stored:
            return stored
        result = _declaration_binding_result(stored, incoming, lambda key: _usable_point(key["x"]))
        return incoming if result == ("initial" if stored is None else "ordinary_rotation") else None

    def judge_catalog(doc, source):
        if not schemas["catalog"].is_valid(doc) or log_seconds(doc["catalog"]["generated_at"]) is None:
            return "WIST1-E14"
        inner = doc["catalog"]
        if inner["publisher"] != domain or inner["collection"] != "default":
            return "WIST2-E04"
        at = log_seconds(inner["generated_at"])
        keys = [k for k in source["publisher"]["keys"] if k["kid"] == doc["sig"]["key_id"]
                and _usable_point(k["x"]) and _in_window(k, at)]
        if not keys:
            return "WIST1-E02"
        if not any(verifies(k, doc, "catalog") for k in keys):
            return "WIST1-E01"
        return None

    def page_source(sealed, page):
        cut = log_seconds(page["feed"]["generated_at"])
        before = [e["envelope"] for e in sealed if log_seconds(e["at"]) <= cut]
        after = [e["envelope"] for e in sealed if log_seconds(e["at"]) > cut]
        for role, chosen in (("current", before[-1:]), ("next", after[:1])):
            for source in chosen:
                if any(k["kid"] == page["sig"]["key_id"] and _usable_point(k["x"]) and verifies(k, page, "feed")
                       for k in source["publisher"]["keys"]):
                    return role
        return "WIST2-E04"

    for case in vector["cases"]:
        sealed = case.get("sealed", [])
        stored = None
        for entry in sealed:
            stored = accept(stored, entry["envelope"])
            assert stored is entry["envelope"], case["name"]
        accepted_catalog, trees, seen, retained = None, set(), set(), None
        assert len(case["pulls"]) == len(case["expected"]), case["name"]
        for pull, want in zip(case["pulls"], case["expected"]):
            got = {"declaration_requests": 1}
            incoming = accept(stored, pull["declaration"])
            if incoming is None:
                got.update(declaration="stopped", code="WIST2-E04" if stored is None else "WIST2-E01",
                           catalog="not_pulled", label_walk="not_pulled", labels_accepted=[], suspended=False)
            else:
                stored = incoming
                got["declaration"] = "accepted"
                objects = {"catalog": [pull["catalog"]], "tree": [], "label_feed": [pull["label_feed"]],
                           "labels": pull["labels"]}
                if pull["budget"] is None:
                    remaining = None
                else:
                    sizes = {"catalog": len(rfc8785.dumps(pull["catalog"])), "tree": len(empty_tree),
                             "label_feed": len(rfc8785.dumps(pull["label_feed"])),
                             "labels": sum(len(rfc8785.dumps(doc)) for doc in pull["labels"])}
                    assert set(pull["budget"]) <= set(objects), case["name"]
                    remaining = sum(sizes[name] for name in pull["budget"])
                suspended = False

                def fetch(octets):
                    nonlocal remaining, suspended
                    if remaining is not None and octets > remaining:
                        remaining, suspended = 0, True
                        return False
                    if remaining is not None:
                        remaining -= octets
                    return True

                if not fetch(len(rfc8785.dumps(pull["catalog"]))):
                    got["catalog"] = "suspended"
                else:
                    code = judge_catalog(pull["catalog"], stored)
                    identifier = None if code else "sha256:" + hashlib.sha256(
                        rfc8785.dumps(pull["catalog"]["catalog"])).hexdigest()
                    if code:
                        got["catalog"] = code
                    elif identifier == accepted_catalog:
                        got["catalog"] = "idempotent"
                    else:
                        name = pull["catalog"]["catalog"]["tree"][len("sha256:"):]
                        assert name == hashlib.sha256(empty_tree).hexdigest(), case["name"]
                        if name not in trees and not fetch(len(empty_tree)):
                            got["catalog"] = "suspended"
                        else:
                            trees.add(name)
                            inner = pull["catalog"]["catalog"]
                            assert inner["size"] == 0 and inner["root"] == "sha256:" + hashlib.sha256(b"").hexdigest()
                            got["catalog"], accepted_catalog = "accepted", identifier
                accepted_labels = []
                if suspended:
                    got["label_walk"] = "not_pulled"
                elif remaining == 0:
                    got["label_walk"] = "waits"
                elif not fetch(len(rfc8785.dumps(pull["label_feed"]))):
                    got["label_walk"] = "suspended"
                else:
                    got["label_walk"] = "pulled"
                    feed = pull["label_feed"]
                    assert schemas["feed"].is_valid(feed) and feed["feed"]["domain"] == domain, case["name"]
                    assert any(k["kid"] == feed["sig"]["key_id"] and verifies(k, feed, "feed")
                               for k in stored["publisher"]["keys"]), case["name"]
                    at = log_seconds(feed["feed"]["generated_at"])
                    assert retained is None or at >= retained, case["name"]
                    retained = at
                    by_id = {"sha256:" + hashlib.sha256(rfc8785.dumps(doc["label"])).hexdigest(): doc
                             for doc in pull["labels"]}
                    unseen = [i for i in feed["feed"]["deltas"] if i not in seen]
                    assert set(by_id) == set(feed["feed"]["deltas"]), case["name"]
                    for identifier in unseen:
                        if not fetch(len(rfc8785.dumps(by_id[identifier]))):
                            got["label_walk"] = "suspended"
                            break
                        if _label_disposition(by_id[identifier], stored, schemas["label"],
                                              defaults["url_cap_bytes"], terms, clock,
                                              defaults["clock_skew_seconds"]) == "accepted":
                            accepted_labels.append(identifier)
                    if "page" in pull and unseen and not suspended:
                        assert feed["feed"]["next"] is not None, case["name"]
                        page = pull["page"]
                        assert schemas["feed"].is_valid(page) and page["feed"]["domain"] == domain
                        got["page"] = page_source(sealed, page)
                        if got["page"] == "WIST2-E04":
                            del got["declaration_requests"]
                            accepted_labels = None
                if accepted_labels is not None:
                    seen.update(accepted_labels)
                    got["labels_accepted"] = accepted_labels
                got["suspended"] = suspended
            assert got == want, (case["name"], got, want)
    assert {want["catalog"] for case in vector["cases"] for want in case["expected"]} >= {
        "accepted", "idempotent", "suspended", "not_pulled", "WIST1-E01", "WIST1-E02", "WIST1-E14", "WIST2-E04"}
    assert {want["label_walk"] for case in vector["cases"] for want in case["expected"]} == {
        "pulled", "waits", "suspended", "not_pulled"}
    assert {want.get("page") for case in vector["cases"] for want in case["expected"]} == {
        None, "current", "next", "WIST2-E04"}
    assert all(want.get("declaration_requests", 1) == 1 for case in vector["cases"] for want in case["expected"])
    prose = re.sub(r"\s+", " ", (ROOT / "specs/WIST-2-site-publication.md").read_text())
    for marker in ("At the start of every pull the Aggregator fetches `publisher.json` and applies it under "
                   "WIST-1 §5.1 and §5.2; no Declaration is read from a cache in its place",
                   "A Catalog that meets a condition is reported (§7.1) with its code, replaces nothing and "
                   "retries nothing",
                   "the `publisher.json` request that opens every pull MUST NOT debit it, and exhaustion MUST NOT "
                   "defer it",
                   "A Label walk that cannot begin under a spent budget (§5.2) waits for the next pull without "
                   "suspending the completed Collection pulls",
                   "No other Declaration supplies authority, a pending Declaration (WIST-1 §5.2) supplies none"):
        assert marker in prose, marker
    assert vector == original



def _page_binding_vectors():
    vector = json.loads((ROOT / "vectors/wist2/page-bindings.json").read_text())
    original = copy.deepcopy(vector)
    schemas = {name: Draft202012Validator(json.loads(
        (ROOT / f"schemas/{name}.schema.json").read_text())) for name in ("publisher", "feed")}

    def usable(key):
        try:
            point = ed25519_curve.string_to_point(canonical_b64u_decode(key["x"]))
        except ed25519_curve.InvalidProof:
            return False
        return not ed25519_curve._is_identity(ed25519_curve._mul(8, point))

    def verifies(key, doc, inner):
        return _ed25519_profile_verdict(canonical_b64u_decode(key["x"]),
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
                    if key["kid"] == doc["sig"]["key_id"] and usable(key) and verifies(key, doc, "feed"):
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
    rotated = vector["probes"][0]
    current = vector["histories"]["rotated"][0]["envelope"]["publisher"]["keys"]
    following = vector["histories"]["rotated"][1]["envelope"]["publisher"]["keys"]
    assert rotated["expected"] == "next"
    assert all(key["kid"] != rotated["envelope"]["sig"]["key_id"] for key in current)
    assert any(key["kid"] == rotated["envelope"]["sig"]["key_id"]
               and verifies(key, rotated["envelope"], "feed") for key in following)
    assert len(vector["probes"]) == 15
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
    public = canonical_b64u_decode(key["x"])
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
            elif (doc["sig"]["key_id"] != key["kid"] or
                  not _ed25519_profile_verdict(public, canonical_b64u_decode(doc["sig"]["value"]),
                                              rfc8785.dumps(doc["feed"]))[0]):
                phase = "signature"
            else:
                phase = "accepted"
        assert phase == case["expected"], case["name"]
        assert case["usable"] == (phase == "accepted"), case["name"]
        assert not {"code", "rejection_noise", "declaration_retries"} & set(case), case["name"]
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
    public = canonical_b64u_decode(key["x"])
    assert _ed25519_profile_verdict(public, canonical_b64u_decode(source["sig"]["value"]),
                                  rfc8785.dumps(source["publisher"]))[0]
    host = vector["host"]
    assert source["publisher"]["domain"] == host
    assert "www." + host in source["publisher"]["subdomain_scope"]
    prefix = f"https://{host}/.well-known/wist/"
    retained = log_seconds(vector["retained_generated_at"])
    w2 = re.sub(r"\s+", " ", (ROOT / "specs/WIST-2-site-publication.md").read_text())
    assert ("MUST be byte-identical to its own Normalized URL (WIST-1 §2) and MUST begin with `https://`, "
            "the requested Canonical Host and `/.well-known/wist/`") in w2
    assert "An unread `next` is checked against nothing." in w2
    assert "the IDs of the Label Feed and Pages already fetched proceed under §5.5" in w2
    assert "an answer 304 lists no new ID" in w2
    codes = {"regression": "WIST2-E05", "unread": None, "end": None, "target": "WIST2-E01", "followed": None}
    observed = set()
    for case in vector["cases"]:
        doc = case["envelope"]
        answer = case.get("answer", 200)
        assert answer in (200, 304), case["name"]
        if not validator.is_valid(doc):
            phase = "fields"
        else:
            rfc8785.dumps(doc)
            feed = doc["feed"]
            if feed["domain"] != host:
                phase = "domain"
            elif (doc["sig"]["key_id"] != key["kid"] or
                  not _ed25519_profile_verdict(public, canonical_b64u_decode(doc["sig"]["value"]),
                                              rfc8785.dumps(feed))[0]):
                phase = "signature"
            elif case["live"] and log_seconds(feed["generated_at"]) < retained:
                phase = "regression"
            elif answer == 304 or all(delta in case["seen"] for delta in feed["deltas"]):
                phase = "unread"
            elif feed["next"] is None:
                phase = "end"
            else:
                target = feed["next"]
                normalized = link_extraction.normalize_url(target, prefix + "label-feed.json")
                phase = "followed" if normalized == target and target.startswith(prefix) else "target"
        assert phase == case["expected"], case["name"]
        if phase in codes:
            assert case["code"] == codes[phase], case["name"]
        else:
            assert "code" not in case, case["name"]
        assert case["next_read"] == (phase in ("end", "target", "followed")), case["name"]
        assert case["fetch"] == (doc["feed"]["next"] if phase == "followed" else None), case["name"]
        assert case["ids_proceed"] == (phase in ("unread", "end", "target", "followed")), case["name"]
        assert "declaration_retries" not in case, case["name"]
        observed.add(phase)
    assert observed == set(codes) | {"fields", "domain", "signature"}
    by_name = {case["name"]: case for case in vector["cases"]}
    assert by_name["scope host"]["expected"] == "target"
    assert by_name["explicit default port"]["expected"] == "target"
    assert by_name["encoded dot segment"]["expected"] == "target"
    assert by_name["encoded separator in prefix"]["expected"] == "target"
    assert by_name["encoded separator inside the layout"]["expected"] == "followed"
    assert by_name["query preserved"]["fetch"].endswith("?v=2&x=%2F")
    assert by_name["regressed Page with bad target"]["expected"] == "target"
    assert by_name["regressed live Label Feed with bad target"]["expected"] == "regression"
    assert not by_name["ingested Label Feed with bad target"]["next_read"]
    not_modified = [case for case in vector["cases"] if case.get("answer") == 304]
    assert not_modified and all(case["envelope"]["feed"]["next"] for case in not_modified)
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
    public = canonical_b64u_decode(key["x"])
    assert _ed25519_profile_verdict(public, canonical_b64u_decode(source["sig"]["value"]),
                                  rfc8785.dumps(source["publisher"]))[0]
    seen = set()
    for case in vector["cases"]:
        retained = None
        for event in case["observations"]:
            doc = event["envelope"]
            if not validator.is_valid(doc):
                disposition = "fields"
            elif doc["feed"]["domain"] != vector["host"]:
                disposition = "domain"
            elif (doc["sig"]["key_id"] != key["kid"] or
                  not _ed25519_profile_verdict(public, canonical_b64u_decode(doc["sig"]["value"]),
                                              rfc8785.dumps(doc["feed"]))[0]):
                disposition = "signature"
            elif retained is not None and log_seconds(doc["feed"]["generated_at"]) < log_seconds(retained):
                disposition = "regressed"
            else:
                disposition = "usable"
                retained = doc["feed"]["generated_at"]
            assert disposition == event["disposition"], event["name"]
            assert event.get("code") == ("WIST2-E05" if disposition == "regressed" else None), event["name"]
            assert retained == event["retained"], event["name"]
            assert event["retained_s"] == (None if retained is None else log_seconds(retained))
            assert not {"noise", "declaration_retries"} & set(event), event["name"]
            seen.add(disposition)
    assert seen == {"fields", "domain", "signature", "regressed", "usable"}
    prose = re.sub(r"\s+", " ", (ROOT / "specs/WIST-2-site-publication.md").read_text())
    assert ("an Aggregator MUST discard a Label Feed whose `generated_at` has regressed, with every Page and ID "
            "its walk would read, under `WIST2-E05`") in prose


check("vectors:wist2-feed-regression", _feed_regression_vectors)


def _payload_link_vectors():
    import copy
    import hmac
    import urllib.parse
    import link_extraction
    vector = json.loads((ROOT / 'vectors/wist1/payload-links.json').read_text())
    original = copy.deepcopy(vector)
    item_schema = Draft202012Validator(json.loads((ROOT / 'schemas/item.schema.json').read_text()))
    names = set()
    for case in vector['cases']:
        assert case['name'] not in names
        names.add(case['name'])
        item_schema.validate(case['item'])
        assert 'removed' not in case['item'], case['name']
        body, payload = case['item'], case['payload']
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
    item_schema = Draft202012Validator(json.loads((ROOT / 'schemas/item.schema.json').read_text()))
    seen = set()
    names = set()

    for case in vector['cases']:
        assert case['name'] not in names
        names.add(case['name'])
        item_schema.validate(case['item'])
        assert 'removed' not in case['item'], case['name']
        try:
            payload = item_rules.strict_loads(case['payload_json'].encode('utf-8')) if 'payload_json' in case else case['payload']
            rfc8785.dumps(payload)
        except (ValueError, item_rules.NotJcsInput, rfc8785.CanonicalizationError):
            assert case['allowed'] == ['WIST1-E05'], case['name']
            seen.add('WIST1-E05')
            continue
        assert payload == case['payload']
        body = case['item']
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


def _withdrawal_vector():
    return json.loads((ROOT / "vectors/wist4/withdrawal.json").read_text())

def _registry_update_id(update):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(update)).hexdigest()

def _withdrawal_judged(case, validator, log_key, key_id, contract, accepted):
    code, doc = _registry_update_eligibility(case["envelope_json"], validator)
    if doc is None:
        return code, None
    if _registry_update_id(doc["update"]) in accepted:
        return None, doc["update"]
    try:
        assert doc["sig"]["key_id"] == key_id
        log_key.verify(b64u_decode(doc["sig"]["value"]), rfc8785.dumps(doc["update"]))
    except (AssertionError, InvalidSignature):
        return "WIST4-E11", None
    update = doc["update"]
    return contract(update["details"]["delta_id"], update["subject"], case["height"]), update

def _withdrawal_replay(cases, judged, withdrawn, code_key, height_key, accepted):
    for case in cases:
        code, update = judged(case, accepted)
        assert code == case[code_key], (case["label"], code_key, code)
        if code is None:
            accepted.setdefault(_registry_update_id(update), case["height"])
            withdrawn.setdefault(update["details"]["delta_id"], (case["height"], update["subject"]))
            assert withdrawn[update["details"]["delta_id"]][0] == case[height_key], (case["label"], height_key)
        else:
            assert case[height_key] is None, (case["label"], height_key)
    return sorted((["withdrawal", i, p, h] for i, (h, p) in withdrawn.items()), key=rfc8785.dumps)

def _dc4_withdrawal():
    """WIST-4 §5.1 and WIST-3 §6.2: payload_withdrawal acts under the Log key
    naming an Item of kind page sealed against a Catalog of the subject at or
    below the act's Epoch; the earliest accepted withdrawal's Epoch governs.
    A Consumer resumed from a Snapshot judges the contract against the Entries
    it applied and the record and removal tuples it holds."""
    v = _withdrawal_vector()
    validator = Draft202012Validator(json.loads((ROOT / "schemas/registry-update.schema.json").read_text()))
    log_key = Ed25519PublicKey.from_public_bytes(b64u_decode(v["log_key"]["public_key"]))
    history = v["sealed_items"]
    for d in history:
        assert _item_id(d["item"]) == d["item_id"] and d["item"]["publisher"] == d["publisher"] \
            and d["item"]["url"] == d["url"], "a sealed Item is not the one it names"
        assert d["kind"] == ("removed" if d["item"].get("removed") is True else "page")
        assert ("payload" in d["item"]) == (d["kind"] == "page")
    assert [d["height"] for d in history] == sorted(d["height"] for d in history)

    def meets(identifier, subject, height):
        return None if any(d["item_id"] == identifier and d["kind"] == "page" and d["publisher"] == subject
                           and d["height"] <= height for d in history) else "WIST4-E04"

    def holdings(height):
        records, removals = {}, {}
        for d in history:
            if d["height"] <= height:
                slot = (d["publisher"], d["url"])
                (records if d["kind"] == "page" else removals)[slot] = d
                (removals if d["kind"] == "page" else records).pop(slot, None)
        return ([["record", d["publisher"], d["url"], d["item"], d["collection"], d["catalog"], d["generated_at"]]
                 for d in records.values()],
                [["removal", d["publisher"], d["url"], d["item_id"], d["catalog"], d["generated_at"]]
                 for d in removals.values()])

    def ordered(tuples):
        return sorted(tuples, key=rfc8785.dumps)

    key_id = v["log_key"]["key_id"]
    withdrawn, accepted = {}, {}
    tuples = _withdrawal_replay(
        v["act_cases"], lambda c, ids: _withdrawal_judged(c, validator, log_key, key_id, meets, ids),
        withdrawn, "code", "withdrawn_height", accepted)
    assert {c["code"] for c in v["act_cases"]} == {None, "WIST4-E11", "WIST4-E04"}
    assert any(c["code"] is None and c["height"] > c["withdrawn_height"] for c in v["act_cases"]), \
        "no repeated withdrawal keeps the first height"
    judged_every_time = {}
    assert any(c["code"] is None and _withdrawal_judged(c, validator, log_key, key_id, meets, judged_every_time)[0]
               == "WIST4-E11" for c in v["act_cases"]), \
        "no occurrence of an accepted Registry Update ID that would fail authentication shows idempotence"
    seen_ids, field_failed_repeat = set(), False
    for c in v["act_cases"]:
        doc = json.loads(c["envelope_json"])
        identifier = _registry_update_id(doc["update"])
        field_failed_repeat |= (identifier in seen_ids and c["code"] == "WIST4-E11"
                                and _registry_update_eligibility(c["envelope_json"], validator)[1] is None)
        if c["code"] is None:
            seen_ids.add(identifier)
    assert field_failed_repeat, "no occurrence of an accepted Registry Update ID fails field validation"

    def idempotence_first(case, ids):
        doc = json.loads(case["envelope_json"])
        if isinstance(doc.get("update"), dict) and _registry_update_id(doc["update"]) in ids:
            return None, doc["update"]
        return _withdrawal_judged(case, validator, log_key, key_id, meets, ids)
    try:
        _withdrawal_replay(v["act_cases"], idempotence_first, {}, "code", "withdrawn_height", {})
        moved = False
    except AssertionError:
        moved = True
    assert moved, "reading idempotence before field validation reproduces every act_case"
    assert tuples == ordered(v["state_tuples"]), "the replay does not leave the vector's withdrawal tuples"
    last = max(d["height"] for d in history)
    records, removals = holdings(last)
    assert ordered(records) == ordered(v["record_tuples"]) and ordered(removals) == ordered(v["removal_tuples"])
    state = Draft202012Validator(json.loads((ROOT / "schemas/snapshot-state.schema.json").read_text()))
    envelope = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
    envelope["state"]["entries"] = v["state_tuples"] + v["record_tuples"] + v["removal_tuples"]
    state.validate(envelope)
    materialized = sorted(_item_id(t[3]) for t in records if _item_id(t[3]) not in withdrawn)
    assert materialized == sorted(v["materialized"]) and materialized, "withdrawn content materialized"
    by_id = {d["item_id"]: d for d in history}
    assert any(withdrawn[i][0] == by_id[i]["height"] for i in withdrawn), "no Item withdrawn in its own Epoch"
    held = {_item_id(t[3]) for t in records}
    assert any(i not in held for i in withdrawn), "no withdrawal of a superseded Item meets the contract"

    def resumed_judge(snapshot):
        top = snapshot["snapshot_height"]
        snap_records, snap_removals = holdings(top)
        assert ordered(snap_records) == ordered(snapshot["record_tuples"])
        assert ordered(snap_removals) == ordered(snapshot["removal_tuples"])
        adopted = {t[1]: (t[3], t[2]) for t in snapshot["adopted"]}
        assert adopted == {i: hp for i, hp in withdrawn.items() if hp[0] <= top}
        assert ordered(snapshot["registry_update_tuples"]) == ordered(
            [["registry_update", i, h] for i, h in accepted.items() if h <= top])
        assert all(c["height"] > top for c in snapshot["act_cases"])

        def resumed(identifier, subject, height):
            walked = [d for d in history if top < d["height"] <= height and d["item_id"] == identifier]
            holders = [t[1] for t in snapshot["record_tuples"] if _item_id(t[3]) == identifier]
            holders += [t[2] for t in snapshot["adopted"] if t[1] == identifier]
            if any(d["kind"] == "page" and d["publisher"] == subject for d in walked) or subject in holders:
                return None
            if walked or holders or any(t[3] == identifier for t in snapshot["removal_tuples"]):
                return "WIST4-E04"
            return None
        return adopted, resumed

    resume = v["resume"]
    adopted, resumed = resumed_judge(resume)
    cases = resume["act_cases"]
    after = _withdrawal_replay(cases, lambda c, ids: _withdrawal_judged(c, validator, log_key, key_id, resumed, ids),
                               dict(adopted), "code", "withdrawn_height",
                               {t[1]: t[2] for t in resume["registry_update_tuples"]})
    assert after == ordered(resume["state_tuples"])
    replayed = _withdrawal_replay(cases, lambda c, ids: _withdrawal_judged(c, validator, log_key, key_id, meets, ids),
                                  dict(adopted), "replay_code", "replay_withdrawn_height",
                                  {i: h for i, h in accepted.items() if h <= resume["snapshot_height"]})
    assert replayed == ordered(resume["replay_state_tuples"])
    differing = [c for c in cases if c["code"] != c["replay_code"]]
    assert differing and all(c["code"] is None and c["replay_code"] == "WIST4-E04" for c in differing), \
        "the resumed Consumer differs from replay other than by accepting an act the Aggregator must not seal"
    assert {c["code"] for c in cases} == {None, "WIST4-E04"} and {c["replay_code"] for c in cases} == {None, "WIST4-E04"}
    residue = [c for c in cases if c["code"] is None and c["replay_code"] is None
               and c["withdrawn_height"] != c["replay_withdrawn_height"]]
    assert residue, "no later withdrawal reads another earliest height after a contract-breaking act"
    named = lambda c: json.loads(c["envelope_json"])["update"]
    tuples_of = {t[1]: t[2] for t in resume["adopted"]}
    assert {c["code"] for c in cases if named(c)["details"]["delta_id"] in tuples_of
            and named(c)["details"]["delta_id"] not in {_item_id(t[3]) for t in resume["record_tuples"]}
            and not any(d["item_id"] == named(c)["details"]["delta_id"] and d["height"] > resume["snapshot_height"]
                        for d in history)} == {None, "WIST4-E04"}, \
        "no act judged against a withdrawal tuple alone, for its Publisher and for another"
    again = resume["resumed_again"]
    adopted_again, resumed_again = resumed_judge(again)
    assert again["snapshot_height"] > resume["snapshot_height"]
    after_again = _withdrawal_replay(again["act_cases"],
                                     lambda c, ids: _withdrawal_judged(c, validator, log_key, key_id, resumed_again, ids),
                                     dict(adopted_again), "code", "withdrawn_height",
                                     {t[1]: t[2] for t in again["registry_update_tuples"]})
    assert after_again == ordered(again["state_tuples"])
    _withdrawal_replay(again["act_cases"], lambda c, ids: _withdrawal_judged(c, validator, log_key, key_id, meets, ids),
                       dict(adopted_again), "replay_code", "replay_withdrawn_height",
                       {i: h for i, h in accepted.items() if h <= again["snapshot_height"]})
    dropped = {_item_id(t[3]) for t in resume["record_tuples"]} - {_item_id(t[3]) for t in again["record_tuples"]}
    assert any(named(c)["details"]["delta_id"] in dropped and c["code"] is None
               and resumed(named(c)["details"]["delta_id"], named(c)["subject"], c["height"]) == "WIST4-E04"
               for c in again["act_cases"]), "no act shows that only the last Snapshot's tuples are read"
    current = {_item_id(d["item"]) for d in history if d["kind"] == "page"} & {
        _item_id(t[3]) for t in holdings(max(c["height"] for c in cases))[0]}
    replaced = {_item_id(t[3]): t[1] for t in resume["record_tuples"] if _item_id(t[3]) not in current}
    judged = {(json.loads(c["envelope_json"])["update"]["details"]["delta_id"],
               json.loads(c["envelope_json"])["update"]["subject"] == replaced.get(
                   json.loads(c["envelope_json"])["update"]["details"]["delta_id"])): c["code"]
              for c in cases}
    assert any(judged.get((i, False)) == "WIST4-E04" and (i, True) in judged and judged[(i, True)] is None
               for i in replaced), "no act names a Snapshot record tuple's Item that a walked Entry replaced"
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-governance.md").read_text())
    for marker in ("The act meets its `details` contract only where a valid `publisher_item` Entry (WIST-3 §3.3) "
                   "sealed the Item it names, of kind `page`, at or below the act's Epoch — in the act's own Epoch "
                   "whatever the order of its Entries — against a Catalog whose `publisher` is `subject`; otherwise "
                   "it fails the contract (`WIST4-E04`).",
                   "the earliest accepted withdrawal's Epoch is the height every rule reads",
                   "E11 takes precedence over E04",
                   "a `record` or `withdrawal` tuple of the Publisher `subject` naming the Item — the act meets "
                   "the contract",
                   "an Entry, a `record` tuple or a `withdrawal` tuple of another Publisher, an Entry of an Item of "
                   "kind `removed`, a `removal` tuple naming the Item ID — the act fails it (`WIST4-E04`), as it "
                   "does on replay",
                   "Where none shows the Item, the Consumer accepts the act as consistent.",
                   "the `record`, `removal` and `withdrawal` tuples of the Snapshot it last resumed from",
                   "for what follows from that act in that Log"):
        assert marker in prose, marker
    prose3 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert ("A withdrawal takes effect at the height of the Epoch that seals it, for an Item sealed in that same "
            "Epoch included: the Item becomes its URL's record (§3.3) and its content is never materialized") in prose3
    assert "What withdrawal does not touch is the record." in prose3
    assert ("judges the contract of a later act as WIST-4 §5.1 states for a Consumer resumed from a "
            "Snapshot") in prose3
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


# WIST-3 §3.4: Aggregator key acts. Placed after `_registry_update_eligibility`
# so that the Envelope partition has one implementation in this file; the key
# validity, admitted-set and Checkpoint rules below are implemented here from
# the prose, never read from tools/gen_vectors.py.
KEY_ACTS = ("aggregator_key_add", "aggregator_key_remove")


def _aggregator_keys_vector():
    return json.loads((ROOT / "vectors/wist3/aggregator-keys.json").read_text())


def _envelope_verifies(raw_pub: bytes, envelope: dict, inner: str = "update") -> bool:
    """WIST-1 §4: the Envelope's signature over the JCS of its inner object."""
    try:
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(
            b64u_decode(envelope["sig"]["value"]), rfc8785.dumps(envelope[inner]))
        return True
    except (InvalidSignature, ValueError):
        return False

def _parameter_resume_run(case, epochs, accepted, amendments):
    public = b64u_decode(case["log_key"]["public_key"])
    for epoch in epochs:
        for index, envelope in enumerate(epoch["acts"]):
            update = envelope["update"]
            assert envelope["sig"]["key_id"] == case["log_key"]["key_id"] and _envelope_verifies(public, envelope)
            assert update["action"] == "parameter_change" and update["subject"] == case["parameter"] \
                == update["details"]["parameter"]
            identifier = _registry_update_id(update)
            if identifier in accepted:
                continue
            if log_seconds(update["effective_at"]) - log_seconds(epoch["sealed_at"]) < 7 * 86400:
                continue
            accepted[identifier] = epoch["epoch_number"]
            amendments.append({"effective_at_s": log_seconds(update["effective_at"]),
                               "epoch_number": epoch["epoch_number"], "entry_index": index,
                               "value": update["details"]["value"], "effective_at": update["effective_at"]})
    return _value_in_force(case["default"], amendments, log_seconds(case["query_at"]))[0]

def _dc4_parameter_resume():
    v = _parameter_vector()
    assert v["resume_cases"]
    for case in v["resume_cases"]:
        top = case["snapshot_epoch"]
        accepted, amendments = {}, []
        _parameter_resume_run(case, case["epochs"][:top + 1], accepted, amendments)
        live = [a for a in amendments if not any(
            b["effective_at_s"] == a["effective_at_s"] and (b["epoch_number"], b["entry_index"])
            > (a["epoch_number"], a["entry_index"]) for b in amendments)]
        tuples = [["parameter", case["parameter"], a["effective_at"], a["value"]] for a in live]
        tuples += [["registry_update", i, h] for i, h in accepted.items()]
        assert sorted(map(rfc8785.dumps, tuples)) == sorted(map(rfc8785.dumps, case["snapshot_tuples"])), \
            f"{case['label']}: the Snapshot's tuples are not the replayed state"
        envelope = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
        envelope["state"]["entries"] = case["snapshot_tuples"]
        Draft202012Validator(json.loads((ROOT / "schemas/snapshot-state.schema.json").read_text())).validate(envelope)
        replayed = _parameter_resume_run(case, case["epochs"], {}, [])
        adopted = {t[1]: t[2] for t in case["snapshot_tuples"] if t[0] == "registry_update"}
        resumed_amendments = [{"effective_at_s": log_seconds(t[2]), "epoch_number": top, "entry_index": -1,
                               "value": t[3]} for t in case["snapshot_tuples"] if t[0] == "parameter"]
        later = case["epochs"][top + 1:]
        resumed = _parameter_resume_run(case, later, adopted, list(resumed_amendments))
        without = _parameter_resume_run(case, later, {}, list(resumed_amendments))
        assert (replayed, resumed, without) == (case["replayed_value"], case["resumed_value"],
                                                case["value_resumed_without_registry_update_tuples"]), case["label"]
        assert replayed == resumed != without, f"{case['label']}: the registry_update tuples decide nothing"
check("vectors:wist4-parameter-resume", _dc4_parameter_resume)


def _keys_valid_at(tuples, genesis_key_id: str, height: int) -> set:
    """WIST-3 §3.4/§7: a tuple's key is valid at height h iff its added height
    is <= h and its removed height is null or greater than h; the set valid at
    height -1 is the genesis key alone."""
    if height < 0:
        return {genesis_key_id}
    return {t[1] for t in tuples if t[3] <= height and (t[4] is None or t[4] > height)}


def _verify_checkpoint_keyset(text: str, log_id: str, pubkeys: dict) -> dict:
    """WIST-3 §5 where more than one Aggregator key may be valid at a height:
    every Aggregator key signs under the Log's origin as its signer name, so a
    line names a known key when its note key ID (§3.4) is one of theirs.
    `pubkeys` maps key_id to the raw public key of a key valid at the
    Checkpoint's height. Rejects as "WIST3-E03: ..." when no line under a key
    of that set verifies, or when a line naming one of them fails."""
    parsed = parse_checkpoint(text)
    if parsed["origin"] != log_id:
        raise ValueError("WIST3-E03: origin does not match the Log's log_id")
    by_note_id = {note_key_id(log_id, raw): key_id for key_id, raw in pubkeys.items()}
    verified = []
    for name, kid, rest in parsed["signatures"]:
        if name != log_id or kid not in by_note_id:
            continue
        if len(rest) != 64:
            raise ValueError("WIST3-E03: signature blob is not a canonical 4+64-octet key_id||signature")
        try:
            Ed25519PublicKey.from_public_bytes(pubkeys[by_note_id[kid]]).verify(
                rest, parsed["signed_bytes"])
        except InvalidSignature:
            raise ValueError("WIST3-E03: signature under a known key does not verify")
        verified.append(by_note_id[kid])
    if not verified:
        raise ValueError("WIST3-E03: no verifying signature under a key valid at this height")
    parsed["verified_key_ids"] = verified
    return parsed


ENTRY_TYPES = ("publisher_declaration", "registry_update", "publisher_catalog",
               "publisher_item", "label", "dispute")


def _key_epoch_rejection(entries):
    """WIST-3 §3.3: an Entry that is not an object of exactly `type` and `body`
    of a listed type rejects its Epoch whole. No other whole-Epoch rejection is
    reachable in a family whose Entries are Registry Updates."""
    formed = [isinstance(e, dict) and set(e) == {"type", "body"} and e["type"] in ENTRY_TYPES
              for e in entries]
    assert all(e["type"] == "registry_update" for e, ok in zip(entries, formed) if ok), \
        "an Entry of a listed type other than registry_update, which this replay does not judge"
    return None if all(formed) else "WIST3-E03"


def _registry_after_act(registry, update, height, suffix_lists, sealed_at):
    """WIST-4 §§3.1, 5, 5.1 for an authenticated non-key act of an accepted
    Epoch: a parameter_change is an amendment once it meets the grace period,
    a suffix_list_update puts its snapshot in force once its `bytes` is the
    octet count of the file it names, and either's ID is accepted."""
    if update["action"] == "parameter_change":
        assert log_seconds(update["effective_at"]) - log_seconds(sealed_at) >= 7 * 86400, \
            "a parameter_change short of the grace period, which this family does not carry"
        registry["amendments"].append((update["subject"], update["effective_at"],
                                       update["details"]["value"]))
    elif update["action"] == "suffix_list_update":
        octets = suffix_lists[update["details"]["sha256"]]
        assert "sha256:" + hashlib.sha256(octets).hexdigest() == update["details"]["sha256"] \
            and len(octets) == update["details"]["bytes"], "a suffix_list_update failing its contract"
        if registry["suffix_list"] is None or registry["suffix_list"][0] != update["details"]["sha256"]:
            registry["suffix_list"] = (update["details"]["sha256"], height)
    else:
        raise AssertionError(f"an act this replay does not judge: {update['action']}")
    registry["accepted"].setdefault(_registry_update_id(update), height)


def _registry_tuples(registry):
    """WIST-3 §7: a parameter tuple per amendment that no later one of its
    identifier and effective_at supersedes (WIST-4 §5), the suffix_list tuple
    of the snapshot in force, one registry_update tuple per accepted ID."""
    tuples = []
    for i, (parameter, effective_at, value) in enumerate(registry["amendments"]):
        if not any(p == parameter and at == effective_at
                   for p, at, _ in registry["amendments"][i + 1:]):
            tuples.append(["parameter", parameter, effective_at, value])
    if registry["suffix_list"] is not None:
        tuples.append(["suffix_list", *registry["suffix_list"]])
    tuples += [["registry_update", i, h] for i, h in registry["accepted"].items()]
    return tuples


def _replay_key_epoch(tuples, log_id, genesis_key_id, height, entries, validator,
                      key_act_authentication="previous height", admitted="ever admitted",
                      note_key_id_collisions=True, removal_reads="previous height",
                      entry_order="ascending", other_act_authentication="own Epoch",
                      registry=None, rejected=False, suffix_lists=None, sealed_at=None,
                      idempotence="after field validation", rejected_key_acts="applied",
                      rejected_ids="key acts", rejected_other_acts="not applied"):
    """WIST-3 §3.4 over one Epoch: authenticated key acts first, in canonical
    Entry index order, each read at height-1 and evaluated against the admitted
    set, then every other act read at the height the accepted key acts leave.
    Returns (`aggregator_key` tuples after the Epoch, one disposition per
    Entry); each tuple carries the accepted key acts §7 keeps, the removal at
    the lower Entry index where an Epoch accepts two of one key. With
    `registry` (accepted IDs, amendments, snapshot in force; updated in place)
    an occurrence of an accepted ID that passes field validation is idempotent
    (WIST-4 §5.1), and of a `rejected` Epoch the key acts alone apply and only
    their IDs are accepted (WIST-3 §3.3, Rejected Epochs). The keyword
    arguments spell the readings §3.3 and §3.4 fix; the mutation twin flips
    each and requires the outcome to move."""
    before = [list(t) for t in tuples]
    after = [list(t) for t in before]
    codes = [None] * len(entries)
    act_indexes = [i for i, e in enumerate(entries) if e["type"] == "registry_update"]
    accepted = registry["accepted"] if registry is not None else None

    def idempotent(index):
        return accepted is not None and idempotence != "none" \
            and _registry_update_id(entries[index]["body"]["update"]) in accepted

    if idempotence == "before field validation":
        act_indexes = [i for i in act_indexes if not idempotent(i)]
    key_act_indexes = [i for i in act_indexes
                       if entries[i]["body"]["update"]["action"] in KEY_ACTS]
    if rejected and rejected_key_acts == "ignored":
        key_act_indexes = []
    if entry_order == "descending":
        key_act_indexes = key_act_indexes[::-1]

    if key_act_authentication == "previous height":
        auth_set = _keys_valid_at(before, genesis_key_id, height - 1)
    elif key_act_authentication == "assume authenticated":
        auth_set = None
    else:                               # "own Epoch": the set this Epoch leaves
        provisional, _ = _replay_key_epoch(
            tuples, log_id, genesis_key_id, height, entries, validator,
            key_act_authentication="assume authenticated", admitted=admitted,
            note_key_id_collisions=note_key_id_collisions, removal_reads=removal_reads,
            entry_order=entry_order, other_act_authentication=other_act_authentication)
        auth_set = _keys_valid_at(provisional, genesis_key_id, height)

    public_before = {t[1]: t[2] for t in before}
    admitted_note_ids = {note_key_id(log_id, b64u_decode(t[2])) for t in before
                         if admitted == "ever admitted"
                         or t[1] in _keys_valid_at(before, genesis_key_id, height - 1)}
    for index in key_act_indexes:
        body = entries[index]["body"]
        code, doc = _registry_update_eligibility(json.dumps(body), validator)
        if code is not None:
            codes[index] = code
            continue
        if idempotent(index):
            continue
        if auth_set is not None:
            signer = body["sig"]["key_id"]
            raw = public_before.get(signer)
            if signer not in auth_set or raw is None or not _envelope_verifies(b64u_decode(raw), body):
                codes[index] = "WIST4-E11"
                continue
        named = doc["update"]["details"]["key_id"]
        if doc["update"]["action"] == "aggregator_key_add":
            public_key = doc["update"]["details"]["public_key"]
            note_id = note_key_id(log_id, b64u_decode(public_key))
            epoching = [t[1] for t in after
                        if admitted == "ever admitted"
                        or t[1] in _keys_valid_at(after, genesis_key_id, height - 1)]
            if named in epoching or (note_key_id_collisions and note_id in admitted_note_ids):
                codes[index] = "WIST4-E04"
                continue
            after.append(["aggregator_key", named, public_key, height, None, body, None])
            admitted_note_ids.add(note_id)
        else:
            reference = _keys_valid_at(before, genesis_key_id, height - 1)
            if removal_reads != "previous height":
                reference = reference | {entries[i]["body"]["update"]["details"]["key_id"]
                                         for i in key_act_indexes
                                         if entries[i]["body"]["update"]["action"] == "aggregator_key_add"}
            if named not in reference:
                codes[index] = "WIST4-E04"
                continue
            for tuple_ in after:
                if tuple_[1] == named:
                    tuple_[4] = height
                    if tuple_[6] is None:
                        tuple_[6] = body
        if accepted is not None and not (rejected and rejected_ids == "none"):
            accepted.setdefault(_registry_update_id(doc["update"]), height)

    other_set = (_keys_valid_at(after, genesis_key_id, height)
                 if other_act_authentication == "own Epoch"
                 else _keys_valid_at(before, genesis_key_id, height - 1))
    public_after = {t[1]: t[2] for t in after}
    for index in act_indexes:
        entry = entries[index]
        if entry["body"]["update"]["action"] in KEY_ACTS:
            continue
        code, doc = _registry_update_eligibility(json.dumps(entry["body"]), validator)
        if code is None and rejected and rejected_other_acts == "not applied":
            code = "WIST3-E03"
            if rejected_ids == "all":
                accepted.setdefault(_registry_update_id(doc["update"]), height)
        elif code is None and not idempotent(index):
            signer = entry["body"]["sig"]["key_id"]
            raw = public_after.get(signer)
            if signer not in other_set or raw is None or not _envelope_verifies(b64u_decode(raw), entry["body"]):
                code = "WIST4-E11"
            elif registry is not None:
                _registry_after_act(registry, doc["update"], height, suffix_lists, sealed_at)
        codes[index] = code
    return after, codes


def _canonical_entry_order(entries) -> bool:
    """WIST-3 §3.3: one type group here, so canonical order is ascending
    leaf-hash order; an Entry of no listed type, which has no group, comes
    after it."""
    ranks = [(e.get("type") != "registry_update", leaf_hash(rfc8785.dumps(e))) for e in entries]
    return ranks == sorted(ranks)


def _replay_key_history(history, validator, **variant):
    """Replay one Log of the vector: returns the per-Epoch dispositions, the
    tuples after each Epoch, the key set and its public keys at each height,
    the cumulative leaf hashes and the verified head. Each published
    Checkpoint is verified here under the keys valid at its own height,
    because only a Checkpoint that verifies applies its Epoch (WIST-3 §5);
    every other comparison against the vector is the caller's."""
    log_id = history["log_id"]
    anchor = history["anchor"]["anchor"]
    genesis_key_id = anchor["genesis_key"]["key_id"]
    tuples = [["aggregator_key", genesis_key_id, anchor["genesis_key"]["public_key"],
               0, None, None, None]]
    states, dispositions, key_sets, pubkeys = {}, [], {-1: {genesis_key_id}}, {}
    leaves, cumulative, head = [], {}, None
    registry = {"accepted": {}, "amendments": [], "suffix_list": None}
    suffix_lists = {s["sha256"]: s["text"].encode() for s in history.get("suffix_lists", [])}
    rejections, registry_states = {}, {}
    for epoch in history["epochs"]:
        height = epoch["epoch_number"]
        entries = epoch["entries"]
        leaves = leaves + [leaf_hash(rfc8785.dumps(e)) for e in entries]
        cumulative[height] = [h.hex() for h in leaves]
        rejections[height] = _key_epoch_rejection(entries)
        candidate = copy.deepcopy(registry)
        after, codes = _replay_key_epoch(tuples, log_id, genesis_key_id, height, entries,
                                         validator, registry=candidate,
                                         rejected=rejections[height] is not None,
                                         suffix_lists=suffix_lists, sealed_at=epoch["sealed_at"],
                                         **variant)
        dispositions.append(codes)
        key_sets[height] = _keys_valid_at(after, genesis_key_id, height)
        pubkeys[height] = {t[1]: b64u_decode(t[2]) for t in after if t[1] in key_sets[height]}
        if epoch["checkpoint"] is not None:
            parsed = _verify_checkpoint_keyset(epoch["checkpoint"], log_id, pubkeys[height])
            root = merkle_root(leaves) if leaves else hashlib.sha256(b"").digest()
            assert parsed["epoch_number"] == height and parsed["tree_size"] == len(leaves) \
                and parsed["root"] == root and parsed["sealed_at"] == epoch["sealed_at"], \
                f"{history['name']} epoch {height}: the Checkpoint does not state this Epoch"
            head = height
            tuples = after
            registry = candidate
        states[height] = [list(t) for t in tuples]
        registry_states[height] = _registry_tuples(registry)
    return {"dispositions": dispositions, "states": states, "key_sets": key_sets,
            "rejections": rejections, "registry_states": registry_states,
            "pubkeys": pubkeys, "head": head, "genesis_key_id": genesis_key_id,
            "leaf_hashes": cumulative}


def _wist3_aggregator_keys():
    """WIST-3 §3.4, §5, §7 and WIST-4 §5.1: a key act sealed in Epoch N
    authenticates under the keys valid at N-1, every other act of Epoch N and
    Checkpoint N under the keys valid at N; an authenticated key act that is a
    key-act failure is WIST4-E04 with the Epoch kept, and an unauthenticated
    one is WIST4-E11. Of a rejected Epoch the key acts alone apply (§3.3), and
    an occurrence of an accepted ID passing field validation is idempotent."""
    v = _aggregator_keys_vector()
    validator = Draft202012Validator(
        json.loads((ROOT / "schemas/registry-update.schema.json").read_text()))
    anchor_schema = Draft202012Validator(
        json.loads((ROOT / "schemas/log-anchor.schema.json").read_text()))
    state_schema = Draft202012Validator(
        json.loads((ROOT / "schemas/snapshot-state.schema.json").read_text()))
    seen_codes, seen_ties, seen_unapplied = set(), 0, 0
    seen_rotation, seen_ignored_line = 0, 0
    seen_rejected, seen_idempotent, seen_field_failure_repeat = 0, 0, 0
    origins = set()
    for history in v["histories"]:
        log_id = history["log_id"]
        assert log_id not in origins, "two histories share one origin"
        origins.add(log_id)
        anchor_schema.validate(history["anchor"])
        anchor = history["anchor"]["anchor"]
        genesis = anchor["genesis_key"]
        assert anchor["log_id"] == log_id, f"{history['name']}: the Anchor names another Log"
        assert history["anchor"]["sig"]["key_id"] == genesis["key_id"] \
            and _envelope_verifies(b64u_decode(genesis["public_key"]), history["anchor"], "anchor"), \
            f"{history['name']}: the Anchor is not self-signed under its own genesis_key"

        replay = _replay_key_history(history, validator)
        expected_sets = {q["height"]: set(q["key_ids"]) for q in history["valid_at"]}
        assert expected_sets[-1] == {genesis["key_id"]}, \
            f"{history['name']}: the key set valid at height -1 is the genesis key alone"
        previous_sealed, seen_ids = None, set()
        for epoch, codes in zip(history["epochs"], replay["dispositions"]):
            height = epoch["epoch_number"]
            where = f"{history['name']} epoch {height}"
            entries = epoch["entries"]
            assert _canonical_entry_order(entries), f"{where}: Entries are not in canonical order"
            assert epoch["leaf_hashes"] == replay["leaf_hashes"][height], \
                f"{where}: leaf_hashes is not the cumulative tree through this Epoch"
            assert epoch["tree_size"] == len(epoch["leaf_hashes"]), where
            assert epoch["rejection"] == replay["rejections"][height], \
                f"{where}: replayed rejection {replay['rejections'][height]}, vector says {epoch['rejection']}"
            seen_rejected += epoch["rejection"] is not None and epoch["applied"]
            acts = [i for i, e in enumerate(entries) if e["type"] == "registry_update"]
            for index in acts:
                code, _ = _registry_update_eligibility(json.dumps(entries[index]["body"]), validator)
                identifier = _registry_update_id(entries[index]["body"]["update"])
                assert code is None or identifier in seen_ids, \
                    f"{where}: an Entry fails WIST-4 §5.1 field validation ({code}) other than " \
                    "an occurrence of an ID sealed before; every other disposition in this " \
                    "family must come from the §3.3 and §3.4 rules"
                seen_field_failure_repeat += code is not None
                seen_idempotent += code is None and identifier in seen_ids and codes[index] is None
                seen_ids.add(identifier)
            sealed = log_seconds(epoch["sealed_at"])
            assert sealed % 3600 == 0, f"{where}: sealed_at is off the hourly grid"
            assert previous_sealed is None or sealed > previous_sealed, \
                f"{where}: sealed_at is not strictly increasing"
            previous_sealed = sealed
            assert [a["entry_index"] for a in epoch["acts"]] == acts, where
            for act in epoch["acts"]:
                entry, code = entries[act["entry_index"]], codes[act["entry_index"]]
                update = entry["body"]["update"]
                assert act["action"] == update["action"] and act["subject"] == update["subject"] \
                    and act["signer_key_id"] == entry["body"]["sig"]["key_id"], \
                    f"{where}: act {act['entry_index']} does not describe its Entry"
                assert code == act["code"], \
                    f"{where}: act {act['entry_index']} replayed as {code}, vector says {act['code']}"
                seen_codes.add(code)
            assert sorted(map(rfc8785.dumps, replay["registry_states"][height])) \
                == sorted(map(rfc8785.dumps, epoch["expected_registry_state"])), \
                f"{where}: the parameter, suffix_list and registry_update tuples the replay leaves"
            assert replay["key_sets"][height] == expected_sets[height], \
                f"{where}: the key set valid at this height"
            assert epoch["applied"] == (epoch["checkpoint"] is not None), where
            expected_state = sorted(map(json.dumps, replay["states"][height]))
            assert expected_state == sorted(map(json.dumps, epoch["expected_state"])), \
                f"{where}: the aggregator_key tuples the replay leaves"
            assert all(t[0] == "aggregator_key" and len(t) == 7 for t in epoch["expected_state"]), where
            if not epoch["applied"]:
                seen_unapplied += 1
                assert epoch["checkpoint_cases"] and all(
                    case["expected"] == "WIST3-E03" for case in epoch["checkpoint_cases"]), \
                    f"{where}: an Epoch no Checkpoint verifies must state the candidates it rejects"
            for tie in epoch.get("tie_breaks", []):
                seen_ties += 1
                assert tie["accepted_entry_index"] < tie["failed_entry_index"], \
                    f"{where}: the accepted act is not the lower Entry index"
                assert codes[tie["accepted_entry_index"]] is None \
                    and codes[tie["failed_entry_index"]] == "WIST4-E04", \
                    f"{where}: the tie-break dispositions"
            if epoch["applied"]:
                published = _verify_checkpoint_keyset(epoch["checkpoint"], log_id,
                                                      replay["pubkeys"][height])
                seen_rotation += len(published["verified_key_ids"]) > 1
            for case in epoch["checkpoint_cases"]:
                try:
                    parsed = _verify_checkpoint_keyset(case["checkpoint"], log_id,
                                                       replay["pubkeys"][height])
                    result = "valid"
                    if case["expected"] == "valid" \
                            and len(parsed["signatures"]) > len(parsed["verified_key_ids"]):
                        seen_ignored_line += 1
                except ValueError as e:
                    assert "WIST3-E03" in str(e), f"{where}: {case['name']}: wrong code: {e}"
                    result = "WIST3-E03"
                assert result == case["expected"], \
                    f"{where}: {case['name']}: got {result}, want {case['expected']}"
        assert replay["head"] == history["verified_head"], \
            f"{history['name']}: the verified head the replay leaves"

        # WIST-3 §5: a Checkpoint at or below the verified head is judged under
        # the keys valid at its own height, never the head's.
        for case in history.get("equivocation_cases", []):
            height = case["epoch_number"]
            assert height <= history["verified_head"], case["name"]
            held = next(b for b in history["epochs"] if b["epoch_number"] == height)
            try:
                parsed = _verify_checkpoint_keyset(case["checkpoint"], log_id,
                                                   replay["pubkeys"][height])
                differs = (parsed["signed_bytes"]
                           != parse_checkpoint(held["checkpoint"])["signed_bytes"])
                result = "WIST3-E02" if differs else "valid"
            except ValueError as e:
                assert "WIST3-E03" in str(e), f"{case['name']}: wrong code: {e}"
                result = "WIST3-E03"
            assert result == case["expected"], \
                f"{history['name']}: {case['name']}: got {result}, want {case['expected']}"

        # WIST-3 §7: the state artifact keeps a removed key's tuple, and a file
        # that omits one does not verify.
        if "snapshot_state" in history:
            snapshot = history["snapshot_state"]
            head_epoch = next(b for b in history["epochs"]
                              if b["epoch_number"] == history["verified_head"])
            assert snapshot["tree_size"] == head_epoch["tree_size"] \
                and snapshot["epoch_number"] == history["verified_head"], \
                f"{history['name']}: the Snapshot position is not the verified head's"
            complete = {json.dumps(t) for t in replay["states"][history["verified_head"]]
                        + replay["registry_states"][history["verified_head"]]}
            envelope = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
            saw_removed_tuple, omitted_updates = False, False
            for case in snapshot["cases"]:
                envelope["state"]["entries"] = case["entries"]
                envelope["state"]["tree_size"] = snapshot["tree_size"]
                state_schema.validate(envelope)      # every case is schema-valid
                carried = {json.dumps(t) for t in case["entries"]}
                verifies = carried == complete
                assert verifies == case["verifies"], \
                    f"{history['name']}: snapshot state case {case['name']!r}"
                if verifies:
                    saw_removed_tuple = any(t[0] == "aggregator_key" and t[4] is not None
                                            for t in case["entries"])
                else:
                    missing = [json.loads(t) for t in complete - carried]
                    assert missing and all(t[0] == "aggregator_key" and t[4] is not None
                                           or t[0] == "registry_update" for t in missing), \
                        f"{history['name']}: {case['name']!r} omits a tuple that is neither a removed key's " \
                        "nor an accepted Registry Update's"
                    omitted_updates |= any(t[0] == "registry_update" for t in missing)
            assert saw_removed_tuple, "no verifying state file carries a removed key's tuple"
            assert omitted_updates, "no state file omitting the registry_update tuples is refused"

    assert seen_codes == {None, "WIST3-E03", "WIST4-E04", "WIST4-E11"}, \
        f"the histories do not exercise every disposition: {sorted(map(str, seen_codes))}"
    assert seen_ties >= 2 and seen_unapplied >= 1 and seen_rotation >= 1 and seen_ignored_line >= 1, \
        "the vector must exercise both tie-breaks, an Epoch no Checkpoint verifies, a " \
        "rotation Checkpoint whose two signature lines both verify under keys valid at " \
        "its height, and a Checkpoint whose line from a key not valid there is ignored"
    assert seen_rejected >= 1 and seen_idempotent >= 3 and seen_field_failure_repeat >= 1, \
        "the vector must exercise a rejected Epoch whose Checkpoint verifies, repeated IDs " \
        "left idempotent, and a repeated ID failing field validation"

    # WIST-3 §3.3, Rejected Epochs: a rejected Epoch admits a key that alone
    # signs its Checkpoint, and carries a parameter_change and another non-key
    # act; the parameter_change, sealed again in a later accepted Epoch, is
    # accepted at that later height.
    shown = False
    for history in v["histories"]:
        replay = _replay_key_history(history, validator)
        heads = [b for b in history["epochs"] if b["rejection"] and b["applied"]]
        for epoch in heads:
            height = epoch["epoch_number"]
            admitted = {t[1] for t in replay["states"][height]} - {t[1] for t in replay["states"][height - 1]}
            signers = _verify_checkpoint_keyset(epoch["checkpoint"], history["log_id"],
                                                replay["pubkeys"][height])["verified_key_ids"]
            others = [e["body"]["update"] for e in epoch["entries"] if e["type"] == "registry_update"
                      and e["body"]["update"]["action"] not in KEY_ACTS]
            later = {t[1]: t[2] for t in replay["registry_states"][history["epochs"][-1]["epoch_number"]]
                     if t[0] == "registry_update"}
            parameter = [_registry_update_id(u) for u in others if u["action"] == "parameter_change"]
            shown |= bool(admitted) and set(signers) <= admitted \
                and len({u["action"] for u in others}) >= 2 \
                and any(later.get(i, height) > height for i in parameter)
    assert shown, "no rejected Epoch shows its key act alone applied and a parameter_change accepted later"

    # WIST-3 §3.4: the key set at N does not depend on the order two key acts of
    # one Epoch are evaluated in. The two histories' additions differ in the
    # `effective_at` that moves their leaf-hash order, so the §7 tuples' carried
    # acts differ by construction; what must agree is the key validity the
    # tuples state — key_id, public key and both heights.
    first, second = (next(h for h in v["histories"] if h["name"] == name)
                     for name in v["same_registry_histories"])

    def index_of(history, action):
        return next(i for i, e in enumerate(history["epochs"][-1]["entries"])
                    if e["body"]["update"]["action"] == action)

    assert [t[:5] for t in first["epochs"][-1]["expected_state"]] \
        == [t[:5] for t in second["epochs"][-1]["expected_state"]], \
        "the two Entry orders leave different key registries"
    assert first["epochs"][-1]["expected_state"] != second["epochs"][-1]["expected_state"], \
        "the two histories carry one addition Envelope, so the Entry orders are not distinct"
    assert (index_of(first, "aggregator_key_add") < index_of(first, "aggregator_key_remove")) \
        != (index_of(second, "aggregator_key_add") < index_of(second, "aggregator_key_remove")), \
        "both histories place the addition on the same side of the removal"

    def anchor_outcome(envelope, null_as_absent=False):
        if null_as_absent and envelope["anchor"].get("predecessor", 0) is None:
            envelope = dict(envelope, anchor={k: x for k, x in envelope["anchor"].items() if k != "predecessor"})
        if not anchor_schema.is_valid(envelope):
            return "WIST3-E03"
        genesis = envelope["anchor"]["genesis_key"]
        verified = envelope["sig"]["key_id"] == genesis["key_id"] and _envelope_verifies(
            b64u_decode(genesis["public_key"]), envelope, "anchor")
        return "accepted" if verified else "rejected"

    stated_anchors = [(c["name"], c["expected"]) for c in v["anchor_cases"]]
    assert [(c["name"], anchor_outcome(c["anchor"])) for c in v["anchor_cases"]] == stated_anchors, \
        "an Anchor case's outcome differs from the schema-first judgment"
    assert [(c["name"], anchor_outcome(c["anchor"], True)) for c in v["anchor_cases"]] != stated_anchors, \
        "reading predecessor null as an absent member reproduces every Anchor outcome"
    null_cases = [c for c in v["anchor_cases"] if c["anchor"]["anchor"].get("predecessor", 0) is None]
    assert null_cases and all(c["expected"] == "WIST3-E03" for c in null_cases)
    assert all(c["anchor"]["sig"]["key_id"] == c["anchor"]["anchor"]["genesis_key"]["key_id"]
               and _envelope_verifies(b64u_decode(c["anchor"]["anchor"]["genesis_key"]["public_key"]),
                                      c["anchor"], "anchor") for c in null_cases), \
        "a predecessor-null Anchor is not correctly self-signed, so its rejection is not the schema's alone"
    assert any(c["expected"] == "accepted" and "predecessor" not in c["anchor"]["anchor"]
               for c in v["anchor_cases"]), "no accepted Anchor without the predecessor member"

    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "A key act sealed in Epoch N is authenticated under the keys valid at height N−1." in prose
    assert "The key set valid at height −1 is the genesis key alone." in prose
    assert "A Consumer replaying the Log ignores one as `WIST4-E04`" in prose
    assert "A removed key's tuple MUST remain" in prose
check("vectors:wist3-aggregator-keys", _wist3_aggregator_keys)


def _wist3_aggregator_keys_twin():
    """Mutation twins: each reading WIST-3 §3.4 fixes, flipped, must move an
    outcome the vector states, and a broken signature must be caught."""
    v = _aggregator_keys_vector()
    validator = Draft202012Validator(
        json.loads((ROOT / "schemas/registry-update.schema.json").read_text()))
    stated = {h["name"]: [[a["code"] for a in b["acts"]] for b in h["epochs"]]
              for h in v["histories"]}
    states = {h["name"]: [(b["expected_state"], sorted(map(rfc8785.dumps, b["expected_registry_state"])))
                          for b in h["epochs"]] for h in v["histories"]}

    def outcome(variant, names=None):
        seen = {}
        for history in v["histories"]:
            if names is not None and history["name"] not in names:
                continue
            try:
                replay = _replay_key_history(history, validator, **variant)
            except (AssertionError, ValueError) as e:
                seen[history["name"]] = f"halted: {e}"   # a Checkpoint the flipped reading cannot verify
                continue
            seen[history["name"]] = (
                [[codes[a["entry_index"]] for a in b["acts"]]
                 for b, codes in zip(history["epochs"], replay["dispositions"])],
                [(replay["states"][b["epoch_number"]],
                  sorted(map(rfc8785.dumps, replay["registry_states"][b["epoch_number"]])))
                 for b in history["epochs"]])
        return seen

    control = outcome({})
    for name in stated:
        assert control[name] == (stated[name], states[name]), f"positive control: {name}"
    for variant in ({"key_act_authentication": "own Epoch"},
                    {"other_act_authentication": "previous height"},
                    {"admitted": "valid only"},
                    {"note_key_id_collisions": False},
                    {"removal_reads": "own Epoch"},
                    {"entry_order": "descending"}):
        assert outcome(variant) != control, f"flipping {variant} changed no outcome the vector states"

    # WIST-3 §3.3, Rejected Epochs, and WIST-4 §5.1's idempotence: each reading
    # flipped must move the history built to decide it.
    rejected = {h["name"] for h in v["histories"]
                if any(b["rejection"] and b["applied"] for b in h["epochs"])}
    repeated = {h["name"] for h in v["histories"]
                if not any(b["rejection"] for b in h["epochs"]) and len(
                    {_registry_update_id(e["body"]["update"]) for b in h["epochs"] for e in b["entries"]})
                < sum(len(b["entries"]) for b in h["epochs"])}
    assert rejected and repeated
    for names, variant in ((rejected, {"rejected_key_acts": "ignored"}),
                           (rejected, {"rejected_ids": "none"}),
                           (rejected, {"rejected_ids": "all"}),
                           (rejected, {"rejected_other_acts": "applied"}),
                           (repeated, {"idempotence": "none"}),
                           (repeated, {"idempotence": "before field validation"})):
        flipped = outcome(variant, names)
        assert all(flipped[n] != control[n] for n in names), \
            f"flipping {variant} changed no outcome of {sorted(names)}"

    # Each flip, at the Entry it is supposed to decide.
    rotation = next(h for h in v["histories"] if h.get("equivocation_cases"))
    genesis_key_id = rotation["anchor"]["anchor"]["genesis_key"]["key_id"]

    def _flip(epoch, act_predicate, expected, **variant):
        prior = [list(t) for t in rotation["epochs"][epoch["epoch_number"] - 1]["expected_state"]]
        _, codes = _replay_key_epoch(prior, rotation["log_id"], genesis_key_id,
                                     epoch["epoch_number"], epoch["entries"], validator, **variant)
        act = next(a for a in epoch["acts"] if act_predicate(a))
        assert act["code"] == "WIST4-E04", "the vector no longer states this failure"
        assert codes[act["entry_index"]] == expected, \
            f"flipping {variant} did not move act {act['entry_index']} of epoch " \
            f"{epoch['epoch_number']}"

    failures_epoch = next(b for b in rotation["epochs"]
                          if sum(a["code"] == "WIST4-E04" for a in b["acts"]) == 6)
    removed_key_id = next(t[1] for t in failures_epoch["expected_state"] if t[4] is not None)
    _flip(failures_epoch,
          lambda a: a["action"] == "aggregator_key_add" and a["subject"] == removed_key_id,
          None, admitted="valid only")
    collision = next(a for a in failures_epoch["acts"]
                     if a["action"] == "aggregator_key_add" and a["code"] == "WIST4-E04"
                     and a["subject"] not in [t[1] for t in failures_epoch["expected_state"]])
    _flip(failures_epoch, lambda a: a["entry_index"] == collision["entry_index"],
          None, note_key_id_collisions=False)

    ties_epoch = next(b for b in rotation["epochs"] if b.get("tie_breaks"))
    same_epoch_removal = next(a for a in ties_epoch["acts"]
                              if a["action"] == "aggregator_key_remove" and a["code"] == "WIST4-E04")
    _flip(ties_epoch, lambda a: a["entry_index"] == same_epoch_removal["entry_index"],
          None, removal_reads="own Epoch")
    prior = [list(t) for t in rotation["epochs"][ties_epoch["epoch_number"] - 1]["expected_state"]]
    _, descending = _replay_key_epoch(prior, rotation["log_id"], genesis_key_id,
                                      ties_epoch["epoch_number"], ties_epoch["entries"],
                                      validator, entry_order="descending")
    for tie in ties_epoch["tie_breaks"]:
        assert descending[tie["accepted_entry_index"]] == "WIST4-E04" \
            and descending[tie["failed_entry_index"]] is None, \
            "evaluating the Epoch's key acts in descending Entry index left the same winner"

    # The authentication height is what decides a key's own removal, and a
    # signature that does not verify is WIST4-E11 rather than a key-act failure.
    order_history = next(h for h in v["histories"] if h["name"] == v["same_registry_histories"][0])
    epoch = order_history["epochs"][-1]
    self_removal = next(a for a in epoch["acts"] if a["action"] == "aggregator_key_remove")
    assert self_removal["code"] is None and self_removal["signer_key_id"] == self_removal["subject"], \
        "the history does not carry a key signing its own removal"
    prior = [list(t) for t in order_history["epochs"][-2]["expected_state"]]
    _, flipped = _replay_key_epoch(prior, order_history["log_id"],
                                   order_history["anchor"]["anchor"]["genesis_key"]["key_id"],
                                   epoch["epoch_number"], epoch["entries"], validator,
                                   key_act_authentication="own Epoch")
    assert flipped[self_removal["entry_index"]] == "WIST4-E11", \
        "reading a key act at its own Epoch did not break the key signing its own removal"

    accepted = next(a for a in epoch["acts"] if a["code"] is None)
    entries = copy.deepcopy(epoch["entries"])
    tampered = bytearray(b64u_decode(entries[accepted["entry_index"]]["body"]["sig"]["value"]))
    tampered[-1] ^= 0xFF
    entries[accepted["entry_index"]]["body"]["sig"]["value"] = \
        base64.urlsafe_b64encode(bytes(tampered)).rstrip(b"=").decode()
    _, broken = _replay_key_epoch(prior, order_history["log_id"],
                                  order_history["anchor"]["anchor"]["genesis_key"]["key_id"],
                                  epoch["epoch_number"], entries, validator)
    assert broken[accepted["entry_index"]] == "WIST4-E11", \
        "an act whose signature does not verify was not WIST4-E11"

    # WIST-3 §5: judging a lower Checkpoint under the head's key set instead of
    # its own height's inverts both equivocation answers.
    rotation = next(h for h in v["histories"] if h.get("equivocation_cases"))
    replay = _replay_key_history(rotation, validator)
    head = rotation["verified_head"]
    head_pubkeys = replay["pubkeys"][head]
    inverted = 0
    for case in rotation["equivocation_cases"]:
        try:
            _verify_checkpoint_keyset(case["checkpoint"], rotation["log_id"], head_pubkeys)
            result = "WIST3-E02"
        except ValueError:
            result = "WIST3-E03"
        inverted += result != case["expected"]
    assert inverted == len(rotation["equivocation_cases"]), \
        "the head's key set answers these Checkpoints as their own height's does"
check("negative:wist3-aggregator-keys", _wist3_aggregator_keys_twin)


# WIST-3 §3.4, §7 and §8: a Snapshot's `aggregator_key` tuples authenticated
# from the Anchor, and the unsealed documents verified at the height of the
# Checkpoint the Consumer adopts. Implemented here from the prose, like the key
# acts above and never from tools/gen_vectors.py: every outcome below is
# recomputed from a case's own Anchor, Checkpoints, Envelopes and tuples, and
# the vector's stated outcome is compared to it afterwards.
UNSEALED_DOCUMENTS = ("index", "manifest", "state")


def _snapshot_keys_vector():
    return json.loads((ROOT / "vectors/wist3/snapshot-keys.json").read_text())


def _carried_act_ok(act, action, key_id, public_key, validator):
    """WIST-3 §7 rules 3 and 4: a carried key act passes WIST-4 §5.1's field
    validation — its JSON/JCS eligibility, its schema and its own version check,
    not the authentication §5.1 performs after them — as that action, naming the
    tuple's key."""
    code, doc = _registry_update_eligibility(json.dumps(act), validator)
    if code is not None:
        return False
    update = doc["update"]
    if update["action"] != action or update["details"].get("key_id") != key_id:
        return False
    return public_key is None or update["details"].get("public_key") == public_key


def _authenticate_key_tuples(tuples, anchor, epoch_number, log_id, validator,
                             act_height="previous height", genesis_binding=True):
    """WIST-3 §7 'Authenticating the key tuples': the rules of 1 through 5 the
    tuple set breaks, every rule evaluated over the whole set so that the answer
    does not depend on the order they are read in. `act_height` and
    `genesis_binding` spell the readings §7 fixes; the twin flips each."""
    keys = [t for t in tuples if t[0] == "aggregator_key"]
    genesis = anchor["genesis_key"]
    violated = set()

    key_ids = [t[1] for t in keys]
    note_ids = [note_key_id(log_id, b64u_decode(t[2])) for t in keys]
    if len(set(key_ids)) != len(key_ids) or len(set(note_ids)) != len(note_ids):
        violated.add(1)

    rootless = [t for t in keys if t[5] is None]
    if len(rootless) != 1:
        violated.add(2)
    elif genesis_binding and (rootless[0][1] != genesis["key_id"]
                              or rootless[0][2] != genesis["public_key"]
                              or rootless[0][3] != 0):
        violated.add(2)

    for tuple_ in keys:
        if tuple_[5] is not None:
            if not _carried_act_ok(tuple_[5], "aggregator_key_add", tuple_[1], tuple_[2],
                                   validator) \
                    or not isinstance(tuple_[3], int) or not 0 <= tuple_[3] <= epoch_number:
                violated.add(3)
        if (tuple_[4] is None) != (tuple_[6] is None):
            violated.add(4)        # the removing act is `null` exactly when the height is
        elif tuple_[6] is not None:
            floor = 0 if tuple_[5] is None else tuple_[3] + 1
            if not _carried_act_ok(tuple_[6], "aggregator_key_remove", tuple_[1], None,
                                   validator) \
                    or not isinstance(tuple_[4], int) \
                    or not floor <= tuple_[4] <= epoch_number:
                violated.add(4)

    for tuple_ in keys:
        for act, height in ((tuple_[5], tuple_[3]), (tuple_[6], tuple_[4])):
            if act is None or not isinstance(height, int):
                continue
            at = height - 1 if act_height == "previous height" else height
            valid = _keys_valid_at(keys, genesis["key_id"], at)
            if not any(named[1] in valid
                       and _envelope_verifies(b64u_decode(named[2]), act)
                       for named in keys if named[1] == act["sig"]["key_id"]):
                violated.add(5)
    return sorted(violated)


def _catch_up_conflicts(tuples, registry, verified_head, surplus=True):
    """WIST-3 §7: a Consumer that already holds key state for the Log rejects a
    Snapshot unless the tuples agree with its own registry up to its verified
    head V — every key the registry holds has a tuple with the registry's
    public key, added height and adding act; a key the registry holds as
    removed has the registry's removed height and removing act; a key the
    registry holds as valid at V has a removed height that is null or greater
    than V; and every tuple for a key the registry does not hold has an added
    height greater than V. `surplus` spells that last clause; the twin drops
    it."""
    carried = {t[1]: t for t in tuples if t[0] == "aggregator_key"}
    held_by = {t[1]: t for t in registry if t[0] == "aggregator_key"}
    conflicts = []
    for key_id, held in held_by.items():
        offered = carried.get(key_id)
        if offered is None:
            conflicts.append({"key_id": key_id, "reason": "omitted"})
            continue
        agrees = (offered[2] == held[2] and offered[3] == held[3]
                  and rfc8785.dumps(offered[5]) == rfc8785.dumps(held[5]))
        if held[4] is None:
            agrees = agrees and (offered[4] is None or offered[4] > verified_head)
        else:
            agrees = agrees and offered[4] == held[4] \
                and rfc8785.dumps(offered[6]) == rfc8785.dumps(held[6])
        if not agrees:
            conflicts.append({"key_id": key_id, "reason": "disagrees"})
    if surplus:
        for key_id, offered in carried.items():
            if key_id not in held_by and not (isinstance(offered[3], int)
                                              and offered[3] > verified_head):
                conflicts.append({"key_id": key_id, "reason": "unknown"})
    return sorted(conflicts, key=lambda conflict: conflict["key_id"])


def _walk_key_acts(tuples, history, log_id, genesis_key_id, epoch_number, head, validator):
    """WIST-3 §8 step 7: the key acts of the Epochs between the Snapshot's and
    the adopted Checkpoint's amend the tuples under §3.4."""
    current = [list(t) for t in tuples if t[0] == "aggregator_key"]
    for epoch in history["epochs"]:
        if epoch_number < epoch["epoch_number"] <= head:
            current, _ = _replay_key_epoch(current, log_id, genesis_key_id,
                                           epoch["epoch_number"], epoch["entries"], validator)
    return current


def _unsealed_failures(case, tuples, genesis_key_id, height):
    """WIST-3 §3.4 'Unsealed documents': the Snapshot index, the manifest and
    the state file verify under the keys valid at the height of the Checkpoint
    the Consumer adopts, whatever a signer's validity at a lower height."""
    valid = _keys_valid_at(tuples, genesis_key_id, height)
    public = {t[1]: t[2] for t in tuples if t[0] == "aggregator_key"}
    failed = []
    for name in UNSEALED_DOCUMENTS:
        signer = case[name]["sig"]["key_id"]
        if signer not in valid or signer not in public \
                or not _envelope_verifies(b64u_decode(public[signer]), case[name], name):
            failed.append(name)
    return sorted(failed)


def _snapshot_case_outcome(case, history, anchor, validator, **variant):
    """One case's answer, recomputed from its own documents: the §7 rules its
    tuples break, the catch-up disagreements, the unsealed documents that do
    not verify, and the key_ids valid at the adopted head."""
    log_id = history["log_id"]
    genesis_key_id = anchor["genesis_key"]["key_id"]
    tuples = case["state"]["state"]["entries"]
    epoch_number, head = case["epoch_number"], case["adopted_head"]
    rules = _authenticate_key_tuples(
        tuples, anchor, epoch_number, log_id, validator,
        act_height=variant.get("act_height", "previous height"),
        genesis_binding=variant.get("genesis_binding", True))
    registry = case.get("consumer_registry")
    conflicts = ([] if registry is None or not variant.get("catch_up", True)
                 else _catch_up_conflicts(tuples, registry["entries"],
                                          registry["verified_head"],
                                          surplus=variant.get("surplus", True)))
    judged_at = (head if variant.get("unsealed_at", "adopted head") == "adopted head"
                 else epoch_number)
    failed = _unsealed_failures(
        case, _walk_key_acts(tuples, history, log_id, genesis_key_id, epoch_number,
                             judged_at, validator),
        genesis_key_id, judged_at)
    at_head = _walk_key_acts(tuples, history, log_id, genesis_key_id, epoch_number,
                             head, validator)
    return {"tuple_rules": rules, "catch_up": conflicts, "unsealed_documents": failed,
            "key_ids": sorted(_keys_valid_at(at_head, genesis_key_id, head))}


def _published_files_hash(v, manifests, where):
    """Every tier file a manifest lists is published with the SHA-256 and
    length the manifest states, and nothing else is."""
    octets = {path: canonical_b64u_decode(value) for path, value in v["files"].items()}
    listed = set()
    for envelope in manifests:
        for entry in envelope["manifest"]["files"]:
            listed.add(entry["path"])
            assert entry["path"] in octets, f"{where}: {entry['path']} is listed and not published"
            assert hashlib.sha256(octets[entry["path"]]).hexdigest() == entry["sha256"] \
                and len(octets[entry["path"]]) == entry["bytes"], \
                f"{where}: {entry['path']} does not hash to the manifest's sha256 and bytes"
    assert listed == set(octets), f"{where}: a published file no manifest lists"


def _published_keys_reproduce(v, log_id):
    """Every signature the family carries, Envelope or Checkpoint line, is
    reproduced from a published seed (Ed25519 signing is deterministic, RFC
    8032 §5.1.6), or is so reproduced with its first octet inverted, the
    damage its failing signatures carry."""
    signers = {}
    for name, key in v["keys"].items():
        assert key["key_id"] == name, f"{name}: the key is published under another key_id"
        private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key["seed_hex"]))
        raw = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        assert base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == key["public_key"], \
            f"{name}: the seed does not derive the public key"
        signers[name] = private
    published = {key["public_key"] for key in v["keys"].values()}
    used_public, used_signers = set(), set()

    def signed_by(message, signature):
        for name, private in signers.items():
            if private.sign(message) == signature:
                return name
        return None

    def walk(node):
        if isinstance(node, list):
            if len(node) == 7 and node[0] == "aggregator_key" and isinstance(node[2], str):
                used_public.add(node[2])
            for child in node:
                walk(child)
            return
        if isinstance(node, str) and "\n\n" in node and node.startswith(log_id + "\n"):
            parsed = parse_checkpoint(node)
            for _name, kid, rest in parsed["signatures"]:
                name = signed_by(parsed["signed_bytes"], rest)
                assert name is not None and note_key_id(log_id, b64u_decode(v["keys"][name]["public_key"])) == kid, \
                    "a Checkpoint signature line no published seed reproduces"
                used_signers.add(name)
            return
        if not isinstance(node, dict):
            return
        if "public_key" in node and isinstance(node["public_key"], str):
            used_public.add(node["public_key"])
        if isinstance(node.get("sig"), dict) and "value" in node["sig"]:
            inner = next(k for k in node if k != "sig")
            message, signature = rfc8785.dumps(node[inner]), b64u_decode(node["sig"]["value"])
            name = signed_by(message, signature) or signed_by(
                message, bytes([signature[0] ^ 0xFF]) + signature[1:])
            assert name is not None, f"an {inner} signature no published seed reproduces"
            used_signers.add(name)
        for key, child in node.items():
            if node is v and key == "keys":
                continue
            walk(child)

    walk(v)
    assert used_public <= published, "a public key the family carries is not published"
    assert published == used_public | {v["keys"][n]["public_key"] for n in used_signers}, \
        "a published key whose signature or public key the family never carries"


def _wist3_snapshot_keys():
    """WIST-3 §7: a state file's `aggregator_key` tuples authenticate from the
    Anchor's genesis key or the Snapshot is rejected (`WIST3-E04`); §3.4: its
    index, manifest and state file verify under the keys valid at the height of
    the Checkpoint the Consumer adopts; §5: a Mirror list that does not verify
    is no error."""
    v = _snapshot_keys_vector()
    history = v["history"]
    log_id = history["log_id"]
    anchor = history["anchor"]["anchor"]
    genesis = anchor["genesis_key"]
    validator = Draft202012Validator(
        json.loads((ROOT / "schemas/registry-update.schema.json").read_text()))
    anchor_schema = Draft202012Validator(
        json.loads((ROOT / "schemas/log-anchor.schema.json").read_text()))
    document_schema = {
        name: Draft202012Validator(json.loads(
            (ROOT / f"schemas/snapshot-{name}.schema.json").read_text()))
        for name in UNSEALED_DOCUMENTS}
    mirrors_schema = Draft202012Validator(
        json.loads((ROOT / "schemas/mirrors.schema.json").read_text()))

    anchor_schema.validate(history["anchor"])
    assert anchor["log_id"] == log_id, "the Anchor names another Log"
    assert history["anchor"]["sig"]["key_id"] == genesis["key_id"] \
        and _envelope_verifies(b64u_decode(genesis["public_key"]), history["anchor"], "anchor"), \
        "the Anchor is not self-signed under its own genesis_key"

    _published_keys_reproduce(v, log_id)
    _published_files_hash(v, [c["manifest"] for c in v["cases"]], "snapshot-keys")

    replay = _replay_key_history(history, validator)
    assert replay["head"] == history["verified_head"], "the verified head the replay leaves"
    for epoch, codes in zip(history["epochs"], replay["dispositions"]):
        height = epoch["epoch_number"]
        assert all(code is None for code in codes), \
            f"epoch {height}: this Log seals accepted key acts only"
        assert sorted(map(json.dumps, replay["states"][height])) \
            == sorted(map(json.dumps, epoch["expected_state"])), \
            f"epoch {height}: the tuples the replay leaves"

    by_name, self_consistent = {}, 0
    for case in v["cases"]:
        where = case["name"]
        assert where not in by_name, f"two cases named {where!r}"
        by_name[where] = case
        assert case["log"] == history["name"], where
        epoch_number, head = case["epoch_number"], case["adopted_head"]
        epoch = history["epochs"][epoch_number]
        assert epoch["epoch_number"] == epoch_number, where
        assert epoch_number <= head <= history["verified_head"], \
            f"{where}: the adopted head is not at or above the Snapshot's Epoch"
        for name in UNSEALED_DOCUMENTS:
            document_schema[name].validate(case[name])
        tuples = case["state"]["state"]["entries"]

        # WIST-3 §8 steps 2-4: the index entry, the manifest and the state file
        # are statements about one Snapshot, and the state file is the one the
        # manifest names, so that nothing below is decided by a mismatch there.
        manifest = case["manifest"]["manifest"]
        entry = case["index"]["index"]["snapshots"][0]
        for field in ("snapshot_date", "tree_size", "content_digest"):
            assert entry[field] == manifest[field], \
                f"{where}: the index entry's {field} disagrees with the manifest"
        octets = rfc8785.dumps(case["state"])
        assert manifest["state"]["sha256"] == hashlib.sha256(octets).hexdigest() \
            and manifest["state"]["bytes"] == len(octets), \
            f"{where}: the manifest does not hash the state file it names"
        assert case["state"]["state"]["tree_size"] == manifest["tree_size"] == epoch["tree_size"], \
            f"{where}: the state file's tree_size is not the manifest's"
        digest = "sha256:" + hashlib.sha256(
            b"".join(sorted(rfc8785.dumps(t) for t in tuples))).hexdigest()
        assert digest == manifest["state"]["state_digest"] == case["state_digest"], \
            f"{where}: the state_digest is not this state file's"

        # WIST-3 §8 step 5: the Snapshot is served with the Checkpoint of its
        # Epoch, stating that Epoch's tree.
        parsed = parse_checkpoint(case["checkpoint"])
        assert parsed["origin"] == log_id and parsed["epoch_number"] == epoch_number \
            and parsed["tree_size"] == epoch["tree_size"] \
            and parsed["root"] == bytes.fromhex(manifest["root_hash"].split(":")[1]), \
            f"{where}: the Checkpoint does not state this Snapshot's tree"

        outcome = _snapshot_case_outcome(case, history, anchor, validator)
        rejected = bool(outcome["tuple_rules"] or outcome["catch_up"]
                        or outcome["unsealed_documents"])
        assert ("WIST3-E04" if rejected else "accept") == case["expected"], \
            f"{where}: replayed {outcome}, vector says {case['expected']}"
        if rejected:
            stated = case["violations"]
            assert outcome["tuple_rules"] == stated["tuple_rules"], \
                f"{where}: §7 rules {outcome['tuple_rules']} vs {stated['tuple_rules']}"
            assert outcome["catch_up"] == stated["catch_up"], \
                f"{where}: catch-up {outcome['catch_up']} vs {stated['catch_up']}"
            assert outcome["unsealed_documents"] == stated["unsealed_documents"], \
                f"{where}: unsealed {outcome['unsealed_documents']} vs " \
                f"{stated['unsealed_documents']}"
        else:
            assert outcome["key_ids"] == case["key_ids_at_adopted_head"], \
                f"{where}: the key set at the adopted head"

        # A Snapshot that verifies against itself: the Checkpoint and all three
        # documents verify under the tuples it carries, so the chain to the
        # Anchor is the only thing that rejects it.
        if case.get("self_consistent"):
            self_consistent += 1
            at_epoch = _keys_valid_at([t for t in tuples if t[0] == "aggregator_key"], genesis["key_id"],
                                      epoch_number)
            _verify_checkpoint_keyset(
                case["checkpoint"], log_id,
                {t[1]: b64u_decode(t[2]) for t in tuples if t[1] in at_epoch})
            assert not outcome["unsealed_documents"] and not outcome["catch_up"], \
                f"{where}: a self-consistent Snapshot's own documents must verify"
            assert outcome["tuple_rules"], \
                f"{where}: a self-consistent Snapshot must be rejected by §7's rules"

    rejects = [c for c in v["cases"] if c["expected"] != "accept"]
    accepts = [c for c in v["cases"] if c["expected"] == "accept"]
    assert rejects and accepts and {c["expected"] for c in v["cases"]} \
        == {"accept", "WIST3-E04"}, "the family does not carry both outcomes"
    for rule in (1, 2, 3, 4, 5):
        assert any(c["violations"]["tuple_rules"] == [rule] for c in rejects), \
            f"no case breaks §7 rule {rule} and nothing else"
    for document in UNSEALED_DOCUMENTS:
        assert any(c["violations"]["unsealed_documents"] == [document] for c in rejects), \
            f"no case rejects on the {document}'s signature alone"
        assert any(c[document]["sig"]["key_id"]
                   not in {t[1] for t in c["state"]["state"]["entries"]} for c in accepts), \
            f"no accepted Snapshot has its {document} signed by a key admitted above its Epoch"
    assert {conflict["reason"] for c in rejects for conflict in c["violations"]["catch_up"]} \
        == {"omitted", "disagrees", "unknown"}, \
        "the catch-up rule's three forms are not all exercised"
    assert any("consumer_registry" in c for c in accepts), \
        "no Consumer registry the Snapshot's tuples agree with"
    assert any("consumer_registry" in c
               and any(t[1] not in {h[1] for h in c["consumer_registry"]["entries"]}
                       and t[3] > c["consumer_registry"]["verified_head"]
                       for t in c["state"]["state"]["entries"])
               for c in accepts), \
        "no accepted Snapshot carries a key admitted above the Consumer's verified head"
    assert any(any(t[1] == genesis["key_id"] and t[4] is not None and t[6] is not None
                   for t in c["state"]["state"]["entries"]) for c in accepts), \
        "no accepted Snapshot carries the removed genesis key's tuple with its removing act"
    assert any(c["adopted_head"] > c["epoch_number"] for c in accepts), \
        "no accepted Snapshot is read at a head above its own Epoch"
    assert self_consistent >= 3, \
        "the family must carry forgeries that verify against themselves"

    # WIST-3 §7: of two removals of one key accepted in one Epoch the tuple
    # carries the one at the lower Entry index; rules 1 through 5 read both, and
    # the state_digest a replaying Consumer rebuilds is what separates them.
    tie = v["removal_tie_break"]
    epoch = history["epochs"][tie["epoch_number"]]
    removals = [index for index, e in enumerate(epoch["entries"])
                if e["body"]["update"]["action"] == "aggregator_key_remove"
                and e["body"]["update"]["details"]["key_id"] == tie["key_id"]]
    codes = replay["dispositions"][tie["epoch_number"]]
    assert len(removals) == 2 and all(codes[index] is None for index in removals), \
        "the Epoch does not accept two removals of the key"
    assert tie["accepted_entry_index"] == min(removals), "the tie-break names the wrong Entry"
    carried = next(t[6] for t in replay["states"][tie["epoch_number"]] if t[1] == tie["key_id"])
    assert carried == epoch["entries"][min(removals)]["body"], \
        "the replay's tuple does not carry the removal at the lower Entry index"
    accepted, alternate = by_name[tie["accepted_case"]], by_name[tie["alternate_case"]]
    assert accepted["state_digest"] == tie["accepted_state_digest"] \
        and alternate["state_digest"] == tie["alternate_state_digest"], \
        "the tie-break restates a digest neither case carries"
    assert accepted["state_digest"] != alternate["state_digest"], \
        "the two removals leave one state_digest, so the tie-break decides nothing recomputable"
    accepted_updates = {}
    for epoch_, codes in zip(history["epochs"], replay["dispositions"]):
        if epoch_["epoch_number"] <= tie["epoch_number"] and epoch_["checkpoint"] is not None:
            for entry, code in zip(epoch_["entries"], codes):
                if code is None:
                    accepted_updates.setdefault(_registry_update_id(entry["body"]["update"]), epoch_["epoch_number"])
    rebuilt = "sha256:" + hashlib.sha256(b"".join(sorted(
        rfc8785.dumps(t) for t in replay["states"][tie["epoch_number"]]
        + [["registry_update", i, h] for i, h in accepted_updates.items()]))).hexdigest()
    assert rebuilt == tie["accepted_state_digest"], \
        "a replaying Consumer's own rebuild is not the accepted case's state_digest"
    assert accepted["expected"] == alternate["expected"] == "accept", \
        "§7's rules read the two tuples alike; only the digest separates them"

    # WIST-3 §5: the Mirror list verifies at the adopted head, and one that does
    # not verify has no error code.
    for case in v["mirror_cases"]:
        mirrors_schema.validate(case["mirrors"])
        assert case["log"] == history["name"] and case["error"] is None, \
            f"{case['name']}: §5 gives an unverifiable Mirror list no error code"
        head = case["adopted_head"]
        authenticated = False
        if head is not None:
            tuples = replay["states"][head]
            public = {t[1]: t[2] for t in tuples}
            signer = case["mirrors"]["sig"]["key_id"]
            authenticated = (signer in _keys_valid_at(tuples, genesis["key_id"], head)
                             and signer in public
                             and _envelope_verifies(b64u_decode(public[signer]),
                                                    case["mirrors"], "mirrors"))
        assert authenticated == case["authenticated"], case["name"]
    assert {c["authenticated"] for c in v["mirror_cases"]} == {True, False} \
        and any(c["adopted_head"] is None for c in v["mirror_cases"]), \
        "the Mirror cases do not cover a verifying list, a since-removed signer and no head"

    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    for marker in (
            "a Consumer holding the Anchor authenticates them from its genesis key before "
            "it uses any tuple",
            "A Consumer verifies it under the keys valid at the height of the Checkpoint it "
            "adopts (§8)",
            "Every non-`null` adding act passes WIST-4 §5.1's field validation",
            "The removing act is `null` exactly when the removed height is `null`.",
            "unless the tuples agree with its own registry up to its verified head *V*",
            "every tuple for a key the registry does not hold has an added height greater "
            "than *V*",
            "Of two removals of one key accepted in one Epoch (§3.4), the tuple carries the "
            "one at the lower Entry index",
            "which of two removals accepted in one Epoch a tuple carries, are assertions of "
            "the state file's signer that these rules do not test",
            "A Consumer catching up through a Snapshot performs cold start's steps against "
            "it, applying §7's additional rule for a Consumer that holds key state.",
            "has no error code, and its entries are location hints integrity never depends on"):
        assert marker in prose, f"missing normative sentence: {marker!r}"
check("vectors:wist3-snapshot-keys", _wist3_snapshot_keys)


_SNAPSHOT_MANIFEST_SCHEMA = Draft202012Validator(
    json.loads((ROOT / "schemas/snapshot-manifest.schema.json").read_text()))


def _without_nulls(value):
    if isinstance(value, dict):
        return {k: _without_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_without_nulls(v) for v in value]
    return value


def _index_case_outcome(case):
    """WIST-3 §8 step 2 on the case's first entry, and §6's listing order."""
    entry = case["index"]["index"]["snapshots"][0]
    chosen = case["manifests"][entry["manifest_url"]]
    schema_errors = [e.message for e in _SNAPSHOT_MANIFEST_SCHEMA.iter_errors(chosen)]
    manifest = chosen["manifest"]
    disagrees = [] if schema_errors else [
        f for f in ("snapshot_date", "tree_size", "content_digest") if entry[f] != manifest[f]]
    keys = []
    for e in case["index"]["index"]["snapshots"]:
        m = case["manifests"][e["manifest_url"]]["manifest"]
        assert e["manifest_url"] == _snapshot_directory(m) + "manifest.json", \
            "an entry does not name its manifest's §6 directory"
        keys.append((e["snapshot_date"], m["epoch_number"]))
    urls = [e["manifest_url"] for e in case["index"]["index"]["snapshots"]]
    assert len(set(urls)) == len(urls), "two entries name one directory"
    response = ("re-fetch the Snapshot, from another Mirror if needed" if schema_errors
                else "re-fetch the index" if disagrees else None)
    return {"expected": "WIST3-E04" if response else "accept", "disagrees": disagrees,
            "schema_errors": schema_errors, "response": response,
            "index_ordered": keys == sorted(keys, reverse=True)}


def _wist3_snapshot_index():
    """WIST-3 §6 and §8 step 2: immutable per-Snapshot directories, the index's
    listing order and the entry-versus-manifest check, each recomputed."""
    v = json.loads((ROOT / "vectors" / "wist3" / "snapshot-index.json").read_text())
    index_schema = Draft202012Validator(json.loads((ROOT / "schemas/snapshot-index.schema.json").read_text()))
    genesis = json.loads((ROOT / "examples/log-anchor.json").read_text())["anchor"]["genesis_key"]
    pub = b64u_decode(genesis["public_key"])
    _published_files_hash(v, [m for c in v["cases"] for m in c["manifests"].values()], "snapshot-index")
    state_octets = rfc8785.dumps(json.loads((ROOT / "examples/snapshot-state.json").read_text()))
    assert all(m["manifest"]["state"]["sha256"] == hashlib.sha256(state_octets).hexdigest()
               and m["manifest"]["state"]["bytes"] == len(state_octets)
               for c in v["cases"] for m in c["manifests"].values()), \
        "a manifest does not hash the example state file"
    seen = set()
    for case in v["cases"]:
        where = case["name"]
        assert where not in seen, f"two cases named {where!r}"
        seen.add(where)
        index_schema.validate(case["index"])
        assert _envelope_verifies(pub, case["index"], "index"), f"{where}: the index signature"
        chosen_url = case["index"]["index"]["snapshots"][0]["manifest_url"]
        for url, manifest in case["manifests"].items():
            if url != chosen_url:
                _SNAPSHOT_MANIFEST_SCHEMA.validate(manifest)
            assert _envelope_verifies(pub, manifest, "manifest"), f"{where}: the manifest signature at {url}"
            assert all(not f["path"].startswith("/") for f in manifest["manifest"]["files"]) \
                and not manifest["manifest"]["state"]["path"].startswith("/"), \
                f"{where}: a listed path is not relative to the manifest"
        outcome = _index_case_outcome(case)
        assert outcome["expected"] == case["expected"], f"{where}: {outcome}, vector says {case['expected']}"
        assert outcome["index_ordered"] == case["index_ordered"], f"{where}: listing order"
        assert outcome["response"] == case.get("response"), f"{where}: the response"
    accepted = next(c for c in v["cases"] if c["expected"] == "accept" and c["index_ordered"])
    null_cases = [c for c in v["cases"] if _index_case_outcome(c)["schema_errors"]]
    assert len(null_cases) == 2, "the family lacks its two null-member manifests"
    for case in null_cases:
        url = case["index"]["index"]["snapshots"][0]["manifest_url"]
        served, plain = case["manifests"][url]["manifest"], accepted["manifests"][url]["manifest"]
        assert served != plain and _without_nulls(served) == plain, \
            f"{case['name']}: differs from the accepted manifest by more than a null member"
        assert case["index"]["index"]["snapshots"] == accepted["index"]["index"]["snapshots"] \
            and {u: m for u, m in case["manifests"].items() if u != url} == \
            {u: m for u, m in accepted["manifests"].items() if u != url}, \
            f"{case['name']}: differs from the accepted case outside the chosen manifest"
    outcomes = {(c["expected"], c["index_ordered"]) for c in v["cases"]}
    assert {("accept", True), ("accept", False), ("WIST3-E04", True)} <= outcomes, \
        "the family does not separate the Consumer's outcome from the Aggregator's order"
    first = v["cases"][0]["index"]["index"]["snapshots"]
    assert first[0]["snapshot_date"] == first[1]["snapshot_date"] \
        and first[0]["manifest_url"] != first[1]["manifest_url"], \
        "no case serves two Snapshots of one date under two directories"

check("vectors:wist3-snapshot-index", _wist3_snapshot_index)


def _wist3_snapshot_index_twin():
    """Mutation twin: an accepted entry given the manifest's tree_size plus one
    must come out WIST3-E04, and a reversed same-date listing out of order."""
    v = json.loads((ROOT / "vectors" / "wist3" / "snapshot-index.json").read_text())
    case = json.loads(json.dumps(next(c for c in v["cases"] if c["expected"] == "accept" and c["index_ordered"])))
    case["index"]["index"]["snapshots"][0]["tree_size"] += 1
    assert _index_case_outcome(case)["expected"] == "WIST3-E04", "a moved tree_size still agreed"
    case = json.loads(json.dumps(next(c for c in v["cases"] if c["expected"] == "accept" and c["index_ordered"])))
    case["index"]["index"]["snapshots"].reverse()
    assert not _index_case_outcome(case)["index_ordered"], "a reversed same-date listing read as ordered"
    for case in (c for c in v["cases"] if c.get("response") == "re-fetch the Snapshot, from another Mirror if needed"):
        url = case["index"]["index"]["snapshots"][0]["manifest_url"]
        lenient = json.loads(json.dumps(case))
        lenient["manifests"][url] = _without_nulls(lenient["manifests"][url])
        assert _index_case_outcome(lenient)["expected"] == "accept", \
            f"{case['name']}: a reader taking null as absent does not accept it"

check("negative:wist3-snapshot-index", _wist3_snapshot_index_twin)


def _wist3_snapshot_keys_twin():
    """Mutation twins: each reading §7 and §3.4 fix, flipped, must move an
    outcome the family states, and a damaged signature must be caught."""
    v = _snapshot_keys_vector()
    history = v["history"]
    anchor = history["anchor"]["anchor"]
    validator = Draft202012Validator(
        json.loads((ROOT / "schemas/registry-update.schema.json").read_text()))

    def outcomes(**variant):
        return [_snapshot_case_outcome(c, history, anchor, validator, **variant)
                for c in v["cases"]]

    control = outcomes()
    for variant in ({"act_height": "own height"}, {"genesis_binding": False},
                    {"unsealed_at": "snapshot epoch"}, {"catch_up": False},
                    {"surplus": False}):
        assert outcomes(**variant) != control, \
            f"flipping {variant} changed no outcome the family states"

    # Each flip, at the case it is supposed to decide.
    forged = next(c for c in v["cases"]
                  if c.get("self_consistent") and c["violations"]["tuple_rules"] == [5])
    assert not _snapshot_case_outcome(forged, history, anchor, validator,
                                      act_height="own height")["tuple_rules"], \
        "reading a key act at its own height did not admit the self-signed addition"
    restated = next(c for c in v["cases"]
                    if c.get("self_consistent") and c["violations"]["tuple_rules"] == [2]
                    and len([t for t in c["state"]["state"]["entries"]
                             if t[0] == "aggregator_key" and t[5] is None]) == 1)
    assert not _snapshot_case_outcome(restated, history, anchor, validator,
                                      genesis_binding=False)["tuple_rules"], \
        "dropping rule 2's comparison against the Anchor did not admit the restated genesis key"
    for document in UNSEALED_DOCUMENTS:
        removed = next(c for c in v["cases"]
                       if c["expected"] != "accept"
                       and c["violations"]["unsealed_documents"] == [document]
                       and c["adopted_head"] > c["epoch_number"])
        assert not _snapshot_case_outcome(removed, history, anchor, validator,
                                          unsealed_at="snapshot epoch")["unsealed_documents"], \
            f"judging the {document} at the Snapshot's Epoch did not admit the removed key"
    for case in v["cases"]:
        if case["expected"] != "accept" and case["violations"]["catch_up"]:
            assert not _snapshot_case_outcome(case, history, anchor, validator,
                                              catch_up=False)["catch_up"], case["name"]
            assert not case["violations"]["tuple_rules"] \
                and not case["violations"]["unsealed_documents"], \
                f"{case['name']}: the catch-up rule is not what rejects this Snapshot"
    surplus = next(c for c in v["cases"]
                   if c["expected"] != "accept"
                   and [conflict["reason"] for conflict in c["violations"]["catch_up"]] == ["unknown"])
    assert not _snapshot_case_outcome(surplus, history, anchor, validator,
                                      surplus=False)["catch_up"], \
        "dropping the clause on tuples the registry does not hold admitted the surplus tuple"
    agreeing = next(c for c in v["cases"]
                    if c["expected"] == "accept" and "consumer_registry" in c)
    for held in agreeing["consumer_registry"]["entries"]:
        dropped = copy.deepcopy(agreeing)
        dropped["consumer_registry"]["entries"] = [
            t for t in dropped["consumer_registry"]["entries"] if t[1] != held[1]]
        assert _snapshot_case_outcome(dropped, history, anchor, validator)["catch_up"] \
            == [{"key_id": held[1], "reason": "unknown"}], \
            f"a registry lacking {held[1]} did not make its tuple a surplus one"

    # A signature the vector states as verifying must be the reason it does.
    for document in UNSEALED_DOCUMENTS:
        case = copy.deepcopy(next(c for c in v["cases"] if c["expected"] == "accept"))
        raw = bytearray(b64u_decode(case[document]["sig"]["value"]))
        raw[0] ^= 0xFF
        case[document]["sig"]["value"] = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
        assert _snapshot_case_outcome(case, history, anchor, validator)["unsealed_documents"] \
            == [document], f"a damaged {document} signature was not caught"

    # An accepted tuple set is accepted because of what it carries: dropping any
    # one tuple's adding act, or moving any height, must reject it.
    case = next(c for c in v["cases"]
                if c["expected"] == "accept" and "consumer_registry" not in c
                and len(c["state"]["state"]["entries"]) > 2)
    for position, replacement in ((5, None), (3, 99), (4, 0), (6, None)):
        for index in range(len(case["state"]["state"]["entries"])):
            mutated = copy.deepcopy(case)
            tuple_ = mutated["state"]["state"]["entries"][index]
            if tuple_[0] != "aggregator_key" or tuple_[position] == replacement:
                continue
            tuple_[position] = replacement
            assert _snapshot_case_outcome(mutated, history, anchor, validator)["tuple_rules"], \
                f"moving member {position} of tuple {index} left the tuples authenticating"
check("negative:wist3-snapshot-keys", _wist3_snapshot_keys_twin)


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
    in Canonical Host form; a second copy of the reading, structured as a map.
    Lines end at U+000A alone and a rule at the first of the five whitespace
    characters; a rule with an empty label or a character Canonical Host
    processing rejects (anything but letters, digits and hyphens here) is ignored."""
    rules = {}
    for line in text.split("\n"):
        token = re.match("[^\t\x0b\x0c\r ]*", line).group(0)
        if token == "" or token.startswith("//"):
            continue
        exception = token[0] == "!"
        labels = token[1 if exception else 0:].split(".")
        if "" in labels or any(not (c.isalnum() or c == "-") for l in labels if l != "*" for c in l):
            continue
        rules[".".join(_psl_host_label(l) for l in labels)] = exception
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
    lines = lists["lines"]["text"]
    assert set(_psl_rules(lines)) == {"com", "net", "org"} | {
        name + ".example.com" for name in ("space", "tab", "vertical-tab", "form-feed", "carriage-return")}
    trimmed = {line.strip().split()[0] for line in lines.splitlines() if line.strip()}
    assert {"leading-space.example.com", "no-break-space.example.com", "next-line.example.org",
            "file-separator.example.com"} <= trimmed, "the lines no longer tell a trimming reader apart"
    assert sum(c["list"] == "lines" for c in v["domain_cases"]) >= 14
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
                                     for e in case["entries"] if _declaration_host_format(e["domain"]))
        assert all(e["type"] in ("publisher_catalog", "publisher_item", "label", "dispute")
                   for e in case["entries"])
        expected = "WIST3-E03" if max(counts.values()) > case["domain_epoch_entries_max"] else None
        assert expected == case["expected"], case["label"]
    assert {c["expected"] for c in v["capacity_cases"]} == {None, "WIST3-E03"}
    assert {e["type"] for c in v["capacity_cases"] for e in c["entries"]} == \
        {"publisher_catalog", "publisher_item", "label", "dispute"}
    assert any(not _declaration_host_format(e["domain"]) for c in v["capacity_cases"] for e in c["entries"]
               if e["type"] == "dispute"), "no dispute of a disputant that is not a Canonical Host"
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
            if h <= state["tree_size"] and (pinned is None or pinned[1] != n):
                pinned = (h, n)
        updates = [["registry_update", _registry_update_id(json.loads(c["envelope_json"])["update"]), c["height"]]
                   for c in v["act_cases"] if c["code"] is None and c["height"] <= state["tree_size"]]
        assert state["entries"] == [["suffix_list", lists[pinned[1]]["sha256"], pinned[0]]] + updates, state
    assert any(h > s["entries"][0][2] for h, _ in accepted for s in v["state_tuples"]
               if h <= s["tree_size"]), "no repeated pin leaves the tuple's height alone"
    schema = Draft202012Validator(json.loads((ROOT / "schemas/snapshot-state.schema.json").read_text()))
    envelope = json.loads((ROOT / "examples" / "snapshot-state.json").read_text())
    envelope["state"]["entries"] = v["state_tuples"][0]["entries"]
    schema.validate(envelope)
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-governance.md").read_text())
    for marker in ("in force from the Epoch after its sealing Epoch",
                   "the Registrable Domain is the host itself",
                   "every Canonical Host is its own Registrable Domain",
                   "An Aggregator MUST NOT seal an act naming a file it does not hold",
                   "it stops at the act's Epoch (`WIST3-E01`)"):
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
        if case["object"] in ("declaration", "label_feed", "page", "mirrors", "change_list"):
            expected = 1048576
        elif case["object"] == "catalog":
            expected = 16384
        elif case["object"] in ("label", "dispute"):
            expected = 16384 + 2 * p["url_cap_bytes"]
        else:
            assert case["object"] == "payload"
            expected = p["extract_cap_bytes"] + p["links_cap_bytes"] + p["summary_cap_bytes"] + 4096
        assert case["bound"] == expected, case["label"]
    assert len({c["bound"] for c in v["object_bounds"] if c["object"] == "label"}) == 2, "one parameter map only"
    assert {c["object"] for c in v["object_bounds"]} == {
        "declaration", "catalog", "change_list", "label_feed", "page", "mirrors", "label", "dispute", "payload"}
    for case in v["label_feed_cases"]:
        if case["declaration"] == "stopped":
            assert case["collections"] == []
            expected = (False, False)
        elif "suspended" in case["collections"]:
            expected = (False, True)
        elif case["budget_remaining"] == 0:
            expected = (False, False)
        else:
            expected = (True, case["budget_remaining"] < case["label_feed_pages"])
        assert (case["label_feed_pulled"], case["suspended"]) == expected, case["label"]
    assert {(c["label_feed_pulled"], c["suspended"]) for c in v["label_feed_cases"]} == \
        {(False, False), (False, True), (True, True), (True, False)}
    assert any(c["label_feed_pulled"] and "accepted" not in c["collections"] and "idempotent" not in c["collections"]
               for c in v["label_feed_cases"]), "no Label Feed pulled after Collections that all failed"
    resolutions = set()
    for case in v["resolution_cases"]:
        declaration, collections = case["declaration"], case["collections"]
        assert declaration in ("discovered", "accepted", "stopped", "stopped_first_contact"), case["label"]
        assert not collections or declaration not in ("stopped", "stopped_first_contact"), case["label"]
        recorded = []
        for collection in collections:
            outcome = collection["catalog"]
            codes = collection.get("codes", [])
            if outcome == "fetch_failed":
                assert codes == ["WIST2-E01"], case["label"]
            elif collection.get("chain") == "discarded":
                assert codes[0] == "WIST2-E08" and outcome in ("refused", "accepted"), case["label"]
                assert codes[1:] == (["WIST2-E07"] if outcome == "refused" else []), case["label"]
            elif outcome == "refused":
                assert len(codes) == 1 and codes[0] in ("WIST2-E04", "WIST2-E05", "WIST2-E07"), case["label"]
            else:
                assert outcome in ("accepted", "idempotent", "suspended") and not codes, case["label"]
            if outcome not in ("accepted", "idempotent"):
                assert collection.get("items_admitted", 0) == 0, case["label"]
            recorded += codes
        assert case["codes_recorded"] == recorded, case["label"]
        assert case["suspended"] == any(c["catalog"] == "suspended" for c in collections), case["label"]
        if declaration == "stopped_first_contact":
            expected = "WIST2-E04"
        elif declaration == "stopped":
            expected = "WIST2-E01"
        elif (declaration == "discovered" or case["labels_admitted"]
              or any(c["catalog"] == "accepted" or c.get("items_admitted") for c in collections)):
            expected = None
        elif case["suspended"]:
            expected = None
        else:
            expected = "WIST2-E02"
        assert case["resolution"] == expected, case["label"]
        assert case["noise"] == (expected in ("WIST2-E02", "WIST2-E04")), case["label"]
        resolutions.add(expected)
    assert resolutions == {None, "WIST2-E01", "WIST2-E02", "WIST2-E04"}
    by_label = {c["label"]: c for c in v["resolution_cases"]}
    for alone, beside in (("a Catalog refused with WIST2-E04 alone", "a Catalog refused with WIST2-E04, another "
                           "Catalog accepted"),
                          ("a catalog.json that cannot be fetched", "a catalog.json that cannot be fetched, another "
                           "Catalog accepted"),
                          ("a discarded chain followed by a refused walk", "a discarded chain followed by a refused "
                           "walk, a Label admitted")):
        alone, beside = alone.replace("-", " "), beside.replace("-", " ")
        assert by_label[alone]["noise"] and not by_label[beside]["noise"], alone
    outcomes = set()
    for case in v["work_cases"]:
        budget, work_bytes, objects = case["budget_remaining"], case["work_bytes_remaining"], case["work_objects_remaining"]
        size, own = case["object_bytes"], case["object_bound"]
        if budget == 0 or work_bytes == 0 or objects == 0:
            expected = ("suspended", 0)
        else:
            allowance = min(budget, work_bytes)
            if size <= allowance and size <= own:
                expected = ("fetched", size)
            elif allowance <= own and size > allowance:
                expected = ("suspended", allowance)
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
                   "16 384 + 2 × `url_cap_bytes` octets of a Label or dispute file",
                   "16 384 octets of `catalog.json`",
                   "`change_list_cap_bytes` octets of a change list",
                   "the Declaration accepted at the instant the request is issued",
                   "a redirect MUST stay on the requested Canonical Host",
                   "An Aggregator MAY suspend a walk below the budget under a per-pull limit of its own",
                   "The Label Feed is pulled once the pull of every Collection has ended: a pull that stops at its "
                   "Declaration (§5.1) or suspends pulls no Label Feed in that pull",
                   "waits for the next pull without suspending the completed Collection pulls",
                   "no Catalog is accepted and no Item, Label or dispute is admitted resolves to `WIST2-E02` (§4), "
                   "unless it stopped at its Declaration outside first contact (§5.1 step 0) or suspended under the "
                   "ingest budget or a per-pull limit (§5.2): neither is noise",
                   "A first-contact pull stopped at its Declaration is `WIST2-E04` and counts as noise",
                   "a discarded chain adds nothing of its own",
                   "A fetch that fails, an answer above §8's bound included, is `WIST2-E01`",
                   "or does not carry the listed ID fails the same way",
                   "the octets read are debited and the walk suspends there",
                   "As an object's octets are read, the bound met first decides"):
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

def _label_disposition(doc, declaration, validator, url_cap_bytes, terms, clock, clock_skew_seconds):
    """WIST-2 §3.3 over one Label Envelope: accepted, fields, clock, self,
    signature or binding, in the order WIST-2 §3.3 and WIST-1 §7 apply them;
    `clock` is the Log instant `asserted_at` is checked against (WIST-1 §3.4)."""
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
        host = _url_host(subject)
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
        expires = publisher_instant(label["expires_at"]) if "expires_at" in label else None
    except ValueError:
        return "fields"
    if asserted > log_seconds(clock) + clock_skew_seconds:
        return "clock"
    if expires is not None and expires <= asserted:
        return "fields"
    if "delta" in label and not subject.startswith("https://"):
        return "fields"
    if host == publisher["domain"] or host in publisher.get("subdomain_scope", []):
        return "self"
    candidates = [k for k in publisher["keys"] if k["kid"] == doc["sig"]["key_id"]
                  and _usable_point(k["x"]) and _in_window(k, asserted)]
    if not candidates:
        return "binding"
    if not any(_ed25519_profile_verdict(canonical_b64u_decode(k["x"]),
                                        canonical_b64u_decode(doc["sig"]["value"]),
                                        rfc8785.dumps(label))[0] for k in candidates):
        return "signature"
    return "accepted"


def _usable_point(encoded):
    try:
        point = ed25519_curve.string_to_point(canonical_b64u_decode(encoded))
    except ed25519_curve.InvalidProof:
        return False
    return not ed25519_curve._is_identity(ed25519_curve._mul(8, point))

def _materialized_binding(case, any_record=False):
    live = {r["publisher"]: r["item"] for r in case["records"] if not r["withdrawn"]}
    if any_record:
        return case["materialized"], case["delta"] in live.values()
    chosen = _materialization_preference(_url_host(case["subject"]), case["host_declared"], list(live))
    return chosen, chosen is not None and live[chosen] == case["delta"]

def _label_vectors():
    """WIST-2 §3.3 and WIST-4 §6: every case's disposition is recomputed over
    the example Declaration, the accepted Label IDs reproduce, and the
    current-Label rule leaves the state tuples the vector names."""
    v = _label_vector()
    validator = Draft202012Validator(json.loads((ROOT / "schemas/label.schema.json").read_text()))
    terms = _wist_label_terms()
    codes = {"accepted": None, "fields": "WIST2-E06", "clock": "WIST2-E06", "self": "WIST2-E06",
             "signature": "WIST1-E01", "binding": "WIST1-E02"}
    bound = log_seconds(v["clock"]) + v["clock_skew_seconds"]
    outcomes = set()
    publisher_schema = Draft202012Validator(json.loads((ROOT / "schemas/publisher.schema.json").read_text()))
    for declaration in v["declarations"].values():
        publisher_schema.validate(declaration)
        assert _declaration_binding_result(None, declaration) == "initial"
    for case in v["cases"]:
        declaration = v["declarations"][case["declaration"]] if "declaration" in case else v["declaration"]
        envelope = case["envelope"]
        if "envelope_json" in case:
            envelope = item_rules.strict_loads(case["envelope_json"].encode("utf-8"))
            assert envelope == case["envelope"] and case["envelope_json"] != json.dumps(case["envelope"])
        got = _label_disposition(envelope, declaration, validator, v["url_cap_bytes"], terms,
                                 v["clock"], v["clock_skew_seconds"])
        assert got == case["expected"], (case["name"], got, case["expected"])
        assert case["code"] == codes[case["expected"]], case["name"]
        label_id = "sha256:" + hashlib.sha256(rfc8785.dumps(case["envelope"]["label"])).hexdigest()
        assert case["label_id"] == (label_id if case["expected"] == "accepted" else None), case["name"]
        outcomes.add(case["expected"])
    assert outcomes == set(codes)
    by_name = {c["name"]: c for c in v["cases"]}
    for spelled, plain in (("value with a zero fraction", "valid Label with a value"),
                           ("value in exponent spelling", "valid Label with a value"),
                           ("value of negative zero", "value at the floor"),
                           ("value at the ceiling with a zero fraction", "value at the ceiling")):
        assert by_name[spelled]["label_id"] == by_name[plain]["label_id"] is not None, spelled
        assert json.dumps(by_name[spelled]["envelope"]["label"]["value"]) != \
            json.dumps(by_name[plain]["envelope"]["label"]["value"]), spelled
    assert "7.5e5" in by_name["value in exponent spelling"]["envelope_json"]
    at_bound = [c for c in v["cases"] if c["expected"] == "accepted"
                and publisher_instant(c["envelope"]["label"]["asserted_at"]) == bound]
    assert len({c["envelope"]["label"]["asserted_at"] for c in at_bound}) >= 2, "no inclusive bound spellings"
    assert any(c["expected"] == "clock" and publisher_instant(c["envelope"]["label"]["asserted_at"]) - bound < 1
               for c in v["cases"]), "no fractional excess"
    example = json.loads((ROOT / "examples" / "label.json").read_text())
    assert _label_disposition(example, v["declaration"], validator, v["url_cap_bytes"], terms,
                              v["clock"], v["clock_skew_seconds"]) == "accepted"
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
            inner["asserted_at"], inner.get("expires_at"), inner.get("delta"), ranked["label_id"],
            ranked["height"]]
        assert case["state_tuple"] == expected, case["name"]
        if expected is not None:
            envelope["state"]["entries"] = [expected]
            state.validate(envelope)
    assert any(c["state_tuple"] is None and not c["sealed"][0]["label"].get("retracted")
               and "expires_at" in c["sealed"][0]["label"] for c in v["current_cases"]), "no expiry drops a tuple"
    assert any(c["state_tuple"] is not None and c["state_tuple"][7] is not None for c in v["current_cases"])
    for case in v["binding_cases"]:
        applies = case["record_item"] is not None and (case["delta"] is None or case["delta"] == case["record_item"])
        assert applies == case["applies"], case["name"]
    assert {c["applies"] for c in v["binding_cases"]} == {True, False}
    for case in v["materialized_binding_cases"]:
        chosen, applies = _materialized_binding(case)
        assert (chosen, applies) == (case["materialized"], case["applies"]), case["name"]
    assert any(c["applies"] is False and any(r["item"] == c["delta"] and not r["withdrawn"] for r in c["records"])
               for c in v["materialized_binding_cases"]), "no Label bound to a record that is not materialized"
    outcomes_expiry = {c["expected"] for c in v["cases"] if "expires_at" in c["envelope"]["label"]}
    assert outcomes_expiry == {"accepted", "fields"}, "expiry cases do not cover both dispositions"
    assert {c["expected"] for c in v["cases"] if "delta" in c["envelope"]["label"]} == {"accepted", "fields"}
    assert any(c["state_tuple"] is None for c in v["current_cases"])
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-2-site-publication.md").read_text())
    assert "the sealed Label with the greatest `asserted_at`, and among equal instants the one later in Log order" in prose
    assert "it is rejected under `WIST2-E06` and never sealed" in prose
    assert ("a Publisher timestamp under WIST-1 §3.4's profile, bound above by the clock rule WIST-1 §3.4 gives "
            "a Catalog's `generated_at`") in prose
    assert "an `asserted_at` beyond the clock allowance" in prose
    assert "applies nothing at an Epoch whose `sealed_at` is at or after that instant" in prose
    assert ("the Label applies only while the subject URL's materialized record (WIST-3 §7, **One URL, one "
            "Publisher**) carries that Item") in prose
    assert ("by the binding check WIST-1 §5.1 gives a Catalog, with `asserted_at` in the place of "
            "`generated_at` for key validity, over `keys` alone") in prose
    windowed = [c for c in v["cases"] if c["expected"] in ("accepted", "binding")
                and "nbf" in c["name"]]
    assert {c["expected"] for c in windowed} == {"accepted", "binding"}, "no key window boundary"
    assert any(c.get("declaration") and c["expected"] == "binding" for c in v["cases"]), \
        "no Collection key refused"
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
    clock = (v["clock"], v["clock_skew_seconds"])
    assert _label_disposition(doc, widened, validator, v["url_cap_bytes"], terms, *clock) == "signature"
    foreign = next(c for c in v["cases"] if c["name"] == "name under a Canonical Host prefix")
    assert _label_disposition(foreign["envelope"], v["declaration"], validator, v["url_cap_bytes"], set(), *clock) == "accepted"
    assert _label_disposition(foreign["envelope"], v["declaration"], validator, 20, terms, *clock) == "fields"
    at_bound = next(c for c in v["cases"] if c["name"] == "asserted_at at the allowance bound")
    assert _label_disposition(at_bound["envelope"], v["declaration"], validator, v["url_cap_bytes"], terms,
                              v["clock"], v["clock_skew_seconds"] - 1) == "clock"
    beyond = next(c for c in v["cases"] if c["name"] == "asserted_at a fraction beyond the allowance")
    assert _label_disposition(beyond["envelope"], v["declaration"], validator, v["url_cap_bytes"], terms,
                              v["clock"], v["clock_skew_seconds"] + 1) == "accepted"
    assert any(_materialized_binding(c, any_record=True)[1] != c["applies"]
               for c in v["materialized_binding_cases"]), "a Label read against any record of its URL passes"
    tie = next(c for c in v["current_cases"] if c["name"] == "equal instants break by Epoch number")
    reversed_order = min(tie["sealed"], key=lambda s: (s["height"], s["entry_index"]))
    assert reversed_order["label_id"] != tie["current"]
check("negative:wist2-labels", _label_vectors_twin)
check("vectors:wist2-declaration-refresh", _declaration_refresh_vectors)


def _dispute_vector():
    return json.loads((ROOT / "vectors/wist2/disputes.json").read_text())

def _dispute_disposition(doc, declaration, validator, sealed, clock, clock_skew_seconds):
    """WIST-2 §3.3 over one Dispute Envelope: accepted, fields, clock,
    unsealed, authority, signature or binding, in the order the section
    applies them; `clock` is the Log instant `asserted_at` is checked
    against, as a Label's is (WIST-1 §3.4)."""
    import link_extraction
    if not validator.is_valid(doc):
        return "fields"
    dispute = doc["dispute"]
    if dispute["height"] > 9007199254740991:
        return "fields"
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
        asserted = publisher_instant(dispute["asserted_at"])
    except ValueError:
        return "fields"
    if asserted > log_seconds(clock) + clock_skew_seconds:
        return "clock"
    label = sealed.get(dispute["label"])
    if label is None:
        return "unsealed"
    subject = label["subject"]
    host = _url_host(subject) if subject.startswith("https://") else subject
    if host != publisher["domain"] and host not in publisher.get("subdomain_scope", []):
        return "authority"
    key = next((k for k in publisher["keys"] if k["kid"] == doc["sig"]["key_id"]), None)
    if key is None:
        return "binding"
    if not _ed25519_profile_verdict(canonical_b64u_decode(key["x"]),
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
    codes = {"accepted": None, "fields": "WIST2-E06", "clock": "WIST2-E06", "unsealed": "WIST2-E06",
             "authority": "WIST2-E06", "signature": "WIST1-E01", "binding": "WIST1-E02"}
    bound = log_seconds(v["clock"]) + v["clock_skew_seconds"]
    outcomes = set()
    for case in v["cases"]:
        envelope = case["envelope"]
        if "envelope_json" in case:
            envelope = item_rules.strict_loads(case["envelope_json"].encode("utf-8"))
            assert envelope == case["envelope"] and case["envelope_json"] != json.dumps(case["envelope"])
        got = _dispute_disposition(envelope, case["declaration"], validator, sealed,
                                   v["clock"], v["clock_skew_seconds"])
        assert got == case["expected"], (case["name"], got, case["expected"])
        assert case["code"] == codes[case["expected"]], case["name"]
        dispute_id = "sha256:" + hashlib.sha256(rfc8785.dumps(case["envelope"]["dispute"])).hexdigest()
        assert case["dispute_id"] == (dispute_id if case["expected"] == "accepted" else None), case["name"]
        outcomes.add(case["expected"])
    assert outcomes == set(codes)
    assert any(c["expected"] == "accepted" and publisher_instant(c["envelope"]["dispute"]["asserted_at"]) == bound
               for c in v["cases"]), "no inclusive bound"
    assert any(c["expected"] == "clock" and publisher_instant(c["envelope"]["dispute"]["asserted_at"]) - bound < 1
               for c in v["cases"]), "no fractional excess"
    assert any(c["expected"] == "accepted" and c["envelope"]["dispute"]["log"] != "log.example" for c in v["cases"]), \
        "no accepted dispute cites another Log"
    by_name = {c["name"]: c for c in v["cases"]}
    plain = by_name["dispute citing another Log"]
    for spelled in ("height with a zero fraction", "height in exponent spelling"):
        assert by_name[spelled]["dispute_id"] == plain["dispute_id"] is not None, spelled
        assert json.dumps(by_name[spelled]["envelope"]["dispute"]["height"]) != \
            json.dumps(plain["envelope"]["dispute"]["height"]), spelled
    assert "7e0" in by_name["height in exponent spelling"]["envelope_json"]
    assert by_name["height at the safe-integer bound"]["expected"] == "accepted" \
        and by_name["height above the safe-integer bound"]["expected"] == "fields"
    ported = {c["expected"] for c in v["cases"]
              if re.match(r"https://[^/]+:\d", sealed.get(c["envelope"]["dispute"].get("label"), {}).get("subject", ""))}
    assert ported == {"accepted", "authority"}, "no disputed subject carries a port on both sides of the scope rule"
    example = json.loads((ROOT / "examples" / "dispute.json").read_text())
    example_sealed = {example["dispute"]["label"]: {"subject": "https://example.com/blog/post-1"}}
    publisher = json.loads((ROOT / "examples" / "publisher.json").read_text())
    assert _dispute_disposition(example, publisher, validator, example_sealed,
                                v["clock"], v["clock_skew_seconds"]) == "accepted"
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
    prose = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-2-site-publication.md").read_text())
    assert "the disputed Label's `subject` MUST lie under the disputant's authority" in prose
    assert "a Normalized URL where the disputant states its grounds, and `asserted_at`, read as a Label's" in prose
    assert "an Aggregator MUST NOT reject a dispute for naming another Log" in prose
    assert "A dispute is never applied by the Aggregator or a Snapshot builder" in prose
    w3 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "`publisher_catalog`, `publisher_item`, `label`, `dispute`, and within each group" in w3
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
    clock = (v["clock"], v["clock_skew_seconds"])
    assert _dispute_disposition(doc, widened, validator, sealed, *clock) == "authority"
    assert _dispute_disposition(valid["envelope"], valid["declaration"], validator, {}, *clock) == "unsealed"
    at_bound = next(c for c in v["cases"] if c["name"] == "asserted_at at the allowance bound")
    assert _dispute_disposition(at_bound["envelope"], at_bound["declaration"], validator, sealed,
                                v["clock"], v["clock_skew_seconds"] - 1) == "clock"
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
    key = next((k for k in publisher["keys"] if k["kid"] == doc["sig"]["key_id"]), None)
    return key is not None and _ed25519_profile_verdict(
        canonical_b64u_decode(key["x"]), canonical_b64u_decode(doc["sig"]["value"]),
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
        over = max(domain.values()) > case["domain_epoch_entries_max"] or \
            (labeler and max(labeler.values()) > case["labeler_epoch_entries_max"])
        assert case["expected"] == ("WIST3-E03" if over else None), case["label"]
        assert case["labeler_epoch_entries_max"] <= case["domain_epoch_entries_max"]
        seen.add(case["expected"])
    assert seen == {None, "WIST3-E03"}
    assert any(e["type"] == "dispute" for c in v["cap_cases"] for e in c["entries"])
    types = {e["type"] for c in v["cap_cases"] for e in c["entries"]}
    assert types == {"publisher_catalog", "publisher_item", "label", "dispute"}, \
        f"the capacity cases carry Entry types other than WIST-3 §3.2 counts: {types}"
    for case in v["persistence_cases"]:
        def live(h):
            # WIST-2 §3.3: the greatest asserted_at, and among equal instants
            # the one later in Log order, which the event list is in.
            current = max((ev for index, ev in enumerate(case["events"]) if ev["height"] <= h),
                          key=lambda ev: (publisher_instant(ev["asserted_at"]),
                                          case["events"].index(ev)), default=None)
            if current is None or current["retracted"]:
                return False
            return case["expires_at_height"] is None or h < case["expires_at_height"]
        for probe in case["probes"]:
            assert probe["counted"] == (live(probe["height"]) and live(probe["height"] - 1)), (case["label"], probe)
        assert {p["counted"] for p in case["probes"]} == {True, False}, case["label"]
    for case in v["inactivity_cases"]:
        assert case["applies"] == (case["height"] - case["last_sealed_height"] <= case["inactivity_epochs"]), case["label"]
    assert {c["applies"] for c in v["inactivity_cases"]} == {True, False}
    w3 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-3-logbook-distribution.md").read_text())
    assert "`(labeler, label_count, retraction_count, distinct_subjects, first_seen_height)`" in w3
    assert "an Epoch MUST NOT carry more than `labeler_epoch_entries_max`" in w3
    assert "`publisher_catalog`, `publisher_item` and `label` Entries, counted together" in w3
    w4 = re.sub(r"\s+", " ", (ROOT / "specs" / "WIST-4-governance.md").read_text())
    assert "only once it has persisted across two consecutive Epochs" in w4
    assert "Ignore a Labeler with no sealed Entry of any type within a configured number of Epochs, 720 by default" in w4
check("vectors:wist3-label-tables", _label_table_vectors)

def _label_table_vectors_twin():
    v = _label_table_vector()
    case = next(c for c in v["persistence_cases"] if c["label"] == "counted from the second consecutive Epoch")
    first = min(p["height"] for p in case["probes"] if p["counted"])
    assert not next(p for p in case["probes"] if p["height"] == first - 1)["counted"], "a Label counts in its sealing Epoch"
    cap = next(c for c in v["cap_cases"] if c["label"] == "labels over the labeler cap")
    assert len(cap["entries"]) <= cap["domain_epoch_entries_max"], "the labeler cap case is really a domain cap case"
check("negative:wist3-label-tables", _label_table_vectors_twin)


sys.exit(1 if failures else 0)
