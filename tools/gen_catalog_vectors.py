#!/usr/bin/env python3
import base64
import calendar
import copy
import hashlib
import json
import pathlib
import time

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import catalogs
import collection_rules as rules
import items
import merkle
import tree_files

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIST1 = ROOT / "vectors" / "wist1"
WIST2 = ROOT / "vectors" / "wist2"

KEY_NAMES = ("owner", "owner2", "recovery", "recovery2", "fresh", "journal", "journal2",
             "store", "store2", "docs")
USED_KEYS = ("owner", "recovery", "journal", "store")
SEEDS = {name: bytes([0xC1 + i]) * 32 for i, name in enumerate(KEY_NAMES)}
PRIVATE = {name: Ed25519PrivateKey.from_private_bytes(SEEDS[name]) for name in USED_KEYS}
X = {name: rules.b64u(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
     for name, key in PRIVATE.items()}
KID = {name: rules.thumbprint(x) for name, x in X.items()}
KEYS_MEMBER = {name: {"seed_hex": SEEDS[name].hex(), "x": X[name], "kid": KID[name]} for name in USED_KEYS}
KEYS_NOTE = "Keys derive from the stated test-only seeds."


def seconds(instant):
    return calendar.timegm(time.strptime(instant, "%Y-%m-%dT%H:%M:%SZ"))


def stamp(value):
    return catalogs.log_timestamp(value)


NBF = seconds("2026-09-01T00:00:00Z")
JOURNAL_EXP = seconds("2026-12-01T00:00:00Z")
DAY = 86400
GENERATED_AT = "2026-10-01T12:00:00Z"
CLOCK = GENERATED_AT
ITEM_PARAMETERS = dict(items.DEFAULT_PARAMETERS)
CATALOG_PARAMETERS = dict(catalogs.DEFAULT_PARAMETERS)
TREE_PARAMETERS = dict(tree_files.DEFAULT_PARAMETERS)
PULL_PARAMETERS = {**CATALOG_PARAMETERS, **TREE_PARAMETERS, **ITEM_PARAMETERS}


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2) + "\n")


def key(name, nbf=NBF, exp=None):
    entry = {"kty": "OKP", "crv": "Ed25519", "x": X[name], "kid": KID[name], "nbf": nbf}
    if exp is not None:
        entry["exp"] = exp
    return entry


def sign(signer, inner_name, inner, key_id=None):
    return {inner_name: inner,
            "sig": {"key_id": key_id or KID[signer], "alg": "Ed25519",
                    "value": rules.b64u(PRIVATE[signer].sign(rfc8785.dumps(inner)))}}


def prefix(url):
    return {"url": url, "match": "prefix"}


def exact(url):
    return {"url": url, "match": "exact"}


def collection(name, scope, keys=None):
    out = {"name": name, "scope": scope}
    if keys is not None:
        out["keys"] = keys
    return out


def declaration(collections=None):
    inner = {"wist_version": "1.0.0", "seq": 0, "domain": "example.com",
             "subdomain_scope": ["www.example.com", "blog.example.com"],
             "keys": [key("owner")], "recovery_keys": [key("recovery")]}
    if collections is not None:
        inner["collections"] = collections
    return inner


WITH_COLLECTIONS = declaration([
    collection("journal", [prefix("https://example.com/journal/"), prefix("https://blog.example.com/journal/")],
               [key("journal", exp=JOURNAL_EXP)]),
    collection("store", [prefix("https://example.com/store/"), exact("https://example.com/cart")], [key("store")])])
IMPLICIT = declaration()
DECLARATIONS = {"collections": sign("owner", "publisher", WITH_COLLECTIONS),
                "implicit": sign("owner", "publisher", IMPLICIT)}
for _envelope in DECLARATIONS.values():
    assert rules.declaration_disposition(_envelope) == "accepted"
DECLARATIONS_NOTE = ("`declarations` holds the signed Declarations the cases name by label: `collections` carries "
                     "the Collections journal (prefix entries https://example.com/journal/ and "
                     "https://blog.example.com/journal/, key journal with exp) and store (prefix "
                     "https://example.com/store/, exact https://example.com/cart, key store); `implicit` carries "
                     "none, so its only Collection is the implicit default, whose Scope is every URL on example.com, "
                     "www.example.com and blog.example.com. Both list the owner key in `keys` and the recovery key "
                     "in `recovery_keys`.")


def publisher_of(label):
    return DECLARATIONS[label]["publisher"]


def salt_for(label):
    return rules.b64u(hashlib.sha256(("salt " + label).encode()).digest()[:16])


def content_for(label, extract=None):
    return {"extract": extract if extract is not None else f"Text of {label}.",
            "links": {"total": 0, "urls": []}, "summary": {"title": f"Title {label}"}}


def publication(url, modified, label=None, lang="en", extract=None):
    return {"url": url, "lang": lang, "modified": modified, "content": content_for(label or url, extract)}


def page(url, observed_at, label=None, lang="en", publisher="example.com", extract=None):
    return items.new_page_item(publisher, publication(url, observed_at, label, lang, extract), salt_for(label or url))


def removed(url, observed_at, publisher="example.com"):
    return {"publisher": publisher, "url": url, "observed_at": observed_at, "removed": True}


def catalog_inner(listed, collection_name="journal", generated_at=GENERATED_AT, publisher="example.com",
                  capacity=tree_files.BUCKET_CAPACITY, depth_max=tree_files.DEFAULT_PARAMETERS["tree_depth_max"]):
    tree, files = tree_files.write_tree(listed, capacity, depth_max)
    return ({"wist_version": "1.0.0", "publisher": publisher, "collection": collection_name,
             "generated_at": generated_at, "size": len(listed), "root": items.root_string(listed), "tree": tree},
            files)


def texts(files):
    return {digest: octets.decode("utf-8") for digest, octets in sorted(files.items())}


def hexes(values):
    return [v.hex() for v in values]


REMOVE = object()


def lang_padding(octets):
    chunks, rest = divmod(octets, 9)
    if rest == 1:
        chunks, tail = chunks - 1, ["-" + "x" * 4] * 2
    else:
        tail = ["-" + "x" * (rest - 1)] if rest else []
    return "".join(["-" + "x" * 8] * chunks + tail)


def padded_to(item, octets):
    lang = item["meta"]["lang"]
    padded = changed(item, ["meta", "lang"], lang + lang_padding(octets - len(rfc8785.dumps(item))))
    assert len(rfc8785.dumps(padded)) == octets
    return padded


def item_bound(parameters):
    return items.ITEM_BOUND_OCTETS + parameters["url_cap_bytes"]


def changed(obj, path, value):
    out = copy.deepcopy(obj)
    target = out
    for part in path[:-1]:
        target = target[part]
    if value is REMOVE:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return out


def item_field_vectors():
    base, base_payload = page("https://example.com/journal/first", "2026-10-01T09:30:00Z", label="first")
    gone = removed("https://example.com/journal/gone", "2026-10-01T10:00:00Z")
    catalog, _ = catalog_inner([base, gone])
    implicit_catalog, _ = catalog_inner([base], collection_name="default")
    cases = []

    def case(name, item, expected, parameters=None, label="collections", judged_with=None):
        parameters = {**ITEM_PARAMETERS, **(parameters or {})}
        judged_with = judged_with or (implicit_catalog if label == "implicit" else catalog)
        got = items.item_disposition(item, judged_with, publisher_of(label), parameters)
        assert got == expected, (name, got, expected)
        cases.append({"name": name, "declaration": label, "catalog": judged_with, "parameters": parameters,
                      "item": item, "expected": expected})

    case("page Item", base, "accepted")
    case("removed Item", gone, "accepted")
    case("page Item with topics and license",
         changed(base, ["meta"], {"lang": "en-GB", "topics": ["history", "maps"], "license": "CC-BY-4.0"}), "accepted")
    case("page Item with ten topics of 64 scalar values",
         changed(base, ["meta", "topics"], ["\U0001F5FA" * 64] * 10), "accepted")
    case("page Item with eleven topics", changed(base, ["meta", "topics"], ["t"] * 11), "WIST1-E14")
    case("page Item with a topic of 65 scalar values", changed(base, ["meta", "topics"], ["t" * 65]), "WIST1-E14")
    case("page Item with a license of 64 scalar values", changed(base, ["meta", "license"], "l" * 64), "accepted")
    case("page Item with a license of 65 scalar values", changed(base, ["meta", "license"], "l" * 65), "WIST1-E14")
    case("page Item with payload.bytes 0", changed(base, ["payload", "bytes"], 0), "accepted")
    case("page Item on a subdomain_scope host inside the Scope",
         changed(base, ["url"], "https://blog.example.com/journal/first"), "accepted")
    case("page Item whose url carries a query", changed(base, ["url"], "https://example.com/journal/?p=1"),
         "accepted")
    case("page Item under the implicit default on a subdomain_scope host",
         changed(base, ["url"], "https://www.example.com/first"), "accepted", label="implicit")

    for member in sorted(items.PAGE_MEMBERS):
        case(f"page Item without {member}", changed(base, [member], REMOVE), "WIST1-E14")
    for member in sorted(items.REMOVED_MEMBERS - {"removed"}):
        case(f"removed Item without {member}", changed(gone, [member], REMOVE), "WIST1-E14")
    for member, value in (("prev", "sha256:" + "0" * 64), ("change_type", "update"), ("wist_version", "1.0.0")):
        case(f"page Item with a Delta member {member}", changed(base, [member], value), "WIST1-E14")
    case("removed Item carrying payload", changed(gone, ["payload"], base["payload"]), "WIST1-E14")
    case("removed Item carrying meta", changed(gone, ["meta"], {"lang": "en"}), "WIST1-E14")
    case("page Item carrying removed true", changed(base, ["removed"], True), "WIST1-E14")
    for label, value in (("false", False), ("the string true", "true"), ("1", 1), ("null", None)):
        case(f"removed {label}", changed(gone, ["removed"], value), "WIST1-E14")
    case("Item that is an array", [base], "WIST1-E14")
    for label, value in (("uppercase", "Example.com"), ("with a trailing dot", "example.com."), ("empty", ""),
                         ("a number", 7), ("a URL", "https://example.com/")):
        case(f"publisher {label}", changed(base, ["publisher"], value), "WIST1-E14")
    for label, value in (("a number", 7), ("null", None), ("an array", ["https://example.com/journal/first"])):
        case(f"url {label}", changed(base, ["url"], value), "WIST1-E14")
    for label, value in (("with second 60", "2026-10-01T09:30:60Z"), ("on 30 February", "2026-02-30T09:30:00Z"),
                         ("with a space for T", "2026-10-01 09:30:00Z"), ("without offset", "2026-10-01T09:30:00"),
                         ("with offset hour 24", "2026-10-01T09:30:00+24:00"),
                         ("with an empty fraction", "2026-10-01T09:30:00.Z"),
                         ("a number", 1790847000), ("date only", "2026-10-01")):
        case(f"observed_at {label}", changed(base, ["observed_at"], value), "WIST1-E14")
        if label == "with second 60":
            case(f"removed Item observed_at {label}", changed(gone, ["observed_at"], value), "WIST1-E14")
    case("payload an array", changed(base, ["payload"], [base["payload"]]), "WIST1-E14")
    case("payload without bytes", changed(base, ["payload", "bytes"], REMOVE), "WIST1-E14")
    case("payload with an extra member", changed(base, ["payload", "salt"], salt_for("first")), "WIST1-E14")
    case("payload.commitment a number", changed(base, ["payload", "commitment"], 7), "WIST1-E14")
    case("payload.alg lowercase", changed(base, ["payload", "alg"], "hmac-sha256"), "WIST1-E14")
    for label, value in (("negative", -1), ("fractional", 1.5), ("a string", "86"), ("true", True),
                         ("one above the safe range", 2**53)):
        case(f"payload.bytes {label}", changed(base, ["payload", "bytes"], value), "WIST1-E14")
    case("meta an array", changed(base, ["meta"], ["en"]), "WIST1-E14")
    case("meta without lang", changed(base, ["meta"], {"license": "CC0-1.0"}), "WIST1-E14")
    for label, value in (("uppercase", "EN"), ("of four letters", "engl"), ("with an empty subtag", "en-"),
                         ("with a nine-character subtag", "en-abcdefghi")):
        case(f"meta.lang {label}", changed(base, ["meta", "lang"], value), "WIST1-E14")
    case("meta with an unknown member", changed(base, ["meta", "title"], "First"), "WIST1-E14")

    for label, url in (("with an uppercase host", "https://EXAMPLE.com/journal/first"),
                       ("with an explicit :443", "https://example.com:443/journal/first"),
                       ("with a fragment", "https://example.com/journal/first#top"),
                       ("with a dot segment", "https://example.com/journal/../journal/first"),
                       ("with an unreserved escape", "https://example.com/journal/%7Efirst"),
                       ("with a lowercase escape", "https://example.com/journal/a%2fb"),
                       ("with no Normalized URL", "https://example.com/journal/%zz"),
                       ("over http", "http://example.com/journal/first")):
        case(f"url {label}", changed(base, ["url"], url), "WIST1-E03")
    case("url on a host outside the authority", changed(base, ["url"], "https://example.org/journal/first"),
         "WIST1-E03")
    case("url outside every Scope", changed(base, ["url"], "https://example.com/about"), "WIST1-E03")
    case("url inside another Collection's Scope", changed(base, ["url"], "https://example.com/store/first"),
         "WIST1-E03")
    case("url equal to another Collection's exact entry", changed(base, ["url"], "https://example.com/cart"),
         "WIST1-E03")
    case("removed Item outside every Scope", changed(gone, ["url"], "https://example.com/about"), "WIST1-E03")
    case("removed Item inside another Collection's Scope", changed(gone, ["url"], "https://example.com/store/gone"),
         "WIST1-E03")
    case("url under the implicit default on a host outside the authority",
         changed(base, ["url"], "https://shop.example.com/first"), "WIST1-E03", label="implicit")

    small_url = {"url_cap_bytes": 64}
    stem = "https://example.com/journal/"
    at_cap = stem + "a" * (64 - 2 - len(stem))
    assert len(rfc8785.dumps(at_cap)) == 64
    case("JCS(url) at url_cap_bytes", changed(base, ["url"], at_cap), "accepted", small_url)
    case("JCS(url) one octet above url_cap_bytes", changed(base, ["url"], at_cap + "a"), "WIST1-E11", small_url)
    case("removed Item with JCS(url) one octet above url_cap_bytes", changed(gone, ["url"], at_cap + "a"),
         "accepted", small_url)
    bound = item_bound(ITEM_PARAMETERS)
    case("page Item whose JCS(item) is at 16 384 + url_cap_bytes octets", padded_to(base, bound), "accepted")
    case("page Item whose JCS(item) is one octet above 16 384 + url_cap_bytes octets", padded_to(base, bound + 1),
         "WIST1-E04")
    small_bound = item_bound({**ITEM_PARAMETERS, **small_url})
    long_gone = changed(gone, ["url"], stem + "x" * (small_bound - len(rfc8785.dumps(changed(gone, ["url"], stem)))))
    assert len(rfc8785.dumps(long_gone)) == small_bound
    case("removed Item whose JCS(item) is at 16 384 + url_cap_bytes octets through its url", long_gone, "accepted",
         small_url)
    case("removed Item whose JCS(item) is one octet above 16 384 + url_cap_bytes octets through its url",
         changed(long_gone, ["url"], long_gone["url"] + "x"), "WIST1-E04", small_url)
    small_caps = {"extract_cap_bytes": 100, "links_cap_bytes": 50, "summary_cap_bytes": 50}
    cap = items.derived_payload_cap({**ITEM_PARAMETERS, **small_caps})
    assert cap == 232
    case("payload.bytes at the derived cap", changed(base, ["payload", "bytes"], cap), "accepted", small_caps)
    case("payload.bytes one above the derived cap", changed(base, ["payload", "bytes"], cap + 1), "WIST1-E04",
         small_caps)
    case("payload.bytes one above the default derived cap", changed(base, ["payload", "bytes"], 38945), "WIST1-E04")
    case("payload.bytes at the default derived cap", changed(base, ["payload", "bytes"], 38944), "accepted")

    for label, observed, expected in (
            ("equal to generated_at", "2026-10-01T12:00:00Z", "accepted"),
            ("equal to generated_at with a zero fraction", "2026-10-01T12:00:00.000Z", "accepted"),
            ("equal to generated_at in lowercase t and z", "2026-10-01t12:00:00z", "accepted"),
            ("one microsecond before generated_at", "2026-10-01T11:59:59.999999Z", "accepted"),
            ("one microsecond after generated_at", "2026-10-01T12:00:00.000001Z", "WIST1-E06"),
            ("one second after generated_at", "2026-10-01T12:00:01Z", "WIST1-E06"),
            ("equal to generated_at at offset +02:00", "2026-10-01T14:00:00+02:00", "accepted"),
            ("half a second after generated_at at offset +02:00", "2026-10-01T14:00:00.5+02:00", "WIST1-E06"),
            ("equal to generated_at at offset -05:00", "2026-10-01T07:00:00-05:00", "accepted"),
            ("equal to generated_at at offset -00:00", "2026-10-01T12:00:00-00:00", "accepted"),
            ("one minute after generated_at by offset -00:01", "2026-10-01T12:00:00-00:01", "WIST1-E06"),
            ("one minute before generated_at by offset +00:01", "2026-10-01T12:00:00+00:01", "accepted"),
            ("on the next day at offset -12:00", "2026-10-02T00:00:00-12:00", "WIST1-E06")):
        case(f"observed_at {label}", changed(base, ["observed_at"], observed), expected)
    long_zero = "2026-10-01T12:00:00." + "0" * 5000 + "Z"
    long_later = "2026-10-01T12:00:00." + "0" * 4999 + "1Z"
    case("observed_at equal to generated_at with a fraction of 5 000 zero digits",
         changed(base, ["observed_at"], long_zero), "accepted")
    case("observed_at later than generated_at by a fraction of 5 000 digits ending in 1",
         changed(base, ["observed_at"], long_later), "WIST1-E06")
    case("removed Item observed_at one second after generated_at",
         changed(gone, ["observed_at"], "2026-10-01T12:00:01Z"), "WIST1-E06")
    other = changed(base, ["url"], "https://blog.example.com/journal/first")
    case("publisher other than the Catalog's", changed(other, ["publisher"], "blog.example.com"), "WIST2-E03")
    case("removed Item with a publisher other than the Catalog's",
         changed(changed(gone, ["url"], "https://blog.example.com/journal/gone"), ["publisher"], "blog.example.com"),
         "WIST2-E03")

    known = []
    query = page("https://example.com/journal/?p=1", "2026-10-01T09:30:00.25+02:00", "query")
    for name, item, payload in (
            ("page Item", base, base_payload), ("removed Item", gone, None),
            ("page Item whose url carries a query", *query),
            ("removed Item on a subdomain_scope host",
             removed("https://blog.example.com/journal/gone", "2026-09-30T23:00:00Z"), None)):
        entry = {"name": name, "item": item, "item_id": items.item_id(item),
                 "key": items.item_key(item["url"]).hex(), "leaf": items.leaf(item).hex()}
        if payload is not None:
            assert items.payload_disposition(item, payload) == "accepted"
            entry["payload"] = payload
        known.append(entry)

    payload_cases = []

    def payload_case(name, item, payload, expected):
        got = items.payload_disposition(item, payload, ITEM_PARAMETERS)
        assert got == expected, (name, got)
        payload_cases.append({"name": name, "item": item,
                              "payload_path": f"/.well-known/wist/collections/journal/payloads/"
                                              f"{items.payload_name(item)}.json",
                              "parameters": ITEM_PARAMETERS, "payload": payload, "expected": expected})

    payload_case("Payload that reproduces the commitment", base, base_payload, "accepted")
    payload_case("Payload with another extract of equal length", base,
                 changed(base_payload, ["content", "extract"], "Text of fir5t."), "WIST1-E10")
    payload_case("Payload with another salt", base, changed(base_payload, ["salt"], salt_for("tsrif")), "WIST1-E10")
    second, second_payload = page("https://example.com/journal/second", "2026-10-01T09:30:00Z", label="final")
    assert len(rfc8785.dumps(second_payload["content"])) == base["payload"]["bytes"]
    payload_case("Payload of another Item of equal length", base, second_payload, "WIST1-E10")
    payload_case("Payload of that other Item under its own Item ID", second, second_payload, "accepted")
    payload_case("Item declaring one octet more than JCS(content)",
                 changed(base, ["payload", "bytes"], base["payload"]["bytes"] + 1), base_payload, "WIST1-E10")

    return {"note": (
        "ADR-0052 Items. item_cases judge `item` with `catalog`, the inner object of the Catalog that lists it, of "
        "which only publisher, collection and generated_at are read, under the Declaration named by `declaration` "
        "and the size-cap map `parameters`. An object with a member `removed` is of kind removed and carries "
        "exactly publisher, url, observed_at and removed (true); any other is of kind page and carries exactly "
        "publisher, url, observed_at, payload and meta; each member has the form WIST-1 sections 3.2, 3.4, 3.6, "
        "3.7 and 3.8 give a Delta's. A form failure is WIST1-E14, except that a string url keeps WIST1-E03 and "
        "WIST1-E11 and a nonnegative safe-integer payload.bytes above the derived cap (extract_cap_bytes + "
        "links_cap_bytes + summary_cap_bytes + 32) keeps WIST1-E04. WIST1-E03: url not byte-identical to its "
        "Normalized URL, host (without port) outside domain and subdomain_scope, or url outside the Scope of the "
        "Catalog's Collection. WIST1-E11: in a page Item, JCS(url) above url_cap_bytes; a removed Item is not held "
        "to url_cap_bytes. WIST1-E04 as well: JCS(item) above 16 384 + url_cap_bytes octets, for either kind. "
        "WIST1-E06: observed_at later than generated_at as exact instants, however many fraction digits "
        "observed_at carries. WIST2-E03: publisher other than the Catalog's. Each rejected case fails "
        "exactly one rule, with one exception: a missing or malformed publisher is also other than the Catalog's, "
        "and those cases exercise the ADR's rule that the WIST1-E14 conditions are checked first. known_answers give Item ID = sha256: + "
        "hex(SHA-256(JCS(item))), key = SHA-256(JCS([\"page\", url])) and leaf = SHA-256(0x00 || key || "
        "SHA-256(JCS(item))), key and leaf as lowercase hex; a page Item's entry carries its Payload. payload_cases check `payload`, served at "
        "`payload_path` whose last segment is the 64 digits of the Item ID that follow sha256:, followed by .json, against the page Item `item` under "
        "WIST-1 section 3.6: JCS(content) must be exactly payload.bytes octets and HMAC-SHA256(salt, JCS(content)) "
        "must reproduce payload.commitment, else WIST1-E10. Every case supplies its own parameter map; no default "
        "applies. " + DECLARATIONS_NOTE + " " + KEYS_NOTE),
        "keys": KEYS_MEMBER, "declarations": DECLARATIONS, "item_cases": cases, "known_answers": known,
        "payload_cases": payload_cases}


def root_pool():
    pool, payloads = [], {}
    for i in range(17):
        url = f"https://example.com/journal/r{i:02d}"
        if i % 3 == 2:
            pool.append(removed(url, f"2026-09-{10 + i:02d}T08:00:00Z"))
        else:
            item, payload = page(url, f"2026-09-{10 + i:02d}T08:00:00Z")
            pool.append(item)
            payloads[items.item_id(item)] = payload
    return pool, payloads


def walk_reaches(item, proof, root_hex):
    h = items.leaf(item)
    path = [bytes.fromhex(p) for p in proof["path"]]
    fn, sn = proof["index"], proof["tree_size"] - 1
    while sn > 0:
        if fn % 2 == 1:
            h = merkle.node_hash(path.pop(0), h)
        elif fn < sn:
            h = merkle.node_hash(h, path.pop(0))
        fn, sn = fn // 2, sn // 2
    return not path and "sha256:" + h.hex() == root_hex



def item_root_vectors():
    pool, payloads = root_pool()
    root_cases = []
    for size in (0, 1, 2, 3, 4, 5, 7, 8, 9, 13, 17):
        listed = items.in_list_order(pool[:size])
        root_cases.append({"name": f"{size} Items", "items": listed,
                           "keys": hexes(items.item_key(i["url"]) for i in listed),
                           "leaves": hexes(items.leaf(i) for i in listed), "root": items.root_string(listed)})
    assert root_cases[0]["root"] == "sha256:" + hashlib.sha256(b"").hexdigest()

    thirteen = items.in_list_order(pool[:13])
    catalog13, _ = catalog_inner(thirteen)
    single = items.in_list_order(pool[:1])
    catalog1, _ = catalog_inner(single)
    three = items.in_list_order(pool[:3])
    catalog3, _ = catalog_inner(three)
    empty, _ = catalog_inner([])
    proof_cases = []

    def proof_case(name, catalog, item, proof, expected, raw=None):
        judged = items.strict_loads(raw.encode("utf-8")) if raw is not None else proof
        got = items.proof_disposition(item, judged, catalog)
        assert got == expected, (name, got)
        entry = {"name": name, "catalog": catalog, "item": item}
        entry.update({"proof_json": raw} if raw is not None else {"proof": proof})
        entry["expected"] = expected
        proof_cases.append(entry)

    first = items.inclusion_proof(thirteen, 0)
    last = items.inclusion_proof(thirteen, 12)
    middle = items.inclusion_proof(thirteen, 6)
    lone = items.inclusion_proof(single, 0)
    assert lone["path"] == []
    proof_case("first leaf of 13", catalog13, thirteen[0], first, "accepted")
    proof_case("last leaf of 13", catalog13, thirteen[12], last, "accepted")
    proof_case("middle leaf of 13", catalog13, thirteen[6], middle, "accepted")
    proof_case("lone leaf", catalog1, single[0], lone, "accepted")
    third = items.inclusion_proof(thirteen, 2)
    proof_case("leaf 2 of 13", catalog13, thirteen[2], third, "accepted")
    third_text = json.dumps(third)
    assert third_text.count('"index": 2,') == 1 and third_text.count('"tree_size": 13,') == 1
    for spelling in ("2.0", "2e0"):
        proof_case(f"leaf 2 of 13, index spelled {spelling}", catalog13, thirteen[2], None, "accepted",
                   third_text.replace('"index": 2,', f'"index": {spelling},'))
    proof_case("leaf 2 of 13, tree_size spelled 13.0", catalog13, thirteen[2], None, "accepted",
               third_text.replace('"tree_size": 13,', '"tree_size": 13.0,'))
    for i in range(3):
        proof_case(f"leaf {i} of 3", catalog3, three[i], items.inclusion_proof(three, i), "accepted")
    reshaped = changed(items.inclusion_proof(three, 1), ["tree_size"], 4)
    assert walk_reaches(three[1], reshaped, catalog3["root"])
    proof_case("tree_size other than the Catalog's size, the walk still ending at its root", catalog3, three[1],
               reshaped, "WIST1-E17")
    proof_case("index equal to tree_size", catalog13, thirteen[12], changed(last, ["index"], 13), "WIST1-E17")
    proof_case("index above tree_size", catalog13, thirteen[12], changed(last, ["index"], 14), "WIST1-E17")
    proof_case("proof against an empty Catalog", empty, thirteen[0], {"index": 0, "tree_size": 0, "path": []},
               "WIST1-E17")
    proof_case("path lacking its last element", catalog13, thirteen[6], changed(middle, ["path"], middle["path"][:-1]),
               "WIST1-E17")
    proof_case("path with one element left unread", catalog13, thirteen[6],
               changed(middle, ["path"], middle["path"] + [middle["path"][0]]), "WIST1-E17")
    flipped = middle["path"][0][:-1] + ("0" if middle["path"][0][-1] != "0" else "1")
    proof_case("path element altered", catalog13, thirteen[6], changed(middle, ["path", 0], flipped), "WIST1-E17")
    proof_case("proof of another Item", catalog13, thirteen[7], middle, "WIST1-E17")
    proof_case("lone-leaf proof of an Item not listed", catalog1, pool[1], lone, "WIST1-E17")
    proof_case("proof without index", catalog13, thirteen[6], changed(middle, ["index"], REMOVE), "WIST1-E14")
    proof_case("proof with an extra member", catalog13, thirteen[6], changed(middle, ["leaf"], "x"), "WIST1-E14")
    proof_case("path element in uppercase hexadecimal", catalog13, thirteen[6],
               changed(middle, ["path", 0], middle["path"][0].upper()), "WIST1-E14")
    proof_case("path element with a sha256: prefix", catalog13, thirteen[6],
               changed(middle, ["path", 0], "sha256:" + middle["path"][0]), "WIST1-E14")
    proof_case("path element of 63 digits", catalog13, thirteen[6],
               changed(middle, ["path", 0], middle["path"][0][:63]), "WIST1-E14")
    proof_case("path not an array", catalog13, thirteen[6], changed(middle, ["path"], "".join(middle["path"])),
               "WIST1-E14")
    proof_case("proof an array", catalog13, thirteen[6], [6, 13, middle["path"]], "WIST1-E14")

    body_cases = []

    def body_case(name, body, expected, catalog=catalog13):
        got = items.body_disposition(body, catalog)
        assert got == expected, (name, got)
        body_cases.append({"name": name, "catalog": catalog, "body": body, "expected": expected})

    body = items.publisher_item_body(thirteen[6], catalog13, thirteen)
    removed_index = next(i for i, item in enumerate(thirteen) if items.kind(item) == "removed")
    removed_body = items.publisher_item_body(thirteen[removed_index], catalog13, thirteen)
    assert items.proof_disposition(body["item"], body["proof"], catalog13) == "accepted"
    body_case("body of a page Item", body, "accepted")
    body_case("body of a removed Item", removed_body, "accepted")
    body_case("body of a lone Item", items.publisher_item_body(single[0], catalog1, single), "accepted", catalog1)
    body_case("body without proof", changed(body, ["proof"], REMOVE), "WIST1-E14")
    body_case("body without item", changed(body, ["item"], REMOVE), "WIST1-E14")
    body_case("body with an extra member", changed(body, ["sig"], {"alg": "Ed25519"}), "WIST1-E14")
    malformed = changed(thirteen[6], ["observed_at"], REMOVE)
    with_malformed = items.in_list_order(thirteen[:6] + [malformed] + thirteen[7:])
    catalog_malformed, _ = catalog_inner(with_malformed)
    body_case("body whose Item lacks observed_at, listed so in its Catalog",
              items.publisher_item_body(malformed, catalog_malformed, with_malformed), "WIST1-E14", catalog_malformed)
    body_case("body naming another Collection than its Catalog's", changed(body, ["collection"], "store"),
              "WIST1-E17")
    foreign, foreign_payload = page("https://blog.example.com/journal/r99", "2026-09-27T08:00:00Z",
                                    publisher="blog.example.com")
    payloads[items.item_id(foreign)] = foreign_payload
    with_foreign = items.in_list_order(thirteen[:4] + [foreign])
    catalog_foreign, _ = catalog_inner(with_foreign)
    body_case("body whose Item's publisher is not the named Catalog's, listed so in its Catalog",
              items.publisher_item_body(foreign, catalog_foreign, with_foreign), "WIST2-E03", catalog_foreign)
    body_case("body of another Item of that Catalog", items.publisher_item_body(with_foreign[0], catalog_foreign,
                                                                                 with_foreign),
              "accepted", catalog_foreign)
    body_case("body whose collection is not a Collection name", changed(body, ["collection"], "Journal"),
              "WIST1-E14")
    body_case("body whose catalog is in uppercase hexadecimal",
              changed(body, ["catalog"], "sha256:" + body["catalog"][7:].upper()), "WIST1-E14")
    body_case("body whose proof path is not an array", changed(body, ["proof", "path"], None), "WIST1-E14")
    body_case("body whose proof lacks its last path element",
              changed(body, ["proof", "path"], body["proof"]["path"][:-1]), "WIST1-E17")

    return {"note": (
        "ADR-0052 roots, Inclusion Proofs and publisher_item bodies. root_cases list `items` in list order "
        "(ascending octet order of key), with each Item's key and leaf as lowercase hex and `root` = sha256: + hex "
        "of the Merkle Tree Hash of WIST-3 section 4 over the leaves, node = SHA-256(0x01 || left || right), "
        "SHA-256(\"\") for no Item; key = SHA-256(JCS([\"page\", url])), leaf = SHA-256(0x00 || key || "
        "SHA-256(JCS(item))). proof_cases verify `proof` for `item` against `catalog` (a Catalog inner object; "
        "size and root are read): a proof that is not an object of exactly index, tree_size and path, with index "
        "and tree_size nonnegative safe integers and path an array of 64-digit lowercase hex strings, is "
        "WIST1-E14; otherwise WIST1-E17 when tree_size is not size, when index is not below tree_size, when the "
        "WIST-3 section 4 walk from the leaf lacks a path element or leaves one unread, or when it ends with a "
        "hash other than root. Each rejected proof is a twin of an accepted one and fails exactly one of these "
        "rules; in the tree_size case the walk under the altered tree_size still consumes the path exactly and "
        "ends at root. A case with `proof_json` in place of `proof` carries the proof as its serialized octets "
        "(UTF-8 text): index and tree_size are integers by value and not by spelling, so 2.0 and 2e0 are the "
        "integer 2. body_cases judge a publisher_item `body` against `catalog`, the inner object of the Catalog "
        "the body names (for a malformed catalog member, the Catalog it was built against): a body other than "
        "exactly item (an Item in the form of the Items section), collection (a Collection name), catalog (the "
        "Catalog ID, sha256: + hex(SHA-256(JCS(catalog)))) and proof (an Inclusion Proof in the form above) is "
        "WIST1-E14; a collection other than the Catalog's is WIST1-E17; an Item whose publisher is not the "
        "Catalog's is WIST2-E03; the proof is then verified against the Catalog as in proof_cases; else "
        "`accepted`. The WIST1-E14 conditions are checked first; no order holds among the other codes. Each "
        "rejected body fails one rule, except the body whose collection is not a Collection name, which is also "
        "not the Catalog's collection and relies on that stated precedence; a body whose Item is malformed or of "
        "another publisher is proved against a Catalog that lists that Item. `payloads` gives the Payload of each page Item, "
        "keyed by Item ID; no root, proof or body reads it. No case reads a parameter."),
        "root_cases": root_cases, "proof_cases": proof_cases, "body_cases": body_cases, "payloads": payloads}


def catalog_field_vectors():
    journal = [page("https://example.com/journal/a", "2026-09-30T10:00:00Z")[0],
               removed("https://example.com/journal/b", "2026-09-30T11:00:00Z")]
    base, _ = catalog_inner(journal)
    store, _ = catalog_inner([page("https://example.com/store/a", "2026-09-30T10:00:00Z")[0]], "store")
    default, _ = catalog_inner([page("https://www.example.com/a", "2026-09-30T10:00:00Z")[0]], "default")
    cases = []

    def case(name, envelope, expected, label="collections", clock=CLOCK, parameters=None, raw=None):
        parameters = {**CATALOG_PARAMETERS, **(parameters or {})}
        judged = raw.encode("utf-8") if raw is not None else envelope
        got = catalogs.catalog_disposition(judged, publisher_of(label), clock, parameters)
        assert got == expected, (name, got, expected)
        entry = {"name": name, "declaration": label, "clock": clock, "parameters": parameters}
        entry.update({"catalog_json": raw} if raw is not None else {"catalog": envelope})
        if raw is not None and expected == "accepted":
            entry["catalog_id"] = catalogs.catalog_id(items.strict_loads(judged)["catalog"])
        entry["expected"] = expected
        cases.append(entry)

    case("journal Catalog signed by an owner key", sign("owner", "catalog", base), "accepted")
    case("journal Catalog signed by the journal key", sign("journal", "catalog", base), "accepted")
    case("store Catalog signed by the store key", sign("store", "catalog", store), "accepted")
    case("store Catalog signed by an owner key", sign("owner", "catalog", store), "accepted")
    case("implicit default Catalog signed by an owner key", sign("owner", "catalog", default), "accepted", "implicit")
    case("journal Catalog signed by the store key", sign("store", "catalog", base), "WIST1-E02")
    case("store Catalog signed by the journal key", sign("journal", "catalog", store), "WIST1-E02")
    case("journal Catalog signed by a recovery key", sign("recovery", "catalog", base), "WIST1-E02")
    case("Catalog of another publisher signed by an owner key of this Declaration",
         sign("owner", "catalog", changed(base, ["publisher"], "blog.example.com")), "WIST1-E02")
    case("implicit default Catalog signed by the journal key", sign("journal", "catalog", default), "WIST1-E02",
         "implicit")
    forged = sign("journal", "catalog", base)
    forged["sig"]["value"] = sign("journal", "catalog", store)["sig"]["value"]
    case("journal Catalog whose signature is over other octets", forged, "WIST1-E01")

    for label, instant, signer, expected in (
            ("generated_at equal to the journal key's nbf", "2026-09-01T00:00:00Z", "journal", "accepted"),
            ("generated_at one second before the journal key's nbf", "2026-08-31T23:59:59Z", "journal", "WIST1-E02"),
            ("generated_at one second before the journal key's exp", "2026-11-30T23:59:59Z", "journal", "accepted"),
            ("generated_at equal to the journal key's exp", "2026-12-01T00:00:00Z", "journal", "WIST1-E02"),
            ("generated_at one second after the journal key's exp", "2026-12-01T00:00:01Z", "journal", "WIST1-E02"),
            ("generated_at equal to the journal key's exp, signed by an owner key", "2026-12-01T00:00:00Z", "owner",
             "accepted")):
        case(label, sign(signer, "catalog", changed(base, ["generated_at"], instant)), expected, clock=instant)

    at_bound = stamp(seconds(CLOCK) + 600)
    case("generated_at at the clock plus clock_skew_seconds",
         sign("owner", "catalog", changed(base, ["generated_at"], at_bound)), "accepted")
    case("generated_at one second beyond the clock plus clock_skew_seconds",
         sign("owner", "catalog", changed(base, ["generated_at"], stamp(seconds(CLOCK) + 601))), "WIST1-E06")
    case("generated_at at the clock under clock_skew_seconds 0", sign("owner", "catalog", base), "accepted",
         parameters={"clock_skew_seconds": 0})
    case("generated_at one second beyond the clock under clock_skew_seconds 0",
         sign("owner", "catalog", changed(base, ["generated_at"], stamp(seconds(CLOCK) + 1))), "WIST1-E06",
         parameters={"clock_skew_seconds": 0})
    case("generated_at at the clock plus clock_skew_seconds, the clock a fraction later",
         sign("owner", "catalog", changed(base, ["generated_at"], at_bound)), "accepted",
         clock="2026-10-01T12:00:00.5Z")
    case("generated_at one second beyond the allowance of a clock with an offset",
         sign("owner", "catalog", changed(base, ["generated_at"], stamp(seconds(CLOCK) + 601))), "WIST1-E06",
         clock="2026-10-01T14:00:00+02:00")

    raised = {"catalog_items_max": 16777217}
    case("size at a catalog_items_max amended above its value",
         sign("owner", "catalog", changed(base, ["size"], 16777217)), "accepted", parameters=raised)
    case("size one above a catalog_items_max amended above its value",
         sign("owner", "catalog", changed(base, ["size"], 16777218)), "WIST1-E04", parameters=raised)
    case("size at the default catalog_items_max", sign("owner", "catalog", changed(base, ["size"], 16777216)),
         "accepted")
    case("size one above the default catalog_items_max",
         sign("owner", "catalog", changed(base, ["size"], 16777217)), "WIST1-E04")
    case("size 0", sign("owner", "catalog", changed(base, ["size"], 0)), "accepted")

    case("collection the Declaration does not name", sign("owner", "catalog", changed(base, ["collection"], "docs")),
         "WIST1-E03")
    case("journal Catalog under a Declaration without collections", sign("owner", "catalog", base), "WIST1-E03",
         "implicit")
    case("default Catalog under a Declaration whose Collections have no default",
         sign("owner", "catalog", changed(base, ["collection"], "default")), "WIST1-E03")

    for version, expected in (("2.0.0", "WIST1-E15"), ("0.9.0", "WIST1-E15"), ("1.2.3", "accepted"),
                              ("1.0", "WIST1-E14"), ("01.0.0", "WIST1-E14"), ("1.0.0-rc.1", "WIST1-E14"),
                              ("v1.0.0", "WIST1-E14")):
        case(f"wist_version {version}", sign("owner", "catalog", changed(base, ["wist_version"], version)), expected)
    envelope = sign("owner", "catalog", base)
    case("Envelope without sig", changed(envelope, ["sig"], REMOVE), "WIST1-E14")
    case("Envelope with an extra member", changed(envelope, ["delta"], {}), "WIST1-E14")
    case("Envelope whose inner member is named delta", {"delta": base, "sig": envelope["sig"]}, "WIST1-E14")
    case("sig with an extra member", changed(envelope, ["sig", "kid"], KID["owner"]), "WIST1-E14")
    case("sig.alg EdDSA", changed(envelope, ["sig", "alg"], "EdDSA"), "WIST1-E14")
    case("sig.key_id a number", changed(envelope, ["sig", "key_id"], 7), "WIST1-E14")
    value = envelope["sig"]["value"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    unused_bit = value[:-1] + alphabet[alphabet.index(value[-1]) | 1]
    assert unused_bit != value and rules.b64u(base64.urlsafe_b64decode(unused_bit + "==")) == value
    case("sig.value with a nonzero unused bit, decoding to the same octets",
         changed(envelope, ["sig", "value"], unused_bit), "WIST1-E14")
    case("sig.value padded", changed(envelope, ["sig", "value"], value + "=="), "WIST1-E14")
    for member in sorted(catalogs.INNER_MEMBERS):
        case(f"catalog without {member}", sign("owner", "catalog", changed(base, [member], REMOVE)), "WIST1-E14")
    case("catalog with an items member", sign("owner", "catalog", changed(base, ["items"], [])), "WIST1-E14")
    for member, label, bad in (
            ("publisher", "uppercase", "Example.com"), ("publisher", "with a trailing dot", "example.com."),
            ("collection", "uppercase", "Journal"), ("collection", "empty", ""),
            ("collection", "with a leading hyphen", "-journal"), ("collection", "of 33 octets", "j" * 33),
            ("generated_at", "with a fraction", "2026-10-01T12:00:00.5Z"),
            ("generated_at", "with offset +00:00", "2026-10-01T12:00:00+00:00"),
            ("generated_at", "with lowercase t", "2026-10-01t12:00:00Z"),
            ("generated_at", "with second 60", "2026-10-01T11:59:60Z"),
            ("generated_at", "on 31 September", "2026-09-31T12:00:00Z"),
            ("generated_at", "a number", 1790856000),
            ("size", "negative", -1), ("size", "fractional", 1.5), ("size", "a string", "2"), ("size", "true", True),
            ("size", "null", None),
            ("root", "without its prefix", base["root"][7:]), ("root", "in uppercase", base["root"].upper()),
            ("tree", "of 63 digits", base["tree"][:-1]), ("tree", "with the hmac-sha256 prefix",
                                                          "hmac-sha256" + base["tree"][6:])):
        case(f"{member} {label}", sign("owner", "catalog", changed(base, [member], bad)), "WIST1-E14")

    text = json.dumps(sign("owner", "catalog", base))
    case("Envelope cut short", None, "WIST1-E05", raw=text[:-1])
    case("size spelled with a leading zero", None, "WIST1-E05", raw=text.replace('"size": 2', '"size": 02'))
    assert text.count('"size": 2,') == 1
    case("size spelled 2", None, "accepted", raw=text)
    for spelling in ("2.0", "2e0"):
        case(f"size spelled {spelling}", None, "accepted", raw=text.replace('"size": 2,', f'"size": {spelling},'))
        assert cases[-1]["catalog_id"] == catalogs.catalog_id(base)
    case("Envelope followed by a second document", None, "WIST1-E05", raw=text + "{}")

    read_cases = []

    def read_case(name, raw, expected):
        octets = raw.encode("utf-8")
        got = catalogs.fetched_catalog_disposition(octets, publisher_of("collections"), CLOCK, CATALOG_PARAMETERS)
        assert got == expected, (name, got, expected)
        read_cases.append({"name": name, "declaration": "collections", "clock": CLOCK,
                           "parameters": CATALOG_PARAMETERS, "octets": len(octets), "catalog_json": raw,
                           "expected": expected})

    compact = rfc8785.dumps(sign("owner", "catalog", base)).decode("utf-8")
    read_bound = catalogs.CATALOG_READ_OCTETS
    read_case("catalog.json of 16 384 octets, a valid Envelope followed by spaces",
              compact + " " * (read_bound - len(compact)), "accepted")
    read_case("catalog.json of 16 385 octets, a valid Envelope followed by spaces: a failed fetch",
              compact + " " * (read_bound + 1 - len(compact)), "failed")
    read_case("catalog.json of 16 385 octets that is not valid JCS input: a failed fetch",
              compact[:-1] + " " * (read_bound + 1 - len(compact) + 1), "failed")
    read_case("catalog.json that is not the JCS serialization of its Envelope", text, "accepted")

    id_cases = []
    empty, _ = catalog_inner([])
    for name, inner in (("journal Catalog", base), ("store Catalog", store), ("empty Collection", empty),
                        ("implicit default Catalog", default)):
        id_cases.append({"name": name, "catalog": inner, "catalog_id": catalogs.catalog_id(inner)})

    return {"note": (
        "ADR-0052 Catalog fields. Each case judges `catalog` (an Envelope) or `catalog_json` (its octets as UTF-8 "
        "text) under the Declaration named by `declaration`, with the validation clock `clock` and `parameters` "
        "(clock_skew_seconds, catalog_items_max). WIST1-E05: octets that are not valid JCS input (here, outside "
        "JSON's grammar). A number's value, not its spelling, decides whether size is an integer: the cases "
        "spelling size 2.0 and 2e0 are accepted and give `catalog_id`, the Catalog ID of their inner object "
        "(JCS serializes the number 2 as 2), equal to that of the twin spelled 2. WIST1-E14: an Envelope other than exactly {catalog, sig}; sig other than exactly "
        "key_id (a string of at most 64 characters), alg Ed25519 and value (canonical base64url of 64 octets); an "
        "inner object other than exactly wist_version (the version spelling of WIST-1 section 3.1), publisher (a "
        "Canonical Host), collection (1 to 32 octets of a-z, 0-9 and -, neither first nor last -), generated_at "
        "(the whole-second literal-Z profile of WIST-3 section 3.1), size (a nonnegative safe integer), root and "
        "tree (sha256: + 64 lowercase hex). WIST1-E15: a major other than 1. WIST1-E04: size above "
        "catalog_items_max. WIST1-E03: a collection the Declaration does not name (a Declaration without "
        "collections names only default). WIST1-E02 / WIST1-E01: the WIST-1 section 5.1 binding check with "
        "generated_at in place of observed_at, over the Declaration history of exactly the Catalog's publisher, "
        "so a Catalog whose publisher is not the Declaration's domain has no candidate: candidates are the entries of `keys` and of the named Collection's "
        "`keys` whose kid equals sig.key_id and whose window holds generated_at (nbf <= generated_at and, with exp, "
        "generated_at < exp); none is WIST1-E02, none verifying the Ed25519 signature over JCS(catalog) is "
        "WIST1-E01. WIST1-E06: generated_at more than clock_skew_seconds after `clock`, compared as exact "
        "instants. Every signed case is signed over its own inner object, so each rejected case fails exactly one "
        "rule, with one exception: a missing or malformed collection is also one the Declaration does not name, "
        "and those cases exercise the ADR's rule that the WIST1-E14 conditions are checked first. id_cases give Catalog ID = sha256: + "
        "hex(SHA-256(JCS(catalog))). read_cases fetch `catalog_json`, the octets of catalog.json as UTF-8 text, "
        "`octets` long, at a pull: an Aggregator reads at most 16 384 octets of catalog.json, and a larger answer "
        "is `failed`, a failed fetch of the Catalog retried as WIST-2 section 7 retries a Feed that cannot be "
        "fetched, neither a refusal nor an acceptance, whatever the octets hold; octets within the bound are judged "
        "as in `cases`, and need only be valid JCS input, not the JCS serialization of the Envelope. "
        + DECLARATIONS_NOTE + " " + KEYS_NOTE),
        "keys": KEYS_MEMBER, "declarations": DECLARATIONS, "cases": cases, "id_cases": id_cases,
        "read_cases": read_cases}


def catalog_order_vectors():
    listed = [page("https://example.com/journal/a", "2026-09-30T10:00:00Z")[0]]
    other_list = listed + [removed("https://example.com/journal/b", "2026-09-30T11:00:00Z")]

    def at(instant, which=listed, **fields):
        inner = catalog_inner(which, generated_at=instant)[0]
        inner.update(fields)
        return inner

    last = at(GENERATED_AT)
    fetched_for = {"publisher": "example.com", "collection": "journal"}
    pull_cases = []
    older = at("2026-09-30T12:00:00Z", other_list)
    for name, previous, fetched, expected, *latest in (
            ("no Catalog accepted before", None, last, "accepted"),
            ("later by one second", last, at("2026-10-01T12:00:01Z"), "accepted"),
            ("later by one day with another list", last, at("2026-10-02T12:00:00Z", other_list), "accepted"),
            ("equal Catalog ID: an idempotent re-serve", last, copy.deepcopy(last), "idempotent"),
            ("equal instant with another Catalog ID", last, at(GENERATED_AT, other_list), "WIST2-E05"),
            ("earlier by one second", last, at("2026-10-01T11:59:59Z"), "WIST2-E05"),
            ("earlier with the list unchanged", last, at("2026-09-01T00:00:00Z"), "WIST2-E05"),
            ("fetched for another Publisher", last, at("2026-10-01T12:00:01Z", publisher="blog.example.com"),
             "WIST2-E04"),
            ("fetched for another Collection", last, at("2026-10-01T12:00:01Z", collection="store"), "WIST2-E04"),
            ("fetched for another Collection with none accepted before", None, at(GENERATED_AT, collection="store"),
             "WIST2-E04"),
            ("the latest Catalog, earlier than the last accepted one: an idempotent re-serve", last,
             copy.deepcopy(older), "idempotent", older),
            ("earlier than the last accepted one with another Catalog ID than the latest Catalog's", last,
             at("2026-09-30T12:00:01Z", other_list), "WIST2-E05", older),
            ("the last accepted Catalog while another is the latest Catalog: an idempotent re-serve", last,
             copy.deepcopy(last), "idempotent", older)):
        latest = latest[0] if latest else previous
        got = catalogs.pull_order(fetched, fetched_for, previous, latest)
        assert got == expected, (name, got)
        pull_cases.append({"name": name, "fetched_for": fetched_for, "last_accepted": previous, "latest": latest,
                           "fetched": fetched, "expected": expected})

    next_cases = []
    for name, clock, served, expected in (
            ("nothing served", "2026-10-01T12:00:00Z", None, "2026-10-01T12:00:00Z"),
            ("nothing served, the clock cut to the whole second", "2026-10-01T12:00:00.999Z", None,
             "2026-10-01T12:00:00Z"),
            ("clock ahead of the served instant", "2026-10-01T12:00:00Z", "2026-10-01T11:00:00Z",
             "2026-10-01T12:00:00Z"),
            ("clock one second ahead of the served instant", "2026-10-01T12:00:00Z", "2026-10-01T11:59:59Z",
             "2026-10-01T12:00:00Z"),
            ("clock with an offset ahead of the served instant", "2026-10-01T14:00:00.25+02:00",
             "2026-10-01T11:00:00Z", "2026-10-01T12:00:00Z"),
            ("served instant equal to the clock", "2026-10-01T12:00:00Z", "2026-10-01T12:00:00Z",
             "2026-10-01T12:00:01Z"),
            ("served instant equal to the clock cut to the whole second", "2026-10-01T12:00:00.5Z",
             "2026-10-01T12:00:00Z", "2026-10-01T12:00:01Z"),
            ("served instant ahead of the clock within the allowance", "2026-10-01T12:00:00Z",
             "2026-10-01T12:05:00Z", "2026-10-01T12:05:01Z"),
            ("served instant one second short of the allowance: the next instant at the allowance",
             "2026-10-01T12:00:00Z", "2026-10-01T12:09:59Z", "2026-10-01T12:10:00Z"),
            ("served instant at the allowance: the next instant one second beyond it", "2026-10-01T12:00:00Z",
             "2026-10-01T12:10:00Z", None),
            ("served instant one second short of the allowance of a clock a fraction later",
             "2026-10-01T12:00:00.999Z", "2026-10-01T12:09:59Z", "2026-10-01T12:10:00Z"),
            ("served instant at the allowance of a clock a fraction later", "2026-10-01T12:00:00.999Z",
             "2026-10-01T12:10:00Z", None),
            ("served instant a day beyond the clock", "2026-10-01T12:00:00Z", "2026-10-02T12:00:00Z", None)):
        got = catalogs.next_generated_at(clock, served, 600)
        assert got == expected, (name, got)
        next_cases.append({"name": name, "clock": clock, "served": served, "clock_skew_seconds": 600,
                           "expected": {"generated_at": got} if got else {"refused": "catalog-instant"}})

    due_cases = []
    served_at = "2026-10-01T12:00:00Z"
    for name, clock, expected in (
            ("clock one second before the served instant plus catalog_refresh_seconds", "2026-10-08T11:59:59Z", False),
            ("clock a fraction before the served instant plus catalog_refresh_seconds", "2026-10-08T11:59:59.999Z",
             False),
            ("clock at the served instant plus catalog_refresh_seconds", "2026-10-08T12:00:00Z", True),
            ("clock a fraction after the served instant plus catalog_refresh_seconds", "2026-10-08T12:00:00.5Z", True),
            ("clock at the served instant plus catalog_refresh_seconds, at an offset", "2026-10-08T14:00:00+02:00",
             True),
            ("clock one second after the served instant plus catalog_refresh_seconds", "2026-10-08T12:00:01Z", True),
            ("clock at the served instant", served_at, False),
            ("no Catalog served: due at any clock", "2026-10-01T12:00:00Z", True)):
        served = None if name.startswith("no Catalog served") else served_at
        got = catalogs.catalog_due(clock, served)
        assert got == expected, (name, got)
        due_cases.append({"name": name, "clock": clock, "served": served,
                          "catalog_refresh_seconds": catalogs.CATALOG_REFRESH_SECONDS, "expected": {"due": got}})

    return {"note": (
        "ADR-0052 Catalog order. pull_cases judge the inner object `fetched`, pulled for the Publisher and "
        "Collection of `fetched_for`, against `last_accepted`, the inner object of that Collection's last "
        "accepted Catalog or null, and `latest`, the inner object of its latest Catalog or null: WIST2-E04 when "
        "fetched.publisher or fetched.collection differs from `fetched_for`; `idempotent` when its Catalog ID "
        "(sha256: + hex(SHA-256(JCS(catalog)))) equals the last accepted one's or the latest one's, replacing "
        "nothing; WIST2-E05 when its generated_at is at or before the last accepted one's and it is no idempotent "
        "re-serve; `accepted` otherwise, the Catalog then replacing the last accepted one. "
        "Only these rules are judged, and each rejected case fails exactly one of them. next_cases give the "
        "generated_at a Publisher signs for a Collection whose served Catalog has generated_at `served` (null when "
        "none is served), at clock `clock` (a Publisher timestamp, WIST-1 section 3.4): the later of the clock cut "
        "to the whole second and served plus one second, as {\"generated_at\": ...}; when that instant is more "
        "than clock_skew_seconds after the clock cut to the whole second, the part that signs refuses, "
        "{\"refused\": \"catalog-instant\"}, and signs nothing. The part that signs reads clock_skew_seconds at its "
        "suite value, 600. due_cases give whether a Catalog of a Collection whose served Catalog has generated_at "
        "`served` is due at clock `clock`, whether or not its list changed: {\"due\": true} once the clock cut to "
        "the whole second is at or after served plus catalog_refresh_seconds, read at its suite value, 604 800 "
        "seconds, whatever a Log has amended, and at any clock when `served` is null, no Catalog being served."),
        "pull_cases": pull_cases, "next_cases": next_cases, "due_cases": due_cases}


POOL = [f"https://example.com/journal/t{i:03d}" for i in range(4000)]
KEY_HEX = {url: items.item_key(url).hex() for url in POOL}


def urls_with(start, count, taken):
    found = [u for u in POOL if KEY_HEX[u].startswith(start) and u not in taken][:count]
    assert len(found) == count, start
    taken.update(found)
    return found


def tree_item(url, index):
    if index % 4 == 3:
        return removed(url, "2026-09-20T08:00:00Z")
    return page(url, "2026-09-20T08:00:00Z")[0]


def emit_node(node, files):
    if "items" in node:
        obj = {"items": node["items"]}
    else:
        obj = {"children": [{"prefix": e["prefix"], "count": e["count"],
                             "file": e.get("file") or "sha256:" + emit_node(e["node"], files)}
                            for e in node["children"]]}
    obj.update(node.get("extra", {}))
    obj = node.get("replace", lambda o: o)(obj)
    octets = node.get("serialize", rfc8785.dumps)(obj)
    digest = hashlib.sha256(octets).hexdigest()
    if not node.get("omit"):
        files[digest] = node.get("stored", octets)
    return digest


def bucket(listed):
    return {"items": list(listed)}


def inner(*entries):
    return {"children": [{"prefix": p, "count": count_of(n), "node": n} for p, n in entries]}


def count_of(node):
    if "items" in node:
        return len(node["items"])
    return sum(e["count"] for e in node["children"])


def tree_catalog(node, listed, **fields):
    files = {}
    digest = emit_node(node, files)
    catalog = {"wist_version": "1.0.0", "publisher": "example.com", "collection": "journal",
               "generated_at": GENERATED_AT, "size": len(listed), "root": items.root_string(listed),
               "tree": "sha256:" + digest}
    catalog.update(fields)
    return catalog, files


def catalog_tree_vectors():
    taken = set()

    def listed_from(urls):
        return items.in_list_order([tree_item(u, i) for i, u in enumerate(urls)])

    root_list = listed_from(urls_with("", 3, taken))
    two_list = listed_from(urls_with("2", 2, taken) + urls_with("5", 1, taken) + urls_with("9", 2, taken))
    three_list = listed_from(urls_with("d0", 2, taken) + urls_with("d7", 1, taken) + urls_with("1", 1, taken)
                             + urls_with("e", 2, taken))
    one_each = listed_from([urls_with(d, 1, taken)[0] for d in tree_files.HEX_DIGITS])
    cases = []

    def case(name, catalog, files, expected_ok, parameters=None):
        parameters = {**TREE_PARAMETERS, **(parameters or {})}
        got = tree_files.walk_disposition(catalog, files, parameters)
        if expected_ok is None:
            assert got == {"refused": "WIST2-E07"}, (name, got)
        else:
            assert got == {"list": [items.item_id(i) for i in expected_ok]}, (name, got)
        cases.append({"name": name, "catalog": catalog, "parameters": parameters, "tree_files": texts(files),
                      "expected": got})

    def reference(listed, capacity, depth_max=tree_files.DEFAULT_PARAMETERS["tree_depth_max"]):
        node = tree_files.plan(listed, capacity, depth_max)
        catalog, files = tree_catalog(node, listed)
        ref_catalog, ref_files = catalog_inner(listed, capacity=capacity, depth_max=depth_max)
        assert catalog == ref_catalog and files == ref_files
        return node, catalog, files

    _, empty_catalog, empty_files = reference([], 16)
    case("empty Collection: one bucket with no Items", empty_catalog, empty_files, [])
    root_node, root_catalog, root_files = reference(root_list, 16)
    case("root bucket", root_catalog, root_files, root_list)
    two_node, two_catalog, two_files = reference(two_list, 2)
    assert "children" in two_node and all("items" in e["node"] for e in two_node["children"])
    case("two levels", two_catalog, two_files, two_list)
    three_node, three_catalog, three_files = reference(three_list, 2)
    assert any("children" in e["node"] for e in three_node["children"])
    case("three levels", three_catalog, three_files, three_list)
    wide_node, wide_catalog, wide_files = reference(one_each, 1)
    assert len(wide_node["children"]) == 16
    case("sixteen children", wide_catalog, wide_files, one_each)

    def mutated(base_node, listed, mutate, parameters=None, **fields):
        node = copy.deepcopy(base_node)
        mutate(node)
        catalog, files = tree_catalog(node, listed, **fields)
        return catalog, files

    def refused(name, base_node, listed, mutate, parameters=None, **fields):
        catalog, files = mutated(base_node, listed, mutate, **fields)
        case(name, catalog, files, None, parameters)

    def omit_first_bucket(node):
        node["children"][0]["node"]["omit"] = True
    refused("tree file unavailable", two_node, two_list, omit_first_bucket)

    file_cap = tree_files.DEFAULT_PARAMETERS["tree_file_cap_bytes"]
    wide_urls = [f"https://example.com/journal/w{i:02d}/" for i in range(16)]
    wide_urls = [u + "x" * (2000 - 2 - len(u)) for u in wide_urls]
    assert all(len(rfc8785.dumps(u)) == 2000 for u in wide_urls)
    wide = items.in_list_order([page(u, "2026-09-20T08:00:00Z", label=f"wide {i}")[0]
                                for i, u in enumerate(wide_urls)])

    def bucket_of(octets):
        listed = copy.deepcopy(wide)
        short = len(rfc8785.dumps({"items": listed}))
        per_item, rest = divmod(octets - short, len(listed))
        for i, item in enumerate(listed):
            listed[i] = padded_to(item, len(rfc8785.dumps(item)) + per_item + (rest if i == 0 else 0))
        listed = items.in_list_order(listed)
        assert len(rfc8785.dumps({"items": listed})) == octets
        return listed

    at_file_cap = bucket_of(file_cap)
    catalog, files = tree_catalog(bucket(at_file_cap), at_file_cap)
    case("bucket of tree_file_cap_bytes octets", catalog, files, at_file_cap)
    above_file_cap = bucket_of(file_cap + 1)
    catalog, files = tree_catalog(bucket(above_file_cap), above_file_cap)
    case("bucket one octet above tree_file_cap_bytes", catalog, files, None)
    catalog, files = tree_catalog(bucket(at_file_cap), at_file_cap)
    case("bucket of tree_file_cap_bytes octets under a tree_file_cap_bytes amended above its value", catalog, files,
         at_file_cap, {"tree_file_cap_bytes": file_cap + 1})
    catalog, files = tree_catalog(bucket(above_file_cap), above_file_cap)
    case("bucket one octet above tree_file_cap_bytes under a tree_file_cap_bytes amended to its size", catalog,
         files, above_file_cap, {"tree_file_cap_bytes": file_cap + 1})
    divided_node, divided_catalog, divided_files = reference(above_file_cap, tree_files.BUCKET_CAPACITY)
    assert "children" in divided_node and all(len(o) <= file_cap for o in divided_files.values())
    case("sixteen Items whose one bucket would exceed tree_file_cap_bytes, divided by the reference writer",
         divided_catalog, divided_files, above_file_cap)

    def swap_stored(node):
        other = rfc8785.dumps({"items": node["children"][1]["node"]["items"]})
        node["children"][0]["node"]["stored"] = other
    refused("tree file with another SHA-256 than its name", two_node, two_list, swap_stored)

    def spaced(node):
        node["children"][0]["node"]["serialize"] = lambda obj: json.dumps(obj).encode("utf-8")
    refused("bucket not in JCS serialization", two_node, two_list, spaced)

    def spaced_root(node):
        node["serialize"] = lambda obj: json.dumps(obj, indent=1).encode("utf-8")
    refused("inner file not in JCS serialization", two_node, two_list, spaced_root)

    def reordered(node):
        node["children"][0]["node"]["serialize"] = lambda obj: (
            b'{"items":[' + b",".join(
                b"{" + b",".join(rfc8785.dumps(k) + b":" + rfc8785.dumps(v) for k, v in reversed(list(i.items())))
                + b"}" for i in obj["items"]) + b"]}")
    refused("bucket with members out of JCS order", two_node, two_list, reordered)

    def count_spelled_as_fraction(node):
        def serialize(obj):
            octets = rfc8785.dumps(obj)
            assert octets.count(b'"count":2,') >= 1
            return octets.replace(b'"count":2,', b'"count":2.0,', 1)
        node["serialize"] = serialize
    refused("inner file spelling a count 2.0", two_node, two_list, count_spelled_as_fraction)

    def second_member(node):
        node["children"][0]["node"]["extra"] = {"count": count_of(node["children"][0]["node"])}
    refused("bucket with a second member", two_node, two_list, second_member)

    def both_members(node):
        node["extra"] = {"items": []}
    refused("inner file with an items member too", two_node, two_list, both_members)

    def unknown_kind(node):
        node["children"][0]["node"]["replace"] = lambda obj: {"entries": obj["items"]}
    refused("tree file whose one member is neither items nor children", two_node, two_list, unknown_kind)

    def items_object(node):
        node["children"][0]["node"]["replace"] = lambda obj: {"items": {str(i): v for i, v in enumerate(obj["items"])}}
    refused("items an object", two_node, two_list, items_object)

    def children_object(node):
        node["replace"] = lambda obj: {"children": {e["prefix"]: e for e in obj["children"]}}
    refused("children an object", two_node, two_list, children_object)

    def entry_member(field, value):
        def mutate(node):
            def replace(obj):
                obj["children"][0][field] = value(obj["children"][0][field])
                return obj
            node["replace"] = replace
        return mutate
    refused("entry count a string", two_node, two_list, entry_member("count", str))
    refused("entry prefix a number", two_node, two_list, entry_member("prefix", int))
    refused("entry file without its sha256: prefix", two_node, two_list, entry_member("file", lambda f: f[7:]))
    refused("entry file in uppercase hexadecimal", two_node, two_list,
            entry_member("file", lambda f: "sha256:" + f[7:].upper()))

    def extra_entry_member(node):
        def replace(obj):
            obj["children"][0]["level"] = 2
            return obj
        node["replace"] = replace
    refused("entry with a member other than prefix, count and file", two_node, two_list, extra_entry_member)

    empty_inner = {"children": []}
    catalog, files = tree_catalog(empty_inner, [])
    case("empty children in a root inner file of an empty Collection", catalog, files, None)

    f_items = urls_with("f", 1, taken)
    seventeen = items.in_list_order(one_each + listed_from(f_items))
    f_pair = [i for i in seventeen if items.item_key(i["url"]).hex().startswith("f")]
    entries = [(d, bucket([i for i in one_each if items.item_key(i["url"]).hex().startswith(d)]))
               for d in tree_files.HEX_DIGITS[:-1]]
    entries += [("f", bucket(f_pair[:1])), ("f", bucket(f_pair[1:]))]
    catalog, files = tree_catalog(inner(*entries), seventeen)
    case("seventeen children, the last prefix repeated", catalog, files, None)

    d4 = listed_from(urls_with("d4", 2, taken))
    others = listed_from(urls_with("3", 2, taken))
    catalog, files = tree_catalog(inner(("3", bucket(others)), ("d", bucket(d4))), others + d4)
    case("root entries of one digit", catalog, files, others + d4)
    catalog, files = tree_catalog(inner(("3", bucket(others)), ("d4", bucket(d4))), others + d4)
    case("root entry prefix two digits longer than the root's", catalog, files, None)

    a0 = listed_from(urls_with("a0", 1, taken))
    b1 = listed_from(urls_with("b1", 1, taken))
    catalog, files = tree_catalog(inner(("a", inner(("a0", bucket(a0)), ("b1", bucket(b1))))), a0 + b1)
    case("inner file prefix not extending its parent's", catalog, files, None)
    catalog, files = tree_catalog(inner(("a", inner(("a0", bucket(a0)))), ("b", inner(("b1", bucket(b1))))),
                                  a0 + b1)
    case("inner files whose prefixes extend their parents'", catalog, files, a0 + b1)

    a_low = listed_from(urls_with("a", 2, taken))
    catalog, files = tree_catalog(inner(("a", bucket(a_low[:1])), ("a", bucket(a_low[1:]))), a_low)
    case("prefix repeated", catalog, files, None)
    catalog, files = tree_catalog(inner(("3", bucket(others)), ("a", bucket(a_low))), others + a_low)
    case("prefixes in ascending order", catalog, files, others + a_low)
    catalog, files = tree_catalog(inner(("a", bucket(a_low)), ("3", bucket(others))), others + a_low)
    case("prefixes out of order", catalog, files, None)
    catalog, files = tree_catalog(inner(("3", bucket(others)), ("A", bucket(a_low))), others + a_low)
    case("prefix with an uppercase digit", catalog, files, None)

    catalog, files = tree_catalog(inner(("3", bucket(others)), ("5", bucket([])), ("a", bucket(a_low))),
                                  others + a_low)
    case("entry count 0 naming an empty bucket", catalog, files, None)

    def counted(node, shifts):
        for entry, shift in zip(node["children"], shifts):
            entry["count"] += shift
        return node
    catalog, files = tree_catalog(counted(inner(("3", bucket(others)), ("a", bucket(a_low))), (1, -1)),
                                  others + a_low)
    case("entry counts disagreeing with the buckets they name, their sum unchanged", catalog, files, None)
    d0 = listed_from(urls_with("d0", 2, taken))
    d7 = listed_from(urls_with("d7", 1, taken))
    e1 = listed_from(urls_with("e1", 1, taken))
    e8 = listed_from(urls_with("e8", 2, taken))
    nested = inner(("d", inner(("d0", bucket(d0)), ("d7", bucket(d7)))),
                   ("e", inner(("e1", bucket(e1)), ("e8", bucket(e8)))))
    nested_list = d0 + d7 + e1 + e8
    catalog, files = tree_catalog(nested, nested_list)
    case("inner files whose counts add up", catalog, files, nested_list)
    catalog, files = tree_catalog(counted(copy.deepcopy(nested), (1, -1)), nested_list)
    case("inner file counts not adding up to the count naming the file, the root's sum unchanged", catalog, files,
         None)

    b_single = listed_from(urls_with("b", 1, taken))
    c_items = listed_from(urls_with("c", 1, taken))
    catalog, files = tree_catalog(inner(("a", bucket(a_low + b_single)), ("c", bucket(c_items))),
                                  a_low + b_single + c_items)
    case("Item key outside its bucket's prefix", catalog, files, None)
    catalog, files = tree_catalog(inner(("a", bucket(a_low)), ("b", bucket(b_single)), ("c", bucket(c_items))),
                                  a_low + b_single + c_items)
    case("every Item key inside its bucket's prefix", catalog, files, a_low + b_single + c_items)

    swapped = [root_list[1], root_list[0], root_list[2]]
    catalog, files = tree_catalog(bucket(swapped), root_list)
    case("bucket keys out of order", catalog, files, None)
    twin = removed(root_list[1]["url"], "2026-09-21T08:00:00Z")
    doubled = root_list[:2] + [twin] + root_list[2:]
    catalog, files = tree_catalog(bucket(doubled), doubled)
    case("two Items of one URL", catalog, files, None)
    catalog, files = tree_catalog(bucket(root_list[:1] + [{"url": 7}] + root_list[2:]), root_list)
    case("bucket element whose url is not a string", catalog, files, None)
    catalog, files = tree_catalog(bucket(root_list[:1] + ["https://example.com/journal/x"] + root_list[2:]),
                                  root_list)
    case("bucket element that is not an object", catalog, files, None)

    depth_max = tree_files.DEFAULT_PARAMETERS["tree_depth_max"]
    deep = root_list[:1]
    deep_key = items.item_key(deep[0]["url"]).hex()

    def chain(bucket_level):
        node = bucket(deep)
        for level in range(bucket_level - 1, 0, -1):
            node = inner((deep_key[:level], node))
        return node

    catalog, files = tree_catalog(chain(depth_max), deep)
    case("bucket at level tree_depth_max below a chain of inner files", catalog, files, deep)
    catalog, files = tree_catalog(chain(depth_max + 1), deep)
    case("inner file at level tree_depth_max", catalog, files, None)
    catalog, files = tree_catalog(chain(depth_max + 1), deep)
    case("inner file at level tree_depth_max under a tree_depth_max amended above its value", catalog, files, deep,
         {"tree_depth_max": depth_max + 1})

    catalog, files = tree_catalog(bucket(root_list), root_list, size=len(root_list) + 1)
    case("size one above the number of Items listed", catalog, files, None)
    catalog, files = tree_catalog(bucket(root_list), root_list, root=items.root_string(root_list[:2]))
    case("root other than the root of the list", catalog, files, None)

    return {"note": (
        "ADR-0052 tree files. Each case walks the tree of `catalog` (an inner object; size, root and tree are read) "
        "with `parameters` (tree_file_cap_bytes, tree_depth_max) over `tree_files`, a map from the 64-digit hex "
        "SHA-256 naming each served file to the file's octets as UTF-8 text; a name absent from the map is an "
        "unavailable file. `expected` is {\"list\": [Item IDs in walk order]} or {\"refused\": \"WIST2-E07\"}. "
        "The walk starts at the file named by tree, prefix \"\", level 1, counted by size. A file is refused when "
        "unavailable, above tree_file_cap_bytes octets, of another SHA-256 than its name, not the JCS "
        "serialization of the one-member object it parses to, or of a member other than items or children. A "
        "bucket's items is an array of objects with a string url, keys (SHA-256(JCS([\"page\", url]))) strictly "
        "ascending, each key's lowercase hex beginning with the bucket's prefix, as many as the count naming it. "
        "An inner file is not at level tree_depth_max; its children is an array of 1 to 16 objects of exactly "
        "prefix (the file's prefix and one lowercase hex digit), count (an integer of at least 1) and file "
        "(sha256: + 64 lowercase hex naming the child), prefixes strictly ascending, counts adding up to the count "
        "naming the file; children are walked in order, one level down. The Items of the buckets in walk order are "
        "the list; it must hold size Items and its root (WIST-3 section 4 over the leaves SHA-256(0x00 || key || "
        "SHA-256(JCS(item)))) must equal root. Each refused case is a twin of an accepted one differing in the "
        "named respect; where one respect necessarily breaks a second rule, the walk refuses at the first it "
        "meets (seventeen children also repeat a prefix; prefixes out of order and bucket keys out of order also "
        "change the root of the list; an uppercase prefix digit leaves no key in its subtree beginning with it; "
        "size above the Items listed also breaks the root file's count). A count spelled 2.0 has the value 2 and "
        "is refused only because the file's octets are not the JCS serialization of its object. Where a tree divides is the Publisher's "
        "choice; the walk reads the tree as served. tree_file_cap_bytes and tree_depth_max are not amended below "
        "65 536 and 16, so each case supplies those values or values amended above them. The reference writer "
        "divides a bucket that lists more than 16 Items or whose file would exceed tree_file_cap_bytes, down to "
        "tree_depth_max; the case of sixteen Items of 2 000-octet URLs is a tree it wrote."),
        "cases": cases}


def catalog_item_vectors():
    listing = [
        (page("https://example.com/journal/a", "2026-09-30T10:00:00Z")[0], "accepted",
         "inside the journal's Scope"),
        (page("https://blog.example.com/journal/h", "2026-09-30T10:00:00Z")[0], "accepted",
         "inside the journal's Scope on a subdomain_scope host"),
        (page("https://example.com/about", "2026-09-30T10:00:00Z")[0], "WIST1-E03", "outside every Scope"),
        (page("https://example.com/store/c", "2026-09-30T10:00:00Z")[0], "WIST1-E03",
         "inside the store's Scope"),
        (removed("https://example.com/journal/d", "2026-09-30T11:00:00Z"), "accepted",
         "removed, inside the journal's Scope"),
        (removed("https://example.com/about-us", "2026-09-30T11:00:00Z"), "WIST1-E03", "removed, outside every Scope"),
        (removed("https://example.com/cart", "2026-09-30T11:00:00Z"), "WIST1-E03",
         "removed, equal to the store's exact entry"),
        (page("https://blog.example.com/journal/g", "2026-09-30T10:00:00Z", publisher="blog.example.com")[0],
         "WIST2-E03", "another publisher"),
    ]
    cases = []

    def case(name, label, envelope, files, expected_catalog, per_item=None, clock=CLOCK):
        publisher = publisher_of(label)
        got = catalogs.catalog_disposition(envelope, publisher, clock, PULL_PARAMETERS)
        assert got == expected_catalog, (name, got)
        expected = {"catalog": got}
        if got == "accepted":
            walked = tree_files.walk(envelope["catalog"], files, PULL_PARAMETERS)
            outcomes = []
            for item in walked:
                disposition = items.item_disposition(item, envelope["catalog"], publisher, PULL_PARAMETERS)
                assert disposition == per_item[item["url"]], (name, item["url"], disposition)
                outcomes.append({"url": item["url"], "item_id": items.item_id(item), "expected": disposition})
            expected["items"] = outcomes
        cases.append({"name": name, "declaration": label, "clock": clock, "parameters": PULL_PARAMETERS,
                      "catalog": envelope, "tree_files": texts(files), "expected": expected})

    journal_items = [i for i, _, _ in listing]
    outcomes = {i["url"]: o for i, o, _ in listing}
    journal, journal_files = catalog_inner(journal_items)
    case("journal Catalog signed by the journal key", "collections", sign("journal", "catalog", journal),
         journal_files, "accepted", outcomes)
    case("journal Catalog signed by an owner key", "collections", sign("owner", "catalog", journal),
         journal_files, "accepted", outcomes)
    store_listing = [
        (page("https://example.com/store/c", "2026-09-30T10:00:00Z")[0], "accepted"),
        (page("https://example.com/cart", "2026-09-30T10:00:00Z")[0], "accepted"),
        (page("https://example.com/journal/a", "2026-09-30T10:00:00Z")[0], "WIST1-E03"),
        (removed("https://example.com/store/gone", "2026-09-30T11:00:00Z"), "accepted"),
        (removed("https://blog.example.com/journal/h", "2026-09-30T11:00:00Z"), "WIST1-E03"),
        (removed("https://example.com/about", "2026-09-30T11:00:00Z"), "WIST1-E03")]
    store, store_files = catalog_inner([i for i, _ in store_listing], "store")
    case("store Catalog signed by the store key", "collections", sign("store", "catalog", store), store_files,
         "accepted", {i["url"]: o for i, o in store_listing})
    default_listing = [
        (page("https://www.example.com/a", "2026-09-30T10:00:00Z")[0], "accepted"),
        (page("https://example.com/journal/a", "2026-09-30T10:00:00Z")[0], "accepted"),
        (page("https://shop.example.com/a", "2026-09-30T10:00:00Z")[0], "WIST1-E03"),
        (removed("https://blog.example.com/b", "2026-09-30T11:00:00Z"), "accepted"),
        (removed("https://example.org/b", "2026-09-30T11:00:00Z"), "WIST1-E03")]
    default, default_files = catalog_inner([i for i, _ in default_listing], "default")
    case("implicit default Catalog signed by an owner key", "implicit", sign("owner", "catalog", default),
         default_files, "accepted", {i["url"]: o for i, o in default_listing})
    case("journal Catalog signed by the store key", "collections", sign("store", "catalog", journal), journal_files,
         "WIST1-E02")
    bound = item_bound(PULL_PARAMETERS)
    long_url = "https://example.com/journal/long-" + "x" * 2020
    assert len(rfc8785.dumps(long_url)) > PULL_PARAMETERS["url_cap_bytes"]
    sized_listing = [
        (page("https://example.com/journal/a", "2026-09-30T10:00:00Z")[0], "accepted"),
        (padded_to(page("https://example.com/journal/at-bound", "2026-09-30T10:00:00Z")[0], bound), "accepted"),
        (padded_to(page("https://example.com/journal/above-bound", "2026-09-30T10:00:00Z")[0], bound + 1),
         "WIST1-E04"),
        (removed(long_url, "2026-09-30T11:00:00Z"), "accepted"),
        (page(long_url + "-page", "2026-09-30T10:00:00Z")[0], "WIST1-E11")]
    sized, sized_files = catalog_inner([i for i, _ in sized_listing])
    case("journal Catalog listing Items at and above the Item bound and above url_cap_bytes", "collections",
         sign("journal", "catalog", sized), sized_files, "accepted", {i["url"]: o for i, o in sized_listing})
    docs, docs_files = catalog_inner(journal_items, "docs")
    case("Catalog naming a Collection the Declaration lacks", "collections", sign("owner", "catalog", docs),
         docs_files, "WIST1-E03")

    return {"note": (
        "ADR-0052 Items of a signed Catalog, in the positions ADR-0051's Verification gives a publication. Each "
        "case judges the Catalog Envelope `catalog` under the Declaration named by `declaration`, at `clock` and "
        "under `parameters`, as vectors/wist1/catalog-fields.json does; `expected.catalog` is `accepted` or the "
        "code refusing the Catalog whole, in which case no Item is judged. For an accepted Catalog the list is "
        "walked from `tree_files` as vectors/wist2/catalog-tree.json does (every walk here succeeds), and "
        "`expected.items` gives, in list order, each Item's url, Item ID and outcome under the Item conditions "
        "of ADR-0052 (vectors/wist1/item-fields.json): `accepted` or its code. A refused Item stays in the list "
        "and its leaf in the root, and the other Items proceed: a page Item one octet above 16 384 + url_cap_bytes "
        "octets of JCS(item) is WIST1-E04 beside one at that bound, and a removed Item whose JCS(url) is above "
        "url_cap_bytes is accepted beside a page Item that is WIST1-E11. " + DECLARATIONS_NOTE + " " + KEYS_NOTE),
        "keys": KEYS_MEMBER, "declarations": DECLARATIONS, "cases": cases}


def item_list_vectors():
    parameters = dict(ITEM_PARAMETERS)
    generated = GENERATED_AT
    cases = []

    def served_of(pairs):
        listed, payloads = [], {}
        for item, payload in pairs:
            listed.append(item)
            if payload is not None:
                payloads[items.item_id(item)] = payload
        return items.in_list_order(listed), payloads

    def case(name, served_pairs, publications, expected_list, generated_at=generated, signs=True,
             wist_version="1.0.0", removals=()):
        served, payloads = served_of(served_pairs)
        salts = [{"url": p["url"], "salt": salt_for("fresh " + p["url"])} for p in publications]
        got = items.derive_list(served, payloads, publications, publisher_of("collections"), "journal",
                                generated_at, {s["url"]: s["salt"] for s in salts}, wist_version, parameters,
                                removals=removals)
        if signs:
            assert "refused" not in got, name
            assert got["list"] == items.in_list_order(expected_list), (name, got["list"], expected_list)
        else:
            assert got == {"refused": "item-instant"}, (name, got)
        cases.append({"name": name, "declaration": "collections", "collection": "journal",
                      "generated_at": generated_at, "wist_version": wist_version, "parameters": parameters,
                      "served": {"list": served, "payloads": payloads}, "publications": publications,
                      "removals": list(removals), "salts": salts, "expected": got})

    def fresh(p, wist_version="1.0.0"):
        return items.new_page_item("example.com", p, salt_for("fresh " + p["url"]), wist_version)[0]

    a_url, b_url, c_url = ("https://example.com/journal/a", "https://example.com/journal/b",
                           "https://example.com/journal/c")
    a = page(a_url, "2026-09-01T08:00:00Z")
    pub_a = publication(a_url, "2026-09-01T08:00:00Z")
    case("a new URL", [], [pub_a], [fresh(pub_a)])
    case("unchanged publication keeps the served Item and its Payload", [a], [pub_a], [a[0]])
    later_a = publication(a_url, "2026-09-30T08:00:00Z")
    case("publication whose modified alone changed keeps the served Item", [a], [later_a], [a[0]])
    changed_a = publication(a_url, "2026-09-30T08:00:00Z", extract="Text of a, revised.")
    case("publication whose content changed", [a], [changed_a], [fresh(changed_a)])
    lang_a = publication(a_url, "2026-09-30T08:00:00Z", lang="en-GB")
    case("publication whose lang alone changed", [a], [lang_a], [fresh(lang_a)])
    case("served page Item without a publication becomes removed at generated_at", [a], [],
         [removed(a_url, generated)])
    foreign = page(a_url, "2026-09-01T08:00:00Z", publisher="blog.example.com")
    case("served page Item of another publisher becomes removed under the Publisher's domain", [foreign], [],
         [removed(a_url, generated)])
    case("served page Item whose Payload the signing part does not hold: a new Item", [(a[0], None)], [pub_a],
         [fresh(pub_a)])
    case("held Payload with another salt, not reproducing the commitment: a new Item",
         [(a[0], changed(a[1], ["salt"], salt_for("another salt")))], [pub_a], [fresh(pub_a)])
    longer = changed(a[0], ["payload", "bytes"], a[0]["payload"]["bytes"] + 1)
    assert longer["payload"]["bytes"] == len(rfc8785.dumps(a[1]["content"])) + 1
    case("served Item declaring one octet more than JCS(content) of its held Payload: a new Item",
         [(longer, a[1])], [pub_a], [fresh(pub_a)])
    case("held Payload of a major version the validator does not implement: a new Item",
         [(a[0], changed(a[1], ["wist_version"], "2.0.0"))], [pub_a], [fresh(pub_a)])
    case("served page Item of another publisher with an equal publication: a new Item", [foreign], [pub_a],
         [fresh(pub_a)])
    foreign_removed = removed(a_url, "2026-09-20T00:00:00Z", publisher="blog.example.com")
    case("served removed Item of another publisher without a publication becomes removed at generated_at",
         [(foreign_removed, None)], [], [removed(a_url, generated)])
    case("served removed Item of another publisher with a publication: a new Item", [(foreign_removed, None)],
         [pub_a], [fresh(pub_a)])
    case("new Item's Payload carries the Catalog's wist_version", [], [pub_a], [fresh(pub_a, "1.2.0")],
         wist_version="1.2.0")
    end = seconds(generated) - 180 * DAY
    kept = removed(b_url, stamp(end + 1))
    case("removed Item one second before the retention end is kept", [(kept, None)], [], [kept])
    at_end = removed(b_url, stamp(end))
    case("removed Item at the retention end is dropped", [(at_end, None)], [], [])
    offset_kept = removed(b_url, "2026-04-04T13:00:01+01:00")
    assert items.instant(offset_kept["observed_at"]) == end + 1
    case("removed Item one second before the retention end, observed_at at an offset", [(offset_kept, None)], [],
         [offset_kept])
    fraction_at = removed(b_url, stamp(end - 1)[:-1] + ".999Z")
    case("removed Item whose retention ended a thousandth of a second before generated_at is dropped", [(fraction_at, None)], [], [])
    again = publication(b_url, "2026-09-30T09:00:00Z")
    case("a removed URL published again", [(removed(b_url, "2026-09-15T00:00:00Z"), None)], [again], [fresh(again)])
    outside = page("https://example.com/store/x", "2026-09-01T08:00:00Z")
    outside_removed = removed("https://example.com/about", "2026-09-20T00:00:00Z")
    case("served Items outside the Collection's Scope: the page Item becomes removed at generated_at, the removed "
         "Item is kept", [outside, (outside_removed, None)], [],
         [removed(outside[0]["url"], generated), outside_removed])
    outside_ended = removed("https://example.com/about", stamp(end))
    case("served removed Item outside the Collection's Scope at the retention end is dropped",
         [(outside_ended, None)], [], [])
    e_url = "https://example.com/journal/e"
    case("URL a removal names with no publication and no served Item becomes removed at generated_at", [], [],
         [removed(e_url, generated)], removals=[e_url])
    served_gone = removed(e_url, "2026-09-15T00:00:00Z")
    case("URL a removal names with a served removed Item keeps the served Item", [(served_gone, None)], [],
         [served_gone], removals=[e_url])
    case("URL a removal names with a served page Item becomes removed at generated_at", [a], [],
         [removed(a_url, generated)], removals=[a_url])
    case("URL a removal names with a served removed Item at the retention end is dropped", [(at_end, None)], [],
         [], removals=[b_url])
    case("URL a removal names outside the Collection's Scope becomes removed at generated_at", [], [],
         [removed("https://example.com/store/y", generated)], removals=["https://example.com/store/y"])
    c = page(c_url, "2026-09-02T08:00:00Z")
    d_url = "https://blog.example.com/journal/d"
    pub_d = publication(d_url, "2026-09-29T00:00:00Z")
    case("every row at once",
         [a, c, outside, (removed(b_url, "2026-09-15T00:00:00Z"), None), (at_end | {"url": d_url + "-old"}, None)],
         [later_a, pub_d, publication(b_url, "2026-09-30T09:00:00Z")],
         [a[0], removed(c_url, generated), removed(outside[0]["url"], generated), fresh(pub_d),
          fresh(publication(b_url, "2026-09-30T09:00:00Z")), removed(e_url, generated)], removals=[e_url])
    future = publication(c_url, "2026-10-01T12:00:01Z")
    case("publication whose modified is later than generated_at: no Catalog is signed", [a], [pub_a, future], [],
         signs=False)
    case("publication whose modified equals generated_at", [a], [pub_a, publication(c_url, generated)],
         [a[0], fresh(publication(c_url, generated))])

    return {"note": (
        "ADR-0052 From publications to Items, for the Collection `collection` under the Declaration named by "
        "`declaration`. Inputs: the served list `served.list` with `served.payloads` (the Payload of each served "
        "page Item, keyed by Item ID), the publications a stream's application leaves ({url, lang, modified, "
        "content}, ADR-0050), `removals`, the URLs the removals of an incremental stream name, the Catalog's "
        "`generated_at` and `wist_version`, `parameters` (the size caps url_cap_bytes, extract_cap_bytes, "
        "links_cap_bytes, link_url_cap_bytes and summary_cap_bytes those Payload checks read, at their suite "
        "values, since the part that signs reads no Log's parameters) and `salts`, the salt a new Item for that url "
        "takes. removal_retention_days is the constant 180 and is read from no parameter map. The publications lie "
        "inside the Collection's Scope; a served Item outside it has no publication and the served rows below "
        "decide it. A served Item whose "
        "publisher is not the Publisher's domain is read as a page Item whose Payload is not held. The first row "
        "a served Item, publication or removed URL meets decides: a publication whose url has a "
        "served page Item with meta.lang equal to its lang and a held Payload that passes WIST-1 section 7's Payload "
        "checks against the Item's payload (the Payload's form and version spelling, WIST1-E14; a supported major, "
        "WIST1-E15; the caps under `parameters`, WIST1-E04; JCS(content) exactly payload.bytes octets and "
        "HMAC-SHA256(salt, JCS(content)) equal to payload.commitment, WIST1-E10; the links rules of WIST-1 "
        "section 3.6, WIST1-E12) and whose JCS(content) equals its content "
        "yields that Item and Payload unchanged; any other publication yields a new page Item {publisher: the "
        "Publisher's domain, url, observed_at: modified, payload: {commitment: hmac-sha256: + "
        "hex(HMAC-SHA256(salt, JCS(content))), alg: HMAC-SHA256, bytes: octets of JCS(content)}, meta: {lang}} and "
        "the Payload {wist_version: the Catalog's wist_version, salt, content}; a served page Item whose url has no publication yields "
        "{publisher: the Publisher's domain, url, observed_at: generated_at, removed: true}; a served removed Item whose url has no "
        "publication is kept unchanged while generated_at is earlier than its observed_at plus "
        "180 days of 86 400 seconds, compared as exact instants, and yields nothing from then on; a url of "
        "`removals` with no publication and no served Item yields {publisher: the Publisher's domain, url, "
        "observed_at: generated_at, removed: true}, whether or not the Collection's Scope covers it. "
        "A served page Item whose Payload is absent from served.payloads does not meet the second row. The "
        "Publisher's domain is the Declaration's `domain`. `expected` is {list (ascending octet order of key), "
        "payloads (keyed by Item ID)}, or {\"refused\": \"item-instant\"} when an Item of the new list has an "
        "observed_at later than generated_at, in which case nothing is published. "
        + DECLARATIONS_NOTE + " " + KEYS_NOTE),
        "keys": KEYS_MEMBER, "declarations": DECLARATIONS, "cases": cases}


write_json(WIST1 / "item-fields.json", item_field_vectors())
write_json(WIST1 / "item-roots.json", item_root_vectors())
write_json(WIST1 / "catalog-fields.json", catalog_field_vectors())
write_json(WIST2 / "catalog-order.json", catalog_order_vectors())
write_json(WIST2 / "catalog-tree.json", catalog_tree_vectors())
write_json(WIST2 / "catalog-items.json", catalog_item_vectors())
write_json(WIST2 / "item-lists.json", item_list_vectors())
print("catalog vectors written")
