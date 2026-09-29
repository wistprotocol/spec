#!/usr/bin/env python3
import calendar
import copy
import json
import pathlib
import time

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import collection_rules as rules
import narrowing

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIST1 = ROOT / "vectors" / "wist1"
WIST2 = ROOT / "vectors" / "wist2"

KEY_NAMES = ("owner", "owner2", "recovery", "recovery2", "fresh", "journal", "journal2",
             "store", "store2", "docs")
SEEDS = {name: bytes([0xC1 + i]) * 32 for i, name in enumerate(KEY_NAMES)}
PRIVATE = {name: Ed25519PrivateKey.from_private_bytes(seed) for name, seed in SEEDS.items()}
X = {name: rules.b64u(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                    serialization.PublicFormat.Raw))
     for name, key in PRIVATE.items()}
KID = {name: rules.thumbprint(x) for name, x in X.items()}
KEYS_MEMBER = {name: {"seed_hex": SEEDS[name].hex(), "x": X[name], "kid": KID[name]} for name in KEY_NAMES}


def seconds(instant):
    return calendar.timegm(time.strptime(instant, "%Y-%m-%dT%H:%M:%SZ"))


NBF = seconds("2026-09-01T00:00:00Z")
T0 = seconds("2026-10-01T00:00:00Z")
HOUR = 3600
DAY = 86400
PROBE_INSTANT = "2026-10-01T12:00:00Z"
DEFAULTS = dict(rules.DEFAULT_PARAMETERS)
HISTORY_DEFAULTS = {**DEFAULTS, "recovery_window_days": 7, "declaration_activation_epochs": 24}
RECORD_SEAL_EPOCHS = 24
PROBE_NOTE = ("A probe is an Envelope in WIST-1 section 4's form whose inner member `probe` is "
              "{publisher, collection, url, instant}, signed over its Canonical Bytes; it stands for the "
              "Collection's signed list in these fixtures and is no protocol object. `instant` takes the "
              "place of `observed_at` in the binding windows of WIST-1 section 5.1.")


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


def declaration(seq=0, predecessor=None, subdomain_scope=("www.example.com", "blog.example.com"),
                keys=("owner",), recovery_keys=("recovery",), collections=None, contact=None, next_keys=None):
    inner = {"wist_version": "1.0.0", "seq": seq, "domain": "example.com"}
    if predecessor is not None:
        inner["prev_declaration"] = rules.declaration_hash(predecessor)
    if subdomain_scope is not None:
        inner["subdomain_scope"] = list(subdomain_scope)
    inner["keys"] = [key(k) if isinstance(k, str) else k for k in keys]
    if recovery_keys is not None:
        inner["recovery_keys"] = [key(k) if isinstance(k, str) else k for k in recovery_keys]
    if next_keys is not None:
        inner["next_keys"] = next_keys
    if collections is not None:
        inner["collections"] = collections
    if contact is not None:
        inner["contact"] = contact
    return inner


def successor(predecessor, **fields):
    inner = copy.deepcopy(predecessor)
    inner["seq"] = predecessor["seq"] + 1
    inner["prev_declaration"] = rules.declaration_hash(predecessor)
    for member, value in fields.items():
        if value is None:
            inner.pop(member, None)
        else:
            inner[member] = value
    return inner


def probe(signer, collection_name, url, instant=PROBE_INSTANT, key_id=None):
    return sign(signer, "probe", {"publisher": "example.com", "collection": collection_name,
                                  "url": url, "instant": instant}, key_id)


def timestamp(value):
    return narrowing.log_timestamp(value)


JOURNAL = collection("journal", [prefix("https://example.com/journal/")], [key("journal")])
STORE = collection("store", [prefix("https://example.com/store/"), exact("https://example.com/cart")],
                   [key("store")])
BASE = declaration(collections=[JOURNAL, STORE])


def field_vectors():
    cases = []

    def case(name, inner, expected, parameters=None, signer="owner"):
        parameters = {**DEFAULTS, **(parameters or {})}
        envelope = sign(signer, "publisher", inner)
        got = rules.declaration_disposition(envelope, parameters)
        assert got == expected, (name, got, expected)
        cases.append({"name": name, "parameters": parameters, "envelope": envelope, "expected": expected})
        return envelope

    def with_collections(collections, **fields):
        inner = declaration(collections=collections)
        inner.update(fields)
        return inner

    def mutated(path, value=None, remove=False):
        inner = copy.deepcopy(BASE)
        target = inner
        for part in path[:-1]:
            target = target[part]
        if remove:
            del target[path[-1]]
        else:
            target[path[-1]] = value
        return inner

    case("without collections", declaration(), "accepted")
    case("two Collections", BASE, "accepted")
    case("default named beside other Collections",
         with_collections([JOURNAL, STORE, collection("default", [prefix("https://www.example.com/")])]),
         "accepted")
    case("Collection without keys", with_collections([collection("journal", JOURNAL["scope"])]), "accepted")
    case("Collection with empty keys", with_collections([collection("journal", JOURNAL["scope"], [])]),
         "accepted")
    case("one Collection of one entry", with_collections([collection("a", [exact("https://example.com/")])]),
         "accepted")
    sixteen = [collection(f"c{i:02d}", [prefix(f"https://example.com/c{i:02d}/")]) for i in range(1, 16)]
    thirty_two = collection("c16", [prefix(f"https://example.com/c16/e{j:02d}") for j in range(1, 33)])
    case("sixteen Collections, one of thirty-two entries", with_collections(sixteen + [thirty_two]), "accepted")
    case("seventeen Collections", with_collections(
        sixteen + [thirty_two, collection("c17", [prefix("https://example.com/c17/")])]), "WIST1-E16")
    case("thirty-three entries in one Scope", with_collections(
        sixteen[:1] + [collection("c16", thirty_two["scope"] + [exact("https://example.com/c16/e33")])]),
        "WIST1-E16")
    raised = {"collections_max": 24, "scope_entries_max": 48}
    twenty_three = [collection(f"c{i:02d}", [prefix(f"https://example.com/c{i:02d}/")]) for i in range(1, 24)]
    forty_eight = collection("c24", [prefix(f"https://example.com/c24/e{j:02d}") for j in range(1, 49)])
    case("raised bounds: twenty-four Collections, one of forty-eight entries",
         with_collections(twenty_three + [forty_eight]), "accepted", raised)
    case("raised bounds: seventeen Collections", with_collections(
        sixteen + [thirty_two, collection("c17", [prefix("https://example.com/c17/")])]), "accepted", raised)
    case("raised bounds: thirty-three entries in one Scope", with_collections(
        sixteen[:1] + [collection("c16", thirty_two["scope"] + [exact("https://example.com/c16/e33")])]),
        "accepted", raised)
    case("raised bounds: twenty-five Collections", with_collections(
        twenty_three + [forty_eight, collection("c25", [prefix("https://example.com/c25/")])]), "WIST1-E16", raised)
    case("raised bounds: forty-nine entries in one Scope", with_collections(
        twenty_three + [collection("c24", forty_eight["scope"] + [exact("https://example.com/c24/e49")])]),
        "WIST1-E16", raised)

    case("empty collections", with_collections([]), "WIST1-E14")
    case("collections an object", with_collections({"journal": JOURNAL}), "WIST1-E14")
    case("collections null", mutated(["collections"], None), "WIST1-E14")
    case("empty scope", mutated(["collections", 0, "scope"], []), "WIST1-E14")
    case("scope entry a string", mutated(["collections", 0, "scope"], ["https://example.com/journal/"]),
         "WIST1-E14")
    case("unknown member in a Collection", mutated(["collections", 0, "title"], "Journal"), "WIST1-E14")
    case("unknown member in an entry", mutated(["collections", 0, "scope", 0, "note"], "x"), "WIST1-E14")
    case("entry without match", mutated(["collections", 0, "scope", 0, "match"], remove=True), "WIST1-E14")
    case("Collection without name", mutated(["collections", 0, "name"], remove=True), "WIST1-E14")
    case("Collection keys null", mutated(["collections", 0, "keys"], None), "WIST1-E14")
    case("Collection key whose kid is not its thumbprint",
         mutated(["collections", 0, "keys", 0, "kid"], KID["store"]), "WIST1-E14")
    for label, name, expected in (
            ("name empty", "", "WIST1-E14"),
            ("name of one octet", "a", "accepted"),
            ("name of 32 octets", "j" * 32, "accepted"),
            ("name of 33 octets", "j" * 33, "WIST1-E14"),
            ("name uppercase", "Journal", "WIST1-E14"),
            ("name with a leading hyphen", "-journal", "WIST1-E14"),
            ("name with a trailing hyphen", "journal-", "WIST1-E14"),
            ("name with an inner hyphen and digits", "journal-2026", "accepted"),
            ("name with an underscore", "my_journal", "WIST1-E14"),
            ("name a number", 7, "WIST1-E14")):
        case(label, mutated(["collections", 0, "name"], name), expected)
    case("repeated name", mutated(["collections", 1, "name"], "journal"), "WIST1-E16")
    case("match of another value", mutated(["collections", 0, "scope", 0, "match"], "suffix"), "WIST1-E14")
    for label, url in (
            ("entry url with an uppercase host", "https://EXAMPLE.com/journal/"),
            ("entry url with an explicit :443", "https://example.com:443/journal/"),
            ("entry url with a dot segment", "https://example.com/news/../journal/"),
            ("entry url with a fragment", "https://example.com/journal/#top"),
            ("entry url with a lowercase escape", "https://example.com/journal/a%2fb"),
            ("entry url with an empty path", "https://example.com"),
            ("entry url with no Normalized URL", "https://example.com/journal/%zz"),
            ("entry url over http", "http://example.com/journal/")):
        case(label, mutated(["collections", 0, "scope", 0, "url"], url), "WIST1-E14")
    at_cap = "https://example.com/journal/" + "a" * (2046 - len("https://example.com/journal/"))
    assert len(rfc8785.dumps(at_cap)) == 2048
    case("entry url whose JCS is exactly url_cap_bytes", mutated(["collections", 0, "scope", 0, "url"], at_cap),
         "accepted")
    case("entry url whose JCS is one octet above url_cap_bytes",
         mutated(["collections", 0, "scope", 0, "url"], at_cap + "a"), "WIST1-E14")
    case("entry host outside the authority", mutated(["collections", 0, "scope", 0, "url"],
                                                     "https://example.org/journal/"), "WIST1-E16")
    case("entry host a subdomain outside subdomain_scope",
         mutated(["collections", 0, "scope", 0, "url"], "https://shop.example.com/"), "WIST1-E16")
    case("entry host inside subdomain_scope", mutated(["collections", 0, "scope", 0, "url"],
                                                      "https://blog.example.com/"), "accepted")
    case("entry url with a port other than 443", mutated(["collections", 0, "scope", 0, "url"],
                                                         "https://example.com:8443/app/"), "accepted")

    def sized(contact_length, total):
        entries = [prefix(f"https://example.com/archive/{i:02d}-" + "x" * 1900) for i in range(32)]
        inner = with_collections([collection("archive", entries)], contact="mailto:" + "a" * (contact_length - 7))
        remaining = total - rules.entry_octets(sign("owner", "publisher", inner))
        for entry in entries:
            grow = min(remaining, 2046 - len(entry["url"]))
            entry["url"] += "x" * grow
            remaining -= grow
        assert remaining == 0
        assert rules.entry_octets(sign("owner", "publisher", inner)) == total
        return inner

    at_bound = sized(200, 65535)
    case("publisher_declaration Entry of exactly 65 535 octets", at_bound, "accepted")
    above = copy.deepcopy(at_bound)
    above["contact"] += "a"
    assert rules.entry_octets(sign("owner", "publisher", above)) == 65536
    case("publisher_declaration Entry of 65 536 octets", above, "WIST1-E04")

    return {"note": ("ADR-0051 Collections: the form, count and size rules of a Declaration's `collections` "
                     "member. Each case validates `envelope` under `parameters` (collections_max, "
                     "scope_entries_max, url_cap_bytes), a map that amends neither count below 16 and 32; `expected` is "
                     "`accepted` or the rejection code. "
                     "Entry size is the octet length of JCS({\"type\": \"publisher_declaration\", \"body\": "
                     "envelope}) (WIST-3 section 3.3). An entry's host is compared without its port. Each "
                     "rejected case fails exactly one rule, so no precedence among codes is exercised. Keys "
                     "derive from the stated test-only seeds."),
            "keys": KEYS_MEMBER, "cases": cases}


SCOPE_DECLARATION = declaration(collections=[
    collection("journal", [prefix("https://example.com/blog")], [key("journal")]),
    collection("pages", [exact("https://example.com/"), exact("https://example.com/about"),
                         exact("https://example.com/~team"), exact("https://example.com/files/a%2Fb")]),
    collection("sub", [prefix("https://blog.example.com/")], [key("store")]),
])
IMPLICIT_DECLARATION = declaration(subdomain_scope=("www.example.com",))
PORT_DECLARATION = declaration(collections=[
    collection("site", [prefix("https://example.com/")]),
    collection("app", [prefix("https://example.com:8443/app/")])])


def scope_vectors():
    signed = sign("owner", "publisher", SCOPE_DECLARATION)
    implicit = sign("owner", "publisher", IMPLICIT_DECLARATION)
    ported = sign("owner", "publisher", PORT_DECLARATION)
    assert rules.declaration_disposition(ported, DEFAULTS) == "accepted"
    coverage_cases = []
    for envelope, name, url, covered, why in (
            (ported, "app", "https://example.com:8443/app/x", True, "an entry with a port covers URLs with that port"),
            (ported, "app", "https://example.com/app/x", False, "coverage compares the port with the rest of the URL"),
            (ported, "site", "https://example.com:8443/x", False, "a prefix entry without a port does not cover a URL with one"),
            (ported, "site", "https://example.com:443/x", True, "an explicit :443 is no port after normalization"),
            (signed, "journal", "https://example.com/blog", True, "a prefix entry covers its own URL"),
            (signed, "journal", "https://example.com/blogs", True, "prefix compares octets, not path segments"),
            (signed, "journal", "https://example.com/blog?p=1", True, "prefix reads no query"),
            (signed, "journal", "https://example.com/blog/2026/post", True, "a longer path"),
            (signed, "journal", "https://example.com/blo", False, "shorter than the entry"),
            (signed, "journal", "https://example.com/Blog", False, "path case is significant"),
            (signed, "journal", "https://EXAMPLE.COM/blog/x", True, "host case is settled by normalization"),
            (signed, "pages", "https://example.com/", True, "the home page as an exact entry"),
            (signed, "pages", "https://example.com", True, "an empty path normalizes to the home page"),
            (signed, "pages", "https://example.com/index.html", False, "exact covers that URL alone"),
            (signed, "pages", "https://example.com/about", True, "exact covers its URL"),
            (signed, "pages", "https://example.com/about?x=1", False, "exact does not cover the URL with a query"),
            (signed, "pages", "https://example.com/about/", False, "exact does not cover a longer path"),
            (signed, "pages", "https://example.com/%7eteam", True, "an unreserved escape is decoded by normalization"),
            (signed, "pages", "https://example.com/files/a%2fb", True, "escape hex is uppercased by normalization"),
            (signed, "pages", "https://example.com/files/a/b", False, "a decoded reserved octet is another URL"),
            (signed, "pages", "https://example.com:443/about", True, "an explicit :443 is removed by normalization"),
            (signed, "journal", "https://example.com/blog/%zz", False, "a URL with no Normalized URL is covered by nothing"),
            (signed, "sub", "https://blog.example.com/any", True, "a prefix entry on a subdomain_scope host"),
            (signed, "pages", "https://example.com/blog", False, "covered by another Collection only"),
            (signed, "default", "https://www.example.com/", False, "a Declaration with collections has no implicit default"),
            (implicit, "default", "https://www.example.com/x", True, "implicit default covers a subdomain_scope host"),
            (implicit, "default", "https://example.com/anything?q", True, "implicit default covers the domain"),
            (implicit, "default", "https://shop.example.com/x", False, "a host outside subdomain_scope"),
            (implicit, "default", "https://example.org/x", False, "another domain"),
            (implicit, "journal", "https://example.com/x", False, "no Collection of that name")):
        got = rules.coverage(envelope["publisher"], name, url)
        assert got == covered, (name, url)
        coverage_cases.append({"name": why, "declaration": envelope, "collection": name, "url": url,
                               "covered": covered})

    disjointness_cases = []

    def pair(label, first, second, expected):
        for order, collections in (("", [first, second]), (", reversed", [second, first])):
            envelope = sign("owner", "publisher", declaration(collections=collections))
            got = rules.declaration_disposition(envelope, DEFAULTS)
            assert got == expected, (label, got)
            disjointness_cases.append({"name": label + order, "parameters": DEFAULTS,
                                       "envelope": envelope, "expected": expected})

    pair("prefix covering prefix", collection("a", [prefix("https://example.com/blog/")]),
         collection("b", [prefix("https://example.com/blog/2026/")]), "WIST1-E16")
    pair("prefix covering prefix by octets", collection("a", [prefix("https://example.com/blog")]),
         collection("b", [prefix("https://example.com/blog-archive/")]), "WIST1-E16")
    pair("prefix covering exact", collection("a", [prefix("https://example.com/shop/")]),
         collection("b", [exact("https://example.com/shop/cart")]), "WIST1-E16")
    pair("exact equal to exact", collection("a", [exact("https://example.com/about")]),
         collection("b", [exact("https://example.com/about")]), "WIST1-E16")
    pair("exact equal to a prefix entry's URL", collection("a", [exact("https://example.com/docs")]),
         collection("b", [prefix("https://example.com/docs")]), "WIST1-E16")
    pair("overlap in a later entry", collection("a", [prefix("https://example.com/a/"), exact("https://example.com/x")]),
         collection("b", [prefix("https://example.com/b/"), prefix("https://example.com/x")]), "WIST1-E16")
    pair("sibling prefixes", collection("a", [prefix("https://example.com/blog/")]),
         collection("b", [prefix("https://example.com/blog-archive/")]), "accepted")
    pair("exact entry not covered by a longer prefix", collection("a", [exact("https://example.com/shop")]),
         collection("b", [prefix("https://example.com/shop/")]), "accepted")
    pair("same path on two hosts", collection("a", [prefix("https://example.com/")]),
         collection("b", [prefix("https://www.example.com/")]), "accepted")
    pair("same host on another port", collection("a", [prefix("https://example.com/")]),
         collection("b", [prefix("https://example.com:8443/")]), "accepted")
    within = sign("owner", "publisher", declaration(collections=[
        collection("a", [prefix("https://example.com/blog/"), exact("https://example.com/blog/post"),
                         prefix("https://example.com/blog/")]),
        collection("b", [prefix("https://example.com/shop/")])]))
    assert rules.declaration_disposition(within, DEFAULTS) == "accepted"
    disjointness_cases.append({"name": "entries of one Collection cover each other and repeat",
                               "parameters": DEFAULTS, "envelope": within, "expected": "accepted"})

    publication_cases = []
    for label, envelope, signer, name, url, expected in (
            ("inside its Scope", signed, "owner", "journal", "https://example.com/blog/post", "accepted"),
            ("inside its Scope on a subdomain_scope host", signed, "owner", "sub", "https://blog.example.com/p", "accepted"),
            ("outside every Scope", signed, "owner", "journal", "https://example.com/shop/item", "WIST1-E03"),
            ("across: inside another Collection's Scope", signed, "owner", "journal", "https://example.com/about", "WIST1-E03"),
            ("across: the home page under the journal", signed, "owner", "journal", "https://example.com/", "WIST1-E03"),
            ("url not a Normalized URL", signed, "owner", "journal", "https://EXAMPLE.com/blog/post", "WIST1-E03"),
            ("a Collection the Declaration does not name", signed, "owner", "store", "https://example.com/blog/post", "WIST1-E03"),
            ("a Collection the Declaration does not name, signed by a key no source lists", signed, "docs", "store",
             "https://example.com/blog/post", "WIST1-E02"),
            ("inside a Scope whose entry carries a port", ported, "owner", "app", "https://example.com:8443/app/x", "accepted"),
            ("same path without the port is outside that Scope", ported, "owner", "app", "https://example.com/app/x", "WIST1-E03"),
            ("implicit default on a subdomain_scope host", implicit, "owner", "default", "https://www.example.com/x", "accepted"),
            ("implicit default outside the authority", implicit, "owner", "default", "https://shop.example.com/x", "WIST1-E03")):
        envelope_probe = probe(signer, name, url)
        got = rules.publication_disposition(envelope, envelope_probe)
        assert got == expected, (label, got)
        publication_cases.append({"name": label, "declaration": envelope, "probe": envelope_probe,
                                  "expected": expected})

    return {"note": ("ADR-0051 Scope. coverage_cases give whether the named Collection's Scope in `declaration` "
                     "covers `url` after normalizing it (WIST-1 section 2); a URL with no Normalized URL and a "
                     "Collection the Declaration does not name cover nothing. A host is compared without its "
                     "port; coverage compares the port with the rest of the URL. disjointness_cases validate "
                     "`envelope` under `parameters`. publication_cases judge `probe` against `declaration`: the "
                     "WIST-1 section 5.1 binding check, then the Scope rule; `url` must already be a Normalized "
                     "URL. " + PROBE_NOTE),
            "keys": KEYS_MEMBER, "coverage_cases": coverage_cases, "disjointness_cases": disjointness_cases,
            "publication_cases": publication_cases}


JOURNAL_EXP = seconds("2026-12-01T00:00:00Z")
KEYS_DECLARATION = declaration(collections=[
    collection("journal", [prefix("https://example.com/journal/")], [key("journal", exp=JOURNAL_EXP)]),
    collection("store", [prefix("https://example.com/store/")], [key("store")]),
])


def key_vectors():
    uniqueness_cases = []
    for label, inner, expected in (
            ("every key once", KEYS_DECLARATION, "accepted"),
            ("one key twice within a Collection", declaration(collections=[
                collection("journal", [prefix("https://example.com/journal/")], [key("journal"), key("journal")])]),
             "WIST1-E08"),
            ("one key twice within a Collection, windows differing", declaration(collections=[
                collection("journal", [prefix("https://example.com/journal/")],
                           [key("journal"), key("journal", exp=JOURNAL_EXP)])]), "WIST1-E08"),
            ("one key in two Collections", declaration(collections=[
                collection("journal", [prefix("https://example.com/journal/")], [key("journal")]),
                collection("store", [prefix("https://example.com/store/")], [key("journal")])]), "WIST1-E08"),
            ("one key in a Collection and in keys", declaration(collections=[
                collection("journal", [prefix("https://example.com/journal/")], [key("owner")])]), "WIST1-E08"),
            ("one key in a Collection and in recovery_keys", declaration(collections=[
                collection("journal", [prefix("https://example.com/journal/")], [key("recovery")])]), "WIST1-E08")):
        envelope = sign("owner", "publisher", inner)
        got = rules.declaration_disposition(envelope, DEFAULTS)
        assert got == expected, (label, got)
        uniqueness_cases.append({"name": label, "parameters": DEFAULTS, "envelope": envelope, "expected": expected})

    signed = sign("owner", "publisher", KEYS_DECLARATION)
    publication_cases = []

    def publication(label, envelope_probe, expected):
        got = rules.publication_disposition(signed, envelope_probe)
        assert got == expected, (label, got)
        publication_cases.append({"name": label, "declaration": signed, "probe": envelope_probe,
                                  "expected": expected})

    journal_url, store_url = "https://example.com/journal/one", "https://example.com/store/one"
    publication("owner key for the journal", probe("owner", "journal", journal_url), "accepted")
    publication("owner key for the store", probe("owner", "store", store_url), "accepted")
    publication("journal key for the journal", probe("journal", "journal", journal_url), "accepted")
    publication("store key for the store", probe("store", "store", store_url), "accepted")
    publication("store key for the journal", probe("store", "journal", journal_url), "WIST1-E02")
    publication("journal key for the store", probe("journal", "store", store_url), "WIST1-E02")
    publication("recovery key for the journal", probe("recovery", "journal", journal_url), "WIST1-E02")
    publication("journal key for a Collection the Declaration does not name",
                probe("journal", "docs", journal_url), "WIST1-E02")
    publication("journal key at its nbf", probe("journal", "journal", journal_url, "2026-09-01T00:00:00Z"),
                "accepted")
    publication("journal key before its nbf", probe("journal", "journal", journal_url, "2026-08-31T23:59:59Z"),
                "WIST1-E02")
    publication("journal key just before its exp",
                probe("journal", "journal", journal_url, "2026-11-30T23:59:59.999Z"), "accepted")
    publication("journal key at its exp", probe("journal", "journal", journal_url, "2026-12-01T00:00:00Z"),
                "WIST1-E02")
    publication("journal key after its exp", probe("journal", "journal", journal_url, "2027-01-01T00:00:00Z"),
                "WIST1-E02")
    nines, zeros = "9" * 5000, "0" * 5000
    publication("journal key a fraction of 5 000 digits before its exp",
                probe("journal", "journal", journal_url, f"2026-11-30T23:59:59.{nines}Z"), "accepted")
    publication("journal key at its exp with a fraction of 5 000 zero digits",
                probe("journal", "journal", journal_url, f"2026-12-01T00:00:00.{zeros}Z"), "WIST1-E02")
    publication("journal key a fraction of 5 000 digits before its nbf",
                probe("journal", "journal", journal_url, f"2026-08-31T23:59:59.{nines}Z"), "WIST1-E02")
    publication("journal key at its nbf with a fraction of 5 000 zero digits",
                probe("journal", "journal", journal_url, f"2026-09-01T00:00:00.{zeros}Z"), "accepted")
    corrupted = probe("journal", "journal", journal_url)
    corrupted["sig"]["value"] = probe("journal", "journal", journal_url + "x")["sig"]["value"]
    publication("corrupted signature under an eligible journal key", corrupted, "WIST1-E01")
    outside = probe("store", "journal", journal_url, "2027-01-01T00:00:00Z", key_id=KID["journal"])
    publication("journal key out of window, store signature under its kid", outside, "WIST1-E02")

    signer_cases = []

    def signer_case(label, fetched, signer, expected):
        stored = signed
        envelope = sign(signer, "publisher", fetched)
        got = narrowing.evaluate_replacement(stored, envelope, DEFAULTS)
        assert got == expected, (label, got)
        signer_cases.append({"name": label, "stored": stored, "fetched": envelope, "expected": expected})

    moved = successor(KEYS_DECLARATION, keys=[key("owner"), key("journal")], collections=[
        collection("journal", [prefix("https://example.com/journal/")], []),
        collection("store", [prefix("https://example.com/store/")], [key("store")])])
    signer_case("Collection key listed in the incoming keys", moved, "journal", "fresh_identity")
    signer_case("Collection key listed only in an incoming Collection",
                successor(KEYS_DECLARATION, contact="mailto:journal@example.com"), "journal", "WIST1-E02")
    signer_case("Collection key listed nowhere in the incoming Declaration",
                successor(KEYS_DECLARATION, collections=[
                    collection("journal", [prefix("https://example.com/journal/")], [key("journal2")]),
                    collection("store", [prefix("https://example.com/store/")], [key("store")])]),
                "journal", "WIST1-E02")
    signer_case("owner key", successor(KEYS_DECLARATION, contact="mailto:owner@example.com"), "owner",
                "ordinary_rotation")

    fingerprint_cases = []
    for label, inner in (("Declaration with Collection keys", KEYS_DECLARATION),
                         ("Declaration with two owner keys and Collection keys",
                          dict(KEYS_DECLARATION, keys=[key("owner"), key("owner2")]))):
        fingerprint_cases.append({"name": label, "publisher": inner,
                                  "fingerprint": rules.key_set_fingerprint(inner["keys"])})

    committed = dict(KEYS_DECLARATION, next_keys=rules.key_set_fingerprint([key("owner2")]))
    committed_signed = sign("owner", "publisher", committed)
    commitment_cases = []

    def commitment(label, fetched, signer, expected):
        envelope = sign(signer, "publisher", fetched)
        got = narrowing.evaluate_replacement(committed_signed, envelope, DEFAULTS)
        assert got == expected, (label, got)
        commitment_cases.append({"name": label, "stored": committed_signed, "fetched": envelope,
                                 "expected": expected})

    journal_scope = [prefix("https://example.com/journal/")]
    store_scope = [prefix("https://example.com/store/")]
    commitment("keys and commitment kept, a Collection key added", successor(committed, collections=[
        collection("journal", journal_scope, [key("journal", exp=JOURNAL_EXP)]),
        collection("store", store_scope, [key("store"), key("store2")])]), "owner", "ordinary_rotation")
    commitment("keys and commitment kept, a Collection key removed", successor(committed, collections=[
        collection("journal", journal_scope, []),
        collection("store", store_scope, [key("store")])]), "owner", "ordinary_rotation")
    commitment("keys and commitment kept, a Collection key replaced", successor(committed, collections=[
        collection("journal", journal_scope, [key("journal2")]),
        collection("store", store_scope, [key("store")])]), "owner", "ordinary_rotation")
    commitment("committed keys installed, Collection keys replaced", successor(
        committed, keys=[key("owner2")], next_keys=None, collections=[
            collection("journal", journal_scope, [key("journal2")]),
            collection("store", store_scope, [key("store2")])]), "owner", "ordinary_rotation")
    commitment("an owner key added outside the commitment",
               successor(committed, keys=[key("owner"), key("docs")]), "owner", "WIST1-E08")
    commitment("a Collection key moved into keys outside the commitment", successor(
        committed, keys=[key("owner"), key("store")], collections=[
            collection("journal", journal_scope, [key("journal", exp=JOURNAL_EXP)]),
            collection("store", store_scope, [])]), "owner", "WIST1-E08")

    return {"note": ("ADR-0051 keys. uniqueness_cases validate `envelope` under `parameters`. publication_cases "
                     "judge `probe` against `declaration`: candidates are the entries of `keys` and of the named "
                     "Collection's `keys` whose kid equals sig.key_id, time-eligible when nbf <= instant and, with "
                     "exp, instant < exp, compared as exact instants however many fraction digits they carry; none is "
                     "WIST1-E02, none verifying is WIST1-E01, then the Scope rule. "
                     "signer_cases and commitment_cases evaluate `fetched` against the accepted `stored` as "
                     "vectors/wist1/declaration-binding.json does: `expected` is the classification or the "
                     "rejection code. fingerprint_cases give the Key Set fingerprint (WIST-1 section 5.1) of "
                     "`publisher`, which covers `keys` alone. " + PROBE_NOTE),
            "keys": KEYS_MEMBER, "uniqueness_cases": uniqueness_cases, "publication_cases": publication_cases,
            "signer_cases": signer_cases, "fingerprint_cases": fingerprint_cases,
            "commitment_cases": commitment_cases}


def record(collection_name, url):
    return {"url": url, "collection": collection_name}


N_G = declaration(collections=[
    collection("journal", [prefix("https://example.com/journal/")], [key("journal")]),
    collection("store", [prefix("https://example.com/store/")], [key("store")]),
    collection("default", [prefix("https://www.example.com/")])])
J1 = record("journal", "https://example.com/journal/2026/one")
J2 = record("journal", "https://example.com/journal/2025/old")
S1 = record("store", "https://example.com/store/item-1")
D1 = record("default", "https://www.example.com/about")
NARROW_2026 = [collection("journal", [prefix("https://example.com/journal/2026/")], [key("journal")]),
               collection("default", [prefix("https://www.example.com/")])]


def history(name, why, declarations, length, events, removals, sealed_at=None, live=None, **parameters):
    parameters = {**HISTORY_DEFAULTS, **parameters}
    sealed_at = sealed_at or {}
    epochs = []
    for height in range(length):
        labels, records = events.get(height, ([], []))
        epochs.append({"height": height, "sealed_at": timestamp(sealed_at.get(height, T0 + height * HOUR)),
                       "declarations": labels, "records": records})
    signed = {label: sign(signer, "publisher", inner) for label, (signer, inner) in declarations.items()}
    labels = {rules.declaration_hash(envelope["publisher"]): label for label, envelope in signed.items()}
    result = narrowing.replay(
        [dict(e, declarations=[signed[label] for label in e["declarations"]]) for e in epochs],
        parameters["recovery_window_days"], parameters["declaration_activation_epochs"],
        {k: parameters[k] for k in DEFAULTS})
    for epoch in result["epochs"]:
        for member in ("current_declaration", "pending_head"):
            if epoch[member] is not None:
                epoch[member] = labels[epoch[member]]
        for transition in epoch["transitions"]:
            transition["declaration"] = labels[transition["declaration"]]
    observed = {epoch["height"]: [(t["kind"], sorted(r["url"] for r in t["removed"]))
                                  for t in epoch["transitions"] if t["kind"] not in ("initial",)]
                for epoch in result["epochs"]}
    observed = {h: v for h, v in observed.items() if v}
    expected = {h: [(kind, sorted(urls)) for kind, urls in v] for h, v in removals.items()}
    assert observed == expected, (name, observed)
    if live is not None:
        assert [(r["url"], r["collection"]) for r in result["live_records"]] == live, (name, result["live_records"])
    return {"name": name, "why": why, "parameters": parameters, "declarations": signed,
            "epochs": epochs, "expected": result}


def recovery_times(opening_height, heights):
    end = T0 + opening_height * HOUR + 7 * DAY
    return end, {h: end + offset for h, offset in heights.items()}


def narrowing_vectors():
    histories = []
    base_records = ([J1, J2, S1, D1])
    rotated = successor(N_G, collections=NARROW_2026)
    histories.append(history(
        "ordinary rotation narrows at its sealing Epoch",
        "Records the new Scopes no longer cover and records of the dropped store leave at height 2. A record "
        "sealed at height 2 inside the new Scope stays; one outside it is never a record.",
        {"G": ("owner", N_G), "D": ("owner", rotated)}, 4,
        {0: (["G"], base_records), 1: ([], [record("journal", "https://example.com/journal/2025/older")]),
         2: (["D"], [record("journal", "https://example.com/journal/2026/two"),
                     record("journal", "https://example.com/journal/2025/new")]),
         3: ([], [record("store", "https://example.com/store/item-2")])},
        {2: [("ordinary_rotation", [J2["url"], "https://example.com/journal/2025/older", S1["url"]])]}))

    recovered = successor(N_G, keys=[key("owner2")], collections=NARROW_2026)
    end, times = recovery_times(2, {4: -HOUR, 5: 0, 6: HOUR})
    histories.append(history(
        "recovery rotation narrows at settlement, an Epoch exactly at the window's end",
        "The recovery rotation sealed at height 2 removes nothing; height 4 is the last Epoch before the end; "
        "height 5, sealed exactly at the end, settles and narrows.",
        {"G": ("owner", N_G), "R": ("recovery", recovered)}, 7,
        {0: (["G"], base_records), 2: (["R"], []),
         5: ([], [record("journal", "https://example.com/journal/2026/three"),
                  record("store", "https://example.com/store/item-9")])},
        {2: [("recovery_rotation", [])], 5: [("settlement", [J2["url"], S1["url"]])]}, times))
    end, times = recovery_times(2, {4: -HOUR, 5: HOUR})
    histories.append(history(
        "recovery rotation narrows at settlement, the first Epoch after the window's end",
        "No Epoch is sealed at the end itself; height 5, sealed one hour after it, is the first at or after "
        "the end and settles.",
        {"G": ("owner", N_G), "R": ("recovery", recovered)}, 6,
        {0: (["G"], base_records), 2: (["R"], [])},
        {2: [("recovery_rotation", [])], 5: [("settlement", [J2["url"], S1["url"]])]}, times))

    wide_recovery = successor(N_G, keys=[key("owner2")])
    follower = successor(wide_recovery, collections=NARROW_2026)
    competitor = successor(follower, keys=[key("fresh")],
                           collections=[collection("default", [prefix("https://www.example.com/")])])
    end, times = recovery_times(2, {5: 0, 6: HOUR})
    histories.append(history(
        "in-window follower becomes the chain head, in-window competitor superseded",
        "R keeps every Scope; F follows it under R's own key and becomes the chain head; C, a fresh identity "
        "with a narrower Scope, becomes current but removes nothing. Settlement makes F current and narrows by "
        "F's Collections alone: the journal record C would have removed stays.",
        {"G": ("owner", N_G), "R": ("recovery", wide_recovery), "F": ("owner2", follower),
         "C": ("fresh", competitor)}, 7,
        {0: (["G"], base_records), 2: (["R"], []), 3: (["F"], []), 4: (["C"], []),
         6: ([], [record("journal", "https://example.com/journal/2026/four")])},
        {2: [("recovery_rotation", [])], 3: [("in_window_chain", [])], 4: [("in_window_competitor", [])],
         5: [("settlement", [J2["url"], S1["url"]])]}, times))

    fresh = successor(N_G, keys=[key("fresh")], collections=NARROW_2026)
    histories.append(history(
        "fresh identity narrows at its activation height",
        "The fresh identity sealed at height 2 is pending until height 26; a store record sealed at height 3 "
        "under the current Declaration is admitted and leaves at activation.",
        {"G": ("owner", N_G), "P": ("fresh", fresh)}, 28,
        {0: (["G"], base_records), 2: (["P"], []), 3: ([], [record("store", "https://example.com/store/item-3")]),
         26: ([], [record("store", "https://example.com/store/item-4"),
                   record("journal", "https://example.com/journal/2026/five")])},
        {2: [("fresh_identity_pending", [])],
         26: [("activation", [J2["url"], S1["url"], "https://example.com/store/item-3"])]}))
    histories.append(history(
        "fresh identity with declaration_activation_epochs 0 narrows at its sealing Epoch",
        "The activation height is the sealing height: the fresh identity becomes pending and activates in "
        "height 2, and the records sealed there are read under it.",
        {"G": ("owner", N_G), "P": ("fresh", fresh)}, 4,
        {0: (["G"], base_records),
         2: (["P"], [record("store", "https://example.com/store/item-3"),
                     record("journal", "https://example.com/journal/2026/five")])},
        {2: [("fresh_identity_pending", []), ("activation", [J2["url"], S1["url"]])]},
        declaration_activation_epochs=0))

    replacement = successor(fresh, collections=[
        collection("journal", [prefix("https://example.com/journal/")], [key("journal")]),
        collection("store", [prefix("https://example.com/store/")], [key("store")])])
    histories.append(history(
        "pending head replaced before activation",
        "P2 names the pending head P and replaces it without moving the activation height; at height 26 the "
        "replacement's Collections narrow, so only the default record leaves.",
        {"G": ("owner", N_G), "P": ("fresh", fresh), "P2": ("fresh", replacement)}, 28,
        {0: (["G"], base_records), 2: (["P"], []), 5: (["P2"], [])},
        {2: [("fresh_identity_pending", [])], 5: [("pending_replacement", [])],
         26: [("activation", [D1["url"]])]}))

    reversal = successor(fresh, keys=[key("owner")], collections=[
        collection("store", [prefix("https://example.com/store/")], [key("store")]),
        collection("default", [prefix("https://www.example.com/")])])
    reversal["seq"] = 2
    reversal["prev_declaration"] = rules.declaration_hash(N_G)
    histories.append(history(
        "pending head reversed by an ordinary rotation that narrows",
        "V names the current Declaration under an owner key: it reverses the pending head, narrows at its "
        "sealing Epoch by its own Collections, and nothing happens at the discarded activation height.",
        {"G": ("owner", N_G), "P": ("fresh", fresh), "V": ("owner", reversal)}, 28,
        {0: (["G"], base_records), 2: (["P"], []), 4: (["V"], []),
         5: ([], [record("journal", "https://example.com/journal/2026/six")])},
        {2: [("fresh_identity_pending", [])], 4: [("reversal_ordinary_rotation", [J1["url"], J2["url"]])]}))

    histories.append(history(
        "idempotent re-serve removes nothing",
        "Re-serving the current Declaration, before and after a narrowing rotation, installs nothing.",
        {"G": ("owner", N_G), "D": ("owner", rotated)}, 5,
        {0: (["G"], base_records), 1: (["G"], []), 3: (["D"], []), 4: (["D"], [])},
        {1: [("idempotent", [])], 3: [("ordinary_rotation", [J2["url"], S1["url"]])], 4: [("idempotent", [])]}))

    without = successor(N_G, subdomain_scope=["blog.example.com"], collections=None)
    histories.append(history(
        "Declaration without collections following one with them",
        "Records of the named journal and store leave; the default record on www.example.com stays although "
        "the new subdomain_scope drops that host. A record sealed afterwards on that host is outside the "
        "authority.",
        {"G": ("owner", N_G), "W": ("owner", without)}, 4,
        {0: (["G"], base_records),
         2: (["W"], [record("default", "https://www.example.com/new"),
                     record("default", "https://example.com/journal/moved")])},
        {2: [("ordinary_rotation", [J1["url"], J2["url"], S1["url"]])]}))

    plain = declaration()
    dropped_host = successor(plain, subdomain_scope=["blog.example.com"])
    histories.append(history(
        "Declaration without collections following one without them drops a subdomain_scope host",
        "Nothing is removed: under a Declaration without collections a default record stays whatever its host.",
        {"G": ("owner", plain), "W": ("owner", dropped_host)}, 4,
        {0: (["G"], [record("default", "https://www.example.com/a"), record("default", "https://blog.example.com/b"),
                     record("default", "https://example.com/c")]),
         2: (["W"], [record("default", "https://www.example.com/new")])},
        {2: [("ordinary_rotation", [])]}))

    keeps_store = successor(N_G, keys=[key("owner2")], collections=[NARROW_2026[0], N_G["collections"][1],
                                                                    NARROW_2026[1]])
    drops_store = successor(keeps_store, collections=NARROW_2026)
    end, times = recovery_times(2, {5: 0})
    histories.append(history(
        "one Epoch settles a window and seals an ordinary rotation",
        "Height 5 settles R, which narrows the journal, and then applies O, an ordinary rotation naming the "
        "restored R outside any window, which drops the store.",
        {"G": ("owner", N_G), "R": ("recovery", keeps_store), "O": ("owner2", drops_store)}, 6,
        {0: (["G"], base_records), 2: (["R"], []), 5: (["O"], [])},
        {2: [("recovery_rotation", [])], 5: [("settlement", [J2["url"]]), ("ordinary_rotation", [S1["url"]])]},
        times))

    split_scope = declaration(collections=[
        collection("journal", [prefix("https://example.com/j/a/"), prefix("https://example.com/j/b/")])])
    dropped_entry = successor(split_scope, collections=[collection("journal", [prefix("https://example.com/j/b/")])])
    restoring = successor(dropped_entry, keys=[key("owner2")], collections=split_scope["collections"])
    end, times = recovery_times(2, {5: 0})
    histories.append(history(
        "ordinary rotation applied before the recovery rotation of the Epoch that opens a window narrows",
        "Height 2 seals O, an ordinary rotation that drops the /j/a/ entry, and then R, a recovery rotation "
        "naming O that restores it. O is a predecessor of R and sealed outside the window: the /j/a/ record "
        "leaves at height 2 and does not return when settlement makes R current.",
        {"G": ("owner", split_scope), "O": ("owner", dropped_entry), "R": ("recovery", restoring)}, 6,
        {0: (["G"], [record("journal", "https://example.com/j/a/1"), record("journal", "https://example.com/j/b/1")]),
         2: (["O", "R"], [])},
        {2: [("ordinary_rotation", ["https://example.com/j/a/1"]), ("recovery_rotation", [])],
         5: [("settlement", [])]}, times,
        live=[("https://example.com/j/b/1", "journal")]))

    journal_moved = [collection("journal", [prefix("https://example.com/journal/")], []),
                     *copy.deepcopy(N_G["collections"][1:])]
    histories.append(history(
        "Declaration signed by a Collection key outside a recovery window is pending",
        "P lists the journal key in its own keys and is signed by it: neither keys nor recovery_keys of G "
        "list the signer, so P is a fresh identity, pending until height 26.",
        {"G": ("owner", N_G), "P": ("journal", successor(N_G, keys=[key("owner"), key("journal")],
                                                         collections=journal_moved))}, 4,
        {0: (["G"], base_records), 2: (["P"], [])},
        {2: [("fresh_identity_pending", [])]}))
    in_window = successor(wide_recovery, keys=[key("owner2"), key("journal")],
                          collections=[collection("journal", [prefix("https://example.com/journal/2026/")], [])])
    end, times = recovery_times(2, {5: 0})
    histories.append(history(
        "Declaration signed by a Collection key inside a recovery window is a competitor, never pending",
        "C names the recovery rotation R, lists the former journal key in its own keys and is signed by it, "
        "inside the window R opened: a competitor that becomes current, is never a pending head and removes "
        "nothing. Settlement makes R current and removes nothing, since R keeps every Scope.",
        {"G": ("owner", N_G), "R": ("recovery", wide_recovery), "C": ("journal", in_window)}, 6,
        {0: (["G"], base_records), 2: (["R"], []), 3: (["C"], [])},
        {2: [("recovery_rotation", [])], 3: [("in_window_competitor", [])], 5: [("settlement", [])]}, times))

    introduced = successor(plain, collections=[
        collection("default", [exact("https://example.com/about"), prefix("https://example.com/pages/")]),
        collection("journal", [prefix("https://example.com/journal/")], [key("journal")]),
        collection("sub", [prefix("https://blog.example.com/")])])
    histories.append(history(
        "Collections introduced with a named default",
        "Default records the named default still covers stay; a default record on a host no Scope covers, one "
        "the sub Collection covers and one the journal covers leave. The journal URL returns when sealed from "
        "the journal.",
        {"G": ("owner", plain), "I": ("owner", introduced)}, 4,
        {0: (["G"], [record("default", "https://example.com/about"), record("default", "https://www.example.com/x"),
                     record("default", "https://blog.example.com/y"), record("default", "https://example.com/journal/p")]),
         2: (["I"], []), 3: ([], [record("journal", "https://example.com/journal/p")])},
        {2: [("ordinary_rotation", ["https://blog.example.com/y", "https://example.com/journal/p",
                                    "https://www.example.com/x"])]}))

    moving = successor(N_G, collections=[
        collection("journal", [prefix("https://example.com/journal/posts/")], [key("journal")]),
        collection("store", [prefix("https://example.com/store/"), prefix("https://example.com/journal/deals/")],
                   [key("store")]),
        collection("default", [prefix("https://www.example.com/")])])
    histories.append(history(
        "URL moving from one Collection to another",
        "The journal's deals URL is removed with the Declaration and sealed again from the store; the final "
        "live records hold that URL once, in the store.",
        {"G": ("owner", N_G), "M": ("owner", moving)}, 4,
        {0: (["G"], [record("journal", "https://example.com/journal/posts/a"),
                     record("journal", "https://example.com/journal/deals/1"), S1]),
         2: (["M"], []), 3: ([], [record("store", "https://example.com/journal/deals/1")])},
        {2: [("ordinary_rotation", ["https://example.com/journal/deals/1"])]},
        live=[("https://example.com/journal/deals/1", "store"), ("https://example.com/journal/posts/a", "journal"),
              (S1["url"], "store")]))

    return {"note": ("ADR-0051 narrowing over one Publisher's Declaration history. Each history replays `epochs` "
                     "in order; an Epoch lists the labels of the Declaration Envelopes it seals (from "
                     "`declarations`) and the records it seals as {url, collection}. Within an Epoch: settle a "
                     "window whose end is at or before sealed_at, activate a pending head whose activation height "
                     "is this height, apply the Declarations in ascending seq (WIST-1 section 5.2), then read the "
                     "Epoch's records under the Declaration then current: a record outside its Collection's Scope "
                     "is WIST1-E03 and never a record. A narrowing transition removes every live record sealed "
                     "below its height that the Declaration taking effect does not keep. `expected.epochs` give, "
                     "per Epoch after it applies, the current Declaration, the pending head and its activation "
                     "height, the open window's end, the transitions in order with the records each removed, and "
                     "the records sealed and rejected; `expected.live_records` are the records live at the end, "
                     "one per URL. A record is identified by its Publisher and URL and carries its Collection: "
                     "sealing a URL again replaces its record. Lists of records are in ascending octet order of "
                     "url, then collection. `parameters` carry recovery_window_days and declaration_activation_epochs as "
                     "trusted fixture input."),
            "parameter_note": (
                "parameter_histories replay `epochs` as histories do, each Epoch under the `parameters` map in force "
                "at its sealed_at (collections_max, scope_entries_max, url_cap_bytes). `expected.epochs` give the "
                "state after each accepted Epoch as in histories; `expected.rejected` is null, or the height of the "
                "first Epoch whose Declaration fails its checks under that Epoch's map with the code, after which "
                "nothing is replayed."),
            "keys": KEYS_MEMBER, "histories": histories, "parameter_histories": parameter_histories()}


def parameter_history(name, why, declarations, epochs, expected_rejection):
    signed = {label: sign(signer, "publisher", inner) for label, (signer, inner) in declarations.items()}
    labels = {rules.declaration_hash(envelope["publisher"]): label for label, envelope in signed.items()}
    replay = narrowing.Replay(HISTORY_DEFAULTS["recovery_window_days"],
                              HISTORY_DEFAULTS["declaration_activation_epochs"], DEFAULTS)
    written, results, rejected = [], [], None
    for height, (sealed, parameters) in enumerate(epochs):
        parameters = {**DEFAULTS, **(parameters or {})}
        epoch = {"height": height, "sealed_at": timestamp(T0 + height * HOUR), "parameters": parameters,
                 "declarations": list(sealed), "records": []}
        written.append(epoch)
        if rejected is not None:
            continue
        replay.parameters = parameters
        try:
            result = replay.epoch(dict(epoch, declarations=[signed[label] for label in sealed]))
        except narrowing.HistoryRejected as rejection:
            rejected = {"height": height, "code": rejection.code}
            continue
        for member in ("current_declaration", "pending_head"):
            if result[member] is not None:
                result[member] = labels[result[member]]
        for transition in result["transitions"]:
            transition["declaration"] = labels[transition["declaration"]]
        results.append(result)
    assert rejected == expected_rejection, (name, rejected)
    return {"name": name, "why": why, "declarations": signed, "epochs": written,
            "expected": {"epochs": results, "rejected": rejected}}


def parameter_histories():
    twenty = successor(N_G, collections=N_G["collections"] + [
        collection(f"c{i:02d}", [prefix(f"https://example.com/c{i:02d}/")]) for i in range(4, 21)])
    other = successor(twenty, contact="mailto:owner@example.com")
    raised = {"collections_max": 24}
    return [
        parameter_history(
            "Declaration of 20 Collections sealed again under a collections_max lowered from 24 to 16 is idempotent",
            "D, sealed at height 1 under collections_max 24, is current; height 2, under 16, seals D again: an "
            "idempotent re-serve under any parameter map, the Epoch accepted and no state changed.",
            {"G": ("owner", N_G), "D": ("owner", twenty)},
            [(["G"], None), (["D"], raised), (["D"], None)], None),
        parameter_history(
            "another Declaration of 20 Collections sealed under a collections_max lowered from 24 to 16 is WIST1-E16",
            "D, sealed at height 1 under collections_max 24, is current; height 2, under 16, seals E, a successor "
            "of D with 20 Collections, which the lowered count rejects.",
            {"G": ("owner", N_G), "D": ("owner", twenty), "E": ("owner", other)},
            [(["G"], None), (["D"], raised), (["E"], None)], {"height": 2, "code": "WIST1-E16"}),
    ]


def pull_vectors():
    known = sign("owner", "publisher", N_G)
    narrowed = sign("owner", "publisher", successor(N_G, collections=NARROW_2026))
    pending = sign("fresh", "publisher", successor(N_G, keys=[key("fresh")], collections=NARROW_2026))
    repeated = sign("owner", "publisher", successor(N_G, collections=[
        JOURNAL, collection("journal", [prefix("https://example.com/store/")])]))
    pull_cases = []
    for label, held, outcome, fetched, acceptance, pulled in (
            ("new octets: an ordinary rotation that narrows, pulled under the fetched Declaration", known,
             "new_octets", narrowed, "ordinary_rotation", ["journal", "default"]),
            ("new octets: a fresh identity that becomes pending, pulled under the current Declaration", known,
             "new_octets", pending, "fresh_identity", ["journal", "store", "default"]),
            ("new octets: a re-serve of a superseded Declaration", narrowed, "new_octets", known, "WIST1-E08", []),
            ("new octets: a repeated Collection name", known, "new_octets", repeated, "WIST1-E16", []),
            ("same octets", known, "same_octets", known, "idempotent", ["journal", "store", "default"]),
            ("unchanged answer to a conditional request", known, "not_modified", None, "idempotent",
             ["journal", "store", "default"]),
            ("fetch failed", known, "failed", None, "not_fetched", []),
            ("fetch timed out", known, "timed_out", None, "not_fetched", [])):
        got = narrowing.collections_pulled(held, outcome, fetched, DEFAULTS)
        assert got == (acceptance, pulled), (label, got)
        pull_cases.append({"name": label, "known": held, "fetch_outcome": outcome, "fetched": fetched,
                           "acceptance": acceptance, "proceeds": bool(pulled), "collections_pulled": pulled})

    reduction_cases = []
    two_owner = declaration(keys=("owner", "owner2"), collections=copy.deepcopy(N_G["collections"]))
    narrow_journal = declaration(collections=[
        collection("journal", [prefix("https://example.com/journal/2026/")], [key("journal")]),
        collection("store", [prefix("https://example.com/store/"), exact("https://example.com/cart")],
                   [key("store")])])
    plain = declaration()

    def scope_with(journal_entries, store_entries=None):
        return [collection("journal", journal_entries, [key("journal")]),
                collection("store", store_entries or [prefix("https://example.com/store/"),
                                                      exact("https://example.com/cart")], [key("store")])]

    def reduction(label, predecessor, expected, record_seal_epochs=RECORD_SEAL_EPOCHS, **changes):
        fetched = successor(predecessor, **changes)
        p_env, d_env = sign("owner", "publisher", predecessor), sign("owner", "publisher", fetched)
        for envelope in (p_env, d_env):
            assert rules.declaration_disposition(envelope, DEFAULTS) == "accepted", label
        found = rules.authority_reductions(predecessor, fetched)
        assert sorted(found) == sorted(expected), (label, found)
        reduces = bool(found)
        reduction_cases.append({
            "name": label, "predecessor": p_env, "declaration": d_env, "reduces_authority": reduces,
            "reductions": found, "discovery_height": 100, "record_seal_epochs": record_seal_epochs,
            "last_seal_height": rules.last_seal_height(100, record_seal_epochs) if reduces else None})

    reduction("a key added to keys", N_G, [], keys=[key("owner"), key("owner2")])
    expiring = NBF + 180 * DAY
    windowed = declaration(keys=(key("owner"), key("owner2", exp=expiring)),
                           collections=copy.deepcopy(N_G["collections"]))
    reduction("a key window shortened by a later nbf", windowed, ["key_window"],
              keys=[key("owner"), key("owner2", nbf=NBF + DAY, exp=expiring)])
    reduction("a key window shortened by an earlier exp", windowed, ["key_window"],
              keys=[key("owner"), key("owner2", exp=expiring - DAY)])
    reduction("a key window shortened by an exp where the predecessor has none", windowed, ["key_window"],
              keys=[key("owner", exp=expiring), key("owner2", exp=expiring)])
    reduction("a key window widened by an earlier nbf", windowed, [],
              keys=[key("owner"), key("owner2", nbf=NBF - DAY, exp=expiring)])
    reduction("a key window widened by a later exp", windowed, [],
              keys=[key("owner"), key("owner2", exp=expiring + DAY)])
    reduction("a key window widened by removing exp", windowed, [], keys=[key("owner"), key("owner2")])
    reduction("a Collection key window shortened by an exp", N_G, ["key_window"], collections=[
        collection("journal", [prefix("https://example.com/journal/")], [key("journal", exp=expiring)]),
        *copy.deepcopy(N_G["collections"][1:])])
    reduction("a Collection added", N_G, [], collections=N_G["collections"] + [
        collection("docs", [prefix("https://example.com/docs/")], [key("docs")])])
    reduction("a Scope entry added", BASE, [], collections=scope_with(
        [prefix("https://example.com/journal/"), exact("https://example.com/news")]))
    reduction("a key added to a Collection", BASE, [], collections=[
        collection("journal", [prefix("https://example.com/journal/")], [key("journal"), key("journal2")]),
        STORE])
    reduction("contact changed only", N_G, [], contact="mailto:owner@example.com")
    reduction("a subdomain_scope host added", N_G, [],
              subdomain_scope=["www.example.com", "blog.example.com", "shop.example.com"])
    reduction("a key removed from keys", two_owner, ["key"], keys=[key("owner")])
    reduction("a key removed from keys, record_seal_epochs 48", two_owner, ["key"], 48, keys=[key("owner")])
    reduction("a recovery key removed", N_G, ["key"], recovery_keys=[])
    reduction("a recovery key replaced", N_G, ["key"], recovery_keys=[key("recovery2")])
    reduction("a Collection key removed", BASE, ["key"], collections=[
        collection("journal", [prefix("https://example.com/journal/")]), STORE])
    reduction("a key moved from keys to a Collection", two_owner, ["key"], keys=[key("owner")], collections=[
        collection("journal", [prefix("https://example.com/journal/")], [key("journal"), key("owner2")]),
        *copy.deepcopy(N_G["collections"][1:])])
    reduction("a key moved from a Collection to keys", BASE, ["key"], keys=[key("owner"), key("journal")],
              collections=[collection("journal", [prefix("https://example.com/journal/")]), STORE])
    reduction("a key moved between Collections", BASE, ["key"], collections=[
        collection("journal", [prefix("https://example.com/journal/")]),
        collection("store", STORE["scope"], [key("store"), key("journal")])])
    reduction("a Collection removed", BASE, ["key", "collection", "scope_entry"], collections=[JOURNAL])
    reduction("a Collection renamed", BASE, ["key", "collection", "scope_entry"], collections=[
        JOURNAL, collection("shop", STORE["scope"], [key("store")])])
    reduction("a Scope entry removed", BASE, ["scope_entry"], collections=scope_with(
        [prefix("https://example.com/journal/")], [prefix("https://example.com/store/")]))
    reduction("an entry replaced by a wider one", narrow_journal, ["scope_entry"], collections=scope_with(
        [prefix("https://example.com/journal/")]))
    reduction("the same entry with match changed from exact to prefix", BASE, ["scope_entry"],
              collections=scope_with([prefix("https://example.com/journal/")],
                                     [prefix("https://example.com/store/"), prefix("https://example.com/cart")]))
    reduction("the same entry with match changed from prefix to exact", BASE, ["scope_entry"],
              collections=scope_with([exact("https://example.com/journal/")]))
    reduction("implicit default replaced by collections with a named default", plain, ["scope_entry"],
              collections=[collection("default", [prefix("https://example.com/")]),
                           collection("sub", [prefix("https://www.example.com/"), prefix("https://blog.example.com/")])])
    reduction("implicit default replaced by collections without a default", plain, ["collection", "scope_entry"],
              collections=[collection("journal", [prefix("https://example.com/journal/")])])
    reduction("collections dropped", BASE, ["key", "collection", "scope_entry"], collections=None)
    reduction("collections of only a named default dropped", declaration(
        collections=[collection("default", [prefix("https://example.com/")])]), ["scope_entry"], collections=None)
    reduction("a subdomain_scope host removed", plain, ["subdomain_scope"], subdomain_scope=["www.example.com"])
    reduction("a subdomain_scope host removed with collections unchanged", N_G, ["subdomain_scope"],
              subdomain_scope=["www.example.com"])

    state_pull_cases = state_pulls()

    return {"note": ("ADR-0051 reaching the Log. pull_cases: an Aggregator whose current Declaration is `known`, "
                     "with no open recovery window and no pending head, fetches the Declaration at the start of a "
                     "pull and applies `fetched` against `known` under WIST-1 section 5.2; `acceptance` is the "
                     "classification, `idempotent`, the rejection code, or `not_fetched` when the fetch failed or "
                     "timed out. `proceeds` is whether it may pull any Collection of the Publisher, and "
                     "`collections_pulled` names the Collections (implicit default included) of the Declarations "
                     "authorized for admission once `fetched` applied: the fetched one after an ordinary rotation, "
                     "the current one for a re-serve, an unchanged answer or a fresh identity that becomes "
                     "pending, and none after a failed fetch or a rejected Declaration. reduction_cases: whether `declaration` reduces authority "
                     "against the `predecessor` it names, with the ADR's tests that hold (`key`, `key_window`, "
                     "`collection`, `scope_entry`, `subdomain_scope`); `key_window` holds when D lists a key P "
                     "lists in the same member with a later nbf, an earlier exp, or an exp where P has none; when it does, the last height at which its "
                     "publisher_declaration Entry may seal is discovery_height + record_seal_epochs, counted as "
                     "WIST-1 section 5.2 counts a recovery Declaration's deadline, and null otherwise."),
            "state_pull_note": (
                "state_pull_cases: an Aggregator's view of one Publisher when a pull starts. `epochs` are the Epochs "
                "sealed before it, applied as vectors/wist1/collection-narrowing.json applies them, each under the "
                "`parameters` map in force at its sealed_at. `discovered` lists, in discovery order, Declarations "
                "accepted and not yet sealed, applied after the Epochs; one that no longer applies there has left "
                "the eligible sealing set and is skipped. The pull then fetches the Declaration at `pull.sealed_at` "
                "under `pull.parameters`, as the next Epoch at `pull.height` would apply it; `pull.fetched` names the "
                "Declaration the answer carries, for `not_modified` the one the cached validator stands for, and is "
                "null when the fetch failed. `expected.acceptance` is the transition kind of the fetched Declaration "
                "(`recovery_chain_head` for the recovery-chain head of an open window served while another "
                "Declaration is current), the rejection code, or `not_fetched`; `sources` name the Declarations the "
                "pull reads, `collections_pulled` their Collections in pull order, and a pull that does not proceed "
                "carries its `disposition` and whether it is `noise` against the Ping quota (WIST-2 section 4)."),
            "keys": KEYS_MEMBER, "pull_cases": pull_cases, "reduction_cases": reduction_cases,
            "state_pull_cases": state_pull_cases}


def state_pull(name, declarations, epochs, pull, discovered=()):
    signed = {label: sign(signer, "publisher", inner) for label, (signer, inner) in declarations.items()}
    labels = {rules.declaration_hash(envelope["publisher"]): label for label, envelope in signed.items()}
    replay = narrowing.Replay(HISTORY_DEFAULTS["recovery_window_days"],
                              HISTORY_DEFAULTS["declaration_activation_epochs"], DEFAULTS)
    written, at = [], T0 - HOUR
    for height, (sealed, parameters, *explicit) in enumerate(epochs):
        at = explicit[0] if explicit else at + HOUR
        parameters = {**DEFAULTS, **(parameters or {})}
        replay.parameters = parameters
        epoch = {"height": height, "sealed_at": timestamp(at), "declarations": list(sealed), "records": []}
        replay.epoch(dict(epoch, declarations=[signed[label] for label in sealed]))
        written.append(dict(epoch, parameters=parameters))
    height, at = len(epochs), at + HOUR
    pull_parameters = {**DEFAULTS, **(pull.get("parameters") or {})}
    replay.parameters = pull_parameters
    fetched = pull.get("fetched")
    result = narrowing.pull(replay, pull["fetch_outcome"], signed[fetched] if fetched else None, height, at,
                            [signed[label] for label in discovered])
    expected = dict(result, sources=[labels[rules.declaration_hash(p)] for p in result["sources"]])
    for member, value in pull.get("expect", {}).items():
        assert expected[member] == value, (name, member, expected[member])
    return {"name": name, "declarations": signed, "epochs": written, "discovered": list(discovered),
            "pull": {"height": height, "sealed_at": timestamp(at), "parameters": pull_parameters,
                     "fetch_outcome": pull["fetch_outcome"], "fetched": fetched},
            "expected": expected}


def state_pulls():
    cases = []
    docs = collection("docs", [prefix("https://example.com/docs/")], [key("docs")])
    recovery = successor(N_G, keys=[key("owner2")], collections=N_G["collections"] + [docs])
    competitor = successor(recovery, keys=[key("fresh")], collections=NARROW_2026)
    frozen = ["journal", "store", "default", "docs"]
    for outcome in ("new_octets", "not_modified"):
        cases.append(state_pull(
            f"recovery-chain head served again while a competitor is current, {outcome}: a success under the "
            "two frozen sources",
            {"G": ("owner", N_G), "R": ("recovery", recovery), "C": ("fresh", competitor)},
            [(["G"], None), ([], None), (["R"], None), (["C"], None)],
            {"fetch_outcome": outcome, "fetched": "R",
             "expect": {"acceptance": "recovery_chain_head", "sources": ["G", "R"], "collections_pulled": frozen}}))
    cases.append(state_pull(
        "recovery-chain head served again while a competitor is current, the recovery rotation discovered and not "
        "yet sealed: a success under the two frozen sources",
        {"G": ("owner", N_G), "R": ("recovery", recovery), "C": ("fresh", competitor)},
        [(["G"], None)],
        {"fetch_outcome": "new_octets", "fetched": "R",
         "expect": {"acceptance": "recovery_chain_head", "sources": ["G", "R"], "collections_pulled": frozen}},
        discovered=["R", "C"]))
    follower = successor(recovery, contact="mailto:owner@example.com")
    follower_competitor = successor(follower, keys=[key("fresh")], collections=NARROW_2026)
    cases.append(state_pull(
        "recovery-chain head that follows the recovery rotation served again: the sources stay the Declaration "
        "before the recovery and the recovery rotation that owns the window",
        {"G": ("owner", N_G), "R": ("recovery", recovery), "F": ("owner2", follower),
         "C": ("fresh", follower_competitor)},
        [(["G"], None), (["R"], None), (["F"], None), (["C"], None)],
        {"fetch_outcome": "new_octets", "fetched": "F",
         "expect": {"acceptance": "recovery_chain_head", "sources": ["G", "R"]}}))

    twenty = successor(N_G, collections=N_G["collections"] + [
        collection(f"c{i:02d}", [prefix(f"https://example.com/c{i:02d}/")]) for i in range(4, 21)])
    raised = {"collections_max": 24}
    for outcome in ("same_octets", "not_modified"):
        cases.append(state_pull(
            f"current Declaration of 20 Collections served again under a collections_max lowered from 24 to 16, "
            f"{outcome}: idempotent, every Collection pulled",
            {"G": ("owner", N_G), "D": ("owner", twenty)},
            [(["G"], None), (["D"], raised)],
            {"fetch_outcome": outcome, "fetched": "D",
             "expect": {"acceptance": "idempotent", "sources": ["D"],
                        "collections_pulled": [c["name"] for c in twenty["collections"]]}}))
    cases.append(state_pull(
        "Declaration of 20 Collections fetched for the first time under collections_max 16: rejected, no pull",
        {"G": ("owner", N_G), "D": ("owner", twenty)},
        [(["G"], None)],
        {"fetch_outcome": "new_octets", "fetched": "D",
         "expect": {"acceptance": "WIST1-E16", "proceeds": False, "disposition": "WIST2-E01", "noise": False}}))

    cases.append(state_pull(
        "recovery rotation discovered and not yet sealed: pulled under the two frozen sources",
        {"G": ("owner", N_G), "R": ("recovery", recovery)},
        [(["G"], None)],
        {"fetch_outcome": "new_octets", "fetched": "R",
         "expect": {"acceptance": "recovery_rotation", "sources": ["G", "R"], "collections_pulled": frozen}}))
    cases.append(state_pull(
        "Declaration fetched after an unsealed recovery rotation is not read",
        {"G": ("owner", N_G), "R": ("recovery", recovery), "F": ("owner2", successor(recovery, collections=NARROW_2026))},
        [(["G"], None)],
        {"fetch_outcome": "new_octets", "fetched": "F",
         "expect": {"acceptance": "in_window_chain", "sources": ["G", "R"], "collections_pulled": frozen}},
        discovered=["R"]))
    fresh = successor(N_G, keys=[key("fresh")], collections=NARROW_2026)
    reversing = successor(fresh, keys=[key("owner2")], collections=N_G["collections"] + [docs])
    reversing["seq"] = 2
    reversing["prev_declaration"] = rules.declaration_hash(N_G)
    cases.append(state_pull(
        "recovery rotation discovered beside a pending head: pulled under the two frozen sources",
        {"G": ("owner", N_G), "P": ("fresh", fresh), "R": ("recovery", reversing)},
        [(["G"], None), (["P"], None)],
        {"fetch_outcome": "new_octets", "fetched": "R",
         "expect": {"acceptance": "reversal_recovery_rotation", "sources": ["G", "R"], "collections_pulled": frozen}}))
    cases.append(state_pull(
        "pending head served again: pulled under the current Declaration alone",
        {"G": ("owner", N_G), "P": ("fresh", fresh)},
        [(["G"], None), (["P"], None)],
        {"fetch_outcome": "same_octets", "fetched": "P",
         "expect": {"acceptance": "idempotent", "sources": ["G"], "collections_pulled": ["journal", "store", "default"]}}))

    rival = successor(competitor, keys=[key("store2")])
    settles = T0 + 2 * HOUR + 7 * DAY
    cases.append(state_pull(
        "recovery rotation superseded unsealed at settlement: pulled under the settled Declaration",
        {"G": ("owner", N_G), "R": ("recovery", recovery), "C": ("fresh", competitor), "X": ("recovery", rival)},
        [(["G"], None), ([], None), (["R"], None), (["C"], None), ([], None, settles)],
        {"fetch_outcome": "same_octets", "fetched": "R",
         "expect": {"acceptance": "idempotent", "sources": ["R"], "collections_pulled": frozen}},
        discovered=["X"]))

    for label, epochs, outcome, fetched, acceptance, disposition in (
            ("fetch failed at first contact", [], "failed", None, "not_fetched", "WIST2-E04"),
            ("Declaration rejected at first contact", [], "new_octets", "B", "WIST1-E16", "WIST2-E04"),
            ("fetch failed after first contact", [(["G"], None)], "timed_out", None, "not_fetched", "WIST2-E01"),
            ("superseded Declaration served again", [(["G"], None), (["N"], None)], "new_octets", "G", "WIST1-E08",
             "WIST2-E01")):
        cases.append(state_pull(
            f"{label}: the pull stops with {disposition}",
            {"G": ("owner", N_G), "N": ("owner", successor(N_G, collections=NARROW_2026)),
             "B": ("owner", declaration(collections=[JOURNAL, collection("journal", [prefix("https://example.com/store/")])]))},
            epochs, {"fetch_outcome": outcome, "fetched": fetched,
                     "expect": {"acceptance": acceptance, "proceeds": False, "disposition": disposition,
                                "noise": disposition == "WIST2-E04"}}))
    cases.append(state_pull(
        "first contact: pulled under the fetched Declaration",
        {"G": ("owner", N_G)}, [], {"fetch_outcome": "new_octets", "fetched": "G",
                                    "expect": {"acceptance": "initial", "sources": ["G"]}}))
    return cases


write_json(WIST1 / "collection-fields.json", field_vectors())
write_json(WIST1 / "collection-scope.json", scope_vectors())
write_json(WIST1 / "collection-keys.json", key_vectors())
write_json(WIST1 / "collection-narrowing.json", narrowing_vectors())
write_json(WIST2 / "declaration-pull.json", pull_vectors())
print("collection vectors written")
