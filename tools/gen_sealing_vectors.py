#!/usr/bin/env python3
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
import combined_view
import items
import sealing
import served_files
import tree_files

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIST2 = ROOT / "vectors" / "wist2"
WIST3 = ROOT / "vectors" / "wist3"
MULTILOG = ROOT / "vectors" / "multilog"

KEY_NAMES = ("owner", "owner2", "recovery", "recovery2", "fresh", "journal", "journal2",
             "store", "store2", "docs")
USED_KEYS = ("owner", "owner2", "recovery", "fresh", "journal", "journal2", "store", "store2", "docs")
SEEDS = {name: bytes([0xC1 + i]) * 32 for i, name in enumerate(KEY_NAMES)}
PRIVATE = {name: Ed25519PrivateKey.from_private_bytes(SEEDS[name]) for name in USED_KEYS}
X = {name: rules.b64u(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
     for name, key in PRIVATE.items()}
KID = {name: rules.thumbprint(x) for name, x in X.items()}
KEYS_MEMBER = {name: {"seed_hex": SEEDS[name].hex(), "x": X[name], "kid": KID[name]} for name in USED_KEYS}


def seconds(instant):
    return calendar.timegm(time.strptime(instant, "%Y-%m-%dT%H:%M:%SZ"))


def stamp(value):
    return catalogs.log_timestamp(value)


NBF = seconds("2026-09-01T00:00:00Z")
T0 = seconds("2026-10-01T00:00:00Z")
HOUR = 3600
DAY = 86400
OBSERVED = "2026-09-30T10:00:00Z"
J = "https://example.com/journal/"
S = "https://example.com/store/"
BLOG = "blog.example.com"
DEFAULT_MAP = {
    "clock_skew_seconds": 600, "catalog_items_max": 16777216, "catalog_refresh_seconds": 604800,
    "removal_retention_days": 180, "domain_epoch_entries_max": 10000, "url_cap_bytes": 2048,
    "extract_cap_bytes": 32768, "links_cap_bytes": 4096, "link_url_cap_bytes": 2048, "summary_cap_bytes": 2048,
    "collections_max": 16, "scope_entries_max": 32, "recovery_window_days": 7, "declaration_activation_epochs": 24}


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2) + "\n")


def key(name, nbf=NBF, exp=None):
    entry = {"kty": "OKP", "crv": "Ed25519", "x": X[name], "kid": KID[name], "nbf": nbf}
    if exp is not None:
        entry["exp"] = exp
    return entry


def sign(signer, inner_name, inner):
    return {inner_name: inner,
            "sig": {"key_id": KID[signer], "alg": "Ed25519",
                    "value": rules.b64u(PRIVATE[signer].sign(rfc8785.dumps(inner)))}}


def prefix(url):
    return {"url": url, "match": "prefix"}


def collection(name, scope, keys=None):
    out = {"name": name, "scope": scope}
    if keys is not None:
        out["keys"] = keys
    return out


JOURNAL = collection("journal", [prefix(J)], [key("journal")])
STORE = collection("store", [prefix(S)], [key("store")])
G = {"wist_version": "1.0.0", "seq": 0, "domain": "example.com", "subdomain_scope": ["www.example.com"],
     "keys": [key("owner")], "recovery_keys": [key("recovery")], "collections": [JOURNAL, STORE]}
SHOP = "shop.example.net"
H = {"wist_version": "1.0.0", "seq": 0, "domain": SHOP, "keys": [key("store2")]}
B = {"wist_version": "1.0.0", "seq": 0, "domain": BLOG, "keys": [key("docs")],
     "collections": [collection("journal", [prefix("https://blog.example.com/journal/")])]}


def successor(predecessor, **fields):
    inner = copy.deepcopy(predecessor)
    inner["seq"] = predecessor["seq"] + 1
    inner["prev_declaration"] = rules.declaration_hash(predecessor)
    for member, value in fields.items():
        inner[member] = value
    return inner


PAYLOADS = {}
PAYLOADS_NOTE = ("`payloads` maps the Item ID of every Item of kind page the file carries to the Payload its "
                 "`payload` commits to ({wist_version, salt, content}, WIST-1 section 3.6); they are carried so the "
                 "commitments can be recomputed, and the replay reads none of them.")


def with_payloads(vector):
    found = {}

    def walk(node):
        if isinstance(node, dict):
            if set(node) == items.PAGE_MEMBERS and isinstance(node["payload"], dict):
                found[items.item_id(node)] = PAYLOADS[node["payload"]["commitment"]]
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(vector)
    vector["note"] += " " + PAYLOADS_NOTE
    vector["payloads"] = {item_id: found[item_id] for item_id in sorted(found)}
    return vector


def salt_for(label):
    return rules.b64u(hashlib.sha256(("salt " + label).encode()).digest()[:16])


def page(url, label=None, observed_at=OBSERVED, publisher="example.com"):
    label = label or url
    publication = {"url": url, "lang": "en", "modified": observed_at,
                   "content": {"extract": f"Text of {label}.", "links": {"total": 0, "urls": []},
                               "summary": {"title": f"Title {label}"}}}
    made, payload = items.new_page_item(publisher, publication, salt_for(label))
    PAYLOADS[made["payload"]["commitment"]] = payload
    return made


def removed(url, observed_at=OBSERVED, publisher="example.com"):
    return {"publisher": publisher, "url": url, "observed_at": observed_at, "removed": True}


class Cat:
    def __init__(self, listed, generated_at, name="journal", publisher="example.com", capacity=16):
        self.listed = items.in_list_order(listed)
        tree, self.files = tree_files.write_tree(self.listed, capacity)
        self.inner = {"wist_version": "1.0.0", "publisher": publisher, "collection": name,
                      "generated_at": stamp(generated_at), "size": len(self.listed),
                      "root": items.root_string(self.listed), "tree": tree}
        self.id = catalogs.catalog_id(self.inner)

    def with_instant(self, generated_at):
        return Cat(self.listed, generated_at, self.inner["collection"], self.inner["publisher"])


def decl(signer, inner):
    return {"type": "publisher_declaration", "body": sign(signer, "publisher", inner)}


def cat(signer, catalog):
    return {"type": "publisher_catalog", "body": sign(signer, "catalog", catalog.inner)}


def item(catalog, url, **changes):
    listed = next(i for i in catalog.listed if i["url"] == url)
    body = items.publisher_item_body(listed, catalog.inner, catalog.listed)
    for member, value in changes.items():
        body[member] = value
    return {"type": "publisher_item", "body": body}


def at(height, offset=-60):
    return T0 + height * HOUR + offset


def build_epochs(spec):
    epochs = []
    for height, epoch in enumerate(spec):
        named = sorted(epoch.get("entries", []),
                       key=lambda pair: (sealing.ENTRY_GROUPS.index(pair[1]["type"]), sealing.entry_leaf(pair[1])))
        epochs.append({"height": height, "sealed_at": stamp(epoch.get("sealed_at", T0 + height * HOUR)),
                       "parameters": {**DEFAULT_MAP, **epoch.get("parameters", {})},
                       "entries": [{"name": name, "entry": entry} for name, entry in named]})
    return epochs


def expected_disposition(value):
    if value == "valid":
        return {"disposition": "valid"}
    code, failed = value
    return {"disposition": "ignored", "failed": failed, "codes": [code]}


def run(epochs, expect, rejected, label):
    results, state = sealing.replay([{"height": e["height"], "sealed_at": e["sealed_at"],
                                      "parameters": e["parameters"],
                                      "entries": [n["entry"] for n in e["entries"]]} for e in epochs])
    names = {}
    for epoch in epochs:
        for named in epoch["entries"]:
            if named["entry"]["type"] == "publisher_declaration":
                names[rules.declaration_hash(named["entry"]["body"]["publisher"])] = named["name"]
    out = []
    for epoch, result in zip(epochs, results):
        assert (result["status"] == "rejected") == (epoch["height"] in rejected), (label, epoch["height"], result)
        entry = {"height": result["height"], "status": result["status"]}
        if result["status"] == "rejected":
            assert result["code"] == rejected[epoch["height"]], (label, result)
            entry["code"] = result["code"]
        else:
            entry["entries"] = []
            for named, got in zip(epoch["entries"], result["entries"]):
                if got is None:
                    continue
                wanted = expected_disposition(expect[named["name"]])
                assert got == wanted, (label, named["name"], got, wanted)
                entry["entries"].append({"name": named["name"], **got})
            entry["records_removed"] = result["records_removed"]
        declared = result["state"]["declarations"]
        for d in declared:
            for member in ("current", "pending_head"):
                if d[member] is not None:
                    d[member] = names[d[member]]
        entry["state"] = result["state"]
        out.append(entry)
    return out, state


def history(name, why, spec, expect, rejected=None, check=None):
    epochs = build_epochs(spec)
    for epoch in epochs:
        for named in epoch["entries"]:
            if named["entry"]["type"] != "publisher_declaration":
                assert named["name"] in expect, (name, named["name"])
    results, state = run(epochs, expect, rejected or {}, name)
    if check is not None:
        check(results)
    return {"name": name, "why": why, "epochs": epochs, "expected": results}


def records_of(results, height):
    return [(r["url"], r["catalog"]) for r in results[height]["state"]["records"]]


def urls_of(results, height):
    return [r["url"] for r in results[height]["state"]["records"]]


E06 = "WIST3-E06"


def sealing_vectors():
    histories = []
    pa, pb, pc, pd = page(J + "a"), page(J + "b"), page(J + "c"), page(J + "d")

    j1 = Cat([pa, pb], at(1))
    s1 = Cat([page(S + "a", observed_at="2026-09-01T12:00:00Z")], seconds("2026-09-02T00:00:00Z"), "store")

    def first_check(results):
        catalogs_state = results[1]["state"]["catalogs"]
        assert [(c["collection"], c["floor"]) for c in catalogs_state] == [
            ("journal", j1.inner["generated_at"]), ("store", s1.inner["generated_at"])]
        assert urls_of(results, 1) == [J + "a", J + "b", S + "a"]

    histories.append(history(
        "first Catalogs of two names and their Items",
        "Neither name has a floor at height 1: the store Catalog, a month older than the journal's, is valid, "
        "since no rule bounds a first instant from below. Each valid page Item becomes the record of its URL.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", j1)), ("S1", cat("store", s1)), ("a@J1", item(j1, J + "a")),
                      ("b@J1", item(j1, J + "b")), ("sa@S1", item(s1, S + "a"))]}],
        {"J1": "valid", "S1": "valid", "a@J1": "valid", "b@J1": "valid", "sa@S1": "valid"}, check=first_check))

    j2_equal = Cat([pa, pc], at(1))
    j3_earlier = Cat([pa, pd], at(1) - 1)
    j4_later = Cat([pa, pc], at(1) + 1)
    histories.append(history(
        "C3: generated_at against the floor",
        "The floor is J1's generated_at. J2 carries the floor's instant and J3 one second before it (C3); J1 "
        "sealed again carries the floor and J1's root inside catalog_refresh_seconds (C3 and C4). J4 is J2 one "
        "second later and is valid. An Item naming the ignored J2 fails I3; the same Item proved against J4 is "
        "valid.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", j1)), ("a@J1", item(j1, J + "a"))]},
         {"entries": [("J2", cat("journal", j2_equal)), ("c@J2", item(j2_equal, J + "c"))]},
         {"entries": [("J3", cat("journal", j3_earlier))]},
         {"entries": [("J1 again", cat("journal", j1))]},
         {"entries": [("J4", cat("journal", j4_later)), ("c@J4", item(j4_later, J + "c"))]}],
        {"J1": "valid", "a@J1": "valid", "J2": (E06, ["C3"]), "c@J2": (E06, ["I3"]), "J3": (E06, ["C3"]),
         "J1 again": (E06, ["C3", "C4"]), "J4": "valid", "c@J4": "valid"}))

    one = Cat([pa], at(1))
    refresh = {"catalog_refresh_seconds": 7200}
    t = seconds(one.inner["generated_at"])
    second_floor = t + 7200
    histories.append(history(
        "C4: unchanged root against catalog_refresh_seconds",
        "catalog_refresh_seconds is 7200 in every Epoch. Against the floor t of J1, the same root at t + 3600 and "
        "t + 7199 fails C4; at t + 7200 it is valid and moves the floor; at the new floor + 7201 it is valid; a "
        "changed root one second after the floor is valid.",
        [{"entries": [("G", decl("owner", G))], "parameters": refresh},
         {"entries": [("J1", cat("journal", one))], "parameters": refresh},
         {"entries": [("J1+3600", cat("journal", one.with_instant(t + 3600)))], "parameters": refresh},
         {"entries": [("J1+7199", cat("journal", one.with_instant(t + 7199)))], "parameters": refresh},
         {"entries": [("J1+7200", cat("journal", one.with_instant(t + 7200)))], "parameters": refresh},
         {"entries": [("J1+14401", cat("journal", one.with_instant(second_floor + 7201)))], "parameters": refresh},
         {"entries": [("J2", cat("journal", Cat([pa, pb], second_floor + 7202)))], "parameters": refresh}],
        {"J1": "valid", "J1+3600": (E06, ["C4"]), "J1+7199": (E06, ["C4"]), "J1+7200": "valid",
         "J1+14401": "valid", "J2": "valid"}))

    rotated_key = successor(G, collections=[collection("journal", [prefix(J)], [key("journal2")]), STORE])
    histories.append(history(
        "C4: unchanged root while the latest Catalog's key is no longer authorized",
        "J1 is signed by the journal key. The same root signed by an owner key one hour later fails C4. D replaces "
        "the journal key by journal2; under D the latest Catalog J1 fails the binding check, so the same root two "
        "hours after J1 is valid inside catalog_refresh_seconds.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", one))]},
         {"entries": [("J1+3600 by owner", cat("owner", one.with_instant(t + 3600)))]},
         {"entries": [("D", decl("owner", rotated_key)), ("J1+7200 by owner", cat("owner", one.with_instant(t + 7200)))]}],
        {"J1": "valid", "J1+3600 by owner": (E06, ["C4"]), "J1+7200 by owner": "valid"}))

    same = one.with_instant(t + 3600)
    histories.append(history(
        "C4: catalog_refresh_seconds read from the Epoch's parameter map",
        "The same Catalog Entry, J1's root one hour after J1, fails C4 at height 2 under catalog_refresh_seconds "
        "604 800 and is valid at height 3 under catalog_refresh_seconds 3600.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", one))]},
         {"entries": [("J1+3600", cat("journal", same))]},
         {"entries": [("J1+3600 again", cat("journal", same))], "parameters": {"catalog_refresh_seconds": 3600}}],
        {"J1": "valid", "J1+3600": (E06, ["C4"]), "J1+3600 again": "valid"}))

    pb2 = page(J + "b", "b changed")
    pe = page(J + "e")
    r1 = Cat([pa, pb, pd], at(1))
    r2 = Cat([pa, pb2, pd], at(2))
    r9 = Cat([pa, pb2, pd, pe], at(4))
    histories.append(history(
        "I3: replaced and never sealed Catalogs",
        "At height 2, J2 replaces J1: the changed b proved against J2 is valid, while d proved against J1 fails "
        "I3. At height 3, d against J2 is valid and e against J9, not yet sealed, fails I3. At height 4 J9 is "
        "sealed and the same e Entry is valid.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", r1)), ("a@J1", item(r1, J + "a")), ("b@J1", item(r1, J + "b"))]},
         {"entries": [("J2", cat("journal", r2)), ("b2@J2", item(r2, J + "b")), ("d@J1", item(r1, J + "d"))]},
         {"entries": [("d@J2", item(r2, J + "d")), ("e@J9", item(r9, J + "e"))]},
         {"entries": [("J9", cat("journal", r9)), ("e@J9 again", item(r9, J + "e"))]}],
        {"J1": "valid", "a@J1": "valid", "b@J1": "valid", "J2": "valid", "b2@J2": "valid",
         "d@J1": (E06, ["I3"]), "d@J2": "valid", "e@J9": (E06, ["I3"]), "J9": "valid", "e@J9 again": "valid"}))

    k1 = Cat([pa, pb, pc], at(1))
    histories.append(history(
        "I4: the key that signed the named Catalog removed",
        "J1 is signed by the journal key and a is valid at height 1. D, sealed at height 2, replaces the journal "
        "key by journal2: b against J1 fails I4 in D's Epoch and c against J1 fails it at height 3.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", k1)), ("a@J1", item(k1, J + "a"))]},
         {"entries": [("D", decl("owner", rotated_key)), ("b@J1", item(k1, J + "b"))]},
         {"entries": [("c@J1", item(k1, J + "c"))]}],
        {"J1": "valid", "a@J1": "valid", "b@J1": ("WIST1-E02", ["I4"]), "c@J1": ("WIST1-E02", ["I4"])}))

    tk = seconds(k1.inner["generated_at"])
    window_kept = successor(G, collections=[collection("journal", [prefix(J)], [key("journal", exp=tk + 1)]), STORE])
    window_cut = successor(window_kept, collections=[collection("journal", [prefix(J)], [key("journal", exp=tk)]),
                                                     STORE])
    histories.append(history(
        "I4: a key window that no longer contains the named Catalog's generated_at",
        "D1 gives the journal key exp one second after J1's generated_at: b is valid. D2 moves exp to J1's "
        "generated_at, which the window [nbf, exp) no longer contains: c fails I4.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", k1)), ("a@J1", item(k1, J + "a"))]},
         {"entries": [("D1", decl("owner", window_kept)), ("b@J1", item(k1, J + "b"))]},
         {"entries": [("D2", decl("owner", window_cut)), ("c@J1", item(k1, J + "c"))]}],
        {"J1": "valid", "a@J1": "valid", "b@J1": "valid", "c@J1": ("WIST1-E02", ["I4"])}))

    n1 = Cat([pa, pb], at(1))
    dropped = successor(G, collections=[STORE])
    named_again = successor(dropped, collections=[JOURNAL, STORE])
    n2_equal = Cat([pa, pb, pc], at(1))
    n3_later = Cat([pa, pb, pc], at(1) + 1)

    def dropped_check(results):
        assert results[2]["records_removed"] == [{"publisher": "example.com", "url": J + "a", "cause": "narrowing"}]
        assert [c["catalog"] for c in results[2]["state"]["catalogs"]] == [n1.id]
        assert urls_of(results, 3) == [J + "a", J + "b"]

    histories.append(history(
        "I4: a Collection the Declaration in force no longer names; the floor kept",
        "D1 drops the journal: narrowing removes a's record, while J1 stays the latest Catalog with its floor. b "
        "against J1 fails I4, and I5 as well since no Scope of the journal covers its URL under D1; both give "
        "WIST1-E03. D2 names the journal again: b and a against the unchanged J1 are valid, a becoming a record "
        "again after narrowing removed it. J2 at J1's instant fails C3 against the kept floor; J3, one second "
        "later, is valid.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", n1)), ("a@J1", item(n1, J + "a"))]},
         {"entries": [("D1", decl("owner", dropped)), ("b@J1", item(n1, J + "b"))]},
         {"entries": [("D2", decl("owner", named_again)), ("b@J1 again", item(n1, J + "b")),
                      ("a@J1 again", item(n1, J + "a"))]},
         {"entries": [("J2", cat("journal", n2_equal))]},
         {"entries": [("J3", cat("journal", n3_later))]}],
        {"J1": "valid", "a@J1": "valid", "b@J1": ("WIST1-E03", ["I4", "I5"]), "b@J1 again": "valid",
         "a@J1 again": "valid", "J2": (E06, ["C3"]), "J3": "valid"}, check=dropped_check))

    old, new = page(J + "2025/x"), page(J + "2026/y")
    long_url = J + "2026/" + "l" * 60
    plong = page(long_url)
    cap = len(items.jcs(long_url)) - 1
    s_list = Cat([old, new, plong], at(1))
    narrowed = successor(G, collections=[collection("journal", [prefix(J + "2026/")], [key("journal")]), STORE])
    widened = successor(narrowed, collections=[JOURNAL, STORE])
    histories.append(history(
        "I5: the Declaration and the parameter map of the Item's own Epoch",
        "D1 narrows the journal to 2026/: narrowing removes the 2025 record, and the 2025 Item against J1 fails "
        "I5 (WIST1-E03) under D1. D2 widens the Scope again and the same Item, an unchanged list's, is valid. At "
        "height 4 the parameter map lowers url_cap_bytes one octet below JCS of the long URL: its Item fails I5 "
        "(WIST1-E11); at height 5 the map is back to 2048 and the same Entry is valid.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", s_list)), ("x@J1", item(s_list, old["url"])),
                      ("y@J1", item(s_list, new["url"]))]},
         {"entries": [("D1", decl("owner", narrowed)), ("x@J1 again", item(s_list, old["url"]))]},
         {"entries": [("D2", decl("owner", widened)), ("x@J1 third", item(s_list, old["url"]))]},
         {"entries": [("long@J1", item(s_list, long_url))], "parameters": {"url_cap_bytes": cap}},
         {"entries": [("long@J1 again", item(s_list, long_url))]}],
        {"J1": "valid", "x@J1": "valid", "y@J1": "valid", "x@J1 again": ("WIST1-E03", ["I5"]),
         "x@J1 third": "valid", "long@J1": ("WIST1-E11", ["I5"]), "long@J1 again": "valid"}))

    foreign = page(J + "f", "f", publisher=BLOG)
    own_f = page(J + "f", "f")
    m1 = Cat([pa, foreign], at(1))
    m2 = Cat([pa, own_f], at(3))
    histories.append(history(
        "I5: collection and publisher against the named Catalog",
        "a against J1 with the body's collection store fails I5 with WIST1-E17 at height 1 and is valid with "
        "journal at height 2. J1 lists f with publisher blog.example.com, a Publisher whose Declaration also names "
        "a journal: f fails I5 with WIST2-E03. J2 lists f with publisher example.com and it is valid.",
        [{"entries": [("G", decl("owner", G)), ("B", decl("docs", B))]},
         {"entries": [("J1", cat("journal", m1)), ("a@J1 as store", item(m1, J + "a", collection="store")),
                      ("f@J1", item(m1, J + "f"))]},
         {"entries": [("a@J1", item(m1, J + "a"))]},
         {"entries": [("J2", cat("journal", m2)), ("f@J2", item(m2, J + "f"))]}],
        {"J1": "valid", "a@J1 as store": ("WIST1-E17", ["I5"]), "f@J1": ("WIST2-E03", ["I5"]), "a@J1": "valid",
         "J2": "valid", "f@J2": "valid"}))

    shop_catalog = Cat([page("https://shop.example.net/p", publisher=SHOP)], at(1), "default", SHOP)
    shop_item = page(J + "g", "g", publisher=SHOP)
    own_g = page(J + "g", "g")
    o1 = Cat([pa, shop_item], at(3))
    o2 = Cat([pa, own_g], at(4))
    histories.append(history(
        "the Publisher of an Entry",
        "A Catalog of shop.example.net fails C1 with WIST1-E02 at height 1, before any Declaration of that "
        "Publisher is sealed, and the same Entry is valid at height 2 after H. J1 of example.com lists g with "
        "publisher shop.example.net, whose Declaration H names no journal. The Publisher of the Item Entry is "
        "J1's, example.com, whose Declaration names the journal: g fails I5 with WIST2-E03 alone, and I4 holds. "
        "J2 lists g with publisher example.com and it is valid.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("shop", cat("store2", shop_catalog))]},
         {"entries": [("H", decl("store2", H)), ("shop again", cat("store2", shop_catalog))]},
         {"entries": [("J1", cat("journal", o1)), ("g@J1", item(o1, J + "g"))]},
         {"entries": [("J2", cat("journal", o2)), ("g@J2", item(o2, J + "g"))]}],
        {"shop": ("WIST1-E02", ["C1"]), "shop again": "valid", "J1": "valid", "g@J1": ("WIST2-E03", ["I5"]),
         "J2": "valid", "g@J2": "valid"}))

    v1 = Cat([pa], at(1))

    def numbered(generated_at):
        inner = dict(Cat([pa], generated_at).inner, collection=7)
        return {"type": "publisher_catalog", "body": sign("owner", "catalog", inner)}

    histories.append(history(
        "a publisher_catalog Entry whose collection is not a string",
        "An Entry whose collection is the number 7 is compared with no other Entry: at height 1 it sits beside "
        "the valid J1, and at height 2 beside another Entry whose collection is also 7. Both Epochs are "
        "accepted, and each such Entry fails C1 with WIST1-E14. The twin of height 1, two journal Catalogs in "
        "one Epoch, is rejected in the history of two publisher_catalog Entries of one name.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", v1)), ("collection 7", numbered(at(1)))]},
         {"entries": [("collection 7, first", numbered(at(2))), ("collection 7, second", numbered(at(2) + 1))]}],
        {"J1": "valid", "collection 7": ("WIST1-E14", ["C1"]), "collection 7, first": ("WIST1-E14", ["C1"]),
         "collection 7, second": ("WIST1-E14", ["C1"])}))

    p1 = Cat([pa, pb, pc], at(1))
    good_a = item(p1, J + "a")
    bad_proof = copy.deepcopy(good_a)
    bad_proof["body"]["proof"]["path"][0] = hashlib.sha256(b"not a sibling").hexdigest()
    extra = copy.deepcopy(item(p1, J + "b"))
    extra["body"]["note"] = "extra"
    histories.append(history(
        "I6 and I1, and one Item Entry sealed twice in one Epoch",
        "a with the first path element replaced fails I6 (WIST1-E17); b with an extra body member fails I1 "
        "(WIST1-E14). At height 2 the untouched Entries are valid. At height 3 the Entry of c appears twice: the "
        "first becomes the record and the second, equal to the record's Item, fails I7.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", p1)), ("a@J1 bad proof", bad_proof), ("b@J1 extra member", extra)]},
         {"entries": [("a@J1", good_a), ("b@J1", item(p1, J + "b"))]},
         {"entries": [("c@J1", item(p1, J + "c")), ("c@J1 twice", item(p1, J + "c"))]}],
        {"J1": "valid", "a@J1 bad proof": ("WIST1-E17", ["I6"]), "b@J1 extra member": ("WIST1-E14", ["I1"]),
         "a@J1": "valid", "b@J1": "valid", "c@J1": "valid", "c@J1 twice": (E06, ["I7"])}))

    pa2 = page(J + "a", "a changed")
    rx, rb = removed(J + "x"), removed(J + "b")
    q1 = Cat([pa, pb, rx], at(1))
    q2 = Cat([pa2, rb, rx], at(3))
    q3 = Cat([pa2, pb, rx], at(4))

    def removal_check(results):
        assert results[3]["state"]["removals"] == [{"publisher": "example.com", "url": J + "b", "catalog": q2.id,
                                                   "generated_at": q2.inner["generated_at"]}]
        assert results[4]["state"]["removals"] == []
        assert records_of(results, 4) == [(J + "a", q2.id), (J + "b", q3.id)]

    histories.append(history(
        "I7: records and removals",
        "The removed Item x has no record and fails I7. a sealed again at height 2 is the record's Item and fails "
        "I7; the changed a against J2 is valid. The removed b against J2 has a record and removes it, leaving a "
        "removal state. J3 lists the original page b again, which is valid against no record.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", q1)), ("a@J1", item(q1, J + "a")), ("b@J1", item(q1, J + "b")),
                      ("x removed@J1", item(q1, J + "x"))]},
         {"entries": [("a@J1 again", item(q1, J + "a"))]},
         {"entries": [("J2", cat("journal", q2)), ("a2@J2", item(q2, J + "a")), ("b removed@J2", item(q2, J + "b"))]},
         {"entries": [("J3", cat("journal", q3)), ("b@J3", item(q3, J + "b"))]}],
        {"J1": "valid", "a@J1": "valid", "b@J1": "valid", "x removed@J1": (E06, ["I7"]),
         "a@J1 again": (E06, ["I7"]), "J2": "valid", "a2@J2": "valid", "b removed@J2": "valid", "J3": "valid",
         "b@J3": "valid"}, check=removal_check))

    empty_docs = Cat([], at(1), "docs")
    empty_store = Cat([], at(1), "store")
    ahead = Cat([pa], T0 + HOUR + 601)
    at_bound = Cat([pa], T0 + 2 * HOUR + 600)
    histories.append(history(
        "C1 at the Epoch: clock bound and Collection named",
        "The Epoch's sealed_at is the clock. A journal Catalog 601 seconds after height 1's sealed_at fails C1 "
        "(WIST1-E06); one exactly 600 seconds after height 2's is valid. An empty Catalog of docs, which the "
        "Declaration does not name, fails C1 (WIST1-E03); the same empty Catalog of store is valid.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J ahead", cat("journal", ahead)), ("docs", cat("owner", empty_docs)),
                      ("store", cat("owner", empty_store))]},
         {"entries": [("J at bound", cat("journal", at_bound))]}],
        {"J ahead": ("WIST1-E06", ["C1"]), "docs": ("WIST1-E03", ["C1"]), "store": "valid",
         "J at bound": "valid"}))

    fresh = successor(G, keys=[key("fresh")])
    signed_fresh = Cat([pa], at(2))
    histories.append(history(
        "C1 at the Epoch: a Catalog signed under a pending head's keys",
        "declaration_activation_epochs is 2. P, a fresh identity signed by the fresh key, is sealed at height 1 "
        "and pending until height 3. The same Catalog signed by the fresh key fails C1 (WIST1-E02) at height 2, "
        "since a pending head supplies no candidate, and is valid at height 3 after activation.",
        [{"entries": [("G", decl("owner", G))], "parameters": {"declaration_activation_epochs": 2}},
         {"entries": [("P", decl("fresh", fresh))], "parameters": {"declaration_activation_epochs": 2}},
         {"entries": [("J by fresh", cat("fresh", signed_fresh))], "parameters": {"declaration_activation_epochs": 2}},
         {"entries": [("J by fresh again", cat("fresh", signed_fresh))],
          "parameters": {"declaration_activation_epochs": 2}}],
        {"J by fresh": ("WIST1-E02", ["C1"]), "J by fresh again": "valid"}))

    d1 = Cat([pa], at(1))
    d2 = Cat([pa, pb], at(2))
    d3 = Cat([pa, pc], at(2) + 1)
    d5 = Cat([pa, pd], at(1))
    ds = Cat([], at(2), "store")

    def duplicate_check(results):
        for height in (2, 3):
            assert results[height]["state"] == results[1]["state"]

    histories.append(history(
        "two publisher_catalog Entries of one Publisher and Collection in one Epoch",
        "Height 2 carries J2 and J3 of the journal, each valid alone, with b against J2: the Epoch is rejected "
        "and the state stays that of height 1. Height 3 carries J2 with J5, which fails C3: rejected as well. "
        "Height 4 carries J2 with a store Catalog: accepted.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", d1)), ("a@J1", item(d1, J + "a"))]},
         {"entries": [("J2", cat("journal", d2)), ("J3", cat("journal", d3)), ("b@J2", item(d2, J + "b"))]},
         {"entries": [("J2", cat("journal", d2)), ("J5", cat("journal", d5)), ("b@J2", item(d2, J + "b"))]},
         {"entries": [("J2", cat("journal", d2)), ("S", cat("store", ds)), ("b@J2", item(d2, J + "b"))]}],
        {"J1": "valid", "a@J1": "valid", "J2": "valid", "J3": "valid", "J5": (E06, ["C3"]), "S": "valid",
         "b@J2": "valid"}, rejected={2: "WIST3-E03", 3: "WIST3-E03"}, check=duplicate_check))

    c1 = Cat([pa, pb, pc, pd], at(1))
    blog_catalog = Cat([], at(1), publisher=BLOG)
    lowered = {"domain_epoch_entries_max": 3}
    not_host = copy.deepcopy(item(c1, J + "d"))
    not_host["body"]["item"]["publisher"] = "Example.com"
    histories.append(history(
        "per-domain Epoch capacity",
        "domain_epoch_entries_max is 3 and every Canonical Host is its own unit. Height 1 carries three Entries "
        "of example.com and one of blog.example.com, besides B's Declaration: accepted. Height 2 carries four "
        "Item Entries of example.com, two of which would be ignored (I7): rejected. Height 3 carries three, one "
        "of which is ignored, and an Item whose publisher is not a Canonical Host, which counts toward no "
        "domain: accepted.",
        [{"entries": [("G", decl("owner", G))], "parameters": lowered},
         {"entries": [("B", decl("docs", B)), ("J1", cat("journal", c1)), ("a@J1", item(c1, J + "a")),
                      ("b@J1", item(c1, J + "b")), ("blog", cat("docs", blog_catalog))], "parameters": lowered},
         {"entries": [("c@J1", item(c1, J + "c")), ("d@J1", item(c1, J + "d")), ("a@J1 again", item(c1, J + "a")),
                      ("b@J1 again", item(c1, J + "b"))], "parameters": lowered},
         {"entries": [("c@J1", item(c1, J + "c")), ("d@J1", item(c1, J + "d")), ("a@J1 again", item(c1, J + "a")),
                      ("d not a host", not_host)], "parameters": lowered}],
        {"J1": "valid", "a@J1": "valid", "b@J1": "valid", "blog": "valid", "c@J1": "valid", "d@J1": "valid",
         "a@J1 again": (E06, ["I7"]), "b@J1 again": (E06, ["I7"]), "d not a host": ("WIST1-E14", ["I1"])},
        rejected={2: "WIST3-E03"}))

    w1 = Cat([pa, pb, pc], at(1))
    w2 = Cat([pa, pb, pc, pd], at(2))
    recovery = successor(G, keys=[key("owner2")])
    end = T0 + 2 * HOUR + 7 * DAY
    histories.append(history(
        "recovery window",
        "R, a recovery rotation sealed at height 2, opens a window ending seven days after height 2's sealed_at. "
        "J2 and b against J1 fail C2 and I2 at height 2 and at height 3, an hour before the end. Height 4, sealed "
        "exactly at the end, is outside the window: J2 and b against J2 are valid.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", w1)), ("a@J1", item(w1, J + "a"))]},
         {"entries": [("R", decl("recovery", recovery)), ("J2", cat("journal", w2)), ("b@J1", item(w1, J + "b"))]},
         {"entries": [("J2 inside", cat("journal", w2)), ("b@J1 inside", item(w1, J + "b"))], "sealed_at": end - HOUR},
         {"entries": [("J2 at end", cat("journal", w2)), ("b@J2", item(w2, J + "b"))], "sealed_at": end}],
        {"J1": "valid", "a@J1": "valid", "J2": (E06, ["C2"]), "b@J1": (E06, ["I2"]), "J2 inside": (E06, ["C2"]),
         "b@J1 inside": (E06, ["I2"]), "J2 at end": "valid", "b@J2": "valid"}))

    b1 = Cat([pa, pb], at(1))
    tb = seconds(b1.inner["generated_at"])

    def base_history(name, why, gap, map2, base):
        b2 = Cat([pa, rb], tb + gap)
        spec = [{"entries": [("G", decl("owner", G))], "parameters": {"removal_retention_days": 2}},
                {"entries": [("J1", cat("journal", b1)), ("a@J1", item(b1, J + "a")), ("b@J1", item(b1, J + "b"))],
                 "parameters": {"removal_retention_days": 2}},
                {"entries": [("J2", cat("journal", b2)), ("a@J2", item(b2, J + "a")),
                             ("b removed@J2", item(b2, J + "b"))],
                 "sealed_at": tb + gap + 60, "parameters": {"removal_retention_days": map2}}]
        expect = {"J1": "valid", "a@J1": "valid", "b@J1": "valid", "J2": "valid"}
        if base:
            expect.update({"a@J2": "valid", "b removed@J2": (E06, ["I7"])})
        else:
            expect.update({"a@J2": (E06, ["I7"]), "b removed@J2": "valid"})

        def check(results):
            assert results[2]["state"]["catalogs"][0]["base"] is base
            causes = [r["cause"] for r in results[2]["records_removed"]]
            assert causes == (["base", "base"] if base else ["removed_item"]), causes

        return history(name, why, spec, expect, check=check)

    histories.append(base_history(
        "base: a gap of exactly removal_retention_days",
        "removal_retention_days is 2. J2 is exactly two days of 86 400 seconds after the floor: not a base. The "
        "records stay, so a against J2 is the record's Item and fails I7, and the removed b removes b's record.",
        2 * DAY, 2, False))
    histories.append(base_history(
        "base: a gap of removal_retention_days and one second",
        "J2 is one second later than in the previous history: a base. Before the Items apply, the records of a "
        "and b are removed; a against J2 restores a's record and the removed b has no record and fails I7.",
        2 * DAY + 1, 2, True))
    histories.append(base_history(
        "base: removal_retention_days read from the map of the Catalog's Epoch",
        "The gap is two days and one second as in the previous history, but the map in force at J2's Epoch says "
        "3 days: J2 is not a base.",
        2 * DAY + 1, 3, False))

    return {"note": (
        "ADR-0052 Sealing: State and Judgment, the base (An Aggregator that was away) and the recovery window as "
        "C2 and I2 read it, replayed from sealed Entries. Each history replays `epochs` in order. An Epoch is "
        "simplified to its height, sealed_at, the parameter map in force at it (`parameters`, complete) and its "
        "Entries, each {type, body} with a `name` beside it; there are no Checkpoints and no Merkle tree of the "
        "Log. Entries are listed in canonical order (WIST-3 section 3.3: grouped publisher_declaration, "
        "publisher_catalog, publisher_item, then by ascending SHA-256(0x00 || JCS(entry))), and the Entry index is "
        "the position in that list. Declarations apply as vectors/wist1/collection-narrowing.json applies them "
        "(WIST-1 section 5.2 and ADR-0051's narrowing), then publisher_catalog and then publisher_item Entries in "
        "ascending Entry index. Each Catalog is judged by C1 to C4 and each Item by I1 to I7 with the Epoch's "
        "sealed_at as the clock, the Epoch's parameter map, and the Declaration in force once the Epoch's "
        "transitions have applied. The Publisher of a Catalog Entry is catalog.publisher and that of an Item "
        "Entry the named Catalog's publisher, whatever item.publisher spells: I2, I4, I5 and I7 read that "
        "Publisher's window, Declaration and records. A Catalog of a Publisher with no Declaration in force fails "
        "C1 with WIST1-E02. C2 to C4 are read only for a Catalog of the form C1 requires, and I2 and I4 to I7 "
        "only where I1 and I3 hold; `failed` lists every condition read that fails. Two publisher_catalog "
        "Entries with the same strings as publisher and collection reject the Epoch; an Entry in which either is "
        "not a string is compared with none. The I7 record is that of the Publisher and URL whatever Collection "
        "it carries; no history reaches a record of another Collection, since disjoint Scopes and narrowing "
        "leave none that an Item passing I5 could meet. A valid Catalog whose name "
        "has a floor and whose generated_at is more than removal_retention_days * 86400 seconds after it is a "
        "base and removes every record of its Publisher in its Collection before the Epoch's Items apply. "
        "`expected` gives per Epoch `status` (`accepted`, or `rejected` with `code` WIST3-E03, the state then "
        "unchanged); for an accepted Epoch, per publisher_catalog and publisher_item Entry its `disposition` "
        "(`valid`, or `ignored` with the conditions `failed` and the `codes` among which WIST-1 section 7 leaves "
        "the choice), `records_removed` in the order removed with the cause (`narrowing`, `base`, "
        "`removed_item`), and `state` after the Epoch: per Publisher the current Declaration, pending head and "
        "open window end; per Publisher and Collection name the latest Catalog's ID, the floor, its sealing "
        "height and whether it applied as a base; per Publisher and URL the record (Item ID, Collection, Catalog "
        "ID and generated_at of the Catalog proved against) and the removal states a valid removed Item left "
        "(Catalog ID and generated_at), which a record removed by narrowing or a base does not leave; lists in "
        "ascending octet order of publisher, then collection or url. Every ignored Entry or rejected Epoch fails "
        "one rule beside a twin that passes it, except where a rule cannot fail alone: a Catalog sealed again "
        "fails C3 and C4, and an Item of a Collection the Declaration no longer names fails I4 and I5. The "
        "per-domain capacity counts publisher_catalog and publisher_item Entries, valid or ignored, per Canonical "
        "Host, since no Public Suffix List snapshot is in force, and a body whose publisher is not a Canonical "
        "Host counts toward none; no fixture carries registry_update, label or dispute Entries, and "
        "recovery_window_days and declaration_activation_epochs are constant within a history. Payloads, tree "
        "files and the rules of Waiting, the queue and settlement are not exercised. Keys derive from the stated "
        "test-only seeds."),
        "keys": KEYS_MEMBER, "histories": histories}


def order_vectors():
    u = J + "u"
    pu, pu2, pu3 = page(u, "u one"), page(u, "u two"), page(u, "u three")
    ru = removed(u, "2026-10-01T01:00:00Z")
    x = Cat([pu, pa_of()], at(1))
    y = Cat([pu2, pa_of()], at(3))
    w = Cat([pu3, pa_of()], at(3))
    z = Cat([ru, pa_of()], at(4))
    early_removal = Cat([ru, pa_of()], at(2))
    base = Cat([pu2, pa_of()], seconds(x.inner["generated_at"]) + 2 * DAY + 1)
    assert w.inner["generated_at"] == y.inner["generated_at"] and w.id != y.id
    order_cases = []
    for name, listed in (("two instants", [y, x]), ("equal instants, two Catalog IDs", [w, y]),
                         ("three Catalogs of two instants", [z, w, x, y]),
                         ("Catalogs of two Collections", [Cat([], at(3), "store"), x, y])):
        ordered = combined_view.in_catalog_order([c.inner for c in listed])
        order_cases.append({"name": name, "catalogs": [c.inner for c in listed],
                            "expected": [catalogs.catalog_id(c) for c in ordered]})
    earlier_id, later_id = sorted((y, w), key=lambda c: c.id.encode())

    genesis = ("G", decl("owner", G))

    def log(name, rows):
        spec = [{"entries": [genesis]}] + [{"entries": row} if isinstance(row, list) else row for row in rows]
        epochs = build_epochs(spec)
        results, state = sealing.replay([{"height": e["height"], "sealed_at": e["sealed_at"],
                                          "parameters": e["parameters"],
                                          "entries": [n["entry"] for n in e["entries"]]} for e in epochs])
        summary = [{"height": r["height"], "status": r["status"],
                    "entries": [{"name": n["name"], **d} for n, d in zip(e["entries"], r["entries"]) if d is not None]}
                   for e, r in zip(epochs, results)]
        assert all(r["status"] == "accepted" for r in results)
        assert all(d["disposition"] == "valid" for r in summary for d in r["entries"]), (name, summary)
        return {"name": name, "epochs": epochs, "results": summary}, state.url_state("example.com", u)

    def case(name, why, logs, expected_logs, check=None):
        built, states = [], {}
        for log_name, rows in logs:
            entry, state = log(log_name, rows)
            built.append(entry)
            states[log_name] = state
        combined = combined_view.combined_state(states)
        assert (combined and combined["logs"]) == expected_logs, (name, combined)
        if check is not None:
            check(combined)
        return {"name": name, "why": why, "publisher": "example.com", "url": u, "logs": built,
                "expected": {"log_states": states, "combined": combined}}

    sealed_x = [("X", cat("journal", x)), ("u@X", item(x, u))]
    sealed_y = [("Y", cat("journal", y)), ("u@Y", item(y, u))]
    sealed_w = [("W", cat("journal", w)), ("u@W", item(w, u))]
    sealed = {y.id: sealed_y, w.id: sealed_w}
    after_z = successor(G, collections=[collection("journal", [prefix(J + "keep/")], [key("journal")]), STORE])
    late_base = Cat([pu2, pa_of()], seconds(z.inner["generated_at"]) + 2 * DAY + 1)
    sealed_z = [("Z", cat("journal", z)), ("u removed@Z", item(z, u))]
    sealed_r = [("R", cat("journal", early_removal)), ("u removed@R", item(early_removal, u))]
    cases = [
        case("the same Catalog in two Logs", "Both Logs hold the Item of u proved against X, at different heights; "
             "they are one Item.", [("A", [sealed_x]), ("B", [[], [], sealed_x])], ["A", "B"]),
        case("a later instant", "A holds u against X and B against Y, whose generated_at is later.",
             [("A", [sealed_x]), ("B", [sealed_x, [], sealed_y])], ["B"]),
        case("equal instants with different Catalog IDs",
             "Y and W carry one generated_at; the Catalog ID that is the greater string in octet order is the later.",
             [("A", [[], [], sealed[earlier_id.id]]), ("B", [[], [], sealed[later_id.id]])],
             ["B"], check=lambda c: c["state"]["catalog"] == later_id.id),
        case("a removal against a record", "A holds the record against X; B sealed X and u, then the removed Item "
             "against the later Z: the URL is removed.", [("A", [sealed_x]), ("B", [sealed_x, [], [], sealed_z])],
             ["B"], check=lambda c: c["state"]["state"] == "removed"),
        case("a record against an earlier removal", "B's removal against R is earlier than A's record against Y.",
             [("A", [sealed_x, [], sealed_y]), ("B", [sealed_x, sealed_r])], ["A"]),
        case("a Log with no state for the URL", "A sealed X and no Item of u.",
             [("A", [[("X", cat("journal", x))]]), ("B", [sealed_x])], ["B"]),
        case("three Logs: a removal is the latest", "A holds u against X, B against Y and C the removal against Z.",
             [("A", [sealed_x]), ("B", [sealed_x, [], sealed_y]), ("C", [sealed_x, [], [], sealed_z])], ["C"]),
        case("three Logs: two hold the latest Catalog", "A and B hold u against Y, C against X.",
             [("A", [sealed_x, [], sealed_y]), ("B", [[], [], sealed_y]), ("C", [sealed_x])], ["A", "B"]),
        case("a record removed by narrowing in one Log and held by another",
             "A seals Y and u against it, then D, which narrows the journal to J + 'keep/' and removes u's record: "
             "A has no state. B holds u against X, which is taken.",
             [("A", [sealed_x, [], sealed_y,
                     [("D", decl("owner", successor(G, collections=[
                         collection("journal", [prefix(J + "keep/")], [key("journal")]), STORE])))]]),
              ("B", [sealed_x])], ["B"]),
        case("a removal state kept through narrowing",
             "A seals the removed Item of u against Z, then D, which narrows the journal to J + 'keep/'. The "
             "removal state stays, and is later than B's record against X.",
             [("A", [sealed_x, [], [], sealed_z, [("D", decl("owner", after_z))]]), ("B", [sealed_x])], ["A"],
             check=lambda c: c["state"]["state"] == "removed"),
        case("a removal state kept through a base",
             "removal_retention_days is 2 in A. A seals the removed Item of u against Z, then a Catalog more than "
             "two days after Z, a base. The removal state stays, and is later than B's record against X.",
             [("A", [sealed_x, [], [], sealed_z,
                     {"entries": [("base", cat("journal", late_base))],
                      "sealed_at": seconds(late_base.inner["generated_at"]) + 60,
                      "parameters": {"removal_retention_days": 2}}]),
              ("B", [sealed_x])], ["A"], check=lambda c: c["state"]["state"] == "removed"),
        case("a record removed by a base in one Log and held by another",
             "removal_retention_days is 2 in A. A seals X and u against it, then a Catalog more than two days "
             "later, a base that removes u's record: A has no state. B holds u against X.",
             [("A", [{"entries": sealed_x, "parameters": {"removal_retention_days": 2}},
                     {"entries": [("base", cat("journal", base))], "sealed_at": seconds(base.inner["generated_at"]) + 60,
                      "parameters": {"removal_retention_days": 2}}]),
              ("B", [sealed_x])], ["B"]),
    ]
    return {"note": (
        "ADR-0052 Several Logs. order_cases list Catalog inner objects of one Publisher; `expected` gives their "
        "Catalog IDs (sha256: + hex(SHA-256(JCS(catalog)))) from earliest to latest: by generated_at, then, "
        "between equal instants, by Catalog ID, the greater string in octet order being the later, across the "
        "Collections of the Publisher. combined_cases "
        "give Logs that replay as vectors/wist3/catalog-sealing.json's histories do, each from the Declaration G "
        "at height 0, with `results` giving every Entry's disposition. `expected.log_states` is each Log's state "
        "for `publisher` and `url` after its last Epoch: a record {state: record, item, collection, catalog, "
        "generated_at}, a removal state {state: removed, catalog, generated_at} left by a valid removed Item, or "
        "null, which a record removed by narrowing or a base leaves. A removal state stays through narrowing "
        "and through a base and ends when a valid page Item becomes the URL's record. `expected.combined` is the state a Consumer "
        "of all the Logs takes: the one proved against the latest Catalog in the order above among the Logs that "
        "hold a state, with `logs` naming those that hold it; null when none does. States proved against one "
        "Catalog are one Item. Epochs are simplified as in catalog-sealing.json (no Checkpoints and no Merkle "
        "tree of the Log). Keys derive from the stated test-only seeds."),
        "keys": KEYS_MEMBER, "order_cases": order_cases, "combined_cases": cases}


def pa_of():
    return page(J + "a")


COLLECTION_PATH = "/.well-known/wist/collections/journal/"


def named_files(catalog):
    out = [COLLECTION_PATH + "tree/" + digest for digest in catalog.files]
    out += [COLLECTION_PATH + "payloads/" + items.payload_name(i) + ".json"
            for i in catalog.listed if items.kind(i) == "page"]
    return sorted(out, key=str.encode)


def served_vectors():
    letters = "abcdefgh"
    base = [page(J + c) for c in letters]
    changed = [page(J + "b", "b changed") if i["url"] == J + "b" else i for i in base]
    extra = changed + [page(J + "x")]
    l1, l2, l3 = (Cat(listed, at(1), capacity=2) for listed in (base, changed, extra))
    assert l1.inner["tree"] != l2.inner["tree"]
    t = T0

    def served(pairs):
        return [{"catalog": c.id, "served_at": stamp(instant), "files": named_files(c)} for c, instant in pairs]

    cases = []

    def case(name, why, sequence, clock, stop, expect_in, expect_out):
        got = served_files.must_serve(sequence, stop, stamp(clock))
        for f in expect_in:
            assert f in got, (name, f)
        for f in expect_out:
            assert f not in got, (name, f)
        cases.append({"name": name, "why": why, "served": sequence, "stop": stop, "clock": stamp(clock),
                      "expected": got})

    only_1 = sorted(set(named_files(l1)) - set(named_files(l2)), key=str.encode)
    tree_1 = [f for f in only_1 if "/tree/" in f]
    payload_b = [f for f in only_1 if "/payloads/" in f]
    assert tree_1 and len(payload_b) == 1
    replaced = served([(l1, t), (l2, t + HOUR)])
    for offset, kept in ((86399, True), (86400, False), (86401, False)):
        case(f"files of a replaced Catalog {offset} seconds after the replacement",
             "C1's tree files and the Payload of b that C2 does not name stay served for 86 400 seconds from C2's "
             "instant.", replaced, t + HOUR + offset, [], only_1 if kept else named_files(l2),
             [] if kept else only_1)
    case("a file the Publisher must stop serving", "Inside the interval, the Payload of b is in the stop set and is "
         "not served; the tree files of C1 are.", replaced, t + HOUR + 100, payload_b, tree_1, payload_b)
    payload_a = [f for f in named_files(l2) if f.endswith(items.payload_name(base[0]) + ".json")]
    assert len(payload_a) == 1
    case("a file the Publisher must stop serving that the served Catalog names",
         "The Payload of a, named by the served C2, is in the stop set and is not served.", replaced,
         t + HOUR + 100, payload_a, only_1, payload_a)
    case("the same clock without a stop set", "The twin of the previous case.", replaced, t + HOUR + 100, [],
         only_1, [])
    again = served([(l1, t), (l2, t + HOUR), (l1, t + 2 * HOUR), (l2, t + 3 * HOUR)])
    case("a file named again inside the interval by a later Catalog",
         "C1's files, dropped by C2 at t + 3600, are named again by C3 at t + 7200 and dropped by C4 at t + 10800: "
         "they are served until t + 10800 + 86400, past t + 3600 + 86400.", again, t + HOUR + DAY + 10, [],
         only_1, [])
    case("a file named again, after the interval of its last naming Catalog", "The same sequence at t + 10800 + "
         "86400.", again, t + 3 * HOUR + DAY, [], [], only_1)
    successive = served([(l1, t), (l2, t + HOUR), (l3, t + 14 * HOUR)])
    only_2 = sorted(set(named_files(l2)) - set(named_files(l3)), key=str.encode)
    assert only_2
    case("a file dropped by two successive Catalogs, inside the interval of the first replacement",
         "The Payload of b and C1's tree files were last named by C1, replaced at t + 3600; C3 replacing C2 at "
         "t + 50400 does not restart their interval.", successive, t + HOUR + 86399, [], only_1 + only_2, [])
    case("a file dropped by two successive Catalogs, at the end of the interval of the first replacement",
         "At t + 3600 + 86400 C1's files are no longer served, while C2's tree files that C3 does not name are.",
         successive, t + HOUR + DAY, [], only_2, only_1)
    return {"note": (
        "ADR-0052 Files: the files a Publisher must serve for one Collection at `clock`, besides catalog.json. "
        "`served` lists the Catalogs the Publisher served, oldest first, each with `served_at`, the instant on "
        "the Publisher's clock at which it replaced its predecessor, and `files`, the paths of the tree files "
        "reached from its `tree` and of the Payloads of its Items of kind page; the last is the served Catalog. "
        "`stop` lists files the Publisher must stop serving. `expected` lists, in ascending octet order, every "
        "file the served Catalog names, and every other file for which `clock` is earlier than the instant at "
        "which the last Catalog that named it was replaced plus replaced_file_seconds, 86 400 seconds, the "
        "suite's value that no Log amends; files in `stop` are removed from the list. The interval is half-open: a file at exactly 86 400 "
        "seconds is no longer due. The sequences are supplied as served, with tree files split at two Items per "
        "bucket, and are not derived from publications; the fixture asserts nothing about files the Publisher "
        "may serve beyond those due. A file in `stop` is removed whether or not the served Catalog names it."),
        "cases": cases}


write_json(WIST3 / "catalog-sealing.json", with_payloads(sealing_vectors()))
write_json(MULTILOG / "catalog-order.json", with_payloads(order_vectors()))
write_json(WIST2 / "served-files.json", served_vectors())
print("sealing vectors written")
