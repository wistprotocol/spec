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
import materialization
import sealing
import served_files
import tree_files

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIST2 = ROOT / "vectors" / "wist2"
WIST3 = ROOT / "vectors" / "wist3"
MULTILOG = ROOT / "vectors" / "multilog"

KEY_NAMES = ("owner", "owner2", "recovery", "recovery2", "fresh", "journal", "journal2",
             "store", "store2", "docs", "log")
USED_KEYS = ("owner", "owner2", "recovery", "fresh", "journal", "journal2", "store", "store2", "docs", "log")
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
    "payload_window_days": 180, "domain_epoch_entries_max": 10000, "url_cap_bytes": 2048,
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


def withdrawal(withdrawn, sealed_at, subject=None):
    update = {"wist_version": "1.0.0", "action": "payload_withdrawal", "subject": subject or withdrawn["publisher"],
              "effective_at": stamp(sealed_at),
              "details": {"delta_id": items.item_id(withdrawn), "legal_basis": "court order 12/2026",
                          "jurisdiction": "BR"}}
    return {"type": "registry_update", "body": sign("log", "update", update)}


def item(catalog, url, **changes):
    listed = next(i for i in catalog.listed if i["url"] == url)
    body = items.publisher_item_body(listed, catalog.inner, catalog.listed)
    for member, value in changes.items():
        body[member] = value
    return {"type": "publisher_item", "body": body}


def item_at(catalog, listed):
    return {"type": "publisher_item", "body": items.publisher_item_body(listed, catalog.inner, catalog.listed)}


def at(height, offset=-60):
    return T0 + height * HOUR + offset


def build_epochs(spec):
    epochs = []
    for height, epoch in enumerate(spec):
        named = sorted(epoch.get("entries", []),
                       key=lambda pair: (sealing.ENTRY_GROUPS.index(pair[1]["type"]), sealing.entry_leaf(pair[1])))
        if epoch.get("stated_order"):
            assert named != epoch["entries"], ("a stated order that is canonical", height)
            named = epoch["entries"]
        epochs.append({"height": height, "sealed_at": stamp(epoch.get("sealed_at", T0 + height * HOUR)),
                       "parameters": {**DEFAULT_MAP, **epoch.get("parameters", {})},
                       "entries": [{"name": name, "entry": entry} for name, entry in named]})
    return epochs


def expected_disposition(value):
    if value == "valid":
        return {"disposition": "valid"}
    code, failed = value
    return {"disposition": "ignored", "failed": failed, "codes": [code]}


def run(epochs, expect, rejected, label, duties=False):
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
            assert result["codes"] == rejected[epoch["height"]], (label, result)
            entry["codes"] = result["codes"]
        else:
            entry["entries"] = []
            for named, got in zip(epoch["entries"], result["entries"]):
                if got is None:
                    continue
                wanted = expected_disposition(expect[named["name"]])
                assert got == wanted, (label, named["name"], got, wanted)
                entry["entries"].append({"name": named["name"], **got})
            entry["records_removed"] = result["records_removed"]
        if duties:
            entry["payload_duties"] = result["payload_duties"]
        declared = result["state"]["declarations"]
        for d in declared:
            for member in ("current", "pending_head"):
                if d[member] is not None:
                    d[member] = names[d[member]]
        entry["state"] = result["state"]
        out.append(entry)
    return out, state


def history(name, why, spec, expect, rejected=None, check=None, duties=False):
    epochs = build_epochs(spec)
    for epoch in epochs:
        for named in epoch["entries"]:
            if named["entry"]["type"] in ("registry_update", "publisher_catalog", "publisher_item"):
                assert named["name"] in expect, (name, named["name"])
    results, state = run(epochs, expect, rejected or {}, name, duties)
    if check is not None:
        check(results)
    return {"name": name, "why": why, "epochs": epochs, "expected": results}


def records_of(results, height):
    return [(r["url"], r["catalog"]) for r in results[height]["state"]["records"]]


def urls_of(results, height):
    return [r["url"] for r in results[height]["state"]["records"]]


E06 = "WIST3-E06"
E03 = "WIST3-E03"
E08 = "WIST1-E08"


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
    long_url = J + "2026/" + "l" * (DEFAULT_MAP["url_cap_bytes"] + 1 - len(items.jcs(J + "2026/")))
    plong = page(long_url, "long")
    assert len(items.jcs(long_url)) == DEFAULT_MAP["url_cap_bytes"] + 1
    s_list = Cat([old, new, plong], at(1))
    narrowed = successor(G, collections=[collection("journal", [prefix(J + "2026/")], [key("journal")]), STORE])
    widened = successor(narrowed, collections=[JOURNAL, STORE])
    histories.append(history(
        "I5: the Declaration and the parameter map of the Item's own Epoch",
        "D1 narrows the journal to 2026/: narrowing removes the 2025 record, and the 2025 Item against J1 fails "
        "I5 (WIST1-E03) under D1. D2 widens the Scope again and the same Item, an unchanged list's, is valid. At "
        "height 4, under url_cap_bytes 2048, the Item of the long URL, whose JCS is one octet above it, fails I5 "
        "(WIST1-E11); at height 5 the map raises url_cap_bytes to 4096 and the same Entry is valid.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", s_list)), ("x@J1", item(s_list, old["url"])),
                      ("y@J1", item(s_list, new["url"]))]},
         {"entries": [("D1", decl("owner", narrowed)), ("x@J1 again", item(s_list, old["url"]))]},
         {"entries": [("D2", decl("owner", widened)), ("x@J1 third", item(s_list, old["url"]))]},
         {"entries": [("long@J1", item(s_list, long_url))]},
         {"entries": [("long@J1 again", item(s_list, long_url))], "parameters": {"url_cap_bytes": 4096}}],
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
        assert results[3]["state"]["removals"] == [{"publisher": "example.com", "url": J + "b",
                                                   "item": items.item_id(rb), "catalog": q2.id,
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
         "b@J2": "valid"}, rejected={2: [E03], 3: [E03]}, check=duplicate_check))

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
        rejected={2: [E03]}))

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
    retention = items.REMOVAL_RETENTION_DAYS * DAY

    def base_history(name, why, gap, base):
        b2 = Cat([pa, rb], tb + gap)
        spec = [{"entries": [("G", decl("owner", G))]},
                {"entries": [("J1", cat("journal", b1)), ("a@J1", item(b1, J + "a")), ("b@J1", item(b1, J + "b"))]},
                {"entries": [("J2", cat("journal", b2)), ("a@J2", item(b2, J + "a")),
                             ("b removed@J2", item(b2, J + "b"))],
                 "sealed_at": tb + gap + 60}]
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
        "removal_retention_days is the constant 180. J2 is exactly 180 days of 86 400 seconds after the floor: not a "
        "base. The records stay, so a against J2 is the record's Item and fails I7, and the removed b removes b's "
        "record.",
        retention, False))
    histories.append(base_history(
        "base: a gap of removal_retention_days and one second",
        "J2 is one second later than in the previous history: a base. Before the Items apply, the records of a "
        "and b are removed; a against J2 restores a's record and the removed b has no record and fails I7.",
        retention + 1, True))

    largest = 7776000
    longest = {"catalog_refresh_seconds": largest}
    histories.append(history(
        "C4 at the largest catalog_refresh_seconds",
        "catalog_refresh_seconds is 7 776 000, the largest value a map may carry, in every Epoch. J1's list one "
        "second short of the floor plus that interval fails C4. At exactly the floor plus 7 776 000 seconds it "
        "passes C4 and is not a base: the records stay, and a against it is the record's Item and fails I7.",
        [{"entries": [("G", decl("owner", G))], "parameters": longest},
         {"entries": [("J1", cat("journal", b1)), ("a@J1", item(b1, J + "a")), ("b@J1", item(b1, J + "b"))],
          "parameters": longest},
         {"entries": [("J1 unchanged, one second short", cat("journal", b1.with_instant(tb + largest - 1)))],
          "sealed_at": tb + largest - 1 + 60, "parameters": longest},
         {"entries": [("J1 unchanged", cat("journal", b1.with_instant(tb + largest))),
                      ("a@J1 unchanged", item(b1.with_instant(tb + largest), J + "a"))],
          "sealed_at": tb + largest + 60, "parameters": longest}],
        {"J1": "valid", "a@J1": "valid", "b@J1": "valid", "J1 unchanged, one second short": (E06, ["C4"]),
         "J1 unchanged": "valid", "a@J1 unchanged": (E06, ["I7"])},
        check=lambda results: results[3]["state"]["catalogs"][0]["base"] is False
        and results[3]["records_removed"] == []))

    week = 7 * DAY
    weekly = [{"entries": [("G", decl("owner", G))], "parameters": longest},
              {"entries": [("J1", cat("journal", b1)), ("a@J1", item(b1, J + "a"))], "parameters": longest}]
    weekly_expect = {"J1": "valid", "a@J1": "valid"}
    for n in range(1, 14):
        name = f"J1 unchanged, week {n}"
        weekly.append({"entries": [(name, cat("journal", b1.with_instant(tb + n * week)))],
                       "sealed_at": tb + n * week + 60, "parameters": longest})
        weekly_expect[name] = "valid" if n == 13 else (E06, ["C4"])

    def weekly_check(results):
        assert results[14]["state"]["catalogs"][0]["base"] is False and results[14]["records_removed"] == []
        assert [r["url"] for r in results[14]["state"]["records"]] == [J + "a"]

    histories.append(history(
        "a weekly signer under the largest catalog_refresh_seconds",
        "catalog_refresh_seconds is 7 776 000 in every Epoch, and the Publisher signs J1's unchanged list every "
        "604 800 seconds. Weeks 1 to 12 are within the interval and fail C4; week 13, 7 862 400 seconds after the "
        "floor, passes C4 and, far from 180 days, is no base: the record of a stays.",
        weekly, weekly_expect, check=weekly_check))

    px, pv, py, pz = page(J + "old/x"), page(J + "old/v"), page(J + "new/y"), page(J + "new/z")
    pw, pu = page(J + "old/w"), page(J + "new/u")
    wl = Cat([px, pv, py, pz, pw, pu], at(1))
    only_new = successor(G, collections=[collection("journal", [prefix(J + "new/")], [key("journal")]), STORE])
    all_again = successor(only_new, collections=[JOURNAL, STORE])

    def withdrawn_check(results):
        assert [r["url"] for r in results[2]["state"]["records"]] == urls_of(results, 1)
        assert {d["url"] for d in results[2]["payload_duties"]} == {J + "old/v", J + "new/y", J + "old/w"}
        assert [(r["url"], r["cause"]) for r in results[3]["records_removed"]] == [
            (J + "old/v", "narrowing"), (J + "old/w", "narrowing"), (J + "old/x", "narrowing")]
        assert {d["url"]: d["until"] for d in results[3]["payload_duties"]} == {
            J + "old/v": stamp(T0 + HOUR + 180 * DAY), J + "old/w": stamp(T0 + HOUR + 180 * DAY),
            J + "new/y": None, J + "new/u": None}
        assert all(d["until"] is None for d in results[4]["payload_duties"])
        assert items.item_id(pz) not in [d["item"] for d in results[5]["payload_duties"]]
        assert J + "new/z" in urls_of(results, 5)

    histories.append(history(
        "I7: a withdrawn Payload",
        "J1 lists old/x, old/v, old/w, new/y, new/z and new/u. x, v, w and y become records at height 1. At "
        "height 2 three payload_withdrawal acts are sealed: one of x, which meets its details contract, so x's "
        "record stays and its serving duty ends; one of w whose subject is blog.example.com, not the Publisher of "
        "the Catalog w was sealed against, and one of u, which no Entry sealed at or below height 2 carries: both "
        "break the contract (WIST4-E04), are ignored and block nothing. u is sealed at height 3 with D1, which "
        "narrows the journal to new/ and removes the records of x, v and w; D2, at height 4, widens it again. "
        "Against the unchanged J1, v and w are sealed again, while x fails I7 (WIST3-E06) since a withdrawal "
        "sealed below height 4 names its Item ID. At height 5 a withdrawal of z is sealed with z's Entry: the act "
        "meets its contract, since z is sealed in its Epoch, z is valid, since the withdrawal is not sealed below "
        "z's Epoch, and z has no serving duty.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", wl)), ("x@J1", item(wl, J + "old/x")), ("v@J1", item(wl, J + "old/v")),
                      ("w@J1", item(wl, J + "old/w")), ("y@J1", item(wl, J + "new/y"))]},
         {"entries": [("withdrawal of x", withdrawal(px, T0 + 2 * HOUR)),
                      ("withdrawal of w under another subject", withdrawal(pw, T0 + 2 * HOUR, BLOG)),
                      ("withdrawal of u never sealed", withdrawal(pu, T0 + 2 * HOUR))]},
         {"entries": [("D1", decl("owner", only_new)), ("u@J1", item(wl, J + "new/u"))]},
         {"entries": [("D2", decl("owner", all_again)), ("x@J1 after widening", item(wl, J + "old/x")),
                      ("v@J1 after widening", item(wl, J + "old/v")),
                      ("w@J1 after widening", item(wl, J + "old/w"))]},
         {"entries": [("withdrawal of z", withdrawal(pz, T0 + 5 * HOUR)), ("z@J1", item(wl, J + "new/z"))]}],
        {"J1": "valid", "x@J1": "valid", "v@J1": "valid", "w@J1": "valid", "y@J1": "valid",
         "withdrawal of x": "valid", "withdrawal of w under another subject": ("WIST4-E04", ["contract"]),
         "withdrawal of u never sealed": ("WIST4-E04", ["contract"]), "u@J1": "valid",
         "x@J1 after widening": (E06, ["I7"]), "v@J1 after widening": "valid", "w@J1 after widening": "valid",
         "withdrawal of z": "valid", "z@J1": "valid"}, check=withdrawn_check, duties=True))

    rk1 = Cat([pa, pb], at(1))
    rk2 = Cat([pa, rb], at(2))
    histories.append(history(
        "a withdrawal that names an Item of kind removed",
        "J1's a and b become records at height 1; the removed b against J2 removes b's record at height 2. At "
        "height 3 a payload_withdrawal names the Item ID of that removed b: a valid publisher_item Entry sealed "
        "it, but an Item of kind removed has no Payload, so the act breaks its details contract (WIST4-E04) and is "
        "ignored; the twin, a withdrawal of a, a sealed Item of kind page, meets it.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", rk1)), ("a@J1", item(rk1, J + "a")), ("b@J1", item(rk1, J + "b"))]},
         {"entries": [("J2", cat("journal", rk2)), ("b removed@J2", item(rk2, J + "b"))]},
         {"entries": [("withdrawal of the removed b", withdrawal(rb, T0 + 3 * HOUR)),
                      ("withdrawal of a", withdrawal(pa, T0 + 3 * HOUR))]}],
        {"J1": "valid", "a@J1": "valid", "b@J1": "valid", "J2": "valid", "b removed@J2": "valid",
         "withdrawal of the removed b": ("WIST4-E04", ["contract"]), "withdrawal of a": "valid"}))

    pk = page(J + "old/k")
    kl = Cat([pk, py], at(1))
    narrowed_again = successor(all_again, collections=only_new["collections"])
    first_stop = T0 + 2 * HOUR
    second_stop = T0 + 4 * HOUR

    first_window = stamp(T0 + HOUR + 180 * DAY)

    def union_check(results):
        def until(height):
            return {d["url"]: d["until"] for d in results[height]["payload_duties"]}.get(J + "old/k", "none")

        assert until(2) == first_window and until(3) is None
        assert until(4) == first_window and until(5) == first_window
        assert T0 + 3 * HOUR + 30 * DAY < second_stop + 31 * DAY

    histories.append(history(
        "the serving duty of an Item sealed twice",
        "k is sealed at height 1 under payload_window_days 180 and is the record from there. D1 removes it by "
        "narrowing at height 2; D2 widens the journal and k is sealed again at height 3, under payload_window_days "
        "30; D3 narrows again at height 4. Each Epoch that sealed k gives its Payload one availability window, read "
        "from that Epoch's map: 180 days from height 1 and 30 days from height 3, the first ending later. At height "
        "5, 31 days after height 4, the window of height 3 has ended and k's duty still holds, since it holds while "
        "the window of either sealing Epoch does.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", kl)), ("k@J1", item(kl, J + "old/k")), ("y@J1", item(kl, J + "new/y"))]},
         {"entries": [("D1", decl("owner", only_new))], "sealed_at": first_stop},
         {"entries": [("D2", decl("owner", all_again)), ("k@J1 again", item(kl, J + "old/k"))],
          "parameters": {"payload_window_days": 30}},
         {"entries": [("D3", decl("owner", narrowed_again))], "sealed_at": second_stop,
          "parameters": {"payload_window_days": 30}},
         {"entries": [], "sealed_at": second_stop + 31 * DAY, "parameters": {"payload_window_days": 30}}],
        {"J1": "valid", "k@J1": "valid", "y@J1": "valid", "k@J1 again": "valid"}, check=union_check, duties=True))

    ps = page(J + "s")
    ps2 = page(J + "s", "s changed")
    short = {"payload_window_days": 30}
    s1 = Cat([ps], at(1))
    s2 = Cat([ps2], at(2))
    short_end = T0 + HOUR + 30 * DAY

    def superseded_check(results):
        def duty(height):
            return {d["item"]: d["until"] for d in results[height]["payload_duties"]}

        assert duty(2) == {items.item_id(ps): stamp(short_end), items.item_id(ps2): None}
        assert duty(3) == duty(2)
        assert duty(4) == {items.item_id(ps2): None}

    histories.append(history(
        "a superseded Payload keeps only the window of the Epoch that sealed its Item",
        "s is sealed at height 1 under payload_window_days 30. At height 2, under payload_window_days 180, s changed "
        "replaces it as the record. s's Payload keeps the window of height 1 alone, 30 days from height 1's "
        "sealed_at, and the Epoch that replaced the record gives it none: it is due at height 3, one second before "
        "that window ends, and not at height 4, sealed when it ends.",
        [{"entries": [("G", decl("owner", G))], "parameters": short},
         {"entries": [("J1", cat("journal", s1)), ("s@J1", item(s1, J + "s"))], "parameters": short},
         {"entries": [("J2", cat("journal", s2)), ("s changed@J2", item(s2, J + "s"))]},
         {"entries": [], "sealed_at": short_end - 1},
         {"entries": [], "sealed_at": short_end}],
        {"J1": "valid", "s@J1": "valid", "J2": "valid", "s changed@J2": "valid"},
        check=superseded_check, duties=True))

    pb3 = page(J + "b", "b three")
    duty_base = Cat([pa, pb3], tb + retention + 1)
    base_at = tb + retention + 1 + 60

    def duty_check(results):
        assert [(d["url"], d["until"]) for d in results[1]["payload_duties"]] == [(J + "a", None), (J + "b", None)]
        assert results[2]["payload_duties"] == []
        assert sorted((d["item"], d["until"]) for d in results[3]["payload_duties"]) == sorted(
            [(items.item_id(pa), None), (items.item_id(pb3), None)])
        assert sorted((d["item"], d["until"]) for d in results[4]["payload_duties"]) == sorted(
            [(items.item_id(pa), None), (items.item_id(pb3), None)])

    histories.append(history(
        "the serving duty of a Payload through a base and a sealing again",
        "payload_window_days is 180 in every Epoch. a and b are records from height 1 and their Payloads are served "
        "while they are. J2, a base at height 2 more than 180 days after height 1, removes both records: the "
        "windows of height 1, the one Epoch that sealed a and b, have ended, and the base gives no window, so "
        "neither Payload is due. At height 3 a, unchanged, is sealed again and is the record again, and b three "
        "replaces b, whose Payload stays not due. At height 4 a and b three are still the records.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", b1)), ("a@J1", item(b1, J + "a")), ("b@J1", item(b1, J + "b"))]},
         {"entries": [("J2", cat("journal", duty_base))], "sealed_at": base_at},
         {"entries": [("a@J2", item(duty_base, J + "a")), ("b three@J2", item(duty_base, J + "b"))],
          "sealed_at": base_at + HOUR},
         {"entries": [], "sealed_at": base_at + retention}],
        {"J1": "valid", "a@J1": "valid", "b@J1": "valid", "J2": "valid", "a@J2": "valid", "b three@J2": "valid"},
        check=duty_check, duties=True))

    first_twin, second_twin = Cat([pa], at(0)), Cat([pb], at(0) + 1)
    histories.append(history(
        "a rejected first Epoch",
        "Height 0 carries G and two journal Catalogs of example.com: the Epoch is rejected whole (WIST3-E03), and "
        "the state stays empty, with no Declaration and no serving duty. Height 1 seals G alone and is accepted.",
        [{"entries": [("G", decl("owner", G)), ("J first", cat("journal", first_twin)),
                      ("J second", cat("journal", second_twin))], "sealed_at": T0 - 30},
         {"entries": [("G", decl("owner", G))]}],
        {"J first": "valid", "J second": "valid"}, rejected={0: [E03]}, duties=True,
        check=lambda results: results[0]["state"]["declarations"] == [] and results[0]["payload_duties"] == []))

    o1 = Cat([pa, pb, pc], at(1))
    bc = [("b@J1", item(o1, J + "b")), ("c@J1", item(o1, J + "c"))]
    descending = sorted(bc, key=lambda pair: sealing.entry_leaf(pair[1]), reverse=True)

    def unchanged_check(kept):
        def check(results):
            for height, reference in kept.items():
                assert results[height]["state"] == results[reference]["state"], height
        return check

    histories.append(history(
        "Entries of one type out of Entry hash order",
        "Height 2 lists the Item Entries of b and c in descending SHA-256(0x00 || JCS(entry)), against the "
        "canonical order: the Epoch is rejected (WIST3-E03) and the state stays that of height 1. Height 3 lists "
        "the same Entries in canonical order: accepted, both valid.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", o1)), ("a@J1", item(o1, J + "a"))]},
         {"entries": descending, "stated_order": True},
         {"entries": bc}],
        {"J1": "valid", "a@J1": "valid", "b@J1": "valid", "c@J1": "valid"},
        rejected={2: [E03]}, check=unchanged_check({2: 1})))

    g1, g2 = Cat([pa, pb], at(1)), Cat([pa, pb, pc], at(3))
    renewed = successor(G)
    histories.append(history(
        "Entry types out of group order",
        "Height 1 lists the Catalog J1 before D, a Declaration of example.com, then a against J1: the Epoch is "
        "rejected (WIST3-E03) and the state stays that of height 0. Height 2 lists the same Entries in canonical "
        "order: accepted. Height 3 lists c against J2 before J2: rejected, the state staying that of height 2. "
        "Height 4 lists the same two Entries in canonical order: accepted, both valid.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", g1)), ("D", decl("owner", renewed)), ("a@J1", item(g1, J + "a"))],
          "stated_order": True},
         {"entries": [("J1", cat("journal", g1)), ("D", decl("owner", renewed)), ("a@J1", item(g1, J + "a"))]},
         {"entries": [("c@J2", item(g2, J + "c")), ("J2", cat("journal", g2))], "stated_order": True},
         {"entries": [("c@J2", item(g2, J + "c")), ("J2", cat("journal", g2))]}],
        {"J1": "valid", "a@J1": "valid", "J2": "valid", "c@J2": "valid"},
        rejected={1: [E03], 3: [E03]}, check=unchanged_check({1: 0, 3: 2})))

    m1, m2, m3 = Cat([pa], at(1)), Cat([pa, pb], at(2)), Cat([pa, pc], at(2) + 1)
    other_first = dict(G, collections=[JOURNAL])
    histories.append(history(
        "a Declaration rejection and a second whole-Epoch rejection in one Epoch",
        "G' is a Declaration of example.com of seq 0 other than G, which WIST-1 section 5.2 rejects once G is "
        "accepted (WIST1-E08). Height 2 carries G' and two journal Catalogs, J2 and J3, with b against J2: the "
        "Epoch meets both rejections and `codes` lists WIST1-E08 and WIST3-E03. Height 3 carries G', J2 and b, "
        "rejected with WIST1-E08 alone; height 4 carries J2, J3 and b, rejected with WIST3-E03 alone; the state "
        "after each stays that of height 1. Height 5 carries J2 and b: accepted.",
        [{"entries": [("G", decl("owner", G))]},
         {"entries": [("J1", cat("journal", m1)), ("a@J1", item(m1, J + "a"))]},
         {"entries": [("G'", decl("owner", other_first)), ("J2", cat("journal", m2)), ("J3", cat("journal", m3)),
                      ("b@J2", item(m2, J + "b"))]},
         {"entries": [("G'", decl("owner", other_first)), ("J2", cat("journal", m2)), ("b@J2", item(m2, J + "b"))]},
         {"entries": [("J2", cat("journal", m2)), ("J3", cat("journal", m3)), ("b@J2", item(m2, J + "b"))]},
         {"entries": [("J2", cat("journal", m2)), ("b@J2", item(m2, J + "b"))]}],
        {"J1": "valid", "a@J1": "valid", "J2": "valid", "J3": "valid", "b@J2": "valid"},
        rejected={2: [E08, E03], 3: [E08], 4: [E03]}, check=unchanged_check({2: 1, 3: 1, 4: 1})))

    parameter_cases = []
    for name, changes in (("catalog_refresh_seconds at 7 776 000", {"catalog_refresh_seconds": 7776000}),
                          ("catalog_refresh_seconds at 7 776 001", {"catalog_refresh_seconds": 7776001}),
                          ("catalog_refresh_seconds at 0", {"catalog_refresh_seconds": 0}),
                          ("catalog_refresh_seconds at 1", {"catalog_refresh_seconds": 1}),
                          ("url_cap_bytes at 32 768", {"url_cap_bytes": 32768}),
                          ("url_cap_bytes at 32 769", {"url_cap_bytes": 32769}),
                          ("url_cap_bytes at 2 048", {"url_cap_bytes": 2048}),
                          ("url_cap_bytes at 2 047", {"url_cap_bytes": 2047}),
                          ("extract_cap_bytes at 32 767", {"extract_cap_bytes": 32767}),
                          ("summary_cap_bytes at 2 047", {"summary_cap_bytes": 2047}),
                          ("links_cap_bytes at 4 095", {"links_cap_bytes": 4095}),
                          ("link_url_cap_bytes at 2 047", {"link_url_cap_bytes": 2047}),
                          ("collections_max at 15", {"collections_max": 15}),
                          ("scope_entries_max at 31", {"scope_entries_max": 31}),
                          ("catalog_items_max at 16 777 215", {"catalog_items_max": 16777215}),
                          ("a map carrying removal_retention_days", {"removal_retention_days": 180})):
        try:
            sealing.check_parameters({**DEFAULT_MAP, **changes})
            outcome = "accepted"
        except ValueError:
            outcome = "refused"
        parameter_cases.append({"name": name, "parameters": {**DEFAULT_MAP, **changes}, "expected": outcome})

    return {"note": (
        "ADR-0052 Sealing: State and Judgment, the base (An Aggregator that was away), the recovery window as C2 "
        "and I2 read it, withdrawn Payloads as I7 reads them and the serving duty of a record's Payload (What a "
        "record carries), replayed from sealed Entries. Each history replays `epochs` in order. An Epoch is "
        "simplified to its height, sealed_at, the parameter map in force at it (`parameters`, complete) and its "
        "Entries, each {type, body} with a `name` beside it; there are no Checkpoints and no Merkle tree of the "
        "Log. Entries are listed in the order the Epoch stores them, and the Entry index is the position in that "
        "list; an Epoch not in canonical order (WIST-3 section 3.3: grouped publisher_declaration, "
        "registry_update, publisher_catalog, publisher_item, then by ascending SHA-256(0x00 || JCS(entry))) is "
        "rejected. Declarations apply as vectors/wist1/collection-narrowing.json "
        "applies them (WIST-1 section 5.2 and ADR-0051's narrowing), then registry_update Entries, then "
        "publisher_catalog and then publisher_item Entries in ascending Entry index. The only registry_update "
        "carried is a payload_withdrawal (WIST-3 section 6.2, WIST-4 section 5.1) whose details.delta_id is an "
        "Item ID, signed by the test-only Log key, which the replay does not authenticate. Its details contract "
        "(WIST-4 section 5.1) is judged once the Epoch's Items have applied: delta_id names an Item of kind page, "
        "since no other has a Payload, that a valid publisher_item Entry sealed at or below the act's Epoch against a Catalog whose publisher is the act's "
        "subject; an act that breaks it is ignored (`failed` [contract], WIST4-E04) and blocks nothing. I7 reads "
        "the delta_id of each act that meets it, and the earliest such act of an Item ID gives the height every "
        "rule reads; `entries` gives each registry_update its disposition beside those of the Catalogs and "
        "Items. Each Catalog is judged by C1 to C4 and each Item by I1 to I7 with the "
        "Epoch's sealed_at as the clock, the Epoch's parameter map, and the Declaration in force once the Epoch's "
        "transitions have applied. The Publisher of a Catalog Entry is catalog.publisher and that of an Item "
        "Entry the named Catalog's publisher, whatever item.publisher spells: I2, I4, I5 and I7 read that "
        "Publisher's window, Declaration and records. A Catalog of a Publisher with no Declaration in force fails "
        "C1 with WIST1-E02. C2 to C4 are read only for a Catalog of the form C1 requires, and I2 and I4 to I7 "
        "only where I1 and I3 hold; `failed` lists every condition read that fails. Two publisher_catalog "
        "Entries with the same strings as publisher and collection reject the Epoch; an Entry in which either is "
        "not a string is compared with none. I7 fails for an Item of kind page that is its URL's record's Item "
        "or whose Item ID a withdrawal sealed in an Epoch below the Item's names, and for an Item of kind removed "
        "without a record; the record is that of the Publisher and URL whatever Collection it carries, and no "
        "history reaches a record of another Collection, since disjoint Scopes and narrowing leave none that an "
        "Item passing I5 could meet. A valid Catalog whose name has a floor and whose generated_at is more than "
        "removal_retention_days, the constant 180, times 86 400 seconds after it is a base and removes every "
        "record of its Publisher in its Collection before the Epoch's Items apply; no parameter map carries "
        "removal_retention_days, catalog_refresh_seconds is from 1 to 7 776 000 and url_cap_bytes at most 32 768 in "
        "every map; `parameter_cases` gives maps and whether a replay accepts or refuses them. "
        "`expected` gives per Epoch `status` (`accepted`, or `rejected` with `codes`, the ascending codes of every "
        "whole-Epoch rejection the Epoch meets, WIST3-E03 or the code WIST-1 section 5.2 gives a rejected "
        "Declaration, of which a validator reports any; the state then unchanged); for an accepted Epoch, per publisher_catalog and publisher_item Entry its `disposition` "
        "(`valid`, or `ignored` with the conditions `failed` and the `codes` among which WIST-1 section 7 leaves "
        "the choice), `records_removed` in the order removed with the cause (`narrowing`, `base`, "
        "`removed_item`), and `state` after the Epoch: per Publisher the current Declaration, pending head and "
        "open window end; per Publisher and Collection name the latest Catalog's ID, the floor, its sealing "
        "height and whether it applied as a base; per Publisher and URL the record (the Item, its Collection, and "
        "the Catalog ID and generated_at of the Catalog proved against) and the removal states a valid removed Item left "
        "(that Item's ID, Catalog ID and generated_at), which a record removed by narrowing or a base does not "
        "leave; lists in ascending octet order of publisher, then collection or url. Histories that carry "
        "`payload_duties` give after each Epoch every Payload the Aggregator must serve (WIST-3 section 6.1): per "
        "Item of kind page, with its publisher and url, `until` null while the Item is its URL's record, and "
        "otherwise the latest end of an availability window (payload_window_days of 86 400 seconds, read from the "
        "map of the Epoch that sealed the Item, counted from that Epoch's sealed_at) among the Epochs that sealed "
        "it; the Epoch at which an Item, narrowing or a base replaced or removed the record gives no window, and a "
        "duty is listed while the Epoch's sealed_at is earlier than `until`; it is null again while the Item is the "
        "record again, and a withdrawal ends it for good; ordered by publisher, url, then Item ID. Every ignored "
        "Entry or rejected Epoch fails "
        "one rule beside a twin that passes it, except where a rule cannot fail alone: a Catalog sealed again "
        "fails C3 and C4, and an Item of a Collection the Declaration no longer names fails I4 and I5; an Epoch "
        "meeting a Declaration rejection and WIST3-E03 stands beside a twin meeting each alone. The "
        "per-domain capacity counts publisher_catalog and publisher_item Entries, valid or ignored, per Canonical "
        "Host, since no Public Suffix List snapshot is in force, and a body whose publisher is not a Canonical "
        "Host counts toward none; no fixture carries label or dispute Entries or a registry_update other than a "
        "payload_withdrawal, and recovery_window_days and declaration_activation_epochs are constant within a "
        "history. Payloads, tree files and the rules of Waiting, the queue and settlement are not exercised. Keys "
        "derive from the stated test-only seeds."),
        "keys": KEYS_MEMBER, "histories": histories, "parameter_cases": parameter_cases}


def order_vectors():
    u = J + "u"
    pu, pu2, pu3 = page(u, "u one"), page(u, "u two"), page(u, "u three")
    ru = removed(u, "2026-10-01T01:00:00Z")
    x = Cat([pu, pa_of()], at(1))
    y = Cat([pu2, pa_of()], at(3))
    w = Cat([pu3, pa_of()], at(3))
    z = Cat([ru, pa_of()], at(4))
    early_removal = Cat([ru, pa_of()], at(2))
    retention = items.REMOVAL_RETENTION_DAYS * DAY
    base = Cat([pu2, pa_of()], seconds(x.inner["generated_at"]) + retention + 1)
    assert w.inner["generated_at"] == y.inner["generated_at"] and w.id != y.id
    order_cases = []
    for name, listed in (("two instants", [y, x]), ("equal instants, two Catalog IDs", [w, y]),
                         ("three Catalogs of two instants", [z, w, x, y]),
                         ("Catalogs of two Collections", [Cat([], at(3), "store"), x, y])):
        ordered = combined_view.in_catalog_order([c.inner for c in listed])
        order_cases.append({"name": name, "catalogs": [c.inner for c in listed],
                            "expected": [catalogs.catalog_id(c) for c in ordered]})
    earlier_id, later_id = sorted((y, w), key=lambda c: c.id.encode())
    pu_one, pu_two = page(u, "u one"), page(u, "u two")
    twin_k = Cat([pu_one, pu_two, pa_of()], at(1))
    sealed_k = [[("K", cat("journal", twin_k)), ("u one@K", item_at(twin_k, pu_one))],
                [("K", cat("journal", twin_k)), ("u two@K", item_at(twin_k, pu_two))]]
    greater_item = max(items.item_id(pu_one), items.item_id(pu_two), key=str.encode)
    greater_log = "A" if greater_item == items.item_id(pu_one) else "B"
    removal_at_m, page_at_m = removed(u, "2026-10-01T02:00:00Z"), page(u, "u two")
    mixed = Cat([removal_at_m, page_at_m, pa_of()], at(4))
    mixed_item = max(items.item_id(removal_at_m), items.item_id(page_at_m), key=str.encode)
    mixed_log = "A" if mixed_item == items.item_id(removal_at_m) else "B"
    z2 = Cat([ru, page(J + "a", "a two")], at(5))

    genesis = ("G", decl("owner", G))

    def snapshot_state(state, url):
        record = next((r for r in state["records"] if r["publisher"] == "example.com" and r["url"] == url), None)
        if record is not None:
            return {"state": "record", "item": items.item_id(record["item"]),
                    **{k: record[k] for k in ("collection", "catalog", "generated_at")}}
        removal = next((r for r in state["removals"] if r["publisher"] == "example.com" and r["url"] == url), None)
        if removal is not None:
            return {"state": "removed", **{k: removal[k] for k in ("item", "catalog", "generated_at")}}
        return None

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
        assert snapshot_state(results[-1]["state"], u) == state.url_state("example.com", u)
        return {"name": name, "epochs": epochs, "results": summary}, state.url_state("example.com", u)

    def case(name, why, logs, expected_logs, check=None, from_snapshot=None):
        built, states = [], {}
        for log_name, rows in logs:
            entry, state = log(log_name, rows)
            built.append(entry)
            states[log_name] = state
        combined = combined_view.combined_state(states)
        assert (combined and combined["logs"]) == expected_logs, (name, combined)
        if check is not None:
            check(combined)
        out = {"name": name, "why": why, "publisher": "example.com", "url": u, "logs": built,
               "expected": {"log_states": states, "combined": combined}}
        if from_snapshot is not None:
            out["expected"]["snapshot"] = {"log": from_snapshot, "removals": sealing.replay([
                {"height": e["height"], "sealed_at": e["sealed_at"], "parameters": e["parameters"],
                 "entries": [n["entry"] for n in e["entries"]]}
                for e in built[[b["name"] for b in built].index(from_snapshot)]["epochs"]])[0][-1]["state"]["removals"]}
        return out

    sealed_x = [("X", cat("journal", x)), ("u@X", item(x, u))]
    sealed_y = [("Y", cat("journal", y)), ("u@Y", item(y, u))]
    sealed_w = [("W", cat("journal", w)), ("u@W", item(w, u))]
    sealed = {y.id: sealed_y, w.id: sealed_w}
    after_z = successor(G, collections=[collection("journal", [prefix(J + "keep/")], [key("journal")]), STORE])
    late_base = Cat([pu2, pa_of()], seconds(z.inner["generated_at"]) + retention + 1)
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
             "A seals the removed Item of u against Z, then a Catalog more than removal_retention_days, 180 days, "
             "after Z, a base. The removal state stays, and is later than B's record against X.",
             [("A", [sealed_x, [], [], sealed_z,
                     {"entries": [("base", cat("journal", late_base))],
                      "sealed_at": seconds(late_base.inner["generated_at"]) + 60}]),
              ("B", [sealed_x])], ["A"], check=lambda c: c["state"]["state"] == "removed"),
        case("a record removed by a base in one Log and held by another",
             "A seals X and u against it, then a Catalog more than 180 days later, a base that removes u's record: "
             "A has no state. B holds u against X.",
             [("A", [{"entries": sealed_x},
                     {"entries": [("base", cat("journal", base))], "sealed_at": seconds(base.inner["generated_at"]) + 60}]),
              ("B", [sealed_x])], ["B"]),
        case("two records of one URL proved against one Catalog",
             "K's root is computed over a list that holds two Items of u, u one and u two, under one key. A seals K "
             "and u one against it, B seals K and u two: between states proved against one Catalog the state of "
             "the greater Item ID in octet order is taken.",
             [("A", [sealed_k[0]]), ("B", [sealed_k[1]])], [greater_log],
             check=lambda c: c["state"]["item"] == greater_item),
        case("a removal and a record of one URL proved against one Catalog",
             "M's root is computed over a list that holds the removed Item of u and the page u two under one key. A "
             "seals X and u against it, then M and the removed Item of u, which removes the record; B seals M and "
             "u two. Both states are proved against M, and the one of the greater Item ID is taken.",
             [("A", [sealed_x, [], [], [("M", cat("journal", mixed)), ("u removed@M", item_at(mixed, removal_at_m))]]),
              ("B", [[], [], [], [("M", cat("journal", mixed)), ("u two@M", item_at(mixed, page_at_m))]])],
             [mixed_log], check=lambda c: c["state"]["item"] == mixed_item),
        case("a Snapshot state above a removal, with another Log's record",
             "A seals the removed Item of u against Z at height 4 and a changed a against Z2 at height 5; its state "
             "at height 5, as a Snapshot carries it, lists the removal of u with Z's Catalog ID and generated_at. "
             "B's record of u against the earlier X is not taken: the URL is removed.",
             [("A", [sealed_x, [], [], sealed_z, [("Z2", cat("journal", z2)), ("a two@Z2", item(z2, J + "a"))]]),
              ("B", [sealed_x])], ["A"], check=lambda c: c["state"]["state"] == "removed" and c["state"]["catalog"] == z.id,
             from_snapshot="A"),
    ]
    return {"note": (
        "ADR-0052 Several Logs. order_cases list Catalog inner objects of one Publisher; `expected` gives their "
        "Catalog IDs (sha256: + hex(SHA-256(JCS(catalog)))) from earliest to latest: by generated_at, then, "
        "between equal instants, by Catalog ID, the greater string in octet order being the later, across the "
        "Collections of the Publisher. combined_cases "
        "give Logs that replay as vectors/wist3/catalog-sealing.json's histories do, each from the Declaration G "
        "at height 0, with `results` giving every Entry's disposition. `expected.log_states` is each Log's state "
        "for `publisher` and `url` after its last Epoch: a record {state: record, item, collection, catalog, "
        "generated_at}, a removal state {state: removed, item, catalog, generated_at} left by a valid removed Item, "
        "item being that Item's ID, or "
        "null, which a record removed by narrowing or a base leaves. A removal state stays through narrowing "
        "and through a base and ends when a valid page Item becomes the URL's record. `expected.combined` is the state a Consumer "
        "of all the Logs takes: the one proved against the latest Catalog in the order above among the Logs that "
        "hold a state, with `logs` naming those that hold it; null when none does. Between states proved against "
        "one Catalog the state of the greater Item ID in octet order is taken; two such states arise where the "
        "Catalog's root is computed over a list holding two Items under one key, which no walk of its tree "
        "accepts but a proof verifies. `snapshot`, where present, names a Log (`log`) and lists as `removals` the "
        "removal states of that Log's state after its last Epoch, each with its publisher, url, Item ID, Catalog "
        "ID and generated_at, as a Snapshot carries them. Epochs are simplified as in catalog-sealing.json (no Checkpoints and no Merkle "
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

    def case(name, why, sequence, clock, stop, expect_in, expect_out, withdrawn=()):
        got = served_files.must_serve(sequence, stop, stamp(clock), withdrawn)
        for f in expect_in:
            assert f in got, (name, f)
        for f in expect_out:
            assert f not in got, (name, f)
        out = {"name": name, "why": why, "served": sequence, "stop": stop, "clock": stamp(clock)}
        if withdrawn:
            out["withdrawn"] = list(withdrawn)
        out["expected"] = got
        cases.append(out)

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
    case("a withdrawn Payload that the served Catalog names",
         "A payload_withdrawal naming a's Item ID is sealed: the Publisher stops serving a's Payload, which the "
         "served C2 names, while the tree files that list a stay due.", replaced, t + HOUR + 100, [],
         tree_1 + [f for f in named_files(l2) if "/tree/" in f], payload_a, withdrawn=[items.item_id(base[0])])
    case("a withdrawn Payload inside the interval of a replaced Catalog",
         "A payload_withdrawal naming the Item ID of b as C1 listed it is sealed: inside the interval that would "
         "keep it due, the Payload of b is no longer served; C1's tree files are.", replaced, t + HOUR + 100, [],
         tree_1, payload_b, withdrawn=[items.item_id(base[1])])
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
        "suite's value that no Log amends; files in `stop` are removed from the list. `expected` states the duty "
        "to serve: for a replaced file it holds at every instant earlier than the end of replaced_file_seconds, "
        "so one second before that end and not at it. From that instant the Publisher may stop serving the file "
        "and no rule obliges it to, so a file absent from `expected` may still be served; the fixture asserts "
        "nothing about files the Publisher serves beyond those due. The sequences are supplied as served, with "
        "tree files split at two Items per bucket, and are not derived from publications. A file in `stop` is "
        "removed whether or not the served Catalog names it. `withdrawn`, where present, lists Item IDs that a "
        "payload_withdrawal sealed at a height the Publisher has reached names (WIST-2 section 3.1): the Payload "
        "file of each, payloads/ followed by the digits of its Item ID and .json, is removed whatever Catalog names "
        "it and whatever interval it is inside, and no other file is."),
        "cases": cases}


def record_key(entry):
    return (entry["publisher"].encode(), entry["url"].encode())


def apply_record_events(state, events, height):
    for event in events:
        kind = event["event"]
        if kind == "declaration":
            state["declared"].add(event["domain"])
        elif kind == "narrowing":
            for url in event["urls"]:
                del state["records"][(event["publisher"], url)]
        elif kind == "withdrawal":
            state["withdrawn"].setdefault(event["item"], height)
        elif kind == "base":
            for slot in [s for s, r in state["records"].items()
                         if s[0] == event["publisher"] and r["collection"] == event["collection"]]:
                del state["records"][slot]
        elif kind == "record":
            slot = (event["publisher"], event["item"]["url"])
            state["records"][slot] = {"item": event["item"], "collection": event["collection"],
                                      "catalog": event["catalog"], "generated_at": event["generated_at"]}
            state["removals"].pop(slot, None)
        else:
            slot = (event["publisher"], event["url"])
            del state["records"][slot]
            state["removals"][slot] = {"item": event["item"], "catalog": event["catalog"],
                                       "generated_at": event["generated_at"]}


def record_summary(state):
    records = [{"publisher": p, "url": u, "item": items.item_id(r["item"]), "collection": r["collection"],
                "catalog": r["catalog"], "generated_at": r["generated_at"]}
               for (p, u), r in state["records"].items()]
    removals = [{"publisher": p, "url": u, **r} for (p, u), r in state["removals"].items()]
    tuples = materialization.materialized(state["records"], state["declared"], state["withdrawn"])
    return {"records": sorted(records, key=record_key), "removals": sorted(removals, key=record_key),
            "materialized": tuples, "content_digest": materialization.content_digest(tuples)}


def record_materialization_vectors():
    cases = []

    def case(name, why, spec, snapshot_after, check):
        epochs = build_epochs(spec)
        results, _ = sealing.replay([{"height": e["height"], "sealed_at": e["sealed_at"],
                                      "parameters": e["parameters"],
                                      "entries": [n["entry"] for n in e["entries"]]} for e in epochs])
        declarations, catalog_envelopes = {}, {}
        state = {"records": {}, "removals": {}, "withdrawn": {}, "declared": set()}
        out_epochs, expected, snapshot = [], [], None
        for epoch, result in zip(epochs, results):
            assert result["status"] == "accepted", (name, result)
            assert all(d is None or d["disposition"] == "valid" for d in result["entries"]), (name, result)
            height, after = epoch["height"], result["state"]
            events = []
            entries = [n["entry"] for n in epoch["entries"]]
            for entry in entries:
                if entry["type"] == "publisher_declaration":
                    inner = entry["body"]["publisher"]
                    declarations.setdefault(rules.declaration_hash(inner), (entry["body"], height))
                    events.append({"event": "declaration", "domain": inner["domain"]})
            narrowed = {}
            for removed_record in result["records_removed"]:
                if removed_record["cause"] == "narrowing":
                    narrowed.setdefault(removed_record["publisher"], []).append(removed_record["url"])
            events += [{"event": "narrowing", "publisher": p, "urls": urls} for p, urls in narrowed.items()]
            for entry in entries:
                if entry["type"] == "registry_update":
                    events.append({"event": "withdrawal", "item": entry["body"]["update"]["details"]["delta_id"]})
            for entry in entries:
                if entry["type"] == "publisher_catalog":
                    catalog = entry["body"]["catalog"]
                    catalog_envelopes[catalogs.catalog_id(catalog)] = entry["body"]
                    held = next(c for c in after["catalogs"] if c["publisher"] == catalog["publisher"]
                                and c["collection"] == catalog["collection"])
                    if held["base"] and held["sealing_height"] == height:
                        events.append({"event": "base", "publisher": catalog["publisher"],
                                       "collection": catalog["collection"], "catalog": held["catalog"]})
            for entry in entries:
                if entry["type"] != "publisher_item":
                    continue
                item_, body = entry["body"]["item"], entry["body"]
                publisher = item_["publisher"]
                if items.kind(item_) == "page":
                    record = next(r for r in after["records"] if r["publisher"] == publisher
                                  and r["url"] == item_["url"])
                    events.append({"event": "record", "publisher": publisher, "item": item_,
                                   "collection": body["collection"], "catalog": body["catalog"],
                                   "generated_at": record["generated_at"]})
                else:
                    removal = next(r for r in after["removals"] if r["publisher"] == publisher
                                   and r["url"] == item_["url"])
                    events.append({"event": "removal", "publisher": publisher, "url": item_["url"],
                                   "item": items.item_id(item_), "catalog": body["catalog"],
                                   "generated_at": removal["generated_at"]})
            apply_record_events(state, events, height)
            summary = record_summary(state)
            assert summary["records"] == [{**r, "item": items.item_id(r["item"])} for r in after["records"]], name
            assert summary["removals"] == after["removals"], name
            out_epochs.append({"height": height, "sealed_at": epoch["sealed_at"], "events": events})
            expected.append({"height": height, **summary})
            if height == snapshot_after:
                tuples = []
                for d in after["declarations"]:
                    envelope, sealed = declarations[d["current"]]
                    tuples.append(["declaration", d["publisher"], envelope, sealed, envelope["publisher"]["seq"]])
                for c in after["catalogs"]:
                    tuples.append(["collection", c["publisher"], c["collection"], catalog_envelopes[c["catalog"]],
                                   c["sealing_height"]])
                for r in after["records"]:
                    tuples.append(["record", r["publisher"], r["url"], r["item"], r["collection"], r["catalog"],
                                   r["generated_at"]])
                for r in after["removals"]:
                    tuples.append(["removal", r["publisher"], r["url"], r["item"], r["catalog"], r["generated_at"]])
                for item_id, withdrawn_at in state["withdrawn"].items():
                    publisher = next(e["publisher"] for ep in out_epochs for e in ep["events"]
                                     if e["event"] == "record" and items.item_id(e["item"]) == item_id)
                    tuples.append(["withdrawal", item_id, publisher, withdrawn_at])
                snapshot = {"height": height, "tuples": sorted(tuples, key=rfc8785.dumps)}
        out = {"name": name, "why": why, "epochs": out_epochs, "expected": expected}
        if snapshot is not None:
            resumed = {"records": {}, "removals": {}, "withdrawn": {}, "declared": set()}
            for t in snapshot["tuples"]:
                if t[0] == "declaration":
                    resumed["declared"].add(t[1])
                elif t[0] == "record":
                    resumed["records"][(t[1], t[2])] = {"item": t[3], "collection": t[4], "catalog": t[5],
                                                        "generated_at": t[6]}
                elif t[0] == "removal":
                    resumed["removals"][(t[1], t[2])] = {"item": t[3], "catalog": t[4], "generated_at": t[5]}
                elif t[0] == "withdrawal":
                    resumed["withdrawn"][t[1]] = t[3]
            assert {"height": snapshot["height"], **record_summary(resumed)} == expected[snapshot["height"]], name
            for epoch, wanted in zip(out_epochs[snapshot["height"] + 1:], expected[snapshot["height"] + 1:]):
                apply_record_events(resumed, epoch["events"], epoch["height"])
                assert {"height": epoch["height"], **record_summary(resumed)} == wanted, name
            out["snapshot"] = snapshot
        check(out)
        cases.append(out)

    def materialized_at(out, height):
        return [(t["publisher"], t["url"]) for t in out["expected"][height]["materialized"]]

    blog, old = "https://example.com/blog/", "https://example.com/old/"
    e1 = {"wist_version": "1.0.0", "seq": 0, "domain": "example.com", "keys": [key("owner")],
          "recovery_keys": [key("recovery")]}
    qa, qb, qd = page(blog + "a", "record a"), page(blog + "b", "record b"), page(blog + "d", "record d")
    qc, qx, rc = page(old + "c", "record c"), page(old + "x", "record x"), removed(old + "c")
    m1 = Cat([qa, qb, qc, qx], at(1), "default")
    m2 = Cat([qa, qb, rc, qx], at(2), "default")
    m3 = Cat([qa, qb, rc, qx, qd], at(3), "default")
    narrowed = successor(e1, collections=[collection("default", [prefix(blog)])])
    base_at = seconds(m3.inner["generated_at"]) + items.REMOVAL_RETENTION_DAYS * DAY + 1
    m5 = Cat([qa], base_at, "default")

    def one_publisher_check(out):
        assert materialized_at(out, 2) == [("example.com", blog + "a"), ("example.com", old + "x")]
        assert [r["url"] for r in out["expected"][3]["records"]] == [blog + "a", blog + "b", blog + "d", old + "x"]
        assert materialized_at(out, 3) == [("example.com", blog + "a"), ("example.com", old + "x")]
        assert [r["url"] for r in out["expected"][4]["removals"]] == [old + "c"]
        assert [r["url"] for r in out["expected"][5]["records"]] == [blog + "a"]
        assert [r["url"] for r in out["expected"][5]["removals"]] == [old + "c"]

    case("records of one Publisher through a removal, withdrawals, narrowing and a base",
         "example.com's default Collection. At height 1 a, b, c and x become records. At height 2 a withdrawal of "
         "b's Item is sealed and the removed c removes c's record, leaving a removal state: b stays a record and "
         "is not materialized. At height 3 d is sealed together with a withdrawal of its own Item: d becomes the "
         "record and is never materialized. At height 4 a Declaration narrows the Collection to blog/: x's record "
         "leaves with no removal state and c's removal state stays. At height 5 a Catalog more than "
         "removal_retention_days after the floor is a base: the records of a, b and d leave before the Items "
         "apply, a is sealed again against it and is the record again, and c's removal state stays.",
         [{"entries": [("E", decl("owner", e1))]},
          {"entries": [("M1", cat("owner", m1)), ("a@M1", item(m1, blog + "a")), ("b@M1", item(m1, blog + "b")),
                       ("c@M1", item(m1, old + "c")), ("x@M1", item(m1, old + "x"))]},
          {"entries": [("withdrawal of b", withdrawal(qb, at(2, 0))), ("M2", cat("owner", m2)),
                       ("c removed@M2", item(m2, old + "c"))]},
          {"entries": [("withdrawal of d", withdrawal(qd, at(3, 0))), ("M3", cat("owner", m3)),
                       ("d@M3", item(m3, blog + "d"))]},
          {"entries": [("E narrowed", decl("owner", narrowed))]},
          {"entries": [("M5", cat("owner", m5)), ("a@M5", item(m5, blog + "a"))], "sealed_at": base_at + 60}],
         3, one_publisher_check)

    news = "https://news.example.com/u"
    p2 = {"wist_version": "1.0.0", "seq": 0, "domain": "example.com", "subdomain_scope": ["news.example.com"],
          "keys": [key("owner")], "recovery_keys": [key("recovery")]}
    z2 = {"wist_version": "1.0.0", "seq": 0, "domain": "zeta.example", "subdomain_scope": ["news.example.com"],
          "keys": [key("store2")]}
    n2 = {"wist_version": "1.0.0", "seq": 0, "domain": "news.example.com", "keys": [key("docs")]}
    up1 = page(news, "u by example.com")
    up2 = page(news, "u by example.com, changed")
    up3 = page(news, "u by example.com, again")
    uz = page(news, "u by zeta.example", publisher="zeta.example")
    un = page(news, "u by news.example.com", publisher="news.example.com")
    urm = removed(news)
    k1 = Cat([up1], at(1), "default")
    kz = Cat([uz], at(1), "default", "zeta.example")
    k3 = Cat([up2], at(3), "default")
    k4 = Cat([urm], at(4), "default")
    kn = Cat([un], at(6), "default", "news.example.com")
    k6 = Cat([up3], at(6), "default")

    def one_url_check(out):
        assert [materialized_at(out, h) for h in range(1, 7)] == [
            [("example.com", news)], [("zeta.example", news)], [("example.com", news)], [("zeta.example", news)],
            [], [("news.example.com", news)]]
        held = {(t[1], t[2]) for t in out["snapshot"]["tuples"] if t[0] == "record"}
        assert ("zeta.example", news) in held and materialized_at(out, 3) == [("example.com", news)]
        assert [r["publisher"] for r in out["expected"][6]["records"]] == ["example.com", "news.example.com",
                                                                          "zeta.example"]
        assert out["expected"][5]["removals"] and not out["expected"][6]["removals"]

    case("one URL held by three Publishers",
         "https://news.example.com/u. example.com and zeta.example both name news.example.com in subdomain_scope. "
         "At height 1 each seals an Item of u: example.com, an ancestor of the host, is materialized and "
         "zeta.example, no ancestor, is not. At height 2 a withdrawal of example.com's Item is sealed: its record "
         "stays and no withdrawal-free record of an ancestor remains, so zeta.example's is materialized. At height "
         "3 example.com's changed Item replaces its record and is materialized again. A Snapshot is taken at "
         "height 3. At height 4 example.com's removed Item removes its record: zeta.example's, unmaterialized at "
         "the Snapshot, is materialized. At height 5 news.example.com's first Declaration is sealed: from then "
         "only the host's own Publisher's record is materialized, and it holds none. At height 6 news.example.com "
         "seals an Item of u, which is materialized, and example.com seals another, which ends its removal state "
         "and is not materialized.",
         [{"entries": [("P", decl("owner", p2)), ("Z", decl("store2", z2))]},
          {"entries": [("K1", cat("owner", k1)), ("KZ", cat("store2", kz)), ("u@K1", item(k1, news)),
                       ("u@KZ", item(kz, news))]},
          {"entries": [("withdrawal of u@K1", withdrawal(up1, at(2, 0)))]},
          {"entries": [("K3", cat("owner", k3)), ("u@K3", item(k3, news))]},
          {"entries": [("K4", cat("owner", k4)), ("u removed@K4", item(k4, news))]},
          {"entries": [("N", decl("docs", n2))]},
          {"entries": [("KN", cat("docs", kn)), ("K6", cat("owner", k6)), ("u@KN", item(kn, news)),
                       ("u@K6", item(k6, news))]}],
         3, one_url_check)

    return {"note": (
        "WIST-3 section 7: the records, removal states and materialized records of one Log. Each case gives per "
        "Epoch its height, sealed_at and `events`, the record events its valid Entries make, in the order the "
        "Entries apply (WIST-3 section 3.3): `declaration`, a sealed publisher_declaration Entry of `domain`; "
        "`narrowing`, the records of `publisher` at `urls` that narrowing removes (WIST-1 section 5.2); "
        "`withdrawal`, a payload_withdrawal that meets its details contract, naming the Item ID `item`; `base`, "
        "a valid Catalog of `publisher` and `collection` that is a base, which removes every record of that "
        "Publisher whose Collection is `collection`; `record`, an Item of kind page that becomes the record of "
        "`publisher` and its url, with its Collection and the Catalog ID and generated_at of the Catalog it was "
        "proved against, in place of any record and ending any removal state; and `removal`, an Item of kind "
        "removed, with its Item ID and the same Catalog members, which removes the record of `publisher` and "
        "`url` and leaves that removal state. A record that narrowing or a base removes leaves no removal state, "
        "a removal state stays through narrowing and a base, and a withdrawal removes no record. `expected` "
        "gives after each Epoch the records (the Item ID, Collection, Catalog ID and generated_at), the removal "
        "states, the materialized records as their content tuples, and the content_digest over them. A record "
        "is materialized when no withdrawal sealed at or below the height names its Item and the one-URL rule "
        "selects its Publisher among the records of its URL that no such withdrawal names: the host's own "
        "Publisher once a publisher_declaration Entry of the host is sealed, else the nearest ancestor of the "
        "host, else the least domain in octet order. `snapshot` gives the state tuples of a Snapshot taken at "
        "`height` (declaration, collection, record, removal and withdrawal; no Aggregator key, parameter, "
        "suffix list, Label or dispute is live): a Consumer resumed from them, holding a host as self-declared "
        "where a declaration tuple names it, and applying the events of the later Epochs, reaches every later "
        "`expected`. The events are those of a replay of signed Entries under the rules of "
        "vectors/wist3/catalog-sealing.json, every Entry valid; Epochs carry no Checkpoint and no Merkle tree. "
        "Keys derive from the stated test-only seeds."),
        "keys": KEYS_MEMBER, "cases": cases}


write_json(WIST3 / "catalog-sealing.json", with_payloads(sealing_vectors()))
write_json(WIST3 / "record-materialization.json", with_payloads(record_materialization_vectors()))
write_json(MULTILOG / "catalog-order.json", with_payloads(order_vectors()))
write_json(WIST2 / "served-files.json", served_vectors())
print("sealing vectors written")
