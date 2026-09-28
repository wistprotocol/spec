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
import items
import sealing
import tree_files
import waiting

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIST1 = ROOT / "vectors" / "wist1"
WIST2 = ROOT / "vectors" / "wist2"
WIST3 = ROOT / "vectors" / "wist3"

KEY_NAMES = ("owner", "owner2", "recovery", "recovery2", "fresh", "journal", "journal2",
             "store", "store2", "docs")
USED_KEYS = ("owner", "owner2", "recovery", "fresh", "journal", "journal2", "store", "store2", "docs")
SEEDS = {name: bytes([0xC1 + i]) * 32 for i, name in enumerate(KEY_NAMES)}
PRIVATE = {name: Ed25519PrivateKey.from_private_bytes(SEEDS[name]) for name in USED_KEYS}
X = {name: rules.b64u(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
     for name, key in PRIVATE.items()}
KID = {name: rules.thumbprint(x) for name, x in X.items()}
KEYS_MEMBER = {name: {"seed_hex": SEEDS[name].hex(), "x": X[name], "kid": KID[name]} for name in USED_KEYS}
KEY_NAME = {kid: name for name, kid in KID.items()}


def seconds(instant):
    return calendar.timegm(time.strptime(instant, "%Y-%m-%dT%H:%M:%SZ"))


def stamp(value):
    return catalogs.log_timestamp(value)


NBF = seconds("2026-09-01T00:00:00Z")
T0 = seconds("2026-10-01T00:00:00Z")
MINUTE = 60
HOUR = 3600
DAY = 86400
OBSERVED = "2026-09-30T10:00:00Z"
J = "https://example.com/journal/"
S = "https://example.com/store/"
DOCS = "https://example.com/docs/"
BLOG = "blog.example.com"
BJ = "https://blog.example.com/journal/"
DEFAULT_MAP = {
    "clock_skew_seconds": 600, "catalog_items_max": 16777216, "catalog_refresh_seconds": 604800,
    "removal_retention_days": 180, "domain_epoch_entries_max": 10000, "max_inclusion_epochs": 4,
    "record_seal_epochs": 24, "url_cap_bytes": 2048, "extract_cap_bytes": 32768, "links_cap_bytes": 4096,
    "link_url_cap_bytes": 2048, "summary_cap_bytes": 2048, "tree_file_cap_bytes": 65536, "tree_depth_max": 16,
    "collections_max": 16, "scope_entries_max": 32, "recovery_window_days": 7, "declaration_activation_epochs": 24}
PAYLOADS = {}


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


def exact(url):
    return {"url": url, "match": "exact"}


def collection(name, scope, keys=None):
    out = {"name": name, "scope": scope}
    if keys is not None:
        out["keys"] = keys
    return out


JOURNAL = collection("journal", [prefix(J)], [key("journal")])
STORE = collection("store", [prefix(S)], [key("store")])
G = {"wist_version": "1.0.0", "seq": 0, "domain": "example.com", "subdomain_scope": ["www.example.com"],
     "keys": [key("owner")], "recovery_keys": [key("recovery")], "collections": [JOURNAL, STORE]}
B = {"wist_version": "1.0.0", "seq": 0, "domain": BLOG, "keys": [key("docs")],
     "collections": [collection("journal", [prefix(BJ)])]}


def successor(predecessor, **fields):
    inner = copy.deepcopy(predecessor)
    inner["seq"] = predecessor["seq"] + 1
    inner["prev_declaration"] = rules.declaration_hash(predecessor)
    for member, value in fields.items():
        inner[member] = value
    return inner


def salt_for(label):
    return rules.b64u(hashlib.sha256(("salt " + label).encode()).digest()[:16])


def page(url, label=None, observed_at=OBSERVED, publisher="example.com"):
    label = label or url
    publication = {"url": url, "lang": "en", "modified": observed_at,
                   "content": {"extract": f"Text of {label}.", "links": {"total": 0, "urls": []},
                               "summary": {"title": f"Title {label}"}}}
    item, payload = items.new_page_item(publisher, publication, salt_for(label))
    PAYLOADS[items.item_id(item)] = payload
    return item


def removed(url, observed_at=OBSERVED, publisher="example.com"):
    return {"publisher": publisher, "url": url, "observed_at": observed_at, "removed": True}


def tampered(payload):
    out = copy.deepcopy(payload)
    out["content"]["extract"] += " Altered."
    return out


def key_ordered(urls):
    return sorted(urls, key=items.item_key)


def reversed_pair(base):
    for i in range(200):
        for j in range(i + 1, 200):
            u, v = f"{base}{i:03d}", f"{base}{j:03d}"
            if items.item_key(v) < items.item_key(u):
                return u, v
    raise AssertionError


class Cat:
    def __init__(self, listed, generated_at, signer, name="journal", publisher="example.com",
                 capacity=tree_files.BUCKET_CAPACITY):
        self.listed = items.in_list_order(listed)
        tree, self.files = tree_files.write_tree(self.listed, capacity)
        self.inner = {"wist_version": "1.0.0", "publisher": publisher, "collection": name,
                      "generated_at": stamp(generated_at), "size": len(self.listed),
                      "root": items.root_string(self.listed), "tree": tree}
        self.envelope = sign(signer, "catalog", self.inner)
        self.id = catalogs.catalog_id(self.inner)

    def signed_by(self, signer):
        other = copy.copy(self)
        other.envelope = sign(signer, "catalog", self.inner)
        return other


class History:
    def __init__(self, name, why, **parameters):
        self.name, self.why = name, why
        self.parameters = {**DEFAULT_MAP, **parameters}
        self.events, self.declarations, self.catalogs, self.tree_files = [], {}, {}, {}
        self.height = -1
        self.last = T0 - HOUR
        self.clock = None

    def declare(self, name, signer, inner):
        self.declarations[name] = sign(signer, "publisher", inner)
        return inner

    def cat(self, name, listed, generated_at, signer, collection_name="journal", publisher="example.com",
            capacity=tree_files.BUCKET_CAPACITY):
        made = Cat(listed, generated_at, signer, collection_name, publisher, capacity)
        self.catalogs[name] = made
        return made

    def add(self, name, made):
        self.catalogs[name] = made
        return made

    def at(self, offset):
        return self.last + offset

    def epoch(self, *declarations, sealed_at=None, **parameters):
        self.height += 1
        self.last = sealed_at if sealed_at is not None else self.last + HOUR
        self.events.append({"event": "epoch", "height": self.height, "sealed_at": stamp(self.last),
                            "parameters": {**self.parameters, **parameters}, "declarations": list(declarations)})

    def pull(self, offset, declaration, collections, publisher="example.com", withhold=(), tamper=(),
             omit=()):
        served = {}
        for name, catalog_name in collections.items():
            made = self.catalogs[catalog_name]
            for digest, octets in made.files.items():
                self.tree_files[digest] = octets.decode()
            payloads = {}
            for listed in made.listed:
                if items.kind(listed) != "page" or listed["url"] in withhold:
                    continue
                payload = PAYLOADS[items.item_id(listed)]
                payloads[items.payload_name(listed)] = tampered(payload) if listed["url"] in tamper else payload
            served[name] = {"catalog": catalog_name,
                            "tree_files": sorted(d for d in made.files if d not in omit),
                            "payloads": dict(sorted(payloads.items()))}
        self.events.append({"event": "pull", "at": stamp(self.at(offset)), "publisher": publisher,
                            "declaration": declaration, "collections": served})


def run(history, check=None):
    aggregator = waiting.Aggregator()
    names = {rules.declaration_hash(e["publisher"]): n for n, e in history.declarations.items()}
    ids = {c.id: n for n, c in history.catalogs.items()}
    expected, epochs, previous = [], [], None
    for event in history.events:
        instant = seconds(event["at"] if event["event"] == "pull" else event["sealed_at"])
        assert previous is None or instant > previous, (history.name, event)
        previous = instant
        if event["event"] == "epoch":
            out = aggregator.epoch(event["height"], event["sealed_at"], event["parameters"],
                                   [history.declarations[n] for n in event["declarations"]])
            epochs.append({"height": event["height"], "sealed_at": event["sealed_at"],
                           "parameters": event["parameters"], "entries": out["entries"]})
        else:
            served = {}
            for name, s in event["collections"].items():
                served[name] = {"catalog": history.catalogs[s["catalog"]].envelope,
                                "tree_files": {d: history.tree_files[d].encode() for d in s["tree_files"]},
                                "payloads": s["payloads"]}
            envelope = history.declarations[event["declaration"]] if event["declaration"] else None
            out = aggregator.pull(event["publisher"], event["at"], envelope, served)
            out["declaration"]["sources"] = [names[h] for h in out["declaration"]["sources"]]
            for result in out["catalogs"]:
                if "sources" in result:
                    result["sources"] = [names[h] for h in result["sources"]]
                if "key" in result:
                    result["key"] = KEY_NAME[result["key"]]
        if "settlement" in out:
            for result in out["settlement"]:
                result["key"] = KEY_NAME[result["key"]]
        state = aggregator.state()
        for entry in state["queue"]:
            entry["key"] = KEY_NAME[entry["key"]]
        for entry in state["reductions_pending"]:
            entry["declaration"] = names[entry["declaration"]]
        out["state"] = state
        expected.append(out)
    results, _ = sealing.replay(epochs)
    for result in results:
        assert result["status"] == "accepted", (history.name, result)
        assert all(d is None or d["disposition"] == "valid" for d in result["entries"]), (history.name, result)
    view = View(expected, ids)
    if check is not None:
        check(view)
    return {"name": history.name, "why": history.why, "declarations": history.declarations,
            "catalogs": {n: c.envelope for n, c in history.catalogs.items()},
            "catalog_ids": {n: c.id for n, c in history.catalogs.items()},
            "tree_files": dict(sorted(history.tree_files.items())), "events": history.events,
            "expected": expected}


class View:
    def __init__(self, expected, ids):
        self.expected, self.ids = expected, ids

    def label(self, ref):
        if ref["type"] == "publisher_catalog":
            return self.ids[ref["catalog"]]
        return ref["url"]

    def sealed(self, event):
        return [self.label(r) for r in self.expected[event]["sealed"]]

    def left(self, event):
        return [(self.label(r), r["condition"], r["codes"], r["reported"]) for r in self.expected[event]["left"]]

    def deferred(self, event):
        return {self.label(r): r["reasons"] for r in self.expected[event]["deferred"]}

    def catalog(self, event, name, publisher="example.com"):
        return self.expected[event]["catalogs"][[c["collection"] for c in self.expected[event]["catalogs"]].index(name)]

    def outcome(self, event, name):
        found = self.catalog(event, name)
        return found["outcome"], found.get("codes")

    def items(self, event, name):
        return {i["url"]: i for i in self.catalog(event, name).get("items", [])}

    def collection(self, event, name, publisher="example.com"):
        return next(c for c in self.expected[event]["state"]["collections"]
                    if c["collection"] == name and c["publisher"] == publisher)

    def last_accepted(self, event, name, publisher="example.com"):
        found = self.collection(event, name, publisher)["last_accepted"]
        return self.ids.get(found)

    def urls(self, event):
        return {u["url"]: u for u in self.expected[event]["state"]["urls"]}


def waiting_vectors():
    histories = []

    h = History("a Catalog accepted at a pull and sealed with its Items in the next Epoch",
                "J1 is accepted at the pull after height 0 and takes place [1, 0]; its two Items wait from the same "
                "pull. All are eligible for height 1 and sealed there, the Catalog before the Items. The store's "
                "catalog.json is unavailable, so the store pulls nothing.")
    h.declare("G", "owner", G)
    h.epoch("G")
    a, b = page(J + "a"), page(J + "b")
    h.cat("J1", [a, b], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()

    def first(v):
        assert v.outcome(1, "journal") == ("accepted", None)
        assert v.outcome(1, "store") == ("unavailable", None)
        assert v.sealed(2) == ["J1"] + [i["url"] for i in items.in_list_order([a, b])]
        assert v.expected[2]["state"]["urls"] == []

    histories.append(run(h, first))

    h = History("a later accepted Catalog takes the place and eligibility Epoch of the waiting one",
                "domain_epoch_entries_max is 1. J1 is accepted at pull 1 and waits with place [1, 0]; S1 at pull 2 "
                "with place [2, 1]; J2 at pull 3 replaces the waiting J1 and takes [1, 0] and J1's eligibility "
                "Epoch 1. Height 1 seals J2 ahead of S1, which a new place for J2 would have reversed. The URL a "
                "waits from pull 1 whichever Item waits for it, so a2 is sealed at height 3 ahead of s, placed at "
                "pull 2. Each deferral moves the eligibility Epoch to the next height and the ceiling with it.",
                domain_epoch_entries_max=1)
    h.declare("G", "owner", G)
    h.epoch("G")
    a, a2, s = page(J + "a"), page(J + "a", "a two"), page(S + "s")
    h.cat("J1", [a], h.at(4 * MINUTE), "journal")
    h.cat("S1", [s], h.at(9 * MINUTE), "store", "store")
    h.cat("J2", [a2], h.at(14 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.pull(10 * MINUTE, "G", {"journal": "J1", "store": "S1"})
    h.pull(15 * MINUTE, "G", {"journal": "J2", "store": "S1"})
    for _ in range(4):
        h.epoch()

    def replacement(v):
        waiting_j = v.collection(3, "journal")["waiting"]
        assert waiting_j["place"] == [1, 0] and waiting_j["eligibility"] == 1 and waiting_j["ceiling"] == 5
        assert v.collection(3, "store")["waiting"]["place"] == [2, 1]
        assert v.urls(3)[J + "a"]["place"] == [1, 0, 0]
        assert v.sealed(4) == ["J2"] and v.sealed(5) == ["S1"] and v.sealed(6) == [J + "a"] and v.sealed(7) == [S + "s"]
        assert v.deferred(4) == {"S1": ["capacity"], J + "a": ["capacity"], S + "s": ["catalog_waiting"]}
        assert v.expected[7]["sealed"][0]["eligibility"] == 4 and v.expected[7]["sealed"][0]["ceiling"] == 8

    histories.append(run(h, replacement))

    h = History("a Catalog that fails C4 at its turn stays the last accepted Catalog",
                "J1 lists a and b; b's Payload is unavailable at pull 1, so b is not admitted and height 1 seals J1 "
                "and a. J1b carries J1's list one hour later, inside catalog_refresh_seconds, and b's Payload is "
                "served: b is admitted and waits. At height 2 J1b fails C4: it leaves waiting unreported and stays "
                "the last accepted Catalog, and b is sealed against J1, the latest Catalog of the same root. The pull "
                "order is then read against J1b: J1m, between J1 and J1b, is WIST2-E05 at pull 3; J1b served again "
                "is an idempotent re-serve at pull 4; J1c, one second after J1b, is accepted at pull 5 and fails C4 "
                "at height 3 in turn. At pull 6 J1, the latest Catalog and not the last accepted one, is served: an "
                "idempotent re-serve and not WIST2-E05.")
    h.declare("G", "owner", G)
    h.epoch("G")
    a, b = page(J + "a"), page(J + "b")
    h.cat("J1", [a, b], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"}, withhold=(J + "b",))
    h.epoch()
    j1 = h.catalogs["J1"]
    h.cat("J1b", [a, b], seconds(j1.inner["generated_at"]) + HOUR, "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1b"})
    h.epoch()
    h.cat("J1m", [a, b], seconds(j1.inner["generated_at"]) + HOUR - 1, "journal")
    h.cat("J1c", [a, b], seconds(j1.inner["generated_at"]) + HOUR + 1, "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1m"})
    h.pull(10 * MINUTE, "G", {"journal": "J1b"})
    h.pull(15 * MINUTE, "G", {"journal": "J1c"})
    h.epoch()
    h.pull(5 * MINUTE, "G", {"journal": "J1"})

    def c4(v):
        assert v.items(1, "journal")[J + "b"]["outcome"] == "not_admitted"
        assert v.sealed(2) == ["J1", J + "a"]
        assert v.items(3, "journal")[J + "b"]["payload"] == "fetched"
        assert v.items(3, "journal")[J + "a"]["payload"] == "record"
        assert v.left(4) == [("J1b", "C4", ["WIST3-E06"], False)]
        assert v.sealed(4) == [J + "b"] and v.expected[4]["sealed"][0]["catalog"] == j1.id
        assert v.last_accepted(4, "journal") == "J1b" and v.collection(4, "journal")["waiting"] is None
        assert v.outcome(5, "journal") == ("refused", ["WIST2-E05"])
        assert v.outcome(6, "journal")[0] == "idempotent"
        assert v.outcome(7, "journal")[0] == "accepted"
        assert v.left(8) == [("J1c", "C4", ["WIST3-E06"], False)] and v.sealed(8) == []
        assert v.last_accepted(8, "journal") == "J1c" and v.outcome(9, "journal") == ("idempotent", None)

    histories.append(run(h, c4))

    h = History("a Catalog that fails C1 at its turn after a Declaration removed its key",
                "J2 is accepted at pull 2, signed by the journal key. At pull 3 the Aggregator discovers D1, which "
                "replaces that key by journal2 and so reduces authority; J3, signed by journal2 with an instant "
                "between J1 and J2, is WIST2-E05 against J2, the last accepted Catalog. Height 2 seals D1: J2 fails "
                "C1 (WIST1-E02) at its turn, is reported and is no longer the last accepted Catalog, which falls back "
                "to J1; S2, signed by the store key D1 keeps, is sealed with t. At pull 4 the same J3 is read against "
                "J1 and accepted.")
    h.declare("G", "owner", G)
    d1 = h.declare("D1", "owner", successor(G, collections=[collection("journal", [prefix(J)], [key("journal2")]),
                                                           STORE]))
    h.epoch("G")
    a, b, c, s, t = page(J + "a"), page(J + "b"), page(J + "c"), page(S + "s"), page(S + "t")
    j1 = h.cat("J1", [a], h.at(4 * MINUTE), "journal")
    h.cat("S1", [s], h.at(4 * MINUTE), "store", "store")
    h.pull(5 * MINUTE, "G", {"journal": "J1", "store": "S1"})
    h.epoch()
    j2 = h.cat("J2", [a, b], h.at(9 * MINUTE), "journal")
    h.cat("S2", [s, t], h.at(9 * MINUTE), "store", "store")
    h.cat("J3", [a, c], h.at(7 * MINUTE), "journal2")
    h.pull(10 * MINUTE, "G", {"journal": "J2", "store": "S2"})
    h.pull(15 * MINUTE, "D1", {"journal": "J3", "store": "S2"})
    h.epoch("D1")
    h.pull(5 * MINUTE, "D1", {"journal": "J3", "store": "S2"})
    h.epoch()

    def c1(v):
        assert v.expected[4]["declaration"]["reduces_authority"] is True
        assert v.outcome(4, "journal") == ("refused", ["WIST2-E05"])
        assert v.left(5) == [("J2", "C1", ["WIST1-E02"], True)]
        assert v.sealed(5) == ["S2", S + "t"]
        assert v.last_accepted(5, "journal") == "J1"
        assert v.outcome(6, "journal")[0] == "accepted"
        assert v.sealed(7) == ["J3", J + "c"]

    histories.append(run(h, c1))

    h = History("the latest Catalog fails the binding check: Items wait with their places",
                "domain_epoch_entries_max is 2 until height 3 and 3 from height 4. J1 lists p1, p2 and p3 in list "
                "order; height 1 seals J1 and p1. D3, discovered at pull 2 and sealed at height 2, replaces the "
                "journal key: from height 2 the latest Catalog J1 fails I4, and p2 and p3 wait. S1 is accepted at "
                "pull 3 after height 3 and J2, J1's list signed by journal2 inside catalog_refresh_seconds, at pull 4; "
                "C4 does not hold J2 back since the latest Catalog fails the binding check. p2 and p3 kept their "
                "places from pull 1, so height 4 seals S1, J2 and p2 ahead of s, placed at pull 3.",
                domain_epoch_entries_max=2)
    h.declare("G", "owner", G)
    h.declare("D3", "owner", successor(G, collections=[collection("journal", [prefix(J)], [key("journal2")]), STORE]))
    h.epoch("G")
    ps = [page(u) for u in key_ordered([J + "p1", J + "p2", J + "p3"])]
    order = [p["url"] for p in items.in_list_order(ps)]
    j1 = h.cat("J1", ps, h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    h.pull(5 * MINUTE, "D3", {"journal": "J1"})
    h.epoch("D3")
    h.epoch()
    s = page(S + "s")
    h.cat("S1", [s], h.at(4 * MINUTE), "store", "store")
    h.add("J2", Cat(ps, h.at(9 * MINUTE), "journal2"))
    h.pull(5 * MINUTE, "D3", {"journal": "J1", "store": "S1"})
    h.pull(10 * MINUTE, "D3", {"journal": "J2", "store": "S1"})
    h.epoch(domain_epoch_entries_max=3)
    h.epoch(domain_epoch_entries_max=3)

    def binding(v):
        assert v.sealed(2) == ["J1", order[0]]
        assert v.deferred(4) == {order[1]: ["latest_fails_i4"], order[2]: ["latest_fails_i4"]}
        assert v.urls(7)[order[1]]["place"] == [1, 0, 1]
        assert v.sealed(8) == ["S1", "J2", order[1]]
        assert v.sealed(9) == [order[2], S + "s"]

    histories.append(run(h, binding))

    h = History("a URL whose Item changes while it waits, and a URL that stops waiting and waits again",
                "domain_epoch_entries_max is 2. J1 lists a and b, J2 a2 and c, J3 a2, b and c, accepted at pulls 1 "
                "to 3 before height 1. a waits without interruption from pull 1 and keeps place [1, 0, i]; b stops "
                "waiting at pull 2, when J2 no longer lists it, and waits again from pull 3 with a new place; c "
                "waits from pull 2. Height 1 seals J3 and a2, height 2 c and b in that order, and domain capacity 1 "
                "at height 2 would leave b for height 3.",
                domain_epoch_entries_max=2)
    h.declare("G", "owner", G)
    h.epoch("G")
    a, a2, b, c = page(J + "a"), page(J + "a", "a two"), page(J + "b"), page(J + "c")
    h.cat("J1", [a, b], h.at(4 * MINUTE), "journal")
    h.cat("J2", [a2, c], h.at(9 * MINUTE), "journal")
    h.cat("J3", [a2, b, c], h.at(14 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.pull(10 * MINUTE, "G", {"journal": "J2"})
    h.pull(15 * MINUTE, "G", {"journal": "J3"})
    h.epoch()
    h.epoch(domain_epoch_entries_max=1)
    h.epoch()

    def places(v):
        assert v.urls(1)[J + "b"]["place"][0] == 1
        assert J + "b" not in v.urls(2)
        assert v.urls(3)[J + "b"]["place"][0] == 3 and v.urls(3)[J + "a"]["place"][0] == 1
        assert v.urls(3)[J + "c"]["place"][0] == 2
        assert v.sealed(4) == ["J3", J + "a"] and v.sealed(5) == [J + "c"] and v.sealed(6) == [J + "b"]

    histories.append(run(h, places))

    u, v_ = reversed_pair(J + "k")
    h = History("capacity order: Catalogs, removed Items, then page Items, by place",
                "domain_epoch_entries_max is 10 at heights 0 and 1 and 3 from height 2. Height 1 seals J1 and S1 "
                "with every Item. At pull 2 the journal is read before the store: J2 changes u and v and removes b, "
                "and S2 changes y. At pull 3 S3 replaces S2, keeping its place, and removes x, whose removal waits "
                "from pull 3. Height 2 seals the two Catalogs and the removal of b; height 3 the removal of x, "
                "although placed later than every changed page, then u' and v' in list order, the order of their "
                "keys, which is the reverse of the order of their strings; height 4 y', whose eligibility Epoch "
                "moved from 2 to 4 and whose ceiling is counted from 4.")
    h.declare("G", "owner", G)
    h.epoch("G")
    pu, pv, pb, px, py = page(u), page(v_), page(J + "b"), page(S + "x"), page(S + "y")
    pu2, pv2, py2 = page(u, "u two"), page(v_, "v two"), page(S + "y", "y two")
    h.cat("J1", [pu, pv, pb], h.at(4 * MINUTE), "journal")
    h.cat("S1", [px, py], h.at(4 * MINUTE), "store", "store")
    h.pull(5 * MINUTE, "G", {"journal": "J1", "store": "S1"})
    h.epoch()
    h.cat("J2", [pu2, pv2, removed(J + "b")], h.at(4 * MINUTE), "journal")
    h.cat("S2", [px, py2], h.at(4 * MINUTE), "store", "store")
    h.cat("S3", [removed(S + "x"), py2], h.at(9 * MINUTE), "store", "store")
    h.pull(5 * MINUTE, "G", {"journal": "J2", "store": "S2"})
    h.pull(10 * MINUTE, "G", {"journal": "J2", "store": "S3"})
    h.epoch(domain_epoch_entries_max=3)
    h.epoch(domain_epoch_entries_max=3)
    h.epoch(domain_epoch_entries_max=3)

    def capacity(v):
        assert u < v_ and items.item_key(v_) < items.item_key(u)
        assert v.sealed(5) == ["J2", "S3", J + "b"]
        assert v.sealed(6) == [S + "x", v_, u]
        assert v.sealed(7) == [S + "y"]
        assert v.expected[7]["sealed"][0]["eligibility"] == 4 and v.expected[7]["sealed"][0]["ceiling"] == 8
        s2 = [i["url"] for i in h.catalogs["S2"].listed]
        s3 = [i["url"] for i in h.catalogs["S3"].listed]
        assert v.urls(4)[S + "y"]["place"] == [3, 1, s2.index(S + "y")]
        assert v.urls(4)[S + "x"]["place"] == [4, 1, s3.index(S + "x")]

    histories.append(run(h, capacity))

    h = History("a Declaration that reduces authority, discovered at a pull",
                "At pull 2 the Aggregator discovers D4, which narrows the journal's Scope to 2026/. No publication "
                "of example.com is sealed at height 1, which does not seal D4, while blog.example.com, another "
                "Publisher and its own capacity unit, is sealed there. Height 2 seals D4: J1 and the waiting Items "
                "are eligible for it and judged under D4, so a is sealed and b, outside the narrowed Scope, fails I5 "
                "(WIST1-E03) at its turn, is reported and leaves waiting.")
    h.declare("G", "owner", G)
    h.declare("B", "docs", B)
    h.declare("D4", "owner", successor(G, collections=[collection("journal", [prefix(J + "2026/")], [key("journal")]),
                                                       STORE]))
    h.epoch("G", "B")
    pa, pb, pz = page(J + "2026/a"), page(J + "2025/b"), page(BJ + "z", publisher=BLOG)
    h.cat("J1", [pa, pb], h.at(4 * MINUTE), "journal")
    h.cat("B1", [pz], h.at(9 * MINUTE), "docs", "journal", BLOG)
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.pull(10 * MINUTE, "D4", {"journal": "J1"})
    h.pull(15 * MINUTE, "B", {"journal": "B1"}, publisher=BLOG)
    h.epoch()
    h.epoch("D4")

    def reduction(v):
        assert v.expected[2]["declaration"]["reduces_authority"] is True
        assert v.expected[3]["state"]["reductions_pending"] == [{"publisher": "example.com", "declaration": "D4"}]
        assert v.sealed(4) == ["B1", BJ + "z"]
        assert v.deferred(4)["J1"] == ["authority_reduction"]
        assert v.sealed(5) == ["J1", J + "2026/a"]
        assert v.left(5) == [(J + "2025/b", "I5", ["WIST1-E03"], True)]

    histories.append(run(h, reduction))

    h = History("a fresh identity that becomes pending, discovered at a pull",
                "At pull 2 the Aggregator discovers F, a fresh identity signed by the fresh key that replaces the "
                "owner key: it reduces authority. Height 1 does not seal F and seals nothing of example.com. Height 2 "
                "seals F, which becomes pending (declaration_activation_epochs 24) and supplies no candidate: J1 and a "
                "are judged under G and sealed there.")
    h.declare("G", "owner", G)
    h.declare("F", "fresh", successor(G, keys=[key("fresh")]))
    h.epoch("G")
    pa = page(J + "a")
    h.cat("J1", [pa], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.pull(10 * MINUTE, "F", {"journal": "J1"})
    h.epoch()
    h.epoch("F")

    def fresh(v):
        assert v.expected[2]["declaration"]["outcome"] == "fresh_identity_pending"
        assert v.expected[2]["declaration"]["sources"] == ["G"]
        assert v.sealed(3) == [] and v.deferred(3)["J1"] == ["authority_reduction"]
        assert v.sealed(4) == ["J1", J + "a"]

    histories.append(run(h, fresh))

    for gap, is_base in ((2 * DAY + 1, True), (2 * DAY, False)):
        h = History(f"{'a base' if is_base else 'not a base'}: a Catalog {gap} seconds after the floor",
                    "removal_retention_days is 2. J1 lists a and b and is sealed with both. J2 lists a unchanged, "
                    "the removal of b and a new c, and is accepted " + (
                        "more than two days of 86 400 seconds after the floor, a base: from that pull I7 is read for "
                        "the journal against no record, so a waits although it is its record's Item, c waits and the "
                        "removal of b does not. The height that seals J2 removes the records and seals a and c."
                        if is_base else
                        "exactly two days after the floor, not a base: a is its record's Item and does not wait, "
                        "while the removal of b and c do."),
                    removal_retention_days=2)
        h.declare("G", "owner", G)
        h.epoch("G")
        pa, pb, pc = page(J + "a"), page(J + "b"), page(J + "c")
        j1 = h.cat("J1", [pa, pb], h.at(4 * MINUTE), "journal")
        h.pull(5 * MINUTE, "G", {"journal": "J1"})
        h.epoch()
        later = seconds(j1.inner["generated_at"]) + gap
        h.cat("J2", [pa, removed(J + "b", stamp(later - HOUR)), pc], later, "journal")
        h.last = later - 5 * MINUTE
        h.pull(6 * MINUTE, "G", {"journal": "J2"})
        h.epoch(sealed_at=later + 10 * MINUTE)

        def base_check(v, is_base=is_base):
            assert v.catalog(3, "journal")["base"] is is_base
            waiting_urls = set(v.urls(3))
            assert waiting_urls == ({J + "a", J + "c"} if is_base else {J + "b", J + "c"})

        histories.append(run(h, base_check))

    h = History("WIST2-E07: a list that drops the URL of a held record",
                "J1 lists keep/a, keep/b and drop/c, all sealed. J2 drops keep/b, whose record the journal's Scope "
                "covers: refused whole with WIST2-E07 at pull 2 and again at pull 3, the next pull. J3 lists the "
                "removal of keep/b instead and is accepted. At pull 5 the Aggregator reads D5, which narrows the "
                "journal to keep/: J4 drops drop/c, whose record is held but which D5's Scope no longer covers, and "
                "is accepted; height 3 seals D5, whose narrowing removes that record, and J4.")
    h.declare("G", "owner", G)
    h.declare("D5", "owner", successor(G, collections=[collection("journal", [prefix(J + "keep/")], [key("journal")]),
                                                       STORE]))
    h.epoch("G")
    ka, kb, dc = page(J + "keep/a"), page(J + "keep/b"), page(J + "drop/c")
    h.cat("J1", [ka, kb, dc], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    h.cat("J2", [ka, dc], h.at(4 * MINUTE), "journal")
    h.cat("J3", [ka, removed(J + "keep/b", stamp(h.at(9 * MINUTE))), dc], h.at(14 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J2"})
    h.pull(10 * MINUTE, "G", {"journal": "J2"})
    h.pull(15 * MINUTE, "G", {"journal": "J3"})
    h.epoch()
    h.cat("J4", [ka], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "D5", {"journal": "J4"})
    h.epoch("D5")

    def dropped(v):
        for event in (3, 4):
            found = v.catalog(event, "journal")
            assert found["outcome"] == "refused" and found["codes"] == ["WIST2-E07"]
            assert found["dropped"] == [J + "keep/b"]
        assert v.outcome(5, "journal")[0] == "accepted"
        assert v.sealed(6) == ["J3", J + "keep/b"]
        assert v.outcome(7, "journal")[0] == "accepted" and v.catalog(7, "journal")["base"] is False
        assert v.sealed(8) == ["J4"]
        assert v.expected[8]["records_removed"] == [
            {"publisher": "example.com", "url": J + "drop/c", "cause": "narrowing"}]

    histories.append(run(h, dropped))

    h = History("WIST2-E07 against a base",
                "removal_retention_days is 2. J1 lists a and b and is sealed. J2x drops b and is generated exactly "
                "two days after the floor: not a base, refused with WIST2-E07. J2y, the same list one second later, "
                "is a base against the floor and is accepted although it drops b's held record.",
                removal_retention_days=2)
    h.declare("G", "owner", G)
    h.epoch("G")
    pa, pb = page(J + "a"), page(J + "b")
    j1 = h.cat("J1", [pa, pb], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    floor = seconds(j1.inner["generated_at"])
    h.cat("J2x", [pa], floor + 2 * DAY, "journal")
    h.cat("J2y", [pa], floor + 2 * DAY + 1, "journal")
    h.last = floor + 2 * DAY + MINUTE
    h.pull(1 * MINUTE, "G", {"journal": "J2x"})
    h.pull(2 * MINUTE, "G", {"journal": "J2y"})
    h.epoch(sealed_at=h.at(10 * MINUTE))

    def base_drop(v):
        assert v.outcome(3, "journal") == ("refused", ["WIST2-E07"])
        found = v.catalog(4, "journal")
        assert found["outcome"] == "accepted" and found["base"] is True
        assert v.sealed(5) == ["J2y", J + "a"]
        assert v.expected[5]["records_removed"] == [
            {"publisher": "example.com", "url": J + "a", "cause": "base"},
            {"publisher": "example.com", "url": J + "b", "cause": "base"}]

    histories.append(run(h, base_drop))

    about = "https://example.com/about"
    h = History("a Declaration that widens a Scope is sealed with the Item it admits",
                "At pull 1 J1 lists a and https://example.com/about, which no Scope of G covers: about is refused "
                "(WIST1-E03) and a is admitted. At pull 2 the Aggregator reads W, which adds an exact entry for about "
                "to the journal and reduces no authority; the idempotent re-serve of J1 judges about again under W "
                "and admits it. W defers nothing and is sealed in the next Epoch, which seals J1, a and about, "
                "judged valid under W.")
    h.declare("G", "owner", G)
    h.declare("W", "owner", successor(G, collections=[
        collection("journal", [prefix(J), exact(about)], [key("journal")]), STORE]))
    h.epoch("G")
    h.cat("J1", [page(J + "a"), page(about)], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.pull(10 * MINUTE, "W", {"journal": "J1"})
    h.epoch("W")

    def widened(v):
        assert v.items(1, "journal")[about]["outcome"] == "refused"
        assert v.expected[2]["declaration"]["outcome"] == "ordinary_rotation"
        assert v.expected[2]["declaration"]["reduces_authority"] is False
        assert v.items(2, "journal")[about]["outcome"] == "admitted"
        assert set(v.sealed(3)) == {"J1", J + "a", about} and v.left(3) == []

    histories.append(run(h, widened))

    stores_first = {**G, "collections": [STORE, JOURNAL]}
    h = History("a URL that begins to wait at an Epoch takes its place in the Declaration's Collection order",
                "G3 lists store before journal. Pull 1 accepts S1 (sa, su) and J1 (ja, ju); "
                "domain_epoch_entries_max 2 lets height 1 seal only the two Catalogs. S2 and J2 drop su and ju, "
                "which stop waiting. D replaces both Collection keys and reduces authority; at height 2, which seals "
                "it, S2 and J2 fail C1 (WIST1-E02), and the last accepted Catalogs fall back to S1 and J1. su and ju "
                "begin to wait at that Epoch and take places after every earlier place, store's before journal's as "
                "D lists them, although journal precedes store in name order. S1 and J1 fail I4 under D, so the "
                "Items wait until S3 and J3, the same lists under the new keys, are accepted at pull 4; height 3, "
                "with domain_epoch_entries_max 5, seals S3, J3, sa, ja and su, and leaves ju for height 4.",
                domain_epoch_entries_max=2)
    h.declare("G3", "owner", stores_first)
    h.declare("D", "owner", successor(stores_first, collections=[
        collection("store", [prefix(S)], [key("store2")]), collection("journal", [prefix(J)], [key("journal2")])]))
    h.epoch("G3")
    sa, su, ja, ju = page(S + "a"), page(S + "u"), page(J + "a"), page(J + "u")
    h.cat("S1", [sa, su], h.at(4 * MINUTE), "store", "store")
    h.cat("J1", [ja, ju], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G3", {"store": "S1", "journal": "J1"})
    h.epoch()
    h.cat("S2", [sa], h.at(4 * MINUTE), "store", "store")
    h.cat("J2", [ja], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G3", {"store": "S2", "journal": "J2"})
    h.pull(10 * MINUTE, "D", {"store": "S2", "journal": "J2"})
    h.epoch("D")
    h.add("S3", Cat([sa, su], h.at(4 * MINUTE), "store2", "store"))
    h.add("J3", Cat([ja, ju], h.at(4 * MINUTE), "journal2"))
    h.pull(5 * MINUTE, "D", {"store": "S3", "journal": "J3"})
    h.epoch(domain_epoch_entries_max=5)
    h.epoch()

    def fallback(v):
        assert sorted(x[:2] for x in v.left(5)) == [("J2", "C1"), ("S2", "C1")]
        urls = v.urls(5)
        s_list = [i["url"] for i in h.catalogs["S1"].listed]
        j_list = [i["url"] for i in h.catalogs["J1"].listed]
        assert urls[S + "u"]["place"] == [5, 0, s_list.index(S + "u")]
        assert urls[J + "u"]["place"] == [5, 1, j_list.index(J + "u")]
        assert urls[S + "u"]["eligibility"] == 3
        assert v.deferred(5)[S + "a"] == ["latest_fails_i4"]
        assert v.sealed(7) == ["S3", "J3", S + "a", J + "a", S + "u"] and v.sealed(8) == [J + "u"]

    histories.append(run(h, fallback))

    return {"note": NOTE_COMMON + (
        " This file exercises ADR-0052 Sealing, Waiting (the last accepted Catalog, what waits, places, leaving, "
        "eligibility, its deferrals and the capacity order), Files (the retry of a refused Catalog and WIST2-E07 "
        "for a list that drops a held record's URL) and An Aggregator that was away (I7 read against no record from "
        "the pull that accepts a base), with ADR-0051 Reaching the Log (a Declaration that reduces authority, and "
        "one that widens a Scope sealed with the Item it admits) and Capacity. A prompt Aggregator seals what "
        "waits at its eligibility Epoch unless a deferral moves it, so a place kept by a replacement always "
        "carries the Epoch a new place would get: no history can show a kept eligibility Epoch, and places show "
        "what is kept."), "keys": KEYS_MEMBER, "histories": histories}


def recovery_vectors():
    histories = []
    docs = collection("docs", [prefix(DOCS)])
    removing = successor(G, keys=[key("owner2")], collections=[
        collection("journal", [prefix(J)], [key("journal2")]), STORE, docs])
    keeping = successor(G, keys=[key("owner2")])

    def opened(h, recovery, catalogs_before=None, withhold=()):
        h.declare("G", "owner", G)
        h.declare("R", "recovery", recovery)
        h.epoch("G")
        if catalogs_before:
            h.pull(5 * MINUTE, "G", catalogs_before, withhold=withhold)
            h.epoch()
        h.pull(5 * MINUTE, "R", {})
        h.epoch("R")
        return h.last

    h = History("the two frozen sources: a recovery rotation discovered, then sealed",
                "R, a recovery rotation, replaces the owner key by owner2 and the journal key by journal2 and adds "
                "docs. At pull 1 it is discovered and not yet sealed: the pull reads G and R, each alone, and pulls "
                "journal and store, then docs, which R alone names. J1, signed by the journal key, passes under G "
                "alone; S0, signed by the store key, under both. They wait as usual. Height 1 seals R and opens the "
                "window: J1 and S0 are queued with the places they had, a and s are held with theirs. Inside the "
                "window J2, signed by journal2, and D1, signed by owner2, pass under R alone and are queued. Height 2, "
                "at the window's end, settles: J1 fails C1 under R (WIST1-E13), J2, S0 and D1 survive.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", removing)
    h.epoch("G")
    pa, pb, ps, pd = page(J + "a"), page(J + "b"), page(S + "s"), page(DOCS + "d")
    h.cat("J1", [pa], h.at(4 * MINUTE), "journal")
    h.cat("S0", [ps], h.at(4 * MINUTE), "store", "store")
    h.pull(5 * MINUTE, "R", {"journal": "J1", "store": "S0"})
    h.epoch("R")
    start = h.last
    h.cat("J2", [pa, pb], h.at(4 * MINUTE), "journal2")
    h.cat("D1", [pd], h.at(4 * MINUTE), "owner2", "docs")
    h.pull(5 * MINUTE, "R", {"journal": "J2", "docs": "D1"})
    h.epoch(sealed_at=start + 7 * DAY)

    def frozen(v):
        d = v.expected[1]["declaration"]
        assert d["outcome"] == "recovery_rotation" and d["sources"] == ["G", "R"] and d["window"] is False
        assert v.expected[1]["collections_pulled"] == ["journal", "store", "docs"]
        assert v.catalog(1, "journal")["sources"] == ["G"] and v.catalog(1, "store")["sources"] == ["G", "R"]
        assert v.catalog(1, "journal")["queued"] is False and v.collection(1, "journal")["waiting"] is not None
        queue = [(q["collection"], q["key"], v.ids[q["catalog"]], q["place"]) for q in v.expected[2]["state"]["queue"]]
        assert queue == [("journal", "journal", "J1", [1, 0]), ("store", "store", "S0", [1, 1])]
        assert v.deferred(2)["J1"] == ["recovery_window"]
        assert v.expected[3]["declaration"]["window"] is True
        assert v.catalog(3, "journal")["sources"] == ["R"] and v.catalog(3, "docs")["sources"] == ["R"]
        settled = {v.ids[s["catalog"]]: s["outcome"] for s in v.expected[4]["settlement"]}
        assert settled == {"J1": "WIST1-E13", "S0": "survivor", "J2": "survivor", "D1": "survivor"}
        assert v.urls(3)[J + "a"]["place"] == v.urls(1)[J + "a"]["place"]
        assert set(v.sealed(4)) >= {"J2", "S0", "D1"}

    histories.append(run(h, frozen))

    h = History("the queue per Collection name and signing key",
                "R removes the journal key. Inside the window J2 is queued under the journal key and J3, signed by "
                "the same key at the clock allowance (the pull's instant plus clock_skew_seconds), replaces it. "
                "J4j, signed by the journal key with an instant before J3's, is WIST2-E05 against the queued J3; "
                "J4, the same inner object signed by journal2, is read against the floor and the queue of its own "
                "key alone and is queued, so the Catalog at the allowance holds back no Catalog of another key. At "
                "the settlement Epoch J3 fails C1 under R (WIST1-E13) and J4 is the last accepted Catalog.")
    pa, pb, pc, pe = page(J + "a"), page(J + "b"), page(J + "c"), page(J + "e")
    h.cat("J1", [pa], T0 + 4 * MINUTE, "journal")
    start = opened(h, removing, {"journal": "J1"})
    h.cat("J2", [pa, pb], h.at(4 * MINUTE), "journal")
    h.cat("J3", [pa, pb, pc], h.at(10 * MINUTE + 600), "journal")
    j4 = h.cat("J4j", [pa, pb, pe], h.at(14 * MINUTE), "journal")
    h.add("J4", j4.signed_by("journal2"))
    h.pull(5 * MINUTE, "R", {"journal": "J2"})
    h.pull(10 * MINUTE, "R", {"journal": "J3"})
    h.pull(15 * MINUTE, "R", {"journal": "J4j"})
    h.pull(18 * MINUTE, "R", {"journal": "J4"})
    h.epoch(sealed_at=start + 7 * DAY)

    def per_key(v):
        queue = lambda e: [(q["key"], v.ids[q["catalog"]]) for q in v.expected[e]["state"]["queue"]]
        assert queue(5) == [("journal", "J2")] and queue(6) == [("journal", "J3")]
        assert v.outcome(7, "journal") == ("refused", ["WIST2-E05"])
        assert queue(8) == [("journal", "J3"), ("journal2", "J4")]
        settled = {(v.ids[s["catalog"]], s["key"]): s["outcome"] for s in v.expected[9]["settlement"]}
        assert settled == {("J3", "journal"): "WIST1-E13", ("J4", "journal2"): "survivor"}
        assert v.sealed(9)[0] == "J4"

    histories.append(run(h, per_key))

    h = History("settlement: equal instants decided by Catalog ID",
                "Inside the window S1, signed by the store key, and S1b, signed by owner2 with S1's generated_at and "
                "another list, are queued under their keys. Both survive settlement; the one whose Catalog ID is the "
                "greater string in octet order is the last accepted Catalog and the other is not sealed and not "
                "reported.")
    start = opened(h, removing)
    h.cat("S1", [page(S + "s")], h.at(4 * MINUTE), "store", "store")
    h.add("S1b", Cat([page(S + "s", "s two")], h.at(4 * MINUTE), "owner2", "store"))
    h.pull(5 * MINUTE, "R", {"store": "S1"})
    h.pull(10 * MINUTE, "R", {"store": "S1b"})
    h.epoch(sealed_at=start + 7 * DAY)
    winner = max(("S1", "S1b"), key=lambda n: h.catalogs[n].id.encode())
    loser = "S1b" if winner == "S1" else "S1"

    def tie(v):
        settled = {v.ids[s["catalog"]]: s["outcome"] for s in v.expected[5]["settlement"]}
        assert settled == {winner: "survivor", loser: "not_latest"}
        assert v.sealed(5)[0] == winner and v.last_accepted(5, "store") == winner

    histories.append(run(h, tie))

    h = History("places after settlement: a Catalog queued at the opening keeps the place it had",
                "domain_epoch_entries_max is 2 from height 2. S0 is accepted at pull 1 and J2 at pull 2, which "
                "discovers R; both wait when height 1 seals R, and are queued with places [1, 1] and [2, 0]. Inside "
                "the window J3, signed by journal2, and D1 are queued. At settlement J2 fails, and J3, the surviving "
                "journal Catalog, takes J2's place as the first Catalog queued under its name. Height 2 seals S0 and "
                "J3 in the order of those places, S0's being the earlier, and D1 waits for height 3. a and b, which "
                "waited at the opening, keep their places; c and d take the places of the pull that queued J3 and "
                "D1.", domain_epoch_entries_max=10)
    h.declare("G", "owner", G)
    h.declare("R", "recovery", removing)
    h.epoch("G")
    pa, pb, pc, ps, pd = page(J + "a"), page(J + "b"), page(J + "c"), page(S + "s"), page(DOCS + "d")
    h.cat("S0", [ps], h.at(4 * MINUTE), "store", "store")
    h.cat("J2", [pa, pb], h.at(9 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"store": "S0"})
    h.pull(10 * MINUTE, "R", {"journal": "J2", "store": "S0"})
    h.epoch("R")
    start = h.last
    h.cat("J3", [pa, pb, pc], h.at(4 * MINUTE), "journal2")
    h.cat("D1", [pd], h.at(4 * MINUTE), "owner2", "docs")
    h.pull(5 * MINUTE, "R", {"journal": "J3", "docs": "D1"})
    for height in range(3):
        h.epoch(sealed_at=start + 7 * DAY if height == 0 else None, domain_epoch_entries_max=2)

    def places(v):
        queue = [(v.ids[q["catalog"]], q["place"]) for q in v.expected[3]["state"]["queue"]]
        assert queue == [("S0", [1, 1]), ("J2", [2, 0])]
        assert v.collection(5, "journal")["waiting"] is None and v.sealed(5) == ["S0", "J3"]
        assert v.expected[5]["sealed"][1]["eligibility"] == 2
        assert v.deferred(5)["D1"] == ["capacity"]
        urls = v.urls(5)
        assert urls[J + "a"]["place"] == v.urls(2)[J + "a"]["place"]
        assert urls[J + "c"]["place"][:2] == [4, 0] and urls[DOCS + "d"]["place"][:2] == [4, 2]

    histories.append(run(h, places))

    h = History("settlement under a follower: a shortened key window and a name with no survivor",
                "R keeps the journal key. At pull 1 u's Payload is unavailable, so height 1 seals J1 and a only. "
                "Inside the window J1, the latest Catalog, is served again: an idempotent re-serve that admits u, "
                "which the window holds without a place. J2 and S1 are queued. F, a follower signed by owner2 and "
                "sealed at height 3 inside the window, gives the journal key an exp equal to J2's generated_at. "
                "Height 4, at the window's end, settles under F, the last recovery-chain Declaration sealed before "
                "it: J2 fails (WIST1-E13), so the journal has no survivor and its last accepted Catalog is J1; u "
                "begins to wait at the settlement and takes its place there, after s, placed at the pull that queued "
                "S1; domain_epoch_entries_max 2 seals S1 and s at height 4 and u at height 5.")
    pa, pu, ps = page(J + "a"), page(J + "u"), page(S + "s")
    h.cat("J1", [pa, pu], T0 + 4 * MINUTE, "journal")
    opened(h, keeping, {"journal": "J1"}, withhold=(J + "u",))
    start = h.last
    j2 = h.cat("J2", [pa, pu, page(J + "v")], h.at(4 * MINUTE), "journal")
    h.cat("S1", [ps], h.at(4 * MINUTE), "store", "store")
    h.pull(5 * MINUTE, "R", {"journal": "J1"})
    h.pull(10 * MINUTE, "R", {"journal": "J2", "store": "S1"})
    f = h.declare("F", "owner2", successor(keeping, collections=[
        collection("journal", [prefix(J)], [key("journal", exp=seconds(j2.inner["generated_at"]))]), STORE]))
    h.pull(15 * MINUTE, "F", {"journal": "J2", "store": "S1"})
    h.epoch("F")
    h.epoch(sealed_at=start + 7 * DAY, domain_epoch_entries_max=2)
    h.epoch(domain_epoch_entries_max=2)

    def follower(v):
        assert v.items(1, "journal")[J + "u"]["outcome"] == "not_admitted"
        assert v.outcome(5, "journal")[0] == "idempotent" and v.items(5, "journal")[J + "u"]["outcome"] == "admitted"
        assert J + "u" not in v.urls(5)
        settled = {v.ids[s["catalog"]]: s for s in v.expected[9]["settlement"]}
        assert settled["J2"]["outcome"] == "WIST1-E13" and settled["J2"]["condition_code"] == "WIST1-E02"
        assert settled["S1"]["outcome"] == "survivor"
        assert v.last_accepted(9, "journal") == "J1"
        assert v.urls(9)[J + "u"]["place"][0] == 9 and v.urls(9)[J + "u"]["eligibility"] == 5
        assert v.sealed(9) == ["S1", S + "s"] and v.sealed(10) == [J + "u"]

    histories.append(run(h, follower))

    h = History("a survivor refused at the settlement Epoch by a Declaration of that Epoch",
                "S2 is queued inside the window. X, signed by owner2 and naming R, replaces the store key by store2; "
                "it is discovered inside the window and sealed at height 3, the Epoch of settlement. S2 survives "
                "settlement, which precedes every Declaration of the Epoch, is eligible for height 3, and there fails "
                "C1 (WIST1-E02) under X: it is reported and the last accepted Catalog falls back to S1.")
    h.cat("S1", [page(S + "s")], T0 + 4 * MINUTE, "store", "store")
    start = opened(h, keeping, {"store": "S1"})
    h.cat("S2", [page(S + "s"), page(S + "t")], h.at(4 * MINUTE), "store", "store")
    h.pull(5 * MINUTE, "R", {"store": "S2"})
    h.declare("X", "owner2", successor(keeping, collections=[JOURNAL, collection("store", [prefix(S)],
                                                                                 [key("store2")])]))
    h.pull(10 * MINUTE, "X", {"store": "S2"})
    h.epoch("X", sealed_at=start + 7 * DAY)

    def refused_at_turn(v):
        settled = {v.ids[s["catalog"]]: s["outcome"] for s in v.expected[7]["settlement"]}
        assert settled == {"S2": "survivor"}
        assert v.left(7) == [("S2", "C1", ["WIST1-E02"], True)] and v.sealed(7) == []
        assert v.last_accepted(7, "store") == "S1"

    histories.append(run(h, refused_at_turn))

    h = History("settlement at a pull between the window's end and the Epoch of settlement",
                "J2 and S1 are queued inside the window. Pull 7 comes after the window's end and before any Epoch "
                "at or after it: it settles the queue first, under R and with its own instant as the clock, and then "
                "reads as a pull outside a window, R alone. J2 is then an idempotent re-serve of the last accepted "
                "Catalog, and So, S1's list signed by the owner key that only G lists, is WIST1-E02, where inside "
                "the window G would have admitted it. Height 4 settles nothing again and seals J2, S1 and their "
                "Items, eligible for it.")
    h.cat("J1", [page(J + "a")], T0 + 4 * MINUTE, "journal")
    start = opened(h, keeping, {"journal": "J1"})
    h.cat("J2", [page(J + "a"), page(J + "b")], h.at(4 * MINUTE), "journal")
    s1 = h.cat("S1", [page(S + "s")], h.at(4 * MINUTE), "store", "store")
    h.pull(5 * MINUTE, "R", {"journal": "J2", "store": "S1"})
    h.epoch()
    h.last = start + 7 * DAY
    h.add("So", Cat([page(S + "s")], seconds(s1.inner["generated_at"]) + 1, "owner", "store"))
    h.pull(5 * MINUTE, "R", {"journal": "J2", "store": "So"})
    h.epoch(sealed_at=start + 7 * DAY + HOUR)

    def at_pull(v):
        pulled = v.expected[7]
        assert {v.ids[s["catalog"]]: s["outcome"] for s in pulled["settlement"]} == {"J2": "survivor",
                                                                                      "S1": "survivor"}
        assert pulled["declaration"]["window"] is False and pulled["declaration"]["sources"] == ["R"]
        assert v.outcome(7, "journal") == ("idempotent", None)
        assert v.outcome(7, "store") == ("refused", ["WIST1-E02"])
        assert v.expected[7]["state"]["queue"] == [] and v.collection(7, "store")["waiting"]["eligibility"] == 4
        assert v.expected[8]["settlement"] == []
        assert set(v.sealed(8)) == {"J2", "S1", J + "b", S + "s"}

    histories.append(run(h, at_pull))

    h = History("an idempotent re-serve inside the window retries its Items under the sources that accept it",
                "D replaces the journal key by journal2 and R, a recovery rotation naming D, keeps D's Collections, "
                "so neither frozen source lists the journal key. u's Payload is unavailable at pull 1 and height 1 "
                "seals J1 and a. Inside the window J1, the latest Catalog, is served again with u's Payload: an "
                "idempotent re-serve that no source accepts, so no Item is retried and u stays not admitted. J2, "
                "J1's list with v added and signed by journal2, is queued under both sources with v's Payload "
                "unavailable; served again at pull 9 with v's Payload, the re-serve is accepted by both sources and "
                "v is admitted. Height 4 settles and seals J2 with u and v.")
    h.declare("G", "owner", G)
    d = h.declare("D", "owner", successor(G, collections=[collection("journal", [prefix(J)], [key("journal2")]),
                                                         STORE]))
    h.declare("R", "recovery", successor(d, keys=[key("owner2")]))
    h.epoch("G")
    pa, pu, pv = page(J + "a"), page(J + "u"), page(J + "v")
    h.cat("J1", [pa, pu], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"}, withhold=(J + "u",))
    h.epoch()
    h.pull(5 * MINUTE, "D", {"journal": "J1"}, withhold=(J + "u",))
    h.epoch("D")
    h.pull(5 * MINUTE, "R", {"journal": "J1"}, withhold=(J + "u",))
    h.epoch("R")
    start = h.last
    h.cat("J2", [pa, pu, pv], h.at(9 * MINUTE), "journal2")
    h.pull(5 * MINUTE, "R", {"journal": "J1"})
    h.pull(10 * MINUTE, "R", {"journal": "J2"}, withhold=(J + "v",))
    h.pull(15 * MINUTE, "R", {"journal": "J2"})
    h.epoch(sealed_at=start + 7 * DAY)

    def reserve(v):
        assert v.expected[7]["declaration"]["window"] is True
        assert v.outcome(7, "journal") == ("idempotent", None) and v.catalog(7, "journal")["items"] == []
        got = v.items(8, "journal")
        assert got[J + "u"]["outcome"] == "admitted" and got[J + "v"]["outcome"] == "not_admitted"
        assert v.catalog(8, "journal")["sources"] == ["D", "R"]
        again = v.catalog(9, "journal")
        assert again["outcome"] == "idempotent" and [i["url"] for i in again["items"]] == [J + "v"]
        assert again["items"][0]["outcome"] == "admitted" and again["items"][0]["payload"] == "fetched"
        assert set(v.sealed(10)) == {"J2", J + "u", J + "v"}

    histories.append(run(h, reserve))

    return {"note": NOTE_COMMON + (
        " This file exercises ADR-0052 Recovery: the queue a pull fills inside an open recovery window from the two "
        "frozen sources of WIST-1 section 5.2 (the Declaration in effect before the recovery and the recovery "
        "Declaration that owns the window, each read alone; a recovery rotation discovered and not yet sealed "
        "reads them too, and what that pull accepts waits as usual until the window opens), one Catalog per "
        "Collection name and signing key with the pull order read against the floor and the queued Catalog of the "
        "same name and key, and settlement, once, at the first event at or after the window's end: a pull, which "
        "settles before it reads anything, with its own instant as the clock and the parameter map of the last "
        "sealed Epoch, and is then a pull outside a window; or the Epoch of settlement, before any of its "
        "Declarations applies, with its sealed_at and its map. Every queued Catalog is judged by C1 under the "
        "settlement source (the last recovery-chain Declaration sealed before that event); `settlement`, on the "
        "event that settles, lists every queued Catalog in the order of its place, then of its key, with "
        "`survivor`, `not_latest` for a survivor that is not the latest of its name in the order of Several Logs "
        "(generated_at, then the greater Catalog ID), or WIST1-E13 with `condition_code`, the Catalog condition "
        "met. What then waits is eligible for the next Epoch. `key` names the test key whose kid is that of the "
        "binding candidate under which the Catalog verified."),
        "keys": KEYS_MEMBER, "histories": histories}


def pull_vectors():
    histories = []
    ordered = successor(G, collections=[STORE, JOURNAL])
    h = History("a current Declaration: its Collections in the order it lists them",
                "G2 lists store before journal. The pull reads G2 alone and pulls store, then journal; with "
                "domain_epoch_entries_max 3 height 2 seals S1, J1 and s, the Item of the Collection read first, and "
                "leaves j for height 3. A failed fetch pulls no Collection; a fetched Declaration that fails its "
                "acceptance checks (Gbad repeats a Collection name, WIST1-E16) pulls none either.",
                domain_epoch_entries_max=3)
    h.declare("G", "owner", G)
    h.declare("G2", "owner", ordered)
    h.declare("Gbad", "owner", successor(ordered, collections=[STORE, collection("store", [prefix(J)])]))
    h.epoch("G")
    h.pull(5 * MINUTE, "G2", {})
    h.epoch("G2")
    pj, ps = page(J + "j"), page(S + "s")
    h.cat("J1", [pj], h.at(4 * MINUTE), "journal")
    h.cat("S1", [ps], h.at(4 * MINUTE), "store", "store")
    h.pull(5 * MINUTE, None, {"journal": "J1", "store": "S1"})
    h.pull(10 * MINUTE, "Gbad", {"journal": "J1", "store": "S1"})
    h.pull(15 * MINUTE, "G2", {"journal": "J1", "store": "S1"})
    h.epoch()
    h.epoch()

    def current(v):
        assert v.expected[1]["collections_pulled"] == ["store", "journal"]
        assert v.expected[3]["declaration"]["outcome"] == "not_fetched" and v.expected[3]["collections_pulled"] == []
        assert v.expected[4]["declaration"]["outcome"] == "WIST1-E16" and v.expected[4]["collections_pulled"] == []
        assert v.expected[5]["collections_pulled"] == ["store", "journal"]
        assert v.sealed(6) == ["S1", "J1", S + "s"] and v.sealed(7) == [J + "j"]

    histories.append(run(h, current))

    h = History("a pending head: the current Declaration alone",
                "P, a fresh identity signed by the fresh key, is discovered at pull 1, where the pull reads G alone: "
                "J1 signed by the fresh key is WIST1-E02 and S1, signed by the store key, is accepted. Height 1 seals "
                "P, which becomes the pending head. At pull 2 the fetched Declaration is the pending head: a success "
                "that changes no source. J1 signed by the fresh key is WIST1-E02 again; J1j, the same inner object "
                "signed by the journal key, is accepted at pull 3.")
    h.declare("G", "owner", G)
    h.declare("P", "fresh", successor(G, keys=[key("fresh")]))
    h.epoch("G")
    pj, ps = page(J + "j"), page(S + "s")
    j1 = h.cat("J1", [pj], h.at(4 * MINUTE), "fresh")
    h.add("J1j", j1.signed_by("journal"))
    h.cat("S1", [ps], h.at(4 * MINUTE), "store", "store")
    h.pull(5 * MINUTE, "P", {"journal": "J1", "store": "S1"})
    h.epoch("P")
    h.pull(5 * MINUTE, "P", {"journal": "J1", "store": "S1"})
    h.pull(10 * MINUTE, "P", {"journal": "J1j", "store": "S1"})
    h.epoch()

    def pending(v):
        assert v.expected[1]["declaration"]["outcome"] == "fresh_identity_pending"
        assert v.expected[1]["declaration"]["sources"] == ["G"]
        assert v.outcome(1, "journal") == ("refused", ["WIST1-E02"])
        assert v.sealed(2) == ["S1", S + "s"]
        assert v.expected[3]["declaration"]["outcome"] == "idempotent"
        assert v.expected[3]["declaration"]["sources"] == ["G"]
        assert v.outcome(3, "journal") == ("refused", ["WIST1-E02"])
        assert v.outcome(4, "journal")[0] == "accepted"
        assert v.sealed(5) == ["J1j", J + "j"]

    histories.append(run(h, pending))

    docs = collection("docs", [prefix(DOCS)])
    h = History("an open recovery window: two sources, each read alone",
                "R, sealed at height 1, names journal and docs and replaces the owner key by owner2; G names journal "
                "and store. Inside the window the pull reads G and R and pulls journal and store, then docs, which R "
                "alone names; journal, which both name, is pulled once. Da, a docs Catalog signed by the owner key, "
                "is refused: G lists the key but names no docs (WIST1-E03), and R names docs but does not list the "
                "key (WIST1-E02). Db, the same inner object signed by owner2, is queued.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", successor(G, keys=[key("owner2")], collections=[JOURNAL, docs]))
    h.epoch("G")
    h.pull(5 * MINUTE, "R", {})
    h.epoch("R")
    pd = page(DOCS + "d")
    da = h.cat("Da", [pd], h.at(4 * MINUTE), "owner", "docs")
    h.add("Db", da.signed_by("owner2"))
    h.pull(5 * MINUTE, "R", {"docs": "Da"})
    h.pull(10 * MINUTE, "R", {"docs": "Db"})

    def sources(v):
        assert v.expected[3]["collections_pulled"] == ["journal", "store", "docs"]
        assert v.expected[3]["declaration"]["sources"] == ["G", "R"]
        assert v.outcome(3, "docs") == ("refused", ["WIST1-E02", "WIST1-E03"])
        assert v.catalog(4, "docs")["queued"] is True and v.catalog(4, "docs")["sources"] == ["R"]

    histories.append(run(h, sources))

    h = History("Payloads at a pull, and the retry of Items refused or not admitted",
                "domain_epoch_entries_max is 2. J1 lists a and b, whose Payloads pull 1 fetches. J2 replaces J1 at "
                "pull 2 and adds c, d, e and f: a's and b's Payloads are held; c's is fetched and verifies; d's is "
                "unavailable and e's fails the commitment check, both WIST2-E03; f, https://example.com/about, lies "
                "outside every Scope and is refused (WIST1-E03); the others proceed. At pull 3 J2 is served again, "
                "an idempotent re-serve: no tree file is fetched, the Items not admitted are judged again, d's "
                "Payload now verifies and d waits from pull 3, while the waiting Items keep their places. At pull 4 "
                "the Aggregator reads D6, which adds an exact entry for f to the journal's Scope, and the re-serve "
                "admits f. At pull 5 J3, a later Catalog of the same list, is accepted and e, whose Payload now "
                "verifies, is admitted; a, sealed as a record, is admitted as its record's Item. Height 2 seals "
                "D6; J3, of J2's root inside catalog_refresh_seconds, fails C4 there and stays the last accepted "
                "Catalog, and the waiting Items are sealed against J2, f under D6's Scope at height 3.",
                domain_epoch_entries_max=2)
    h.declare("G", "owner", G)
    about = "https://example.com/about"
    h.declare("D6", "owner", successor(G, collections=[
        collection("journal", [prefix(J), exact(about)], [key("journal")]), STORE]))
    h.epoch("G")
    pa, pb, pc, pd, pe, pf = (page(J + "a"), page(J + "b"), page(J + "c"), page(J + "d"), page(J + "e"),
                              page(about))
    h.cat("J1", [pa, pb], h.at(4 * MINUTE), "journal")
    h.cat("J2", [pa, pb, pc, pd, pe, pf], h.at(9 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.pull(10 * MINUTE, "G", {"journal": "J2"}, withhold=(J + "d",), tamper=(J + "e",))
    h.epoch()
    h.pull(5 * MINUTE, "G", {"journal": "J2"}, tamper=(J + "e",))
    h.pull(10 * MINUTE, "D6", {"journal": "J2"}, tamper=(J + "e",))
    h.cat("J3", [pa, pb, pc, pd, pe, pf], h.at(14 * MINUTE), "journal")
    h.pull(15 * MINUTE, "D6", {"journal": "J3"})
    h.epoch("D6")
    h.epoch()
    h.epoch()

    def payloads(v):
        got = v.items(2, "journal")
        assert got[J + "a"]["payload"] == "held" and got[J + "b"]["payload"] == "held"
        assert got[J + "c"]["payload"] == "fetched"
        assert got[J + "d"]["outcome"] == "not_admitted" and got[J + "d"]["payload"] == "unavailable"
        assert got[J + "e"]["payload"] == "failed" and got[J + "e"]["codes"] == ["WIST2-E03"]
        assert got[about]["outcome"] == "refused" and got[about]["codes"] == ["WIST1-E03"]
        retry = v.catalog(4, "journal")
        assert retry["outcome"] == "idempotent" and retry["tree_files_fetched"] == []
        assert set(v.items(4, "journal")) == {J + "d", J + "e", about}
        assert v.items(4, "journal")[J + "d"]["outcome"] == "admitted"
        assert v.urls(4)[J + "d"]["place"][0] == 4
        assert all(v.urls(4)[u]["place"] == v.urls(3)[u]["place"] for u in v.urls(3))
        assert v.items(5, "journal")[about]["outcome"] == "admitted"
        assert v.items(6, "journal")[J + "e"]["payload"] == "fetched"
        assert v.left(7) == [("J3", "C4", ["WIST3-E06"], False)]
        assert v.left(8) == [] and v.left(9) == [] and v.expected[-1]["state"]["urls"] == []

    histories.append(run(h, payloads))

    h = History("a walk that an unavailable tree file interrupts resumes from the files held",
                "J1's list of six Items is split into buckets of two. At pull 1 one bucket file is unavailable: J1 is "
                "refused whole with WIST2-E07, nothing of it waits, and the tree files fetched are kept under their "
                "hashes. At pull 2 J1 is fetched again, every file is served, and the walk fetches only the files it "
                "does not hold: the one that was unavailable and those the interrupted walk had not reached.")
    h.declare("G", "owner", G)
    h.epoch("G")
    six = [page(J + f"w{i}") for i in range(6)]
    walked = h.cat("J1", six, h.at(4 * MINUTE), "journal", capacity=2)
    buckets = sorted(d for d, octets in walked.files.items() if octets.startswith(b'{"items"'))
    h.pull(5 * MINUTE, "G", {"journal": "J1"}, omit=(buckets[0],))
    h.pull(10 * MINUTE, "G", {"journal": "J1"})
    h.epoch()

    def resumed(v):
        first = v.catalog(1, "journal")
        assert first["outcome"] == "refused" and first["codes"] == ["WIST2-E07"]
        assert buckets[0] in first["tree_files_fetched"] and v.expected[1]["state"]["urls"] == []
        second = v.catalog(2, "journal")
        held = set(first["tree_files_fetched"]) - {buckets[0]}
        assert held and second["outcome"] == "accepted"
        assert second["tree_files_fetched"] == sorted(set(walked.files) - held)
        assert v.sealed(3)[0] == "J1" and len(v.sealed(3)) == 7

    histories.append(run(h, resumed))

    return {"note": NOTE_COMMON + (
        " This file exercises ADR-0051 Reaching the Log (the sources a pull reads, for each row of its table, and "
        "the Collections pulled in order; admission inside an open recovery window, each source read alone) and "
        "ADR-0052 Files (the admission of Items and their Payloads, WIST2-E03, and the retry of Items refused or "
        "not admitted at a pull that accepts a Catalog and at an idempotent re-serve)."),
        "keys": KEYS_MEMBER, "histories": histories}


NOTE_COMMON = (
    "An Aggregator that seals every Entry in the Epoch it is eligible for, fed `events` in time order. Each history "
    "names its signed Declarations (`declarations`), its signed Catalog Envelopes (`catalogs`, with `catalog_ids`; "
    "two names share an ID where one inner object is signed twice) and the octets of every tree file served, as "
    "UTF-8 text keyed by the 64 hexadecimal digits of their SHA-256 (`tree_files`). An `epoch` event gives height, "
    "sealed_at, the complete parameter map in force at it and the Declarations it seals by name; Epochs are "
    "simplified to those and their Entries, with no Checkpoint and no Merkle tree of the Log, and the Aggregator "
    "seals exactly those Declarations and plans the Catalog and Item Entries. Every Declaration discovered at a "
    "pull that does not reduce authority is sealed in the next Epoch, which ADR-0051 requires of a prompt "
    "Aggregator; one that reduces authority may be sealed later within record_seal_epochs, and the fixture uses "
    "that to show its deferral. A `pull` event gives its instant, "
    "which is the clock of the pull, the Publisher pulled, the Declaration served (null for a failed fetch) and, per "
    "Collection name, the Catalog served at catalog.json, the tree files served (by name, from `tree_files`) and "
    "the Payloads served, keyed by the digits of their Item ID. A Collection absent from `collections` has no "
    "catalog.json and a file absent from a pull is unavailable; there is no HTTP, and these maps stand for the "
    "Publisher's site. At a pull the Catalog, Item and Payload conditions read the parameter map of the last sealed "
    "Epoch; the parameters a pull reads and max_inclusion_epochs are constant within each history, so the fixture "
    "does not fix which map a pull or the ceiling reads. Every Canonical Host is its own capacity unit, since no Public Suffix List snapshot is in force, and no "
    "history carries Labels, disputes or registry updates. `expected` has one element per event. For a pull, "
    "`settlement` is empty unless the pull settles a queue (catalog-recovery.json), and `declaration` gives `outcome` (the served Declaration applied under WIST-1 section 5.2 after the Log's "
    "Declarations and those the Aggregator discovered and has not sealed: `initial`, `ordinary_rotation`, "
    "`recovery_rotation`, `fresh_identity_pending`, `in_window_chain`, `idempotent`, a rejection code, or "
    "`not_fetched`), `discovered`, `reduces_authority` against the Declaration it names (false unless discovered), "
    "`sources` (the Declarations the pull reads, as ADR-0051's table gives them: the two frozen sources inside an "
    "open window or for a recovery rotation discovered and not yet sealed, and otherwise the current Declaration) "
    "and `window`, whether the pull is inside an open window and queues what it accepts. `collections_pulled` lists the Collections in reading order. Per Collection pulled: "
    "`outcome` (`unavailable`, `accepted`, `idempotent` for an idempotent re-serve, a Catalog with the Catalog ID "
    "of the last accepted Catalog or of the latest Catalog, or of the queued Catalog of its name and key inside a "
    "window, or `refused` with `codes`, "
    "those of every condition met, among which WIST-1 section 7 leaves the choice, and for WIST2-E07 a `reason` "
    "and, for a list that drops a held record's URL, `dropped`), `catalog` (its Catalog ID), `sources` under which "
    "it passed the Catalog conditions, `tree_files_fetched` (the files the walk requested because the Aggregator "
    "did not hold them, served or not, in ascending order; a file whose SHA-256 matches its name is then held), "
    "`base` (a base against the floor under the pull's map), `key` (the test key named by the kid of the binding "
    "candidate under which it verified), `queued` (inside a window) and `items`, each Item judged at the pull in list order: all Items of an "
    "accepted list, and at an idempotent re-serve those not admitted before; `outcome` is `admitted`, "
    "`not_admitted` (WIST2-E03) or `refused` (the Item condition codes under every source that accepts the "
    "Catalog), and `payload` "
    "says how an Item of kind page was admitted or failed: `record`, `held`, `fetched`, `unavailable`, or `failed` "
    "with `payload_code`. For an Epoch: `settlement`, `entries` in canonical order (WIST-3 section 3.3), `sealed` "
    "in capacity order with each Entry's eligibility Epoch and the last Epoch its ceiling allows, `left` (what "
    "left waiting at its turn, with the condition failed, its codes and whether it is reported at the status "
    "endpoint), `deferred` (every waiting Catalog and URL whose eligibility Epoch had come and that was not sealed, "
    "with the deferrals that applied: `recovery_window`, `authority_reduction`, `catalog_waiting`, "
    "`latest_fails_i4`, and `capacity` only where no other applied) and `records_removed`. After every event "
    "`state` gives per Publisher and Collection name the latest Catalog, the last accepted Catalog and the waiting "
    "Catalog with its place, eligibility Epoch and ceiling; every waiting URL with its Collection, Item, place, "
    "eligibility Epoch and ceiling (null while a window holds it); the queue; the Declarations that reduce "
    "authority, discovered and not sealed; and the records. A place is [event index, position of the Collection in "
    "the pull's reading order] for a Catalog, with the Item's index in the list appended for a URL; places compare "
    "as arrays. A URL that begins to wait at an Epoch or at a settlement takes that event's index, the position of "
    "its Collection among the Collections of the Declaration in force (a name that Declaration lacks after them, in "
    "ascending order) and its list index. What takes a place is eligible for the Epoch after that event, a "
    "replacement that keeps a place keeps its eligibility Epoch, and each Epoch at which it waits unsealed moves "
    "it to the following one; the ceiling is the eligibility Epoch plus max_inclusion_epochs of the last "
    "sealed Epoch's map. The planned Entries replay as valid under the rules of vectors/wist3/catalog-sealing.json. "
    "The fixture asserts nothing about an Aggregator that seals later within the ceiling, nor about Consumers, "
    "which cannot derive these rules from the Log. Keys derive from the stated test-only seeds.")


write_json(WIST3 / "catalog-waiting.json", waiting_vectors())
write_json(WIST1 / "catalog-recovery.json", recovery_vectors())
write_json(WIST2 / "collection-pull.json", pull_vectors())
print("waiting vectors written")
