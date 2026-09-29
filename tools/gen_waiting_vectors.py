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
             "store", "store2", "docs", "log")
USED_KEYS = ("owner", "owner2", "recovery", "fresh", "journal", "journal2", "store", "store2", "docs", "log")
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
    "payload_window_days": 180, "domain_epoch_entries_max": 10000, "max_inclusion_epochs": 4,
    "record_seal_epochs": 24, "url_cap_bytes": 2048, "extract_cap_bytes": 32768, "links_cap_bytes": 4096,
    "link_url_cap_bytes": 2048, "summary_cap_bytes": 2048, "tree_file_cap_bytes": 65536, "tree_depth_max": 16,
    "collections_max": 16, "scope_entries_max": 32, "recovery_window_days": 7, "declaration_activation_epochs": 24}
PAYLOADS = {}
PUBLICATIONS = {}


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


def page(url, label=None, observed_at=OBSERVED, publisher="example.com", extract=None):
    label = label or url
    publication = {"url": url, "lang": "en", "modified": observed_at,
                   "content": {"extract": extract if extract is not None else f"Text of {label}.",
                               "links": {"total": 0, "urls": []}, "summary": {"title": f"Title {label}"}}}
    item, payload = items.new_page_item(publisher, publication, salt_for(label))
    PAYLOADS[items.item_id(item)] = payload
    PUBLICATIONS[items.item_id(item)] = publication
    return item


def derived(served, kept, declaration, name, generated_at):
    out = items.derive_list(served, PAYLOADS, [PUBLICATIONS[items.item_id(i)] for i in kept], declaration, name,
                            stamp(generated_at), {}, "1.0.0")
    return out["list"]


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
    def __init__(self, name, why, suffix_list=None, **parameters):
        self.name, self.why = name, why
        self.suffix_list = suffix_list
        self.parameters = {**DEFAULT_MAP, **parameters}
        self.events, self.declarations, self.catalogs, self.tree_files, self.updates = [], {}, {}, {}, {}
        self.height = -1
        self.last = T0 - HOUR
        self.clock = None
        self.map = None

    def declare(self, name, signer, inner):
        self.declarations[name] = sign(signer, "publisher", inner)
        return inner

    def withdraw(self, name, withdrawn):
        update = {"wist_version": "1.0.0", "action": "payload_withdrawal", "subject": withdrawn["publisher"],
                  "effective_at": stamp(self.last + HOUR),
                  "details": {"delta_id": items.item_id(withdrawn), "legal_basis": "court order 12/2026",
                              "jurisdiction": "BR"}}
        self.updates[name] = sign("log", "update", update)

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

    def epoch(self, *declarations, sealed_at=None, updates=(), late=(), **parameters):
        self.height += 1
        self.last = sealed_at if sealed_at is not None else self.last + HOUR
        self.map = {**self.parameters, **parameters}
        event = {"event": "epoch", "height": self.height, "sealed_at": stamp(self.last), "parameters": self.map,
                 "declarations": list(declarations)}
        if updates:
            event["updates"] = list(updates)
        if late:
            event["sealed_later"] = list(late)
        self.events.append(event)

    def pull(self, offset, declaration, collections, publisher="example.com", withhold=(), tamper=(),
             omit=(), parameters=None):
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
                            "parameters": {**self.map, **(parameters or {})}, "declaration": declaration,
                            "collections": served})


def run(history, check=None):
    aggregator = waiting.Aggregator(history.suffix_list)
    names = {rules.declaration_hash(e["publisher"]): n for n, e in history.declarations.items()}
    ids = {c.id: n for n, c in history.catalogs.items()}
    expected, epochs, previous = [], [], None
    for event in history.events:
        instant = seconds(event["at"] if event["event"] == "pull" else event["sealed_at"])
        assert previous is None or instant > previous, (history.name, event)
        previous = instant
        if event["event"] == "epoch":
            out = aggregator.epoch(event["height"], event["sealed_at"], event["parameters"],
                                   [history.declarations[n] for n in event["declarations"]],
                                   [history.updates[n] for n in event.get("updates", [])],
                                   {rules.declaration_hash(history.declarations[n]["publisher"])
                                    for n in event.get("sealed_later", [])})
            for member in ("declarations_failed", "declarations_left"):
                for entry in out.get(member, []):
                    entry["declaration"] = names[entry["declaration"]]
                    if "names" in entry:
                        entry["names"] = names[entry["names"]]
            epochs.append({"height": event["height"], "sealed_at": event["sealed_at"],
                           "parameters": event["parameters"], "entries": out["entries"]})
        else:
            served = {}
            for name, s in event["collections"].items():
                served[name] = {"catalog": history.catalogs[s["catalog"]].envelope,
                                "tree_files": {d: history.tree_files[d].encode() for d in s["tree_files"]},
                                "payloads": s["payloads"]}
            envelope = history.declarations[event["declaration"]] if event["declaration"] else None
            out = aggregator.pull(event["publisher"], event["at"], envelope, served, event["parameters"])
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
    out = {"name": history.name, "why": history.why}
    if history.suffix_list is not None:
        out["suffix_list"] = history.suffix_list
    if history.updates:
        out["registry_updates"] = history.updates
    return {**out, "declarations": history.declarations,
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

    def held(self, event):
        return {self.label(r): r["reasons"] for r in self.expected[event].get("held", [])}

    def eligibility(self, event):
        return {self.label(r): (r["eligibility"], r["ceiling"]) for r in self.expected[event]["sealed"]}

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
                "Publisher and its own capacity unit, is sealed there. The hold orders the sealing and defers "
                "nothing: J1 and the waiting Items keep eligibility Epoch 1 and the ceiling 5 it gives. Height 2 "
                "seals D4 and then J1 and a, judged under D4, while b, outside the narrowed Scope, fails I5 "
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
        assert v.held(4)["J1"] == ["authority_reduction"] and "J1" not in v.deferred(4)
        assert v.collection(4, "journal")["waiting"]["eligibility"] == 1
        assert v.sealed(5) == ["J1", J + "2026/a"]
        assert v.eligibility(5) == {"J1": (1, 5), J + "2026/a": (1, 5)}
        assert v.left(5) == [(J + "2025/b", "I5", ["WIST1-E03"], True)]

    histories.append(run(h, reduction))

    h = History("a fresh identity that becomes pending, discovered at a pull",
                "At pull 2 the Aggregator discovers F, a fresh identity signed by the fresh key that replaces the "
                "owner key: it reduces authority. Height 1 does not seal F and seals nothing of example.com, which "
                "moves no eligibility Epoch. Height 2 seals F, which becomes pending (declaration_activation_epochs "
                "24) and supplies no candidate: J1 and a are judged under G and sealed there, with eligibility "
                "Epoch 1.")
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
        assert v.sealed(3) == [] and v.held(3)["J1"] == ["authority_reduction"] and v.deferred(3) == {}
        assert v.sealed(4) == ["J1", J + "a"] and v.eligibility(4)["J1"] == (1, 5)

    histories.append(run(h, fresh))

    retention = items.REMOVAL_RETENTION_DAYS * DAY
    for gap, is_base in ((retention + 1, True), (retention, False)):
        h = History(f"{'a base' if is_base else 'not a base'}: a Catalog {gap} seconds after the floor",
                    "removal_retention_days is the constant 180. J1 lists a and b and is sealed with both. J2 lists a "
                    "unchanged, the removal of b and a new c, and is accepted " + (
                        "more than 180 days of 86 400 seconds after the floor, a base: from that pull I7 is read for "
                        "the journal against no record, so a waits although it is its record's Item, c waits and the "
                        "removal of b does not. The height that seals J2 removes the records and seals a and c."
                        if is_base else
                        "exactly 180 days after the floor, not a base: a is its record's Item and does not wait, "
                        "while the removal of b and c do."))
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
                "J1 lists a and b and is sealed. J2x drops b and is generated exactly removal_retention_days, 180 "
                "days, after the floor: not a base, refused with WIST2-E07. J2y, the same list one second later, "
                "is a base against the floor and is accepted although it drops b's held record.")
    h.declare("G", "owner", G)
    h.epoch("G")
    pa, pb = page(J + "a"), page(J + "b")
    j1 = h.cat("J1", [pa, pb], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    floor = seconds(j1.inner["generated_at"])
    h.cat("J2x", [pa], floor + retention, "journal")
    h.cat("J2y", [pa], floor + retention + 1, "journal")
    h.last = floor + retention + MINUTE
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

    overlap = successor(G, collections=[JOURNAL, collection("store", [prefix(S)], [key("store", exp=T0 + 400 * DAY)])])
    h = History("the hold keeps eligibility Epochs and ceilings, and a Catalog of another root defers nothing",
                "At pull 2 the Aggregator discovers D, which gives the store key an exp and so reduces authority; it "
                "seals D at height 5, the last Epoch the ceiling of the earliest waiting publication allows. J1 and u "
                "wait from pull 1 with eligibility Epoch 1 and ceiling 5. Heights 1 to 4 seal nothing of example.com "
                "and move no eligibility Epoch. At pull 4 J2, of another root, replaces the waiting J1 and keeps its "
                "place and eligibility Epoch; u, which had reached its eligibility Epoch, keeps it and its ceiling, "
                "and w, new in J2, is eligible for height 2. Height 5 seals D, then J2, u and w, each with the "
                "eligibility Epoch it took.")
    h.declare("G", "owner", G)
    h.declare("D", "owner", overlap)
    h.epoch("G")
    pu, pw = page(J + "u"), page(J + "w")
    h.cat("J1", [pu], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.pull(10 * MINUTE, "D", {"journal": "J1"})
    h.epoch()
    h.cat("J2", [pu, pw], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "D", {"journal": "J2"})
    for _ in range(3):
        h.epoch()
    h.epoch("D")

    def kept(v):
        assert v.expected[2]["declaration"]["reduces_authority"] is True
        for event in (3, 5, 6, 7):
            assert v.sealed(event) == [] and v.deferred(event) == {}
            assert v.urls(event)[J + "u"]["eligibility"] == 1 and v.urls(event)[J + "u"]["ceiling"] == 5
        assert v.held(3) == {"J1": ["authority_reduction"], J + "u": ["authority_reduction"]}
        assert v.collection(4, "journal")["waiting"]["eligibility"] == 1
        assert v.urls(4)[J + "w"]["eligibility"] == 2
        assert v.sealed(8) == ["J2"] + [i["url"] for i in items.in_list_order([pu, pw])]
        assert v.eligibility(8) == {"J2": (1, 5), J + "u": (1, 5), J + "w": (2, 6)}

    histories.append(run(h, kept))

    fresh_head = successor(G, keys=[key("fresh")])
    replacement = successor(fresh_head, collections=[JOURNAL])
    reversal = successor(G, seq=3)
    h = History("a pending replacement that reduces authority, discarded by a reversal before it is sealed",
                "P, a fresh identity, is sealed at height 1 and is the pending head. At pull 2 the Aggregator "
                "discovers P2, a replacement of P that drops the store and so reduces authority, and accepts J2; "
                "height 2 does not seal P2 and seals nothing of example.com. At pull 3 it discovers V, an ordinary "
                "rotation naming G signed by the owner key: a reversal, which discards the pending head and P2. A "
                "discarded replacement is still sealed, at or below the reversal's Epoch, and its hold ends at the "
                "Epoch that seals it: height 3 seals P2, then V, then J2 and a2, whose eligibility Epoch 2 the hold "
                "did not move.")
    h.declare("G", "owner", G)
    h.declare("P", "fresh", fresh_head)
    h.declare("P2", "fresh", replacement)
    h.declare("V", "owner", reversal)
    h.epoch("G")
    pa, pa2 = page(J + "a"), page(J + "a", "a two")
    h.cat("J1", [pa], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "P", {"journal": "J1"})
    h.epoch("P")
    h.cat("J2", [pa2], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "P2", {"journal": "J2"})
    h.epoch()
    h.pull(5 * MINUTE, "V", {"journal": "J2"})
    h.epoch("P2", "V")

    def discarded(v):
        assert v.expected[3]["declaration"]["outcome"] == "pending_replacement"
        assert v.expected[3]["declaration"]["reduces_authority"] is True
        assert v.held(4) == {"J2": ["authority_reduction"], J + "a": ["authority_reduction"]}
        assert v.expected[5]["declaration"]["outcome"] == "reversal_ordinary_rotation"
        assert v.expected[5]["state"]["reductions_pending"] == [{"publisher": "example.com", "declaration": "P2"}]
        assert [e["body"]["publisher"]["seq"] for e in v.expected[6]["entries"]
                if e["type"] == "publisher_declaration"] == [2, 3]
        assert v.sealed(6) == ["J2", J + "a"] and v.eligibility(6)["J2"] == (2, 6)
        assert v.expected[6]["state"]["reductions_pending"] == []

    histories.append(run(h, discarded))

    hosts = ("a.example.com", "b.example.com")

    def host_declaration(host, stores_first, moved):
        journal = collection("journal", [exact(f"https://{host}/journal/k")] if moved else
                             [prefix(f"https://{host}/journal/")], [key("journal")])
        store = collection("store", [prefix(f"https://{host}/store/")] + (
            [exact(f"https://{host}/journal/u")] if moved else []), [key("store")])
        inner = {"wist_version": "1.0.0", "seq": 0, "domain": host, "keys": [key("owner")],
                 "collections": [store, journal] if stores_first else [journal, store]}
        return inner

    h = History("places taken at one Epoch by two Publishers of one Registrable Domain",
                "The snapshot in force is the one rule com, so a.example.com and b.example.com share the Registrable "
                "Domain example.com and its capacity. a lists journal before store and b store before journal. Each "
                "has u under journal; its D moves u to the store by an exact entry, and the store Catalog lists the "
                "same Item of u that is the record. At height 2, which seals both D, narrowing removes both records "
                "of u and both begin to wait at that Epoch. Places taken at one Epoch are ordered by Canonical Host "
                "first: with domain_epoch_entries_max 1, height 3 seals a's u, although a's store is its second "
                "Collection and b's its first, and height 4 seals b's.",
                suffix_list=["com"])
    for host, stores_first in zip(hosts, (False, True)):
        h.declare("G " + host, "owner", host_declaration(host, stores_first, False))
        h.declare("D " + host, "owner", successor(host_declaration(host, stores_first, False),
                                                   collections=host_declaration(host, stores_first, True)["collections"]))
    h.epoch(*["G " + host for host in hosts])
    moving = {}
    for host in hosts:
        k, u = page(f"https://{host}/journal/k", publisher=host), page(f"https://{host}/journal/u", publisher=host)
        moving[host] = u
        h.cat("J1 " + host, [k, u], h.at(4 * MINUTE), "journal", publisher=host)
        h.cat("S1 " + host, [], h.at(4 * MINUTE), "store", "store", publisher=host)
        h.cat("J2 " + host, [k], h.at(34 * MINUTE), "journal", publisher=host)
        h.cat("S2 " + host, [u], h.at(34 * MINUTE), "store", "store", publisher=host)
    for i, host in enumerate(hosts):
        h.pull((5 + i) * MINUTE, "G " + host, {"journal": "J1 " + host, "store": "S1 " + host}, publisher=host)
    h.epoch()
    for i, host in enumerate(hosts):
        h.pull((35 + i) * MINUTE, "D " + host, {"journal": "J2 " + host, "store": "S2 " + host}, publisher=host)
    h.epoch(*["D " + host for host in hosts])
    h.epoch(domain_epoch_entries_max=1)
    h.epoch(domain_epoch_entries_max=1)

    def hosts_first(v):
        a_url, b_url = moving[hosts[0]]["url"], moving[hosts[1]]["url"]
        assert v.items(4, "store")[a_url]["payload"] == "record" and a_url not in v.urls(4)
        urls = v.urls(6)
        assert urls[a_url]["place"] == [6, 1, 0] and urls[b_url]["place"] == [6, 0, 0]
        assert v.sealed(7) == [a_url] and v.deferred(7) == {b_url: ["capacity"]}
        assert v.sealed(8) == [b_url]

    histories.append(run(h, hosts_first))

    wide = successor(G, collections=[collection("journal", [prefix(J)] + [exact(f"{J}e{i:02d}") for i in range(35)],
                                                [key("journal")]), STORE])
    other = successor(G, subdomain_scope=["www.example.com", "docs.example.com"])
    h = History("an accepted Declaration that fails at its candidate Epoch",
                "scope_entries_max is 40 at heights 0 and 2 and at the pulls after them, and 32 at height 1. At pull "
                "1 the Aggregator discovers D, an ordinary rotation whose journal Scope has 36 entries, within 40, "
                "and accepts J1 under it. At height 1 D fails WIST1-E16 under 32: it is not sealed, it leaves the "
                "eligible sealing set and is reported, G is the accepted head again and the sequence floor stays at "
                "D's seq. J1 and a, judged under G, are sealed there. At pull 2, under 32, O, another Declaration "
                "of D's seq naming G, is WIST1-E08; at pull 3, under 40 again, D served again is WIST1-E08 too, and "
                "G served again is an idempotent re-serve at pull 4. A Declaration that left, served under a map "
                "whose counts it exceeds, may be rejected with WIST1-E08 or with the code of that check, either "
                "diagnostic conforming; D is served again under 40 so that the expected result does not depend on "
                "the choice.", scope_entries_max=40)
    h.declare("G", "owner", G)
    h.declare("D", "owner", wide)
    h.declare("O", "owner", other)
    h.epoch("G")
    pa = page(J + "a")
    h.cat("J1", [pa], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "D", {"journal": "J1"})
    h.epoch("D", scope_entries_max=32)
    h.pull(5 * MINUTE, "O", {"journal": "J1"})
    h.epoch()
    h.pull(5 * MINUTE, "D", {"journal": "J1"})
    h.pull(10 * MINUTE, "G", {"journal": "J1"})

    def candidate(v):
        assert v.expected[1]["declaration"]["outcome"] == "ordinary_rotation"
        assert v.expected[1]["declaration"]["sources"] == ["D"]
        assert v.expected[2]["declarations_failed"] == [{"declaration": "D", "code": "WIST1-E16"}]
        assert all(e["type"] != "publisher_declaration" for e in v.expected[2]["entries"])
        assert v.sealed(2) == ["J1", J + "a"]
        assert v.expected[3]["declaration"]["outcome"] == "WIST1-E08"
        assert v.expected[5]["declaration"]["outcome"] == "WIST1-E08"
        assert v.expected[6]["declaration"]["outcome"] == "idempotent"
        assert v.expected[6]["declaration"]["sources"] == ["G"]

    histories.append(run(h, candidate))

    rekeyed = successor(G, collections=[collection("journal", [prefix(J)], [key("journal2")]), STORE])
    h = History("a base that fails C1 at its turn",
                "J1 lists a and b, sealed at height 1. J2 carries the same list more than 180 days after the floor: "
                "a base, accepted at pull 2, from which I7 is read for the journal against no record, so a and b wait "
                "although they are their records' Items. At pull 3 the Aggregator discovers D, which replaces the "
                "journal key. Height 2 seals D; J2 fails C1 (WIST1-E02) at its turn, is reported and is no longer "
                "the last accepted Catalog. I7 is read against the records again: a and b, their records' Items, leave "
                "as Items for which I7 no longer holds, listed in `left` and not reported, and the records stay.")
    h.declare("G", "owner", G)
    h.declare("D", "owner", rekeyed)
    h.epoch("G")
    pa, pb = page(J + "a"), page(J + "b")
    j1 = h.cat("J1", [pa, pb], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    later = seconds(j1.inner["generated_at"]) + retention + 1
    h.cat("J2", [pa, pb], later, "journal")
    h.last = later
    h.pull(1 * MINUTE, "G", {"journal": "J2"})
    h.pull(2 * MINUTE, "D", {"journal": "J2"})
    h.epoch("D", sealed_at=later + 10 * MINUTE)

    def base_left(v):
        assert v.catalog(3, "journal")["base"] is True and set(v.urls(3)) == {J + "a", J + "b"}
        assert v.left(5) == [("J2", "C1", ["WIST1-E02"], True)] + [
            (i["url"], "I7", ["WIST1-E02", "WIST3-E06"], False) for i in h.catalogs["J2"].listed]
        assert v.sealed(5) == []
        assert v.urls(5) == {} and [r["url"] for r in v.expected[5]["state"]["records"]] == [J + "a", J + "b"]

    histories.append(run(h, base_left))

    only_q = successor(G, collections=[collection("journal", [prefix(J + "q/")], [key("journal")]), STORE])
    h = History("an Item that fails I7 and another condition leaves unreported",
                "J1 lists p/x and q/y, sealed at height 1. J2 lists the removal of p/x, whose record exists, and "
                "waits with it from pull 2. At pull 3 the Aggregator discovers D1, which narrows the journal to q/, "
                "and J2 is served again. Height 2 seals D1, whose narrowing removes p/x's record, and J2: the "
                "removal of p/x then fails I7, having no record, and I5, outside the Scope; it leaves waiting "
                "unreported and nothing is sealed for it.")
    h.declare("G", "owner", G)
    h.declare("D1", "owner", only_q)
    h.epoch("G")
    px, py = page(J + "p/x"), page(J + "q/y")
    h.cat("J1", [px, py], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    h.cat("J2", [removed(J + "p/x", stamp(h.at(3 * MINUTE))), py], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J2"})
    h.pull(10 * MINUTE, "D1", {"journal": "J2"})
    h.epoch("D1")

    def unreported(v):
        assert set(v.urls(3)) == {J + "p/x"}
        assert v.left(5) == [(J + "p/x", "I7", ["WIST1-E03", "WIST3-E06"], False)]
        assert v.sealed(5) == ["J2"] and v.urls(5) == {}
        assert v.expected[5]["records_removed"] == [
            {"publisher": "example.com", "url": J + "p/x", "cause": "narrowing"}]

    histories.append(run(h, unreported))

    kept_only = successor(G, keys=[key("fresh")], collections=[
        collection("journal", [prefix(J + "keep/")], [key("journal")]), STORE])
    h = History("a pending head that narrows a Collection",
                "P, a fresh identity that narrows the journal to keep/, is sealed at height 2 and is the pending "
                "head; the pull reads G alone. The Publisher derives J2 under P, the Declaration it serves, from J1's "
                "list and the publication of keep/a: x, outside P's Scope, has no publication and becomes an Item of "
                "kind removed. G still covers x, so J2 is accepted, where a list without x would be WIST2-E07, and "
                "the removal of x is sealed at height 3 and removes its record.")
    h.declare("G", "owner", G)
    h.declare("P", "fresh", kept_only)
    h.epoch("G")
    pa, px = page(J + "keep/a"), page(J + "x")
    j1 = h.cat("J1", [pa, px], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    h.pull(5 * MINUTE, "P", {"journal": "J1"})
    h.epoch("P")
    generated = h.at(4 * MINUTE)
    h.cat("J2", derived(j1.listed, [pa], kept_only, "journal", generated), generated, "journal")
    h.pull(5 * MINUTE, "P", {"journal": "J2"})
    h.epoch()

    def pending_narrowed(v):
        assert v.expected[5]["declaration"]["sources"] == ["G"]
        assert v.outcome(5, "journal") == ("accepted", None)
        assert v.items(5, "journal")[J + "x"]["outcome"] == "admitted"
        assert v.sealed(6) == ["J2", J + "x"]
        assert v.expected[6]["records_removed"] == [{"publisher": "example.com", "url": J + "x",
                                                     "cause": "removed_item"}]

    histories.append(run(h, pending_narrowed))

    only_n = successor(G, collections=[collection("journal", [prefix(J + "n/")], [key("journal")]), STORE])
    widened_again = successor(only_n, collections=[JOURNAL, STORE])
    h = History("an Item sealed again after narrowing and a later widening",
                "J1 lists n/a and o/x, sealed at height 1. D1, sealed at height 2, narrows the journal to n/ and "
                "removes x's record; x, the Item of the unchanged latest Catalog J1, then passes I7 and begins to "
                "wait at that Epoch. D2, discovered at pull 3 and sealed at height 3, widens the journal again, and "
                "height 3 seals x once more against J1.")
    h.declare("G", "owner", G)
    h.declare("D1", "owner", only_n)
    h.declare("D2", "owner", widened_again)
    h.epoch("G")
    pa, px = page(J + "n/a"), page(J + "o/x")
    h.cat("J1", [pa, px], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    h.pull(5 * MINUTE, "D1", {"journal": "J1"})
    h.epoch("D1")
    h.pull(5 * MINUTE, "D2", {"journal": "J1"})
    h.epoch("D2")

    def sealed_again(v):
        j_list = [i["url"] for i in h.catalogs["J1"].listed]
        assert v.urls(4)[J + "o/x"]["place"] == [4, 0, j_list.index(J + "o/x")]
        assert v.sealed(6) == [J + "o/x"] and v.expected[6]["sealed"][0]["catalog"] == h.catalogs["J1"].id

    histories.append(run(h, sealed_again))

    moved_u = S + "x/u"
    moving = successor(G, collections=[collection("journal", [prefix(J), prefix(S + "x/")], [key("journal")]),
                                       collection("store", [prefix(S + "y/")], [key("store")])])
    h = History("two Collections whose last accepted Catalogs list one URL",
                "At pull 1 S1, the store's list of s/x/u, is accepted under G and u waits in the store. At pull 2 the "
                "Aggregator discovers D, which moves s/x/ from the store to the journal; the store's catalog.json "
                "cannot be fetched, so S1 is not judged again, and J1, the journal's list of the same Item of u, "
                "later than S1, is accepted under D. Both last accepted Catalogs list an admitted Item for u, and "
                "the Item of the Collection whose Scope covers u under the Declaration in force waits: after pull 2, "
                "with G in force, the store's, although J1 is the later Catalog; at height 1, once D's transitions "
                "have applied, the journal's, keeping its place. Height 1 seals D, then S1 and J1 in the order of "
                "their places, and u against J1.")
    h.declare("G", "owner", G)
    h.declare("D", "owner", moving)
    h.epoch("G")
    pu = page(moved_u)
    h.cat("S1", [pu], h.at(4 * MINUTE), "store", "store")
    h.cat("J1", [pu], h.at(8 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"store": "S1"})
    h.pull(10 * MINUTE, "D", {"journal": "J1"})
    h.epoch("D")

    def later_catalog(v):
        assert v.urls(1)[moved_u]["collection"] == "store"
        assert v.outcome(2, "store") == ("unavailable", None)
        assert v.urls(2)[moved_u]["collection"] == "store" and v.urls(2)[moved_u]["place"] == [1, 1, 0]
        assert v.sealed(3) == ["S1", "J1", moved_u] and v.expected[3]["sealed"][2]["collection"] == "journal"
        assert v.left(3) == []

    histories.append(run(h, later_catalog))

    wide_first = {**G, "collections": [collection("journal", [prefix(J)] + [exact(f"{J}e{i:02d}") for i in range(35)],
                                                  [key("journal")]), STORE]}
    h = History("a first Declaration that fails at its candidate Epoch",
                "scope_entries_max is 40 at height 0 and the pulls after it and 32 from height 1. At pull 1 the "
                "Aggregator accepts Gw, the Publisher's first Declaration, whose journal Scope has 36 entries, and at "
                "pull 2 D, which names Gw and has the journal Scope of one entry. At height 1 Gw fails WIST1-E16 and leaves the eligible sealing set, and D "
                "leaves with it, reported with the same code. No accepted Declaration remains: the domain returns to "
                "first contact with no sequence floor, and at pull 3 G, another Declaration of seq 0, is accepted as "
                "the first and sealed at height 2.", scope_entries_max=40)
    h.declare("Gw", "owner", wide_first)
    h.declare("D", "owner", successor(wide_first, collections=G["collections"]))
    h.declare("G", "owner", G)
    h.epoch()
    h.pull(5 * MINUTE, "Gw", {})
    h.pull(10 * MINUTE, "D", {})
    h.epoch("Gw", "D", scope_entries_max=32)
    h.pull(5 * MINUTE, "G", {})
    h.epoch("G", scope_entries_max=32)

    def first_fails(v):
        assert v.expected[1]["declaration"]["outcome"] == "initial"
        assert v.expected[3]["declarations_failed"] == [{"declaration": "Gw", "code": "WIST1-E16"}]
        assert v.expected[3]["declarations_left"] == [{"declaration": "D", "names": "Gw", "code": "WIST1-E16"}]
        assert v.expected[4]["declaration"]["outcome"] == "initial" and v.expected[4]["declaration"]["discovered"]
        assert [e["body"]["publisher"]["seq"] for e in v.expected[5]["entries"]] == [0]

    histories.append(run(h, first_fails))

    fresh_head = successor(G, keys=[key("fresh")])
    replacement = successor(fresh_head, collections=[JOURNAL])
    long_reversal = successor(G, seq=3, collections=[
        collection("journal", [prefix(J)] + [exact(f"{J}e{i:02d}") for i in range(35)], [key("journal")]), STORE])
    h = History("a reversal that fails at its candidate Epoch",
                "P, a fresh identity, is sealed at height 1 and is the pending head. P2, a replacement of P that "
                "reduces authority, is accepted at pull 2, and V, a reversal naming G whose journal Scope has 36 "
                "entries, at pull 3 under scope_entries_max 40; V discards P and P2. At height 2, under 32, V fails "
                "WIST1-E16 and leaves the eligible sealing set: the admission state is that of the accepted "
                "Declarations that remain, applied in the order of their acceptance, so P2, which V had discarded, "
                "is the pending head again and stays in the eligible sealing set: at pull 4 P2 served again is an "
                "idempotent re-serve, and height 3 seals it.",
                scope_entries_max=40)
    h.declare("G", "owner", G)
    h.declare("P", "fresh", fresh_head)
    h.declare("P2", "fresh", replacement)
    h.declare("V", "owner", long_reversal)
    h.epoch("G")
    h.pull(5 * MINUTE, "P", {})
    h.epoch("P")
    h.pull(5 * MINUTE, "P2", {})
    h.pull(10 * MINUTE, "V", {})
    h.epoch("V", scope_entries_max=32)
    h.pull(5 * MINUTE, "P2", {})
    h.epoch("P2", scope_entries_max=32)

    def reversal_fails(v):
        assert v.expected[4]["declaration"]["outcome"] == "reversal_ordinary_rotation"
        assert v.expected[5]["declarations_failed"] == [{"declaration": "V", "code": "WIST1-E16"}]
        assert v.expected[5]["state"]["reductions_pending"] == [{"publisher": "example.com", "declaration": "P2"}]
        assert v.expected[6]["declaration"]["outcome"] == "idempotent"
        assert v.expected[6]["declaration"]["sources"] == ["G"]
        assert [e["body"]["publisher"]["seq"] for e in v.expected[7]["entries"]] == [2]

    histories.append(run(h, reversal_fails))

    rekeyed = successor(G, collections=[collection("journal", [prefix(J)], [key("journal2")]), STORE])
    h = History("a Catalog served again that meets a Catalog condition retries nothing",
                "J1 is sealed with a at height 1. J2 lists a and b and waits from pull 2, where b's Payload is "
                "unavailable. At pull 3 J2's inner object is served with J1's signature: it meets WIST1-E01, is "
                "refused before its order is read, replaces nothing and retries nothing, though b's Payload is "
                "served. At pull 4 the Aggregator discovers D, which removes the journal key, and J2 served again "
                "meets WIST1-E02 under D: refused, retrying nothing.")
    h.declare("G", "owner", G)
    h.declare("D", "owner", rekeyed)
    h.epoch("G")
    pa, pb = page(J + "a"), page(J + "b")
    j1 = h.cat("J1", [pa], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    j2 = h.cat("J2", [pa, pb], h.at(4 * MINUTE), "journal")
    bad = copy.copy(j2)
    bad.envelope = {"catalog": j2.inner, "sig": j1.envelope["sig"]}
    h.add("J2 under J1's signature", bad)
    h.pull(5 * MINUTE, "G", {"journal": "J2"}, withhold=(J + "b",))
    h.pull(10 * MINUTE, "G", {"journal": "J2 under J1's signature"})
    h.pull(15 * MINUTE, "D", {"journal": "J2"})

    def condition_first(v):
        assert v.items(3, "journal")[J + "b"]["outcome"] == "not_admitted"
        assert v.outcome(4, "journal") == ("refused", ["WIST1-E01"]) and "items" not in v.catalog(4, "journal")
        assert v.outcome(5, "journal") == ("refused", ["WIST1-E02"]) and "items" not in v.catalog(5, "journal")
        assert v.last_accepted(5, "journal") in ("J2", "J2 under J1's signature") and J + "b" not in v.urls(5)

    histories.append(run(h, condition_first))

    h = History("a pull that accepts nothing and admits nothing is noise",
                "J1 lists a and b; b's Payload is unavailable at pull 1 and height 1 seals J1 and a. Pull 2 serves J1 "
                "again with b's Payload still unavailable: an idempotent re-serve that admits nothing, and G served "
                "again, so the pull accepts no Declaration and no Catalog and admits no Item: noise. Pull 3 serves "
                "J1 again with b's Payload: the re-serve admits b, and the pull is not noise.")
    h.declare("G", "owner", G)
    h.epoch("G")
    h.cat("J1", [page(J + "a"), page(J + "b")], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"}, withhold=(J + "b",))
    h.epoch()
    h.pull(5 * MINUTE, "G", {"journal": "J1"}, withhold=(J + "b",))
    h.pull(10 * MINUTE, "G", {"journal": "J1"})

    def noise(v):
        assert "noise" not in v.expected[1]
        assert v.expected[3]["noise"] is True and v.outcome(3, "journal")[0] == "idempotent"
        assert "noise" not in v.expected[4] and v.items(4, "journal")[J + "b"]["outcome"] == "admitted"

    histories.append(run(h, noise))

    store_exp = successor(rekeyed, collections=[collection("journal", [prefix(J)], [key("journal2")]),
                                                collection("store", [prefix(S)], [key("store", exp=T0 + 400 * DAY)])])
    h = History("the latest Catalog fails I4 while a Catalog of the Collection waits that nothing defers",
                "J1 and a are sealed at height 1. D1, sealed at height 2, replaces the journal key, so the latest "
                "Catalog J1 fails I4 from then on. At pull 3 the Aggregator discovers D2, which reduces authority, "
                "and accepts J2, signed by journal2, with b, eligible for height 3. The hold keeps J2 and b out until "
                "height 7, which seals D2; the fourth deferral does not apply to b while J2 waits and nothing defers "
                "it, so b is held, not deferred, and keeps eligibility Epoch 3 and ceiling 7.")
    h.declare("G", "owner", G)
    h.declare("D1", "owner", rekeyed)
    h.declare("D2", "owner", store_exp)
    h.epoch("G")
    pa, pb = page(J + "a"), page(J + "b")
    h.cat("J1", [pa], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    h.pull(5 * MINUTE, "D1", {"journal": "J1"})
    h.epoch("D1")
    h.cat("J2", [pa, pb], h.at(4 * MINUTE), "journal2")
    h.pull(5 * MINUTE, "D2", {"journal": "J2"})
    for _ in range(4):
        h.epoch()
    h.epoch("D2")

    def undeferred(v):
        for event in (6, 7, 8, 9):
            assert v.held(event)[J + "b"] == ["authority_reduction"] and J + "b" not in v.deferred(event)
        assert v.sealed(10) == ["J2", J + "b"] and v.eligibility(10)[J + "b"] == (3, 7)

    histories.append(run(h, undeferred))

    owner_journal = successor(G, collections=[STORE])
    h = History("a Catalog that fails C1 and C4 at its turn leaves as one that fails C1",
                "J1, signed by the owner key, is sealed with a at height 1. J1b, J1's list one hour later, waits from "
                "pull 2. At pull 3 the Aggregator discovers D, which drops the journal. At height 2, which seals D, "
                "J1b fails C1 (WIST1-E03, a Collection D does not name) and C4 (J1's root inside "
                "catalog_refresh_seconds, J1 still passing the binding check under the owner key): it leaves as one "
                "that fails C1, reported with that code alone.")
    h.declare("G", "owner", G)
    h.declare("D", "owner", owner_journal)
    h.epoch("G")
    pa = page(J + "a")
    j1 = h.cat("J1", [pa], h.at(4 * MINUTE), "owner")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    h.cat("J1b", [pa], seconds(j1.inner["generated_at"]) + HOUR, "owner")
    h.pull(5 * MINUTE, "G", {"journal": "J1b"})
    h.pull(10 * MINUTE, "D", {})
    h.epoch("D")

    def c1_alone(v):
        assert v.left(5) == [("J1b", "C1", ["WIST1-E03"], True)]
        assert v.last_accepted(5, "journal") == "J1"

    histories.append(run(h, c1_alone))

    xs = S + "x"
    moves_x = successor(G, collections=[collection("journal", [prefix(J), exact(xs)], [key("journal")]),
                                        collection("store", [prefix(S + "y/")], [key("store")])])
    h = History("a base and a record of its URL in another Collection",
                "J1's a and S1's s/x are sealed at height 1, x's record in the store. More than 180 days later the "
                "Aggregator discovers D, which moves s/x to the journal, and accepts J2, a base against the journal's "
                "floor listing a and the removal of s/x. Under the base I7 is read against no record of the journal: "
                "a waits although it is its record's Item, and the removal of x, whose record is in the store, is read "
                "as outside a base and waits. Height 2 seals D, whose narrowing removes x's record, and J2, which "
                "removes a's: a is sealed. Once D and J2 have applied, the Item that waits for x is read again: the "
                "removal now fails I7, and the store's page Item of x, no longer its record's, meets the Waits row, "
                "so it takes x's turn with x's place and eligibility Epoch, the removal leaving without a report, "
                "and fails I5 (WIST1-E03), the store no longer covering x: it is reported and x waits no more.")
    h.declare("G", "owner", G)
    h.declare("D", "owner", moves_x)
    h.epoch("G")
    pa, px = page(J + "a"), page(xs)
    j1 = h.cat("J1", [pa], h.at(4 * MINUTE), "journal")
    h.cat("S1", [px], h.at(4 * MINUTE), "store", "store")
    h.pull(5 * MINUTE, "G", {"journal": "J1", "store": "S1"})
    h.epoch()
    later = seconds(j1.inner["generated_at"]) + items.REMOVAL_RETENTION_DAYS * DAY + 1
    h.cat("J2", [pa, removed(xs, stamp(later - MINUTE))], later, "journal")
    h.last = later
    h.pull(1 * MINUTE, "D", {"journal": "J2"})
    h.epoch("D", sealed_at=later + 10 * MINUTE)

    def other_collection(v):
        assert v.catalog(3, "journal")["base"] is True and set(v.urls(3)) == {J + "a", xs}
        assert v.sealed(4) == ["J2", J + "a"]
        assert v.left(4) == [(xs, "I5", ["WIST1-E03"], True)] and v.urls(4) == {}
        assert v.expected[4]["left"][0]["item"] == items.item_id(px)

    histories.append(run(h, other_collection))

    return {"note": NOTE_COMMON + (
        " This file exercises ADR-0052 Sealing, Waiting (the last accepted Catalog, what waits, places, leaving, "
        "eligibility, its deferrals and the capacity order), Files (the retry of a refused Catalog and WIST2-E07 "
        "for a list that drops a held record's URL) and An Aggregator that was away (I7 read against no record from "
        "the pull that accepts a base until it is sealed or leaves), with ADR-0051 Reaching the Log (the hold of a "
        "Declaration that reduces authority, which moves no eligibility Epoch or ceiling and ends when the "
        "Declaration is sealed or leaves the eligible sealing set, a Declaration that fails at its candidate Epoch, "
        "and one that widens a Scope sealed with the Item it admits) and Capacity. Outside the hold a prompt "
        "Aggregator seals what waits at its eligibility Epoch unless a deferral moves it, so the history of the "
        "hold is the one that shows an eligibility Epoch and a ceiling kept across Epochs and a replacement."), "keys": KEYS_MEMBER, "histories": histories}


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
                "J0, signed by the journal key, is accepted at pull 1 and waits with a. R, a recovery rotation, "
                "replaces the owner key by owner2 and the journal key by journal2 and adds docs. At pull 2 it is "
                "discovered and not yet sealed: the pull reads G and R, each alone, and pulls journal and store, then "
                "docs, which R alone names. From that pull what a pull accepts is queued per Collection name and "
                "signing key and no URL takes a place: J1, signed by the journal key, passes under G alone and is "
                "queued after J0, which still waits, and S0, signed by the store key, passes under both. R reduces "
                "authority, so height 1, which seals it and opens the window, is the first Epoch at which J0 could be "
                "sealed; the window holds it and holds a with its place, and does not queue J0, since J1, of its name and "
                "key with a later instant, is queued already and stays. Inside "
                "the window J2, signed by journal2, and D1, signed by owner2, pass under R alone and are queued. "
                "Height 2, at the window's end, settles: J1 fails C1 under R (WIST1-E13) and J2, S0 and D1 survive; "
                "J2 takes the earliest place among the Catalogs queued under the journal and the one that waited for it "
                "when the window opened, J0's, although J0 was kept out of the queue, and a keeps its own.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", removing)
    h.epoch("G")
    pa, pb, pc, ps, pd = page(J + "a"), page(J + "b"), page(J + "c"), page(S + "s"), page(DOCS + "d")
    h.cat("J0", [pa], h.at(2 * MINUTE), "journal")
    h.cat("J1", [pa, pc], h.at(4 * MINUTE), "journal")
    h.cat("S0", [ps], h.at(4 * MINUTE), "store", "store")
    h.pull(3 * MINUTE, "G", {"journal": "J0"})
    h.pull(5 * MINUTE, "R", {"journal": "J1", "store": "S0"})
    h.epoch("R")
    start = h.last
    h.cat("J2", [pa, pb], h.at(4 * MINUTE), "journal2")
    h.cat("D1", [pd], h.at(4 * MINUTE), "owner2", "docs")
    h.pull(5 * MINUTE, "R", {"journal": "J2", "docs": "D1"})
    h.epoch(sealed_at=start + 7 * DAY)

    def frozen(v):
        d = v.expected[2]["declaration"]
        assert d["outcome"] == "recovery_rotation" and d["sources"] == ["G", "R"] and d["window"] is False
        assert v.expected[2]["collections_pulled"] == ["journal", "store", "docs"]
        assert v.catalog(2, "journal")["sources"] == ["G"] and v.catalog(2, "store")["sources"] == ["G", "R"]
        assert v.catalog(2, "journal")["queued"] is True and v.last_accepted(2, "journal") == "J0"
        assert set(v.urls(2)) == {J + "a"} and v.urls(2)[J + "a"]["place"] == [1, 0, 0]
        assert v.held(3) == {} and v.deferred(3)["J0"] == ["recovery_window"]
        queue = [(q["collection"], q["key"], v.ids[q["catalog"]], q["place"], q["first_place"])
                 for q in v.expected[3]["state"]["queue"]]
        assert queue == [("journal", "journal", "J1", [2, 0], [1, 0]), ("store", "store", "S0", [2, 1], [2, 1])]
        assert v.expected[4]["declaration"]["window"] is True
        assert v.catalog(4, "journal")["sources"] == ["R"] and v.catalog(4, "docs")["sources"] == ["R"]
        settled = {v.ids[s["catalog"]]: s["outcome"] for s in v.expected[5]["settlement"]}
        assert settled == {"J1": "WIST1-E13", "S0": "survivor", "J2": "survivor", "D1": "survivor"}
        journal_sealed = next(r for r in v.expected[5]["sealed"] if r["type"] == "publisher_catalog"
                              and r["collection"] == "journal")
        assert v.ids[journal_sealed["catalog"]] == "J2" and journal_sealed["eligibility"] == 2
        assert v.sealed(5)[:3] == ["J2", "S0", "D1"]

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
                "domain_epoch_entries_max is 2 from height 2. S0 is accepted at pull 1 and waits; J2 is accepted at "
                "pull 2, which discovers R, and is queued there with place [2, 0]. Height 1 seals R and queues S0 "
                "with its place [1, 1]. Inside "
                "the window J3, signed by journal2, and D1 are queued. At settlement J2 fails, and J3, the surviving "
                "journal Catalog, takes J2's place as the first Catalog queued under its name. Height 2 seals S0 and "
                "J3 in the order of those places, S0's being the earlier, and D1 waits for height 3. a and b took no "
                "place at the pull that discovered R; with c and d they take the places of the pull that queued J3 "
                "and D1.", domain_epoch_entries_max=10)
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
        assert J + "a" not in v.urls(2) and urls[J + "a"]["place"][:2] == [4, 0]
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
                "seals J1 and a. Inside the window J1, the latest Catalog, is served again with u's Payload: no source "
                "accepts it, so it meets a Catalog condition (WIST1-E02), is refused before its order is read, and "
                "retries no Item; u stays not admitted. J2, "
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
        assert v.outcome(7, "journal") == ("refused", ["WIST1-E02"]) and "items" not in v.catalog(7, "journal")
        got = v.items(8, "journal")
        assert got[J + "u"]["outcome"] == "admitted" and got[J + "v"]["outcome"] == "not_admitted"
        assert v.catalog(8, "journal")["sources"] == ["D", "R"]
        again = v.catalog(9, "journal")
        assert again["outcome"] == "idempotent" and [i["url"] for i in again["items"]] == [J + "v"]
        assert again["items"][0]["outcome"] == "admitted" and again["items"][0]["payload"] == "fetched"
        assert set(v.sealed(10)) == {"J2", J + "u", J + "v"}

    histories.append(run(h, reserve))

    competitor = successor(keeping, keys=[key("fresh")])
    h = History("a competitor that reduces authority, superseded unsealed at settlement",
                "Inside the window J2 is queued, and the Aggregator discovers C, a fresh identity naming R and signed "
                "by the fresh key: a competitor that removes owner2 and so reduces authority, which it does not "
                "seal. Height 4, the Epoch of settlement, settles the queue under R and supersedes C, which leaves "
                "the eligible sealing set unsealed; the hold ends, and J2 and b, eligible for that Epoch, are sealed "
                "there. C served again after settlement is WIST1-E08.")
    h.cat("J1", [page(J + "a")], T0 + 4 * MINUTE, "journal")
    start = opened(h, keeping, {"journal": "J1"})
    h.declare("C", "fresh", competitor)
    h.cat("J2", [page(J + "a"), page(J + "b")], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "R", {"journal": "J2"})
    h.pull(10 * MINUTE, "C", {"journal": "J2"})
    h.epoch()
    h.epoch(sealed_at=start + 7 * DAY)
    h.pull(5 * MINUTE, "C", {})

    def superseded(v):
        assert v.expected[6]["declaration"]["outcome"] == "in_window_competitor"
        assert v.expected[6]["declaration"]["reduces_authority"] is True
        assert v.expected[7]["state"]["reductions_pending"] == [{"publisher": "example.com", "declaration": "C"}]
        assert v.expected[8]["state"]["reductions_pending"] == []
        assert v.sealed(8) == ["J2", J + "b"] and v.eligibility(8)["J2"] == (4, 8)
        assert v.expected[9]["declaration"]["outcome"] == "WIST1-E08"

    histories.append(run(h, superseded))

    narrowed_recovery = successor(G, keys=[key("owner2")], collections=[
        collection("journal", [prefix(J + "keep/")], [key("journal2")]), STORE])
    h = History("a recovery rotation that narrows a Scope: the owner's Catalog is queued",
                "J1 lists keep/a and x, sealed at height 1. R, sealed at height 2, narrows the journal to keep/ and "
                "replaces the journal key by journal2. The owner derives J2 under R from J1's list and the "
                "publication of keep/a: x becomes an Item of kind removed. Inside the window J2 passes under R alone, "
                "under which the removal of x is outside the Scope and refused alone (WIST1-E03); the list holds an "
                "Item for x, whose record G's Scope covers, so J2 is not WIST2-E07 and is queued. Height 3 settles, "
                "R's narrowing removes x's record, and J2 is sealed.")
    pa, px = page(J + "keep/a"), page(J + "x")
    j1 = h.cat("J1", [pa, px], T0 + 4 * MINUTE, "journal")
    start = opened(h, narrowed_recovery, {"journal": "J1"})
    generated = h.at(4 * MINUTE)
    h.cat("J2", derived(j1.listed, [pa], narrowed_recovery, "journal", generated), generated, "journal2")
    h.pull(5 * MINUTE, "R", {"journal": "J2"})
    h.epoch(sealed_at=start + 7 * DAY)

    def narrowing_queued(v):
        found = v.catalog(5, "journal")
        assert found["outcome"] == "accepted" and found["queued"] is True and found["sources"] == ["R"]
        assert v.items(5, "journal")[J + "x"] == {**v.items(5, "journal")[J + "x"], "outcome": "refused",
                                                  "codes": ["WIST1-E03"]}
        assert v.sealed(6) == ["J2"]
        assert v.expected[6]["records_removed"] == [{"publisher": "example.com", "url": J + "x",
                                                     "cause": "narrowing"}]

    histories.append(run(h, narrowing_queued))

    h = History("records sealed under a key an attacker held, and the owner's Catalogs after settlement",
                "An attacker holding the journal key has J1 sealed at height 1 with e1 and e2 beside a. R, sealed at "
                "height 2, replaces the journal key by journal2. After the window settles at height 3, the owner's "
                "J2, signed by journal2, lists a alone: refused with WIST2-E07, the report naming e1 and e2. J3 "
                "lists the removals of e1 and e2 and is accepted; height 4 seals it with both removals, which remove "
                "the records.")
    pa, pe1, pe2 = page(J + "a"), page(J + "e1"), page(J + "e2")
    h.cat("J1", [pa, pe1, pe2], T0 + 4 * MINUTE, "journal")
    start = opened(h, removing, {"journal": "J1"})
    h.epoch(sealed_at=start + 7 * DAY)
    h.cat("J2", [pa], h.at(4 * MINUTE), "journal2")
    h.cat("J3", [pa, removed(J + "e1", stamp(h.at(7 * MINUTE))), removed(J + "e2", stamp(h.at(7 * MINUTE)))],
          h.at(8 * MINUTE), "journal2")
    h.pull(5 * MINUTE, "R", {"journal": "J2"})
    h.pull(10 * MINUTE, "R", {"journal": "J3"})
    h.epoch()

    def attacker(v):
        found = v.catalog(6, "journal")
        assert found["outcome"] == "refused" and found["codes"] == ["WIST2-E07"]
        assert found["dropped"] == [J + "e1", J + "e2"]
        assert v.outcome(7, "journal")[0] == "accepted"
        assert v.sealed(8) == ["J3", J + "e1", J + "e2"] or v.sealed(8) == ["J3", J + "e2", J + "e1"]
        assert sorted(r["url"] for r in v.expected[8]["records_removed"]) == [J + "e1", J + "e2"]

    histories.append(run(h, attacker))

    about = "https://example.com/about"
    wiki = "https://example.com/wiki/"
    adding = successor(G, keys=[key("owner2")], collections=[
        collection("journal", [prefix(J), exact(about)], [key("journal2")]), STORE,
        collection("wiki", [prefix(wiki)]), collection("docs", [prefix(DOCS)])])
    h = History("a pull between the discovery and the sealing of a recovery rotation",
                "R replaces the owner and journal keys, adds an exact entry for https://example.com/about to the "
                "journal, and adds wiki and then docs. At pull 1 R is discovered and not sealed: from that pull a "
                "pull reads G and R, each alone, and queues what it accepts per Collection name and signing key, no "
                "URL taking a place. J1, signed by the journal key G alone lists, passes under G, under which about "
                "is outside the Scope: refused, where R's entry would cover it. W1 and D1, signed by owner2, which R "
                "alone lists, are queued with that pull's places, ordered by G's Collections and then the names G "
                "lacks in ascending octet order: docs before wiki, although the pull reads wiki first. At pull 2 J1 "
                "served again is an idempotent re-serve of a queued Catalog that retries about under G alone, the "
                "source that accepts J1. At pull 3 J1r, signed by journal2 with an instant one minute before J1's, "
                "is read against the floor and the queued Catalog of its own key and is queued beside J1. Nothing "
                "queued is sealed before settlement: height 1 seals R and opens the window; height 2 settles, J1 "
                "fails C1 under R (WIST1-E13), and J1r, taking the journal's first place, D1 and W1 are sealed in "
                "the order of their places, then d and w, placed at pull 1, and a and j, placed at pull 3.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", adding)
    h.epoch("G")
    pa, pab, pw, pd = page(J + "a"), page(about), page(wiki + "w"), page(DOCS + "d")
    h.cat("J1", [pa, pab], h.at(4 * MINUTE), "journal")
    h.cat("W1", [pw], h.at(4 * MINUTE), "owner2", "wiki")
    h.cat("D1", [pd], h.at(4 * MINUTE), "owner2", "docs")
    h.pull(5 * MINUTE, "R", {"journal": "J1", "wiki": "W1", "docs": "D1"})
    h.pull(10 * MINUTE, "R", {"journal": "J1"})
    pj = page(J + "j")
    h.cat("J1r", [pa, pj], h.at(3 * MINUTE), "journal2")
    h.pull(15 * MINUTE, "R", {"journal": "J1r"})
    h.epoch("R")
    start = h.last
    h.epoch(sealed_at=start + 7 * DAY)

    def discovery(v):
        d = v.expected[1]["declaration"]
        assert d["sources"] == ["G", "R"] and d["window"] is False
        assert v.expected[1]["collections_pulled"] == ["journal", "store", "wiki", "docs"]
        assert v.catalog(1, "journal")["sources"] == ["G"] and v.catalog(1, "journal")["queued"] is True
        assert v.items(1, "journal")[about]["outcome"] == "refused"
        assert v.catalog(1, "docs")["sources"] == ["R"] and v.urls(1) == {}
        places = {v.ids[q["catalog"]]: q["place"] for q in v.expected[1]["state"]["queue"]}
        assert places == {"J1": [1, 0], "D1": [1, 2], "W1": [1, 3]}
        again = v.catalog(2, "journal")
        assert again["outcome"] == "idempotent" and [i["outcome"] for i in again["items"]] == ["refused"]
        assert v.outcome(3, "journal")[0] == "accepted" and v.catalog(3, "journal")["sources"] == ["R"]
        assert [(q["key"], v.ids[q["catalog"]]) for q in v.expected[3]["state"]["queue"]
                if q["collection"] == "journal"] == [("journal", "J1"), ("journal2", "J1r")]
        assert v.sealed(4) == []
        assert v.sealed(5) == ["J1r", "D1", "W1", DOCS + "d", wiki + "w"] + [
            i["url"] for i in h.catalogs["J1r"].listed]

    histories.append(run(h, discovery))

    follower_store = successor(keeping, collections=[JOURNAL, collection("store", [prefix(S)], [key("store2")])])
    h = History("frozen sources when a follower is sealed in the owner's Epoch",
                "R keeps the collections and replaces the owner key by owner2; F, a follower signed by owner2, "
                "replaces the store key by store2. Both are discovered and sealed at height 1, which opens the "
                "window with R as its owner and F as the recovery-chain head. The frozen sources are G and R: S1, "
                "signed by the owner key G alone lists, is queued; S2, signed by store2, which F alone lists, is "
                "refused (WIST1-E02). Height 2 settles under F: S1 is rejected (WIST1-E13). S2 is accepted at the "
                "first pull after settlement.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", keeping)
    h.declare("F", "owner2", follower_store)
    h.epoch("G")
    h.pull(5 * MINUTE, "R", {})
    h.pull(10 * MINUTE, "F", {})
    h.epoch("R", "F")
    start = h.last
    h.cat("S1", [page(S + "s")], h.at(4 * MINUTE), "owner", "store")
    h.cat("S2", [page(S + "s")], h.at(8 * MINUTE), "store2", "store")
    h.pull(5 * MINUTE, "F", {"store": "S1"})
    h.pull(10 * MINUTE, "F", {"store": "S2"})
    h.epoch(sealed_at=start + 7 * DAY)
    h.pull(5 * MINUTE, "F", {"store": "S2"})

    def frozen_follower(v):
        assert v.expected[4]["declaration"]["sources"] == ["G", "R"]
        assert v.catalog(4, "store")["queued"] is True and v.catalog(4, "store")["sources"] == ["G"]
        assert v.outcome(5, "store") == ("refused", ["WIST1-E02"])
        assert {v.ids[s["catalog"]]: s["outcome"] for s in v.expected[6]["settlement"]} == {"S1": "WIST1-E13"}
        assert v.expected[7]["declaration"]["sources"] == ["F"] and v.outcome(7, "store")[0] == "accepted"

    histories.append(run(h, frozen_follower))

    h = History("the recovery-chain head served again while a competitor is current",
                "R is sealed at height 1 and opens the window. C, a fresh identity naming R, is a competitor "
                "sealed at height 2 and is current. At pull 3 the site serves R again: a success of the fetch, "
                "under which the pull reads the two frozen sources, pulls the Collections of both and queues J2, "
                "signed by owner2, R's key.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", keeping)
    h.declare("C", "fresh", competitor)
    h.epoch("G")
    h.pull(5 * MINUTE, "R", {})
    h.epoch("R")
    h.pull(5 * MINUTE, "C", {})
    h.epoch("C")
    h.cat("J2", [page(J + "a")], h.at(4 * MINUTE), "owner2")
    h.pull(5 * MINUTE, "R", {"journal": "J2"})

    def chain_head(v):
        d = v.expected[5]["declaration"]
        assert d["outcome"] == "recovery_chain_head" and d["sources"] == ["G", "R"] and d["window"] is True
        assert v.expected[5]["collections_pulled"] == ["journal", "store"]
        found = v.catalog(5, "journal")
        assert found["queued"] is True and found["key"] == "owner2"

    histories.append(run(h, chain_head))

    h = History("a settlement with nothing queued for a name",
                "J1 is sealed at height 1. J2, J1's root one hour later, is accepted at pull 2, fails C4 at height 2 "
                "and stays the last accepted Catalog. R opens a window at height 3 and nothing is queued for the "
                "journal. At settlement, height 4, the journal's last accepted Catalog is the latest Catalog, J1: "
                "J3, of another root with an instant between J1's and J2's, is accepted at the next pull, where "
                "against J2 it would be WIST2-E05, and sealed at height 5.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", keeping)
    h.epoch("G")
    pa = page(J + "a")
    j1 = h.cat("J1", [pa], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    t1 = seconds(j1.inner["generated_at"])
    h.cat("J2", [pa], t1 + HOUR, "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J2"})
    h.epoch()
    h.pull(5 * MINUTE, "R", {})
    h.epoch("R")
    start = h.last
    h.epoch(sealed_at=start + 7 * DAY)
    h.cat("J3", [pa, page(J + "b")], t1 + HOUR // 2, "journal")
    h.pull(5 * MINUTE, "R", {"journal": "J3"})
    h.epoch()

    def nothing_queued(v):
        assert v.left(4) == [("J2", "C4", ["WIST3-E06"], False)] and v.last_accepted(4, "journal") == "J2"
        assert v.expected[6]["state"]["queue"] == []
        assert v.last_accepted(7, "journal") == "J1"
        assert v.outcome(8, "journal")[0] == "accepted"
        assert v.sealed(9) == ["J3", J + "b"]

    histories.append(run(h, nothing_queued))

    both_keys = successor(G, keys=[key("owner2")], collections=[
        collection("journal", [prefix(J)], [key("journal"), key("journal2")]), STORE])
    h = History("one inner Catalog signed by two keys, both queued",
                "R lists journal and journal2 for the journal. Inside the window J2 is queued under the journal key "
                "and J2b, the same inner object signed by journal2, under journal2: one Catalog ID in two Envelopes. "
                "X, a follower that removes journal2, is sealed at height 3, the Epoch of settlement. Both survive "
                "settlement, which precedes X, and the one queued first, J2 under the journal key, becomes the last "
                "accepted Catalog; judged under X it is valid and sealed with b.")
    pa, pb = page(J + "a"), page(J + "b")
    h.cat("J1", [pa], T0 + 4 * MINUTE, "journal")
    start = opened(h, both_keys, {"journal": "J1"})
    j2 = h.cat("J2", [pa, pb], h.at(4 * MINUTE), "journal")
    h.add("J2b", j2.signed_by("journal2"))
    h.declare("X", "owner2", successor(both_keys, collections=[JOURNAL, STORE]))
    h.pull(5 * MINUTE, "R", {"journal": "J2"})
    h.pull(10 * MINUTE, "R", {"journal": "J2b"})
    h.pull(15 * MINUTE, "X", {})
    h.epoch("X", sealed_at=start + 7 * DAY)

    def first_queued(v):
        assert [(q["key"], q["catalog"]) for q in v.expected[6]["state"]["queue"]] == [
            ("journal", j2.id), ("journal2", j2.id)]
        settled = {s["key"]: s["outcome"] for s in v.expected[8]["settlement"]}
        assert settled == {"journal": "survivor", "journal2": "not_latest"}
        assert v.sealed(8)[1:] == [J + "b"] and v.expected[8]["sealed"][0]["catalog"] == j2.id and v.left(8) == []
        body = next(e["body"] for e in v.expected[8]["entries"] if e["type"] == "publisher_catalog")
        assert body["sig"]["key_id"] == KID["journal"]

    histories.append(run(h, first_queued))

    h = History("two Catalogs of one Collection queued between the discovery and the sealing of a recovery rotation",
                "At pull 1 the Aggregator discovers R, which replaces the journal key by journal2, and queues J1, "
                "signed by journal2, which R alone lists. At pull 2 J2, signed by the journal key, which G alone "
                "lists, with a later instant, is read against the floor and the queued Catalog of its own key and "
                "queued beside J1. Height 1 seals R. At settlement, height 2, J2 fails C1 under R (WIST1-E13) and "
                "J1, the Catalog under R's key, survives and is sealed with its Items.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", removing)
    h.epoch("G")
    pa, pb = page(J + "a"), page(J + "b")
    h.cat("J1", [pa], h.at(4 * MINUTE), "journal2")
    h.cat("J2", [pa, pb], h.at(8 * MINUTE), "journal")
    h.pull(5 * MINUTE, "R", {"journal": "J1"})
    h.pull(10 * MINUTE, "R", {"journal": "J2"})
    h.epoch("R")
    start = h.last
    h.epoch(sealed_at=start + 7 * DAY)

    def both_queued(v):
        assert v.catalog(1, "journal")["sources"] == ["R"] and v.catalog(2, "journal")["sources"] == ["G"]
        assert [(q["key"], v.ids[q["catalog"]]) for q in v.expected[2]["state"]["queue"]] == [
            ("journal2", "J1"), ("journal", "J2")]
        settled = {v.ids[s["catalog"]]: s["outcome"] for s in v.expected[4]["settlement"]}
        assert settled == {"J1": "survivor", "J2": "WIST1-E13"}
        assert v.sealed(4) == ["J1", J + "a"]

    histories.append(run(h, both_queued))

    long_scope = successor(G, keys=[key("owner2")], collections=[
        collection("journal", [prefix(J)] + [exact(f"{J}e{i:02d}") for i in range(35)], [key("journal2")]), STORE])
    h = History("a recovery rotation that fails at its candidate Epoch settles the queue at that Epoch",
                "scope_entries_max is 40 at height 0 and the pull after it and 32 from height 1. At pull 1 the "
                "Aggregator discovers R, a recovery rotation whose journal Scope has 36 entries, and queues J1, "
                "signed by journal2, which R alone lists, and S1, signed by the store key. At height 1 R fails "
                "WIST1-E16 under 32 and leaves the eligible sealing set unsealed: the queue is settled at that Epoch "
                "under G, the Declaration then current, with its sealed_at as the clock. J1 is rejected (WIST1-E13) "
                "and S1 survives and is sealed with s at height 1. Pull 2 is a pull outside a window under G alone: "
                "J1 served again is judged as any other Catalog and refused (WIST1-E02).", scope_entries_max=40)
    h.declare("G", "owner", G)
    h.declare("R", "recovery", long_scope)
    h.epoch("G")
    h.cat("J1", [page(J + "a")], h.at(4 * MINUTE), "journal2")
    h.cat("S1", [page(S + "s")], h.at(4 * MINUTE), "store", "store")
    h.pull(5 * MINUTE, "R", {"journal": "J1", "store": "S1"})
    h.epoch("R", scope_entries_max=32)
    h.pull(5 * MINUTE, "G", {"journal": "J1"})

    def failed_owner(v):
        assert v.expected[1]["declaration"]["sources"] == ["G", "R"]
        assert [v.ids[q["catalog"]] for q in v.expected[1]["state"]["queue"]] == ["J1", "S1"]
        assert v.expected[2]["declarations_failed"] == [{"declaration": "R", "code": "WIST1-E16"}]
        settled = {v.ids[s["catalog"]]: s for s in v.expected[2]["settlement"]}
        assert settled["J1"]["outcome"] == "WIST1-E13" and settled["S1"]["outcome"] == "survivor"
        assert v.sealed(2) == ["S1", S + "s"] and v.expected[2]["state"]["queue"] == []
        d = v.expected[3]["declaration"]
        assert d["outcome"] == "idempotent" and d["sources"] == ["G"] and d["window"] is False
        assert v.outcome(3, "journal") == ("refused", ["WIST1-E02"])

    histories.append(run(h, failed_owner))

    h = History("a queued Catalog and a later one of equal instant under the same key",
                "Inside the window J2, signed by the journal key, is queued. J2e, another list signed by the same "
                "key with J2's generated_at, is WIST2-E05 against the queued Catalog of its name and key, which "
                "stays queued and is sealed at settlement with b.")
    pa, pb, pc = page(J + "a"), page(J + "b"), page(J + "c")
    h.cat("J1", [pa], T0 + 4 * MINUTE, "journal")
    start = opened(h, keeping, {"journal": "J1"})
    j2 = h.cat("J2", [pa, pb], h.at(4 * MINUTE), "journal")
    h.cat("J2e", [pa, pc], seconds(j2.inner["generated_at"]), "journal")
    h.pull(5 * MINUTE, "R", {"journal": "J2"})
    h.pull(10 * MINUTE, "R", {"journal": "J2e"})
    h.epoch(sealed_at=start + 7 * DAY)

    def equal_instant(v):
        assert v.outcome(6, "journal") == ("refused", ["WIST2-E05"])
        assert [v.ids[q["catalog"]] for q in v.expected[6]["state"]["queue"]] == ["J2"]
        assert v.sealed(7) == ["J2", J + "b"]

    histories.append(run(h, equal_instant))

    h = History("a Catalog that waited at the opening and one queued after the discovery share a Catalog ID",
                "R lists journal and journal2 for the journal. J0, signed by the journal key, is accepted at pull 1 "
                "and waits. At pull 2, which discovers R, J0b, J0's inner object signed by journal2, is not an "
                "idempotent re-serve, since another key signed it, and is queued under journal2 with that pull's "
                "place. Height 1 seals R and queues J0 under the journal key with the place it had, the earlier. "
                "At settlement both survive with one Catalog ID, and the one of the earliest place, J0 under the "
                "journal key, becomes the last accepted Catalog and is sealed.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", both_keys)
    h.epoch("G")
    pa = page(J + "a")
    j0 = h.cat("J0", [pa], h.at(4 * MINUTE), "journal")
    h.add("J0b", j0.signed_by("journal2"))
    h.pull(5 * MINUTE, "G", {"journal": "J0"})
    h.pull(10 * MINUTE, "R", {"journal": "J0b"})
    h.epoch("R")
    start = h.last
    h.epoch(sealed_at=start + 7 * DAY)

    def shared_id(v):
        assert v.outcome(2, "journal")[0] == "accepted" and v.catalog(2, "journal")["queued"] is True
        assert [(q["key"], q["place"]) for q in v.expected[3]["state"]["queue"]] == [
            ("journal", [1, 0]), ("journal2", [2, 0])]
        assert {s["key"]: s["outcome"] for s in v.expected[4]["settlement"]} == {
            "journal": "survivor", "journal2": "not_latest"}
        body = next(e["body"] for e in v.expected[4]["entries"] if e["type"] == "publisher_catalog")
        assert body["sig"]["key_id"] == KID["journal"]

    histories.append(run(h, shared_id))

    h = History("a base queued inside a window",
                "J1's a and b are sealed at height 1. About 180 days later R opens a window, inside which J2, a and "
                "b unchanged with c, more than 180 days after the floor, is a base against it and is queued. A "
                "queued Catalog begins no reading of I7 against no record: a and b are judged against the records "
                "and admitted as their records' Items, and nothing is held for them. At settlement J2 becomes the "
                "last accepted Catalog and I7 is read against no record: a, b and c wait, and height 3 seals J2, "
                "which removes the records, and the three Items.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", keeping)
    h.epoch("G")
    pa, pb, pc = page(J + "a"), page(J + "b"), page(J + "c")
    j1 = h.cat("J1", [pa, pb], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    floor = seconds(j1.inner["generated_at"])
    h.last = floor + items.REMOVAL_RETENTION_DAYS * DAY
    h.pull(1 * MINUTE, "R", {})
    h.epoch("R")
    start = h.last
    h.cat("J2", [pa, pb, pc], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "R", {"journal": "J2"})
    h.epoch(sealed_at=start + 7 * DAY)

    def queued_base(v):
        found = v.catalog(5, "journal")
        assert found["base"] is True and found["queued"] is True
        got = v.items(5, "journal")
        assert got[J + "a"]["payload"] == "record" and got[J + "b"]["payload"] == "record"
        assert v.urls(5) == {}
        assert set(v.sealed(6)) == {"J2", J + "a", J + "b", J + "c"}
        assert [r["cause"] for r in v.expected[6]["records_removed"]] == ["base", "base"]

    histories.append(run(h, queued_base))

    h = History("the order of a pull before the window opens, against the waiting Catalog of the same key",
                "J0, signed by the journal key, is accepted at pull 1 and waits. At pull 2 the Aggregator discovers "
                "R. J1, signed by the same key with J0's instant and another Catalog ID, is WIST2-E05 against the "
                "Catalog that waits for the journal, which stays. At pull 3 J2, signed by the same key with a later "
                "instant, is queued. Height 1 seals R and opens the window: J0 is not queued, since J2, of its name "
                "and key with a later instant, is queued already and stays, and the journal's Catalog takes the "
                "earliest place among the Catalogs queued under its name and the one that waited for it when the "
                "window opened, kept out of the queue included: J0's. Height 2 settles and seals J2.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", keeping)
    h.epoch("G")
    pa, pb, pc = page(J + "a"), page(J + "b"), page(J + "c")
    j0 = h.cat("J0", [pa], h.at(4 * MINUTE), "journal")
    h.cat("J1", [pa, pb], seconds(j0.inner["generated_at"]), "journal")
    h.cat("J2", [pa, pc], h.at(12 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J0"})
    h.pull(10 * MINUTE, "R", {"journal": "J1"})
    h.pull(15 * MINUTE, "R", {"journal": "J2"})
    h.epoch("R")
    start = h.last
    h.epoch(sealed_at=start + 7 * DAY)

    def before_opening(v):
        assert v.outcome(2, "journal") == ("refused", ["WIST2-E05"]) and v.last_accepted(2, "journal") == "J0"
        assert [v.ids[q["catalog"]] for q in v.expected[3]["state"]["queue"]] == ["J2"]
        assert [(v.ids[q["catalog"]], q["first_place"]) for q in v.expected[4]["state"]["queue"]] == [
            ("J2", [1, 0])]
        assert v.sealed(5)[0] == "J2" and v.urls(4)[J + "a"]["place"] == [1, 0, 0]

    histories.append(run(h, before_opening))

    long_competitor = successor(keeping, keys=[key("fresh")], collections=[
        collection("journal", [prefix(J)] + [exact(f"{J}e{i:02d}") for i in range(35)], [key("journal")]), STORE])
    h = History("a competitor that fails at its candidate Epoch while a follower is current",
                "Inside R's window the Aggregator accepts C, a competitor naming R whose journal Scope has 36 entries, "
                "under scope_entries_max 40, and then F, a follower naming R that drops the store and so reduces "
                "authority, which becomes current. At height 3, under 32, C fails WIST1-E16 and leaves the eligible "
                "sealing set: the admission state is that of the Declarations that remain, applied in the order of "
                "their acceptance, so F stays current. F served again is an idempotent re-serve under the two frozen "
                "sources, and C served again, at a pull whose map has scope_entries_max 40 so that its counts pass, "
                "is WIST1-E08.", scope_entries_max=40)
    start = opened(h, keeping)
    h.declare("C", "fresh", long_competitor)
    h.declare("F", "owner2", successor(keeping, seq=3, collections=[JOURNAL]))
    h.pull(5 * MINUTE, "C", {})
    h.pull(10 * MINUTE, "F", {})
    h.epoch("C", scope_entries_max=32)
    h.pull(5 * MINUTE, "F", {})
    h.pull(10 * MINUTE, "C", {}, parameters={"scope_entries_max": 40})

    def competitor_fails(v):
        assert v.expected[3]["declaration"]["outcome"] == "in_window_competitor"
        assert v.expected[4]["declaration"]["outcome"] == "in_window_chain"
        assert v.expected[5]["declarations_failed"] == [{"declaration": "C", "code": "WIST1-E16"}]
        assert v.expected[6]["declaration"]["outcome"] == "idempotent"
        assert v.expected[6]["declaration"]["sources"] == ["G", "R"]
        assert v.expected[7]["declaration"]["outcome"] == "WIST1-E08"

    histories.append(run(h, competitor_fails))

    h = History("a queue settled when the rotation fails keeps what waited at the discovery",
                "scope_entries_max is 40 until height 2 and 32 at height 3. J0 is accepted at pull 1 and waits with "
                "a, eligible for height 1 with ceiling 5. At pull 2 the Aggregator discovers R, a recovery rotation "
                "whose journal Scope has 36 entries, and queues S1 with s. R reduces authority, so heights 1 and 2 "
                "seal nothing of example.com. At height 3 R fails WIST1-E16, and the queue is settled at that "
                "Epoch: J0 and a, which waited at the discovery, keep eligibility Epoch 1 and ceiling 5, and S1 and "
                "s, queued from the discovery, are eligible for height 3, the first Epoch not sealed before the "
                "event. All four are sealed there.", scope_entries_max=40)
    h.declare("G", "owner", G)
    h.declare("R", "recovery", long_scope)
    h.epoch("G")
    h.cat("J0", [page(J + "a")], h.at(4 * MINUTE), "journal")
    h.cat("S1", [page(S + "s")], h.at(8 * MINUTE), "store", "store")
    h.pull(5 * MINUTE, "G", {"journal": "J0"})
    h.pull(10 * MINUTE, "R", {"store": "S1"})
    h.epoch()
    h.epoch()
    h.epoch("R", scope_entries_max=32)

    def kept_eligibility(v):
        assert v.held(3) == {"J0": ["authority_reduction"], J + "a": ["authority_reduction"]}
        assert v.expected[5]["declarations_failed"] == [{"declaration": "R", "code": "WIST1-E16"}]
        assert v.eligibility(5) == {"J0": (1, 5), "S1": (3, 7), J + "a": (1, 5), S + "s": (3, 7)}

    histories.append(run(h, kept_eligibility))

    adds_journal2 = successor(G, collections=[collection("journal", [prefix(J)], [key("journal"), key("journal2")]),
                                              STORE])
    h = History("a queued Catalog not later than the floor at settlement does not survive",
                "J1 is sealed with a at height 1. J2 waits from pull 2 under the journal key. At pull 3 the Aggregator "
                "discovers R, a recovery rotation that adds journal2 and reduces no authority, and queues J3, signed "
                "by journal2, with an instant between J1's and J2's: it is read against the floor, J1's, and against "
                "no Catalog of its key. R is sealed at height 3, later than its discovery allows a Declaration that "
                "reduces no authority to wait, since no publication of the pull that read it is sealed before "
                "settlement; height 2 seals J2, a Catalog that waited at the discovery, in its turn, and the floor "
                "moves to J2's instant. At settlement, height 4, J3 is not later than the floor and does not survive "
                "(WIST2-E05); the journal's last accepted Catalog is J2.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", adds_journal2)
    h.epoch("G")
    pa, pb, pc = page(J + "a"), page(J + "b"), page(J + "c")
    j1 = h.cat("J1", [pa], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    h.cat("J2", [pa, pb], h.at(4 * MINUTE), "journal")
    h.cat("J3", [pa, pc], seconds(j1.inner["generated_at"]) + 30 * MINUTE, "journal2")
    h.pull(5 * MINUTE, "G", {"journal": "J2"})
    h.pull(10 * MINUTE, "R", {"journal": "J3"})
    h.epoch(late=("R",))
    h.epoch("R")
    start = h.last
    h.epoch(sealed_at=start + 7 * DAY)

    def not_later(v):
        assert v.catalog(4, "journal")["queued"] is True
        assert v.sealed(5) == ["J2", J + "b"]
        assert {v.ids[s["catalog"]]: s["outcome"] for s in v.expected[7]["settlement"]} == {"J3": "WIST2-E05"}
        assert v.last_accepted(7, "journal") == "J2" and v.sealed(7) == []

    histories.append(run(h, not_later))

    h = History("a URL that did not wait at the opening takes the place of the pull that queued the survivor",
                "J0 is accepted at pull 1 and waits with a. At pull 2 the Aggregator discovers R and queues J1, "
                "listing a and c, under the same key with a later instant. At the opening J0 is not queued, and the "
                "journal's Catalog takes the earliest place, J0's. At the settlement at pull 3, J1 survives with "
                "that place; a keeps its own, and c, which did not wait when the window opened, takes the place of "
                "the pull that queued J1.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", keeping)
    h.epoch("G")
    pa, pc = page(J + "a"), page(J + "c")
    h.cat("J0", [pa], h.at(4 * MINUTE), "journal")
    j1 = h.cat("J1", [pa, pc], h.at(8 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J0"})
    h.pull(10 * MINUTE, "R", {"journal": "J1"})
    h.epoch("R")
    start = h.last
    h.last = start + 7 * DAY
    h.pull(5 * MINUTE, "R", {})

    def survivor_place(v):
        assert v.collection(4, "journal")["waiting"]["place"] == [1, 0]
        urls = v.urls(4)
        assert urls[J + "a"]["place"] == [1, 0, 0]
        assert urls[J + "c"]["place"] == [2, 0, [i["url"] for i in j1.listed].index(J + "c")]

    histories.append(run(h, survivor_place))

    def ordered(first, second, third):
        for i in range(400):
            for j in range(400):
                for k in range(400):
                    u, w, x = f"{J}{first}{i}", f"{J}{second}{j}", f"{J}{third}{k}"
                    if items.item_key(x) < items.item_key(u) < items.item_key(w):
                        return u, w, x
        raise AssertionError

    ua, uu, uj = ordered("a", "u", "j")
    h = History("a pull that settles is two events, the settlement first",
                "J1 lists a and u; u's Payload is unavailable at pull 1, and height 1 seals J1 and a. R opens a "
                "window at height 2; inside it J1 served again admits u, which takes no place. Pull 5, after the "
                "window's end, settles first: u begins to wait at the settlement and takes its place there. Then, as "
                "a second event, the pull accepts J3, listing a, u and j, whose key is the smallest of the three: j "
                "takes its place at the pull, after u's, although j comes first in the list. With "
                "domain_epoch_entries_max 2, height 3 seals J3 and u and leaves j for height 4.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", keeping)
    h.epoch("G")
    pa, pu, pj = page(ua), page(uu), page(uj)
    h.cat("J1", [pa, pu], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"}, withhold=(uu,))
    h.epoch()
    h.pull(5 * MINUTE, "R", {})
    h.epoch("R")
    start = h.last
    h.pull(5 * MINUTE, "R", {"journal": "J1"})
    h.cat("J3", [pa, pu, pj], start + 7 * DAY + 4 * MINUTE, "journal")
    h.last = start + 7 * DAY
    h.pull(5 * MINUTE, "R", {"journal": "J3"})
    h.epoch(domain_epoch_entries_max=2)
    h.epoch(domain_epoch_entries_max=2)

    def two_events(v):
        assert v.items(5, "journal")[uu]["outcome"] == "admitted" and uu not in v.urls(5)
        urls = v.urls(6)
        assert urls[uu]["place"][0] == 6 and urls[uj]["place"][0] == 7
        assert urls[uj]["place"][2] < urls[uu]["place"][2]
        assert v.sealed(7) == ["J3", uu] and v.sealed(8) == [uj]

    histories.append(run(h, two_events))

    stores_first_follower = successor(keeping, collections=[
        collection("store", [prefix(S)], [key("store", exp=T0 + 400 * DAY)]), JOURNAL])
    h = History("the order of Collections at a settlement made by a pull",
                "J1 lists a and u and S1 lists b and s; the Payloads of u and s are unavailable at pull 1, and height "
                "1 seals J1, S1, a and b. R opens a window at height 2. Inside it J1 and S1 served again admit u and "
                "s, which take no place, and the Aggregator accepts F, a follower naming R that lists store before "
                "journal and reduces authority, so it is not sealed. At pull 6, after the window's end, the "
                "settlement reads the order of Collections from the Declaration it leaves current at admission, F: "
                "s, of the store, takes the earlier place, although R lists journal first.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", keeping)
    h.declare("F", "owner2", stores_first_follower)
    h.epoch("G")
    pa, pu, pb, ps = page(J + "a"), page(J + "u"), page(S + "b"), page(S + "s")
    h.cat("J1", [pa, pu], h.at(4 * MINUTE), "journal")
    h.cat("S1", [pb, ps], h.at(4 * MINUTE), "store", "store")
    h.pull(5 * MINUTE, "G", {"journal": "J1", "store": "S1"}, withhold=(J + "u", S + "s"))
    h.epoch()
    h.pull(5 * MINUTE, "R", {})
    h.epoch("R")
    start = h.last
    h.pull(5 * MINUTE, "R", {"journal": "J1", "store": "S1"})
    h.pull(10 * MINUTE, "F", {})
    h.last = start + 7 * DAY
    h.pull(5 * MINUTE, "F", {})

    def follower_order(v):
        assert v.expected[6]["declaration"]["outcome"] == "in_window_chain"
        urls = v.urls(7)
        assert urls[S + "s"]["place"][1] == 0 and urls[J + "u"]["place"][1] == 1

    histories.append(run(h, follower_order))

    h = History("an Item held inside a window is reported with the window alone",
                "J1 lists a and b; b's Payload is unavailable at pull 1, and height 1 seals J1 and a. Pull 2 serves "
                "J1 again with b's Payload, and b waits. R, sealed at height 2, replaces the journal key, so J1 "
                "fails I4 under R; the window holds b. At heights 2, 3 and 4, inside the window, b is reported with "
                "the window alone.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", removing)
    h.epoch("G")
    h.cat("J1", [page(J + "a"), page(J + "b")], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"}, withhold=(J + "b",))
    h.epoch()
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.pull(10 * MINUTE, "R", {})
    h.epoch("R")
    h.epoch()
    h.epoch()

    def window_alone(v):
        for event in (5, 6, 7):
            assert v.deferred(event) == {J + "b": ["recovery_window"]}

    histories.append(run(h, window_alone))

    h = History("an Item admitted at a pull from the discovery takes its place at the next Epoch",
                "J0 lists a and u and waits from pull 1, where u's Payload is unavailable. At pull 2 the Aggregator "
                "discovers R, and J0 served again with u's Payload is an idempotent re-serve that admits u; no URL "
                "takes a place at that pull. Height 1 seals R: u takes its place at that Epoch, before the window "
                "opens and holds it.")
    h.declare("G", "owner", G)
    h.declare("R", "recovery", keeping)
    h.epoch("G")
    j0 = h.cat("J0", [page(J + "a"), page(J + "u")], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J0"}, withhold=(J + "u",))
    h.pull(10 * MINUTE, "R", {"journal": "J0"})
    h.epoch("R")

    def next_epoch(v):
        assert v.outcome(2, "journal")[0] == "idempotent" and v.items(2, "journal")[J + "u"]["outcome"] == "admitted"
        assert J + "u" not in v.urls(2)
        assert v.urls(3)[J + "u"]["place"] == [3, 0, [i["url"] for i in j0.listed].index(J + "u")]

    histories.append(run(h, next_epoch))

    return {"note": NOTE_COMMON + (
        " This file exercises ADR-0052 Recovery: the queue a pull fills inside an open recovery window from the two "
        "frozen sources of WIST-1 section 5.2 (the Declaration in effect before the recovery and the recovery "
        "Declaration that owns the window, each read alone, whatever follower the opening Epoch seals; a pull "
        "between the discovery and the sealing of a recovery rotation reads them too and queues as well), one "
        "Catalog per Collection name and signing "
        "key with the pull order read against the floor and the queued Catalog of the same name and key, and "
        "settlement, once, at the first event at or after the window's end: a pull, which settles before it reads "
        "anything, with its own instant as the clock and its own parameter map, and is then a pull outside a "
        "window; or the Epoch of settlement, before any of its Declarations applies, with its sealed_at and its "
        "map. Every queued Catalog is judged by C1 under the settlement source (the last recovery-chain Declaration "
        "sealed before that event); `settlement`, on the event that settles, lists every queued Catalog in the order "
        "of its place, then of its key, with `survivor` for the one that becomes the last accepted Catalog of its "
        "name (the latest in the order of Several Logs, generated_at then the greater Catalog ID, and among "
        "survivors of that Catalog ID the one of the earliest place), `not_latest` for every other survivor, WIST2-E05 for a Catalog whose "
        "generated_at is not later than the floor of its name at that event, which does not survive, or WIST1-E13 "
        "with `condition_code`, the Catalog condition met. Where no Catalog of a name survives, a name with nothing "
        "queued included, the last accepted Catalog is the latest Catalog. What then waits is eligible for the next "
        "Epoch. A fetched Catalog whose generated_at is at or before that of the queued Catalog of its name and "
        "signing key, or, before the window opens, of the Catalog that waits for its Collection under the same "
        "key, and whose Catalog ID differs, is WIST2-E05 and that Catalog stays; one with the Catalog ID of a "
        "queued or waiting Catalog signed by another key is no idempotent re-serve and is queued under its own "
        "key. A Catalog that waited when the window opened is not queued where a Catalog of its name and key with "
        "a later instant is queued already; the Collection's Catalog takes the earliest place among the Catalogs "
        "queued under its name and the one that waited for it when the window opened, those a later Catalog of "
        "their key replaced or kept out of the queue included. A queued Catalog has the place of the pull that queued it, before or inside the window, and one that "
        "waited when the window opened the place it had; a Collection's surviving Catalog takes the earliest "
        "place among the Catalogs queued under its name (`first_place`), and every other URL the place of the "
        "surviving Catalog, or of the settlement where no Catalog of its name survived; a URL that waited when "
        "the window opened and waits at settlement keeps its place. `key` names the test key whose kid is that of the binding candidate under which the Catalog "
        "verified."),
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

    only_new = successor(G, collections=[collection("journal", [prefix(J + "new/")], [key("journal")]), STORE])
    wide_again = successor(only_new, collections=[JOURNAL, STORE])
    h = History("a withdrawn Item that a later list names",
                "J1 lists new/a and old/x, sealed at height 1. A payload_withdrawal of x is sealed at height 2 and the "
                "Aggregator destroys x's Payload. D1, sealed at height 3, narrows the journal to new/ and removes x's "
                "record; D2, sealed at height 4, widens it again, and x does not wait, since I7 fails for a withdrawn "
                "Item. J2, accepted at pull 4, still names x: x is not admitted and is reported with WIST2-E03, and "
                "its Payload, which the site still serves, is not fetched, although x is no longer its URL's record's "
                "Item. Height 5 seals J2 and new/b alone.")
    h.declare("G", "owner", G)
    h.declare("D1", "owner", only_new)
    h.declare("D2", "owner", wide_again)
    h.epoch("G")
    pa, px, pb = page(J + "new/a"), page(J + "old/x"), page(J + "new/b")
    h.cat("J1", [pa, px], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    h.withdraw("withdrawal of x", px)
    h.epoch(updates=["withdrawal of x"])
    h.pull(5 * MINUTE, "D1", {"journal": "J1"})
    h.epoch("D1")
    h.pull(5 * MINUTE, "D2", {"journal": "J1"})
    h.epoch("D2")
    h.cat("J2", [pa, px, pb], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "D2", {"journal": "J2"})
    h.epoch()

    def withdrawn(v):
        assert v.sealed(2) == ["J1"] + [i["url"] for i in items.in_list_order([pa, px])]
        assert any(e["type"] == "registry_update" for e in v.expected[3]["entries"])
        assert v.expected[5]["records_removed"] == [{"publisher": "example.com", "url": J + "old/x",
                                                     "cause": "narrowing"}]
        assert J + "old/x" not in v.urls(5) and J + "old/x" not in v.urls(7)
        got = v.items(8, "journal")[J + "old/x"]
        assert got["outcome"] == "not_admitted" and got["codes"] == ["WIST2-E03"] and got["payload"] == "withdrawn"
        assert v.sealed(9) == ["J2", J + "new/b"]

    histories.append(run(h, withdrawn))

    h = History("an Item whose Payload fails a cap amended before its candidate Epoch",
                "J1 lists a and x, whose extract is 20 000 octets of JCS. At pull 1, under extract_cap_bytes 32 768, "
                "x's Payload is fetched and verifies, and x is admitted. The map in force at height 1 amends "
                "extract_cap_bytes to 16 384: x still meets every Item condition, but its Payload, checked again "
                "under that map before sealing, fails (WIST1-E04), so x is not sealed, is no longer admitted and is "
                "reported with WIST2-E03. J1 and a are sealed.")
    h.declare("G", "owner", G)
    h.epoch("G")
    pa, px = page(J + "a"), page(J + "x", extract="x" * 19998)
    assert len(items.jcs(PAYLOADS[items.item_id(px)]["content"]["extract"])) == 20000
    h.cat("J1", [pa, px], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch(extract_cap_bytes=16384)

    def amended_cap(v):
        assert v.items(1, "journal")[J + "x"]["payload"] == "fetched"
        assert v.sealed(2) == ["J1", J + "a"]
        assert v.left(2) == [(J + "x", "payload", ["WIST2-E03"], True)]
        assert v.expected[2]["left"][0]["payload_code"] == "WIST1-E04"
        assert v.urls(2) == {}

    histories.append(run(h, amended_cap))

    h = History("a record's Item that waits under a base and whose Payload fails an amended cap",
                "J1 lists a and x, whose extract is 20 000 octets of JCS, sealed at height 1. J2, the same list with "
                "b added more than 180 days after the floor, is a base: from pull 2 I7 is read for the journal "
                "against no record, so x waits although it is its record's Item, admitted without a Payload check. "
                "The map of height 2 amends extract_cap_bytes to 16 384: the base removes the records, a and b are "
                "sealed, and x, whose held Payload is checked at its turn under that map and fails (WIST1-E04), is "
                "not sealed, is no longer admitted and is reported with WIST2-E03.")
    h.declare("G", "owner", G)
    h.epoch("G")
    pa, px, pb = page(J + "a"), page(J + "big/x", extract="y" * 19998), page(J + "b")
    j1 = h.cat("J1", [pa, px], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    later = seconds(j1.inner["generated_at"]) + items.REMOVAL_RETENTION_DAYS * DAY + 1
    h.cat("J2", [pa, px, pb], later, "journal")
    h.last = later
    h.pull(1 * MINUTE, "G", {"journal": "J2"})
    h.epoch(sealed_at=later + 10 * MINUTE, extract_cap_bytes=16384)

    def record_payload(v):
        assert v.catalog(3, "journal")["base"] is True
        assert v.items(3, "journal")[J + "big/x"]["payload"] == "record" and J + "big/x" in v.urls(3)
        assert set(v.sealed(4)) == {"J2", J + "a", J + "b"}
        assert v.left(4) == [(J + "big/x", "payload", ["WIST2-E03"], True)]
        assert v.expected[4]["left"][0]["payload_code"] == "WIST1-E04"

    histories.append(run(h, record_payload))

    h = History("a Payload not held at the Item's turn",
                "J1's n/a and o/x are sealed at height 1. D1, sealed at height 2, narrows the journal to n/ and "
                "removes x's record, and x begins to wait there. Height 3 seals D2, which widens the journal again, "
                "and a payload_withdrawal of x, which meets its contract since x was sealed at height 1. The "
                "Aggregator destroys x's Payload from that Epoch, so at x's turn it holds none: x is not sealed, is "
                "no longer admitted and is reported with WIST2-E03, although I7, which reads withdrawals sealed "
                "below the Epoch, would hold.")
    h.declare("G", "owner", G)
    h.declare("D1", "owner", only_new)
    h.declare("D2", "owner", wide_again)
    h.epoch("G")
    pa, px = page(J + "new/a"), page(J + "old/x")
    h.cat("J1", [pa, px], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    h.pull(5 * MINUTE, "D1", {"journal": "J1"})
    h.epoch("D1")
    h.pull(5 * MINUTE, "D2", {"journal": "J1"})
    h.withdraw("withdrawal of x", px)
    h.epoch("D2", updates=["withdrawal of x"])

    def not_held(v):
        assert J + "old/x" in v.urls(4)
        assert v.sealed(6) == [] and v.left(6) == [(J + "old/x", "payload", ["WIST2-E03"], True)]
        assert v.expected[6]["left"][0].get("payload_code") is None

    histories.append(run(h, not_held))

    h = History("a withdrawal that breaks its contract is not sealed",
                "As in the previous history, x begins to wait at height 2, and height 3 is to seal D2 with a "
                "payload_withdrawal naming x, but its subject is blog.example.com, not the Publisher of the Catalog x "
                "was sealed against. The act breaks its contract: the Aggregator does not seal it and reports it with "
                "WIST4-E04, destroys no Payload, and seals x, whose Payload it holds at its turn.")
    h.declare("G", "owner", G)
    h.declare("D1", "owner", only_new)
    h.declare("D2", "owner", wide_again)
    h.epoch("G")
    pa, px = page(J + "new/a"), page(J + "old/x")
    h.cat("J1", [pa, px], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    h.pull(5 * MINUTE, "D1", {"journal": "J1"})
    h.epoch("D1")
    h.pull(5 * MINUTE, "D2", {"journal": "J1"})
    h.withdraw("withdrawal of x under another subject", px)
    h.updates["withdrawal of x under another subject"] = sign("log", "update", {
        **h.updates["withdrawal of x under another subject"]["update"], "subject": BLOG})
    h.epoch("D2", updates=["withdrawal of x under another subject"])

    def not_sealed(v):
        assert v.expected[6]["updates_refused"] == [{"delta_id": items.item_id(px), "subject": BLOG,
                                                     "code": "WIST4-E04"}]
        assert all(e["type"] != "registry_update" for e in v.expected[6]["entries"])
        assert v.sealed(6) == [J + "old/x"] and v.left(6) == []

    histories.append(run(h, not_sealed))

    h = History("a withdrawn Item that also fails an Item condition",
                "J1's new/a and old/x are sealed at height 1 and a payload_withdrawal of x at height 2. D1, sealed at "
                "height 3, narrows the journal to new/ and removes x's record. J2, accepted at pull 3 under D1, still "
                "names x, now outside the Scope as well: the withdrawal is read before the Item conditions other "
                "than form, so x is not admitted and is reported with WIST2-E03, not refused with WIST1-E03.")
    h.declare("G", "owner", G)
    h.declare("D1", "owner", only_new)
    h.epoch("G")
    pa, px, pb = page(J + "new/a"), page(J + "old/x"), page(J + "new/b")
    h.cat("J1", [pa, px], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "G", {"journal": "J1"})
    h.epoch()
    h.withdraw("withdrawal of x", px)
    h.epoch(updates=["withdrawal of x"])
    h.pull(5 * MINUTE, "D1", {"journal": "J1"})
    h.epoch("D1")
    h.cat("J2", [pa, px, pb], h.at(4 * MINUTE), "journal")
    h.pull(5 * MINUTE, "D1", {"journal": "J2"})

    def withdrawal_first(v):
        got = v.items(6, "journal")[J + "old/x"]
        assert got["outcome"] == "not_admitted" and got["codes"] == ["WIST2-E03"] and got["payload"] == "withdrawn"

    histories.append(run(h, withdrawal_first))

    return {"note": NOTE_COMMON + (
        " This file exercises ADR-0051 Reaching the Log (the sources a pull reads, for each row of its table, and "
        "the Collections pulled in order; admission inside an open recovery window, each source read alone) and "
        "ADR-0052 Files (the admission of Items and their Payloads, WIST2-E03, and the retry of Items refused or "
        "not admitted at a pull that accepts a Catalog and at an idempotent re-serve)."),
        "keys": KEYS_MEMBER, "histories": histories}


NOTE_COMMON = (
    "An Aggregator that seals every Entry in the Epoch it is eligible for unless a deferral or the hold keeps it "
    "out, fed `events` in time order. Each history names its signed Declarations (`declarations`), its signed "
    "Catalog Envelopes (`catalogs`, with `catalog_ids`; two names share an ID where one inner object is signed "
    "twice), the octets of every tree file served, as UTF-8 text keyed by the 64 hexadecimal digits of their "
    "SHA-256 (`tree_files`), and, where present, `registry_updates`, payload_withdrawal Envelopes (WIST-3 section "
    "6.2, WIST-4 section 5.1) whose details.delta_id is an Item ID, signed by the test-only Log key and not "
    "authenticated by the replay. An `epoch` event gives height, sealed_at, the complete parameter map in force at "
    "it, the Declarations the Aggregator seals in it by name and, as `updates`, the registry updates it seals; "
    "Epochs are simplified to those and their Entries, with no Checkpoint and no Merkle tree of the Log, and the "
    "Aggregator plans the Catalog and Item Entries. A listed Declaration is checked again under the Epoch's map "
    "(ADR-0051 Size); one that fails is not sealed and leaves the eligible sealing set with every accepted "
    "Declaration that names it: `declarations_failed` gives it with the code of the check that failed and "
    "`declarations_left` those that named it, each with that code (each member present only when nonempty); the "
    "admission state is then that of the accepted Declarations that remain, applied in the order of their "
    "acceptance, a pending replacement a failed reversal had discarded included, and the sequence floor does not "
    "change, except that where none remains the domain returns to first contact with no floor. Every Declaration "
    "discovered at a pull that does not reduce authority and is still in the eligible sealing set is sealed in the "
    "next Epoch, which ADR-0051 requires of a prompt Aggregator, unless the epoch event lists it in "
    "`sealed_later`, which a history uses for a recovery rotation none of whose pulls' publications is sealed "
    "before settlement; one that reduces authority may be sealed later, at or below the last Epoch the earliest "
    "ceiling among its Publisher's waiting publications allows, and the fixture uses that to show the hold. The "
    "eligible sealing set loses a competitor accepted inside a window, and its descendants, at the settlement of "
    "that window at a pull or an Epoch; a pending replacement that a reversal discards stays in it and is sealed "
    "at or below the reversal's Epoch, its hold ending at the Epoch that seals it. A `pull` "
    "event gives its instant, which is the clock of the pull, the Publisher pulled, the parameter map in force at "
    "the pull (`parameters`), which its Declaration, Catalog, Item and Payload checks and a settlement it performs "
    "read, the Declaration served (null for a failed fetch) and, per Collection name, the Catalog served at "
    "catalog.json, the tree files served (by name, from `tree_files`) and the Payloads served, keyed by the digits "
    "of their Item ID. A Collection absent from `collections` has no catalog.json and a file absent from a pull is "
    "unavailable; there is no HTTP, these maps stand for the Publisher's site, and the octets of catalog.json are "
    "not modelled (its read bound is carried by vectors/wist1/catalog-fields.json). max_inclusion_epochs and "
    "record_seal_epochs are constant within each history. Every Canonical Host is its own capacity unit unless the "
    "history carries `suffix_list`, the rules of a Public Suffix List snapshot in force at every event, from which "
    "the Registrable Domain is derived as WIST-4 section 3.1 states; no history carries Labels, disputes or other "
    "registry updates. `expected` has one element per event. For a pull, `settlement` is empty unless the pull "
    "settles a queue (catalog-recovery.json), and `declaration` gives `outcome` (the served Declaration applied "
    "under WIST-1 section 5.2 after the Log's Declarations and those the Aggregator discovered that are still in "
    "the eligible sealing set: `initial`, `ordinary_rotation`, `recovery_rotation`, `fresh_identity_pending`, "
    "`pending_replacement`, `reversal_ordinary_rotation`, `in_window_chain`, `in_window_competitor`, `idempotent`, "
    "`recovery_chain_head` for the recovery-chain head of an open window served again, a success of the fetch, a "
    "rejection code, or `not_fetched`), `discovered`, `reduces_authority` against the Declaration it names (false "
    "unless discovered), `sources` (the Declarations the pull reads, as ADR-0051's table gives them: the two frozen "
    "sources, the Declaration in effect before the recovery and the recovery Declaration that owns the window or "
    "was discovered, inside an open window or for a recovery rotation discovered and not yet sealed, and otherwise "
    "the current Declaration) and `window`, whether the pull is inside an open window. A pull result carries `noise`, "
    "true, where the pull accepts no Declaration and no Catalog and admits no Item (WIST-2 section 4), and no "
    "`noise` otherwise. "
    "From the pull that discovers a recovery rotation, a pull queues what it accepts as a pull inside the window "
    "does, per Collection name and signing key, its order read against the floor, against the queued Catalog "
    "of the same name and key and, before the window opens, against the waiting Catalog where the same key signed "
    "it, and no URL takes a place at it; a queued Catalog is not the last accepted Catalog "
    "and replaces no waiting one until settlement makes it one, and it is not sealed before settlement, while a "
    "Catalog and Items that waited at the discovery keep waiting and are queued and held, with the places they "
    "had, when the window opens. Where the recovery rotation leaves the eligible sealing set unsealed, the queue, "
    "with what waits, is settled at that event under the Declaration then current in the Log, with the event's "
    "instant as the clock and its parameter map; what waited at the discovery keeps its place, eligibility "
    "Epoch and ceiling, what was queued from the discovery is eligible for the first Epoch not sealed before the "
    "event, and later pulls are pulls outside a window. `collections_pulled` lists the Collections in reading order. Per Collection "
    "pulled: a fetched Catalog is read first against the Catalog conditions other than the order; one that meets "
    "one is refused with its codes, replaces nothing and retries nothing, and only one that meets none is read "
    "for the order and for an idempotent re-serve. `outcome` (`unavailable`, `accepted`, `idempotent` for an "
    "idempotent re-serve, a Catalog with the "
    "Catalog ID of the last accepted Catalog or of the latest Catalog, or of the queued Catalog of its name and key "
    "inside a window, or `refused` with `codes`, those of every condition met, among which WIST-1 section 7 leaves "
    "the choice, and for WIST2-E07 a `reason` and, for a list that drops a held record's URL, `dropped`, the URL of "
    "every such record; an Item the list holds for the URL counts whether or not it is refused alone), `catalog` "
    "(its Catalog ID), `sources` under which it passed the Catalog conditions, `tree_files_fetched` (the files the "
    "walk requested because the Aggregator did not hold them, served or not, in ascending order; a file whose "
    "SHA-256 matches its name is then held), `base` (a base against the floor), `key` (the test key named by the "
    "kid of the binding candidate under which it verified), `queued` (inside a window) and `items`, each Item "
    "judged at the pull in list order: all Items of an accepted list, and at an idempotent re-serve those not "
    "admitted before, judged under the sources that accept the Catalog where the pull reads two sources and under "
    "the Declaration it reads otherwise; `outcome` is `admitted`, `not_admitted` (WIST2-E03) or `refused` (the "
    "Item condition codes under every source that accepts the Catalog), and `payload` says how an Item of kind "
    "page was admitted or failed: `withdrawn` (a payload_withdrawal sealed in the Log, meeting its contract, "
    "names its Item ID: not admitted and its Payload not fetched, read before every Item condition other than "
    "form), `record`, `held`, `fetched`, `unavailable`, or "
    "`failed` with `payload_code`; a held Payload is verified again under the pull's map. For an Epoch: "
    "`settlement`, `entries` in canonical order (WIST-3 section 3.3), `sealed` in capacity order with each Entry's "
    "eligibility Epoch and the last Epoch its ceiling allows, `left` (what left waiting at its turn, with the "
    "condition failed, its codes and whether it is reported at the status endpoint: `C1`, reported with the codes "
    "of C1 alone, whatever else the Catalog fails; `C4`, not "
    "reported; `I5`, reported; `I7`, for an Item for which I7 no longer holds once the Epoch's transitions and "
    "Catalogs have applied, not reported whatever other condition it fails; `payload`, for an Item of kind page, "
    "however it was admitted, whose held Payload, checked again at its turn when the capacity has room, under the "
    "Epoch's map, fails: not sealed, "
    "no longer admitted, reported with WIST2-E03 and `payload_code`), `deferred` (every waiting Catalog and URL "
    "whose eligibility Epoch had come, that was not sealed and to which a deferral applied, with the deferrals: "
    "`recovery_window`, alone inside a window, `catalog_waiting` for a URL whose waiting Catalog the capacity "
    "holds out, `latest_fails_i4`, which applies only while no Catalog of the Item's Collection waits that nothing "
    "defers, and `capacity` only where no other applied), `held` when nonempty (every such Catalog and "
    "URL to which no deferral applied and that the Epoch does not seal: `authority_reduction` while a Declaration "
    "of its Publisher that reduces authority is discovered, in the eligible sealing set and not sealed at or below "
    "the Epoch, and `catalog_waiting` for a URL whose waiting Catalog nothing defers and the Epoch does not seal) "
    "and `records_removed`. After every event `state` gives per Publisher and Collection name the latest Catalog, "
    "the last accepted Catalog and the waiting Catalog with its place, eligibility Epoch and ceiling; every waiting "
    "URL with its Collection, Item, place, eligibility Epoch and ceiling (null while a window holds it); the queue; "
    "the Declarations that reduce authority, discovered, in the eligible sealing set and not sealed; and the "
    "records. A place is [event index, position of the Collection] for a Catalog; event indices count a pull "
    "that settles a queue as two events, the settlement first, so they run one ahead of the positions in "
    "`expected` after such a pull, with the Item's index in the "
    "list appended for a URL. The position is that of the Collection among the Collections of the Declaration in "
    "force for the Publisher, a name that Declaration lacks coming after them in ascending octet order: at a pull "
    "the Declaration it reads Collections from, and with two sources the one in effect before the recovery; at an "
    "Epoch the one in force once its transitions have applied; at a settlement the one it leaves current, at a "
    "pull's settlement the admission head, unsealed followers included. Places "
    "compare by event index, then by the Publisher's Canonical Host in ascending octet order, then by position and "
    "list index. A URL that begins to wait at an Epoch or at a settlement takes that event's place. What takes a "
    "place is eligible for the Epoch after that event, a replacement that keeps a place keeps its eligibility "
    "Epoch, and each Epoch at which a deferral applies to it moves it to the following one; the hold and a waiting "
    "Catalog that nothing defers move none. The ceiling is the eligibility Epoch plus max_inclusion_epochs. A URL "
    "waits while its Item is admitted and I7 holds for it, an Item of kind page whose Item ID a sealed withdrawal "
    "names failing I7; where the last accepted Catalogs of two Collections of the Publisher each list an admitted "
    "Item for one URL that meets that row, the Item of the Collection whose Scope covers the URL under the "
    "Declaration in force (at an Epoch once its transitions have applied, at a pull the Log's) waits, and where "
    "no Scope covers it, that of the Catalog later in the order of Several Logs (generated_at, then Catalog ID); from the pull that accepts a base until it, or one that replaces it while it waits, is "
    "sealed or leaves, I7 is read for its Collection against no record; a queued Catalog begins no such reading "
    "until settlement makes it the last accepted Catalog. When a base fails C1 at its turn, the Items that are "
    "their URL's record's Items leave as Items for which I7 no longer holds, listed in `left` with `I7`, the "
    "codes of their judgment against the latest Catalog once the Epoch has applied, and not reported. The "
    "payload_withdrawal acts an Epoch seals that meet their contract through an Item sealed below that Epoch "
    "destroy their Payloads before its planning; the Aggregator seals no withdrawal that breaks its contract: "
    "one the Epoch lists is left out, destroys nothing and is reported in `updates_refused` with WIST4-E04 "
    "(present only when nonempty). An Item "
    "of kind page whose Payload is not held at its turn is treated as one whose Payload fails (`payload`, "
    "WIST2-E03, no `payload_code`). Deferrals are listed in the order window, capacity, waiting Catalog, latest "
    "Catalog failing I4. The planned Entries replay as valid under "
    "the rules of vectors/wist3/catalog-sealing.json, whose capacity check counts per Canonical Host. The fixture "
    "asserts nothing about an Aggregator that seals later within the ceiling, nor about Consumers, which cannot "
    "derive these rules from the Log. Keys derive from the stated test-only seeds.")


write_json(WIST3 / "catalog-waiting.json", waiting_vectors())
write_json(WIST1 / "catalog-recovery.json", recovery_vectors())
write_json(WIST2 / "collection-pull.json", pull_vectors())
print("waiting vectors written")
