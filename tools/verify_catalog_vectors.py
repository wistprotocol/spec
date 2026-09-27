import base64
import hashlib
import hmac
import json
import math
import pathlib
import re
import sys

import rfc8785

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from link_extraction import normalize_url
from verify_collection_vectors import (
    VerifierError, authority, b64u_canonical, b64u_encode, canonical_host, check_keys_block, collection_named,
    collection_names, entry_covers, log_seconds, log_timestamp, public_raw, publisher_instant, require_accepted,
    signature_verifies, strict_load, url_host, usable_public, DEFAULT_PARAMETERS)

ROOT = pathlib.Path(__file__).resolve().parent.parent

SAFE_INTEGER = 2 ** 53 - 1
REGISTRY_SIZE_CAPS = {"url_cap_bytes": 2048, "extract_cap_bytes": 32768, "links_cap_bytes": 4096,
                      "link_url_cap_bytes": 2048, "summary_cap_bytes": 2048}

VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
HASH = re.compile(r"sha256:[0-9a-f]{64}")
HEX64 = re.compile(r"[0-9a-f]{64}")
COMMITMENT = re.compile(r"hmac-sha256:[0-9a-f]{64}")
NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")
LANG = re.compile(r"[a-z]{2,3}(?:-[A-Za-z0-9]{1,8})*")
PAYLOAD_PATH = re.compile(r"/\.well-known/wist/collections/([^/]+)/payloads/([0-9a-f]{64})\.json")
HEX_DIGITS = "0123456789abcdef"
B64U_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

PAGE_MEMBERS = {"publisher", "url", "observed_at", "payload", "meta"}
REMOVED_MEMBERS = {"publisher", "url", "observed_at", "removed"}
CATALOG_MEMBERS = {"wist_version", "publisher", "collection", "generated_at", "size", "root", "tree"}
PROOF_MEMBERS = {"index", "tree_size", "path"}
BODY_MEMBERS = {"item", "collection", "catalog", "proof"}
ENTRY_MEMBERS = {"prefix", "count", "file"}

E14 = frozenset({"WIST1-E14"})
E05 = frozenset({"WIST1-E05"})
ACCEPTED = "accepted"


class NotJcsInput(Exception):
    pass


class Refused(Exception):
    pass


def _as_double(value):
    if isinstance(value, bool) or not isinstance(value, (int, list, dict)):
        return value
    if isinstance(value, int):
        return value if abs(value) <= SAFE_INTEGER else float(value)
    if isinstance(value, list):
        return [_as_double(v) for v in value]
    return {k: _as_double(v) for k, v in value.items()}


def jcs(value):
    return rfc8785.dumps(_as_double(value))


def sha256(data):
    return hashlib.sha256(data).digest()


def integer(value, low=0, high=SAFE_INTEGER):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not (math.isfinite(value) and value.is_integer()):
        return None
    number = int(value)
    return number if low <= number <= high else None


def _scalar_values(value):
    if isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, list):
        for v in value:
            _scalar_values(v)
    elif isinstance(value, dict):
        for k, v in value.items():
            k.encode("utf-8")
            _scalar_values(v)


def parse_json_text(text):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise NotJcsInput(f"repeated member {key!r}")
            out[key] = value
        return out

    def constant(name):
        raise NotJcsInput(name)

    def number(literal):
        try:
            value = float(literal)
        except OverflowError:
            raise NotJcsInput(literal)
        if not math.isfinite(value):
            raise NotJcsInput(literal)
        return value

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_int=number,
                           parse_float=number)
        _scalar_values(value)
    except (ValueError, UnicodeEncodeError) as error:
        raise NotJcsInput(str(error))
    return value


def outcome(codes):
    return ACCEPTED if not codes else frozenset(codes)


def matches(expected, verdict):
    if verdict == ACCEPTED:
        return expected == ACCEPTED
    return expected in verdict


def shown(verdict):
    return verdict if verdict == ACCEPTED else " or ".join(sorted(verdict))


def publisher_ts(value):
    try:
        return publisher_instant(value)
    except VerifierError:
        return None


def log_instant(value):
    try:
        return log_seconds(value)
    except VerifierError:
        return None


def b64u_bytes(value):
    if not isinstance(value, str) or not value or len(value) % 4 == 1 or any(c not in B64U_ALPHABET for c in value):
        return None
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    return raw if b64u_encode(raw) == value else None


def catalog_id(inner):
    return "sha256:" + sha256(jcs(inner)).hex()


def item_id(item):
    return "sha256:" + sha256(jcs(item)).hex()


def key_of(url):
    return sha256(jcs(["page", url]))


def leaf_of(item):
    return sha256(b"\x00" + key_of(item["url"]) + sha256(jcs(item)))


def node(left, right):
    return sha256(b"\x01" + left + right)


def merkle_root(leaves):
    if not leaves:
        return sha256(b"")
    level = list(leaves)
    while len(level) > 1:
        paired = [node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            paired.append(level[-1])
        level = paired
    return level[0]


def covered(publisher, collection, url):
    if "collections" not in publisher:
        return collection == "default" and url_host(url) in authority(publisher)
    own = collection_named(publisher, collection)
    if own is None or not any(entry_covers(entry, url) for entry in own["scope"]):
        return False
    return not any(other is not own and any(entry_covers(entry, url) for entry in other["scope"])
                   for other in publisher["collections"])


def meta_form(meta):
    if not isinstance(meta, dict) or "lang" not in meta or not set(meta) <= {"lang", "topics", "license"}:
        return False
    if not isinstance(meta["lang"], str) or not LANG.fullmatch(meta["lang"]):
        return False
    if "topics" in meta:
        topics = meta["topics"]
        if not isinstance(topics, list) or len(topics) > 10:
            return False
        if not all(isinstance(topic, str) and len(topic) <= 64 for topic in topics):
            return False
    if "license" in meta and not (isinstance(meta["license"], str) and len(meta["license"]) <= 64):
        return False
    return True


def commitment_form(payload):
    if not isinstance(payload, dict) or set(payload) != {"commitment", "alg", "bytes"}:
        return False
    if not isinstance(payload["commitment"], str) or not COMMITMENT.fullmatch(payload["commitment"]):
        return False
    return payload["alg"] == "HMAC-SHA256" and integer(payload["bytes"]) is not None


def item_form(item):
    if not isinstance(item, dict):
        return False
    removed = "removed" in item
    if set(item) != (REMOVED_MEMBERS if removed else PAGE_MEMBERS):
        return False
    if removed and item["removed"] is not True:
        return False
    if not canonical_host(item["publisher"]) or not isinstance(item["url"], str):
        return False
    if publisher_ts(item["observed_at"]) is None:
        return False
    return removed or (commitment_form(item["payload"]) and meta_form(item["meta"]))


def derived_cap(parameters):
    return parameters["extract_cap_bytes"] + parameters["links_cap_bytes"] + parameters["summary_cap_bytes"] + 32


def judge_item(item, inner, publisher, parameters):
    if not item_form(item):
        return E14
    codes = set()
    url = item["url"]
    if normalize_url(url, "") != url or url_host(url) not in authority(publisher) \
            or not covered(publisher, inner["collection"], url):
        codes.add("WIST1-E03")
    if len(jcs(url)) > parameters["url_cap_bytes"]:
        codes.add("WIST1-E11")
    if "removed" not in item and integer(item["payload"]["bytes"]) > derived_cap(parameters):
        codes.add("WIST1-E04")
    if publisher_instant(item["observed_at"]) > log_seconds(inner["generated_at"]):
        codes.add("WIST1-E06")
    if item["publisher"] != inner["publisher"]:
        codes.add("WIST2-E03")
    return outcome(codes)


def payload_form(payload):
    if not isinstance(payload, dict) or set(payload) != {"wist_version", "salt", "content"}:
        return False
    if not isinstance(payload["wist_version"], str) or not VERSION.fullmatch(payload["wist_version"]):
        return False
    salt = b64u_bytes(payload["salt"])
    if salt is None or len(salt) < 16:
        return False
    content = payload["content"]
    if not isinstance(content, dict) or set(content) != {"extract", "links", "summary"}:
        return False
    if not isinstance(content["extract"], str):
        return False
    links = content["links"]
    if not isinstance(links, dict) or set(links) != {"total", "urls"} or integer(links["total"]) is None:
        return False
    if not isinstance(links["urls"], list) or not all(isinstance(u, str) for u in links["urls"]):
        return False
    summary = content["summary"]
    if not isinstance(summary, dict) or "title" not in summary or not set(summary) <= {"title", "abstract"}:
        return False
    if not isinstance(summary["title"], str) or len(summary["title"]) > 256:
        return False
    return "abstract" not in summary or (isinstance(summary["abstract"], str) and len(summary["abstract"]) <= 1500)


def internal(url, domain):
    host = url_host(url)
    return host == domain or host.endswith("." + domain)


def judge_payload(payload, item, parameters):
    if not payload_form(payload):
        return E14
    codes = set()
    content = payload["content"]
    if int(VERSION.fullmatch(payload["wist_version"]).group(1)) != 1:
        codes.add("WIST1-E15")
    urls = content["links"]["urls"]
    if len(jcs(content["extract"])) > parameters["extract_cap_bytes"] \
            or len(jcs(content["links"])) > parameters["links_cap_bytes"] \
            or any(len(jcs(u)) > parameters["link_url_cap_bytes"] for u in urls) \
            or len(jcs(content["summary"])) > parameters["summary_cap_bytes"]:
        codes.add("WIST1-E04")
    if len(set(urls)) != len(urls) or len(urls) > integer(content["links"]["total"]) \
            or any(normalize_url(u, "") != u or internal(u, item["publisher"]) for u in urls):
        codes.add("WIST1-E12")
    message = jcs(content)
    digest = hmac.new(b64u_bytes(payload["salt"]), message, hashlib.sha256).hexdigest()
    if len(message) != integer(item["payload"]["bytes"]) or "hmac-sha256:" + digest != item["payload"]["commitment"]:
        codes.add("WIST1-E10")
    return outcome(codes)


def sig_form(sig):
    if not isinstance(sig, dict) or set(sig) != {"key_id", "alg", "value"}:
        return False
    if not isinstance(sig["key_id"], str) or len(sig["key_id"]) > 64 or sig["alg"] != "Ed25519":
        return False
    return b64u_canonical(sig["value"], 64) is not None


def catalog_inner_form(inner):
    if not isinstance(inner, dict) or set(inner) != CATALOG_MEMBERS:
        return False
    if not isinstance(inner["wist_version"], str) or not VERSION.fullmatch(inner["wist_version"]):
        return False
    if not canonical_host(inner["publisher"]):
        return False
    if not isinstance(inner["collection"], str) or not NAME.fullmatch(inner["collection"]):
        return False
    if log_instant(inner["generated_at"]) is None or integer(inner["size"]) is None:
        return False
    return all(isinstance(inner[m], str) and HASH.fullmatch(inner[m]) for m in ("root", "tree"))


def binding_code(publisher, inner, sig):
    if inner["publisher"] != publisher["domain"]:
        return "WIST1-E02"
    instant = log_seconds(inner["generated_at"])
    entries = list(publisher["keys"])
    named = collection_named(publisher, inner["collection"])
    if named is not None:
        entries += named.get("keys", [])
    eligible = [entry for entry in entries
                if entry["kid"] == sig["key_id"] and usable_public(public_raw(entry))
                and entry["nbf"] <= instant and ("exp" not in entry or instant < entry["exp"])]
    if not eligible:
        return "WIST1-E02"
    signature = b64u_canonical(sig["value"], 64)
    message = jcs(inner)
    if not any(signature_verifies(public_raw(entry), signature, message) for entry in eligible):
        return "WIST1-E01"
    return None


def judge_catalog(case, publisher):
    if "catalog_json" in case:
        try:
            envelope = parse_json_text(case["catalog_json"])
        except NotJcsInput:
            return E05, None
    else:
        envelope = case["catalog"]
    if not isinstance(envelope, dict) or set(envelope) != {"catalog", "sig"} or not sig_form(envelope["sig"]):
        return E14, None
    inner = envelope["catalog"]
    if not catalog_inner_form(inner):
        return E14, None
    parameters = case["parameters"]
    codes = set()
    if int(VERSION.fullmatch(inner["wist_version"]).group(1)) != 1:
        codes.add("WIST1-E15")
    if integer(inner["size"]) > parameters["catalog_items_max"]:
        codes.add("WIST1-E04")
    if inner["collection"] not in collection_names(publisher):
        codes.add("WIST1-E03")
    binding = binding_code(publisher, inner, envelope["sig"])
    if binding:
        codes.add(binding)
    if log_seconds(inner["generated_at"]) > publisher_instant(case["clock"]) + parameters["clock_skew_seconds"]:
        codes.add("WIST1-E06")
    return outcome(codes), inner


def proof_form(proof):
    if not isinstance(proof, dict) or set(proof) != PROOF_MEMBERS:
        return False
    if integer(proof["index"]) is None or integer(proof["tree_size"]) is None:
        return False
    path = proof["path"]
    return isinstance(path, list) and all(isinstance(p, str) and HEX64.fullmatch(p) for p in path)


def proof_holds(proof, leaf, inner):
    index, tree_size = integer(proof["index"]), integer(proof["tree_size"])
    if tree_size != integer(inner["size"]) or index >= tree_size:
        return False
    path = [bytes.fromhex(p) for p in proof["path"]]
    used, fn, sn, h = 0, index, tree_size - 1, leaf
    while sn > 0:
        if fn % 2 == 1 or fn < sn:
            if used == len(path):
                return False
            h = node(path[used], h) if fn % 2 == 1 else node(h, path[used])
            used += 1
        fn, sn = fn // 2, sn // 2
    return used == len(path) and "sha256:" + h.hex() == inner["root"]


def judge_proof(proof, item, inner):
    if not proof_form(proof):
        return E14
    return ACCEPTED if proof_holds(proof, leaf_of(item), inner) else frozenset({"WIST1-E17"})


def judge_body(body, inner):
    if not isinstance(body, dict) or set(body) != BODY_MEMBERS or not item_form(body["item"]):
        return E14
    if not isinstance(body["collection"], str) or not NAME.fullmatch(body["collection"]):
        return E14
    if not isinstance(body["catalog"], str) or not HASH.fullmatch(body["catalog"]) or not proof_form(body["proof"]):
        return E14
    if body["catalog"] != catalog_id(inner):
        raise VerifierError("the body names another Catalog than the one supplied")
    item = body["item"]
    codes = set()
    if body["collection"] != inner["collection"]:
        codes.add("WIST1-E17")
    if item["publisher"] != inner["publisher"]:
        codes.add("WIST2-E03")
    if normalize_url(item["url"], "") != item["url"]:
        codes.add("WIST1-E03")
    if publisher_instant(item["observed_at"]) > log_seconds(inner["generated_at"]):
        codes.add("WIST1-E06")
    if not proof_holds(body["proof"], leaf_of(item), inner):
        codes.add("WIST1-E17")
    return outcome(codes)


def walk_tree(inner, files, parameters):
    listed = []

    def visit(name, prefix, level, count):
        text = files.get(name)
        if not isinstance(text, str):
            raise Refused(f"tree file {name} unavailable")
        try:
            octets = text.encode("utf-8")
        except UnicodeEncodeError:
            raise Refused(f"tree file {name} is not UTF-8")
        if len(octets) > parameters["tree_file_cap_bytes"]:
            raise Refused(f"tree file {name} above tree_file_cap_bytes")
        if hashlib.sha256(octets).hexdigest() != name:
            raise Refused(f"tree file {name} has another SHA-256")
        try:
            obj = parse_json_text(text)
            serialized = jcs(obj)
        except (NotJcsInput, ValueError, TypeError, rfc8785.CanonicalizationError) as error:
            raise Refused(f"tree file {name} does not parse: {error}")
        if not isinstance(obj, dict) or len(obj) != 1 or serialized != octets:
            raise Refused(f"tree file {name} is not the JCS serialization of a one-member object")
        if "items" in obj:
            visit_bucket(obj["items"], prefix, count)
        elif "children" in obj:
            if level >= parameters["tree_depth_max"]:
                raise Refused(f"inner file at level {level}")
            visit_inner(obj["children"], prefix, level, count)
        else:
            raise Refused("tree file member is neither items nor children")

    def visit_bucket(items, prefix, count):
        if not isinstance(items, list) or not all(isinstance(e, dict) and isinstance(e.get("url"), str)
                                                  for e in items):
            raise Refused("bucket items malformed")
        keys = [key_of(e["url"]) for e in items]
        if any(a >= b for a, b in zip(keys, keys[1:])):
            raise Refused("bucket keys not strictly ascending")
        if not all(k.hex().startswith(prefix) for k in keys):
            raise Refused("bucket key outside its prefix")
        if len(items) != count:
            raise Refused("bucket count differs")
        listed.extend(items)

    def visit_inner(children, prefix, level, count):
        if not isinstance(children, list) or not 1 <= len(children) <= 16:
            raise Refused("children not an array of 1 to 16 entries")
        total, last = 0, None
        for entry in children:
            if not isinstance(entry, dict) or set(entry) != ENTRY_MEMBERS:
                raise Refused("entry members")
            p = entry["prefix"]
            if not isinstance(p, str) or len(p) != len(prefix) + 1 or not p.startswith(prefix) \
                    or p[-1] not in HEX_DIGITS:
                raise Refused("entry prefix")
            if last is not None and p <= last:
                raise Refused("entry prefixes not strictly ascending")
            last = p
            n = integer(entry["count"], 1)
            if n is None:
                raise Refused("entry count")
            if not isinstance(entry["file"], str) or not HASH.fullmatch(entry["file"]):
                raise Refused("entry file")
            total += n
        if total != count:
            raise Refused("entry counts do not add up")
        for entry in children:
            visit(entry["file"][len("sha256:"):], entry["prefix"], level + 1, integer(entry["count"], 1))

    size = integer(inner["size"])
    visit(inner["tree"][len("sha256:"):], "", 1, size)
    if len(listed) != size:
        raise Refused("list length differs from size")
    if "sha256:" + merkle_root([leaf_of(item) for item in listed]).hex() != inner["root"]:
        raise Refused("list root differs from root")
    return listed


def derive_list(case, publisher):
    domain, collection = publisher["domain"], case["collection"]
    generated = log_seconds(case["generated_at"])
    retention = case["parameters"]["removal_retention_days"] * 86400
    held = case["served"]["payloads"]
    publications = {p["url"]: p for p in case["publications"]}
    salts = {s["url"]: s["salt"] for s in case["salts"]}
    listed, payloads, served_urls = [], {}, set()

    def new_item(publication):
        salt = salts[publication["url"]]
        message = jcs(publication["content"])
        digest = hmac.new(b64u_bytes(salt), message, hashlib.sha256).hexdigest()
        item = {"publisher": domain, "url": publication["url"], "observed_at": publication["modified"],
                "payload": {"commitment": "hmac-sha256:" + digest, "alg": "HMAC-SHA256", "bytes": len(message)},
                "meta": {"lang": publication["lang"]}}
        listed.append(item)
        payloads[item_id(item)] = {"wist_version": case["wist_version"], "salt": salt,
                                   "content": publication["content"]}

    for item in case["served"]["list"]:
        url = item["url"]
        served_urls.add(url)
        if not covered(publisher, collection, url):
            continue
        own_publisher = item["publisher"] == domain
        publication = publications.get(url)
        if publication is not None:
            own = item_id(item)
            if own_publisher and "removed" not in item and item["meta"]["lang"] == publication["lang"] \
                    and own in held and judge_payload(held[own], item, case["parameters"]) == ACCEPTED \
                    and jcs(held[own]["content"]) == jcs(publication["content"]):
                listed.append(item)
                payloads[own] = held[own]
            else:
                new_item(publication)
        elif "removed" not in item or not own_publisher:
            listed.append({"publisher": domain, "url": url, "observed_at": case["generated_at"], "removed": True})
        elif generated < publisher_instant(item["observed_at"]) + retention:
            listed.append(item)
    for publication in case["publications"]:
        if publication["url"] not in served_urls:
            new_item(publication)
    if any(publisher_instant(item["observed_at"]) > generated for item in listed):
        return {"refused": "item-instant"}
    listed.sort(key=lambda item: key_of(item["url"]))
    return {"list": listed, "payloads": payloads}


def next_instant(case):
    cut = math.floor(publisher_instant(case["clock"]))
    instant = cut if case["served"] is None else max(cut, log_seconds(case["served"]) + 1)
    if instant > cut + case["clock_skew_seconds"]:
        return {"refused": "catalog-instant"}
    return {"generated_at": log_timestamp(instant)}


def pull_order(case):
    fetched, wanted, last = case["fetched"], case["fetched_for"], case["last_accepted"]
    if fetched["publisher"] != wanted["publisher"] or fetched["collection"] != wanted["collection"]:
        return "WIST2-E04"
    if last is None:
        return ACCEPTED
    if catalog_id(fetched) == catalog_id(last):
        return "idempotent"
    if log_seconds(fetched["generated_at"]) <= log_seconds(last["generated_at"]):
        return "WIST2-E05"
    return ACCEPTED


class Report:
    def __init__(self):
        self.cases = 0
        self.failures = []
        self.several = []

    def verdict(self, name, expected, verdict):
        self.cases += 1
        if isinstance(verdict, frozenset) and len(verdict) > 1:
            self.several.append((name, shown(verdict)))
        if not matches(expected, verdict):
            self.failures.append((name, f"expected {expected}, got {shown(verdict)}"))

    def equal(self, name, expected, actual):
        self.cases += 1
        if expected != actual:
            self.failures.append((name, f"expected {json.dumps(expected)[:300]}, got {json.dumps(actual)[:300]}"))

    def run(self, name, fn):
        try:
            fn()
        except (VerifierError, KeyError, TypeError, ValueError, AttributeError) as error:
            self.cases += 1
            self.failures.append((name, f"{type(error).__name__}: {error}"))


def declarations(data):
    publishers = {}
    for label, envelope in data.get("declarations", {}).items():
        require_accepted(envelope, DEFAULT_PARAMETERS)
        publishers[label] = envelope["publisher"]
    return publishers


def family_item_fields(data, report):
    publishers = declarations(data)
    for case in data["item_cases"]:
        report.run(case["name"], lambda c=case: report.verdict(
            c["name"], c["expected"],
            judge_item(c["item"], c["catalog"], publishers[c["declaration"]], c["parameters"])))
    for case in data["known_answers"]:
        def one(c=case):
            item = c["item"]
            actual = {"item_id": item_id(item), "key": key_of(item["url"]).hex(), "leaf": leaf_of(item).hex()}
            expected = {k: c[k] for k in actual}
            if "payload" in c:
                actual["payload"] = shown(judge_payload(c["payload"], item, REGISTRY_SIZE_CAPS))
                expected["payload"] = ACCEPTED
            report.equal(c["name"], expected, actual)
        report.run(case["name"], one)
    for case in data["payload_cases"]:
        def one(c=case):
            path = PAYLOAD_PATH.fullmatch(c["payload_path"])
            if not path or not NAME.fullmatch(path.group(1)) or "sha256:" + path.group(2) != item_id(c["item"]):
                raise VerifierError(f"payload_path does not name the Item ID: {c['payload_path']}")
            report.verdict(c["name"], c["expected"], judge_payload(c["payload"], c["item"], c["parameters"]))
        report.run(case["name"], one)


def proof_input(case):
    if "proof_json" in case:
        try:
            return parse_json_text(case["proof_json"])
        except NotJcsInput as error:
            raise VerifierError(f"proof_json is not JSON: {error}")
    return case["proof"]


def family_item_roots(data, report):
    page_items = {}
    for case in data["root_cases"]:
        def one(c=case):
            items = c["items"]
            keys = [key_of(item["url"]) for item in items]
            if keys != sorted(keys):
                raise VerifierError("items are not in ascending octet order of key")
            leaves = [leaf_of(item) for item in items]
            for item in items:
                if isinstance(item, dict) and "removed" not in item:
                    page_items[item_id(item)] = item
            report.equal(c["name"], {"keys": c["keys"], "leaves": c["leaves"], "root": c["root"]},
                         {"keys": [k.hex() for k in keys], "leaves": [lf.hex() for lf in leaves],
                          "root": "sha256:" + merkle_root(leaves).hex()})
        report.run(case["name"], one)
    for case in data["proof_cases"]:
        report.run(case["name"], lambda c=case: report.verdict(
            c["name"], c["expected"], judge_proof(proof_input(c), c["item"], c["catalog"])))
    for case in data["body_cases"]:
        report.run(case["name"], lambda c=case: report.verdict(
            c["name"], c["expected"], judge_body(c["body"], c["catalog"])))
    for item in [c["item"] for c in data["proof_cases"]] + [c["body"].get("item") for c in data["body_cases"]
                                                             if isinstance(c["body"], dict)]:
        if item_form(item) and "removed" not in item:
            page_items[item_id(item)] = item
    for identifier, payload in data["payloads"].items():
        def one(i=identifier, p=payload):
            if i not in page_items:
                raise VerifierError("no page Item of the file has this Item ID")
            report.verdict(f"payloads[{i}]", ACCEPTED, judge_payload(p, page_items[i], REGISTRY_SIZE_CAPS))
        report.run(f"payloads[{identifier}]", one)
    for identifier in page_items.keys() - data["payloads"].keys():
        report.cases += 1
        report.failures.append((f"payloads[{identifier}]", "page Item without a Payload"))


def family_catalog_fields(data, report):
    publishers = declarations(data)
    for case in data["cases"]:
        report.run(case["name"], lambda c=case: report.verdict(
            c["name"], c["expected"], judge_catalog(c, publishers[c["declaration"]])[0]))
    for case in data["id_cases"]:
        report.run(case["name"], lambda c=case: report.equal(c["name"], c["catalog_id"], catalog_id(c["catalog"])))


def family_catalog_order(data, report):
    for case in data["pull_cases"]:
        report.run(case["name"], lambda c=case: report.equal(c["name"], c["expected"], pull_order(c)))
    for case in data["next_cases"]:
        report.run(case["name"], lambda c=case: report.equal(c["name"], c["expected"], next_instant(c)))


def family_catalog_tree(data, report):
    for case in data["cases"]:
        def one(c=case):
            try:
                actual = {"list": [item_id(item) for item in walk_tree(c["catalog"], c["tree_files"], c["parameters"])]}
            except Refused:
                actual = {"refused": "WIST2-E07"}
            report.equal(c["name"], c["expected"], actual)
        report.run(case["name"], one)


def family_catalog_items(data, report):
    publishers = declarations(data)
    for case in data["cases"]:
        def one(c=case):
            publisher, expected = publishers[c["declaration"]], c["expected"]
            verdict, inner = judge_catalog(c, publisher)
            if verdict != ACCEPTED:
                report.verdict(c["name"], expected["catalog"], verdict)
                if set(expected) != {"catalog"}:
                    report.failures.append((c["name"], "a refused Catalog carries Item outcomes"))
                return
            try:
                listed = walk_tree(inner, c["tree_files"], c["parameters"])
            except Refused as refusal:
                report.verdict(c["name"], expected["catalog"], frozenset({"WIST2-E07"}))
                report.failures.append((c["name"], f"walk refused: {refusal}"))
                return
            report.verdict(c["name"], expected["catalog"], ACCEPTED)
            wanted = expected.get("items", [])
            if len(wanted) != len(listed):
                report.failures.append((c["name"], f"expected {len(wanted)} Items, the walk lists {len(listed)}"))
                return
            for position, (want, item) in enumerate(zip(wanted, listed)):
                label = f"{c['name']} Item {position}"
                if want["url"] != item.get("url") or want["item_id"] != item_id(item):
                    report.cases += 1
                    report.failures.append((label, "url or Item ID differs from the walk"))
                    continue
                report.verdict(label, want["expected"], judge_item(item, inner, publisher, c["parameters"]))
        report.run(case["name"], one)


def family_item_lists(data, report):
    publishers = declarations(data)
    for case in data["cases"]:
        report.run(case["name"], lambda c=case: report.equal(
            c["name"], c["expected"], derive_list(c, publishers[c["declaration"]])))


FAMILIES = [
    ("item-fields", "wist1/item-fields.json", family_item_fields),
    ("item-roots", "wist1/item-roots.json", family_item_roots),
    ("catalog-fields", "wist1/catalog-fields.json", family_catalog_fields),
    ("catalog-order", "wist2/catalog-order.json", family_catalog_order),
    ("catalog-tree", "wist2/catalog-tree.json", family_catalog_tree),
    ("catalog-items", "wist2/catalog-items.json", family_catalog_items),
    ("item-lists", "wist2/item-lists.json", family_item_lists),
]


def main(argv):
    base = pathlib.Path(argv[1]) if len(argv) > 1 else ROOT / "vectors"
    failed = False
    for family, relative, check in FAMILIES:
        report = Report()
        try:
            data = strict_load(base / relative)
            keys = []
            check_keys_block(data, keys)
            report.failures.extend(keys)
            check(data, report)
        except (OSError, VerifierError, KeyError, TypeError, ValueError) as error:
            report.failures.append(("file", f"{type(error).__name__}: {error}"))
        status = "FAIL" if report.failures else "PASS"
        failed = failed or bool(report.failures)
        print(f"{status} {family}: {report.cases} cases, {len(report.failures)} disagreeing")
        for name, what in report.failures:
            print(f"  {name}: {what}")
        for name, codes in report.several:
            print(f"  several diagnostics permitted: {name}: {codes}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
