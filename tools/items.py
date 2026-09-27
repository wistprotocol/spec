import base64
import hashlib
import hmac
import json
import math
import re

import rfc8785

import collection_rules as rules
import emissions
import merkle
from link_extraction import _external, normalize_url

DEFAULT_PARAMETERS = {
    "url_cap_bytes": 2048,
    "extract_cap_bytes": 32768,
    "links_cap_bytes": 4096,
    "link_url_cap_bytes": 2048,
    "summary_cap_bytes": 2048,
    "removal_retention_days": 180,
}
SAFE_INTEGER_MAX = 2**53 - 1
DAY_SECONDS = 86400
CONTENT_STRUCTURE_OCTETS = 32
PAYLOAD_VERSION = "1.0.0"

PAGE_MEMBERS = frozenset(("publisher", "url", "observed_at", "payload", "meta"))
REMOVED_MEMBERS = frozenset(("publisher", "url", "observed_at", "removed"))
COMMITMENT_MEMBERS = frozenset(("commitment", "alg", "bytes"))
META_OPTIONAL = frozenset(("topics", "license"))
PROOF_MEMBERS = frozenset(("index", "tree_size", "path"))
BODY_MEMBERS = frozenset(("item", "collection", "catalog", "proof"))
PAYLOAD_MEMBERS = frozenset(("wist_version", "salt", "content"))
CONTENT_MEMBERS = frozenset(("extract", "links", "summary"))
LINKS_MEMBERS = frozenset(("total", "urls"))

COMMITMENT_PATTERN = re.compile(r"hmac-sha256:[0-9a-f]{64}")
HASH_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
HEX64_PATTERN = re.compile(r"[0-9a-f]{64}")
VERSION_PATTERN = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
B64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]+")
EMPTY_ROOT = hashlib.sha256(b"").digest()


class NotJcsInput(Exception):
    pass


def _members(pairs):
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        raise NotJcsInput("repeated member name")
    return dict(pairs)


def _reject_constant(name):
    raise NotJcsInput(name)


def _integer(lexeme):
    value = int(lexeme)
    if abs(value) <= SAFE_INTEGER_MAX:
        return value
    try:
        return float(value)
    except OverflowError:
        raise NotJcsInput("a number beyond the finite range")


def _double(lexeme):
    value = float(lexeme)
    if not math.isfinite(value):
        raise NotJcsInput("a number beyond the finite range")
    return value


def _scalars_only(node):
    if isinstance(node, str):
        return not any(0xD800 <= ord(c) <= 0xDFFF for c in node)
    if isinstance(node, dict):
        return all(_scalars_only(k) and _scalars_only(v) for k, v in node.items())
    if isinstance(node, list):
        return all(_scalars_only(v) for v in node)
    return True


def strict_loads(octets):
    try:
        text = octets.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_members, parse_int=_integer, parse_float=_double,
                           parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise NotJcsInput(str(error))
    if not _scalars_only(value):
        raise NotJcsInput("a string that is not a sequence of Unicode scalar values")
    return value


class Refused(Exception):
    def __init__(self, code, reason):
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


def jcs(value):
    return rfc8785.dumps(value)


def is_safe_integer(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not value.is_integer():
        return False
    return 0 <= value <= SAFE_INTEGER_MAX


def kind(item):
    return "removed" if "removed" in item else "page"


def item_id(item):
    return "sha256:" + hashlib.sha256(jcs(item)).hexdigest()


def item_key(url):
    return hashlib.sha256(jcs(["page", url])).digest()


def leaf(item):
    return merkle.leaf_hash(item_key(item["url"]) + hashlib.sha256(jcs(item)).digest())


def in_list_order(items):
    return sorted(items, key=lambda item: item_key(item["url"]))


def root(items):
    if not items:
        return EMPTY_ROOT
    return merkle.merkle_root([leaf(item) for item in in_list_order(items)])


def root_string(items):
    return "sha256:" + root(items).hex()


def payload_name(item):
    return item_id(item)[len("sha256:"):]


def derived_payload_cap(parameters):
    return (parameters["extract_cap_bytes"] + parameters["links_cap_bytes"]
            + parameters["summary_cap_bytes"] + CONTENT_STRUCTURE_OCTETS)


def instant(value):
    if not emissions.is_publisher_timestamp(value):
        return None
    return rules.publisher_timestamp_seconds(value)


def check_commitment_form(payload):
    if not isinstance(payload, dict) or set(payload) != COMMITMENT_MEMBERS:
        raise Refused("WIST1-E14", "payload members")
    if not isinstance(payload["commitment"], str) or not COMMITMENT_PATTERN.fullmatch(payload["commitment"]):
        raise Refused("WIST1-E14", "payload.commitment form")
    if payload["alg"] != "HMAC-SHA256":
        raise Refused("WIST1-E14", "payload.alg")
    if not is_safe_integer(payload["bytes"]):
        raise Refused("WIST1-E14", "payload.bytes is not a nonnegative safe integer")


def check_meta_form(meta):
    if not isinstance(meta, dict) or "lang" not in meta or not set(meta) <= {"lang"} | META_OPTIONAL:
        raise Refused("WIST1-E14", "meta members")
    if not emissions.is_language_tag(meta["lang"]):
        raise Refused("WIST1-E14", "meta.lang")
    if "topics" in meta:
        topics = meta["topics"]
        if not isinstance(topics, list) or len(topics) > 10 or not all(
                isinstance(t, str) and len(t) <= 64 for t in topics):
            raise Refused("WIST1-E14", "meta.topics")
    if "license" in meta and not (isinstance(meta["license"], str) and len(meta["license"]) <= 64):
        raise Refused("WIST1-E14", "meta.license")


def check_item_form(item):
    if not isinstance(item, dict):
        raise Refused("WIST1-E14", "an Item is an object")
    members = REMOVED_MEMBERS if "removed" in item else PAGE_MEMBERS
    if set(item) != members:
        raise Refused("WIST1-E14", "member set of the kind")
    if "removed" in item and item["removed"] is not True:
        raise Refused("WIST1-E14", "removed is not true")
    if not isinstance(item["publisher"], str) or not rules.is_canonical_host(item["publisher"]):
        raise Refused("WIST1-E14", "publisher is not a Canonical Host")
    if not isinstance(item["url"], str):
        raise Refused("WIST1-E14", "url is not a string")
    if instant(item["observed_at"]) is None:
        raise Refused("WIST1-E14", "observed_at is not a Publisher timestamp")
    if "payload" in item:
        check_commitment_form(item["payload"])
        check_meta_form(item["meta"])


def url_disposition(url, publisher, collection_name):
    if normalize_url(url, url) != url:
        return "not its own Normalized URL"
    if rules.url_host(url) not in rules.authority_hosts(publisher):
        return "host outside the Publisher's authority"
    collection = rules.collection_named(publisher, collection_name)
    if collection is None or not rules.scope_covers(publisher, collection, url):
        return "outside the Scope of the Catalog's Collection"
    return None


def judge_item(item, catalog, publisher, parameters):
    check_item_form(item)
    reason = url_disposition(item["url"], publisher, catalog["collection"])
    if reason is not None:
        raise Refused("WIST1-E03", reason)
    if len(jcs(item["url"])) > parameters["url_cap_bytes"]:
        raise Refused("WIST1-E11", "JCS(url) above url_cap_bytes")
    if "payload" in item and item["payload"]["bytes"] > derived_payload_cap(parameters):
        raise Refused("WIST1-E04", "payload.bytes above the derived cap")
    if instant(item["observed_at"]) > instant(catalog["generated_at"]):
        raise Refused("WIST1-E06", "observed_at later than generated_at")
    if item["publisher"] != catalog["publisher"]:
        raise Refused("WIST2-E03", "publisher other than the Catalog's")


def item_disposition(item, catalog, publisher, parameters=None):
    parameters = {**DEFAULT_PARAMETERS, **(parameters or {})}
    try:
        judge_item(item, catalog, publisher, parameters)
    except Refused as refused:
        return refused.code
    return "accepted"


def decode_salt(value):
    if not isinstance(value, str) or not B64URL_PATTERN.fullmatch(value) or len(value) % 4 == 1:
        return None
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if rules.b64u(raw) != value or len(raw) < 16:
        return None
    return raw


def commit(salt_raw, content):
    return "hmac-sha256:" + hmac.new(salt_raw, jcs(content), hashlib.sha256).hexdigest()


def check_payload_form(payload):
    if not isinstance(payload, dict) or set(payload) != PAYLOAD_MEMBERS:
        raise Refused("WIST1-E14", "Payload members")
    if not isinstance(payload["wist_version"], str) or not VERSION_PATTERN.fullmatch(payload["wist_version"]):
        raise Refused("WIST1-E14", "Payload wist_version")
    if decode_salt(payload["salt"]) is None:
        raise Refused("WIST1-E14", "Payload salt")
    content = payload["content"]
    if not isinstance(content, dict) or set(content) != CONTENT_MEMBERS:
        raise Refused("WIST1-E14", "content members")
    if not isinstance(content["extract"], str):
        raise Refused("WIST1-E14", "extract")
    links = content["links"]
    if not isinstance(links, dict) or set(links) != LINKS_MEMBERS or not is_safe_integer(links["total"]):
        raise Refused("WIST1-E14", "links")
    if not isinstance(links["urls"], list) or not all(isinstance(u, str) for u in links["urls"]):
        raise Refused("WIST1-E14", "links.urls")
    summary = content["summary"]
    if not isinstance(summary, dict) or "title" not in summary or not set(summary) <= {"title", "abstract"}:
        raise Refused("WIST1-E14", "summary members")
    if not isinstance(summary["title"], str) or len(summary["title"]) > 256:
        raise Refused("WIST1-E14", "summary.title")
    if "abstract" in summary and not (isinstance(summary["abstract"], str)
                                      and len(summary["abstract"]) <= 1500):
        raise Refused("WIST1-E14", "summary.abstract")


def links_disposition(links, publisher_domain):
    urls = links["urls"]
    if len(set(urls)) != len(urls) or len(urls) > links["total"]:
        return False
    return all(normalize_url(u, u) == u and _external(u, publisher_domain) for u in urls)


def judge_payload(item, payload, parameters):
    check_payload_form(payload)
    if VERSION_PATTERN.fullmatch(payload["wist_version"]).group(1) != "1":
        raise Refused("WIST1-E15", "unimplemented major version")
    content = payload["content"]
    if (len(jcs(content["extract"])) > parameters["extract_cap_bytes"]
            or len(jcs(content["links"])) > parameters["links_cap_bytes"]
            or any(len(jcs(u)) > parameters["link_url_cap_bytes"] for u in content["links"]["urls"])
            or len(jcs(content["summary"])) > parameters["summary_cap_bytes"]):
        raise Refused("WIST1-E04", "a Payload cap")
    if len(jcs(content)) != item["payload"]["bytes"]:
        raise Refused("WIST1-E10", "JCS(content) is not payload.bytes octets")
    if commit(decode_salt(payload["salt"]), content) != item["payload"]["commitment"]:
        raise Refused("WIST1-E10", "the Payload does not reproduce the commitment")
    if not links_disposition(content["links"], item["publisher"]):
        raise Refused("WIST1-E12", "links")


def payload_disposition(item, payload, parameters=None):
    parameters = {**DEFAULT_PARAMETERS, **(parameters or {})}
    if kind(item) != "page":
        raise ValueError("an Item of kind removed has no Payload")
    try:
        judge_payload(item, payload, parameters)
    except Refused as refused:
        return refused.code
    return "accepted"


def inclusion_proof(items, index):
    ordered = in_list_order(items)
    leaves = [leaf(item) for item in ordered]
    return {"index": index, "tree_size": len(ordered),
            "path": [h.hex() for h in merkle.audit_path(index, leaves)]}


def check_proof_form(proof):
    if not isinstance(proof, dict) or set(proof) != PROOF_MEMBERS:
        raise Refused("WIST1-E14", "proof members")
    if not is_safe_integer(proof["index"]) or not is_safe_integer(proof["tree_size"]):
        raise Refused("WIST1-E14", "index or tree_size")
    if not isinstance(proof["path"], list) or not all(
            isinstance(h, str) and HEX64_PATTERN.fullmatch(h) for h in proof["path"]):
        raise Refused("WIST1-E14", "path")


def judge_proof(item, proof, catalog):
    check_proof_form(proof)
    index, size = int(proof["index"]), int(proof["tree_size"])
    if size != catalog["size"]:
        raise Refused("WIST1-E17", "tree_size is not the Catalog's size")
    if index >= size:
        raise Refused("WIST1-E17", "index not below tree_size")
    path = [bytes.fromhex(h) for h in proof["path"]]
    h = leaf(item)
    fn, sn = index, size - 1
    while sn > 0:
        if fn % 2 == 1:
            if not path:
                raise Refused("WIST1-E17", "path runs out")
            h = merkle.node_hash(path.pop(0), h)
        elif fn < sn:
            if not path:
                raise Refused("WIST1-E17", "path runs out")
            h = merkle.node_hash(h, path.pop(0))
        fn, sn = fn // 2, sn // 2
    if path:
        raise Refused("WIST1-E17", "path elements left unread")
    if "sha256:" + h.hex() != catalog["root"]:
        raise Refused("WIST1-E17", "the walk does not end with the Catalog's root")


def proof_disposition(item, proof, catalog):
    try:
        judge_proof(item, proof, catalog)
    except Refused as refused:
        return refused.code
    return "accepted"


def catalog_id(catalog):
    return "sha256:" + hashlib.sha256(jcs(catalog)).hexdigest()


def body_disposition(body, catalog):
    try:
        if not isinstance(body, dict) or set(body) != BODY_MEMBERS:
            raise Refused("WIST1-E14", "body members")
        check_item_form(body["item"])
        if not isinstance(body["collection"], str) or not rules.NAME_PATTERN.fullmatch(body["collection"]):
            raise Refused("WIST1-E14", "collection is not a Collection name")
        if not isinstance(body["catalog"], str) or not HASH_PATTERN.fullmatch(body["catalog"]):
            raise Refused("WIST1-E14", "catalog is not a Catalog ID")
        check_proof_form(body["proof"])
        if body["catalog"] != catalog_id(catalog):
            raise ValueError("the supplied Catalog is not the one the body names")
        if body["collection"] != catalog["collection"]:
            raise Refused("WIST1-E17", "collection is not the named Catalog's")
        if body["item"]["publisher"] != catalog["publisher"]:
            raise Refused("WIST2-E03", "the Item's publisher is not the named Catalog's")
        judge_proof(body["item"], body["proof"], catalog)
    except Refused as refused:
        return refused.code
    return "accepted"


def publisher_item_body(item, catalog, items):
    ordered = in_list_order(items)
    index = next(i for i, listed in enumerate(ordered) if listed == item)
    return {"item": item, "collection": catalog["collection"], "catalog": catalog_id(catalog),
            "proof": inclusion_proof(ordered, index)}


def new_page_item(publisher_domain, publication, salt, wist_version=PAYLOAD_VERSION):
    content = publication["content"]
    item = {"publisher": publisher_domain, "url": publication["url"], "observed_at": publication["modified"],
            "payload": {"commitment": commit(decode_salt(salt), content), "alg": "HMAC-SHA256",
                        "bytes": len(jcs(content))},
            "meta": {"lang": publication["lang"]}}
    return item, {"wist_version": wist_version, "salt": salt, "content": content}


def retention_seconds(parameters):
    return parameters["removal_retention_days"] * DAY_SECONDS


def held_payload(item, served_payloads, publisher_domain, parameters):
    if item["publisher"] != publisher_domain or kind(item) != "page":
        return None
    payload = served_payloads.get(item_id(item))
    if payload is None or payload_disposition(item, payload, parameters) != "accepted":
        return None
    return payload


def derive_list(served, served_payloads, publications, publisher, collection_name, generated_at, salts,
                wist_version, parameters=None):
    parameters = {**DEFAULT_PARAMETERS, **(parameters or {})}
    now = instant(generated_at)
    by_url = {p["url"]: p for p in publications}
    if len(by_url) != len(publications):
        raise ValueError("two publications of one URL")
    collection = rules.collection_named(publisher, collection_name)
    out, payloads = [], {}

    def covered(url):
        return collection is not None and rules.scope_covers(publisher, collection, url)

    served_by_url = {}
    for item in served:
        url = item["url"]
        if not covered(url):
            continue
        served_by_url[url] = item
        if url in by_url:
            continue
        if kind(item) == "page" or item["publisher"] != publisher["domain"]:
            out.append({"publisher": publisher["domain"], "url": url, "observed_at": generated_at, "removed": True})
        elif now < instant(item["observed_at"]) + retention_seconds(parameters):
            out.append(item)
    for url, publication in by_url.items():
        if not covered(url):
            raise ValueError("a publication outside the Collection's Scope")
        prior = served_by_url.get(url)
        prior_payload = held_payload(prior, served_payloads, publisher["domain"], parameters) if prior is not None else None
        if prior_payload is not None:
            if (prior["meta"]["lang"] == publication["lang"]
                    and jcs(prior_payload["content"]) == jcs(publication["content"])):
                out.append(prior)
                payloads[item_id(prior)] = prior_payload
                continue
        item, payload = new_page_item(publisher["domain"], publication, salts[url], wist_version)
        out.append(item)
        payloads[item_id(item)] = payload
    if any(instant(item["observed_at"]) > now for item in out):
        return {"refused": "item-instant"}
    ordered = in_list_order(out)
    return {"list": ordered,
            "payloads": {item_id(i): payloads[item_id(i)] for i in ordered if item_id(i) in payloads}}

