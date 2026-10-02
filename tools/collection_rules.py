import base64
import hashlib
import re
import urllib.parse
from fractions import Fraction

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import ed25519_curve
from link_extraction import normalize_url

DEFAULT_PARAMETERS = {"collections_max": 16, "scope_entries_max": 32, "url_cap_bytes": 2048}
COUNT_FLOORS = {"collections_max": 16, "scope_entries_max": 32}
UNREAD_PARAMETERS = {"collections_max": float("inf"), "scope_entries_max": float("inf"),
                     "url_cap_bytes": float("inf")}
DIGIT_CHUNK = 1000
ENTRY_OCTETS_MAX = 65535
SAFE_INTEGER_MAX = 2**53 - 1
NUMERIC_DATE_MAX = 253402300799
IMPLICIT_DEFAULT = "default"

PUBLISHER_REQUIRED = {"wist_version", "domain", "keys", "seq"}
PUBLISHER_OPTIONAL = {"prev_declaration", "subdomain_scope", "recovery_keys", "next_keys",
                      "contact", "collections"}
KEY_REQUIRED = {"kty", "crv", "x", "kid", "nbf"}
KEY_OPTIONAL = {"exp"}
COLLECTION_REQUIRED = {"name", "scope"}
COLLECTION_OPTIONAL = {"keys"}
ENTRY_MEMBERS = {"url", "match"}
MATCHES = ("prefix", "exact")

HOST_PATTERN = re.compile(r"[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*")
NAME_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")
VERSION_PATTERN = re.compile(r"([0-9]+)\.[0-9]+\.[0-9]+")
HASH_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
B64URL_ALPHABET = re.compile(r"[A-Za-z0-9_-]*")
TIMESTAMP_PATTERN = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?"
    r"(?:([Zz])|([+-])([0-9]{2}):([0-9]{2}))")


class RuleViolation(Exception):
    def __init__(self, code, reason):
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def canonical_b64url(value, length):
    if not isinstance(value, str) or not value or not B64URL_ALPHABET.fullmatch(value):
        return None
    if len(value) % 4 == 1:
        return None
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64u(raw) != value or len(raw) != length:
        return None
    return raw


def thumbprint(x):
    return b64u(hashlib.sha256(rfc8785.dumps({"crv": "Ed25519", "kty": "OKP", "x": x})).digest())


def key_set_fingerprint(entries):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(sorted(e["kid"] for e in entries))).hexdigest()


def declaration_hash(publisher):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(publisher)).hexdigest()


def entry_octets(envelope):
    return len(rfc8785.dumps({"type": "publisher_declaration", "body": envelope}))


def is_integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def is_canonical_host(value):
    if not isinstance(value, str) or len(value) > 253 or not HOST_PATTERN.fullmatch(value):
        return False
    if any(label.startswith("xn--") for label in value.split(".")):
        raise NotImplementedError("A-label hosts are outside this reference's fixtures")
    return True


def publisher_timestamp_seconds(value):
    m = TIMESTAMP_PATTERN.fullmatch(value) if isinstance(value, str) else None
    if m is None:
        return None
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days_in_month = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if not (1 <= month <= 12 and 1 <= day <= days_in_month[month - 1]
            and hour <= 23 and minute <= 59 and second <= 59):
        return None
    offset = 0
    if m.group(8) is None:
        off_hour, off_minute = int(m.group(10)), int(m.group(11))
        if off_hour > 23 or off_minute > 59:
            return None
        offset = (off_hour * 3600 + off_minute * 60) * (1 if m.group(9) == "+" else -1)
    y = year - (month <= 2)
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    fraction = Fraction(decimal_digits_value(m.group(7)), 10 ** len(m.group(7))) if m.group(7) else Fraction(0)
    return days * 86400 + hour * 3600 + minute * 60 + second + fraction - offset


def decimal_digits_value(digits):
    value = 0
    for start in range(0, len(digits), DIGIT_CHUNK):
        chunk = digits[start:start + DIGIT_CHUNK]
        value = value * 10 ** len(chunk) + int(chunk)
    return value


def usable_point(raw):
    try:
        point = ed25519_curve.string_to_point(raw)
    except ed25519_curve.InvalidProof:
        return False
    return not ed25519_curve._is_identity(ed25519_curve._mul(8, point))


def verifies(public_raw, signature_raw, message):
    if ed25519_curve.string_to_int(signature_raw[32:]) >= ed25519_curve.Q:
        return False
    if not usable_point(signature_raw[:32]):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature_raw, message)
    except InvalidSignature:
        return False
    return True


def check_key_entry(entry, where):
    if not isinstance(entry, dict) or not KEY_REQUIRED <= entry.keys() <= KEY_REQUIRED | KEY_OPTIONAL:
        raise RuleViolation("WIST1-E14", f"{where}: key entry members")
    if entry["kty"] != "OKP" or entry["crv"] != "Ed25519":
        raise RuleViolation("WIST1-E14", f"{where}: key type")
    if canonical_b64url(entry["x"], 32) is None:
        raise RuleViolation("WIST1-E14", f"{where}: x is not canonical base64url of 32 octets")
    if entry["kid"] != thumbprint(entry["x"]):
        raise RuleViolation("WIST1-E14", f"{where}: kid is not the thumbprint of x")
    for member in ("nbf", "exp"):
        if member in entry and not (is_integer(entry[member]) and 0 <= entry[member] <= NUMERIC_DATE_MAX):
            raise RuleViolation("WIST1-E14", f"{where}: {member} is not a NumericDate")
    if "exp" in entry and entry["exp"] <= entry["nbf"]:
        raise RuleViolation("WIST1-E14", f"{where}: exp not greater than nbf")


def check_key_array(value, where, nonempty):
    if not isinstance(value, list) or (nonempty and not value):
        raise RuleViolation("WIST1-E14", f"{where}: not a key array")
    for i, entry in enumerate(value):
        check_key_entry(entry, f"{where}[{i}]")


def check_publisher_fields(envelope):
    if not isinstance(envelope, dict) or set(envelope) != {"publisher", "sig"}:
        raise RuleViolation("WIST1-E14", "envelope members")
    sig = envelope["sig"]
    if not isinstance(sig, dict) or set(sig) != {"key_id", "alg", "value"}:
        raise RuleViolation("WIST1-E14", "sig members")
    if not isinstance(sig["key_id"], str) or len(sig["key_id"]) > 64 or sig["alg"] != "Ed25519":
        raise RuleViolation("WIST1-E14", "sig key_id or alg")
    if canonical_b64url(sig["value"], 64) is None:
        raise RuleViolation("WIST1-E14", "sig value is not canonical base64url of 64 octets")
    p = envelope["publisher"]
    if not isinstance(p, dict) or not PUBLISHER_REQUIRED <= p.keys() <= PUBLISHER_REQUIRED | PUBLISHER_OPTIONAL:
        raise RuleViolation("WIST1-E14", "publisher members")
    version = VERSION_PATTERN.fullmatch(p["wist_version"]) if isinstance(p["wist_version"], str) else None
    if version is None:
        raise RuleViolation("WIST1-E14", "wist_version")
    if version.group(1) != "1":
        raise RuleViolation("WIST1-E15", "unimplemented major version")
    if not is_canonical_host(p["domain"]):
        raise RuleViolation("WIST1-E14", "domain is not a Canonical Host")
    if not is_integer(p["seq"]) or not 0 <= p["seq"] <= SAFE_INTEGER_MAX:
        raise RuleViolation("WIST1-E14", "seq")
    for member in ("prev_declaration", "next_keys"):
        if member in p and not (isinstance(p[member], str) and HASH_PATTERN.fullmatch(p[member])):
            raise RuleViolation("WIST1-E14", member)
    if "subdomain_scope" in p and not (isinstance(p["subdomain_scope"], list)
                                       and all(is_canonical_host(h) for h in p["subdomain_scope"])):
        raise RuleViolation("WIST1-E14", "subdomain_scope")
    if "contact" in p and not (isinstance(p["contact"], str) and len(p["contact"]) <= 256):
        raise RuleViolation("WIST1-E14", "contact")
    check_key_array(p["keys"], "keys", nonempty=True)
    if "recovery_keys" in p:
        check_key_array(p["recovery_keys"], "recovery_keys", nonempty=False)


def authority_hosts(publisher):
    return {publisher["domain"], *publisher.get("subdomain_scope", [])}


def url_host(url):
    return urllib.parse.urlsplit(url).hostname


def check_collection_forms(publisher, parameters):
    collections = publisher["collections"]
    if not isinstance(collections, list) or not collections:
        raise RuleViolation("WIST1-E14", "collections is not an array of one or more objects")
    for i, collection in enumerate(collections):
        where = f"collections[{i}]"
        if not isinstance(collection, dict) or not (
                COLLECTION_REQUIRED <= collection.keys() <= COLLECTION_REQUIRED | COLLECTION_OPTIONAL):
            raise RuleViolation("WIST1-E14", f"{where}: members")
        name = collection["name"]
        if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
            raise RuleViolation("WIST1-E14", f"{where}: name")
        if "keys" in collection:
            check_key_array(collection["keys"], f"{where}.keys", nonempty=False)
        scope = collection["scope"]
        if not isinstance(scope, list) or not scope:
            raise RuleViolation("WIST1-E14", f"{where}: scope is not an array of one or more entries")
        for j, entry in enumerate(scope):
            spot = f"{where}.scope[{j}]"
            if not isinstance(entry, dict) or set(entry) != ENTRY_MEMBERS:
                raise RuleViolation("WIST1-E14", f"{spot}: members")
            if entry["match"] not in MATCHES:
                raise RuleViolation("WIST1-E14", f"{spot}: match")
            url = entry["url"]
            if not isinstance(url, str) or normalize_url(url, url) != url:
                raise RuleViolation("WIST1-E14", f"{spot}: url is not a Normalized URL")
            if len(rfc8785.dumps(url)) > parameters["url_cap_bytes"]:
                raise RuleViolation("WIST1-E14", f"{spot}: JCS(url) above url_cap_bytes")


def covers(entry, url):
    if entry["match"] == "exact":
        return url == entry["url"]
    return url.startswith(entry["url"])


def check_collection_semantics(publisher, parameters):
    collections = publisher["collections"]
    if len(collections) > parameters["collections_max"]:
        raise RuleViolation("WIST1-E16", "more Collections than collections_max")
    names = [c["name"] for c in collections]
    if len(set(names)) != len(names):
        raise RuleViolation("WIST1-E16", "repeated Collection name")
    hosts = authority_hosts(publisher)
    for collection in collections:
        if len(collection["scope"]) > parameters["scope_entries_max"]:
            raise RuleViolation("WIST1-E16", f"{collection['name']}: more entries than scope_entries_max")
        for entry in collection["scope"]:
            if url_host(entry["url"]) not in hosts:
                raise RuleViolation("WIST1-E16", f"{collection['name']}: entry host outside the authority")
    for a in collections:
        for b in collections:
            if a is b:
                continue
            for ea in a["scope"]:
                for eb in b["scope"]:
                    if covers(ea, eb["url"]):
                        raise RuleViolation(
                            "WIST1-E16", f"an entry of {a['name']} covers an entry of {b['name']}")


def listed_public_keys(publisher):
    out = [("keys", e) for e in publisher["keys"]]
    out += [("recovery_keys", e) for e in publisher.get("recovery_keys", [])]
    for collection in publisher.get("collections", []):
        out += [(("collection", collection["name"]), e) for e in collection.get("keys", [])]
    return out


def check_unique_keys(publisher):
    seen = set()
    for _, entry in listed_public_keys(publisher):
        raw = canonical_b64url(entry["x"], 32)
        if raw in seen:
            raise RuleViolation("WIST1-E08", "a public key is listed twice across keys, recovery_keys and Collections")
        seen.add(raw)


def parameter_map(parameters):
    parameters = {**DEFAULT_PARAMETERS, **(parameters or {})}
    for name, floor in COUNT_FLOORS.items():
        if parameters[name] < floor:
            raise ValueError(f"{name} is amended below {floor}")
    return parameters


def validate_declaration(envelope, parameters=None, read_parameters=True):
    parameters = parameter_map(parameters) if read_parameters else UNREAD_PARAMETERS
    check_publisher_fields(envelope)
    publisher = envelope["publisher"]
    if "collections" in publisher:
        check_collection_forms(publisher, parameters)
        check_collection_semantics(publisher, parameters)
    check_unique_keys(publisher)
    if read_parameters and entry_octets(envelope) > ENTRY_OCTETS_MAX:
        raise RuleViolation("WIST1-E04", "the publisher_declaration Entry is above 65 535 octets")


def declaration_disposition(envelope, parameters=None):
    try:
        validate_declaration(envelope, parameters)
    except RuleViolation as violation:
        return violation.code
    return "accepted"


def collections_of(publisher):
    if "collections" not in publisher:
        return [{"name": IMPLICIT_DEFAULT, "scope": None, "keys": []}]
    return [{"name": c["name"], "scope": c["scope"], "keys": c.get("keys", [])}
            for c in publisher["collections"]]


def collection_named(publisher, name):
    return next((c for c in collections_of(publisher) if c["name"] == name), None)


def scope_covers(publisher, collection, url):
    if collection["scope"] is None:
        return url_host(url) in authority_hosts(publisher)
    return any(covers(entry, url) for entry in collection["scope"])


def coverage(publisher, collection_name, url):
    normalized = normalize_url(url, url) if isinstance(url, str) else None
    collection = collection_named(publisher, collection_name)
    if normalized is None or collection is None:
        return False
    return scope_covers(publisher, collection, normalized)


def record_in_scope(publisher, collection_name, url):
    if not isinstance(url, str) or normalize_url(url, url) != url:
        return False
    return coverage(publisher, collection_name, url)


def binding_candidates(publisher, collection_name, key_id):
    sources = list(publisher["keys"])
    collection = collection_named(publisher, collection_name)
    if collection is not None:
        sources += collection["keys"]
    return [e for e in sources if e["kid"] == key_id]


def time_eligible(entry, instant):
    return entry["nbf"] <= instant and ("exp" not in entry or instant < entry["exp"])


def publication_disposition(declaration, probe_envelope):
    publisher = declaration["publisher"]
    probe = probe_envelope["probe"]
    sig = probe_envelope["sig"]
    instant = publisher_timestamp_seconds(probe["instant"])
    signature = canonical_b64url(sig["value"], 64)
    if instant is None or signature is None or sig["alg"] != "Ed25519":
        return "WIST1-E14"
    if probe["publisher"] != publisher["domain"]:
        return "WIST1-E02"
    candidates = [e for e in binding_candidates(publisher, probe["collection"], sig["key_id"])
                  if usable_point(canonical_b64url(e["x"], 32)) and time_eligible(e, instant)]
    if not candidates:
        return "WIST1-E02"
    message = rfc8785.dumps(probe)
    if not any(verifies(canonical_b64url(e["x"], 32), signature, message) for e in candidates):
        return "WIST1-E01"
    if not record_in_scope(publisher, probe["collection"], probe["url"]):
        return "WIST1-E03"
    return "accepted"


IMPLICIT_SCOPE_ENTRY = ("implicit", None)


def scope_entries(collection):
    if collection["scope"] is None:
        return {IMPLICIT_SCOPE_ENTRY}
    return {(e["url"], e["match"]) for e in collection["scope"]}


def keys_by_member(publisher):
    members = {"keys": {}, "recovery_keys": {}}
    for collection in collections_of(publisher):
        members[("collection", collection["name"])] = {}
    for member, entry in listed_public_keys(publisher):
        members[member][canonical_b64url(entry["x"], 32)] = entry
    return members


def window_shortened(before, after):
    if after["nbf"] > before["nbf"]:
        return True
    if "exp" not in after:
        return False
    return "exp" not in before or after["exp"] < before["exp"]


REDUCTION_BULLETS = ("key", "key_window", "collection", "scope_entry", "subdomain_scope")


def authority_reductions(predecessor, successor):
    found = []
    p_keys, d_keys = keys_by_member(predecessor), keys_by_member(successor)
    if any(not keys.keys() <= d_keys.get(member, {}).keys() for member, keys in p_keys.items()):
        found.append("key")
    if any(window_shortened(entry, d_keys[member][raw])
           for member, keys in p_keys.items() for raw, entry in keys.items()
           if raw in d_keys.get(member, {})):
        found.append("key_window")
    p_collections = {c["name"]: c for c in collections_of(predecessor)}
    d_collections = {c["name"]: c for c in collections_of(successor)}
    if not p_collections.keys() <= d_collections.keys():
        found.append("collection")
    if any(not scope_entries(c) <= (scope_entries(d_collections[name]) if name in d_collections else set())
           for name, c in p_collections.items()):
        found.append("scope_entry")
    if not set(predecessor.get("subdomain_scope", [])) <= set(successor.get("subdomain_scope", [])):
        found.append("subdomain_scope")
    return found


def reduces_authority(predecessor, successor):
    return bool(authority_reductions(predecessor, successor))


def last_seal_height(last_sealed_at_discovery, record_seal_epochs):
    return last_sealed_at_discovery + 1 + record_seal_epochs


FETCH_SUCCESSES = ("new_octets", "same_octets", "not_modified")
FETCH_FAILURES = ("failed", "timed_out")


def pull_proceeds(fetch_outcome):
    if fetch_outcome in FETCH_SUCCESSES:
        return True
    if fetch_outcome in FETCH_FAILURES:
        return False
    raise ValueError(fetch_outcome)
