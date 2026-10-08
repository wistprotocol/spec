import base64
import copy
import hashlib
import json
import pathlib
import re
import sys
import urllib.parse
from fractions import Fraction

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from link_extraction import normalize_url

ROOT = pathlib.Path(__file__).resolve().parent.parent

SAFE_INTEGER = 2 ** 53 - 1
NUMERIC_DATE_MAX = 253402300799
ENTRY_OCTETS_MAX = 65535
DEFAULT_PARAMETERS = {"collections_max": 16, "scope_entries_max": 32, "url_cap_bytes": 2048}
URI_PARTS = re.compile(r"(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?", re.DOTALL)
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")
PORT_SUFFIX = re.compile(r":[0-9]*\Z")
UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
REG_NAME = UNRESERVED + "!$&'()*+,;=" + "%"
PCHAR = REG_NAME + ":@"
URI_CHARACTERS = PCHAR + "/?#[]"
HEX_DIGITS = "0123456789ABCDEFabcdef"
UNAMENDED = {"recovery_window_days": 7, "declaration_activation_epochs": 24}


class Rejected(Exception):
    def __init__(self, code, why=""):
        super().__init__(f"{code} {why}".strip())
        self.code = code


class VerifierError(Exception):
    pass


def strict_load(path):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise VerifierError(f"{path.name}: repeated member {key!r}")
            out[key] = value
        return out

    def constant(name):
        raise VerifierError(f"{path.name}: non-JSON number {name}")

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def jcs(value):
    return rfc8785.dumps(value)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def declaration_hash(publisher):
    return "sha256:" + sha256_hex(jcs(publisher))


_B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def b64u_canonical(value, octets):
    if not isinstance(value, str) or not value or len(value) % 4 == 1:
        return None
    if any(ch not in _B64U for ch in value):
        return None
    number = 0
    for ch in value:
        number = (number << 6) | _B64U.index(ch)
    unused = len(value) * 6 % 8
    if number & ((1 << unused) - 1):
        return None
    raw = (number >> unused).to_bytes(len(value) * 6 // 8, "big")
    if len(raw) != octets:
        return None
    return raw


def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def thumbprint(x):
    return b64u_encode(hashlib.sha256(jcs({"crv": "Ed25519", "kty": "OKP", "x": x})).digest())


def keyset_fingerprint(entries):
    kids = sorted((entry["kid"] for entry in entries), key=lambda kid: kid.encode("utf-8"))
    return "sha256:" + sha256_hex(jcs(kids))


_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _decode_point(raw):
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        if sign:
            return None
        x = 0
    else:
        x = pow(x2, (_P + 3) // 8, _P)
        if (x * x - x2) % _P:
            x = x * _SQRT_M1 % _P
        if (x * x - x2) % _P:
            return None
        if x & 1 != sign:
            x = _P - x
    return (x, y, 1, x * y % _P)


def _add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _small_order(point):
    for _ in range(3):
        point = _add(point, point)
    x, y, z, _t = point
    return x % _P == 0 and (y - z) % _P == 0


def usable_public(raw):
    point = _decode_point(raw)
    return point is not None and not _small_order(point)


def signature_verifies(public_raw, signature_raw, message):
    if len(signature_raw) != 64:
        return False
    if int.from_bytes(signature_raw[32:], "little") >= _L:
        return False
    if not usable_public(public_raw) or not usable_public(signature_raw[:32]):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature_raw, message)
    except InvalidSignature:
        return False
    return True


def _days_from_civil(year, month, day):
    year -= month <= 2
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(days):
    days += 719468
    era = days // 146097
    doe = days - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + (3 if mp < 10 else -9)
    return yoe + era * 400 + (month <= 2), month, day


def _valid_date(year, month, day):
    if not 1 <= month <= 12 or day < 1:
        return False
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    length = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
    return day <= length


_PUBLISHER_TS = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]+))?(?:([Zz])|([+-])([0-9]{2}):([0-9]{2}))")


def publisher_instant(value):
    match = _PUBLISHER_TS.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise VerifierError(f"malformed Publisher timestamp {value!r}")
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    if not _valid_date(year, month, day) or hour > 23 or minute > 59 or second > 59:
        raise VerifierError(f"invalid Publisher timestamp {value!r}")
    instant = Fraction(_days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second)
    if match.group(7):
        instant += Fraction(int(match.group(7)), 10 ** len(match.group(7)))
    if match.group(9):
        off_h, off_m = int(match.group(10)), int(match.group(11))
        if off_h > 23 or off_m > 59:
            raise VerifierError(f"invalid offset {value!r}")
        offset = off_h * 3600 + off_m * 60
        instant -= offset if match.group(9) == "+" else -offset
    return instant


_LOG_TS = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")


def log_seconds(value):
    match = _LOG_TS.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise VerifierError(f"malformed Log timestamp {value!r}")
    year, month, day, hour, minute, second = (int(g) for g in match.groups())
    if not _valid_date(year, month, day) or hour > 23 or minute > 59 or second > 59:
        raise VerifierError(f"invalid Log timestamp {value!r}")
    return _days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second


def log_timestamp(seconds):
    days, rest = divmod(seconds, 86400)
    year, month, day = _civil_from_days(days)
    return f"{year:04d}-{month:02d}-{day:02d}T{rest // 3600:02d}:{rest % 3600 // 60:02d}:{rest % 60:02d}Z"


LOG_TIME_MAX = log_seconds("9999-12-31T23:59:59Z")


def _is_integer(value, low, high):
    if isinstance(value, bool):
        return False
    if isinstance(value, float):
        if not value.is_integer():
            return False
        value = int(value)
    return isinstance(value, int) and low <= value <= high and abs(value) <= SAFE_INTEGER




_HOST = re.compile(r"[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*")


def uri_form(candidate):
    scheme, authority, path, query, fragment = URI_PARTS.fullmatch(candidate).groups()
    if scheme is not None and not SCHEME.fullmatch(scheme):
        return False
    if authority is not None:
        if "@" in authority:
            return False
        host = PORT_SUFFIX.sub("", authority)
        literal = host.startswith("[") and host.endswith("]")
        if not all(ord(c) > 0x7F or c in (URI_CHARACTERS if literal else REG_NAME) for c in host):
            return False
    if any(c not in PCHAR + "/" for c in path):
        return False
    for part in (path, query, fragment):
        escapes = [part[i + 1:i + 3] for i, c in enumerate(part or "") if c == "%"]
        if any(len(digits) != 2 or any(d not in HEX_DIGITS for d in digits) for digits in escapes):
            return False
    return all(part is None or all(c in PCHAR + "/?" for c in part) for part in (query, fragment))


def normalized(candidate, base):
    return normalize_url(candidate, base) if uri_form(candidate) else None


def canonical_host(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 253 or not _HOST.fullmatch(value):
        return False
    if any(label.startswith("xn--") for label in value.split(".")):
        raise VerifierError(f"A-label host {value!r} needs UTS #46 processing this verifier does not implement")
    return True


_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_VERSION = re.compile(r"([0-9]+)\.([0-9]+)\.([0-9]+)")
_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")
_KEY_MEMBERS = {"kty", "crv", "x", "kid", "nbf", "exp"}
_PUBLISHER_MEMBERS = {"wist_version", "domain", "seq", "prev_declaration", "subdomain_scope", "keys",
                      "recovery_keys", "next_keys", "contact", "collections"}


def _e14(why):
    raise Rejected("WIST1-E14", why)


def _check_key_entry(entry):
    if not isinstance(entry, dict) or not {"kty", "crv", "x", "kid", "nbf"} <= set(entry) <= _KEY_MEMBERS:
        _e14("key entry members")
    if entry["kty"] != "OKP" or entry["crv"] != "Ed25519":
        _e14("key entry kty/crv")
    if b64u_canonical(entry["x"], 32) is None:
        _e14("key entry x")
    if b64u_canonical(entry["kid"], 32) is None or entry["kid"] != thumbprint(entry["x"]):
        _e14("kid is not the thumbprint of x")
    if not _is_integer(entry["nbf"], 0, NUMERIC_DATE_MAX):
        _e14("nbf")
    if "exp" in entry and (not _is_integer(entry["exp"], 1, NUMERIC_DATE_MAX) or entry["exp"] <= entry["nbf"]):
        _e14("exp")


def _check_key_array(value, nonempty):
    if not isinstance(value, list) or (nonempty and not value):
        _e14("key array")
    for entry in value:
        _check_key_entry(entry)


def _check_collections(value, parameters):
    if not isinstance(value, list) or not value:
        _e14("collections is not a nonempty array")
    for collection in value:
        if not isinstance(collection, dict) or not {"name", "scope"} <= set(collection) <= {"name", "scope", "keys"}:
            _e14("Collection members")
        if not isinstance(collection["name"], str) or not _NAME.fullmatch(collection["name"]):
            _e14("Collection name")
        scope = collection["scope"]
        if not isinstance(scope, list) or not scope:
            _e14("scope is not a nonempty array")
        for entry in scope:
            if not isinstance(entry, dict) or set(entry) != {"url", "match"}:
                _e14("Scope entry members")
            if entry["match"] not in ("prefix", "exact"):
                _e14("Scope entry match")
            url = entry["url"]
            if not isinstance(url, str) or normalized(url, url) != url:
                _e14("Scope entry url is not its own Normalized URL")
            if parameters is not None and len(jcs(url)) > parameters["url_cap_bytes"]:
                _e14("Scope entry url above url_cap_bytes")
        if "keys" in collection:
            _check_key_array(collection["keys"], nonempty=False)


def field_check(envelope, parameters):
    if not isinstance(envelope, dict) or set(envelope) != {"publisher", "sig"}:
        _e14("Envelope members")
    sig = envelope["sig"]
    if not isinstance(sig, dict) or set(sig) != {"key_id", "alg", "value"}:
        _e14("sig members")
    if not isinstance(sig["key_id"], str) or len(sig["key_id"]) > 64 or sig["alg"] != "Ed25519":
        _e14("sig key_id/alg")
    if b64u_canonical(sig["value"], 64) is None:
        _e14("sig value")
    publisher = envelope["publisher"]
    if not isinstance(publisher, dict) or not {"wist_version", "domain", "keys", "seq"} <= set(publisher) \
            or not set(publisher) <= _PUBLISHER_MEMBERS:
        _e14("publisher members")
    if not isinstance(publisher["wist_version"], str) or not _VERSION.fullmatch(publisher["wist_version"]):
        _e14("wist_version")
    if not canonical_host(publisher["domain"]):
        _e14("domain")
    if not _is_integer(publisher["seq"], 0, SAFE_INTEGER):
        _e14("seq")
    if "prev_declaration" in publisher and (
            not isinstance(publisher["prev_declaration"], str) or not _HASH.fullmatch(publisher["prev_declaration"])):
        _e14("prev_declaration")
    if "subdomain_scope" in publisher:
        hosts = publisher["subdomain_scope"]
        if not isinstance(hosts, list) or not all(canonical_host(host) for host in hosts):
            _e14("subdomain_scope")
    _check_key_array(publisher["keys"], nonempty=True)
    if "recovery_keys" in publisher:
        _check_key_array(publisher["recovery_keys"], nonempty=False)
    if "next_keys" in publisher and (
            not isinstance(publisher["next_keys"], str) or not _HASH.fullmatch(publisher["next_keys"])):
        _e14("next_keys")
    if "contact" in publisher and (not isinstance(publisher["contact"], str) or len(publisher["contact"]) > 256):
        _e14("contact")
    if "collections" in publisher:
        _check_collections(publisher["collections"], parameters)


def url_host(url):
    return urllib.parse.urlsplit(url).hostname


def authority(publisher):
    return {publisher["domain"], *publisher.get("subdomain_scope", [])}


def entry_covers(entry, url):
    if entry["match"] == "exact":
        return url.encode("utf-8") == entry["url"].encode("utf-8")
    return url.encode("utf-8").startswith(entry["url"].encode("utf-8"))


def collection_named(publisher, name):
    for collection in publisher.get("collections", []):
        if collection["name"] == name:
            return collection
    return None


def collection_names(publisher):
    if "collections" not in publisher:
        return ["default"]
    return [collection["name"] for collection in publisher["collections"]]


def public_raw(entry):
    return b64u_canonical(entry["x"], 32)


def semantic_check(envelope, parameters):
    publisher = envelope["publisher"]
    if int(_VERSION.fullmatch(publisher["wist_version"]).group(1)) != 1:
        raise Rejected("WIST1-E15", "unsupported major")
    collections = publisher.get("collections")
    if collections is not None:
        names = [collection["name"] for collection in collections]
        if len(names) != len(set(names)):
            raise Rejected("WIST1-E16", "repeated Collection name")
        if parameters is not None and len(collections) > parameters["collections_max"]:
            raise Rejected("WIST1-E16", "above collections_max")
        if parameters is not None and any(
                len(collection["scope"]) > parameters["scope_entries_max"] for collection in collections):
            raise Rejected("WIST1-E16", "above scope_entries_max")
        hosts = authority(publisher)
        for collection in collections:
            for entry in collection["scope"]:
                if url_host(entry["url"]) not in hosts:
                    raise Rejected("WIST1-E16", "Scope entry host outside the authority")
        for i, first in enumerate(collections):
            for j, second in enumerate(collections):
                if i == j:
                    continue
                for a in first["scope"]:
                    for b in second["scope"]:
                        if entry_covers(a, b["url"]):
                            raise Rejected("WIST1-E16", "an entry of one Collection covers an entry of another")
    listed = [public_raw(entry) for entry in publisher["keys"] + publisher.get("recovery_keys", [])]
    for collection in collections or []:
        listed += [public_raw(entry) for entry in collection.get("keys", [])]
    if len(listed) != len(set(listed)):
        raise Rejected("WIST1-E08", "a public key listed twice")
    if parameters is not None and len(jcs({"type": "publisher_declaration", "body": envelope})) > ENTRY_OCTETS_MAX:
        raise Rejected("WIST1-E04", "publisher_declaration Entry above 65 535 octets")


def validate(envelope, parameters):
    field_check(envelope, parameters)
    semantic_check(envelope, parameters)


def resolve_signer(envelope, predecessor):
    key_id = envelope["sig"]["key_id"]
    sources = list(envelope["publisher"]["keys"])
    if predecessor is not None:
        sources = predecessor["keys"] + predecessor.get("recovery_keys", []) + sources
    candidates = {public_raw(entry) for entry in sources if entry["kid"] == key_id}
    candidates = {raw for raw in candidates if usable_public(raw)}
    if not candidates:
        raise Rejected("WIST1-E02", "no usable Declaration signer candidate")
    signature = b64u_canonical(envelope["sig"]["value"], 64)
    message = jcs(envelope["publisher"])
    verified = [raw for raw in candidates if signature_verifies(raw, signature, message)]
    if not verified:
        raise Rejected("WIST1-E01", "no candidate verifies the Declaration")
    if len(verified) != 1:
        raise VerifierError("one kid resolved to two verifying keys")
    return verified[0]


def classify(envelope, predecessor):
    signer = resolve_signer(envelope, predecessor)
    incoming = envelope["publisher"]
    if signer in {public_raw(entry) for entry in predecessor["keys"]}:
        result = "ordinary_rotation"
    elif signer in {public_raw(entry) for entry in predecessor.get("recovery_keys", [])}:
        result = "recovery_rotation"
    else:
        result = "fresh_identity"
    protected = predecessor.get("recovery_keys", [])
    if result != "recovery_rotation" and protected:
        if "recovery_keys" not in incoming or jcs(incoming["recovery_keys"]) != jcs(protected):
            raise Rejected("WIST1-E08", "recovery_keys changed without a recovery signature")
    if result == "ordinary_rotation" and "next_keys" in predecessor:
        kept = ({e["kid"] for e in predecessor["keys"]} == {e["kid"] for e in incoming["keys"]}
                and incoming.get("next_keys") == predecessor["next_keys"])
        if not kept and keyset_fingerprint(incoming["keys"]) != predecessor["next_keys"]:
            raise Rejected("WIST1-E08", "ordinary rotation outside the next_keys commitment")
    return result


def check_prev_presence(publisher):
    if ("prev_declaration" in publisher) != (publisher["seq"] > 0):
        raise Rejected("WIST1-E08", "prev_declaration presence does not match seq")


def standalone(envelope, parameters):
    try:
        validate(envelope, parameters)
        check_prev_presence(envelope["publisher"])
        resolve_signer(envelope, None)
        return "accepted"
    except Rejected as rejection:
        return rejection.code


def require_accepted(envelope, parameters):
    outcome = standalone(envelope, parameters)
    if outcome != "accepted":
        raise VerifierError(f"fixture Declaration is not accepted: {outcome}")


def scope_verdict(publisher, collection, url):
    if not isinstance(url, str) or normalized(url, url) != url:
        return "WIST1-E03"
    if "collections" not in publisher:
        if collection != "default" or url_host(url) not in authority(publisher):
            return "WIST1-E03"
        return None
    own = collection_named(publisher, collection)
    if own is None or not any(entry_covers(entry, url) for entry in own["scope"]):
        return "WIST1-E03"
    for other in publisher["collections"]:
        if other is not own and any(entry_covers(entry, url) for entry in other["scope"]):
            return "WIST1-E03"
    if url_host(url) not in authority(publisher):
        return "WIST1-E03"
    return None


def covers(publisher, collection, url):
    normalized_url = normalized(url, url) if isinstance(url, str) else None
    if normalized_url is None:
        return False
    if "collections" not in publisher:
        return collection == "default" and url_host(normalized_url) in authority(publisher)
    own = collection_named(publisher, collection)
    return own is not None and any(entry_covers(entry, normalized_url) for entry in own["scope"])


def judge_probe(declaration, probe):
    publisher = declaration["publisher"]
    if not isinstance(probe, dict) or set(probe) != {"probe", "sig"}:
        raise VerifierError("probe Envelope members")
    inner, sig = probe["probe"], probe["sig"]
    if set(inner) != {"publisher", "collection", "url", "instant"}:
        raise VerifierError("probe members")
    if not isinstance(sig, dict) or set(sig) != {"key_id", "alg", "value"} or sig["alg"] != "Ed25519":
        return "WIST1-E14"
    signature = b64u_canonical(sig["value"], 64)
    if signature is None:
        return "WIST1-E14"
    if inner["publisher"] != publisher["domain"]:
        return "WIST1-E02"
    instant = publisher_instant(inner["instant"])
    bindings = list(publisher["keys"])
    named = collection_named(publisher, inner["collection"])
    if named is not None:
        bindings += named.get("keys", [])
    eligible = [entry for entry in bindings
                if entry["kid"] == sig["key_id"] and usable_public(public_raw(entry))
                and entry["nbf"] <= instant and ("exp" not in entry or instant < entry["exp"])]
    if not eligible:
        return "WIST1-E02"
    message = jcs(inner)
    if not any(signature_verifies(public_raw(entry), signature, message) for entry in eligible):
        return "WIST1-E01"
    return scope_verdict(publisher, inner["collection"], inner["url"]) or "accepted"


def new_state():
    return {"decls": {}, "current": None, "pending": None, "activation": None, "window": None, "floor": None}


def state_with_current(envelope, label="known"):
    state = new_state()
    state["decls"][label] = envelope
    state["current"] = label
    state["floor"] = envelope["publisher"]["seq"]
    return state


def _pub(state, label):
    return state["decls"][label]["publisher"]


def check_parameter_map(parameters):
    # ADR-0051 Size: no Log amends collections_max below 16 or scope_entries_max below 32.
    if parameters["collections_max"] < 16 or parameters["scope_entries_max"] < 32:
        raise VerifierError(f"a parameter map amends a count below its suite value: {parameters}")
    return parameters


def repeats_head(state, envelopes):
    publisher_bytes = [jcs(member["publisher"]) for member in envelopes]
    for head in (state["current"], state["pending"]):
        if head is not None and all(item == jcs(_pub(state, head)) for item in publisher_bytes):
            return True
    return False


def apply_group(state, labels, height, sealed_at, parameters, sizes=None):
    envelopes = [state["decls"][label] for label in labels]
    label, envelope = labels[0], envelopes[0]
    for member in envelopes:
        field_check(member, None)
    incoming = envelope["publisher"]
    for member in envelopes[1:]:
        if member["publisher"]["domain"] != incoming["domain"]:
            raise VerifierError("one group spans two domains")
    if state["current"] is not None:
        if incoming["domain"] != _pub(state, state["current"])["domain"]:
            raise VerifierError("a Declaration of another domain")
        # ADR-0051 Size: a repeat of the current Declaration or the pending head is idempotent under any map.
        if repeats_head(state, envelopes):
            return {"kind": "idempotent", "declaration": label, "class": "idempotent"}
    sizes = parameters if sizes is None else sizes
    for member in envelopes:
        field_check(member, sizes or None)
    if any(jcs(member) != jcs(envelope) for member in envelopes[1:]):
        raise Rejected("WIST1-E08", "conflicting same-sequence Declaration group")
    semantic_check(envelope, sizes or None)
    prior = state["current"]
    if state["current"] is None:
        check_prev_presence(incoming)
        resolve_signer(envelope, None)
        state["current"], state["floor"] = label, incoming["seq"]
        return {"kind": "initial", "declaration": label, "class": "initial"}
    check_prev_presence(incoming)
    if incoming["seq"] <= state["floor"]:
        raise Rejected("WIST1-E08", "seq not above the accepted floor")
    eligible = [state["current"]]
    if state["pending"] is not None:
        eligible.append(state["pending"])
    if state["window"] is not None:
        eligible.append(state["window"]["head"])
    named = [head for head in eligible if declaration_hash(_pub(state, head)) == incoming["prev_declaration"]]
    if not named:
        raise Rejected("WIST1-E08", "prev_declaration names no eligible predecessor")
    predecessor = named[0]
    result = classify(envelope, _pub(state, predecessor))
    state["floor"] = incoming["seq"]
    if state["window"] is not None:
        state["current"] = label
        if predecessor == state["window"]["head"] and result in ("ordinary_rotation", "recovery_rotation"):
            state["window"]["head"] = label
            return {"kind": "in_window_chain", "declaration": label, "class": result}
        return {"kind": "in_window_competitor", "declaration": label, "class": result}
    if state["pending"] is not None:
        if predecessor == state["pending"]:
            state["pending"] = label
            return {"kind": "pending_replacement", "declaration": label, "class": result}
        if result == "fresh_identity":
            raise Rejected("WIST1-E08", "fresh identity naming the current Declaration beside a pending head")
        state["pending"], state["activation"] = None, None
        state["current"] = label
        if result == "recovery_rotation":
            open_recovery_window(state, label, prior, sealed_at, parameters)
        return {"kind": "reversal_" + result, "declaration": label, "class": result,
                "narrows": result == "ordinary_rotation"}
    if result == "fresh_identity":
        state["pending"] = label
        state["activation"] = None if height is None else height + parameters["declaration_activation_epochs"]
        return {"kind": "fresh_identity_pending", "declaration": label, "class": result}
    state["current"] = label
    if result == "recovery_rotation":
        open_recovery_window(state, label, prior, sealed_at, parameters)
        return {"kind": "recovery_rotation", "declaration": label, "class": result}
    return {"kind": "ordinary_rotation", "declaration": label, "class": result, "narrows": True}


def open_window(state, label, sealed_at, parameters):
    window = {"end": None, "head": label, "owner": label}
    if sealed_at is not None:
        window["end"] = sealed_at + parameters["recovery_window_days"] * 86400
        if window["end"] > LOG_TIME_MAX:
            raise Rejected("WIST1-E08", "recovery window would end after the last Log instant")
    state["window"] = window


def open_recovery_window(state, label, before, sealed_at, parameters):
    open_window(state, label, sealed_at, parameters)
    state["window"]["before"] = before


def record_key(record):
    return (record["url"].encode("utf-8"), record["collection"].encode("utf-8"))


def narrow(live, publisher):
    removed = []
    for url, (collection, sealed_height) in list(live.items()):
        if "collections" in publisher:
            named = collection_named(publisher, collection)
            stays = named is not None and any(entry_covers(entry, url) for entry in named["scope"])
        else:
            stays = collection == "default"
        if not stays:
            removed.append({"url": url, "collection": collection, "sealed_height": sealed_height})
            del live[url]
    return sorted(removed, key=record_key)


def epoch_parameters(history, epoch):
    return check_parameter_map({**UNAMENDED, **history.get("parameters", {}), **epoch.get("parameters", {})})


def settle_due(state, sealed_at, live, transitions):
    window = state["window"]
    if window is not None and window["end"] is not None and sealed_at >= window["end"]:
        head = window["head"]
        state["current"], state["window"] = head, None
        transitions.append({"kind": "settlement", "declaration": head, "narrows": True,
                            "removed": narrow(live, _pub(state, head))})


def apply_epoch(state, epoch, parameters, live):
    height, sealed_at = epoch["height"], log_seconds(epoch["sealed_at"])
    transitions = []
    settle_due(state, sealed_at, live, transitions)
    activate_due(state, height, live, transitions)
    groups = {}
    for label in epoch["declarations"]:
        groups.setdefault(state["decls"][label]["publisher"]["seq"], []).append(label)
    for seq in sorted(groups):
        outcome = apply_group(state, groups[seq], height, sealed_at, parameters)
        narrows = outcome.get("narrows", False)
        transitions.append({"kind": outcome["kind"], "declaration": outcome["declaration"], "narrows": narrows,
                            "removed": narrow(live, _pub(state, outcome["declaration"])) if narrows else []})
        activate_due(state, height, live, transitions)
    sealed, rejected = [], []
    for record in epoch["records"]:
        members_read(record, {"url", "collection"})
        if state["window"] is not None:
            raise VerifierError("a record sealed inside an open recovery window")
        if state["current"] is None:
            raise VerifierError("a record sealed before any Declaration")
        code = scope_verdict(_pub(state, state["current"]), record["collection"], record["url"])
        if code:
            rejected.append({"url": record["url"], "collection": record["collection"], "code": code})
        else:
            live[record["url"]] = (record["collection"], height)
            sealed.append({"url": record["url"], "collection": record["collection"]})
    return {
        "height": height,
        "current_declaration": state["current"],
        "pending_head": state["pending"],
        "activation_height": state["activation"],
        "window_end": None if state["window"] is None or state["window"]["end"] is None
        else log_timestamp(state["window"]["end"]),
        "transitions": transitions,
        "records_sealed": sorted(sealed, key=record_key),
        "records_rejected": sorted(rejected, key=record_key),
    }


def replay_epochs(state, history, epoch_members, live):
    produced = []
    previous_height = None
    for epoch in history["epochs"]:
        members_read(epoch, epoch_members)
        if previous_height is not None and epoch["height"] != previous_height + 1:
            raise VerifierError("Epoch heights are not consecutive")
        previous_height = epoch["height"]
        trial_state, trial_live = copy.deepcopy(state), dict(live)
        try:
            produced.append(apply_epoch(trial_state, epoch, epoch_parameters(history, epoch), trial_live))
        except Rejected as rejection:
            return produced, {"height": epoch["height"], "code": rejection.code}
        state.update(trial_state)
        live.clear()
        live.update(trial_live)
    return produced, None


def replay(history, epoch_members):
    state = new_state()
    state["decls"] = dict(history["declarations"])
    live = {}
    produced, rejected = replay_epochs(state, history, epoch_members, live)
    live_records = sorted(({"url": url, "collection": collection, "sealed_height": sealed_height}
                           for url, (collection, sealed_height) in live.items()), key=record_key)
    return {"epochs": produced, "live_records": live_records, "rejected": rejected}


def activate_due(state, height, live, transitions):
    if state["pending"] is not None and state["activation"] == height:
        head = state["pending"]
        state["current"], state["pending"], state["activation"] = head, None, None
        transitions.append({"kind": "activation", "declaration": head, "narrows": True,
                            "removed": narrow(live, _pub(state, head))})


def pull(case):
    known = case["known"]
    validate(known, DEFAULT_PARAMETERS)
    if case["fetch_outcome"] in ("failed", "timed_out"):
        return "not_fetched", False, []
    if case["fetch_outcome"] == "not_modified":
        return "idempotent", True, collection_names(known["publisher"])
    if case["fetch_outcome"] not in ("same_octets", "new_octets"):
        raise VerifierError(f"unknown fetch outcome {case['fetch_outcome']!r}")
    state = state_with_current(known)
    state["decls"]["fetched"] = case["fetched"]
    try:
        outcome = apply_group(state, ["fetched"], None, None, DEFAULT_PARAMETERS)
    except Rejected as rejection:
        return rejection.code, False, []
    result = outcome["class"]
    if result == "ordinary_rotation":
        return result, True, collection_names(case["fetched"]["publisher"])
    if result == "recovery_rotation":
        names = collection_names(known["publisher"])
        names += [name for name in collection_names(case["fetched"]["publisher"]) if name not in names]
        return result, True, names
    return result, True, collection_names(known["publisher"])


def fetch_declaration(state, label, height, sealed_at, parameters):
    envelope = state["decls"][label]
    field_check(envelope, None)
    if state["current"] is not None and repeats_head(state, [envelope]):
        return "idempotent"
    window = state["window"]
    # ADR-0051 Reaching the Log: the recovery-chain head of the admission window, open from the
    # discovery of the recovery rotation, served again changes no source.
    if window is not None and jcs(envelope["publisher"]) == jcs(_pub(state, window["head"])):
        return "recovery_chain_head"
    return apply_group(state, [label], height, sealed_at, parameters)["kind"]


def pull_sources(state):
    window = state["window"]
    if window is not None:
        return [window["before"], window["owner"]]
    return [state["current"]]


def pulled_collections(state, sources):
    names = []
    for label in sources:
        names += [name for name in collection_names(_pub(state, label)) if name not in names]
    return names


def state_pull(case):
    state = new_state()
    state["decls"] = dict(case["declarations"])
    live = {}
    if set(case.get("history_parameters", {})) - set(UNAMENDED):
        raise VerifierError("history_parameters carries a member this verifier does not read")
    replayed = {"epochs": case["epochs"], "parameters": case.get("history_parameters", {})}
    epochs, rejected = replay_epochs(state, replayed, STATE_PULL_EPOCH_MEMBERS, live)
    if rejected is not None:
        raise VerifierError(f"a supplied Epoch is rejected: {rejected}")
    request = case["pull"]
    members_read(request, {"height", "sealed_at", "parameters", "fetch_outcome", "fetched"})
    if epochs and request["height"] != epochs[-1]["height"] + 1:
        raise VerifierError("the pull is not at the height after the supplied Epochs")
    history = {"parameters": case.get("history_parameters", {})}
    parameters = epoch_parameters(history, request)
    admission = epoch_parameters(history, case["epochs"][-1]) if case["epochs"] else parameters
    for label in case["discovered"]:
        trial = copy.deepcopy(state)
        try:
            apply_group(trial, [label], None, None, admission, sizes={})
        except Rejected:
            continue
        state.update(trial)
    first_contact = state["current"] is None
    transitions = []
    settle_due(state, log_seconds(request["sealed_at"]), live, transitions)
    stopped = {"proceeds": False, "sources": [], "collections_pulled": [],
               "disposition": "WIST2-E04" if first_contact else "WIST2-E01", "noise": first_contact}
    outcome = request["fetch_outcome"]
    if outcome in ("failed", "timed_out"):
        if request["fetched"] is not None:
            raise VerifierError("a failed fetch names a Declaration")
        return {"acceptance": "not_fetched", **stopped}
    if outcome not in ("new_octets", "same_octets", "not_modified"):
        raise VerifierError(f"unknown fetch outcome {outcome!r}")
    try:
        acceptance = fetch_declaration(state, request["fetched"], request["height"],
                                       log_seconds(request["sealed_at"]), parameters)
    except Rejected as rejection:
        return {"acceptance": rejection.code, **stopped}
    sources = pull_sources(state)
    return {"acceptance": acceptance, "proceeds": True, "sources": sources,
            "collections_pulled": pulled_collections(state, sources), "disposition": None, "noise": False}


_IMPLICIT_ENTRY = ("implicit", "default")


def _members(publisher):
    members = {"keys": publisher["keys"], "recovery_keys": publisher.get("recovery_keys", [])}
    for name in collection_names(publisher):
        named = collection_named(publisher, name)
        members["collection:" + name] = named.get("keys", []) if named else []
    return members


def _scopes(publisher):
    if "collections" not in publisher:
        return {"default": [_IMPLICIT_ENTRY]}
    return {c["name"]: [(e["url"], e["match"]) for e in c["scope"]] for c in publisher["collections"]}


def reductions(predecessor, declaration):
    p_members, d_members = _members(predecessor), _members(declaration)
    found = []
    key_removed = key_window = False
    for member, entries in p_members.items():
        listed = {public_raw(entry): entry for entry in d_members.get(member, [])}
        for entry in entries:
            other = listed.get(public_raw(entry))
            if other is None:
                key_removed = True
                continue
            if other["nbf"] > entry["nbf"] or ("exp" in other and ("exp" not in entry or other["exp"] < entry["exp"])):
                key_window = True
    if key_removed:
        found.append("key")
    if key_window:
        found.append("key_window")
    p_scopes, d_scopes = _scopes(predecessor), _scopes(declaration)
    if any(name not in d_scopes for name in p_scopes):
        found.append("collection")
    if any(entry not in d_scopes.get(name, []) for name, entries in p_scopes.items() for entry in entries):
        found.append("scope_entry")
    if any(host not in declaration.get("subdomain_scope", []) for host in predecessor.get("subdomain_scope", [])):
        found.append("subdomain_scope")
    return found


HISTORY_EPOCH_MEMBERS = {"height", "sealed_at", "declarations", "records"}
PARAMETER_EPOCH_MEMBERS = HISTORY_EPOCH_MEMBERS | {"parameters"}
STATE_PULL_EPOCH_MEMBERS = PARAMETER_EPOCH_MEMBERS
DOCUMENTATION = {"note", "parameter_note", "state_pull_note"}
OPTIONAL_MEMBERS = {"state_pull_cases": {"history_parameters"}}
FILE_ARRAYS = {
    "collection-fields": {"cases": {"name", "envelope", "parameters", "expected"}},
    "collection-scope": {
        "coverage_cases": {"name", "declaration", "collection", "url", "covered"},
        "disjointness_cases": {"name", "envelope", "parameters", "expected"},
        "publication_cases": {"name", "declaration", "probe", "expected"},
    },
    "collection-keys": {
        "uniqueness_cases": {"name", "envelope", "parameters", "expected"},
        "publication_cases": {"name", "declaration", "probe", "expected"},
        "signer_cases": {"name", "stored", "fetched", "expected"},
        "commitment_cases": {"name", "stored", "fetched", "expected"},
        "fingerprint_cases": {"name", "publisher", "fingerprint"},
    },
    "collection-narrowing": {
        "histories": {"name", "why", "parameters", "declarations", "epochs", "expected"},
        "parameter_histories": {"name", "why", "declarations", "epochs", "expected"},
    },
    "declaration-pull": {
        "pull_cases": {"name", "known", "fetch_outcome", "fetched", "acceptance", "proceeds", "collections_pulled"},
        "reduction_cases": {"name", "predecessor", "declaration", "last_sealed_at_discovery", "record_seal_epochs",
                            "reduces_authority", "reductions", "last_seal_height"},
        "state_pull_cases": {"name", "declarations", "epochs", "discovered", "pull", "expected"},
    },
}


def members_read(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        found = set(value) if isinstance(value, dict) else set()
        raise VerifierError(f"members {sorted(found ^ set(expected))} differ from those this verifier reads")


def check_file_members(family, data):
    arrays = FILE_ARRAYS[family]
    members_read(data, set(arrays) | {"keys", "note"} | (DOCUMENTATION & set(data)))
    for name, members in arrays.items():
        for case in data[name]:
            members_read(case, members | (OPTIONAL_MEMBERS.get(name, set()) & set(case)))
    for key in data["keys"].values():
        members_read(key, {"seed_hex", "x", "kid"})
    return sum(len(data[name]) for name in arrays)


def check_keys_block(data, failures):
    for name, key in data.get("keys", {}).items():
        raw = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key["seed_hex"])).public_key().public_bytes_raw()
        if b64u_encode(raw) != key["x"]:
            failures.append((f"keys.{name}", f"x is not derived from its seed: {key['x']}"))
        if thumbprint(key["x"]) != key["kid"]:
            failures.append((f"keys.{name}", f"kid is not the thumbprint of x: {key['kid']}"))


def compare(failures, label, expected, actual):
    if expected != actual:
        failures.append((label, f"expected {json.dumps(expected)}, got {json.dumps(actual)}"))


def run_case(failures, label, fn):
    try:
        fn()
    except (VerifierError, Rejected, KeyError, TypeError, ValueError) as error:
        failures.append((label, f"{type(error).__name__}: {error}"))


def family_fields(data, failures):
    for case in data["cases"]:
        run_case(failures, case["name"], lambda c=case: compare(
            failures, c["name"], c["expected"], standalone(c["envelope"], check_parameter_map(c["parameters"]))))


def family_scope(data, failures):
    for case in data["coverage_cases"]:
        def one(c=case):
            require_accepted(c["declaration"], DEFAULT_PARAMETERS)
            compare(failures, c["name"], c["covered"], covers(c["declaration"]["publisher"], c["collection"], c["url"]))
        run_case(failures, case["name"], one)
    for case in data["disjointness_cases"]:
        run_case(failures, case["name"], lambda c=case: compare(
            failures, c["name"], c["expected"], standalone(c["envelope"], check_parameter_map(c["parameters"]))))
    publication_cases(data["publication_cases"], failures)


def publication_cases(cases, failures):
    for case in cases:
        def one(c=case):
            require_accepted(c["declaration"], DEFAULT_PARAMETERS)
            compare(failures, c["name"], c["expected"], judge_probe(c["declaration"], c["probe"]))
        run_case(failures, case["name"], one)


def family_keys(data, failures):
    for case in data["uniqueness_cases"]:
        run_case(failures, case["name"], lambda c=case: compare(
            failures, c["name"], c["expected"], standalone(c["envelope"], check_parameter_map(c["parameters"]))))
    publication_cases(data["publication_cases"], failures)
    for case in data["signer_cases"] + data["commitment_cases"]:
        def one(c=case):
            require_accepted(c["stored"], DEFAULT_PARAMETERS)
            state = state_with_current(c["stored"])
            state["decls"]["fetched"] = c["fetched"]
            try:
                actual = apply_group(state, ["fetched"], None, None, DEFAULT_PARAMETERS)["class"]
            except Rejected as rejection:
                actual = rejection.code
            compare(failures, c["name"], c["expected"], actual)
        run_case(failures, case["name"], one)
    for case in data["fingerprint_cases"]:
        def one(c=case):
            publisher = c["publisher"]["publisher"] if "sig" in c["publisher"] else c["publisher"]
            compare(failures, c["name"], c["fingerprint"], keyset_fingerprint(publisher["keys"]))
        run_case(failures, case["name"], one)


def compare_replay(failures, name, expected, actual, members):
    if set(expected) != members:
        raise VerifierError(f"expected members {sorted(expected)} differ from {sorted(members)}")
    if len(expected["epochs"]) != len(actual["epochs"]):
        failures.append((name, f"Epoch count differs: expected {len(expected['epochs'])}, got {len(actual['epochs'])}"))
        return
    for want, got in zip(expected["epochs"], actual["epochs"]):
        for field in want.keys() | got.keys():
            if want.get(field) != got.get(field):
                failures.append((name, f"height {want.get('height')} {field}: expected "
                                 f"{json.dumps(want.get(field))}, got {json.dumps(got.get(field))}"))
                return
    for field in sorted(members - {"epochs"}):
        compare(failures, f"{name} {field}", expected[field], actual[field])


def family_narrowing(data, failures):
    for history in data["histories"]:
        def one(h=history):
            check_parameter_map(h["parameters"])
            actual = replay(h, HISTORY_EPOCH_MEMBERS)
            if actual["rejected"] is not None:
                raise VerifierError(f"an Epoch is rejected: {actual['rejected']}")
            compare_replay(failures, h["name"], h["expected"], actual, {"epochs", "live_records"})
        run_case(failures, history["name"], one)
    for history in data["parameter_histories"]:
        run_case(failures, history["name"], lambda h=history: compare_replay(
            failures, h["name"], h["expected"], replay(h, PARAMETER_EPOCH_MEMBERS), {"epochs", "rejected"}))


def family_pull(data, failures):
    for case in data["pull_cases"]:
        run_case(failures, case["name"], lambda c=case: compare(
            failures, c["name"],
            {"acceptance": c["acceptance"], "proceeds": c["proceeds"], "collections_pulled": c["collections_pulled"]},
            dict(zip(("acceptance", "proceeds", "collections_pulled"), pull(c)))))
    for case in data["reduction_cases"]:
        def one(c=case):
            predecessor, declaration = c["predecessor"], c["declaration"]
            require_accepted(predecessor, DEFAULT_PARAMETERS)
            validate(declaration, DEFAULT_PARAMETERS)
            if declaration["publisher"].get("prev_declaration") != declaration_hash(predecessor["publisher"]):
                raise VerifierError("the Declaration does not name the predecessor")
            found = reductions(predecessor["publisher"], declaration["publisher"])
            # WIST-1 section 5.2: counted from the first Epoch sealed after the discovery.
            last = c["last_sealed_at_discovery"] + 1 + c["record_seal_epochs"] if found else None
            compare(failures, c["name"],
                    {"reduces_authority": c["reduces_authority"], "reductions": c["reductions"],
                     "last_seal_height": c["last_seal_height"]},
                    {"reduces_authority": bool(found), "reductions": found, "last_seal_height": last})
        run_case(failures, case["name"], one)
    for case in data["state_pull_cases"]:
        run_case(failures, case["name"], lambda c=case: compare(failures, c["name"], c["expected"], state_pull(c)))


FAMILIES = [
    ("collection-fields", "wist1/collection-fields.json", family_fields),
    ("collection-scope", "wist1/collection-scope.json", family_scope),
    ("collection-keys", "wist1/collection-keys.json", family_keys),
    ("collection-narrowing", "wist1/collection-narrowing.json", family_narrowing),
    ("declaration-pull", "wist2/declaration-pull.json", family_pull),
]


def main(argv):
    sys.set_int_max_str_digits(0)
    base = pathlib.Path(argv[1]) if len(argv) > 1 else ROOT / "vectors"
    failed = False
    for family, relative, check in FAMILIES:
        failures = []
        count = 0
        try:
            data = strict_load(base / relative)
            count = check_file_members(family, data)
            check_keys_block(data, failures)
            check(data, failures)
        except (OSError, VerifierError, KeyError, TypeError, ValueError) as error:
            failures.append(("file", f"{type(error).__name__}: {error}"))
        if failures:
            failed = True
            label, what = failures[0]
            more = f" (+{len(failures) - 1} more)" if len(failures) > 1 else ""
            print(f"FAIL {family}: {count} cases: {label}: {what}{more}")
        else:
            print(f"PASS {family}: {count} cases recomputed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
