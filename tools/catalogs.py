import math
import re
import time

import collection_rules as rules
import items

DEFAULT_PARAMETERS = {"clock_skew_seconds": 600, "catalog_items_max": items.CATALOG_ITEMS_MAX}
CATALOG_REFRESH_SECONDS = 604800
CATALOG_READ_OCTETS = 16384

ENVELOPE_MEMBERS = frozenset(("catalog", "sig"))
SIG_MEMBERS = frozenset(("key_id", "alg", "value"))
INNER_MEMBERS = frozenset(("wist_version", "publisher", "collection", "generated_at", "size", "root", "tree"))
LOG_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9]Z")


def log_seconds(value):
    if not isinstance(value, str) or not LOG_TIMESTAMP.fullmatch(value):
        return None
    return rules.publisher_timestamp_seconds(value)


def log_timestamp(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(seconds)))


def catalog_id(catalog):
    return items.catalog_id(catalog)


def check_envelope_form(envelope):
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_MEMBERS:
        raise items.Refused("WIST1-E14", "Envelope members")
    sig = envelope["sig"]
    if not isinstance(sig, dict) or set(sig) != SIG_MEMBERS:
        raise items.Refused("WIST1-E14", "sig members")
    if not isinstance(sig["key_id"], str) or len(sig["key_id"]) > 64 or sig["alg"] != "Ed25519":
        raise items.Refused("WIST1-E14", "sig key_id or alg")
    if rules.canonical_b64url(sig["value"], 64) is None:
        raise items.Refused("WIST1-E14", "sig value is not canonical base64url of 64 octets")
    catalog = envelope["catalog"]
    if not isinstance(catalog, dict) or set(catalog) != INNER_MEMBERS:
        raise items.Refused("WIST1-E14", "catalog members")
    if not isinstance(catalog["wist_version"], str) or not items.VERSION_PATTERN.fullmatch(catalog["wist_version"]):
        raise items.Refused("WIST1-E14", "wist_version")
    if not isinstance(catalog["publisher"], str) or not rules.is_canonical_host(catalog["publisher"]):
        raise items.Refused("WIST1-E14", "publisher is not a Canonical Host")
    if not isinstance(catalog["collection"], str) or not rules.NAME_PATTERN.fullmatch(catalog["collection"]):
        raise items.Refused("WIST1-E14", "collection is not a Collection name")
    if log_seconds(catalog["generated_at"]) is None:
        raise items.Refused("WIST1-E14", "generated_at is not in the whole-second profile")
    if not items.is_safe_integer(catalog["size"]):
        raise items.Refused("WIST1-E14", "size is not a nonnegative safe integer")
    for member in ("root", "tree"):
        if not isinstance(catalog[member], str) or not items.HASH_PATTERN.fullmatch(catalog[member]):
            raise items.Refused("WIST1-E14", member)


def binding(envelope, publisher):
    catalog, sig = envelope["catalog"], envelope["sig"]
    if catalog["publisher"] != publisher["domain"]:
        raise items.Refused("WIST1-E02", "a Declaration of another domain supplies no candidate")
    instant = log_seconds(catalog["generated_at"])
    candidates = [e for e in rules.binding_candidates(publisher, catalog["collection"], sig["key_id"])
                  if rules.usable_point(rules.canonical_b64url(e["x"], 32)) and rules.time_eligible(e, instant)]
    if not candidates:
        raise items.Refused("WIST1-E02", "no usable, time-eligible binding")
    signature = rules.canonical_b64url(sig["value"], 64)
    message = items.jcs(catalog)
    if not any(rules.verifies(rules.canonical_b64url(e["x"], 32), signature, message) for e in candidates):
        raise items.Refused("WIST1-E01", "no candidate verifies the signature")


def judge_catalog(envelope, publisher, clock, parameters):
    if isinstance(envelope, (bytes, bytearray)):
        try:
            envelope = items.strict_loads(envelope)
        except items.NotJcsInput as error:
            raise items.Refused("WIST1-E05", str(error))
    check_envelope_form(envelope)
    catalog = envelope["catalog"]
    if items.VERSION_PATTERN.fullmatch(catalog["wist_version"]).group(1) != "1":
        raise items.Refused("WIST1-E15", "unimplemented major version")
    if catalog["size"] > parameters["catalog_items_max"]:
        raise items.Refused("WIST1-E04", "size above catalog_items_max")
    if rules.collection_named(publisher, catalog["collection"]) is None:
        raise items.Refused("WIST1-E03", "a Collection the Declaration does not name")
    binding(envelope, publisher)
    if log_seconds(catalog["generated_at"]) > items.instant(clock) + parameters["clock_skew_seconds"]:
        raise items.Refused("WIST1-E06", "generated_at beyond the clock allowance")


def catalog_disposition(envelope, publisher, clock, parameters=None):
    parameters = {**DEFAULT_PARAMETERS, **(parameters or {})}
    try:
        judge_catalog(envelope, publisher, clock, parameters)
    except items.Refused as refused:
        return refused.code
    return "accepted"


def fetched_catalog_disposition(octets, publisher, clock, parameters=None):
    if len(octets) > CATALOG_READ_OCTETS:
        return "failed"
    return catalog_disposition(bytes(octets), publisher, clock, parameters)


def pull_order(fetched, fetched_for, last_accepted, latest=None):
    if fetched["publisher"] != fetched_for["publisher"] or fetched["collection"] != fetched_for["collection"]:
        return "WIST2-E04"
    if any(known is not None and catalog_id(fetched) == catalog_id(known) for known in (last_accepted, latest)):
        return "idempotent"
    if last_accepted is None:
        return "accepted"
    if log_seconds(fetched["generated_at"]) <= log_seconds(last_accepted["generated_at"]):
        return "WIST2-E05"
    return "accepted"


def next_generated_at(clock, served, clock_skew_seconds):
    now = math.floor(items.instant(clock))
    instant = now if served is None else max(now, log_seconds(served) + 1)
    if instant - now > clock_skew_seconds:
        return None
    return log_timestamp(instant)


def sign_list(clock, served_generated_at, clock_skew_seconds, served, served_payloads, publications, publisher,
              collection_name, salts, wist_version, parameters=None, removals=()):
    if items.rules.collection_named(publisher, collection_name) is None:
        return {"refused": "collection"}
    generated_at = next_generated_at(clock, served_generated_at, clock_skew_seconds)
    if generated_at is None:
        return {"refused": "catalog-instant"}
    derived = items.derive_list(served, served_payloads, publications, publisher, collection_name, generated_at,
                                salts, wist_version, parameters, removals=removals)
    if "refused" in derived:
        return derived
    return {"generated_at": generated_at, **derived}


def catalog_due(clock, served):
    if served is None:
        return True
    return math.floor(items.instant(clock)) >= log_seconds(served) + CATALOG_REFRESH_SECONDS
