import copy
import hashlib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from verify_collection_vectors import (
    Rejected, VerifierError, apply_group, b64u_canonical, canonical_host, check_keys_block, check_parameter_map,
    collection_names, log_seconds, log_timestamp, narrow, publisher_instant, signature_verifies, strict_load,
    validate)
from verify_catalog_vectors import (
    ACCEPTED, BODY_MEMBERS, E14, HASH, NAME, PAGE_MEMBERS, REGISTRY_SIZE_CAPS, REMOVAL_RETENTION_SECONDS, VERSION,
    Report, binding_code, catalog_id, catalog_inner_form, check_floors, commitment_form, integer, item_form, item_id,
    jcs, judge_item, judge_payload, leaf_of, log_instant, proof_form, proof_holds, shown, sig_form)

ROOT = pathlib.Path(__file__).resolve().parent.parent

DAY_SECONDS = 86400
ENTRY_OCTETS_MAX = 65535
REPLACED_FILE_SECONDS = 86400
CATALOG_REFRESH_BOUNDS = (1, REMOVAL_RETENTION_SECONDS)
PAYLOAD_WINDOW_DAYS_MIN = 30
GROUP_ORDER = ["publisher_declaration", "registry_update", "publisher_catalog", "publisher_item", "label", "dispute"]
SUPPORTED_TYPES = {"publisher_declaration", "registry_update", "publisher_catalog", "publisher_item"}
JUDGED_TYPES = ("registry_update", "publisher_catalog", "publisher_item")
OUT_OF_PLACE = "WIST3-E06"
EPOCH_REJECTED = "WIST3-E03"
CONTRACT_BROKEN = "WIST4-E04"
SERVED_PATH = re.compile(r"/\.well-known/wist/collections/([^/]+)/(?:tree/([0-9a-f]{64})|payloads/([0-9a-f]{64})\.json)")

PROSE = {"note", "why"}
PARAMETER_MEMBERS = {
    "clock_skew_seconds", "catalog_items_max", "catalog_refresh_seconds", "payload_window_days",
    "domain_epoch_entries_max", "url_cap_bytes", "extract_cap_bytes", "links_cap_bytes", "link_url_cap_bytes",
    "summary_cap_bytes", "collections_max", "scope_entries_max", "recovery_window_days",
    "declaration_activation_epochs"}
KEY_MEMBERS = {"seed_hex", "x", "kid"}
EPOCH_MEMBERS = {"height", "sealed_at", "parameters", "entries"}
NAMED_ENTRY_MEMBERS = {"name", "entry"}
ENTRY_MEMBERS = {"type", "body"}
UPDATE_ENVELOPE_MEMBERS = {"update", "sig"}
UPDATE_MEMBERS = {"wist_version", "action", "subject", "effective_at", "details"}
WITHDRAWAL_DETAILS = {"delta_id", "legal_basis", "jurisdiction"}
FILE_MEMBERS = {
    "catalog-sealing": {"keys", "histories", "payloads"},
    "multilog-catalog-order": {"keys", "order_cases", "combined_cases", "payloads"},
    "served-files": {"cases"},
}
HISTORY_MEMBERS = {"name", "epochs", "expected"}
ORDER_CASE_MEMBERS = {"name", "catalogs", "expected"}
COMBINED_CASE_MEMBERS = {"name", "publisher", "url", "logs", "expected"}
LOG_MEMBERS = {"name", "epochs", "results"}
SERVED_CASE_MEMBERS = {"name", "served", "clock", "stop", "expected"}
SERVED_CATALOG_MEMBERS = {"catalog", "served_at", "files"}


class EpochRejected(Exception):
    def __init__(self, code, why):
        super().__init__(f"{code} {why}")
        self.code = code


def members_read(value, expected, where, prose=frozenset()):
    if not isinstance(value, dict):
        raise VerifierError(f"{where} is not an object")
    if not prose <= PROSE:
        raise VerifierError(f"{where}: {sorted(prose - PROSE)} are not prose members")
    unread = set(value) - set(expected) - prose
    missing = (set(expected) | prose) - set(value)
    if unread or missing:
        raise VerifierError(f"{where}: members {sorted(unread)} are not read, {sorted(missing)} are missing")


def octets(value):
    return value.encode("utf-8")


def leaf_hash(entry):
    return hashlib.sha256(b"\x00" + jcs(entry)).digest()


def check_map(parameters):
    members_read(parameters, PARAMETER_MEMBERS, "parameter map")
    low, high = CATALOG_REFRESH_BOUNDS
    refresh = integer(parameters["catalog_refresh_seconds"], low, high)
    if refresh is None:
        raise VerifierError(f"catalog_refresh_seconds outside {low} to {high}")
    if integer(parameters["payload_window_days"], PAYLOAD_WINDOW_DAYS_MIN) is None:
        raise VerifierError(f"payload_window_days below {PAYLOAD_WINDOW_DAYS_MIN}")
    check_floors(parameters)
    check_parameter_map(parameters)
    return parameters


def new_log(log_key=None):
    return {"domains": {}, "latest": {}, "records": {}, "removals": {}, "withdrawn": {}, "sealed_items": {},
            "duties": {}, "log_key": log_key, "window_end": None}


def in_force(log, domain):
    state = log["domains"].get(domain)
    if state is None or state["current"] is None:
        return None
    return state["decls"][state["current"]]["publisher"]


def window_open(log, domain):
    state = log["domains"].get(domain)
    return state is not None and state["window"] is not None


def stop_record(log, key):
    record = log["records"].pop(key)
    duty = log["duties"].setdefault(record["item"], {"key": key, "record": True, "until": None})
    duty["record"] = False
    if log["window_end"] is not None:
        duty["until"] = log["window_end"] if duty["until"] is None else max(duty["until"], log["window_end"])


def start_record(log, key, record):
    log["records"][key] = record
    duty = log["duties"].setdefault(record["item"], {"key": key, "record": True, "until": None})
    duty["record"] = True


def remove_records(log, publisher, urls, cause, removed):
    for url in sorted(urls, key=octets):
        stop_record(log, (publisher, url))
        removed.append({"publisher": publisher, "url": url, "cause": cause})


def narrow_records(log, domain, label, removed):
    state = log["domains"][domain]
    live = {url: (record["collection"], None) for (publisher, url), record in log["records"].items()
            if publisher == domain}
    gone = narrow(live, state["decls"][label]["publisher"])
    remove_records(log, domain, [record["url"] for record in gone], "narrowing", removed)


def activate(log, domain, height, removed):
    state = log["domains"][domain]
    if state["pending"] is not None and state["activation"] == height:
        head = state["pending"]
        state["current"], state["pending"], state["activation"] = head, None, None
        narrow_records(log, domain, head, removed)


def apply_declarations(log, entries, height, sealed_at, parameters, removed):
    groups = {}
    for entry in entries:
        envelope = entry["entry"]["body"]
        try:
            validate(envelope, parameters)
        except Rejected as rejection:
            raise EpochRejected(rejection.code, f"Declaration {entry['name']}")
        domain = envelope["publisher"]["domain"]
        state = log["domains"].setdefault(domain, {"decls": {}, "current": None, "pending": None,
                                                    "activation": None, "window": None, "floor": None})
        if entry["name"] in state["decls"] and jcs(state["decls"][entry["name"]]) != jcs(envelope):
            raise VerifierError(f"two Declarations named {entry['name']!r}")
        state["decls"][entry["name"]] = envelope
        groups.setdefault(domain, {}).setdefault(envelope["publisher"]["seq"], []).append(entry["name"])
    for domain in sorted(log["domains"], key=octets):
        state = log["domains"][domain]
        window = state["window"]
        if window is not None and sealed_at >= window["end"]:
            state["current"], state["window"] = window["head"], None
            narrow_records(log, domain, window["head"], removed)
        activate(log, domain, height, removed)
        for seq in sorted(groups.get(domain, {})):
            try:
                outcome = apply_group(state, groups[domain][seq], height, sealed_at, parameters)
            except Rejected as rejection:
                raise EpochRejected(rejection.code, f"Declaration group {groups[domain][seq]}")
            if outcome.get("narrows"):
                narrow_records(log, domain, outcome["declaration"], removed)
        activate(log, domain, height, removed)


def c1_codes(body, publisher, parameters, clock):
    if not isinstance(body, dict) or set(body) != {"catalog", "sig"} or not sig_form(body["sig"]) \
            or not catalog_inner_form(body["catalog"]):
        return set(E14)
    inner = body["catalog"]
    codes = set()
    if int(VERSION.fullmatch(inner["wist_version"]).group(1)) != 1:
        codes.add("WIST1-E15")
    if integer(inner["size"]) > parameters["catalog_items_max"]:
        codes.add("WIST1-E04")
    if publisher is None:
        codes.add("WIST1-E02")
    else:
        if inner["collection"] not in collection_names(publisher):
            codes.add("WIST1-E03")
        binding = binding_code(publisher, inner, body["sig"])
        if binding:
            codes.add(binding)
    if log_seconds(inner["generated_at"]) > clock + parameters["clock_skew_seconds"]:
        codes.add("WIST1-E06")
    return codes


def latest_binds(log, latest):
    publisher = in_force(log, latest["envelope"]["catalog"]["publisher"])
    if publisher is None:
        return False
    return binding_code(publisher, latest["envelope"]["catalog"], latest["envelope"]["sig"]) is None


def judge_catalog_entry(log, body, height, clock, parameters, removed):
    failed, codes = [], set()
    domain = body["catalog"].get("publisher") if isinstance(body, dict) and isinstance(body.get("catalog"), dict) \
        else None
    publisher = in_force(log, domain) if isinstance(domain, str) else None
    c1 = c1_codes(body, publisher, parameters, clock)
    if c1:
        failed.append("C1")
        codes |= c1
    if c1 == set(E14):
        return failed, codes
    inner = body["catalog"]
    name = (inner["publisher"], inner["collection"])
    generated = log_seconds(inner["generated_at"])
    latest = log["latest"].get(name)
    floor = None if latest is None else log_seconds(latest["envelope"]["catalog"]["generated_at"])
    if window_open(log, inner["publisher"]):
        failed.append("C2")
    if floor is not None and generated <= floor:
        failed.append("C3")
    if latest is not None and inner["root"] == latest["envelope"]["catalog"]["root"] \
            and generated < floor + parameters["catalog_refresh_seconds"] and latest_binds(log, latest):
        failed.append("C4")
    if any(condition != "C1" for condition in failed):
        codes.add(OUT_OF_PLACE)
    if failed:
        return failed, codes
    base = floor is not None and generated > floor + REMOVAL_RETENTION_SECONDS
    log["latest"][name] = {"envelope": body, "id": catalog_id(inner), "height": height, "base": base}
    if base:
        urls = [url for (owner, url), record in log["records"].items()
                if owner == inner["publisher"] and record["collection"] == inner["collection"]]
        remove_records(log, inner["publisher"], urls, "base", removed)
    return failed, codes


def body_form(body):
    if not isinstance(body, dict) or set(body) != BODY_MEMBERS or not item_form(body["item"]):
        return False
    if not isinstance(body["collection"], str) or not NAME.fullmatch(body["collection"]):
        return False
    return isinstance(body["catalog"], str) and HASH.fullmatch(body["catalog"]) is not None \
        and proof_form(body["proof"])


def named_catalog(log, body):
    for latest in log["latest"].values():
        if latest["id"] == body["catalog"]:
            return latest
    return None


def judge_item_entry(log, body, parameters, removed):
    if not body_form(body):
        return ["I1"], {"WIST1-E14"}
    failed, codes = [], set()
    named = named_catalog(log, body)
    if named is None:
        return ["I3"], {OUT_OF_PLACE}
    inner = named["envelope"]["catalog"]
    domain = inner["publisher"]
    publisher = in_force(log, domain)
    item = body["item"]
    identifier = item_id(item)
    if window_open(log, domain):
        failed.append("I2")
        codes.add(OUT_OF_PLACE)
    if publisher is None:
        failed.append("I4")
        codes.add("WIST1-E02")
    elif inner["collection"] not in collection_names(publisher):
        failed.append("I4")
        codes.add("WIST1-E03")
    else:
        binding = binding_code(publisher, inner, named["envelope"]["sig"])
        if binding:
            failed.append("I4")
            codes.add(binding)
    i5 = set()
    if body["collection"] != inner["collection"]:
        i5.add("WIST1-E17")
    if publisher is None:
        i5.add("WIST1-E03")
        if item["publisher"] != domain:
            i5.add("WIST2-E03")
    else:
        verdict = judge_item(item, inner, publisher, parameters)
        if verdict != ACCEPTED:
            i5 |= verdict
    if i5:
        failed.append("I5")
        codes |= i5
    if not proof_holds(body["proof"], leaf_of(item), inner):
        failed.append("I6")
        codes.add("WIST1-E17")
    key = (domain, item["url"])
    record = log["records"].get(key)
    if "removed" in item:
        i7 = record is None
    else:
        i7 = (record is not None and record["item"] == identifier) or identifier in log["withdrawn"]
    if i7:
        failed.append("I7")
        codes.add(OUT_OF_PLACE)
    if failed:
        return failed, codes
    if "removed" not in item:
        log["sealed_items"].setdefault(identifier, set()).add(domain)
    if record is not None:
        stop_record(log, key)
    if "removed" in item:
        removed.append({"publisher": domain, "url": item["url"], "cause": "removed_item"})
        log["removals"][key] = {"item": identifier, "catalog": named["id"], "generated_at": inner["generated_at"]}
    else:
        start_record(log, key, {"item": identifier, "collection": inner["collection"], "catalog": named["id"],
                                "generated_at": inner["generated_at"]})
        log["removals"].pop(key, None)
    return failed, codes


def withdrawal_form(log, body):
    members_read(body, UPDATE_ENVELOPE_MEMBERS, "registry_update body")
    update, sig = body["update"], body["sig"]
    members_read(update, UPDATE_MEMBERS, "update")
    if update["action"] != "payload_withdrawal":
        raise VerifierError(f"a Registry Update of action {update['action']!r} is outside this fixture's scope")
    if not isinstance(update["wist_version"], str) or not VERSION.fullmatch(update["wist_version"]) \
            or int(VERSION.fullmatch(update["wist_version"]).group(1)) != 1:
        raise VerifierError("a Registry Update of another wist_version is outside this fixture's scope")
    if log_instant(update["effective_at"]) is None:
        raise VerifierError("a Registry Update whose effective_at is not a Log timestamp")
    details = update["details"]
    members_read(details, WITHDRAWAL_DETAILS, "payload_withdrawal details")
    if not canonical_host(update["subject"]) or not isinstance(details["delta_id"], str) \
            or not HASH.fullmatch(details["delta_id"]) \
            or not all(isinstance(details[m], str) for m in ("legal_basis", "jurisdiction")):
        raise VerifierError("a payload_withdrawal of another form is outside this fixture's scope")
    if not sig_form(sig):
        raise VerifierError("a Registry Update whose sig is of another form")
    key = log["log_key"]
    if key is not None and (sig["key_id"] != key["kid"] or not signature_verifies(
            b64u_canonical(key["x"], 32), b64u_canonical(sig["value"], 64), jcs(update))):
        raise VerifierError("a Registry Update not signed by the fixture's Log key")
    return update["subject"], details["delta_id"]


def judge_withdrawal(log, body, height):
    subject, identifier = withdrawal_form(log, body)
    if subject not in log["sealed_items"].get(identifier, set()):
        return ["contract"], {CONTRACT_BROKEN}
    log["withdrawn"].setdefault(identifier, height)
    return [], set()


def body_member(entry, outer, member):
    body = entry["body"]
    if not isinstance(body, dict) or not isinstance(body.get(outer), dict):
        return None
    return body[outer].get(member)


def epoch_rejections(entries, parameters):
    seen, counts = set(), {}
    for named in entries:
        entry = named["entry"]
        if len(jcs(entry)) > ENTRY_OCTETS_MAX:
            raise EpochRejected(EPOCH_REJECTED, f"Entry {named['name']} above {ENTRY_OCTETS_MAX} octets")
        if entry["type"] == "publisher_catalog":
            pair = (body_member(entry, "catalog", "publisher"), body_member(entry, "catalog", "collection"))
            if all(isinstance(value, str) for value in pair):
                if pair in seen:
                    raise EpochRejected(EPOCH_REJECTED, f"two publisher_catalog Entries of {pair}")
                seen.add(pair)
        if entry["type"] in ("publisher_catalog", "publisher_item"):
            host = body_member(entry, "catalog" if entry["type"] == "publisher_catalog" else "item", "publisher")
            if isinstance(host, str) and canonical_host(host):
                counts[host] = counts.get(host, 0) + 1
    for host, count in counts.items():
        if count > parameters["domain_epoch_entries_max"]:
            raise EpochRejected(EPOCH_REJECTED, f"{count} Entries of {host} above the per-domain capacity")


def check_order(entries):
    ranks = []
    for named in entries:
        members_read(named, NAMED_ENTRY_MEMBERS, f"Entry {named.get('name')!r}")
        entry = named["entry"]
        members_read(entry, ENTRY_MEMBERS, f"Entry {named['name']!r}")
        if entry["type"] not in SUPPORTED_TYPES:
            raise VerifierError(f"Entry type {entry['type']!r} is outside this fixture's scope")
        ranks.append((GROUP_ORDER.index(entry["type"]), leaf_hash(entry)))
    if ranks != sorted(ranks):
        raise VerifierError("Entries are not in canonical order")


def duties(log, sealed_at):
    listed = []
    for identifier, duty in log["duties"].items():
        if identifier in log["withdrawn"]:
            continue
        if duty["record"]:
            until = None
        elif duty["until"] is not None and sealed_at < duty["until"]:
            until = log_timestamp(duty["until"])
        else:
            continue
        publisher, url = duty["key"]
        listed.append({"publisher": publisher, "url": url, "item": identifier, "until": until})
    return sorted(listed, key=lambda d: (octets(d["publisher"]), octets(d["url"]), octets(d["item"])))


def apply_epoch(log, epoch):
    height, sealed_at, parameters = epoch["height"], log_seconds(epoch["sealed_at"]), epoch["parameters"]
    entries = epoch["entries"]
    check_order(entries)
    before = copy.deepcopy(log)
    log["window_end"] = sealed_at + parameters["payload_window_days"] * DAY_SECONDS
    removed, verdicts = [], {}
    try:
        epoch_rejections(entries, parameters)
        apply_declarations(log, [e for e in entries if e["entry"]["type"] == "publisher_declaration"],
                           height, sealed_at, parameters, removed)
    except EpochRejected as rejection:
        log.clear()
        log.update(before)
        return {"height": height, "status": "rejected", "code": rejection.code}
    judges = {
        "publisher_catalog": lambda b: judge_catalog_entry(log, b, height, sealed_at, parameters, removed),
        "publisher_item": lambda b: judge_item_entry(log, b, parameters, removed),
        "registry_update": lambda b: judge_withdrawal(log, b, height),
    }
    for kind in ("publisher_catalog", "publisher_item", "registry_update"):
        for index, named in enumerate(entries):
            if named["entry"]["type"] == kind:
                verdicts[index] = judges[kind](named["entry"]["body"])
    results = []
    for index, named in enumerate(entries):
        if index not in verdicts:
            continue
        failed, codes = verdicts[index]
        if failed:
            shown_codes = ["WIST1-E14"] if "WIST1-E14" in codes else sorted(codes)
            results.append({"name": named["name"], "disposition": "ignored", "failed": failed, "codes": shown_codes})
        else:
            results.append({"name": named["name"], "disposition": "valid"})
    return {"height": height, "status": "accepted", "entries": results, "records_removed": removed}


def snapshot(log):
    declarations = []
    for domain in sorted(log["domains"], key=octets):
        state = log["domains"][domain]
        declarations.append({"publisher": domain, "current": state["current"], "pending_head": state["pending"],
                             "window_end": None if state["window"] is None else log_timestamp(state["window"]["end"])})
    by_key = lambda kv: (octets(kv[0][0]), octets(kv[0][1]))
    catalogs = [{"publisher": publisher, "collection": collection, "catalog": latest["id"],
                 "floor": latest["envelope"]["catalog"]["generated_at"], "sealing_height": latest["height"],
                 "base": latest["base"]}
                for (publisher, collection), latest in sorted(log["latest"].items(), key=by_key)]
    records = [{"publisher": p, "url": u, **record} for (p, u), record in sorted(log["records"].items(), key=by_key)]
    return {"declarations": declarations, "catalogs": catalogs, "records": records, "removals": removals_of(log)}


def removals_of(log):
    by_key = lambda kv: (octets(kv[0][0]), octets(kv[0][1]))
    return [{"publisher": p, "url": u, **state} for (p, u), state in sorted(log["removals"].items(), key=by_key)]


def replay(epochs, log_key, with_duties=False):
    log, produced, previous = new_log(log_key), [], None
    for epoch in epochs:
        members_read(epoch, EPOCH_MEMBERS, f"Epoch {epoch.get('height')}")
        check_map(epoch["parameters"])
        instant = (epoch["height"], log_seconds(epoch["sealed_at"]))
        if previous is not None and (instant[0] != previous[0] + 1 or instant[1] <= previous[1]):
            raise VerifierError("Epoch heights or sealed_at instants do not increase")
        previous = instant
        result = apply_epoch(log, epoch)
        if with_duties and result["status"] == "accepted":
            result["payload_duties"] = duties(log, instant[1])
        result["state"] = snapshot(log)
        produced.append(result)
    return log, produced


def compare_epochs(report, label, expected, produced):
    if len(produced) != len(expected):
        report.equal(f"{label} Epoch count", len(expected), len(produced))
        return
    for want, got in zip(expected, produced):
        report.cases += 1
        for field in sorted(want.keys() | got.keys()):
            if want.get(field) != got.get(field):
                report.failures.append((f"{label} height {want.get('height')} {field}",
                                        f"expected {json.dumps(want.get(field))}, got {json.dumps(got.get(field))}"))


def carries_duties(history):
    accepted = [epoch for epoch in history["expected"] if epoch.get("status") == "accepted"]
    carried = {"payload_duties" in epoch for epoch in accepted}
    if len(carried) > 1:
        raise VerifierError("payload_duties carried by some accepted Epochs of the history and not by others")
    return carried == {True}


def page_items(epochs_lists):
    found = {}
    for epochs in epochs_lists:
        for epoch in epochs:
            for named in epoch["entries"]:
                entry = named["entry"]
                if entry["type"] == "publisher_item" and isinstance(entry["body"], dict):
                    item = entry["body"].get("item")
                    if isinstance(item, dict) and set(item) == PAGE_MEMBERS and isinstance(item["publisher"], str) \
                            and commitment_form(item["payload"]):
                        found[item_id(item)] = item
    return found


def check_payloads(report, payloads, items):
    for identifier, payload in payloads.items():
        def one(i=identifier, p=payload):
            if i not in items:
                raise VerifierError("no page Item of the file has this Item ID")
            verdict = judge_payload(p, items[i], REGISTRY_SIZE_CAPS)
            report.equal(f"payloads[{i}]", ACCEPTED, verdict if verdict == ACCEPTED else shown(verdict))
        report.run(f"payloads[{identifier}]", one)
    for identifier in sorted(items.keys() - payloads.keys()):
        report.cases += 1
        report.failures.append((f"payloads[{identifier}]", "page Item without a Payload"))


def family_sealing(data, report):
    for history in data["histories"]:
        def one(h=history):
            members_read(h, HISTORY_MEMBERS, f"history {h.get('name')!r}", {"why"})
            produced = replay(h["epochs"], data["keys"]["log"], carries_duties(h))[1]
            compare_epochs(report, h["name"], h["expected"], produced)
        report.run(history["name"], one)
    check_payloads(report, data["payloads"], page_items(h["epochs"] for h in data["histories"]))


def log_state(log, publisher, url):
    record = log["records"].get((publisher, url))
    if record is not None:
        return {"state": "record", **record}
    removal = log["removals"].get((publisher, url))
    if removal is not None:
        return {"state": "removed", **removal}
    return None


def catalog_order_key(generated_at, identifier):
    return log_seconds(generated_at), octets(identifier)


def combined(states, order):
    holding = [(name, state) for name, state in states.items() if state is not None]
    if not holding:
        return None
    rank = lambda state: (catalog_order_key(state["generated_at"], state["catalog"]), octets(state["item"]))
    chosen = max((state for _, state in holding), key=rank)
    return {"state": chosen, "logs": [name for name in order if states[name] == chosen]}


def family_multilog(data, report):
    for case in data["order_cases"]:
        def one(c=case):
            members_read(c, ORDER_CASE_MEMBERS, f"order case {c.get('name')!r}")
            catalogs = c["catalogs"]
            for inner in catalogs:
                if not catalog_inner_form(inner):
                    raise VerifierError("a Catalog inner object of another form")
                if inner["publisher"] != catalogs[0]["publisher"]:
                    raise VerifierError("Catalogs of two Publishers")
            ordered = sorted(catalogs, key=lambda inner: catalog_order_key(inner["generated_at"], catalog_id(inner)))
            report.equal(c["name"], c["expected"], [catalog_id(inner) for inner in ordered])
        report.run(case["name"], one)
    for case in data["combined_cases"]:
        def one(c=case):
            members_read(c, COMBINED_CASE_MEMBERS, f"combined case {c.get('name')!r}", {"why"})
            states, order, logs = {}, [], {}
            for entry in c["logs"]:
                members_read(entry, LOG_MEMBERS, f"{c['name']} Log {entry.get('name')!r}")
                log, produced = replay(entry["epochs"], data["keys"]["log"])
                results = [{k: v for k, v in result.items() if k in ("height", "status", "code", "entries")}
                           for result in produced]
                compare_epochs(report, f"{c['name']} Log {entry['name']}", entry["results"], results)
                states[entry["name"]] = log_state(log, c["publisher"], c["url"])
                order.append(entry["name"])
                logs[entry["name"]] = log
            actual = {"log_states": states, "combined": combined(states, order)}
            if "snapshot" in c["expected"]:
                named = c["expected"]["snapshot"]
                members_read(named, {"log", "removals"}, f"{c['name']} snapshot")
                if named["log"] not in logs:
                    raise VerifierError(f"snapshot names no Log of the case: {named['log']!r}")
                actual["snapshot"] = {"log": named["log"], "removals": removals_of(logs[named["log"]])}
            report.equal(c["name"], c["expected"], actual)
        report.run(case["name"], one)
    check_payloads(report, data["payloads"],
                   page_items(log["epochs"] for case in data["combined_cases"] for log in case["logs"]))


def check_served_path(path, collection):
    match = SERVED_PATH.fullmatch(path) if isinstance(path, str) else None
    if not match or not NAME.fullmatch(match.group(1)):
        raise VerifierError(f"not a tree or Payload path: {path!r}")
    if match.group(1) != collection:
        raise VerifierError(f"a path of another Collection: {path!r}")


def due_files(case):
    members_read(case, SERVED_CASE_MEMBERS, f"case {case.get('name')!r}", {"why"})
    served = case["served"]
    if not served:
        raise VerifierError("no served Catalog")
    for catalog in served:
        members_read(catalog, SERVED_CATALOG_MEMBERS, "served Catalog")
    collection = SERVED_PATH.fullmatch(served[-1]["files"][0]).group(1) if served[-1]["files"] else None
    instants = []
    for catalog in served:
        if not isinstance(catalog["catalog"], str) or not HASH.fullmatch(catalog["catalog"]):
            raise VerifierError(f"not a Catalog ID: {catalog['catalog']!r}")
        instants.append(publisher_instant(catalog["served_at"]))
        for path in catalog["files"]:
            check_served_path(path, collection)
    if any(a >= b for a, b in zip(instants, instants[1:])):
        raise VerifierError("served_at does not increase")
    for path in case["stop"]:
        check_served_path(path, collection)
    clock = publisher_instant(case["clock"])
    if clock < instants[-1]:
        raise VerifierError("clock earlier than the served Catalog's instant")
    last_named = {}
    for index, catalog in enumerate(served):
        for path in catalog["files"]:
            last_named[path] = index
    due = set()
    for path, index in last_named.items():
        if index == len(served) - 1 or clock < instants[index + 1] + REPLACED_FILE_SECONDS:
            due.add(path)
    due -= set(case["stop"])
    return sorted(due, key=octets)


def family_served(data, report):
    for case in data["cases"]:
        report.run(case["name"], lambda c=case: report.equal(c["name"], c["expected"], due_files(c)))


FAMILIES = [
    ("catalog-sealing", "wist3/catalog-sealing.json", family_sealing),
    ("multilog-catalog-order", "multilog/catalog-order.json", family_multilog),
    ("served-files", "wist2/served-files.json", family_served),
]


def main(argv):
    base = pathlib.Path(argv[1]) if len(argv) > 1 else ROOT / "vectors"
    failed = False
    for family, relative, check in FAMILIES:
        report = Report()
        try:
            data = strict_load(base / relative)
            members_read(data, FILE_MEMBERS[family], relative, {"note"})
            for name, key in data.get("keys", {}).items():
                members_read(key, KEY_MEMBERS, f"keys.{name}")
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
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
