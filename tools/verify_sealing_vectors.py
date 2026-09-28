import copy
import hashlib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from verify_collection_vectors import (
    Rejected, VerifierError, apply_group, canonical_host, check_keys_block, collection_names, log_seconds,
    log_timestamp, narrow, publisher_instant, strict_load, validate)
from verify_catalog_vectors import (
    BODY_MEMBERS, E14, HASH, NAME, VERSION, Report, binding_code, catalog_id, catalog_inner_form, integer,
    item_form, item_id, jcs, judge_item, leaf_of, proof_form, proof_holds, sig_form)

ROOT = pathlib.Path(__file__).resolve().parent.parent

ENTRY_OCTETS_MAX = 65535
REPLACED_FILE_SECONDS = 86400
GROUP_ORDER = ["publisher_declaration", "registry_update", "publisher_catalog", "publisher_item", "label", "dispute"]
SUPPORTED_TYPES = {"publisher_declaration", "publisher_catalog", "publisher_item"}
OUT_OF_PLACE = "WIST3-E06"
EPOCH_REJECTED = "WIST3-E03"
SERVED_PATH = re.compile(r"/\.well-known/wist/collections/([^/]+)/(?:tree/([0-9a-f]{64})|payloads/([0-9a-f]{64})\.json)")


class EpochRejected(Exception):
    def __init__(self, code, why):
        super().__init__(f"{code} {why}")
        self.code = code


def octets(value):
    return value.encode("utf-8")


def leaf_hash(entry):
    return hashlib.sha256(b"\x00" + jcs(entry)).digest()


def new_log():
    return {"domains": {}, "latest": {}, "records": {}, "removals": {}}


def in_force(log, domain):
    state = log["domains"].get(domain)
    if state is None or state["current"] is None:
        return None
    return state["decls"][state["current"]]["publisher"]


def window_open(log, domain):
    state = log["domains"].get(domain)
    return state is not None and state["window"] is not None


def remove_records(log, publisher, urls, cause, removed):
    for url in sorted(urls, key=octets):
        del log["records"][(publisher, url)]
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
    base = floor is not None and generated > floor + parameters["removal_retention_days"] * 86400
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
        if verdict != "accepted":
            i5 |= verdict
    if i5:
        failed.append("I5")
        codes |= i5
    if not proof_holds(body["proof"], leaf_of(item), inner):
        failed.append("I6")
        codes.add("WIST1-E17")
    record = log["records"].get((domain, item["url"]))
    if "removed" in item:
        if record is None:
            failed.append("I7")
            codes.add(OUT_OF_PLACE)
    elif record is not None and record["item"] == item_id(item):
        failed.append("I7")
        codes.add(OUT_OF_PLACE)
    if failed:
        return failed, codes
    key = (domain, item["url"])
    if "removed" in item:
        remove_records(log, domain, [item["url"]], "removed_item", removed)
        log["removals"][key] = {"catalog": named["id"], "generated_at": inner["generated_at"]}
    else:
        log["records"][key] = {"item": item_id(item), "collection": inner["collection"], "catalog": named["id"],
                               "generated_at": inner["generated_at"]}
        log["removals"].pop(key, None)
    return failed, codes


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
        entry = named["entry"]
        if not isinstance(entry, dict) or set(entry) != {"type", "body"}:
            raise VerifierError(f"Entry {named['name']} is not {{type, body}}")
        if entry["type"] not in SUPPORTED_TYPES:
            raise VerifierError(f"Entry type {entry['type']!r} is outside this fixture's scope")
        ranks.append((GROUP_ORDER.index(entry["type"]), leaf_hash(entry)))
    if ranks != sorted(ranks):
        raise VerifierError("Entries are not in canonical order")


def apply_epoch(log, epoch):
    height, sealed_at, parameters = epoch["height"], log_seconds(epoch["sealed_at"]), epoch["parameters"]
    entries = epoch["entries"]
    check_order(entries)
    before = copy.deepcopy(log)
    removed, results = [], []
    try:
        epoch_rejections(entries, parameters)
        apply_declarations(log, [e for e in entries if e["entry"]["type"] == "publisher_declaration"],
                           height, sealed_at, parameters, removed)
    except EpochRejected as rejection:
        log.clear()
        log.update(before)
        return {"height": height, "status": "rejected", "code": rejection.code}
    for kind, judge in (("publisher_catalog", lambda b: judge_catalog_entry(log, b, height, sealed_at, parameters,
                                                                            removed)),
                        ("publisher_item", lambda b: judge_item_entry(log, b, parameters, removed))):
        for named in entries:
            if named["entry"]["type"] != kind:
                continue
            failed, codes = judge(named["entry"]["body"])
            if failed:
                shown = ["WIST1-E14"] if "WIST1-E14" in codes else sorted(codes)
                results.append({"name": named["name"], "disposition": "ignored", "failed": failed, "codes": shown})
            else:
                results.append({"name": named["name"], "disposition": "valid"})
    return {"height": height, "status": "accepted", "entries": results, "records_removed": removed}


def snapshot(log):
    declarations = []
    for domain in sorted(log["domains"], key=octets):
        state = log["domains"][domain]
        declarations.append({"publisher": domain, "current": state["current"], "pending_head": state["pending"],
                             "window_end": None if state["window"] is None else log_timestamp(state["window"]["end"])})
    catalogs = [{"publisher": publisher, "collection": collection, "catalog": latest["id"],
                 "floor": latest["envelope"]["catalog"]["generated_at"], "sealing_height": latest["height"],
                 "base": latest["base"]}
                for (publisher, collection), latest in sorted(log["latest"].items(),
                                                              key=lambda kv: (octets(kv[0][0]), octets(kv[0][1])))]
    by_key = lambda kv: (octets(kv[0][0]), octets(kv[0][1]))
    records = [{"publisher": p, "url": u, **record} for (p, u), record in sorted(log["records"].items(), key=by_key)]
    removals = [{"publisher": p, "url": u, **state} for (p, u), state in sorted(log["removals"].items(), key=by_key)]
    return {"declarations": declarations, "catalogs": catalogs, "records": records, "removals": removals}


def replay(epochs):
    log, produced, previous = new_log(), [], None
    for epoch in epochs:
        instant = (epoch["height"], log_seconds(epoch["sealed_at"]))
        if previous is not None and (instant[0] != previous[0] + 1 or instant[1] <= previous[1]):
            raise VerifierError("Epoch heights or sealed_at instants do not increase")
        previous = instant
        result = apply_epoch(log, epoch)
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


def family_sealing(data, report):
    for history in data["histories"]:
        def one(h=history):
            compare_epochs(report, h["name"], h["expected"], replay(h["epochs"])[1])
        report.run(history["name"], one)


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
    latest = max(catalog_order_key(state["generated_at"], state["catalog"]) for _, state in holding)
    chosen = [(name, state) for name, state in holding
              if catalog_order_key(state["generated_at"], state["catalog"]) == latest]
    if any(state != chosen[0][1] for _, state in chosen):
        raise VerifierError("two Logs hold different states proved against one Catalog")
    return {"state": chosen[0][1], "logs": [name for name in order if name in dict(chosen)]}


def family_multilog(data, report):
    for case in data["order_cases"]:
        def one(c=case):
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
            states, order = {}, []
            for entry in c["logs"]:
                log, produced = replay(entry["epochs"])
                results = [{k: v for k, v in result.items() if k in ("height", "status", "code", "entries")}
                           for result in produced]
                compare_epochs(report, f"{c['name']} Log {entry['name']}", entry["results"], results)
                states[entry["name"]] = log_state(log, c["publisher"], c["url"])
                order.append(entry["name"])
            report.equal(c["name"], c["expected"], {"log_states": states, "combined": combined(states, order)})
        report.run(case["name"], one)


def check_served_path(path, collection):
    match = SERVED_PATH.fullmatch(path) if isinstance(path, str) else None
    if not match or not NAME.fullmatch(match.group(1)):
        raise VerifierError(f"not a tree or Payload path: {path!r}")
    if match.group(1) != collection:
        raise VerifierError(f"a path of another Collection: {path!r}")


def due_files(case):
    served = case["served"]
    if not served:
        raise VerifierError("no served Catalog")
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
