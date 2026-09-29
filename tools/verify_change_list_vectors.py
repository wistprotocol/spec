import hashlib
import pathlib
import sys

import rfc8785

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from verify_collection_vectors import VerifierError, check_keys_block, strict_load
from verify_catalog_vectors import (
    ACCEPTED, HASH, HEX64, PARAMETER_FLOORS, REGISTRY_SIZE_CAPS, REMOVAL_RETENTION_SECONDS, NotJcsInput, Refused,
    Report, catalog_id, item_id, jcs, judge_payload, key_of, leaf_of, log_time, merkle_root, parse_json_text,
    publisher_time, shifted, unread_members, walk_tree)

ROOT = pathlib.Path(__file__).resolve().parent.parent

CHANGE_LIST_CAP_BYTES = 1048576
CHANGE_CHAIN_MAX = 16
TEXT_SHOWN_OCTETS = 65536
REPLACED_FILE_SECONDS = 86400
CHANGE_LIST_MEMBERS = {"previous", "catalog", "dropped", "items"}
DISCARD = "WIST2-E08"
WALK_REFUSED = "WIST2-E07"


def large_items(large, name):
    spec = large[name]
    return [{"publisher": spec["publisher"], "observed_at": spec["observed_at"], "url": prefix + "x" * fill,
             "removed": True} for prefix, fill in spec["urls"]]


def expand(items, large):
    out = []
    for element in items:
        out.extend(large_items(large, element) if isinstance(element, str) else [element])
    return out


def keyed(items):
    table = {}
    for item in items:
        key = key_of(item["url"])
        if key in table:
            raise VerifierError(f"two Items of one key: {item['url']}")
        table[key] = item
    return table


def summary(table):
    ordered = [table[key] for key in sorted(table)]
    return {"list": [item_id(item) for item in ordered], "size": len(ordered),
            "root": "sha256:" + merkle_root([leaf_of(item) for item in ordered]).hex()}


def list_root(items):
    return "sha256:" + merkle_root([leaf_of(item) for item in sorted(items, key=lambda i: key_of(i["url"]))]).hex()


def check_catalog_list(catalog, items):
    if catalog["size"] != len(items) or catalog["root"] != list_root(items):
        raise VerifierError(f"the list does not have the size and root of Catalog {catalog_id(catalog)}")


def change_list_octets(value, large):
    if isinstance(value, str):
        return value.encode("utf-8", "surrogatepass")
    obj = dict(value)
    if isinstance(obj.get("items"), str):
        obj["items"] = sorted(large_items(large, obj["items"]), key=lambda item: key_of(item["url"]))
    return jcs(obj)


def change_list_form(octets, file_hex):
    try:
        text = octets.decode("utf-8")
        obj = parse_json_text(text)
        serialized = jcs(obj)
    except (UnicodeDecodeError, NotJcsInput, ValueError, TypeError, rfc8785.CanonicalizationError):
        return None
    if not isinstance(obj, dict) or set(obj) != CHANGE_LIST_MEMBERS:
        return None
    if not all(isinstance(obj[m], str) and HASH.fullmatch(obj[m]) for m in ("previous", "catalog")):
        return None
    dropped, items = obj["dropped"], obj["items"]
    if not isinstance(dropped, list) or not all(isinstance(k, str) and HEX64.fullmatch(k) for k in dropped):
        return None
    if any(a >= b for a, b in zip(dropped, dropped[1:])):
        return None
    if not isinstance(items, list) or not all(isinstance(e, dict) and isinstance(e.get("url"), str) for e in items):
        return None
    keys = [key_of(e["url"]) for e in items]
    if any(a >= b for a, b in zip(keys, keys[1:])):
        return None
    if set(dropped) & {k.hex() for k in keys}:
        return None
    if serialized != octets or obj["catalog"] != "sha256:" + file_hex:
        return None
    return obj


def apply(table, change_list):
    out = dict(table)
    for key in change_list["dropped"]:
        out.pop(bytes.fromhex(key), None)
    for element in change_list["items"]:
        out[key_of(element["url"])] = element
    return out


def written_change_list(served, new, large):
    if served is None:
        return None
    old = keyed(expand(served["list"], large))
    now = keyed(expand(new["list"], large))
    obj = {"previous": catalog_id(served["catalog"]), "catalog": catalog_id(new["catalog"]),
           "dropped": [key.hex() for key in sorted(old) if key not in now],
           "items": [now[key] for key in sorted(now) if key not in old or item_id(old[key]) != item_id(now[key])]}
    octets = jcs(obj)
    return None if len(octets) > CHANGE_LIST_CAP_BYTES else octets


def write_result(served, new, large):
    octets = written_change_list(served, new, large)
    if octets is None:
        return {"written": False}
    result = {"written": True, "name": catalog_id(new["catalog"])[len("sha256:"):], "octets": len(octets),
              "sha256": hashlib.sha256(octets).hexdigest()}
    if len(octets) <= TEXT_SHOWN_OCTETS:
        result["text"] = octets.decode("utf-8")
    return result


def check_derived(case, large):
    generated = case["derived"]["generated_at"]
    if generated != case["new"]["catalog"]["generated_at"]:
        raise VerifierError("derived.generated_at is not the new Catalog's generated_at")
    instant = log_time(generated)
    now = keyed(expand(case["new"]["list"], large))
    for key, item in keyed(expand(case["served"]["list"], large)).items():
        if "removed" not in item:
            continue
        kept = instant < shifted(publisher_time(item["observed_at"]), REMOVAL_RETENTION_SECONDS)
        listed = key in now and item_id(now[key]) == item_id(item)
        if kept != listed:
            raise VerifierError(f"the removed Item {item['url']} is {'' if listed else 'not '}listed at {generated}")


def chain_of(catalog_hex, previous_of, stopped):
    names, current = [], catalog_hex
    while current in previous_of and current not in stopped and current not in names:
        names.append(current)
        current = previous_of[current]
    return names


def instant(value):
    return log_time(value)[0]


def serving_sequence(case, large):
    steps = case["steps"]
    served_at = [instant(step["served_at"]) for step in steps]
    for position, step in enumerate(steps):
        check_catalog_list(step["catalog"], expand(step["list"], large))
        if position and (log_time(step["catalog"]["generated_at"]) <= log_time(
                steps[position - 1]["catalog"]["generated_at"]) or served_at[position] <= served_at[position - 1]):
            raise VerifierError("a step does not replace the Catalog before it later")
    stops = [(stop["change_list"], instant(stop["at"])) for stop in case["stop_serving"]]
    declaration = case["declaration_stops_at"]
    declaration = None if declaration is None else instant(declaration)
    if declaration is not None and served_at[-1] >= declaration:
        raise VerifierError("a Catalog is served after the Declaration stops naming the Collection")
    hexes = [catalog_id(step["catalog"])[len("sha256:"):] for step in steps]
    written, previous_of, written_at = [], {}, {}
    for position, step in enumerate(steps):
        previous = steps[position - 1] if position else None
        if written_change_list(previous, step, large) is None:
            written.append(None)
            continue
        written.append(hexes[position])
        previous_of[hexes[position]] = hexes[position - 1]
        written_at[hexes[position]] = served_at[position]

    def stopped(t):
        return {name for name, at in stops if at <= t}

    def chain(position, t):
        present = {name: prev for name, prev in previous_of.items() if written_at[name] <= t}
        return chain_of(hexes[position], present, stopped(t))

    intervals = []
    for position in range(1, len(steps)):
        t = served_at[position]
        beyond = chain(position, t)[CHANGE_CHAIN_MAX:]
        intervals.extend((name, t, t + REPLACED_FILE_SECONDS) for name in chain(position - 1, t)[:CHANGE_CHAIN_MAX]
                         if name in beyond)

    def running(t):
        return {name for name, start, end in intervals if start <= t < end}

    def obliged(t):
        current = max((p for p, at in enumerate(served_at) if at <= t), default=None)
        if current is None:
            raise VerifierError("a clock earlier than the first Catalog served")
        return (set(chain(current, t)[:CHANGE_CHAIN_MAX]) | running(t)) - stopped(t)

    clocks = []
    for entry in case["expected"]["clocks"]:
        t = instant(entry["clock"])
        if declaration is not None and t >= declaration:
            kept = obliged(declaration) if t < declaration + REPLACED_FILE_SECONDS else set()
            must = (kept | running(t)) - stopped(t)
        else:
            must = obliged(t)
        present = {name for name, at in written_at.items() if at <= t}
        must_not = present & stopped(t)
        clocks.append({"clock": entry["clock"], "must_serve": sorted(must),
                       "may_serve": sorted(present - must - must_not), "must_not_serve": sorted(must_not)})
    return {"written": written, "clocks": clocks}


class Suspended(Exception):
    pass


class TreeSource:
    def __init__(self, held, served, cap, remaining):
        self.held = held
        self.served = served
        self.cap = cap
        self.remaining = remaining
        self.fetched = set()
        self.octets = 0

    def get(self, name):
        if name in self.held:
            return self.held[name]
        self.fetched.add(name)
        text = self.served.get(name)
        if not isinstance(text, str):
            return None
        size = len(text.encode("utf-8", "surrogatepass"))
        if size > self.cap:
            if self.remaining is not None:
                raise VerifierError("a tree file above tree_file_cap_bytes under an ingest budget")
            return text
        if self.remaining is not None and size > self.remaining - self.octets:
            self.octets = self.remaining
            raise Suspended()
        self.octets += size
        if hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest() == name:
            self.held[name] = text
        return text


def walk(catalog, state, pull, remaining):
    parameters = pull["parameters"] or {}
    if set(parameters) - {"tree_file_cap_bytes", "tree_depth_max"}:
        raise VerifierError("the pull's parameter map carries another member")
    parameters = {**PARAMETER_FLOORS, **parameters}
    source = TreeSource(state["tree"], pull["tree_files_served"], parameters["tree_file_cap_bytes"], remaining)
    listed = None
    try:
        listed = walk_tree(catalog, source, parameters)
        result = {"list": [item_id(item) for item in listed]}
    except Refused:
        result = {"refused": WALK_REFUSED}
    except Suspended:
        result = {"suspended": True}
    result["tree_files_fetched"] = sorted(source.fetched)
    result["octets"] = source.octets
    return result, None if listed is None else keyed(listed)


def walked(chain, pull, state, fetched_id, remaining, fields):
    result, table = walk(pull["catalog"], state, pull, remaining)
    if table is not None:
        state["held"][fetched_id] = table
        state["left"] = False
    return {"chain": chain, **fields, "walk": result}


def read_pull(pull, state, large):
    catalog = pull["catalog"]
    fetched_id = catalog_id(catalog)
    held = state["held"]
    for table in list(held.values()):
        found = summary(table)
        if found["size"] == catalog["size"] and found["root"] == catalog["root"]:
            held[fetched_id] = table
            state["left"] = False
            return {"chain": "held", "lists_read": [], "octets": 0, "list": found["list"]}
    budget = pull["budget"]
    if state["left"]:
        return walked("after_suspension", pull, state, fetched_id, budget, {"lists_read": [], "octets": 0})
    if not held:
        return walked("none", pull, state, fetched_id, budget, {"lists_read": [], "octets": 0})
    octets, lists_read, read, name = 0, [], [], fetched_id

    def discard(condition, at):
        remaining = None if budget is None else budget - octets
        report = {"code": DISCARD, "condition": condition, "catalog": fetched_id, "change_list": at}
        return walked("discarded", pull, state, fetched_id, remaining,
                      {"lists_read": lists_read, "octets": octets, "report": report})

    while True:
        value = pull["change_lists"].get(name[len("sha256:"):])
        if value is None:
            return discard("fetch", name)
        answer = change_list_octets(value, large)
        if budget is not None and len(answer) > budget - octets and len(answer) > CHANGE_LIST_CAP_BYTES:
            raise VerifierError("an answer above change_list_cap_bytes under a smaller budget")
        if len(answer) > CHANGE_LIST_CAP_BYTES:
            return discard("size", name)
        if budget is not None and len(answer) > budget - octets:
            state["left"] = True
            return {"chain": "suspended", "lists_read": lists_read, "octets": budget}
        octets += len(answer)
        lists_read.append(name)
        change_list = change_list_form(answer, name[len("sha256:"):])
        if change_list is None:
            return discard("form", name)
        read.append(change_list)
        if change_list["previous"] in held:
            break
        if len(read) == CHANGE_CHAIN_MAX:
            return discard("chain", name)
        name = change_list["previous"]
    previous = read[-1]["previous"]
    table = held[previous]
    for change_list in reversed(read):
        table = apply(table, change_list)
    found = summary(table)
    if found["size"] != catalog["size"] or found["root"] != catalog["root"]:
        return discard("result", fetched_id)
    held[fetched_id] = table
    return {"chain": "accepted", "previous": previous, "lists_read": lists_read, "octets": octets,
            "list": found["list"]}


def page_items(items, found):
    for item in items:
        if isinstance(item, dict) and "removed" not in item:
            found[item_id(item)[len("sha256:"):]] = item


def check_payloads(data, found, report):
    payloads = data["payloads"]
    for digits, item in found.items():
        label = f"payloads[{digits}]"
        if digits not in payloads:
            report.cases += 1
            report.failures.append((label, "page Item without a Payload"))
            continue
        report.run(label, lambda d=digits, i=item: report.verdict(
            f"payloads[{d}]", ACCEPTED, judge_payload(payloads[d], i, REGISTRY_SIZE_CAPS)))
    for digits in payloads.keys() - found.keys():
        report.cases += 1
        report.failures.append((f"payloads[{digits}]", "no page Item of the file has this Item ID"))


def family_change_lists(data, report):
    found = {}
    for case in data["form_cases"]:
        def one(c=case):
            octets = c["text"].encode("utf-8", "surrogatepass")
            actual = ACCEPTED if change_list_form(octets, c["file"]) is not None else "form"
            report.equal(c["name"], c["expected"], actual)
        report.run(case["name"], one)
    for case in data["application_cases"]:
        def one(c=case):
            change_list = c["change_list"]
            parsed = parse_json_text(change_list)
            obj = change_list_form(change_list.encode("utf-8"), parsed["catalog"][len("sha256:"):])
            if obj is None:
                raise VerifierError("change_list is not of the form")
            page_items(c["list"], found)
            report.equal(c["name"], c["expected"], summary(apply(keyed(c["list"]), obj)))
        report.run(case["name"], one)
    check_payloads(data, found, report)




def family_change_list_serving(data, report):
    large, found = data["large_item_sets"], {}
    for case in data["write_cases"]:
        def one(c=case):
            for side in ("served", "new"):
                if c[side] is not None:
                    check_catalog_list(c[side]["catalog"], expand(c[side]["list"], large))
                    page_items(c[side]["list"], found)
            if "derived" in c:
                check_derived(c, large)
            report.equal(c["name"], c["expected"], write_result(c["served"], c["new"], large))
        report.run(case["name"], one)
    for case in data["sequence_cases"]:
        def one(c=case):
            for step in c["steps"]:
                page_items(step["list"], found)
            actual = serving_sequence(c, large)
            report.equal(f"{c['name']} written", c["expected"]["written"], actual["written"])
            for want, got in zip(c["expected"]["clocks"], actual["clocks"]):
                report.equal(f"{c['name']} at {want['clock']}", want, got)
        report.run(case["name"], one)
    check_payloads(data, found, report)


def fresh_state(pull, large):
    return {"held": {cid: keyed(expand(items, large)) for cid, items in pull["held"].items()},
            "tree": dict(pull["tree_files_held"]), "left": False}


def family_change_chains(data, report):
    large, found = data["large_item_sets"], {}
    for case in data["cases"]:
        def one(c=case):
            if len(c["pulls"]) != len(c["expected"]):
                raise VerifierError("expected does not have one entry per pull")
            carried = c.get("carried", False)
            state = None
            for position, (pull, want) in enumerate(zip(c["pulls"], c["expected"])):
                if not carried or position == 0:
                    for items in list(pull["held"].values()) + list(pull["held_other_collection"].values()):
                        page_items(items, found)
                    state = fresh_state(pull, large)
                elif {"held", "held_other_collection", "tree_files_held"} & set(pull):
                    raise VerifierError("a carried pull after the first supplies held state")
                actual = read_pull(pull, state, large)
                if carried:
                    actual["held_after"] = sorted(state["held"])
                label = c["name"] if len(c["pulls"]) == 1 else f"{c['name']} pull {position + 1}"
                report.equal(label, want, actual)
        report.run(case["name"], one)
    check_payloads(data, found, report)


FAMILIES = [
    ("change-lists", "wist2/change-lists.json", family_change_lists, {"payloads"}, {
        "form_cases": {"name", "text", "file", "expected"},
        "application_cases": {"name", "list", "change_list", "expected"}}),
    ("change-list-serving", "wist2/change-list-serving.json", family_change_list_serving,
     {"large_item_sets", "payloads"}, {
        "write_cases": {"name", "served", "new", "derived", "expected"},
        "sequence_cases": {"name", "steps", "stop_serving", "declaration_stops_at", "expected"}}),
    ("change-chains", "wist2/change-chains.json", family_change_chains, {"large_item_sets", "payloads"}, {
        "cases": {"name", "carried", "pulls", "expected"}}),
]


def main(argv):
    base = pathlib.Path(argv[1]) if len(argv) > 1 else ROOT / "vectors"
    failed = False
    for family, relative, check, other, arrays in FAMILIES:
        report = Report()
        try:
            data = strict_load(base / relative)
            report.failures.extend(("unread", what) for what in unread_members(data, other, arrays))
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
