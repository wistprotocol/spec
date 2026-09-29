import copy
import hashlib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from verify_collection_vectors import (
    Rejected, VerifierError, apply_group, canonical_host, check_keys_block, check_parameter_map, collection_names,
    declaration_hash, fetch_declaration, log_seconds, narrow, new_state, pull_sources, pulled_collections, reductions,
    repeats_head, strict_load, validate)
from verify_catalog_vectors import (
    ACCEPTED, BODY_MEMBERS, HASH, NAME, REMOVAL_RETENTION_SECONDS, VERSION, Refused, Report, binding_code, catalog_id,
    catalog_inner_form, covered, integer, item_form, item_id, jcs, judge_item, judge_payload, leaf_of, merkle_root,
    proof_form, proof_holds, sig_form, walk_tree)

ROOT = pathlib.Path(__file__).resolve().parent.parent
E14 = "WIST1-E14"
OUT_OF_PLACE = "WIST3-E06"
EPOCH_REJECTED = "WIST3-E03"
ENTRY_OCTETS_MAX = 65535
REFRESH_SECONDS_MAX = 15552000
GROUP_ORDER = ["publisher_declaration", "registry_update", "publisher_catalog", "publisher_item", "label", "dispute"]
DROPPED_REASON = "the list drops the URL of a held record"
UNORDERED = {"left", "deferred", "held", "records_removed", "declarations_failed", "declarations_left"}

PROSE = {"note", "why"}
FILE_MEMBERS = {"note", "keys", "histories"}
KEY_MEMBERS = {"seed_hex", "x", "kid"}
HISTORY_MEMBERS = {"name", "why", "declarations", "catalogs", "catalog_ids", "tree_files", "events", "expected"}
HISTORY_OPTIONAL = {"suffix_list", "registry_updates"}
PULL_MEMBERS = {"event", "at", "publisher", "parameters", "declaration", "collections"}
SERVED_MEMBERS = {"catalog", "tree_files", "payloads"}
EPOCH_MEMBERS = {"event", "height", "sealed_at", "parameters", "declarations"}
EPOCH_OPTIONAL = {"updates"}
PULL_EXPECTED = {"settlement", "declaration", "collections_pulled", "catalogs", "state"}
EPOCH_EXPECTED = {"settlement", "entries", "sealed", "left", "deferred", "records_removed", "state"}
EPOCH_EXPECTED_OPTIONAL = {"held", "declarations_failed", "declarations_left"}
STATE_MEMBERS = {"collections", "urls", "queue", "reductions_pending", "records"}


class EpochRejected(Exception):
    def __init__(self, code, why):
        super().__init__(f"{code} {why}")
        self.code = code


class OneOf:
    def __init__(self, codes):
        self.codes = frozenset(codes)

    def __eq__(self, other):
        if isinstance(other, OneOf):
            return other.codes == self.codes
        return isinstance(other, str) and other in self.codes

    def __hash__(self):
        return hash(self.codes)


def shown(value):
    return json.dumps(value, sort_keys=True, default=lambda o: " or ".join(sorted(o.codes)))


def octets(value):
    return value.encode("utf-8")


def members_read(value, required, optional=frozenset(), where=""):
    found = set(value) if isinstance(value, dict) else set()
    if not isinstance(value, dict) or not required <= found or not found <= required | optional:
        unread = sorted(found - required - optional)
        missing = sorted(required - found)
        raise VerifierError(f"{where}: members this verifier does not read {unread}, missing {missing}")


def shown_codes(codes):
    return [E14] if E14 in codes else sorted(codes)


def audit_path(leaves, index):
    if len(leaves) <= 1:
        return []
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < split:
        return audit_path(leaves[:split], index) + [merkle_root(leaves[split:])]
    return audit_path(leaves[split:], index - split) + [merkle_root(leaves[:split])]


def generated(envelope):
    return log_seconds(envelope["catalog"]["generated_at"])


def is_base(inner, latest):
    return latest is not None and log_seconds(inner["generated_at"]) > generated(latest["envelope"]) \
        + REMOVAL_RETENTION_SECONDS


def suffix_rules(lines):
    rules = []
    for line in lines:
        text = line.split()[0] if line.split() else ""
        if not text or text.startswith("//"):
            continue
        exception = text.startswith("!")
        labels = (text[1:] if exception else text).split(".")
        for label in labels:
            if label != "*" and (not label.isascii() or not canonical_host(label.lower())):
                raise VerifierError(f"suffix rule {text!r} needs WIST-1 section 2 processing this verifier lacks")
        rules.append((exception, [label.lower() for label in labels]))
    return rules


def registrable_domain(host, rules):
    if rules is None or not isinstance(host, str):
        return host
    labels = host.split(".")
    matching = [(exception, rule) for exception, rule in rules
                if len(rule) <= len(labels)
                and all(r == "*" or r == h for r, h in zip(reversed(rule), reversed(labels)))]
    exceptions = [rule for exception, rule in matching if exception]
    if exceptions:
        length = max(len(rule) for rule in exceptions) - 1
    elif matching:
        length = max(len(rule) for _, rule in matching)
    else:
        length = 1
    if len(labels) <= length:
        return host
    return ".".join(labels[-length - 1:])


def leaf_hash(entry):
    return hashlib.sha256(b"\x00" + jcs(entry)).digest()


def new_log():
    return {"domains": {}, "latest": {}, "records": {}, "removals": {}, "sealed_items": set(), "withdrawn": {}}


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
        domain = envelope["publisher"]["domain"]
        state = log["domains"].setdefault(domain, new_state())
        # ADR-0051 Size: a repeat of the current Declaration or the pending head is not read again.
        if state["current"] is None or not repeats_head(state, [envelope]):
            try:
                validate(envelope, parameters)
            except Rejected as rejection:
                raise EpochRejected(rejection.code, f"Declaration {entry['name']}")
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
        return {E14}
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


def binds(log, latest):
    inner = latest["envelope"]["catalog"]
    publisher = in_force(log, inner["publisher"])
    return publisher is not None and binding_code(publisher, inner, latest["envelope"]["sig"]) is None


def passes_i4(log, latest):
    inner = latest["envelope"]["catalog"]
    publisher = in_force(log, inner["publisher"])
    return publisher is not None and inner["collection"] in collection_names(publisher) and binds(log, latest)


def judge_catalog_entry(log, body, height, clock, parameters, removed):
    failed, codes = [], set()
    domain = body["catalog"].get("publisher") if isinstance(body, dict) and isinstance(body.get("catalog"), dict) \
        else None
    publisher = in_force(log, domain) if isinstance(domain, str) else None
    c1 = c1_codes(body, publisher, parameters, clock)
    if c1:
        failed.append("C1")
        codes |= c1
    if c1 == {E14}:
        return failed, codes
    inner = body["catalog"]
    name = (inner["publisher"], inner["collection"])
    instant = log_seconds(inner["generated_at"])
    latest = log["latest"].get(name)
    floor = None if latest is None else generated(latest["envelope"])
    if window_open(log, inner["publisher"]):
        failed.append("C2")
    if floor is not None and instant <= floor:
        failed.append("C3")
    if latest is not None and inner["root"] == latest["envelope"]["catalog"]["root"] \
            and instant < floor + parameters["catalog_refresh_seconds"] and binds(log, latest):
        failed.append("C4")
    if any(condition != "C1" for condition in failed):
        codes.add(OUT_OF_PLACE)
    if failed:
        return failed, codes
    base = is_base(inner, latest)
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


def withdrawn(log, identifier):
    return identifier in log["withdrawn"]


def judge_item_entry(log, body, parameters, removed):
    if not body_form(body):
        return ["I1"], {E14}
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
        if verdict != ACCEPTED:
            i5 |= verdict
    if i5:
        failed.append("I5")
        codes |= i5
    if not proof_holds(body["proof"], leaf_of(item), inner):
        failed.append("I6")
        codes.add("WIST1-E17")
    record = log["records"].get((domain, item["url"]))
    identity = item_id(item)
    if "removed" in item:
        if record is None:
            failed.append("I7")
            codes.add(OUT_OF_PLACE)
    elif (record is not None and record["item"] == identity) or withdrawn(log, identity):
        failed.append("I7")
        codes.add(OUT_OF_PLACE)
    if failed:
        return failed, codes
    key = (domain, item["url"])
    log["sealed_items"].add((domain, identity))
    if "removed" in item:
        remove_records(log, domain, [item["url"]], "removed_item", removed)
        log["removals"][key] = {"catalog": named["id"], "generated_at": inner["generated_at"]}
    else:
        log["records"][key] = {"item": identity, "collection": inner["collection"], "catalog": named["id"],
                               "generated_at": inner["generated_at"]}
        log["removals"].pop(key, None)
    return failed, codes


def withdrawal_target(body):
    update = body["update"]
    if update["action"] != "payload_withdrawal":
        raise VerifierError(f"a registry update of action {update['action']!r} is outside this fixture's scope")
    return update["subject"], update["details"]["delta_id"]


def apply_withdrawals(log, bodies, height):
    for body in bodies:
        subject, identifier = withdrawal_target(body)
        # ADR-0052 Judgment: the contract counts Items sealed at or below the withdrawal's Epoch.
        if (subject, identifier) in log["sealed_items"]:
            log["withdrawn"].setdefault(identifier, height)


def body_member(entry, outer, member):
    body = entry["body"]
    if not isinstance(body, dict) or not isinstance(body.get(outer), dict):
        return None
    return body[outer].get(member)


def epoch_rejections(entries, parameters, rules):
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
                unit = registrable_domain(host, rules)
                counts[unit] = counts.get(unit, 0) + 1
    for unit, count in counts.items():
        if count > parameters["domain_epoch_entries_max"]:
            raise EpochRejected(EPOCH_REJECTED, f"{count} Entries of {unit} above the per-domain capacity")


def check_order(entries):
    ranks = [(GROUP_ORDER.index(named["entry"]["type"]), leaf_hash(named["entry"])) for named in entries]
    if ranks != sorted(ranks):
        raise VerifierError("Entries are not in canonical order")


def apply_epoch(log, height, sealed_at, parameters, entries, rules):
    check_order(entries)
    removed, results = [], []
    epoch_rejections(entries, parameters, rules)
    apply_declarations(log, [e for e in entries if e["entry"]["type"] == "publisher_declaration"],
                       height, sealed_at, parameters, removed)
    for kind, judge in (("publisher_catalog", lambda b: judge_catalog_entry(log, b, height, sealed_at, parameters,
                                                                            removed)),
                        ("publisher_item", lambda b: judge_item_entry(log, b, parameters, removed))):
        for named in entries:
            if named["entry"]["type"] != kind:
                continue
            failed, codes = judge(named["entry"]["body"])
            if failed:
                results.append({"name": named["name"], "failed": failed, "codes": shown_codes(codes)})
    apply_withdrawals(log, [e["entry"]["body"] for e in entries if e["entry"]["type"] == "registry_update"],
                      height)
    return results, removed


def place_key(publisher, place):
    return (place[0], octets(publisher), *place[1:])


class TreeStore:
    def __init__(self, held, texts, served, fetched):
        self.held, self.texts, self.served, self.fetched = held, texts, set(served), fetched

    def get(self, name):
        if name in self.held:
            return self.held[name]
        self.fetched.add(name)
        if name not in self.served:
            return None
        if name not in self.texts:
            raise VerifierError(f"tree file {name} is served but absent from tree_files")
        text = self.texts[name]
        if isinstance(text, str) and hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest() == name:
            self.held[name] = text
        return text


class Replay:
    def __init__(self, data, history):
        self.history = history
        self.names = {entry["kid"]: name for name, entry in data["keys"].items()}
        self.rules = suffix_rules(history["suffix_list"]) if "suffix_list" in history else None
        self.updates = history.get("registry_updates", {})
        self.log = new_log()
        self.parameters = None
        self.constants = None
        self.height = None
        self.sealed_at = None
        self.clock = None
        self.lists = {}
        self.payloads = {}
        self.trees = {}
        self.tracked = {}
        self.urls = {}
        self.queue = {}
        self.first_place = {}
        self.queued_domains = set()
        self.settled = {}
        self.discovered = {}
        self.seq_floor = {}

    def read_parameters(self, parameters):
        check_parameter_map(parameters)
        if "removal_retention_days" in parameters:
            raise VerifierError("removal_retention_days is a constant and appears in no parameter map")
        if not 1 <= parameters["catalog_refresh_seconds"] <= REFRESH_SECONDS_MAX:
            raise VerifierError("catalog_refresh_seconds amended outside 1 to 15 552 000")
        constants = (parameters["max_inclusion_epochs"], parameters["record_seal_epochs"])
        if self.constants is not None and constants != self.constants:
            raise VerifierError("max_inclusion_epochs or record_seal_epochs changes within the history")
        self.constants = constants
        self.parameters = parameters
        return parameters

    def advance(self, instant):
        if self.clock is not None and instant < self.clock:
            raise VerifierError("events are not in time order")
        self.clock = instant

    def key_name(self, envelope):
        kid = envelope["sig"]["key_id"]
        if kid not in self.names:
            raise VerifierError(f"no test key has the kid {kid}")
        return self.names[kid]

    def unit(self, publisher):
        return registrable_domain(publisher, self.rules)

    def last_accepted(self, log, publisher, collection):
        entry = self.tracked.get((publisher, collection))
        if entry is not None and entry["last"] is not None:
            return entry["last"]
        latest = log["latest"].get((publisher, collection))
        return None if latest is None else {"id": latest["id"], "envelope": latest["envelope"]}

    def catalog_waits(self, log, publisher, collection):
        entry = self.tracked.get((publisher, collection))
        if entry is None or entry["last"] is None or entry["failed_c4"]:
            return False
        latest = log["latest"].get((publisher, collection))
        return latest is None or latest["id"] != entry["last"]["id"]

    def no_record(self, log, publisher, collection):
        if not self.catalog_waits(log, publisher, collection):
            return False
        return is_base(self.tracked[(publisher, collection)]["last"]["envelope"]["catalog"],
                       log["latest"].get((publisher, collection)))

    def publishers(self, log):
        return {key[0] for key in self.tracked} | {key[0] for key in log["latest"]} | {key[0] for key in self.urls}

    def names_of(self, log, publisher, extra=()):
        keys = set(self.tracked) | set(log["latest"]) | {(k[0], k[1]) for k in self.queue}
        return {c for p, c in keys if p == publisher} | set(extra)

    def positions(self, log, publisher, declaration, extra=()):
        named = [] if declaration is None else collection_names(declaration)
        others = sorted((c for c in self.names_of(log, publisher, extra) if c not in named), key=octets)

        def place(collection):
            if collection in named:
                return named.index(collection)
            if collection not in others:
                raise VerifierError(f"Collection {collection!r} has no position")
            return len(named) + others.index(collection)
        return place

    @staticmethod
    def i7(log, publisher, item, no_record):
        if "removed" in item:
            return not no_record and (publisher, item["url"]) in log["records"]
        identity = item_id(item)
        if withdrawn(log, identity):
            return False
        record = None if no_record else log["records"].get((publisher, item["url"]))
        return record is None or record["item"] != identity

    def listed_item(self, log, publisher, collection, url):
        last = self.last_accepted(log, publisher, collection)
        if last is None:
            return None
        entry = self.lists.get(last["id"])
        if entry is None:
            raise VerifierError(f"the list of {last['id']} was never walked")
        for index, item in enumerate(entry["list"]):
            if item["url"] == url:
                return {"collection": collection, "index": index, "item": item, "catalog": last["id"],
                        "admitted": entry["status"][index] == "admitted"}
        return None

    def desired(self, log, publisher):
        found = {}
        for collection in sorted(self.names_of(log, publisher), key=octets):
            last = self.last_accepted(log, publisher, collection)
            if last is None:
                continue
            entry = self.lists.get(last["id"])
            if entry is None:
                raise VerifierError(f"the list of {last['id']} was never walked")
            no_record = self.no_record(log, publisher, collection)
            for index, item in enumerate(entry["list"]):
                if entry["status"][index] != "admitted" or not self.i7(log, publisher, item, no_record):
                    continue
                order = (generated(last["envelope"]), octets(last["id"]))
                other = found.get(item["url"])
                if other is not None and other["order"] == order:
                    raise VerifierError(f"one Catalog lists {item['url']} twice")
                if other is None or order > other["order"]:
                    found[item["url"]] = {"collection": collection, "index": index, "item": item,
                                          "catalog": last["id"], "order": order}
        return found

    def refresh(self, log, publisher, place_of, eligibility):
        found = self.desired(log, publisher)
        for key in [k for k in self.urls if k[0] == publisher and k[1] not in found]:
            del self.urls[key]
        for url, now in found.items():
            current = self.urls.get((publisher, url))
            if current is not None:
                current["collection"], current["item"] = now["collection"], now["item"]
            else:
                self.urls[(publisher, url)] = {"collection": now["collection"], "item": now["item"],
                                               "place": place_of(now["collection"], now["index"]),
                                               "eligibility": eligibility}

    def descendants(self, domain, labels):
        gone = set(labels)
        hashes = {declaration_hash(self.history["declarations"][label]["publisher"]) for label in gone}
        for entry in self.discovered.get(domain, []):
            prev = self.history["declarations"][entry["label"]]["publisher"].get("prev_declaration")
            if prev in hashes and entry["label"] not in gone:
                gone.add(entry["label"])
                hashes.add(declaration_hash(self.history["declarations"][entry["label"]]["publisher"]))
        return gone - set(labels)

    def leave(self, domain, labels):
        self.discovered[domain] = [e for e in self.discovered.get(domain, []) if e["label"] not in labels]

    def reducing(self, domain):
        return [e["label"] for e in self.discovered.get(domain, []) if e["reduces"]]

    def admission(self, domain, at):
        state = copy.deepcopy(self.log["domains"].get(domain)) or new_state()
        window = state["window"]
        if window is not None and window["end"] is not None and at >= window["end"]:
            state["current"], state["window"] = window["head"], None
        for entry in self.discovered.get(domain, []):
            state["decls"][entry["label"]] = self.history["declarations"][entry["label"]]
            try:
                apply_group(state, [entry["label"]], None, None, entry["parameters"])
            except Rejected as rejection:
                raise VerifierError(f"discovered Declaration {entry['label']} no longer applies: {rejection.code}")
        if state["current"] is not None and domain in self.seq_floor:
            state["floor"] = max(state["floor"], self.seq_floor[domain])
        return state

    @staticmethod
    def labelled(state, digest):
        for label, envelope in state["decls"].items():
            if declaration_hash(envelope["publisher"]) == digest:
                return label
        return None

    def withdrawn_page(self, item):
        return "removed" not in item and withdrawn(self.log, item_id(item))

    def judge_listed(self, identifier, index, domain, publishers, served, parameters):
        entry = self.lists[identifier]
        item = entry["list"][index]
        identity = item_id(item)
        row = {"url": item.get("url"), "item": identity}
        if item_form(item) and self.withdrawn_page(item):
            entry["status"][index] = "not_admitted"
            row.update(outcome="not_admitted", codes=["WIST2-E03"], payload="withdrawn")
            return row
        verdicts = [judge_item(item, entry["inner"], publisher, parameters) for publisher in publishers]
        if not any(verdict == ACCEPTED for verdict in verdicts):
            entry["status"][index] = "refused"
            row.update(outcome="refused", codes=shown_codes(set().union(*verdicts)))
            return row
        entry["status"][index] = "admitted"
        row["outcome"] = "admitted"
        if "removed" in item:
            row["payload"] = None
            return row
        record = self.log["records"].get((domain, item["url"]))
        if record is not None and record["item"] == identity:
            row["payload"] = "record"
            return row
        held = self.payloads.get(identity)
        payload = held if held is not None else served["payloads"].get(identity[len("sha256:"):])
        verdict = None if payload is None else judge_payload(payload, item, parameters)
        if verdict == ACCEPTED:
            row["payload"] = "held" if held is not None else "fetched"
            self.payloads[identity] = payload
            return row
        entry["status"][index] = "not_admitted"
        row.update(outcome="not_admitted", codes=["WIST2-E03"])
        row["payload"] = "unavailable" if verdict is None else "failed"
        if verdict is not None:
            row["payload_code"] = OneOf(verdict)
        return row

    def rejudge(self, identifier, domain, publishers, served, parameters):
        entry = self.lists.get(identifier)
        if entry is None:
            raise VerifierError(f"an idempotent re-serve of {identifier}, whose list was never walked")
        pending = [index for index, status in enumerate(entry["status"]) if status != "admitted"]
        return [self.judge_listed(identifier, index, domain, publishers, served, parameters) for index in pending]

    def pull_collection(self, index, position, domain, name, served, sources, queueing, parameters, at):
        row = {"collection": name}
        if served is None:
            row["outcome"] = "unavailable"
            return row
        members_read(served, SERVED_MEMBERS, where=f"collections.{name}")
        envelope = self.history["catalogs"][served["catalog"]]
        if not isinstance(envelope, dict) or set(envelope) != {"catalog", "sig"} or not sig_form(envelope["sig"]) \
                or not catalog_inner_form(envelope["catalog"]):
            row.update(outcome="refused", codes=[E14])
            return row
        inner = envelope["catalog"]
        identifier = catalog_id(inner)
        row["catalog"] = identifier
        latest = self.log["latest"].get((domain, name))
        last = self.last_accepted(self.log, domain, name)
        kid = envelope["sig"]["key_id"]
        queued = self.queue.get((domain, name, kid)) if queueing else None
        waiting = last if queueing and self.catalog_waits(self.log, domain, name) else None
        same_key = [entry for entry in (queued, waiting)
                    if entry is not None and entry["envelope"]["sig"]["key_id"] == kid]
        publishers = [publisher for _, publisher in sources]
        # ADR-0052 Catalogs: from the discovery of a recovery rotation until settlement the signing key counts.
        known = [latest] + same_key if queueing else [latest, last]
        if identifier in {entry["id"] for entry in known if entry is not None}:
            if queueing:
                publishers = [publisher for publisher in publishers
                              if not c1_codes(envelope, publisher, parameters, at)]
            items = self.rejudge(identifier, domain, publishers, served, parameters) if publishers else []
            row.update(outcome="idempotent", tree_files_fetched=[], items=items)
            return row
        verdicts = [c1_codes(envelope, publisher, parameters, at) for publisher in publishers]
        passing = [source for source, codes in zip(sources, verdicts) if not codes]
        codes = set() if passing else set().union(*verdicts)
        if inner["publisher"] != domain or inner["collection"] != name:
            codes.add("WIST2-E04")
        instant = log_seconds(inner["generated_at"])
        if queueing:
            if latest is not None and instant <= generated(latest["envelope"]):
                codes.add("WIST2-E05")
            if any(instant <= generated(entry["envelope"]) for entry in same_key):
                codes.add("WIST2-E05")
        elif last is not None and instant <= generated(last["envelope"]):
            codes.add("WIST2-E05")
        if codes:
            row.update(outcome="refused", codes=shown_codes(codes))
            return row
        row["sources"] = [label for label, _ in passing]
        fetched = set()
        try:
            listed = walk_tree(inner, TreeStore(self.trees, self.history["tree_files"], served["tree_files"], fetched),
                               parameters)
        except Refused as refusal:
            row.update(tree_files_fetched=sorted(fetched), outcome="refused", codes=["WIST2-E07"],
                       reason=re.sub(r" [0-9a-f]{64}", "", str(refusal)))
            return row
        row["tree_files_fetched"] = sorted(fetched)
        base = is_base(inner, latest)
        if not base:
            present = {item["url"] for item in listed}
            dropped = sorted((url for (owner, url), record in self.log["records"].items()
                              if owner == domain and record["collection"] == name and url not in present
                              and any(covered(publisher, name, url) for publisher in publishers)), key=octets)
            if dropped:
                row.update(outcome="refused", codes=["WIST2-E07"], reason=DROPPED_REASON, dropped=dropped)
                return row
        self.lists[identifier] = {"inner": inner, "list": listed, "status": [None] * len(listed)}
        accepting = [publisher for _, publisher in passing]
        items = [self.judge_listed(identifier, i, domain, accepting, served, parameters) for i in range(len(listed))]
        row.update(outcome="accepted", base=base, key=self.key_name(envelope), queued=queueing, items=items)
        place = [index, position(name)]
        if queueing:
            self.enqueue(domain, name, {"id": identifier, "envelope": envelope, "place": place})
            return row
        entry = self.tracked.setdefault((domain, name), {"last": None, "failed_c4": False, "waiting": None})
        kept = entry["waiting"] if self.catalog_waits(self.log, domain, name) else None
        entry["last"] = {"id": identifier, "envelope": envelope}
        entry["failed_c4"] = False
        entry["waiting"] = kept if kept is not None else {"place": place, "eligibility": self.height + 1}
        return row

    def enqueue(self, domain, name, queued):
        key = (domain, name, queued["envelope"]["sig"]["key_id"])
        present = self.queue.get(key)
        if present is None or generated(queued["envelope"]) > generated(present["envelope"]):
            self.queue[key] = queued
        earliest = self.first_place.get((domain, name))
        if earliest is None or place_key(domain, queued["place"]) < place_key(domain, earliest):
            self.first_place[(domain, name)] = queued["place"]

    def pull(self, index, event):
        members_read(event, PULL_MEMBERS, where="pull")
        if self.height is None:
            raise VerifierError("a pull before the first Epoch")
        domain, at = event["publisher"], log_seconds(event["at"])
        parameters = self.read_parameters(event["parameters"])
        self.advance(at)
        out = {"settlement": [], "declaration": None, "collections_pulled": [], "catalogs": []}
        window = self.log_window(domain)
        if window is not None and at >= window["end"] and self.settled.get(domain) != window["end"]:
            out["settlement"] = self.settle(domain, index, at, parameters, self.height + 1,
                                            window["head"], window["end"])
        window = self.log_window(domain)
        inside = window is not None and at < window["end"] and self.settled.get(domain) != window["end"]
        declaration = {"outcome": "not_fetched", "discovered": False, "reduces_authority": False, "sources": [],
                       "window": False}
        out["declaration"] = declaration
        label = event["declaration"]
        if label is None:
            return out
        state = self.admission(domain, at)
        envelope = self.history["declarations"][label]
        if not isinstance(envelope.get("publisher"), dict) or envelope["publisher"].get("domain") != domain:
            raise VerifierError(f"the Declaration {label} is not of {domain}")
        known = state["decls"].get(label)
        if known is not None and jcs(known) != jcs(envelope):
            raise VerifierError(f"two Declarations named {label}")
        state["decls"][label] = envelope
        try:
            kind = fetch_declaration(state, label, None, None, parameters)
        except Rejected as rejection:
            declaration["outcome"] = rejection.code
            return out
        declaration["outcome"] = kind
        if kind not in ("idempotent", "recovery_chain_head"):
            declaration["discovered"] = True
            prev = envelope["publisher"].get("prev_declaration")
            predecessor = None if prev is None else self.labelled(state, prev)
            reduces = predecessor is not None and bool(reductions(state["decls"][predecessor]["publisher"],
                                                                  envelope["publisher"]))
            declaration["reduces_authority"] = reduces
            if kind.startswith("reversal_"):
                pending = [e["label"] for e in self.discovered.get(domain, [])
                           if e["kind"] in ("pending_replacement", "fresh_identity_pending")]
                self.leave(domain, set(pending) | self.descendants(domain, pending))
            self.discovered.setdefault(domain, []).append({"label": label, "parameters": parameters, "kind": kind,
                                                           "reduces": reduces})
            self.seq_floor[domain] = max(self.seq_floor.get(domain, 0), envelope["publisher"]["seq"])
        sources = [(source, state["decls"][source]["publisher"]) for source in pull_sources(state)]
        declaration["sources"] = [source for source, _ in sources]
        declaration["window"] = inside
        queueing = state["window"] is not None
        names = pulled_collections(state, [source for source, _ in sources])
        out["collections_pulled"] = names
        position = self.positions(self.log, domain, sources[0][1], names)
        for name in names:
            out["catalogs"].append(self.pull_collection(index, position, domain, name,
                                                        event["collections"].get(name), sources, queueing,
                                                        parameters, at))
        unread = set(event["collections"]) - set(names)
        if unread:
            raise VerifierError(f"served Collections the pull does not read: {sorted(unread)}")
        if not queueing:
            self.refresh(self.log, domain, lambda c, i: [index, position(c), i], self.height + 1)
        return out

    def log_window(self, domain):
        state = self.log["domains"].get(domain)
        return None if state is None else state["window"]

    def settle(self, domain, index, clock, parameters, eligibility, source_label, marker):
        state = self.log["domains"][domain]
        source = state["decls"][source_label]["publisher"]
        keys = sorted((key for key in self.queue if key[0] == domain),
                      key=lambda key: (place_key(domain, self.queue[key]["place"]), octets(key[2])))
        rows, survivors = [], {}
        for key in keys:
            queued = self.queue[key]
            row = {"publisher": domain, "collection": key[1], "key": self.key_name(queued["envelope"]),
                   "catalog": queued["id"]}
            codes = c1_codes(queued["envelope"], source, parameters, clock)
            if codes:
                row.update(outcome="WIST1-E13", condition_code=OneOf(codes))
            else:
                survivors.setdefault(key[1], []).append((queued, row))
            rows.append(row)
        chosen = {}
        for collection, entries in survivors.items():
            latest = max((generated(q["envelope"]), octets(q["id"])) for q, _ in entries)
            first = min((q for q, _ in entries if (generated(q["envelope"]), octets(q["id"])) == latest),
                        key=lambda q: place_key(domain, q["place"]))
            for queued, row in entries:
                row["outcome"] = "survivor" if queued is first else "not_latest"
            chosen[collection] = first
        for collection in sorted({key[1] for key in keys} | {c for p, c in self.tracked if p == domain}, key=octets):
            entry = self.tracked.setdefault((domain, collection), {"last": None, "failed_c4": False, "waiting": None})
            entry["last"] = None if collection not in chosen else \
                {"id": chosen[collection]["id"], "envelope": chosen[collection]["envelope"]}
            entry["failed_c4"], entry["waiting"] = False, None
            if self.catalog_waits(self.log, domain, collection):
                entry["waiting"] = {"place": self.first_place[(domain, collection)], "eligibility": eligibility}
        held = {url: entry for (owner, url), entry in self.urls.items() if owner == domain}
        position = self.positions(self.log, domain, source)
        for url in held:
            del self.urls[(domain, url)]
        for url, now in self.desired(self.log, domain).items():
            if url in held:
                place = held[url]["place"]
            elif now["collection"] in chosen:
                place = chosen[now["collection"]]["place"] + [now["index"]]
            else:
                place = [index, position(now["collection"]), now["index"]]
            self.urls[(domain, url)] = {"collection": now["collection"], "item": now["item"], "place": place,
                                        "eligibility": eligibility}
        for key in keys:
            del self.queue[key]
        for key in [k for k in self.first_place if k[0] == domain]:
            del self.first_place[key]
        self.queued_domains.discard(domain)
        self.settled[domain] = marker
        competitors = [e["label"] for e in self.discovered.get(domain, []) if e["kind"] == "in_window_competitor"]
        self.leave(domain, set(competitors) | self.descendants(domain, competitors))
        return rows

    def queue_waiting(self, domain):
        for (publisher, collection), entry in sorted(self.tracked.items(), key=lambda kv: octets(kv[0][1])):
            if publisher != domain or not self.catalog_waits(self.log, publisher, collection):
                continue
            self.enqueue(domain, collection, {"id": entry["last"]["id"], "envelope": entry["last"]["envelope"],
                                              "place": entry["waiting"]["place"]})
            entry["last"], entry["waiting"], entry["failed_c4"] = None, None, False

    def open_queue(self, domain):
        self.queue_waiting(domain)
        for (publisher, _), entry in self.urls.items():
            if publisher == domain:
                entry["eligibility"] = None
        self.queued_domains.add(domain)

    def check_declarations(self, labels, parameters):
        sealing, failed = [], []
        for label in labels:
            envelope = self.history["declarations"][label]
            domain = envelope["publisher"]["domain"]
            state = self.log["domains"].get(domain)
            if state is None or state["current"] is None or not repeats_head(state, [envelope]):
                try:
                    validate(envelope, parameters)
                except Rejected as rejection:
                    failed.append({"declaration": label, "code": rejection.code})
                    continue
            sealing.append(label)
        return sealing, failed

    def epoch(self, index, event):
        members_read(event, EPOCH_MEMBERS, EPOCH_OPTIONAL, where="epoch")
        height, sealed_at = event["height"], log_seconds(event["sealed_at"])
        parameters = self.read_parameters(event["parameters"])
        if self.height is not None and (height != self.height + 1 or sealed_at <= self.sealed_at):
            raise VerifierError("Epoch heights or sealed_at instants do not increase")
        self.advance(sealed_at)
        ceiling = parameters["max_inclusion_epochs"]
        out = {"settlement": [], "entries": [], "sealed": [], "left": [], "deferred": [], "records_removed": []}
        held_rows = []
        for domain in sorted(self.log["domains"], key=octets):
            window = self.log["domains"][domain]["window"]
            if window is not None and sealed_at >= window["end"] and self.settled.get(domain) != window["end"]:
                out["settlement"] += self.settle(domain, index, sealed_at, parameters, height, window["head"],
                                                 window["end"])
        labels = event["declarations"]
        sealing, failed = self.check_declarations(labels, parameters)
        left_labels = []
        for row in failed:
            domain = self.history["declarations"][row["declaration"]]["publisher"]["domain"]
            gone = self.descendants(domain, [row["declaration"]])
            left_labels += sorted(gone)
            recovery = [e for e in self.discovered.get(domain, [])
                        if e["label"] in gone | {row["declaration"]}
                        and e["kind"] in ("recovery_rotation", "reversal_recovery_rotation")]
            self.leave(domain, gone | {row["declaration"]})
            if recovery:
                self.queue_waiting(domain)
                source = self.log["domains"][domain]["current"]
                out["settlement"] += self.settle(domain, index, sealed_at, parameters, height, source,
                                                 ("left", recovery[0]["label"]))
        sealing = [label for label in sealing if label not in left_labels]
        if failed:
            out["declarations_failed"] = failed
        if left_labels:
            out["declarations_left"] = [{"declaration": label} for label in left_labels]
        declared = [{"name": label, "entry": {"type": "publisher_declaration",
                                              "body": self.history["declarations"][label]}} for label in sealing]
        updates = [{"name": name, "entry": {"type": "registry_update", "body": self.updates[name]}}
                   for name in event.get("updates", [])]
        plan = copy.deepcopy(self.log)
        removed = []
        try:
            apply_declarations(plan, declared, height, sealed_at, parameters, removed)
        except EpochRejected as rejection:
            raise VerifierError(f"the Epoch's Declarations are rejected: {rejection}")
        for label in sealing:
            domain = self.history["declarations"][label]["publisher"]["domain"]
            self.leave(domain, {label})
        for update in updates:
            target = withdrawal_target(update["entry"]["body"])
            if target in self.log["sealed_items"]:
                self.payloads.pop(target[1], None)
        hold = {domain for domain in self.discovered if self.reducing(domain)}
        room, capacity = {}, parameters["domain_epoch_entries_max"]
        sealed_entries, deferred_catalogs, deferred_urls, catalog_turn = [], [], [], {}

        def has_room(publisher):
            return room.get(self.unit(publisher), capacity) > 0

        def take_room(publisher):
            room[self.unit(publisher)] = room.get(self.unit(publisher), capacity) - 1

        def hold_row(row, eligibility):
            if eligibility + ceiling <= height:
                raise VerifierError(f"the hold keeps {row} out of the last Epoch its ceiling allows")
            held_rows.append({**row, "reasons": ["authority_reduction"]})

        candidates = sorted((place_key(p, entry["waiting"]["place"]), octets(c), p, c)
                            for (p, c), entry in self.tracked.items()
                            if self.catalog_waits(self.log, p, c) and entry["waiting"]["eligibility"] <= height)
        for _, _, publisher, collection in candidates:
            entry = self.tracked[(publisher, collection)]
            place = entry["waiting"]["place"]
            row = {"type": "publisher_catalog", "publisher": publisher, "collection": collection,
                   "catalog": entry["last"]["id"]}
            if window_open(plan, publisher):
                out["deferred"].append({**row, "place": place, "reasons": ["recovery_window"]})
                deferred_catalogs.append(entry)
                catalog_turn[(publisher, collection)] = "deferred"
                continue
            if publisher in hold:
                hold_row({**row, "place": place}, entry["waiting"]["eligibility"])
                catalog_turn[(publisher, collection)] = "held"
                continue
            if not has_room(publisher):
                out["deferred"].append({**row, "place": place, "reasons": ["capacity"]})
                deferred_catalogs.append(entry)
                catalog_turn[(publisher, collection)] = "deferred"
                continue
            body = entry["last"]["envelope"]
            conditions, codes = judge_catalog_entry(plan, body, height, sealed_at, parameters, removed)
            if not conditions:
                take_room(publisher)
                sealed_entries.append({"type": "publisher_catalog", "body": body})
                out["sealed"].append({**row, "eligibility": entry["waiting"]["eligibility"],
                                      "ceiling": entry["waiting"]["eligibility"] + ceiling})
                entry["waiting"] = None
            elif "C1" in conditions:
                c1 = c1_codes(body, in_force(plan, publisher), parameters, sealed_at)
                out["left"].append({**row, "condition": "C1", "codes": shown_codes(c1), "reported": True})
                entry["last"], entry["waiting"] = None, None
            elif conditions == ["C4"]:
                out["left"].append({**row, "condition": "C4", "codes": sorted(codes), "reported": False})
                entry["failed_c4"], entry["waiting"] = True, None
            else:
                raise VerifierError(f"a waiting Catalog fails {conditions} at its turn, which Waiting does not cover")
        items = []
        for (publisher, url), entry in list(self.urls.items()):
            if entry["eligibility"] is None or entry["eligibility"] > height:
                continue
            current = self.desired(plan, publisher).get(url)
            if current is None:
                self.leave_unreported(plan, publisher, url, entry, parameters, out)
                continue
            kind = 0 if "removed" in current["item"] else 1
            items.append((kind, place_key(publisher, entry["place"]), octets(url), publisher, url, current, entry))
        for _, _, _, publisher, url, current, entry in sorted(items, key=lambda r: r[:3]):
            collection, item = current["collection"], current["item"]
            identity = item_id(item)
            place = entry["place"]
            row = {"type": "publisher_item", "publisher": publisher, "collection": collection, "url": url,
                   "item": identity}
            reasons = []
            if window_open(plan, publisher):
                reasons.append("recovery_window")
            if catalog_turn.get((publisher, collection)) == "deferred":
                reasons.append("catalog_waiting")
            latest = plan["latest"].get((publisher, collection))
            if latest is not None and not passes_i4(plan, latest):
                reasons.append("latest_fails_i4")
            if reasons:
                out["deferred"].append({**row, "place": place, "reasons": reasons})
                deferred_urls.append(entry)
                continue
            if publisher in hold:
                hold_row({**row, "place": place}, entry["eligibility"])
                continue
            if self.catalog_waits(plan, publisher, collection):
                held_rows.append({**row, "place": place, "reasons": ["catalog_waiting"]})
                continue
            if not has_room(publisher):
                out["deferred"].append({**row, "place": place, "reasons": ["capacity"]})
                deferred_urls.append(entry)
                continue
            last = self.lists[current["catalog"]]["inner"]
            if latest is None or latest["envelope"]["catalog"]["root"] != last["root"]:
                raise VerifierError(f"{url} has no deferral and no latest Catalog of its last accepted root")
            if "removed" not in item:
                payload = self.payloads.get(identity)
                verdict = None if payload is None else judge_payload(payload, item, parameters)
                if verdict != ACCEPTED:
                    failure = {**row, "condition": "payload", "codes": ["WIST2-E03"], "reported": True}
                    if verdict is not None:
                        failure["payload_code"] = OneOf(verdict)
                    out["left"].append(failure)
                    self.lists[current["catalog"]]["status"][current["index"]] = "not_admitted"
                    continue
            body = self.item_body(latest, identity, collection)
            conditions, codes = judge_item_entry(plan, body, parameters, removed)
            if not conditions:
                take_room(publisher)
                sealed_entries.append({"type": "publisher_item", "body": body})
                out["sealed"].append({**row, "catalog": latest["id"], "eligibility": entry["eligibility"],
                                      "ceiling": entry["eligibility"] + ceiling})
            elif conditions == ["I5"]:
                out["left"].append({**row, "condition": "I5", "codes": shown_codes(codes), "reported": True})
                self.lists[current["catalog"]]["status"][current["index"]] = "refused"
            else:
                raise VerifierError(f"the Item of {url} fails {conditions} at its turn")
        self.seal(height, sealed_at, parameters, declared, updates, sealed_entries, plan, removed, out)
        for entry in deferred_catalogs:
            entry["waiting"]["eligibility"] = height + 1
        for entry in deferred_urls:
            entry["eligibility"] = height + 1
        for publisher in sorted(self.publishers(self.log), key=octets):
            if publisher in self.queued_domains:
                continue
            position = self.positions(self.log, publisher, in_force(self.log, publisher))
            self.refresh(self.log, publisher, lambda c, i, p=position: [index, p(c), i], height + 1)
        for domain in sorted(self.log["domains"], key=octets):
            window = self.log["domains"][domain]["window"]
            if window is not None and domain not in self.queued_domains and self.settled.get(domain) != window["end"]:
                self.open_queue(domain)
        if held_rows:
            out["held"] = held_rows
        self.height, self.sealed_at = height, sealed_at
        return out

    def item_body(self, latest, identity, collection):
        listed = self.lists[latest["id"]]["list"]
        position = [item_id(other) for other in listed].index(identity)
        leaves = [leaf_of(other) for other in listed]
        return {"item": listed[position], "collection": collection, "catalog": latest["id"],
                "proof": {"index": position, "tree_size": len(listed),
                          "path": [h.hex() for h in audit_path(leaves, position)]}}

    def leave_unreported(self, plan, publisher, url, entry, parameters, out):
        listed = self.listed_item(plan, publisher, entry["collection"], url)
        if listed is None or not listed["admitted"]:
            return
        item = listed["item"]
        if self.i7(plan, publisher, item, self.no_record(plan, publisher, entry["collection"])):
            return
        identity = item_id(item)
        latest = plan["latest"].get((publisher, entry["collection"]))
        last = self.lists[listed["catalog"]]["inner"]
        if latest is not None and latest["envelope"]["catalog"]["root"] == last["root"]:
            _, codes = judge_item_entry(copy.deepcopy(plan), self.item_body(latest, identity, entry["collection"]),
                                        parameters, [])
        else:
            publisher_now = in_force(plan, publisher)
            verdict = ACCEPTED if publisher_now is None else judge_item(item, last, publisher_now, parameters)
            codes = {OUT_OF_PLACE} | (set() if verdict == ACCEPTED else set(verdict))
        out["left"].append({"type": "publisher_item", "publisher": publisher, "collection": entry["collection"],
                            "url": url, "item": identity, "condition": "I7", "codes": shown_codes(codes),
                            "reported": False})

    def seal(self, height, sealed_at, parameters, declared, updates, sealed_entries, plan, removed, out):
        apply_withdrawals(plan, [u["entry"]["body"] for u in updates], height)
        named = declared + updates + [{"name": f"planned {n}", "entry": entry}
                                      for n, entry in enumerate(sealed_entries)]
        named.sort(key=lambda e: (GROUP_ORDER.index(e["entry"]["type"]), leaf_hash(e["entry"])))
        try:
            ignored, replayed = apply_epoch(self.log, height, sealed_at, parameters, named, self.rules)
        except EpochRejected as rejection:
            raise VerifierError(f"the planned Epoch is rejected: {rejection}")
        if ignored:
            raise VerifierError(f"the Judgment ignores planned Entries: {ignored}")
        if not multiset_equal(replayed, removed) or plan["records"] != self.log["records"] \
                or plan["withdrawn"] != self.log["withdrawn"] \
                or {k: v["id"] for k, v in plan["latest"].items()} \
                != {k: v["id"] for k, v in self.log["latest"].items()}:
            raise VerifierError("the plan and the Judgment disagree on the state")
        for identifier in self.log["withdrawn"]:
            self.payloads.pop(identifier, None)
        out["entries"] = [entry["entry"] for entry in named]
        out["records_removed"] = replayed

    def snapshot(self):
        ceiling = self.parameters["max_inclusion_epochs"]
        collections = []
        for publisher, collection in sorted(set(self.tracked) | set(self.log["latest"]),
                                            key=lambda k: (octets(k[0]), octets(k[1]))):
            latest = self.log["latest"].get((publisher, collection))
            last = self.last_accepted(self.log, publisher, collection)
            waiting = None
            if self.catalog_waits(self.log, publisher, collection):
                entry = self.tracked[(publisher, collection)]["waiting"]
                if entry is None:
                    raise VerifierError(f"the waiting Catalog of {collection} has no place")
                waiting = {"catalog": last["id"], "place": entry["place"], "eligibility": entry["eligibility"],
                           "ceiling": entry["eligibility"] + ceiling}
            collections.append({"publisher": publisher, "collection": collection,
                                "latest": None if latest is None else latest["id"],
                                "last_accepted": None if last is None else last["id"], "waiting": waiting})
        urls = [{"publisher": p, "url": u, "collection": e["collection"], "item": item_id(e["item"]),
                 "place": e["place"], "eligibility": e["eligibility"],
                 "ceiling": None if e["eligibility"] is None else e["eligibility"] + ceiling}
                for (p, u), e in sorted(self.urls.items(), key=lambda kv: (place_key(kv[0][0], kv[1]["place"]),
                                                                          octets(kv[0][1])))]
        queue = [{"publisher": key[0], "collection": key[1], "key": self.key_name(q["envelope"]),
                  "catalog": q["id"], "place": q["place"], "first_place": self.first_place[(key[0], key[1])]}
                 for key, q in sorted(self.queue.items(), key=lambda kv: (place_key(kv[0][0], kv[1]["place"]),
                                                                         octets(kv[0][2])))]
        pending = [{"publisher": p, "declaration": label} for p in sorted(self.discovered, key=octets)
                   for label in self.reducing(p)]
        records = [{"publisher": p, "url": u, "collection": r["collection"], "item": r["item"],
                    "catalog": r["catalog"]}
                   for (p, u), r in sorted(self.log["records"].items(), key=lambda kv: (octets(kv[0][0]),
                                                                                       octets(kv[0][1])))]
        return {"collections": collections, "urls": urls, "queue": queue, "reductions_pending": pending,
                "records": records}


def unmatched(want, got):
    rest, missing = list(got), []
    for element in want:
        for position, candidate in enumerate(rest):
            if element == candidate:
                del rest[position]
                break
        else:
            missing.append(element)
    return missing, rest


def multiset_equal(want, got):
    if not isinstance(want, list) or not isinstance(got, list):
        return want == got
    return unmatched(want, got) == ([], [])


def first_difference(want, got, path):
    if isinstance(want, dict) and isinstance(got, dict) and want.keys() == got.keys():
        for key in want:
            if want[key] != got[key]:
                return first_difference(want[key], got[key], f"{path}.{key}")
    if isinstance(want, list) and isinstance(got, list) and len(want) == len(got):
        for position, (a, b) in enumerate(zip(want, got)):
            if a != b:
                return first_difference(a, b, f"{path}[{position}]")
    return path, want, got


def compare(report, label, want, got):
    disagree = False
    for field in sorted(want.keys() | got.keys()):
        report.cases += 1
        expected, actual = want.get(field), got.get(field)
        if field == "state" and isinstance(expected, dict) and isinstance(actual, dict):
            agree = expected.keys() == actual.keys() and all(multiset_equal(expected[k], actual[k]) for k in expected)
        elif field in UNORDERED:
            agree = multiset_equal(expected, actual)
        else:
            agree = expected == actual
        if agree:
            continue
        disagree = True
        if field in UNORDERED and isinstance(expected, list) and isinstance(actual, list):
            missing, extra = unmatched(expected, actual)
            report.failures.append((f"{label} {field}", f"expected also {shown(missing)}, got instead {shown(extra)}"))
            continue
        if field == "state" and isinstance(expected, dict) and isinstance(actual, dict) \
                and expected.keys() == actual.keys():
            for key in expected:
                if not multiset_equal(expected[key], actual[key]):
                    missing, extra = unmatched(expected[key], actual[key])
                    report.failures.append((f"{label} state.{key}",
                                            f"expected also {shown(missing)}, got instead {shown(extra)}"))
            continue
        path, a, b = first_difference(expected, actual, field)
        report.failures.append((f"{label} {path}", f"expected {shown(a)}, got {shown(b)}"))
    return disagree


def check_members(data):
    members_read(data, FILE_MEMBERS, where="file")
    for name, key in data["keys"].items():
        members_read(key, KEY_MEMBERS, where=f"keys.{name}")
    for history in data["histories"]:
        where = history.get("name", "history")
        members_read(history, HISTORY_MEMBERS, HISTORY_OPTIONAL, where=where)
        if len(history["events"]) != len(history["expected"]):
            raise VerifierError(f"{where}: {len(history['events'])} events and {len(history['expected'])} results")
        for index, (event, want) in enumerate(zip(history["events"], history["expected"])):
            if event.get("event") == "pull":
                members_read(want, PULL_EXPECTED, where=f"{where} expected {index}")
            elif event.get("event") == "epoch":
                members_read(want, EPOCH_EXPECTED, EPOCH_EXPECTED_OPTIONAL, where=f"{where} expected {index}")
            else:
                raise VerifierError(f"{where}: event {index} is neither a pull nor an Epoch")
            members_read(want["state"], STATE_MEMBERS, where=f"{where} expected {index} state")
        named = {name for event in history["events"] for name in event.get("updates", [])}
        if named != set(history.get("registry_updates", {})):
            raise VerifierError(f"{where}: registry updates no Epoch seals, or an Epoch names one not given")
        if set(history["catalogs"]) != set(history["catalog_ids"]):
            raise VerifierError(f"{where}: catalogs and catalog_ids name different Catalogs")


def family(data, report):
    totals = {"histories": 0, "pulls": 0, "epochs": 0}
    for history in data["histories"]:
        name = history["name"]
        totals["histories"] += 1
        for label, envelope in history["catalogs"].items():
            report.equal(f"{name} catalog_ids.{label}", history["catalog_ids"][label], catalog_id(envelope["catalog"]))
        replay = Replay(data, history)
        for index, (event, want) in enumerate(zip(history["events"], history["expected"])):
            label = f"{name}: event {index} ({event['event']})"
            try:
                got = replay.pull(index, event) if event["event"] == "pull" else replay.epoch(index, event)
                got["state"] = replay.snapshot()
            except (VerifierError, Rejected, KeyError, TypeError, ValueError, AttributeError, IndexError) as error:
                report.cases += 1
                report.failures.append((label, f"{type(error).__name__}: {error}"))
                break
            totals["pulls" if event["event"] == "pull" else "epochs"] += 1
            compare(report, label, want, got)
    return totals


FAMILIES = [
    ("catalog-waiting", "wist3/catalog-waiting.json"),
    ("catalog-recovery", "wist1/catalog-recovery.json"),
    ("collection-pull", "wist2/collection-pull.json"),
]


def main(argv):
    base = pathlib.Path(argv[1]) if len(argv) > 1 else ROOT / "vectors"
    failed = False
    for name, relative in FAMILIES:
        report = Report()
        totals = {"histories": 0, "pulls": 0, "epochs": 0}
        try:
            data = strict_load(base / relative)
            check_members(data)
            keys = []
            check_keys_block(data, keys)
            report.failures.extend(keys)
            totals = family(data, report)
        except (OSError, VerifierError, KeyError, TypeError, ValueError) as error:
            report.failures.append(("file", f"{type(error).__name__}: {error}"))
        status = "FAIL" if report.failures else "PASS"
        failed = failed or bool(report.failures)
        print(f"{status} {name}: {totals['histories']} histories, {totals['pulls']} pulls and {totals['epochs']} "
              f"Epochs recomputed, {len(report.failures)} disagreeing")
        for label, what in report.failures:
            print(f"  {label}: {what}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
