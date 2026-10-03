import copy

import catalogs
import collection_rules as rules
import items
import merkle
import narrowing
import tree_files

ENTRY_GROUPS = ("publisher_declaration", "registry_update", "publisher_catalog", "publisher_item", "label", "dispute")
ENTRY_MEMBERS = {"type", "body"}
LABEL_MEMBERS = {"label": "labeler", "dispute": "disputant"}
OUT_OF_PLACE = "WIST3-E06"
EPOCH_REJECTED = "WIST3-E03"
DAY_SECONDS = 86400
DECLARATION_PARAMETERS = tuple(rules.DEFAULT_PARAMETERS)
REFRESH_BOUNDS = (1, 7776000)
TREE_FLOORS = dict(tree_files.DEFAULT_PARAMETERS)
WITHDRAWAL = "payload_withdrawal"
CONTRACT_FAILED = "WIST4-E04"
ENVELOPE_FAILED = "WIST4-E11"
FIELD_FAILED = "WIST1-E14"


def check_parameters(parameters):
    if "removal_retention_days" in parameters:
        raise ValueError("removal_retention_days is a constant that no Log amends")
    low, high = REFRESH_BOUNDS
    if not low <= parameters["catalog_refresh_seconds"] <= high:
        raise ValueError("catalog_refresh_seconds is amended outside 1 to 7 776 000")
    items.check_parameters({k: parameters[k] for k in items.DEFAULT_PARAMETERS})
    for name, floor in {**TREE_FLOORS, "catalog_items_max": items.CATALOG_ITEMS_MAX}.items():
        if name in parameters and parameters[name] < floor:
            raise ValueError(f"{name} is amended below {floor}")
    if parameters.get("labeler_epoch_entries_max", 1) > parameters["domain_epoch_entries_max"]:
        raise ValueError("labeler_epoch_entries_max exceeds domain_epoch_entries_max")
    rules.parameter_map({k: parameters[k] for k in DECLARATION_PARAMETERS})
    return parameters


def entry_form(entry):
    return isinstance(entry, dict) and set(entry) == ENTRY_MEMBERS and entry["type"] in ENTRY_GROUPS


def withdrawal_act(entry):
    if not isinstance(entry["body"], dict):
        return None
    update = entry["body"].get("update")
    if not isinstance(update, dict) or update.get("action") != WITHDRAWAL:
        raise ValueError("a registry_update this replay does not carry")
    return update["details"]["delta_id"], update["subject"]


def entry_leaf(entry):
    return merkle.leaf_hash(items.jcs(entry))


def canonical_order(entries):
    return sorted(entries, key=lambda e: (ENTRY_GROUPS.index(e["type"]), entry_leaf(e)))


def catalog_strings(body):
    catalog = body.get("catalog") if isinstance(body, dict) else None
    if not isinstance(catalog, dict):
        return None
    publisher, name = catalog.get("publisher"), catalog.get("collection")
    if not isinstance(publisher, str) or not isinstance(name, str):
        return None
    return publisher, name


def counted_host(entry):
    body = entry["body"]
    member = {"publisher_catalog": "catalog", "publisher_item": "item", "label": "label",
              "dispute": "dispute"}.get(entry["type"])
    if member is None:
        return None
    inner = body.get(member) if isinstance(body, dict) else None
    host = inner.get(LABEL_MEMBERS.get(member, "publisher")) if isinstance(inner, dict) else None
    if not isinstance(host, str) or not rules.is_canonical_host(host):
        return None
    return host


def capacity_counts(entries):
    counts = {}
    for entry in entries:
        host = counted_host(entry)
        if host is not None:
            counts[host] = counts.get(host, 0) + 1
    return counts


def item_body_form(body):
    if not isinstance(body, dict) or set(body) != items.BODY_MEMBERS:
        raise items.Refused("WIST1-E14", "body members")
    items.check_item_form(body["item"])
    if not isinstance(body["collection"], str) or not rules.NAME_PATTERN.fullmatch(body["collection"]):
        raise items.Refused("WIST1-E14", "collection is not a Collection name")
    if not isinstance(body["catalog"], str) or not items.HASH_PATTERN.fullmatch(body["catalog"]):
        raise items.Refused("WIST1-E14", "catalog is not a Catalog ID")
    items.check_proof_form(body["proof"])


def refusal(check, *arguments):
    try:
        check(*arguments)
    except items.Refused as refused:
        return refused.code
    return None


def disposition(failed):
    if not failed:
        return {"disposition": "valid"}
    return {"disposition": "ignored", "failed": [condition for condition, _ in failed],
            "codes": sorted({code for _, code in failed})}


class Sealing:
    def __init__(self):
        self.replays = {}
        self.latest = {}
        self.records = {}
        self.removals = {}
        self.withdrawals = {}
        self.sealed_items = {}
        self.duties = {}
        self.sealed_at = None

    def declaration(self, domain):
        replay = self.replays.get(domain)
        return replay.current if replay is not None else None

    def window_open(self, domain):
        replay = self.replays.get(domain)
        return replay is not None and replay.window is not None

    def binding_code(self, envelope, publisher):
        if publisher is None:
            return "WIST1-E02"
        return refusal(catalogs.binding, envelope, publisher)

    def named(self, catalog_id):
        for held in self.latest.values():
            if catalogs.catalog_id(held["envelope"]["catalog"]) == catalog_id:
                return held
        return None

    def apply_declarations(self, entries, height, sealed_at, parameters, removed):
        by_domain = {}
        for entry in entries:
            if entry["type"] == "publisher_declaration" and isinstance(entry["body"], dict):
                by_domain.setdefault(entry["body"]["publisher"]["domain"], []).append(entry["body"])
        for domain in sorted(set(self.replays) | set(by_domain)):
            replay = self.replays.setdefault(domain, narrowing.Replay(
                parameters["recovery_window_days"], parameters["declaration_activation_epochs"], None))
            replay.recovery_window_days = parameters["recovery_window_days"]
            replay.declaration_activation_epochs = parameters["declaration_activation_epochs"]
            replay.parameters = {k: parameters[k] for k in DECLARATION_PARAMETERS}
            replay.live = {url: (record["collection"], record["height"])
                           for (publisher, url), record in self.records.items() if publisher == domain}
            replay.epoch({"height": height, "sealed_at": sealed_at, "declarations": by_domain.get(domain, []),
                          "records": []})
            for publisher, url in sorted(self.records):
                if publisher == domain and url not in replay.live:
                    self.remove_record((publisher, url), parameters)
                    removed.append({"publisher": publisher, "url": url, "cause": "narrowing"})

    def judge_catalog(self, envelope, sealed_at, parameters):
        form = refusal(catalogs.check_envelope_form, envelope)
        if form is not None:
            return [("C1", form)]
        catalog = envelope["catalog"]
        publisher = self.declaration(catalog["publisher"])
        failed = []
        if publisher is None:
            failed.append(("C1", "WIST1-E02"))
        else:
            code = refusal(catalogs.judge_catalog, envelope, publisher, sealed_at, parameters)
            if code is not None:
                failed.append(("C1", code))
        if self.window_open(catalog["publisher"]):
            failed.append(("C2", OUT_OF_PLACE))
        latest = self.latest.get((catalog["publisher"], catalog["collection"]))
        if latest is not None:
            instant = catalogs.log_seconds(catalog["generated_at"])
            floor = catalogs.log_seconds(latest["envelope"]["catalog"]["generated_at"])
            if instant <= floor:
                failed.append(("C3", OUT_OF_PLACE))
            if (catalog["root"] == latest["envelope"]["catalog"]["root"]
                    and instant < floor + parameters["catalog_refresh_seconds"]
                    and self.binding_code(latest["envelope"], publisher) is None):
                failed.append(("C4", OUT_OF_PLACE))
        return failed

    def is_base(self, catalog):
        latest = self.latest.get((catalog["publisher"], catalog["collection"]))
        if latest is None:
            return False
        floor = catalogs.log_seconds(latest["envelope"]["catalog"]["generated_at"])
        return catalogs.log_seconds(catalog["generated_at"]) > floor + items.retention_seconds()

    def withdrawn_below(self, item, height):
        withdrawn = self.withdrawals.get(items.item_id(item))
        return withdrawn is not None and withdrawn < height

    def start_duty(self, item, parameters):
        identifier = items.item_id(item)
        if identifier not in self.withdrawals:
            end = narrowing.log_seconds(self.sealed_at) + parameters["payload_window_days"] * DAY_SECONDS
            duty = self.duties.setdefault(identifier, {"publisher": item["publisher"], "url": item["url"],
                                                       "until": end, "record": True})
            duty["record"] = True
            duty["until"] = max(duty["until"], end)

    def end_duty(self, item):
        duty = self.duties.get(items.item_id(item))
        if duty is not None:
            duty["record"] = False

    def remove_record(self, slot, parameters):
        record = self.records.pop(slot)
        self.end_duty(record["item"])

    def apply_withdrawal(self, item_id, subject, height):
        if subject not in self.sealed_items.get(item_id, set()):
            return [("contract", CONTRACT_FAILED)]
        self.withdrawals.setdefault(item_id, height)
        self.duties.pop(item_id, None)
        return []

    def apply_catalog(self, envelope, height, parameters, removed):
        catalog = envelope["catalog"]
        base = self.is_base(catalog)
        self.latest[(catalog["publisher"], catalog["collection"])] = {"envelope": envelope, "height": height,
                                                                      "base": base}
        if base:
            for publisher, url in sorted(self.records):
                if publisher == catalog["publisher"] and self.records[(publisher, url)]["collection"] == catalog["collection"]:
                    self.remove_record((publisher, url), parameters)
                    removed.append({"publisher": publisher, "url": url, "cause": "base"})

    def judge_item(self, body, height, parameters):
        form = refusal(item_body_form, body)
        if form is not None:
            return [("I1", form)], None
        item = body["item"]
        named = self.named(body["catalog"])
        if named is None:
            return [("I3", OUT_OF_PLACE)], None
        envelope = named["envelope"]
        catalog = envelope["catalog"]
        publisher = self.declaration(catalog["publisher"])
        failed = []
        if self.window_open(catalog["publisher"]):
            failed.append(("I2", OUT_OF_PLACE))
        if rules.collection_named(publisher, catalog["collection"]) is None:
            failed.append(("I4", "WIST1-E03"))
        else:
            code = refusal(catalogs.binding, envelope, publisher)
            if code is not None:
                failed.append(("I4", code))
        if body["collection"] != catalog["collection"]:
            failed.append(("I5", "WIST1-E17"))
        code = refusal(items.judge_item, item, catalog, publisher, parameters)
        if code is not None:
            failed.append(("I5", code))
        code = refusal(items.judge_proof, item, body["proof"], catalog)
        if code is not None:
            failed.append(("I6", code))
        record = self.records.get((catalog["publisher"], item["url"]))
        if items.kind(item) == "page":
            if (record is not None and items.item_id(record["item"]) == items.item_id(item)) or self.withdrawn_below(
                    item, height):
                failed.append(("I7", OUT_OF_PLACE))
        elif record is None:
            failed.append(("I7", OUT_OF_PLACE))
        return failed, named

    def apply_item(self, body, named, height, parameters, removed):
        item = body["item"]
        catalog = named["envelope"]["catalog"]
        slot = (catalog["publisher"], item["url"])
        if items.kind(item) == "page":
            self.sealed_items.setdefault(items.item_id(item), set()).add(catalog["publisher"])
        if slot in self.records:
            self.remove_record(slot, parameters)
        if items.kind(item) == "page":
            self.records[slot] = {"item": item, "collection": body["collection"], "catalog": body["catalog"],
                                  "generated_at": catalog["generated_at"], "height": height}
            self.removals.pop(slot, None)
            self.start_duty(item, parameters)
            return
        self.removals[slot] = {"item": items.item_id(item), "catalog": body["catalog"],
                               "generated_at": catalog["generated_at"]}
        removed.append({"publisher": slot[0], "url": slot[1], "cause": "removed_item"})

    def rejections(self, entries, parameters):
        found = []
        if not all(entry_form(e) for e in entries):
            found.append((EPOCH_REJECTED, "an Entry not an object of exactly type and body of an Entry type"))
            entries = [e for e in entries if entry_form(e)]
        if any(e["type"] == "publisher_declaration" and not isinstance(e["body"], dict) for e in entries):
            found.append((FIELD_FAILED, "a publisher_declaration body that is not an object"))
        if list(entries) != canonical_order(entries):
            found.append((EPOCH_REJECTED, "Entries not in canonical order"))
        pairs = [catalog_strings(e["body"]) for e in entries if e["type"] == "publisher_catalog"]
        pairs = [p for p in pairs if p is not None]
        if len(set(pairs)) != len(pairs):
            found.append((EPOCH_REJECTED, "two publisher_catalog Entries of one publisher and collection"))
        if any(n > parameters["domain_epoch_entries_max"] for n in capacity_counts(entries).values()):
            found.append((EPOCH_REJECTED, "above the per-domain Epoch capacity"))
        labeled = capacity_counts([e for e in entries if e["type"] in LABEL_MEMBERS])
        if any(n > parameters["labeler_epoch_entries_max"] for n in labeled.values()):
            found.append((EPOCH_REJECTED, "above the per-Labeler Epoch cap"))
        return found, entries

    def epoch(self, epoch):
        height, sealed_at, parameters = epoch["height"], epoch["sealed_at"], check_parameters(epoch["parameters"])
        entries = epoch["entries"]
        found, formed = self.rejections(entries, parameters)
        saved = copy.deepcopy(self.__dict__)
        self.sealed_at = sealed_at
        removed, dispositions = [], {}
        try:
            self.apply_declarations(canonical_order(formed), height, sealed_at, parameters, removed)
        except narrowing.HistoryRejected as rejection:
            found.append((rejection.code, rejection.reason))
        if found:
            self.__dict__ = saved
            return {"height": height, "status": "rejected", "codes": sorted({code for code, _ in found}),
                    "reason": "; ".join(reason for _, reason in found)}
        acts = {index: withdrawal_act(entry) for index, entry in enumerate(entries) if entry["type"] == "registry_update"}
        for index, entry in enumerate(entries):
            if entry["type"] != "publisher_catalog":
                continue
            failed = self.judge_catalog(entry["body"], sealed_at, parameters)
            dispositions[index] = disposition(failed)
            if not failed:
                self.apply_catalog(entry["body"], height, parameters, removed)
        for index, entry in enumerate(entries):
            if entry["type"] != "publisher_item":
                continue
            failed, named = self.judge_item(entry["body"], height, parameters)
            dispositions[index] = disposition(failed)
            if not failed:
                self.apply_item(entry["body"], named, height, parameters, removed)
        for index, act in sorted(acts.items()):
            dispositions[index] = disposition([("envelope", ENVELOPE_FAILED)] if act is None
                                              else self.apply_withdrawal(*act, height))
        return {"height": height, "status": "accepted",
                "entries": [dispositions.get(i) for i in range(len(entries))],
                "records_removed": removed}

    def state(self):
        return {
            "declarations": [{"publisher": domain,
                              "current": rules.declaration_hash(r.current) if r.current else None,
                              "pending_head": rules.declaration_hash(r.pending["head"]) if r.pending else None,
                              "window_end": narrowing.log_timestamp(r.window["end"]) if r.window else None}
                             for domain, r in sorted(self.replays.items())],
            "catalogs": [{"publisher": publisher, "collection": name,
                          "catalog": catalogs.catalog_id(held["envelope"]["catalog"]),
                          "floor": held["envelope"]["catalog"]["generated_at"],
                          "sealing_height": held["height"], "base": held["base"]}
                         for (publisher, name), held in sorted(self.latest.items(),
                                                               key=lambda kv: (kv[0][0].encode(), kv[0][1].encode()))],
            "records": [{"publisher": publisher, "url": url, "item": record["item"],
                         "collection": record["collection"], "catalog": record["catalog"],
                         "generated_at": record["generated_at"]}
                        for (publisher, url), record in sorted(self.records.items(),
                                                               key=lambda kv: (kv[0][0].encode(), kv[0][1].encode()))],
            "removals": [{"publisher": publisher, "url": url, "item": state["item"], "catalog": state["catalog"],
                          "generated_at": state["generated_at"]}
                         for (publisher, url), state in sorted(self.removals.items(),
                                                               key=lambda kv: (kv[0][0].encode(), kv[0][1].encode()))]}

    def payload_duties(self):
        if self.sealed_at is None:
            return []
        now = narrowing.log_seconds(self.sealed_at)
        return [{"publisher": duty["publisher"], "url": duty["url"], "item": identifier,
                 "until": None if duty["record"] else narrowing.log_timestamp(duty["until"])}
                for identifier, duty in sorted(self.duties.items(),
                                               key=lambda kv: (kv[1]["publisher"].encode(), kv[1]["url"].encode(),
                                                               kv[0].encode()))
                if duty["record"] or duty["until"] > now]

    def url_state(self, publisher, url):
        record = self.records.get((publisher, url))
        if record is not None:
            return {"state": "record", "item": items.item_id(record["item"]), "collection": record["collection"],
                    "catalog": record["catalog"], "generated_at": record["generated_at"]}
        removal = self.removals.get((publisher, url))
        if removal is not None:
            return {"state": "removed", "item": removal["item"], "catalog": removal["catalog"],
                    "generated_at": removal["generated_at"]}
        return None


def replay(epochs):
    sealing = Sealing()
    results, previous = [], None
    for epoch in epochs:
        if previous is not None and (epoch["height"] != previous["height"] + 1 or narrowing.log_seconds(
                epoch["sealed_at"]) <= narrowing.log_seconds(previous["sealed_at"])):
            raise ValueError("Epochs must have consecutive heights and increasing sealed_at")
        result = sealing.epoch(epoch)
        result["state"] = sealing.state()
        result["payload_duties"] = sealing.payload_duties()
        results.append(result)
        previous = epoch
    return results, sealing
