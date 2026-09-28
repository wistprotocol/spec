import copy
import hashlib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import verify_collection_vectors
from verify_collection_vectors import (
    Rejected, VerifierError, apply_group, check_keys_block, collection_names, declaration_hash, log_seconds,
    new_state, reductions, strict_load, validate)
from verify_catalog_vectors import (
    ACCEPTED, Refused, Report, binding_code, catalog_id, catalog_inner_form, covered, item_id, judge_item,
    judge_payload, leaf_of, merkle_root, sig_form, walk_tree)
from verify_sealing_vectors import (
    GROUP_ORDER, EpochRejected, apply_declarations, apply_epoch, c1_codes, in_force, judge_catalog_entry,
    judge_item_entry, leaf_hash, new_log, window_open)

ROOT = pathlib.Path(__file__).resolve().parent.parent
DAY_SECONDS = 86400
E14 = "WIST1-E14"
DROPPED_REASON = "the list drops the URL of a held record"
UNORDERED = {"left", "deferred", "records_removed"}

_open_window = verify_collection_vectors.open_window


def open_owned_window(state, label, sealed_at, parameters):
    _open_window(state, label, sealed_at, parameters)
    state["window"]["owner"] = label


verify_collection_vectors.open_window = open_owned_window


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


def audit_path(leaves, index):
    if len(leaves) <= 1:
        return []
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < split:
        return audit_path(leaves[:split], index) + [merkle_root(leaves[split:])]
    return audit_path(leaves[split:], index - split) + [merkle_root(leaves[:split])]


def generated(envelope):
    return log_seconds(envelope["catalog"]["generated_at"])


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
        self.log = new_log()
        self.parameters = None
        self.height = None
        self.sealed_at = None
        self.clock = None
        self.lists = {}
        self.tracked = {}
        self.urls = {}
        self.queue = {}
        self.first_place = {}
        self.hold = set()
        self.settled = {}
        self.discovered = {}
        self.reducing = {}
        self.trees = {}
        self.payloads = set()

    def advance(self, instant):
        if self.clock is not None and instant < self.clock:
            raise VerifierError("events are not in time order")
        self.clock = instant

    def key_name(self, envelope):
        kid = envelope["sig"]["key_id"]
        if kid not in self.names:
            raise VerifierError(f"no test key has the kid {kid}")
        return self.names[kid]

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

    def publishers(self, log):
        return {key[0] for key in self.tracked} | {key[0] for key in log["latest"]} | {key[0] for key in self.urls}

    def collections_of(self, log, publisher):
        keys = set(self.tracked) | set(log["latest"])
        return sorted((c for p, c in keys if p == publisher), key=octets)

    def positions(self, log, publisher, declaration):
        named = [] if declaration is None else collection_names(declaration)
        others = sorted({c for c in self.collections_of(log, publisher) if c not in named}, key=octets)

        def place(collection):
            if collection in named:
                return named.index(collection)
            if collection not in others:
                raise VerifierError(f"Collection {collection!r} has no position")
            return len(named) + others.index(collection)
        return place

    @staticmethod
    def is_base(inner, latest, parameters):
        if latest is None:
            return False
        floor = generated(latest["envelope"])
        return log_seconds(inner["generated_at"]) > floor + parameters["removal_retention_days"] * DAY_SECONDS

    @staticmethod
    def i7(log, publisher, item, no_record):
        record = None if no_record else log["records"].get((publisher, item["url"]))
        if "removed" in item:
            return record is not None
        return record is None or record["item"] != item_id(item)

    def desired(self, log, publisher, parameters):
        found = {}
        for collection in self.collections_of(log, publisher):
            last = self.last_accepted(log, publisher, collection)
            if last is None:
                continue
            entry = self.lists.get(last["id"])
            if entry is None:
                raise VerifierError(f"the list of {last['id']} was never walked")
            latest = log["latest"].get((publisher, collection))
            no_record = latest is not None and latest["id"] != last["id"] \
                and self.is_base(last["envelope"]["catalog"], latest, parameters)
            for index, item in enumerate(entry["list"]):
                if entry["status"][index] != "admitted" or not self.i7(log, publisher, item, no_record):
                    continue
                if item["url"] in found:
                    raise VerifierError(f"two Collections list {item['url']}")
                found[item["url"]] = {"collection": collection, "index": index, "item": item, "catalog": last["id"]}
        return found

    def refresh(self, log, publisher, place_of, eligibility, parameters):
        found = self.desired(log, publisher, parameters)
        for key in [k for k in self.urls if k[0] == publisher and k[1] not in found]:
            del self.urls[key]
        for url, now in found.items():
            current = self.urls.get((publisher, url))
            if current is None:
                self.urls[(publisher, url)] = {"collection": now["collection"], "item": now["item"],
                                               "place": place_of(now["collection"], now["index"]),
                                               "eligibility": eligibility}
            else:
                current["collection"], current["item"] = now["collection"], now["item"]

    def log_window(self, domain):
        state = self.log["domains"].get(domain)
        return None if state is None else state["window"]

    def admission(self, domain, at):
        state = copy.deepcopy(self.log["domains"].get(domain)) or new_state()
        window = state["window"]
        if window is not None and window["end"] is not None and at >= window["end"]:
            state["current"], state["window"] = window["head"], None
        for label in self.discovered.get(domain, []):
            state["decls"][label] = self.history["declarations"][label]
            try:
                apply_group(state, [label], None, None, self.parameters)
            except Rejected as rejection:
                raise VerifierError(f"discovered Declaration {label} no longer applies: {rejection.code}")
        return state

    @staticmethod
    def labelled(state, digest):
        for label, envelope in state["decls"].items():
            if declaration_hash(envelope["publisher"]) == digest:
                return label
        return None

    def sources(self, state):
        window = state["window"]
        if window is not None:
            owner = window["owner"]
            before = self.labelled(state, state["decls"][owner]["publisher"]["prev_declaration"])
            if before is None:
                raise VerifierError(f"the Declaration {owner} names no known predecessor")
            return [(before, state["decls"][before]["publisher"]), (owner, state["decls"][owner]["publisher"])]
        if state["current"] is None:
            raise VerifierError("no current Declaration")
        return [(state["current"], state["decls"][state["current"]]["publisher"])]

    def judge_listed(self, identifier, index, domain, publishers, served, parameters):
        entry = self.lists[identifier]
        item = entry["list"][index]
        identity = item_id(item)
        row = {"url": item.get("url"), "item": identity}
        verdicts = [judge_item(item, entry["inner"], publisher, parameters) for publisher in publishers]
        if not any(verdict == ACCEPTED for verdict in verdicts):
            codes = set().union(*verdicts)
            row.update(outcome="refused", codes=[E14] if E14 in codes else sorted(codes))
            entry["status"][index] = "refused"
            return row
        entry["status"][index] = "admitted"
        row["outcome"] = "admitted"
        if "removed" in item:
            row["payload"] = None
            return row
        record = self.log["records"].get((domain, item["url"]))
        if record is not None and record["item"] == identity:
            row["payload"] = "record"
        elif identity in self.payloads:
            row["payload"] = "held"
        else:
            payload = served["payloads"].get(identity[len("sha256:"):])
            verdict = None if payload is None else judge_payload(payload, item, parameters)
            if verdict == ACCEPTED:
                self.payloads.add(identity)
                row["payload"] = "fetched"
            else:
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

    def pull_collection(self, index, position, domain, name, served, sources, inside, parameters, at):
        row = {"collection": name}
        if served is None:
            row["outcome"] = "unavailable"
            return row
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
        queued = self.queue.get((domain, name, envelope["sig"]["key_id"])) if inside else None
        publishers = [publisher for _, publisher in sources]
        if identifier in {entry["id"] for entry in (latest, last, queued) if entry is not None}:
            if inside:
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
        if inside:
            if latest is not None and instant <= generated(latest["envelope"]):
                codes.add("WIST2-E05")
            if queued is not None and instant <= generated(queued["envelope"]):
                codes.add("WIST2-E05")
        elif last is not None and instant <= generated(last["envelope"]):
            codes.add("WIST2-E05")
        if codes:
            row.update(outcome="refused", codes=[E14] if E14 in codes else sorted(codes))
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
        base = self.is_base(inner, latest, parameters)
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
        row.update(outcome="accepted", base=base, key=self.key_name(envelope), queued=inside, items=items)
        place = [index, position]
        if inside:
            self.first_place.setdefault((domain, name), place)
            self.queue[(domain, name, envelope["sig"]["key_id"])] = {"id": identifier, "envelope": envelope,
                                                                     "place": place}
            return row
        entry = self.tracked.setdefault((domain, name), {"last": None, "failed_c4": False, "waiting": None})
        kept = entry["waiting"] if self.catalog_waits(self.log, domain, name) else None
        entry["last"] = {"id": identifier, "envelope": envelope}
        entry["failed_c4"] = False
        entry["waiting"] = kept if kept is not None else {"place": place, "eligibility": self.height + 1}
        return row

    def pull(self, index, event):
        if self.parameters is None:
            raise VerifierError("a pull before the first Epoch")
        domain, at, parameters = event["publisher"], log_seconds(event["at"]), self.parameters
        self.advance(at)
        out = {"settlement": [], "declaration": None, "collections_pulled": [], "catalogs": []}
        window = self.log_window(domain)
        if window is not None and at >= window["end"] and self.settled.get(domain) != window["end"]:
            out["settlement"] = self.settle(domain, index, at, parameters, self.height + 1)
        inside = window is not None and at < window["end"]
        declaration = {"outcome": "not_fetched", "discovered": False, "reduces_authority": False, "sources": [],
                       "window": False}
        out["declaration"] = declaration
        label = event["declaration"]
        if label is None:
            return out
        state = self.admission(domain, at)
        envelope = self.history["declarations"][label]
        try:
            validate(envelope, parameters)
            if envelope["publisher"]["domain"] != domain:
                raise VerifierError(f"the Declaration {label} is of another domain")
            known = state["decls"].get(label)
            if known is not None and known != envelope:
                raise VerifierError(f"two Declarations named {label}")
            state["decls"][label] = envelope
            result = apply_group(state, [label], None, None, parameters)
        except Rejected as rejection:
            declaration["outcome"] = rejection.code
            return out
        declaration["outcome"] = result["kind"]
        if result["kind"] != "idempotent":
            declaration["discovered"] = True
            self.discovered.setdefault(domain, []).append(label)
            prev = envelope["publisher"].get("prev_declaration")
            predecessor = None if prev is None else self.labelled(state, prev)
            if predecessor is not None and reductions(state["decls"][predecessor]["publisher"],
                                                      envelope["publisher"]):
                declaration["reduces_authority"] = True
                self.reducing.setdefault(domain, []).append(label)
        sources = self.sources(state)
        declaration["sources"] = [source for source, _ in sources]
        declaration["window"] = inside
        names = list(collection_names(sources[0][1]))
        for source, publisher in sources[1:]:
            names += [name for name in collection_names(publisher) if name not in names]
        out["collections_pulled"] = names
        for position, name in enumerate(names):
            out["catalogs"].append(self.pull_collection(index, position, domain, name,
                                                        event["collections"].get(name), sources, inside,
                                                        parameters, at))
        if not inside:
            def place_of(collection, list_index):
                if collection not in names:
                    raise VerifierError(f"a URL of {collection!r} begins to wait at a pull that did not read it")
                return [index, names.index(collection), list_index]
            self.refresh(self.log, domain, place_of, self.height + 1, parameters)
        return out

    def settle(self, domain, index, clock, parameters, eligibility):
        state = self.log["domains"][domain]
        window = state["window"]
        source = state["decls"][window["head"]]["publisher"]
        keys = sorted((key for key in self.queue if key[0] == domain),
                      key=lambda key: (self.queue[key]["place"], octets(key[2])))
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
            best = max(entries, key=lambda e: (generated(e[0]["envelope"]), octets(e[0]["id"])))[0]
            for queued, row in entries:
                row["outcome"] = "survivor" if queued is best else "not_latest"
            chosen[collection] = best
        for collection in {key[1] for key in keys}:
            if collection in chosen:
                entry = self.tracked.setdefault((domain, collection), {"last": None, "failed_c4": False,
                                                                        "waiting": None})
                entry["last"] = {"id": chosen[collection]["id"], "envelope": chosen[collection]["envelope"]}
            elif (domain, collection) in self.tracked:
                entry = self.tracked[(domain, collection)]
                entry["last"] = None
            else:
                continue
            entry["failed_c4"], entry["waiting"] = False, None
            if self.catalog_waits(self.log, domain, collection):
                entry["waiting"] = {"place": self.first_place[(domain, collection)], "eligibility": eligibility}
        held = {url: entry for (owner, url), entry in self.urls.items() if owner == domain}
        position = self.positions(self.log, domain, source)
        for url in held:
            del self.urls[(domain, url)]
        for url, now in self.desired(self.log, domain, parameters).items():
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
        self.hold.discard(domain)
        self.settled[domain] = window["end"]
        return rows

    def open_hold(self, domain):
        for (publisher, collection), entry in self.tracked.items():
            if publisher != domain or not self.catalog_waits(self.log, publisher, collection):
                continue
            envelope = entry["last"]["envelope"]
            place = entry["waiting"]["place"]
            self.queue[(domain, collection, envelope["sig"]["key_id"])] = {"id": entry["last"]["id"],
                                                                           "envelope": envelope, "place": place}
            self.first_place.setdefault((domain, collection), place)
            entry["last"], entry["waiting"], entry["failed_c4"] = None, None, False
        for (publisher, _), entry in self.urls.items():
            if publisher == domain:
                entry["eligibility"] = None
        self.hold.add(domain)

    @staticmethod
    def i4(log, latest):
        inner = latest["envelope"]["catalog"]
        publisher = in_force(log, inner["publisher"])
        return publisher is not None and inner["collection"] in collection_names(publisher) \
            and binding_code(publisher, inner, latest["envelope"]["sig"]) is None

    def epoch(self, index, event):
        height, sealed_at, parameters = event["height"], log_seconds(event["sealed_at"]), event["parameters"]
        if self.height is not None and (height != self.height + 1 or sealed_at <= self.sealed_at):
            raise VerifierError("Epoch heights or sealed_at instants do not increase")
        self.advance(sealed_at)
        self.parameters = parameters
        ceiling = parameters["max_inclusion_epochs"]
        out = {"settlement": [], "entries": [], "sealed": [], "left": [], "deferred": [], "records_removed": []}
        for domain in sorted(self.log["domains"], key=octets):
            window = self.log["domains"][domain]["window"]
            if window is not None and sealed_at >= window["end"] and self.settled.get(domain) != window["end"]:
                out["settlement"] += self.settle(domain, index, sealed_at, parameters, height)
        labels = event["declarations"]
        declared = [{"type": "publisher_declaration", "body": self.history["declarations"][label]}
                    for label in labels]
        plan = copy.deepcopy(self.log)
        removed = []
        try:
            apply_declarations(plan, [{"name": label, "entry": entry} for label, entry in zip(labels, declared)],
                               height, sealed_at, parameters, removed)
        except EpochRejected as rejection:
            raise VerifierError(f"the Epoch's Declarations are rejected: {rejection}")
        for label in labels:
            domain = self.history["declarations"][label]["publisher"]["domain"]
            for held in (self.discovered, self.reducing):
                if label in held.get(domain, []):
                    held[domain].remove(label)
        room = {}
        capacity = parameters["domain_epoch_entries_max"]
        sealed_entries, deferred_catalogs, deferred_urls = [], [], []

        def publisher_reasons(publisher):
            reasons = []
            if window_open(plan, publisher):
                reasons.append("recovery_window")
            if self.reducing.get(publisher):
                reasons.append("authority_reduction")
            return reasons

        candidates = sorted(((entry["waiting"]["place"], octets(p), octets(c), p, c)
                             for (p, c), entry in self.tracked.items()
                             if self.catalog_waits(self.log, p, c) and entry["waiting"]["eligibility"] <= height))
        for place, _, _, publisher, collection in candidates:
            entry = self.tracked[(publisher, collection)]
            shown_row = {"type": "publisher_catalog", "publisher": publisher, "collection": collection,
                         "catalog": entry["last"]["id"]}
            reasons = publisher_reasons(publisher)
            if not reasons and room.get(publisher, capacity) == 0:
                reasons = ["capacity"]
            if reasons:
                out["deferred"].append({**shown_row, "place": place, "reasons": reasons})
                deferred_catalogs.append(entry)
                continue
            body = entry["last"]["envelope"]
            failed, codes = judge_catalog_entry(plan, body, height, sealed_at, parameters, removed)
            if not failed:
                room[publisher] = room.get(publisher, capacity) - 1
                sealed_entries.append({"type": "publisher_catalog", "body": body})
                out["sealed"].append({**shown_row, "eligibility": entry["waiting"]["eligibility"],
                                      "ceiling": entry["waiting"]["eligibility"] + ceiling})
                entry["waiting"] = None
            elif "C1" in failed:
                c1 = c1_codes(body, in_force(plan, publisher), parameters, sealed_at)
                out["left"].append({**shown_row, "condition": "C1", "codes": sorted(c1), "reported": True})
                entry["last"], entry["waiting"] = None, None
            elif failed == ["C4"]:
                out["left"].append({**shown_row, "condition": "C4", "codes": sorted(codes), "reported": False})
                entry["failed_c4"], entry["waiting"] = True, None
            else:
                raise VerifierError(f"a waiting Catalog fails {failed} at its turn, which no rule of Waiting covers")
        now = {}
        items = []
        for (publisher, url), entry in self.urls.items():
            if entry["eligibility"] is None or entry["eligibility"] > height:
                continue
            if publisher not in now:
                now[publisher] = self.desired(plan, publisher, parameters)
            current = now[publisher].get(url)
            if current is None:
                continue
            kind = 0 if "removed" in current["item"] else 1
            items.append((kind, entry["place"], octets(publisher), octets(url), publisher, url, current, entry))
        for _, place, _, _, publisher, url, current, entry in sorted(items, key=lambda row: row[:4]):
            collection, item = current["collection"], current["item"]
            identity = item_id(item)
            shown_row = {"type": "publisher_item", "publisher": publisher, "collection": collection, "url": url,
                         "item": identity}
            reasons = publisher_reasons(publisher)
            if self.catalog_waits(plan, publisher, collection):
                reasons.append("catalog_waiting")
            latest = plan["latest"].get((publisher, collection))
            if latest is not None and not self.i4(plan, latest):
                reasons.append("latest_fails_i4")
            if not reasons:
                last = self.lists[current["catalog"]]["inner"]
                if latest is None or latest["envelope"]["catalog"]["root"] != last["root"]:
                    raise VerifierError(f"{url} has no deferral and no latest Catalog of its last accepted root")
                if room.get(publisher, capacity) == 0:
                    reasons = ["capacity"]
            if reasons:
                out["deferred"].append({**shown_row, "place": place, "reasons": reasons})
                deferred_urls.append(entry)
                continue
            listed = self.lists[latest["id"]]["list"]
            position = [item_id(other) for other in listed].index(identity)
            leaves = [leaf_of(other) for other in listed]
            body = {"item": listed[position], "collection": collection, "catalog": latest["id"],
                    "proof": {"index": position, "tree_size": len(listed),
                              "path": [h.hex() for h in audit_path(leaves, position)]}}
            failed, codes = judge_item_entry(plan, body, parameters, removed)
            if not failed:
                room[publisher] = room.get(publisher, capacity) - 1
                sealed_entries.append({"type": "publisher_item", "body": body})
                out["sealed"].append({**shown_row, "catalog": latest["id"], "eligibility": entry["eligibility"],
                                      "ceiling": entry["eligibility"] + ceiling})
            elif failed == ["I5"]:
                out["left"].append({**shown_row, "condition": "I5", "codes": sorted(codes), "reported": True})
                self.lists[current["catalog"]]["status"][current["index"]] = "refused"
            else:
                raise VerifierError(f"the Item of {url} fails {failed} at its turn")
        named = [{"name": label, "entry": entry} for label, entry in zip(labels, declared)]
        named += [{"name": f"planned {n}", "entry": entry} for n, entry in enumerate(sealed_entries)]
        named.sort(key=lambda e: (GROUP_ORDER.index(e["entry"]["type"]), leaf_hash(e["entry"])))
        ordered = [entry["entry"] for entry in named]
        result = apply_epoch(self.log, {"height": height, "sealed_at": event["sealed_at"], "parameters": parameters,
                                        "entries": named})
        if result["status"] != "accepted":
            raise VerifierError(f"the planned Epoch is rejected: {result.get('code')}")
        ignored = [r for r in result["entries"] if r["disposition"] != "valid"]
        if ignored:
            raise VerifierError(f"the Judgment ignores planned Entries: {ignored}")
        if result["records_removed"] != removed or plan["records"] != self.log["records"] \
                or {k: v["id"] for k, v in plan["latest"].items()} != {k: v["id"] for k, v in self.log["latest"].items()}:
            raise VerifierError("the plan and the Judgment disagree on the state")
        out["entries"] = ordered
        out["records_removed"] = result["records_removed"]
        for entry in deferred_catalogs:
            entry["waiting"]["eligibility"] = height + 1
        for entry in deferred_urls:
            entry["eligibility"] = height + 1
        for publisher in sorted(self.publishers(self.log), key=octets):
            if publisher in self.hold:
                continue
            position = self.positions(self.log, publisher, in_force(self.log, publisher))
            self.refresh(self.log, publisher, lambda c, i, p=position: [index, p(c), i], height + 1, parameters)
        for domain in sorted(self.log["domains"], key=octets):
            window = self.log["domains"][domain]["window"]
            if window is not None and domain not in self.hold and self.settled.get(domain) != window["end"]:
                self.open_hold(domain)
        self.height, self.sealed_at = height, sealed_at
        return out

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
                for (p, u), e in sorted(self.urls.items(), key=lambda kv: (kv[1]["place"], octets(kv[0][0]),
                                                                          octets(kv[0][1])))]
        queue = [{"publisher": key[0], "collection": key[1], "key": self.key_name(q["envelope"]),
                  "catalog": q["id"], "place": q["place"], "first_place": self.first_place[(key[0], key[1])]}
                 for key, q in sorted(self.queue.items(), key=lambda kv: (kv[1]["place"], octets(kv[0][2])))]
        pending = [{"publisher": p, "declaration": label} for p in sorted(self.reducing, key=octets)
                   for label in self.reducing[p]]
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


def family(data, report):
    for history in data["histories"]:
        name = history["name"]
        for label, envelope in history["catalogs"].items():
            report.run(f"{name} catalog_ids.{label}", lambda l=label, e=envelope: report.equal(
                f"{name} catalog_ids.{l}", history["catalog_ids"].get(l), catalog_id(e["catalog"])))
        if len(history["events"]) != len(history["expected"]):
            report.equal(f"{name} expected count", len(history["events"]), len(history["expected"]))
            continue
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
            compare(report, label, want, got)


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
        try:
            data = strict_load(base / relative)
            keys = []
            check_keys_block(data, keys)
            report.failures.extend(keys)
            family(data, report)
        except (OSError, VerifierError, KeyError, TypeError, ValueError) as error:
            report.failures.append(("file", f"{type(error).__name__}: {error}"))
        status = "FAIL" if report.failures else "PASS"
        failed = failed or bool(report.failures)
        print(f"{status} {name}: {report.cases} cases, {len(report.failures)} disagreeing")
        for label, what in report.failures:
            print(f"  {label}: {what}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
